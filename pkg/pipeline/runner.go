// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package pipeline

import (
	"context"
	"log"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/featureextractor"
	"github.com/kernloom/kernloom/pkg/metricbaseline"
	"github.com/kernloom/kernloom/pkg/registry"
	"github.com/kernloom/kernloom/pkg/riskaggregator"
	"github.com/kernloom/kernloom/pkg/signalengine"
)

// Runner is the generic metric pipeline. It connects observation sources
// through feature extraction, baseline scoring, and signal generation.
//
// The Runner is safe for concurrent use: observations are submitted via
// SubmitObservations and processing happens on a dedicated goroutine.
type Runner struct {
	cfg        Config
	registry   *registry.Bundle
	baseline   *metricbaseline.Engine
	guards     []adapterruntime.LearningGuard
	extractors []featureextractor.Extractor
	engines    []signalengine.Engine
	logger     *log.Logger

	obsCh  chan []observation.Observation
	status Status
}

// Options configures the Runner at construction time.
type Options struct {
	Config     Config
	Registry   *registry.Bundle // nil = use embedded defaults
	Baseline   *metricbaseline.Engine
	Guards     []adapterruntime.LearningGuard
	Extractors []featureextractor.Extractor
	Engines    []signalengine.Engine
	Logger     *log.Logger
}

// New creates a new pipeline Runner. Call Start to begin processing.
// Returns a no-op runner when cfg.Enabled is false.
func New(opts Options) *Runner {
	reg := opts.Registry
	if reg == nil {
		reg = registry.DefaultBundle()
	}

	baseline := opts.Baseline
	if baseline == nil {
		bc := metricbaseline.DefaultConfig()
		baseline = metricbaseline.New(bc)
	}

	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}

	return &Runner{
		cfg:        opts.Config,
		registry:   reg,
		baseline:   baseline,
		guards:     opts.Guards,
		extractors: opts.Extractors,
		engines:    opts.Engines,
		logger:     logger,
		obsCh:      make(chan []observation.Observation, 256),
		status: Status{
			Mode:      opts.Config.Mode,
			StartedAt: time.Now().UTC(),
		},
	}
}

// Start begins the pipeline processing goroutine. Returns immediately.
// The context cancellation stops the goroutine cleanly.
func (r *Runner) Start(ctx context.Context) {
	if !r.cfg.IsActive() {
		return
	}
	r.logger.Printf("[pipeline] starting in mode=%s window=%v", r.cfg.Mode, r.cfg.Window)
	go r.loop(ctx)
}

// SubmitObservations queues observations for processing.
// Non-blocking: observations are dropped when the channel is full.
// Only call when the pipeline is active (IsActive returns true).
func (r *Runner) SubmitObservations(obs []observation.Observation) {
	if !r.cfg.IsActive() || len(obs) == 0 {
		return
	}
	select {
	case r.obsCh <- obs:
	default:
		r.status.DroppedObs += uint64(len(obs))
	}
}

// Status returns a snapshot of the current pipeline status.
func (r *Runner) CurrentStatus() Status {
	s := r.status
	s.BaselineProfiles = r.baseline.Len()
	return s
}

// IsActive returns true when the pipeline is enabled and running.
func (r *Runner) IsActive() bool { return r.cfg.IsActive() }

// ── Processing loop ───────────────────────────────────────────────────────────

func (r *Runner) loop(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Window)
	defer ticker.Stop()

	var pending []observation.Observation

	for {
		select {
		case <-ctx.Done():
			r.logger.Printf("[pipeline] stopped")
			return

		case obs := <-r.obsCh:
			pending = append(pending, obs...)

		case <-ticker.C:
			if len(pending) == 0 {
				continue
			}
			r.process(ctx, pending)
			pending = pending[:0]
		}
	}
}

func (r *Runner) process(ctx context.Context, obs []observation.Observation) {
	r.status.Ticks++
	now := time.Now()

	// Step 1: Extract metrics from observations.
	var allMetrics metric.Batch
	allMetrics = metric.NewBatch("pipeline", now, now.Add(r.cfg.Window))
	for _, ext := range r.extractors {
		filtered := filterObsByType(obs, ext.AppliesTo())
		if len(filtered) == 0 {
			continue
		}
		batch, err := ext.Extract(ctx, filtered)
		if err != nil {
			r.logger.Printf("[pipeline] extractor %s error: %v", ext.Name(), err)
			continue
		}
		for _, m := range batch.Metrics {
			allMetrics.Add(m)
		}
	}
	r.status.MetricsExtracted += uint64(allMetrics.Len())

	// Step 2: Registry validation — warn or drop unknown metric IDs.
	validated := r.validateMetrics(allMetrics)

	// Step 3: Learning guard — determine if this window is suspicious.
	guardInput := adapterruntime.LearningGuardInput{
		Observations: obs,
		Metrics:      validated,
		Timestamp:    now,
	}
	suspicious := r.runGuards(ctx, guardInput)

	// Step 4: Update metric baselines.
	var baselineResults []metricbaseline.Result
	for _, m := range validated.Metrics {
		result := r.baseline.Update(m, metricbaseline.UpdateOptions{
			Suspicious: suspicious,
			Now:        now,
		})
		baselineResults = append(baselineResults, result)
	}
	if suspicious {
		r.status.SuspiciousWindows++
	} else {
		r.status.LearnedWindows++
	}

	// Step 5: Signal engines (shadow only in shadow mode).
	var signals []signal.Signal
	if r.cfg.Mode != ModeShadow || len(r.engines) > 0 {
		engineInput := signalengine.Input{
			Observations: obs,
			Metrics:      validated.Metrics,
			Baselines:    baselineResults,
		}
		for _, eng := range r.engines {
			sigs, err := eng.Evaluate(ctx, engineInput)
			if err != nil {
				r.logger.Printf("[pipeline] signal engine %s error: %v", eng.Name(), err)
				continue
			}
			signals = append(signals, sigs...)
		}
	}
	r.status.SignalsEmitted += uint64(len(signals))

	// Step 6: Risk aggregation (shadow, no enforcement).
	if len(signals) > 0 {
		raCfg := riskaggregator.Config{Mode: riskaggregator.ModeMaxScore}
		raResults := riskaggregator.Aggregate(raCfg, signals)
		if r.status.Ticks%30 == 1 && len(raResults) > 0 {
			for _, ra := range raResults {
				r.logger.Printf("[pipeline:risk] subject=%s shadow_risk=%d signal=%s",
					ra.SubjectID, ra.ShadowRisk, ra.TopSignal.Type)
			}
		}
	}

	// Step 7: Dry-run action proposals (audit mode only).
	if r.cfg.Mode == ModeAudit && r.cfg.ActionProposals.Enabled && len(signals) > 0 {
		r.logDryRunProposals(signals)
	}

	if r.status.Ticks%30 == 0 {
		r.logger.Printf("[pipeline] tick=%d mode=%s obs=%d metrics=%d baselines=%d signals=%d suspicious=%v",
			r.status.Ticks, r.cfg.Mode, len(obs), allMetrics.Len(), len(baselineResults), len(signals), suspicious)
	}
}

func (r *Runner) validateMetrics(batch metric.Batch) metric.Batch {
	if r.registry == nil {
		return batch
	}
	out := metric.NewBatch(batch.Source, batch.From, batch.To)
	for _, m := range batch.Metrics {
		if !r.registry.HasMetric(string(m.ID)) {
			r.status.UnknownMetricsDropped++
			// warn-only in shadow mode; proposal says managed mode can drop
			r.logger.Printf("[pipeline] unknown metric_id=%s (warn)", m.ID)
			continue
		}
		out.Add(m)
	}
	return out
}

func (r *Runner) runGuards(ctx context.Context, input adapterruntime.LearningGuardInput) bool {
	for _, g := range r.guards {
		dec := g.IsSuspicious(ctx, input)
		if dec.Suspicious {
			r.logger.Printf("[pipeline] guard=%s suspicious reasons=%v", g.Name(), dec.ReasonCodes)
			return true
		}
	}
	return false
}

func (r *Runner) logDryRunProposals(signals []signal.Signal) {
	for _, sig := range signals {
		r.logger.Printf("[pipeline:dry-run] signal=%s subject=%s score=%d → would propose enforce.network.rate_limit (dry-run only)",
			sig.Type, sig.Subject.ID, sig.Score)
	}
	r.status.DryRunProposals += uint64(len(signals))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func filterObsByType(obs []observation.Observation, types []observation.ObservationType) []observation.Observation {
	if len(types) == 0 {
		return obs
	}
	allowed := make(map[observation.ObservationType]bool, len(types))
	for _, t := range types {
		allowed[t] = true
	}
	out := make([]observation.Observation, 0, len(obs))
	for _, o := range obs {
		if allowed[o.Type] {
			out = append(out, o)
		}
	}
	return out
}
