// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package graphpipeline is a generic graph-learning pipeline component.
// It is NOT a vendor adapter — it contains zero vendor-specific code and
// connects to no external system. It lives in pkg/pipeline/ because it
// orchestrates generic Kernloom infrastructure stages.
//
// It implements adapterruntime.Adapter only for lifecycle management
// (Start/Stop/Health via the EventBus). The generic stack it wires:
//
//	observation.TypeFlow
//	  → network.Extractor          (candidate relationships)
//	  → LearningGuard              (exclusion check)
//	  → relationshiplearner.Learner (promotion, freeze, state)
//	  → metricbaseline.Engine       (per-edge EWMA PPS/BPS)
//	  → signal.Bus                  (deviation / freeze-violation signals)
//
// The old graphlearner stored edges in graphstore/sqlite (an L3/L4-specific
// schema).  This adapter stores everything in statestore/sqlite.
package graphpipeline

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	corebaseline "github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/capability"
	"github.com/kernloom/kernloom/pkg/core/learning"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/metricbaseline"
	"github.com/kernloom/kernloom/pkg/relationshiplearner"
	rlnetwork "github.com/kernloom/kernloom/pkg/relationshiplearner/network"
)

var logger = log.New(os.Stderr, "[graph-pipeline] ", log.LstdFlags)

// Mode mirrors the old graphlearner mode names for easy migration.
type Mode string

const (
	ModeLearn         Mode = "learn"
	ModeFrozenObserve Mode = "frozen-observe"
	ModeFrozenEnforce Mode = "frozen-enforce"
)

// Config configures the graph pipeline adapter.
type Config struct {
	NodeID string
	Mode   Mode

	// Promotion controls when candidate relationships become learned.
	Promotion relationshiplearner.PromotionConfig

	// Baseline tuning — same semantics as old graphlearner.
	BaselineAlpha              float64
	BaselineAlphaBootstrap     float64
	BaselineMinObservations    uint64
	BaselineDeviationThreshold float64
	BaselineMinUpdatePPS       float64
	BaselineMinUpdateBPS       float64
	BaselinePeakTolerance      float64

	// BaselineTrigPPS/BPS: host-level trigger thresholds from autotune.
	// Observations above these values are never learned as edge baselines.
	BaselineTrigPPS float64
	BaselineTrigBPS float64

	// Network extractor filters (same semantics as old graphlearner).
	MinPacketsPerTick  uint64
	MinBytesPerTick    uint64
	ExcludeBroadcast   bool
	ExcludeLoopback    bool
	ExcludeSourceCIDRs []net.IPNet
}

// exclusionCooldown is the minimum interval between consecutive exclusions for
// the same entity from the same attack signal. Without this, a sustained high-PPS
// source creates one exclusion per signal emission (every few seconds).
const exclusionCooldown = 2 * time.Minute

// Adapter is the graph pipeline adapter.
type Adapter struct {
	cfgMu     sync.RWMutex
	cfg       Config
	learner   *relationshiplearner.Learner
	guard     learning.Guard
	engine    *metricbaseline.Engine
	extractor *rlnetwork.Extractor
	healthy   atomic.Bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// exclMu guards lastExclusionAt — tracks when we last added an exclusion
	// for each entity so we don't flood the DB with duplicate entries.
	exclMu          sync.Mutex
	lastExclusionAt map[string]time.Time
}

// New creates a graph pipeline adapter.
// learner and guard must already be configured and ready — this adapter does
// not own their lifecycle (they are shared with the CLI read path).
func New(cfg Config, learner *relationshiplearner.Learner, guard learning.Guard) *Adapter {
	if cfg.BaselineAlpha <= 0 {
		cfg.BaselineAlpha = 0.1
	}
	if cfg.BaselineAlphaBootstrap <= 0 {
		cfg.BaselineAlphaBootstrap = 0.1
	}
	if cfg.BaselineMinObservations == 0 {
		cfg.BaselineMinObservations = 30
	}
	if cfg.BaselineDeviationThreshold <= 0 {
		cfg.BaselineDeviationThreshold = 5.0
	}
	if cfg.BaselinePeakTolerance <= 0 {
		cfg.BaselinePeakTolerance = 1.5
	}

	extCfg := rlnetwork.Config{
		NodeID:                 cfg.NodeID,
		ExcludeLoopback:        cfg.ExcludeLoopback,
		ExcludeBroadcast:       cfg.ExcludeBroadcast,
		ExcludeSourceCIDRs:     cfg.ExcludeSourceCIDRs,
		MinPackets:             cfg.MinPacketsPerTick,
		MinBytes:               cfg.MinBytesPerTick,
		CollapseEphemeralPorts: true,
	}

	blCfg := metricbaseline.DefaultConfig()
	blCfg.Alpha = cfg.BaselineAlpha
	blCfg.AlphaPromoted = cfg.BaselineAlphaBootstrap
	blCfg.MinCount = cfg.BaselineMinObservations
	blCfg.DeviationThreshold = cfg.BaselineDeviationThreshold

	a := &Adapter{
		cfg:             cfg,
		learner:         learner,
		guard:           guard,
		engine:          metricbaseline.New(blCfg),
		extractor:       rlnetwork.New(extCfg),
		lastExclusionAt: make(map[string]time.Time),
	}
	a.healthy.Store(false)
	return a
}

func (a *Adapter) ID() string                       { return "graph-pipeline" }
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterTelemetry }

func (a *Adapter) Capabilities() []*capability.Capability {
	return []*capability.Capability{
		adapterruntime.WellKnownGraphLearnEdges(),
		adapterruntime.WellKnownGraphDetectNewEdge(),
	}
}

func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error { return nil }

func (a *Adapter) Start(ctx context.Context, bus adapterruntime.EventBus) error {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.healthy.Store(true)

	a.wg.Add(1)
	go a.observationLoop(ctx, bus)

	sigCh := bus.SubscribeSignals(64)
	a.wg.Add(1)
	go a.signalLoop(ctx, sigCh)

	return nil
}

func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
	return adapterruntime.HealthStatus{Healthy: a.healthy.Load()}
}

func (a *Adapter) Stop(_ context.Context) error {
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	a.healthy.Store(false)
	return nil
}

// BaselineEngine returns the in-memory metric baseline engine.
// Callers (e.g. kliq main loop) should periodically call engine.FlushDirty(ctx, store)
// to persist dirty baselines to SQLite.
func (a *Adapter) BaselineEngine() *metricbaseline.Engine {
	return a.engine
}

// UpdateTriggers updates the host-level trigger thresholds (called by autotune).
func (a *Adapter) UpdateTriggers(trigPPS, trigBPS float64) {
	a.cfgMu.Lock()
	a.cfg.BaselineTrigPPS = trigPPS
	a.cfg.BaselineTrigBPS = trigBPS
	a.cfgMu.Unlock()
}

// signalLoop watches for heuristic signals and adds learning exclusions for the subject.
func (a *Adapter) signalLoop(ctx context.Context, signals <-chan signal.Signal) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-signals:
			if !ok {
				return
			}
			a.handleSignal(ctx, sig)
		}
	}
}

func (a *Adapter) handleSignal(ctx context.Context, sig signal.Signal) {
	switch sig.Type {
	// Attack / anomaly signals → add learning exclusion so tainted traffic
	// is not learned as normal baseline behaviour.
	case signal.SignalPPSHigh, signal.SignalBPSHigh, signal.SignalSYNRateHigh,
		signal.SignalScanSuspected, signal.SignalRateLimitDropsSustained,
		signal.SignalGraphEdgeBaselinePPSDeviation, signal.SignalGraphEdgeBaselineBytesDeviation,
		signal.SignalGraphEdgeBaselinePPSPeakExceeded, signal.SignalGraphEdgeBaselineBPSPeakExceeded:
	// graph.new_edge_after_freeze is a topology notification, NOT an attack signal.
	// It must NOT create a learning exclusion — doing so would permanently block
	// learning from every source that communicates while the graph is frozen.
	default:
		return
	}
	if sig.Subject.ID == "" || a.guard == nil {
		return
	}

	// Dedup: skip if we added an exclusion for this entity recently.
	now := time.Now()
	a.exclMu.Lock()
	if last, ok := a.lastExclusionAt[sig.Subject.ID]; ok && now.Sub(last) < exclusionCooldown {
		a.exclMu.Unlock()
		return
	}
	a.lastExclusionAt[sig.Subject.ID] = now
	a.exclMu.Unlock()

	ttl := sig.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	ex := learning.Exclusion{
		ID:              generateID(),
		EntityID:        sig.Subject.ID,
		EntityKind:      "ip",
		Reason:          learning.ReasonSuspiciousSignal,
		Severity:        float64(sig.Score) / 100.0,
		SignalID:        sig.ID,
		AppliesTo:       []learning.AppliesTo{learning.AppliesMetricBaseline, learning.AppliesRelationshipLearning},
		StartsAt:        time.Now(),
		ExpiresAt:       time.Now().Add(ttl),
		SourceComponent: "graph-pipeline",
		Status:          "active",
	}
	if err := a.guard.AddExclusion(ctx, ex); err != nil {
		logger.Printf("add exclusion for %s: %v", sig.Subject.ID, err)
	}
}

// observationLoop drains flow observations and processes them through the pipeline.
func (a *Adapter) observationLoop(ctx context.Context, bus adapterruntime.EventBus) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case obs, ok := <-bus.Observations():
			if !ok {
				return
			}
			if obs.Type != observation.TypeFlow {
				continue
			}
			a.handle(ctx, bus, obs)
		}
	}
}

func (a *Adapter) handle(ctx context.Context, bus adapterruntime.EventBus, obs observation.Observation) {
	// Extract relationships.
	candidates, err := a.extractor.Extract(ctx, []observation.Observation{obs})
	if err != nil || len(candidates) == 0 {
		return
	}

	// Learning guard check before learning and before baseline update.
	pps := obs.Metrics["pps"]
	bps := obs.Metrics["bps"]

	a.cfgMu.RLock()
	trigPPS := a.cfg.BaselineTrigPPS
	trigBPS := a.cfg.BaselineTrigBPS
	minPPS := a.cfg.BaselineMinUpdatePPS
	minBPS := a.cfg.BaselineMinUpdateBPS
	thresh := a.cfg.BaselineDeviationThreshold
	peakTol := a.cfg.BaselinePeakTolerance
	a.cfgMu.RUnlock()

	// Anti-poisoning: skip baseline if pps/bps exceed host-level trigger thresholds.
	baselineClean := true
	if trigPPS > 0 && pps > trigPPS {
		baselineClean = false
	}
	if trigBPS > 0 && bps > trigBPS {
		baselineClean = false
	}
	if minPPS > 0 && pps < minPPS {
		baselineClean = false
	}
	if minBPS > 0 && bps < minBPS {
		baselineClean = false
	}

	// Feed relationships through the learner.
	a.learner.Learn(ctx, candidates)

	// Per-edge baseline and deviation signals.
	for _, r := range candidates {
		check := learning.MetricCheck{
			SubjectEntityID: r.SubjectEntityID,
			SourceAdapter:   r.SourceAdapter,
		}
		guardResult := a.guard.CheckMetric(ctx, check)
		suspicious := guardResult.Decision != learning.AllowLearning

		k := edgeBaselineKey(r, "network.xdp.edge.packets_per_second")
		opts := metricbaseline.UpdateOptions{Suspicious: suspicious || !baselineClean}
		resultPPS := a.engine.UpdateWithBaselineKey(k, pps, opts)

		kBps := edgeBaselineKey(r, "network.xdp.edge.bytes_per_second")
		resultBPS := a.engine.UpdateWithBaselineKey(kBps, bps, opts)

		if !resultPPS.Promoted && !resultBPS.Promoted {
			continue
		}

		// EWMA deviation signals.
		if thresh > 0 && (resultPPS.DeviationScore > thresh || resultBPS.DeviationScore > thresh) {
			factor := resultPPS.DeviationScore
			sigType := signal.SignalGraphEdgeBaselinePPSDeviation
			if resultBPS.DeviationScore > resultPPS.DeviationScore {
				factor = resultBPS.DeviationScore
				sigType = signal.SignalGraphEdgeBaselineBytesDeviation
			}
			score := 50 + int((factor-thresh)*10)
			if score > 99 {
				score = 99
			}
			port := r.Dimensions["destination_port"]
			proto := r.Dimensions["protocol"]
			sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, sigType, obs.Subject).
				SetScore(score).SetConfidence(80).SetTTL(2*time.Minute).
				AddReasonCode("baseline_edge_deviation").
				SetAttribute("edge", port+"/"+proto).
				SetAttribute("deviation_pps", strconv.FormatFloat(resultPPS.DeviationScore, 'f', 1, 64)).
				SetAttribute("deviation_bytes", strconv.FormatFloat(resultBPS.DeviationScore, 'f', 1, 64))
			_ = bus.PublishSignal(ctx, *sig)
		}

		// Peak deviation signals.
		if peakTol > 0 {
			peakFactorPPS := peakFactor(resultPPS)
			peakFactorBPS := peakFactor(resultBPS)
			if peakFactorPPS > peakTol || peakFactorBPS > peakTol {
				factor := peakFactorPPS
				sigType := signal.SignalGraphEdgeBaselinePPSPeakExceeded
				if peakFactorBPS > peakFactorPPS {
					factor = peakFactorBPS
					sigType = signal.SignalGraphEdgeBaselineBPSPeakExceeded
				}
				score := 60 + int((factor-peakTol)*20)
				if score > 99 {
					score = 99
				}
				sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, sigType, obs.Subject).
					SetScore(score).SetConfidence(85).SetTTL(2*time.Minute).
					AddReasonCode("baseline_edge_peak_exceeded").
					SetAttribute("peak_factor_pps", strconv.FormatFloat(peakFactorPPS, 'f', 2, 64)).
					SetAttribute("peak_factor_bps", strconv.FormatFloat(peakFactorBPS, 'f', 2, 64))
				_ = bus.PublishSignal(ctx, *sig)
			}
		}
	}
}

// edgeBaselineKey builds a baseline.Key for a per-edge metric.
func edgeBaselineKey(r relationship.Relationship, metricID string) corebaseline.Key {
	return corebaseline.Key{
		MetricID:        metricID,
		ScopeType:       "relationship",
		ScopeID:         r.DimensionsHash,
		SubjectEntityID: r.SubjectEntityID,
		ObjectEntityID:  r.ObjectEntityID,
		DimensionsHash:  r.DimensionsHash,
		SourceClass:     "xdp",
		VisibilityPoint: "pre_stack_ingress",
		MeasurementType: "counter_delta",
		TruthClass:      "primary_packet_observation",
		WindowSeconds:   60,
	}
}

func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// peakFactor returns value/peak if the profile is promoted and has a peak, else 0.
func peakFactor(r metricbaseline.Result) float64 {
	if !r.Promoted || r.Peak <= 0 {
		return 0
	}
	return r.Value / r.Peak
}
