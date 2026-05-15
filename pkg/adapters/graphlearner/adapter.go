// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package graphlearner provides a KLIQ adapter that consumes flow Observations
// from the EventBus and maintains a local communication graph in a Store.
//
// It supports three modes:
//
//	learn         – edges accumulate; candidates are promoted to learned over time.
//	frozen-observe – graph is fixed; new edges emit a Signal but are not blocked.
//	frozen-enforce – (future) new edges can be enforced against.
package graphlearner

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/capability"
	"github.com/kernloom/kernloom/pkg/core/graph"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/core/suspicious"
)

var logger = log.New(os.Stderr, "[graph-learner] ", log.LstdFlags)

// Mode controls how the learner behaves.
type Mode string

const (
	// ModeLearn accumulates edges and promotes candidates to learned.
	ModeLearn Mode = "learn"
	// ModeFrozenObserve: new edges after freeze emit a signal; no enforcement.
	ModeFrozenObserve Mode = "frozen-observe"
	// ModeFrozenEnforce: new edges after freeze emit a high-score signal that
	// causes the decision engine to enforce immediately via the PEP adapter.
	ModeFrozenEnforce Mode = "frozen-enforce"
)

// Store is the interface the adapter needs from a graph edge store.
type Store interface {
	Upsert(e *graph.Edge) (*graph.Edge, error)
	GetByKey(key graph.EdgeKey) (*graph.Edge, error)
	PromoteCandidates(nodeID string, cfg graph.PromotionConfig, now time.Time) (int, error)
	MarkExpired(nodeID string, cutoff time.Time, minSeenCount uint64) (int, error)
	// ExpireCandidatesBySource expires fresh candidate edges (seen_count < minSeenCount)
	// whose source IP matches sourceID. Established candidates are preserved.
	ExpireCandidatesBySource(nodeID, sourceID string, minSeenCount uint64) (int, error)
	// UpdateEdgeBaseline updates the EWMA traffic baseline for a specific edge.
	// Must only be called when the source is not suspicious (anti-poisoning).
	UpdateEdgeBaseline(key graph.EdgeKey, pps, bytesPS, alphaStable, alphaBootstrap float64, minObs, minObsTimeBased uint64, minAge time.Duration) error
	// UpdateEdgeBaselineDecay is UpdateEdgeBaseline with optional half-life peak decay.
	UpdateEdgeBaselineDecay(key graph.EdgeKey, pps, bytesPS, alphaStable, alphaBootstrap float64, minObs, minObsTimeBased uint64, minAge time.Duration, peakDecayHalfLife time.Duration) error
	// EdgeBaselineDeviation returns EWMA deviation factors vs the learned baseline.
	EdgeBaselineDeviation(key graph.EdgeKey, pps, bytesPS float64) (devPPS, devBytes float64)
	// EdgeBaselinePeakDeviation returns pps/peak and bps/peak ratios.
	// > peakTolerance means the edge exceeded its learned maximum.
	EdgeBaselinePeakDeviation(key graph.EdgeKey, pps, bytesPS float64) (factorPPS, factorBPS float64)
	// ListSourcesWithLearnedEdges returns source IPs with learned/approved/frozen edges.
	ListSourcesWithLearnedEdges(nodeID string) (map[string]struct{}, error)
}

// Config configures the graph learner adapter.
type Config struct {
	// NodeID is the local node identifier.
	NodeID string

	// Mode is the current operating mode (learn or frozen-observe).
	Mode Mode

	// Promotion controls when candidates become learned edges.
	Promotion graph.PromotionConfig

	// PromoteInterval is how often the adapter scans for promotable candidates.
	PromoteInterval time.Duration

	// ExpireTTL is how long an unseen edge is kept before being marked expired.
	// 0 disables expiry.
	ExpireTTL time.Duration

	// MinPacketsPerTick skips recording an edge if the flow had fewer packets
	// in this tick. Useful to ignore isolated SYN probes (default: 0 = off).
	MinPacketsPerTick uint64

	// MinBytesPerTick skips recording an edge if the flow carried fewer bytes
	// in this tick (default: 0 = off).
	MinBytesPerTick uint64

	// ExcludeBroadcast drops flows whose destination is a broadcast or
	// multicast address (224.0.0.0/4, 255.255.255.255, ff00::/8).
	ExcludeBroadcast bool

	// ExcludeLoopback drops flows whose source or destination is a loopback
	// address (127.0.0.0/8, ::1).
	ExcludeLoopback bool

	// ExcludeSourceCIDRs drops flows whose source IP matches any of these CIDRs.
	// Useful to exclude NAT gateways, local routers or WSL host IPs that funnel
	// all external traffic and would otherwise dominate the graph.
	ExcludeSourceCIDRs []net.IPNet

	// Baseline tuning. Edge baseline is always active when the graph learner runs.
	// Alpha controls EWMA adaptation speed (0.0–1.0, recommended 0.05–0.15).
	// BaselineAlpha is the stable long-run EWMA adaptation speed (e.g. 0.02).
	BaselineAlpha float64
	// BaselineAlphaBootstrap is the faster alpha used while obs < BaselineMinObservations.
	BaselineAlphaBootstrap float64
	// BaselineMinObservations before a profile is promoted to learned (observation-based).
	BaselineMinObservations uint64
	// BaselineMinObsTimeBased is the lower observation threshold for time-based promotion.
	// An edge is promoted when obs >= BaselineMinObsTimeBased AND age >= BaselineMinAge.
	// Useful for low-frequency traffic (weekly cron jobs etc.). 0 = disabled.
	BaselineMinObsTimeBased uint64
	// BaselineMinAge is the minimum edge age for time-based promotion.
	BaselineMinAge time.Duration
	// BaselineDeviationThreshold is the MAD multiplier that triggers a signal.
	BaselineDeviationThreshold float64

	// BaselineMinUpdatePPS / BaselineMinUpdateBPS filter out very-low-traffic
	// ticks (keepalives, noise) from EWMA updates. Without this, bimodal sources
	// (idle keepalives + response bursts) converge to the idle level and trigger
	// deviation signals on every burst. 0 = disabled.
	BaselineMinUpdatePPS float64
	BaselineMinUpdateBPS float64

	// BaselinePeakTolerance is the multiplier applied to the learned peak before
	// emitting a peak-exceeded signal. Default 1.5 (50% above learned maximum).
	// Lower = more sensitive; 1.0 = any new maximum triggers.
	BaselinePeakTolerance float64

	// BaselineTrigPPS and BaselineTrigBPS are the host-level trigger thresholds
	// from the signal engine. Observations that exceed these values are by
	// definition above-normal for this host and must not be learned as baseline —
	// even on the very first observation, before isSuspicious() has fired.
	// Set to the current TrigPPS/TrigBPS from the heuristic engine config.
	// 0 = disabled (no cap).
	BaselineTrigPPS float64
	BaselineTrigBPS float64

	// BaselinePeakDecayHalfLife is the Sprint-5 decaying peak configuration.
	// 0 = disabled (running maximum, original behaviour).
	// Recommended: 336h (14 days) — a spike from two weeks ago decays to 50% of its
	// original value, preventing it from permanently capping legitimate burst detection.
	BaselinePeakDecayHalfLife time.Duration
}

// pendingBaselineUpdate buffers a baseline observation for the delayed-commit
// anti-poisoning pattern (Sprint 4). Updates are committed only after
// CommitDelay has elapsed and neither the source nor the edge became suspicious
// in the interim.
type pendingBaselineUpdate struct {
	Key        graph.EdgeKey
	PPS        float64
	BPS        float64
	ObservedAt time.Time
	CommitAt   time.Time
}

// Adapter is the graph learner adapter.
type Adapter struct {
	// cfgMu guards mutable fields on cfg that may change at runtime.
	// Only BaselineTrigPPS and BaselineTrigBPS are mutated post-Start (autotune
	// updates the host-level trigger thresholds). All other cfg fields are
	// effectively immutable after Start and are read without the lock.
	cfgMu        sync.RWMutex
	cfg          Config
	store        Store
	excludeCIDRs []net.IPNet
	healthy      atomic.Bool
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// susp is the shared source+edge suspicious registry (Sprint 4).
	susp *suspicious.Registry

	// knownSources caches source IPs with learned/approved/frozen edges.
	// Refreshed every promote cycle so the isSuspicious bypass kicks in quickly.
	knownMu      sync.RWMutex
	knownSources map[string]struct{}

	// pendingMu guards pendingUpdates.
	pendingMu      sync.Mutex
	pendingUpdates []pendingBaselineUpdate
}

// UpdateTriggers updates the host-level trigger thresholds used for the
// anti-poisoning cap. Call this whenever autotune produces new trigger values
// so baseline updates respect the current learned host limits.
func (a *Adapter) UpdateTriggers(trigPPS, trigBPS float64) {
	a.cfgMu.Lock()
	a.cfg.BaselineTrigPPS = trigPPS
	a.cfg.BaselineTrigBPS = trigBPS
	a.cfgMu.Unlock()
}

// CommitDelay is how long a baseline update is held in the pending buffer before
// being committed. Long enough for a signal to fire and mark the source suspicious,
// but short enough not to lag the learning curve significantly.
const CommitDelay = 30 * time.Second

// maxPendingBaselines bounds the pending baseline update buffer so a slow DB
// commit cannot let the slice grow without limit under high edge cardinality.
// Once full, new updates are dropped (anti-DoS); they will be re-observed on
// the next tick and queued again.
const maxPendingBaselines = 10000

// New creates a new graph learner adapter.
func New(cfg Config, store Store) *Adapter {
	a := &Adapter{
		cfg:          cfg,
		store:        store,
		excludeCIDRs: cfg.ExcludeSourceCIDRs,
		susp:         suspicious.New(),
		knownSources: make(map[string]struct{}),
	}
	a.healthy.Store(false)
	return a
}

func (a *Adapter) ID() string                       { return "graph-learner" }
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterTelemetry }

func (a *Adapter) Capabilities() []*capability.Capability {
	return []*capability.Capability{
		adapterruntime.WellKnownGraphLearnEdges(),
		adapterruntime.WellKnownGraphDetectNewEdge(),
	}
}

func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error {
	return nil
}

// Start begins consuming observations and signals from the bus.
func (a *Adapter) Start(ctx context.Context, bus adapterruntime.EventBus) error {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.healthy.Store(true)

	a.wg.Add(1)
	go a.observationLoop(ctx, bus)

	sigCh := bus.SubscribeSignals(64)
	a.wg.Add(1)
	go a.signalLoop(ctx, sigCh)

	if a.cfg.PromoteInterval > 0 {
		a.wg.Add(1)
		go a.maintenanceLoop(ctx)
	}

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

// signalLoop watches for heuristic signals and marks sources as suspicious.
// Observations from suspicious sources are skipped by handleObservation so that
// traffic seen during an attack is not learned as normal baseline behaviour.
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
			a.handleSignal(sig)
		}
	}
}

// handleSignal records the signal subject as suspicious for the signal's TTL
// and retroactively expires any candidate edges from that source that may have
// been written before the signal arrived (race-condition cleanup).
func (a *Adapter) handleSignal(sig signal.Signal) {
	switch sig.Type {
	case signal.SignalPPSHigh,
		signal.SignalBPSHigh,
		signal.SignalSYNRateHigh,
		signal.SignalScanSuspected,
		signal.SignalRateLimitDropsSustained,
		signal.SignalGraphEdgeBaselinePPSDeviation,
		signal.SignalGraphEdgeBaselineBytesDeviation,
		signal.SignalGraphEdgeBaselinePPSPeakExceeded,
		signal.SignalGraphEdgeBaselineBPSPeakExceeded:
	default:
		return
	}
	if sig.Subject.ID == "" {
		return
	}

	// For sources with established learned/approved/frozen edges, signals that
	// originate from the edge baseline itself must not block baseline updates —
	// doing so creates a deadlock: the signal prevents the update that would
	// resolve the signal.
	//
	// Global heuristic signals (PPS/BPS) are also suppressed for known sources
	// because the per-edge model is the right detector there.
	//
	// SYN, scan and RL signals still apply — they indicate threats regardless
	// of whether we have a learned edge for the source.
	if a.sourceIsKnown(sig.Subject.ID) {
		switch sig.Type {
		case signal.SignalPPSHigh, signal.SignalBPSHigh,
			signal.SignalGraphEdgeBaselinePPSDeviation,
			signal.SignalGraphEdgeBaselineBytesDeviation,
			signal.SignalGraphEdgeBaselinePPSPeakExceeded,
			signal.SignalGraphEdgeBaselineBPSPeakExceeded:
			return
		}
	}
	ttl := sig.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	a.susp.MarkSource(sig.Subject.ID, ttl)

	// For freeze-violation signals, also mark the specific edge suspicious so
	// other edges from the same source continue learning (edge-level granularity).
	if sig.Type == signal.SignalGraphNewEdgeAfterFreeze {
		if port, err := strconv.ParseUint(sig.Attributes["destination_port"], 10, 16); err == nil {
			a.susp.MarkEdge(suspicious.EdgeKey{
				SourceID:        sig.Subject.ID,
				DestinationID:   sig.Object.ID,
				Protocol:        sig.Attributes["protocol"],
				DestinationPort: uint16(port),
			}, ttl)
		}
	}

	// Expire only fresh candidate edges (seen_count < minSeen) that snuck in
	// during the attack burst. Established candidates survive — they represent
	// real historical traffic from the source, not attack-created fake edges.
	minSeen := a.cfg.Promotion.MinSeenCount
	if minSeen == 0 {
		minSeen = 5
	}
	if n, err := a.store.ExpireCandidatesBySource(a.cfg.NodeID, sig.Subject.ID, minSeen); err != nil {
		logger.Printf("expire candidates for %s: %v", sig.Subject.ID, err)
	} else if n > 0 {
		logger.Printf("expired %d fresh candidate(s) for suspicious source %s", n, sig.Subject.ID)
	}
}

// sourceIsKnown returns true when the source has learned/approved/frozen edges.
// Thread-safe; reads from the periodically refreshed knownSources cache.
func (a *Adapter) sourceIsKnown(sourceID string) bool {
	a.knownMu.RLock()
	_, ok := a.knownSources[sourceID]
	a.knownMu.RUnlock()
	return ok
}

// refreshKnownSources updates the known-sources cache from the DB.
// Called after every promote cycle so newly learned edges take effect quickly.
func (a *Adapter) refreshKnownSources() {
	known, err := a.store.ListSourcesWithLearnedEdges(a.cfg.NodeID)
	if err != nil {
		logger.Printf("refresh known sources: %v", err)
		return
	}
	a.knownMu.Lock()
	a.knownSources = known
	a.knownMu.Unlock()
}

// isSuspicious returns true when the given source IP is currently flagged.
func (a *Adapter) isSuspicious(ip string) bool {
	return a.susp.IsSourceSuspicious(ip)
}

// observationLoop drains flow observations from the bus and updates the graph.
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
			a.handleObservation(ctx, bus, obs)
		}
	}
}

// handleObservation converts a flow observation into a graph edge upsert.
func (a *Adapter) handleObservation(ctx context.Context, bus adapterruntime.EventBus, obs observation.Observation) {
	if obs.Subject.ID == "" {
		return
	}

	// Shield src maps only record the source IP; the destination is implicitly
	// this node. Fill in the node as object so graph edges can be recorded.
	if obs.Object.ID == "" {
		obs.Object = observation.EntityRef{
			Kind: observation.KindNode,
			ID:   obs.NodeID,
		}
		if obs.Object.ID == "" {
			obs.Object.ID = a.cfg.NodeID
		}
	}

	// Skip sources currently flagged by the heuristic signal engine (pps_high,
	// syn_rate_high, scan_suspected, rate_limit_drops). Traffic seen during an
	// active attack must not be learned as normal baseline behaviour.
	if a.isSuspicious(obs.Subject.ID) {
		return
	}

	// Drop observations without destination_port — these come from the src4
	// aggregate map which has no L4 info. Only flow4 observations (with protocol
	// and destination_port set) produce meaningful graph edges.
	if obs.Attributes["destination_port"] == "" {
		return
	}

	// Relevance filters — drop flows that pollute the graph with noise.
	if a.cfg.ExcludeLoopback {
		if isLoopback(obs.Subject.ID) || isLoopback(obs.Object.ID) {
			return
		}
	}
	if a.cfg.ExcludeBroadcast {
		if isBroadcastOrMulticast(obs.Object.ID) {
			return
		}
	}
	if len(a.excludeCIDRs) > 0 && isInCIDRs(obs.Subject.ID, a.excludeCIDRs) {
		return
	}
	if a.cfg.MinPacketsPerTick > 0 {
		if pkts := uint64(obs.Metrics["packets"]); pkts < a.cfg.MinPacketsPerTick {
			return
		}
	}
	if a.cfg.MinBytesPerTick > 0 {
		if byt := uint64(obs.Metrics["bytes"]); byt < a.cfg.MinBytesPerTick {
			return
		}
	}

	dir := directionFor(obs)
	proto := obs.Attributes["protocol"]
	if proto == "" {
		proto = "unknown"
	}
	var dstPort uint16
	if p, err := strconv.ParseUint(obs.Attributes["destination_port"], 10, 16); err == nil {
		dstPort = uint16(p)
	}
	// Collapse ephemeral destination ports (>= 32768) to 0.
	// These are local ports assigned to outgoing connections whose responses
	// arrive back here (e.g. NTP, DNS). The ephemeral port changes every
	// request, so we track the peer by IP+proto only, not by the transient port.
	if dstPort >= 32768 {
		dstPort = 0
	}

	now := obs.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e := graph.NewEdge(a.cfg.NodeID, obs.Subject, obs.Object, proto, dstPort, dir, now)
	if pkts, ok := obs.Metrics["packets"]; ok {
		e.PacketsTotal = uint64(pkts)
	}
	if byt, ok := obs.Metrics["bytes"]; ok {
		e.BytesTotal = uint64(byt)
	}

	current, err := a.store.Upsert(e)
	if err != nil || current == nil {
		return
	}

	// Per-edge baseline: update EWMA with current tick rates and check for
	// deviation.
	// Two anti-poisoning layers:
	//   1. isSuspicious() above: skips sources already flagged by signals.
	//   2. TrigPPS/TrigBPS cap below: skips observations that are by definition
	//      above the host-level trigger threshold — these are attack-level values
	//      that must not be learned as normal even on the first observation.
	//      This closes the race window where signals haven't fired yet (obs ≤ 2).
	pps := obs.Metrics["pps"]
	bps := obs.Metrics["bps"]

	baselineClean := true
	a.cfgMu.RLock()
	trigPPS := a.cfg.BaselineTrigPPS
	trigBPS := a.cfg.BaselineTrigBPS
	a.cfgMu.RUnlock()
	if trigPPS > 0 && pps > trigPPS {
		baselineClean = false
	}
	if trigBPS > 0 && bps > trigBPS {
		baselineClean = false
	}
	// Skip very-low-traffic ticks (keepalives, noise) that would drag the
	// EWMA median down below the typical active traffic level. This is
	// important for bimodal traffic (idle keepalives + response bursts):
	// without this filter the median converges to the idle level, causing
	// every burst to trigger a deviation signal.
	if a.cfg.BaselineMinUpdatePPS > 0 && pps < a.cfg.BaselineMinUpdatePPS {
		baselineClean = false
	}
	if a.cfg.BaselineMinUpdateBPS > 0 && bps < a.cfg.BaselineMinUpdateBPS {
		baselineClean = false
	}

	alpha := a.cfg.BaselineAlpha
	if alpha <= 0 {
		alpha = 0.1
	}
	minObs := a.cfg.BaselineMinObservations
	if minObs == 0 {
		minObs = 30
	}
	if baselineClean {
		// Sprint 4: buffer the update. It will be committed after CommitDelay
		// only if neither the source nor the edge became suspicious in the interim.
		// This closes the race window where the first attack observation reaches
		// the baseline before the signal fires.
		now := time.Now()
		a.pendingMu.Lock()
		if len(a.pendingUpdates) < maxPendingBaselines {
			a.pendingUpdates = append(a.pendingUpdates, pendingBaselineUpdate{
				Key:        current.Key(),
				PPS:        pps,
				BPS:        bps,
				ObservedAt: now,
				CommitAt:   now.Add(CommitDelay),
			})
		}
		a.pendingMu.Unlock()
	}

	thresh := a.cfg.BaselineDeviationThreshold
	if thresh <= 0 {
		thresh = 5.0
	}
	devPPS, devBytes := a.store.EdgeBaselineDeviation(current.Key(), pps, bps)
	if devPPS > thresh || devBytes > thresh {
		factor := devPPS
		sigType := signal.SignalGraphEdgeBaselinePPSDeviation
		if devBytes > devPPS {
			factor = devBytes
			sigType = signal.SignalGraphEdgeBaselineBytesDeviation
		}
		score := 50 + int((factor-thresh)*10)
		if score > 99 {
			score = 99
		}
		sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, sigType, obs.Subject).
			SetScore(score).
			SetConfidence(80).
			SetTTL(2*time.Minute).
			AddReasonCode("baseline_edge_deviation").
			SetAttribute("edge", strconv.Itoa(int(dstPort))+"/"+proto).
			SetAttribute("deviation_pps", strconv.FormatFloat(devPPS, 'f', 1, 64)).
			SetAttribute("deviation_bytes", strconv.FormatFloat(devBytes, 'f', 1, 64))
		_ = bus.PublishSignal(ctx, *sig)
	}

	// Peak deviation check: signal when current traffic exceeds the learned
	// maximum by more than BaselinePeakTolerance. Unlike the EWMA check (which
	// detects "above average"), this catches traffic that genuinely exceeds the
	// historic maximum — even for bimodal sources where average is misleading.
	peakTol := a.cfg.BaselinePeakTolerance
	if peakTol <= 0 {
		peakTol = 1.5
	}
	factorPPS, factorBPS := a.store.EdgeBaselinePeakDeviation(current.Key(), pps, bps)
	if factorPPS > peakTol || factorBPS > peakTol {
		factor := factorPPS
		sigType := signal.SignalGraphEdgeBaselinePPSPeakExceeded
		if factorBPS > factorPPS {
			factor = factorBPS
			sigType = signal.SignalGraphEdgeBaselineBPSPeakExceeded
		}
		score := 60 + int((factor-peakTol)*20)
		if score > 99 {
			score = 99
		}
		sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, sigType, obs.Subject).
			SetScore(score).
			SetConfidence(85).
			SetTTL(2*time.Minute).
			AddReasonCode("baseline_edge_peak_exceeded").
			SetAttribute("edge", strconv.Itoa(int(dstPort))+"/"+proto).
			SetAttribute("peak_factor_pps", strconv.FormatFloat(factorPPS, 'f', 2, 64)).
			SetAttribute("peak_factor_bps", strconv.FormatFloat(factorBPS, 'f', 2, 64))
		_ = bus.PublishSignal(ctx, *sig)
	}

	// In frozen modes, signal any edge that is not frozen/approved.
	// Candidate edges (seen during learning but never promoted) are treated as
	// unknown — they were never part of the frozen baseline.
	// frozen-observe: score=70 → FSM strikes only.
	// frozen-enforce: score=95 → decision engine calls PEP directly.
	if (a.cfg.Mode == ModeFrozenObserve || a.cfg.Mode == ModeFrozenEnforce) &&
		current.State != graph.EdgeFrozen &&
		current.State != graph.EdgeApproved {
		a.emitNewEdgeSignal(ctx, bus, current, a.cfg.Mode == ModeFrozenEnforce)
	}
}

// emitNewEdgeSignal publishes a graph.new_edge_after_freeze signal onto the bus.
// enforce=true sets score=95 so the decision engine enforces via PEP directly;
// enforce=false sets score=70 which only injects FSM strikes.
func (a *Adapter) emitNewEdgeSignal(ctx context.Context, bus adapterruntime.EventBus, e *graph.Edge, enforce bool) {
	score := 70
	if enforce {
		score = 95
	}
	sig := signal.NewSignal(
		signal.ProducerKLIQ,
		signal.ScopeLocal,
		signal.SignalGraphNewEdgeAfterFreeze,
		e.Source,
	).
		SetObject(e.Destination).
		SetScore(score).
		SetConfidence(80).
		SetTTL(30*time.Minute).
		AddReasonCode("graph_new_edge_after_freeze").
		SetAttribute("node_id", e.NodeID).
		SetAttribute("protocol", e.Protocol).
		SetAttribute("destination_port", strconv.Itoa(int(e.DestinationPort)))

	_ = bus.PublishSignal(ctx, *sig)
}

// maintenanceLoop periodically promotes candidates, marks expired edges, and
// commits the pending baseline buffer.
func (a *Adapter) maintenanceLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.PromoteInterval)
	// Commit pending baseline updates more frequently (every 10s) so the 30s
	// commit delay is honoured without waiting a full PromoteInterval.
	commitTicker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer commitTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-commitTicker.C:
			a.commitPendingBaselines()
			a.susp.Evict() // lazy TTL cleanup
		case now := <-ticker.C:
			n, err := a.store.PromoteCandidates(a.cfg.NodeID, a.cfg.Promotion, now)
			if err != nil {
				logger.Printf("promote candidates: %v", err)
			} else if n > 0 {
				logger.Printf("promoted %d candidate(s) to learned", n)
			}
			// Refresh known-sources cache after promotion so newly learned edges
			// immediately protect their source IPs from isSuspicious marking.
			a.refreshKnownSources()
			if a.cfg.ExpireTTL > 0 {
				minSeen := a.cfg.Promotion.MinSeenCount
				if minSeen == 0 {
					minSeen = 5
				}
				if n, err := a.store.MarkExpired(a.cfg.NodeID, now.Add(-a.cfg.ExpireTTL), minSeen); err != nil {
					logger.Printf("mark expired: %v", err)
				} else if n > 0 {
					logger.Printf("marked %d edge(s) as expired", n)
				}
			}
		}
	}
}

// commitPendingBaselines writes ready pending updates to the store, dropping
// any whose source or edge was marked suspicious since the observation time.
func (a *Adapter) commitPendingBaselines() {
	now := time.Now()
	a.pendingMu.Lock()
	// Use a fresh backing array for `remaining` to avoid aliasing
	// `a.pendingUpdates`: appending into a sliced-down version of the same
	// backing array can overwrite entries we still need to read in the loop.
	remaining := make([]pendingBaselineUpdate, 0, len(a.pendingUpdates))
	ready := make([]pendingBaselineUpdate, 0, len(a.pendingUpdates))
	for _, u := range a.pendingUpdates {
		if now.Before(u.CommitAt) {
			remaining = append(remaining, u) // not ready yet
		} else {
			ready = append(ready, u)
		}
	}
	// Replace slice with only the not-yet-ready entries.
	if len(remaining) == 0 {
		a.pendingUpdates = a.pendingUpdates[:0]
	} else {
		a.pendingUpdates = remaining
	}
	a.pendingMu.Unlock()

	alphaBootstrap := a.cfg.BaselineAlphaBootstrap
	if alphaBootstrap <= 0 {
		alphaBootstrap = 0.10
	}
	alpha := a.cfg.BaselineAlpha
	if alpha <= 0 {
		alpha = 0.1
	}
	minObs := a.cfg.BaselineMinObservations
	if minObs == 0 {
		minObs = 30
	}

	committed, dropped := 0, 0
	for _, u := range ready {
		// Drop if source became suspicious after we observed this packet.
		if a.susp.WasSourceSuspiciousSince(u.Key.SourceID, u.ObservedAt) {
			dropped++
			continue
		}
		// Drop if the specific edge became suspicious (freeze violation, Sprint 4).
		edgeKey := suspicious.EdgeKey{
			SourceID:        u.Key.SourceID,
			DestinationID:   u.Key.DestinationID,
			Protocol:        u.Key.Protocol,
			DestinationPort: u.Key.DestinationPort,
		}
		if a.susp.WasEdgeSuspiciousSince(edgeKey, u.ObservedAt) {
			dropped++
			continue
		}
		if err := a.store.UpdateEdgeBaselineDecay(
			u.Key, u.PPS, u.BPS,
			alpha, alphaBootstrap,
			minObs, a.cfg.BaselineMinObsTimeBased,
			a.cfg.BaselineMinAge,
			a.cfg.BaselinePeakDecayHalfLife,
		); err != nil {
			logger.Printf("pending baseline commit %s→%s: %v", u.Key.SourceID, u.Key.DestinationID, err)
		} else {
			committed++
		}
	}
	if committed+dropped > 0 {
		logger.Printf("baseline commit: committed=%d dropped=%d (anti-poisoning)", committed, dropped)
	}
}

// directionFor infers the flow direction from the observation subject IP.
// Egress: source is a private/local address. Ingress: otherwise.
func directionFor(obs observation.Observation) graph.Direction {
	if obs.Subject.Kind != observation.KindIP {
		return graph.DirectionEgress
	}
	ip := net.ParseIP(obs.Subject.ID)
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		return graph.DirectionEgress
	}
	return graph.DirectionIngress
}

func isLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

func isInCIDRs(addr string, cidrs []net.IPNet) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for i := range cidrs {
		if cidrs[i].Contains(ip) {
			return true
		}
	}
	return false
}

func isBroadcastOrMulticast(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsMulticast() || ip.Equal(net.IPv4bcast)
}
