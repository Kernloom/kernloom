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

	"github.com/adrianenderlin/kernloom/pkg/adapterruntime"
	"github.com/adrianenderlin/kernloom/pkg/core/capability"
	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	"github.com/adrianenderlin/kernloom/pkg/core/signal"
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
	MarkExpired(nodeID string, cutoff time.Time) (int, error)
	// ExpireCandidatesBySource expires all candidate edges whose source IP
	// matches sourceID for the given node. Used to retroactively clean up
	// candidates that slipped through before the heuristic signal fired.
	ExpireCandidatesBySource(nodeID, sourceID string) (int, error)
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
}

// suspiciousEntry tracks an IP flagged by the heuristic signal engine.
type suspiciousEntry struct {
	expiresAt time.Time
}

// Adapter is the graph learner adapter.
type Adapter struct {
	cfg          Config
	store        Store
	excludeCIDRs []net.IPNet // parsed once from cfg.ExcludeSourceCIDRs
	healthy      atomic.Bool
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	suspMu     sync.Mutex
	suspicious map[string]suspiciousEntry // key: IP string
}

// New creates a new graph learner adapter.
func New(cfg Config, store Store) *Adapter {
	a := &Adapter{
		cfg:          cfg,
		store:        store,
		excludeCIDRs: cfg.ExcludeSourceCIDRs,
		suspicious:   make(map[string]suspiciousEntry),
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

	a.wg.Add(1)
	go a.signalLoop(ctx, bus)

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
func (a *Adapter) signalLoop(ctx context.Context, bus adapterruntime.EventBus) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-bus.Signals():
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
		signal.SignalSYNRateHigh,
		signal.SignalScanSuspected,
		signal.SignalRateLimitDropsSustained:
	default:
		return
	}
	if sig.Subject.ID == "" {
		return
	}
	ttl := sig.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	a.suspMu.Lock()
	a.suspicious[sig.Subject.ID] = suspiciousEntry{expiresAt: time.Now().Add(ttl)}
	a.suspMu.Unlock()

	// Expire any candidate edges that snuck through before this signal fired.
	if n, err := a.store.ExpireCandidatesBySource(a.cfg.NodeID, sig.Subject.ID); err != nil {
		logger.Printf("expire candidates for %s: %v", sig.Subject.ID, err)
	} else if n > 0 {
		logger.Printf("expired %d candidate(s) for suspicious source %s", n, sig.Subject.ID)
	}
}

// isSuspicious returns true when the given IP is currently flagged.
// Expired entries are evicted lazily on access.
func (a *Adapter) isSuspicious(ip string) bool {
	a.suspMu.Lock()
	defer a.suspMu.Unlock()
	e, ok := a.suspicious[ip]
	if !ok {
		return false
	}
	if time.Now().After(e.expiresAt) {
		delete(a.suspicious, ip)
		return false
	}
	return true
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

// maintenanceLoop periodically promotes candidates and marks expired edges.
func (a *Adapter) maintenanceLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.PromoteInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			n, err := a.store.PromoteCandidates(a.cfg.NodeID, a.cfg.Promotion, now)
			if err != nil {
				logger.Printf("promote candidates: %v", err)
			} else if n > 0 {
				logger.Printf("promoted %d candidate(s) to learned", n)
			}
			if a.cfg.ExpireTTL > 0 {
				if n, err := a.store.MarkExpired(a.cfg.NodeID, now.Add(-a.cfg.ExpireTTL)); err != nil {
					logger.Printf("mark expired: %v", err)
				} else if n > 0 {
					logger.Printf("marked %d edge(s) as expired", n)
				}
			}
		}
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
