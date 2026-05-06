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

// Mode controls how the learner behaves.
type Mode string

const (
	// ModeLearn accumulates edges and promotes candidates to learned.
	ModeLearn Mode = "learn"
	// ModeFrozenObserve: new edges after freeze emit a signal; no enforcement.
	ModeFrozenObserve Mode = "frozen-observe"
)

// Store is the interface the adapter needs from a graph edge store.
type Store interface {
	Upsert(e *graph.Edge) (*graph.Edge, error)
	GetByKey(key graph.EdgeKey) (*graph.Edge, error)
	PromoteCandidates(nodeID string, cfg graph.PromotionConfig, now time.Time) (int, error)
	MarkExpired(nodeID string, cutoff time.Time) (int, error)
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
}

// Adapter is the graph learner adapter.
type Adapter struct {
	cfg     Config
	store   Store
	healthy atomic.Bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New creates a new graph learner adapter.
func New(cfg Config, store Store) *Adapter {
	a := &Adapter{cfg: cfg, store: store}
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

// Start begins consuming observations from the bus and maintaining the graph.
func (a *Adapter) Start(ctx context.Context, bus adapterruntime.EventBus) error {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.healthy.Store(true)

	a.wg.Add(1)
	go a.observationLoop(ctx, bus)

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

	// In frozen-observe mode, signal any edge that is not already known.
	if a.cfg.Mode == ModeFrozenObserve &&
		current.State == graph.EdgeCandidate &&
		current.SeenCount == 1 {
		a.emitNewEdgeSignal(ctx, bus, current)
	}
}

// emitNewEdgeSignal publishes a graph.new_edge_after_freeze signal onto the bus.
func (a *Adapter) emitNewEdgeSignal(ctx context.Context, bus adapterruntime.EventBus, e *graph.Edge) {
	sig := signal.NewSignal(
		signal.ProducerKLIQ,
		signal.ScopeLocal,
		signal.SignalGraphNewEdgeAfterFreeze,
		e.Source,
	).
		SetObject(e.Destination).
		SetScore(70).
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
				log.Printf("graph-learner: promote candidates: %v", err)
			} else if n > 0 {
				log.Printf("graph-learner: promoted %d candidate(s) to learned", n)
			}
			if a.cfg.ExpireTTL > 0 {
				if n, err := a.store.MarkExpired(a.cfg.NodeID, now.Add(-a.cfg.ExpireTTL)); err != nil {
					log.Printf("graph-learner: mark expired: %v", err)
				} else if n > 0 {
					log.Printf("graph-learner: marked %d edge(s) as expired", n)
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

func isBroadcastOrMulticast(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsMulticast() || ip.Equal(net.IPv4bcast)
}
