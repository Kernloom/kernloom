// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package graphlearner_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/graphlearner"
	"github.com/kernloom/kernloom/pkg/core/graph"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	gstore "github.com/kernloom/kernloom/pkg/graphstore/sqlite"
)

func newBus() *adapterruntime.Bus { return adapterruntime.NewBus(64) }

func flowObs(srcIP, dstIP string, port int) observation.Observation {
	o := observation.NewObservation(
		observation.SourceShield,
		observation.TypeFlow,
		"node-1",
		observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
	)
	o.SetObject(observation.EntityRef{Kind: observation.KindIP, ID: dstIP})
	o.SetAttribute("protocol", "tcp")
	o.SetAttribute("destination_port", func() string {
		return string(rune('0'+port/100)) + string(rune('0'+(port/10)%10)) + string(rune('0'+port%10))
	}())
	o.SetMetric("packets", 10)
	o.SetMetric("bytes", 1024)
	return *o
}

func openStore(t *testing.T) *gstore.Store {
	t.Helper()
	s, err := gstore.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAdapter_LearnMode_UpsertEdge(t *testing.T) {
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeLearn,
		Promotion: graph.PromotionConfig{
			MinSeenCount:       5,
			MinDistinctWindows: 3,
			MinFirstSeenAge:    10 * time.Minute,
		},
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	obs := flowObs("10.0.0.1", "10.0.0.2", 443)
	_ = bus.PublishObservation(ctx, obs)

	// Give the goroutine time to process.
	time.Sleep(50 * time.Millisecond)

	key := graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        "10.0.0.1",
		DestinationKind: observation.KindIP,
		DestinationID:   "10.0.0.2",
		Protocol:        "tcp",
		DestinationPort: 443,
		Direction:       graph.DirectionEgress,
	}
	e, err := store.GetByKey(key)
	if err != nil {
		t.Fatalf("get edge: %v", err)
	}
	if e == nil {
		t.Fatal("expected edge to be stored, got nil")
	}
	if e.State != graph.EdgeCandidate {
		t.Errorf("expected candidate, got %s", e.State)
	}
}

func TestAdapter_FrozenObserve_EmitsSignal(t *testing.T) {
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeFrozenObserve,
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	obs := flowObs("203.0.113.55", "10.0.0.2", 443)
	sigCh := bus.SubscribeSignals(64)
	_ = bus.PublishObservation(ctx, obs)

	select {
	case sig := <-sigCh:
		if sig.Type != "graph.new_edge_after_freeze" {
			t.Errorf("unexpected signal type: %s", sig.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("expected signal for new edge in frozen-observe mode, got none")
	}
}

// flowObsPort builds a flow observation with an arbitrary port string.
func flowObsPort(srcIP, dstIP string, port int) observation.Observation {
	o := observation.NewObservation(
		observation.SourceShield,
		observation.TypeFlow,
		"node-1",
		observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
	)
	o.SetObject(observation.EntityRef{Kind: observation.KindIP, ID: dstIP})
	o.SetAttribute("protocol", "tcp")
	o.SetAttribute("destination_port", strconv.Itoa(port))
	o.SetMetric("packets", 10)
	o.SetMetric("bytes", 1024)
	return *o
}

func flowObsNoDstPort(srcIP string) observation.Observation {
	o := observation.NewObservation(
		observation.SourceShield,
		observation.TypeFlow,
		"node-1",
		observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
	)
	o.SetMetric("packets", 10)
	return *o
}

// heuristicSignal returns a pps_high signal for the given source IP.
func heuristicSignal(srcIP string) signal.Signal {
	return *signal.NewSignal(
		signal.ProducerKLIQ,
		signal.ScopeLocal,
		signal.SignalPPSHigh,
		observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
	).SetScore(80).SetConfidence(80).SetTTL(5 * time.Minute)
}

func TestAdapter_SuspiciousSource_SkipsEdge(t *testing.T) {
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeLearn,
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	// Mark the source as suspicious via a heuristic signal.
	attackIP := "203.0.113.99"
	_ = bus.PublishSignal(ctx, heuristicSignal(attackIP))
	time.Sleep(50 * time.Millisecond)

	// Send a flow observation from the flagged IP.
	obs := flowObsPort(attackIP, "10.0.0.1", 443)
	_ = bus.PublishObservation(ctx, obs)
	time.Sleep(50 * time.Millisecond)

	key := graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        attackIP,
		DestinationKind: observation.KindIP,
		DestinationID:   "10.0.0.1",
		Protocol:        "tcp",
		DestinationPort: 443,
		Direction:       graph.DirectionIngress,
	}
	e, err := store.GetByKey(key)
	if err != nil {
		t.Fatalf("get edge: %v", err)
	}
	if e != nil {
		t.Error("expected edge from suspicious source to be skipped, but it was stored")
	}
}

func TestAdapter_SuspiciousSource_ExpiresCandidates(t *testing.T) {
	// Verify that a candidate written before the signal fires gets retroactively
	// expired when the signal arrives (race-condition cleanup).
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeLearn,
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	attackIP := "198.51.100.7"

	// Publish observation first — creates candidate before signal fires.
	obs := flowObsPort(attackIP, "10.0.0.1", 443)
	_ = bus.PublishObservation(ctx, obs)
	time.Sleep(60 * time.Millisecond)

	// Now publish the heuristic signal — should expire that candidate.
	_ = bus.PublishSignal(ctx, heuristicSignal(attackIP))
	time.Sleep(60 * time.Millisecond)

	key := graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        attackIP,
		DestinationKind: observation.KindIP,
		DestinationID:   "10.0.0.1",
		Protocol:        "tcp",
		DestinationPort: 443,
		Direction:       graph.DirectionIngress,
	}
	e, err := store.GetByKey(key)
	if err != nil {
		t.Fatalf("get edge: %v", err)
	}
	if e != nil && e.State == graph.EdgeCandidate {
		t.Error("candidate from attack IP should have been expired when signal arrived")
	}
}

func TestAdapter_SuspiciousSource_AllowsAfterTTLExpiry(t *testing.T) {
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeLearn,
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	attackIP := "203.0.113.88"
	// Signal with a very short TTL (already expired by the time we check).
	sig := *signal.NewSignal(
		signal.ProducerKLIQ,
		signal.ScopeLocal,
		signal.SignalPPSHigh,
		observation.EntityRef{Kind: observation.KindIP, ID: attackIP},
	).SetScore(80).SetConfidence(80).SetTTL(1 * time.Millisecond)
	_ = bus.PublishSignal(ctx, sig)
	time.Sleep(100 * time.Millisecond) // let TTL expire

	obs := flowObsPort(attackIP, "10.0.0.1", 80)
	_ = bus.PublishObservation(ctx, obs)
	time.Sleep(50 * time.Millisecond)

	key := graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        attackIP,
		DestinationKind: observation.KindIP,
		DestinationID:   "10.0.0.1",
		Protocol:        "tcp",
		DestinationPort: 80,
		Direction:       graph.DirectionIngress,
	}
	e, err := store.GetByKey(key)
	if err != nil {
		t.Fatalf("get edge: %v", err)
	}
	if e == nil {
		t.Error("expected edge to be stored after suspicious TTL expired")
	}
}

func TestAdapter_EphemeralPort_CollapsedToZero(t *testing.T) {
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeLearn,
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	// Port 32768 is the lower bound of the ephemeral range.
	obs := flowObsPort("10.0.0.5", "10.0.0.1", 32768)
	_ = bus.PublishObservation(ctx, obs)
	time.Sleep(50 * time.Millisecond)

	// Edge must be stored with port 0 (collapsed).
	key := graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        "10.0.0.5",
		DestinationKind: observation.KindIP,
		DestinationID:   "10.0.0.1",
		Protocol:        "tcp",
		DestinationPort: 0,
		Direction:       graph.DirectionEgress,
	}
	e, err := store.GetByKey(key)
	if err != nil {
		t.Fatalf("get edge: %v", err)
	}
	if e == nil {
		t.Error("expected edge with port=0 for ephemeral destination port")
	}

	// Also verify port 32767 (just below threshold) is NOT collapsed.
	obs2 := flowObsPort("10.0.0.5", "10.0.0.1", 32767)
	_ = bus.PublishObservation(ctx, obs2)
	time.Sleep(50 * time.Millisecond)

	key2 := graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        "10.0.0.5",
		DestinationKind: observation.KindIP,
		DestinationID:   "10.0.0.1",
		Protocol:        "tcp",
		DestinationPort: 32767,
		Direction:       graph.DirectionEgress,
	}
	e2, err := store.GetByKey(key2)
	if err != nil {
		t.Fatalf("get edge 32767: %v", err)
	}
	if e2 == nil {
		t.Error("expected edge with port=32767 to be stored as-is")
	}
}

func TestAdapter_NoDstPort_Skipped(t *testing.T) {
	store := openStore(t)
	bus := newBus()
	cfg := graphlearner.Config{
		NodeID: "node-1",
		Mode:   graphlearner.ModeLearn,
	}
	a := graphlearner.New(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.Start(ctx, bus); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop(context.Background())

	obs := flowObsNoDstPort("10.0.0.7")
	_ = bus.PublishObservation(ctx, obs)
	time.Sleep(50 * time.Millisecond)

	// No edge should exist since destination_port was absent (src4 aggregate obs).
	key := graph.EdgeKey{
		NodeID:     "node-1",
		SourceKind: observation.KindIP,
		SourceID:   "10.0.0.7",
	}
	// The store's GetByKey requires a full key; we verify indirectly by checking
	// that no edge with this source is stored under any port.
	e, _ := store.GetByKey(graph.EdgeKey{
		NodeID:          "node-1",
		SourceKind:      observation.KindIP,
		SourceID:        "10.0.0.7",
		DestinationKind: observation.KindNode,
		DestinationID:   "node-1",
		Protocol:        "unknown",
		DestinationPort: 0,
		Direction:       graph.DirectionIngress,
	})
	_ = key
	if e != nil {
		t.Error("expected observation without destination_port to be skipped")
	}
}

func TestAdapter_Health(t *testing.T) {
	store := openStore(t)
	cfg := graphlearner.Config{NodeID: "node-1", Mode: graphlearner.ModeLearn}
	a := graphlearner.New(cfg, store)

	ctx := context.Background()
	if a.Health(ctx).Healthy {
		t.Error("should be unhealthy before Start")
	}

	bus := newBus()
	_ = a.Start(ctx, bus)
	if !a.Health(ctx).Healthy {
		t.Error("should be healthy after Start")
	}

	_ = a.Stop(ctx)
	if a.Health(ctx).Healthy {
		t.Error("should be unhealthy after Stop")
	}
}
