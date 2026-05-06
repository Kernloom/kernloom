// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package graphlearner_test

import (
	"context"
	"testing"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/adapters/graphlearner"
	"github.com/adrianenderlin/kernloom/pkg/adapterruntime"
	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	gstore "github.com/adrianenderlin/kernloom/pkg/graphstore/sqlite"
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
	_ = bus.PublishObservation(ctx, obs)

	select {
	case sig := <-bus.Signals():
		if sig.Type != "graph.new_edge_after_freeze" {
			t.Errorf("unexpected signal type: %s", sig.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("expected signal for new edge in frozen-observe mode, got none")
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
