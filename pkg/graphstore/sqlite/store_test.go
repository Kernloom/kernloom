// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package sqlite_test

import (
	"testing"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	gstore "github.com/adrianenderlin/kernloom/pkg/graphstore/sqlite"
)

func openStore(t *testing.T) *gstore.Store {
	t.Helper()
	s, err := gstore.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeEdge(nodeID, srcIP, dstIP string, port uint16, now time.Time) *graph.Edge {
	return graph.NewEdge(
		nodeID,
		observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
		observation.EntityRef{Kind: observation.KindIP, ID: dstIP},
		"tcp", port, graph.DirectionEgress, now,
	)
}

func TestStore_UpsertAndGetByKey(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	e := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now)
	e.PacketsTotal = 10
	e.BytesTotal = 1024

	got, err := s.Upsert(e)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got.ID != e.ID {
		t.Errorf("id mismatch: want %s got %s", e.ID, got.ID)
	}
	if got.SeenCount != 1 {
		t.Errorf("seen_count: want 1 got %d", got.SeenCount)
	}
}

func TestStore_Upsert_Merges(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	e := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now)
	e.PacketsTotal = 5
	e.SeenCount = 1
	e.DistinctWindows = 1

	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	e2 := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now.Add(time.Minute))
	e2.PacketsTotal = 7
	e2.SeenCount = 1
	e2.DistinctWindows = 1

	got, err := s.Upsert(e2)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if got.SeenCount != 2 {
		t.Errorf("seen_count: want 2 got %d", got.SeenCount)
	}
	if got.PacketsTotal != 12 {
		t.Errorf("packets_total: want 12 got %d", got.PacketsTotal)
	}
	if got.DistinctWindows != 2 {
		t.Errorf("distinct_windows: want 2 got %d", got.DistinctWindows)
	}
}

func TestStore_ListByNode(t *testing.T) {
	s := openStore(t)
	now := time.Now()

	for _, port := range []uint16{80, 443, 5432} {
		e := makeEdge("node-1", "1.2.3.4", "10.0.0.1", port, now)
		if _, err := s.Upsert(e); err != nil {
			t.Fatalf("upsert port %d: %v", port, err)
		}
	}
	// different node
	e := makeEdge("node-2", "1.2.3.4", "10.0.0.1", 80, now)
	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("upsert node-2: %v", err)
	}

	edges, err := s.ListByNode("node-1", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(edges) != 3 {
		t.Errorf("want 3 edges for node-1, got %d", len(edges))
	}
}

func TestStore_PromoteCandidates(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	old := now.Add(-20 * time.Minute)

	cfg := graph.PromotionConfig{
		MinSeenCount:       5,
		MinDistinctWindows: 3,
		MinFirstSeenAge:    10 * time.Minute,
	}

	// ready to promote
	e := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, old)
	e.SeenCount = 10
	e.DistinctWindows = 5
	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// not ready (too young)
	e2 := makeEdge("node-1", "5.6.7.8", "10.0.0.1", 443, now)
	e2.SeenCount = 10
	e2.DistinctWindows = 5
	if _, err := s.Upsert(e2); err != nil {
		t.Fatalf("upsert e2: %v", err)
	}

	promoted, err := s.PromoteCandidates("node-1", cfg, now)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if promoted != 1 {
		t.Errorf("want 1 promoted, got %d", promoted)
	}

	got, err := s.GetByKey(e.Key())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != graph.EdgeLearned {
		t.Errorf("want EdgeLearned, got %s", got.State)
	}
}

func TestStore_MarkExpired(t *testing.T) {
	s := openStore(t)
	now := time.Now()

	old := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now.Add(-48*time.Hour))
	if _, err := s.Upsert(old); err != nil {
		t.Fatal(err)
	}
	recent := makeEdge("node-1", "9.9.9.9", "10.0.0.1", 80, now)
	if _, err := s.Upsert(recent); err != nil {
		t.Fatal(err)
	}

	cutoff := now.Add(-24 * time.Hour)
	n, err := s.MarkExpired("node-1", cutoff)
	if err != nil {
		t.Fatalf("mark expired: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 expired, got %d", n)
	}

	got, err := s.GetByKey(old.Key())
	if err != nil {
		t.Fatal(err)
	}
	if got.State != graph.EdgeExpired {
		t.Errorf("want expired, got %s", got.State)
	}
}

func TestStore_Upsert_ExpiredRestartsLearning(t *testing.T) {
	s := openStore(t)
	now := time.Now()

	// Create an edge and mark it expired (simulates attack suppression).
	e := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now.Add(-1*time.Hour))
	e.SeenCount = 40
	e.DistinctWindows = 20
	e.PacketsTotal = 4000
	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	if _, err := s.MarkExpired("node-1", now); err != nil {
		t.Fatalf("mark expired: %v", err)
	}

	// Verify it is expired.
	got, _ := s.GetByKey(e.Key())
	if got.State != graph.EdgeExpired {
		t.Fatalf("expected expired, got %s", got.State)
	}

	// New observation arrives after the false-positive window — traffic resumed.
	e2 := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now.Add(10*time.Minute))
	e2.SeenCount = 1
	e2.DistinctWindows = 1
	e2.PacketsTotal = 5
	got2, err := s.Upsert(e2)
	if err != nil {
		t.Fatalf("re-upsert after expire: %v", err)
	}

	// State must be reset to candidate — learning starts fresh.
	if got2.State != graph.EdgeCandidate {
		t.Errorf("expected candidate after re-upsert on expired, got %s", got2.State)
	}
	// Counters must be fresh, not accumulated from the old expired values.
	if got2.SeenCount != 1 {
		t.Errorf("expected seen_count=1 (fresh start), got %d", got2.SeenCount)
	}
	if got2.PacketsTotal != 5 {
		t.Errorf("expected packets_total=5 (fresh start), got %d", got2.PacketsTotal)
	}
}

func TestStore_Upsert_DeniedNotOverwritten(t *testing.T) {
	s := openStore(t)
	now := time.Now()

	e := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now)
	e.State = graph.EdgeDenied
	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("upsert denied: %v", err)
	}

	// New observation must not reset a denied edge.
	e2 := makeEdge("node-1", "1.2.3.4", "10.0.0.1", 443, now.Add(time.Minute))
	got, err := s.Upsert(e2)
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if got.State != graph.EdgeDenied {
		t.Errorf("denied edge must not be overwritten, got %s", got.State)
	}
}

func TestStore_ExpireCandidatesBySource(t *testing.T) {
	s := openStore(t)
	now := time.Now()

	// Two candidate edges from the same source IP.
	e1 := makeEdge("node-1", "5.5.5.5", "10.0.0.1", 80, now)
	e2 := makeEdge("node-1", "5.5.5.5", "10.0.0.1", 443, now)
	// One from a different source — must not be touched.
	e3 := makeEdge("node-1", "6.6.6.6", "10.0.0.1", 80, now)

	for _, e := range []*graph.Edge{e1, e2, e3} {
		if _, err := s.Upsert(e); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	n, err := s.ExpireCandidatesBySource("node-1", "5.5.5.5")
	if err != nil {
		t.Fatalf("expire by source: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 expired, got %d", n)
	}

	// e3 must still be candidate.
	got, _ := s.GetByKey(e3.Key())
	if got.State != graph.EdgeCandidate {
		t.Errorf("unrelated edge should stay candidate, got %s", got.State)
	}
}

func TestStore_Stats(t *testing.T) {
	s := openStore(t)
	now := time.Now()

	e1 := makeEdge("node-1", "1.1.1.1", "10.0.0.1", 443, now)
	if _, err := s.Upsert(e1); err != nil {
		t.Fatal(err)
	}
	e2 := makeEdge("node-1", "2.2.2.2", "10.0.0.1", 80, now)
	e2.State = graph.EdgeLearned
	if _, err := s.Upsert(e2); err != nil {
		t.Fatal(err)
	}

	stats, err := s.Stats("node-1")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats[graph.EdgeCandidate] != 1 {
		t.Errorf("want 1 candidate, got %d", stats[graph.EdgeCandidate])
	}
	if stats[graph.EdgeLearned] != 1 {
		t.Errorf("want 1 learned, got %d", stats[graph.EdgeLearned])
	}
}
