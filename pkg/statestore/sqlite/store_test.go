// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/learning"
)

func openMemStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSchema_MigratesClean(t *testing.T) {
	s := openMemStore(t)
	// Re-opening the same schema must be idempotent.
	if err := s.migrate(); err != nil {
		t.Fatalf("second migration: %v", err)
	}
}

func TestUpsertEntity_InsertAndGet(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	e := entity.Entity{
		Kind:        entity.KindIP,
		ID:          "10.0.0.1",
		Namespace:   "",
		Labels:      map[string]string{"role": "web"},
		FirstSeenAt: time.Now().Add(-time.Hour),
		LastSeenAt:  time.Now(),
	}
	if err := s.UpsertEntity(ctx, e); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetEntity(ctx, entity.KindIP, "10.0.0.1", "")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected entity, got nil")
	}
	if got.ID != "10.0.0.1" {
		t.Errorf("id: want 10.0.0.1, got %q", got.ID)
	}
	if got.Labels["role"] != "web" {
		t.Errorf("label role: want web, got %q", got.Labels["role"])
	}
}

func TestGetEntity_NotFound(t *testing.T) {
	s := openMemStore(t)
	got, err := s.GetEntity(context.Background(), entity.KindIP, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for unknown entity, got %+v", got)
	}
}

func TestUpsertBaseline_RoundTrip(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	k := baseline.Key{
		MetricID:        "pps",
		ScopeType:       "role",
		ScopeID:         "web",
		SubjectEntityID: "abc123",
		SourceClass:     "xdp",
		VisibilityPoint: "pre_stack_ingress",
		MeasurementType: "counter_delta",
		TruthClass:      "primary_packet_observation",
		WindowSeconds:   60,
	}
	row := BaselineRow{
		Key:   k,
		State: "candidate",
		EWMAState: map[string]any{
			"median": 42.5,
			"mad":    5.1,
		},
		Observations: 7,
		LastUpdated:  time.Now(),
	}
	if err := s.UpsertBaseline(ctx, row); err != nil {
		t.Fatalf("upsert baseline: %v", err)
	}

	got, err := s.GetBaseline(ctx, k)
	if err != nil {
		t.Fatalf("get baseline: %v", err)
	}
	if got == nil {
		t.Fatal("expected baseline row, got nil")
	}
	if got.Observations != 7 {
		t.Errorf("observations: want 7, got %d", got.Observations)
	}
	if got.EWMAState["median"] != 42.5 {
		t.Errorf("ewma median: want 42.5, got %v", got.EWMAState["median"])
	}
}

func TestUpsertExclusion_ActiveLookup(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	ex := learning.Exclusion{
		ID:         "exc-1",
		EntityID:   "10.0.0.99",
		EntityKind: "ip",
		Reason:     learning.ReasonEnforcementActive,
		Severity:   0.9,
		AppliesTo:  []learning.AppliesTo{learning.AppliesMetricBaseline, learning.AppliesRelationshipLearning},
		StartsAt:   time.Now().Add(-time.Minute),
		ExpiresAt:  time.Now().Add(time.Hour),
		Status:     "active",
	}
	if err := s.UpsertExclusion(ctx, ex); err != nil {
		t.Fatalf("upsert exclusion: %v", err)
	}

	list, err := s.ActiveExclusionsFor(ctx, "10.0.0.99")
	if err != nil {
		t.Fatalf("active exclusions: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 exclusion, got %d", len(list))
	}
	if list[0].Reason != learning.ReasonEnforcementActive {
		t.Errorf("reason: want %q, got %q", learning.ReasonEnforcementActive, list[0].Reason)
	}
}

func TestRevokeExclusion(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	ex := learning.Exclusion{
		ID:        "exc-rev",
		EntityID:  "10.0.0.5",
		Reason:    learning.ReasonBlocked,
		StartsAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		Status:    "active",
	}
	_ = s.UpsertExclusion(ctx, ex)
	_ = s.RevokeExclusion(ctx, "exc-rev")

	list, err := s.ActiveExclusionsFor(ctx, "10.0.0.5")
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 active exclusions after revoke, got %d", len(list))
	}
}

func TestGC_PrunesExpired(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	// Insert an exclusion that has already expired.
	ex := learning.Exclusion{
		ID:        "exc-expired",
		EntityID:  "10.0.0.7",
		Reason:    learning.ReasonBlocked,
		StartsAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
		Status:    "active",
	}
	_ = s.UpsertExclusion(ctx, ex)

	if err := s.GC(ctx); err != nil {
		t.Fatalf("GC: %v", err)
	}

	// After GC the row should be status='expired'.
	list, _ := s.ActiveExclusionsFor(ctx, "10.0.0.7")
	if len(list) != 0 {
		t.Errorf("expected 0 active exclusions after GC, got %d", len(list))
	}
}

func TestDimensionsHash_Deterministic(t *testing.T) {
	a := DimensionsHash(map[string]string{"proto": "tcp", "dport": "443"})
	b := DimensionsHash(map[string]string{"dport": "443", "proto": "tcp"})
	if a != b {
		t.Errorf("hash not deterministic: %q vs %q", a, b)
	}
	if DimensionsHash(nil) != "" {
		t.Error("nil map should return empty string")
	}
}
