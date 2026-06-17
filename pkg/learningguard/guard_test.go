// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package learningguard_test

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/learning"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/core/suspicious"
	"github.com/kernloom/kernloom/pkg/learningguard"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(sqlite.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newGuard(t *testing.T, susp *suspicious.Registry) *learningguard.Guard {
	t.Helper()
	cfg := learningguard.DefaultConfig()
	cfg.CacheTTL = 50 * time.Millisecond // short TTL for testing
	return learningguard.New(cfg, openStore(t), susp)
}

// ── Allow ─────────────────────────────────────────────────────────────────────

func TestCheckMetric_AllowsCleanEntity(t *testing.T) {
	g := newGuard(t, nil)
	r := g.CheckMetric(context.Background(), learning.MetricCheck{
		SubjectEntityID: "10.0.0.1",
		SourceAdapter:   "conntrack",
	})
	if r.Decision != learning.AllowLearning {
		t.Errorf("expected AllowLearning, got %q (%s)", r.Decision, r.Details)
	}
}

// ── SuspiciousRegistry bridge ────────────────────────────────────────────────

func TestCheckMetric_DeniesWhenSuspicious(t *testing.T) {
	susp := suspicious.New()
	susp.MarkSource("10.0.0.9", 5*time.Minute)

	g := newGuard(t, susp)
	r := g.CheckMetric(context.Background(), learning.MetricCheck{SubjectEntityID: "10.0.0.9"})
	if r.Decision != learning.DenyLearning {
		t.Errorf("expected DenyLearning, got %q", r.Decision)
	}
	if r.Reason != learning.ReasonSuspiciousSignal {
		t.Errorf("expected SuspiciousSignal reason, got %q", r.Reason)
	}
}

func TestCheckMetric_AllowsAfterSuspiciousExpiry(t *testing.T) {
	susp := suspicious.New()
	susp.MarkSource("10.0.0.8", 1*time.Millisecond) // expires immediately

	g := newGuard(t, susp)
	time.Sleep(5 * time.Millisecond)

	r := g.CheckMetric(context.Background(), learning.MetricCheck{SubjectEntityID: "10.0.0.8"})
	if r.Decision != learning.AllowLearning {
		t.Errorf("expected AllowLearning after expiry, got %q", r.Decision)
	}
}

// ── Enforcement exclusion ─────────────────────────────────────────────────────

func TestAddExclusion_BlocksMetricLearning(t *testing.T) {
	g := newGuard(t, nil)
	ctx := context.Background()

	ex := learning.Exclusion{
		ID:        "ex-1",
		EntityID:  "10.0.0.2",
		Reason:    learning.ReasonEnforcementActive,
		AppliesTo: []learning.AppliesTo{learning.AppliesMetricBaseline},
		StartsAt:  time.Now().Add(-time.Second),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "active",
	}
	if err := g.AddExclusion(ctx, ex); err != nil {
		t.Fatalf("AddExclusion: %v", err)
	}

	r := g.CheckMetric(ctx, learning.MetricCheck{SubjectEntityID: "10.0.0.2"})
	if r.Decision != learning.DenyLearning {
		t.Errorf("expected DenyLearning, got %q", r.Decision)
	}
}

func TestAddExclusion_DoesNotBlockOtherDimension(t *testing.T) {
	g := newGuard(t, nil)
	ctx := context.Background()

	// Exclusion only applies to metric baseline, not relationship learning.
	ex := learning.Exclusion{
		ID:        "ex-2",
		EntityID:  "10.0.0.3",
		Reason:    learning.ReasonRateLimited,
		AppliesTo: []learning.AppliesTo{learning.AppliesMetricBaseline},
		StartsAt:  time.Now().Add(-time.Second),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "active",
	}
	_ = g.AddExclusion(ctx, ex)

	r := g.CheckRelationship(ctx, learning.RelationshipCheck{
		Relationship: relationship.Relationship{SubjectEntityID: "10.0.0.3"},
	})
	if r.Decision != learning.AllowLearning {
		t.Errorf("exclusion should not apply to relationship learning, got %q", r.Decision)
	}
}

// ── Downstream contamination ──────────────────────────────────────────────────

func TestDownstreamContamination_ConntrackDeniedWhenEnforcementActive(t *testing.T) {
	// Simulate: klshield is blocking 10.0.0.5.
	// Conntrack checks the guard before updating baselines.
	g := newGuard(t, nil)
	ctx := context.Background()

	_ = g.AddExclusion(ctx, learning.Exclusion{
		ID:        "ex-downstream",
		EntityID:  "10.0.0.5",
		Reason:    learning.ReasonDownstreamCensored,
		AppliesTo: []learning.AppliesTo{learning.AppliesMetricBaseline, learning.AppliesRelationshipLearning},
		StartsAt:  time.Now().Add(-time.Second),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "active",
	})

	// conntrack adapter attempts a metric update
	r := g.CheckMetric(ctx, learning.MetricCheck{
		SubjectEntityID: "10.0.0.5",
		SourceAdapter:   "conntrack",
	})
	if r.Decision != learning.DenyLearning {
		t.Errorf("downstream conntrack should be denied, got %q", r.Decision)
	}

	// nginx adapter attempts a relationship promotion
	r2 := g.CheckRelationship(ctx, learning.RelationshipCheck{
		Relationship: relationship.Relationship{SubjectEntityID: "10.0.0.5"},
	})
	if r2.Decision != learning.DenyLearning {
		t.Errorf("downstream nginx relationship should be denied, got %q", r2.Decision)
	}
}

// ── Revoke ────────────────────────────────────────────────────────────────────

func TestRevokeExclusion_ReAllowsLearning(t *testing.T) {
	g := newGuard(t, nil)
	ctx := context.Background()

	_ = g.AddExclusion(ctx, learning.Exclusion{
		ID:        "ex-rev",
		EntityID:  "10.0.0.6",
		Reason:    learning.ReasonBlocked,
		AppliesTo: nil, // applies to all
		StartsAt:  time.Now().Add(-time.Second),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "active",
	})

	// Blocked before revoke.
	r := g.CheckMetric(ctx, learning.MetricCheck{SubjectEntityID: "10.0.0.6"})
	if r.Decision != learning.DenyLearning {
		t.Fatalf("expected DenyLearning before revoke, got %q", r.Decision)
	}

	_ = g.RevokeExclusion(ctx, "ex-rev")

	// Allowed after revoke (cache was flushed).
	r2 := g.CheckMetric(ctx, learning.MetricCheck{SubjectEntityID: "10.0.0.6"})
	if r2.Decision != learning.AllowLearning {
		t.Errorf("expected AllowLearning after revoke, got %q", r2.Decision)
	}
}

// ── SuspiciousSignal → EvidenceOnly ───────────────────────────────────────────

func TestSuspiciousSignalExclusion_ReturnsEvidenceOnly(t *testing.T) {
	g := newGuard(t, nil)
	ctx := context.Background()

	_ = g.AddExclusion(ctx, learning.Exclusion{
		ID:        "ex-signal",
		EntityID:  "10.0.0.7",
		Reason:    learning.ReasonSuspiciousSignal,
		AppliesTo: nil,
		StartsAt:  time.Now().Add(-time.Second),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "active",
	})

	r := g.CheckMetric(ctx, learning.MetricCheck{SubjectEntityID: "10.0.0.7"})
	if r.Decision != learning.EvidenceOnly {
		t.Errorf("suspicious signal should produce EvidenceOnly, got %q", r.Decision)
	}
}

// ── InMemory mode (no store) ─────────────────────────────────────────────────

func TestGuard_InMemoryOnly(t *testing.T) {
	cfg := learningguard.DefaultConfig()
	g := learningguard.New(cfg, nil, nil) // no store, no suspicious registry

	r := g.CheckMetric(context.Background(), learning.MetricCheck{SubjectEntityID: "1.2.3.4"})
	if r.Decision != learning.AllowLearning {
		t.Errorf("in-memory-only guard should allow clean entity, got %q", r.Decision)
	}
}

// ── IsExcluded ────────────────────────────────────────────────────────────────

func TestIsExcluded_ReturnsTrueForActiveExclusion(t *testing.T) {
	g := newGuard(t, nil)
	ctx := context.Background()

	_ = g.AddExclusion(ctx, learning.Exclusion{
		ID:        "ex-check",
		EntityID:  "192.168.1.5",
		Reason:    learning.ReasonEnforcementActive,
		AppliesTo: []learning.AppliesTo{learning.AppliesMetricBaseline},
		StartsAt:  time.Now().Add(-time.Second),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "active",
	})

	if !g.IsExcluded(ctx, "192.168.1.5", learning.AppliesMetricBaseline) {
		t.Error("expected IsExcluded=true")
	}
	if g.IsExcluded(ctx, "192.168.1.5", learning.AppliesRelationshipLearning) {
		t.Error("exclusion applies only to metric baseline, not relationship")
	}
}
