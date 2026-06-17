// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline_test

import (
	"context"
	"testing"
	"time"

	corebaseline "github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/metricbaseline"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(sqlite.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testKey(metricID, subject string) corebaseline.Key {
	return corebaseline.Key{
		MetricID:        metricID,
		ScopeType:       "role",
		ScopeID:         "web",
		SubjectEntityID: subject,
		SourceClass:     "xdp",
		VisibilityPoint: "pre_stack_ingress",
		MeasurementType: "counter_delta",
		TruthClass:      "primary_packet_observation",
		WindowSeconds:   60,
	}
}

func TestUpdateWithBaselineKey_Learns(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 5
	e := metricbaseline.New(cfg)
	k := testKey("pps", "10.0.0.1")

	for i := 0; i < 10; i++ {
		e.UpdateWithBaselineKey(k, 100.0, metricbaseline.UpdateOptions{})
	}
	// After 10 updates with MinCount=5, profile should be promoted.
	r := e.UpdateWithBaselineKey(k, 100.0, metricbaseline.UpdateOptions{})
	if !r.Promoted {
		t.Error("expected profile to be promoted after MinCount updates")
	}
	if r.DeviationScore > 1.0 {
		t.Errorf("stable input should have near-zero deviation, got %.2f", r.DeviationScore)
	}
}

func TestUpdateWithBaselineKey_MeasurementIsolation(t *testing.T) {
	// Two keys with different TruthClass must produce independent profiles.
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 5
	e := metricbaseline.New(cfg)

	kXDP := testKey("pps", "10.0.0.1")
	kConntrack := corebaseline.Key{
		MetricID:        "pps",
		ScopeType:       "role",
		ScopeID:         "web",
		SubjectEntityID: "10.0.0.1",
		SourceClass:     "proc_net",
		VisibilityPoint: "post_xdp_conntrack",
		MeasurementType: "snapshot_gauge",
		TruthClass:      "sampled_state",
		WindowSeconds:   60,
	}

	// Train XDP profile to 1000 PPS.
	for i := 0; i < 10; i++ {
		e.UpdateWithBaselineKey(kXDP, 1000.0, metricbaseline.UpdateOptions{})
	}
	// Train conntrack profile to 10 PPS (conntrack sees less because of XDP drops).
	for i := 0; i < 10; i++ {
		e.UpdateWithBaselineKey(kConntrack, 10.0, metricbaseline.UpdateOptions{})
	}

	if e.Len() != 2 {
		t.Fatalf("want 2 independent profiles, got %d", e.Len())
	}

	// Querying XDP key with conntrack-level value should look anomalous.
	r := e.UpdateWithBaselineKey(kXDP, 10.0, metricbaseline.UpdateOptions{
		Now: time.Now(),
	})
	if !r.Promoted {
		t.Skip("profile not yet promoted; skipping deviation check")
	}
	// 10 vs 1000 should produce a noticeable deviation score.
	if r.DeviationScore < 5.0 {
		t.Errorf("expected high deviation for 10 vs 1000 PPS baseline, got %.2f", r.DeviationScore)
	}
}

func TestFlushDirtyAndLoad(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 3
	e1 := metricbaseline.New(cfg)
	k := testKey("pps", "10.1.1.1")

	for i := 0; i < 5; i++ {
		e1.UpdateWithBaselineKey(k, 500.0, metricbaseline.UpdateOptions{})
	}

	n, err := e1.FlushDirty(ctx, store)
	if err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 flushed, got %d", n)
	}

	// Load into a fresh engine.
	e2 := metricbaseline.New(cfg)
	if err := e2.LoadFromStore(ctx, store, "10.1.1.1"); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}
	if e2.Len() != 1 {
		t.Fatalf("want 1 restored profile, got %d", e2.Len())
	}
}

func TestFlushDirty_IdempotentOnSecondFlush(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	e := metricbaseline.New(metricbaseline.DefaultConfig())
	k := testKey("bps", "10.2.2.2")
	e.UpdateWithBaselineKey(k, 1024.0, metricbaseline.UpdateOptions{})

	n1, err1 := e.FlushDirty(ctx, store)
	n2, err2 := e.FlushDirty(ctx, store) // nothing new to flush

	if err1 != nil || err2 != nil {
		t.Fatalf("flush errors: %v / %v", err1, err2)
	}
	if n1 != 1 {
		t.Errorf("first flush: want 1, got %d", n1)
	}
	if n2 != 0 {
		t.Errorf("second flush: want 0 (nothing dirty), got %d", n2)
	}
}
