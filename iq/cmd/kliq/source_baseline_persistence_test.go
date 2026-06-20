// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/sourcebaseline"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestRuntimeSourceBaselinePersistenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 20, 11, 0, 0, 0, time.UTC)
	cache := sourcebaseline.New(sourcebaseline.Config{MinObs: 2, MinUpdatePPS: 1})
	cache.Update("10.0.0.1", 100, 1000, 10, 1, false, now)
	cache.Update("10.0.0.1", 120, 1200, 12, 2, false, now.Add(2*time.Second))

	flushed, err := flushRuntimeSourceBaselines(ctx, cache, store, 2*time.Second, false)
	if err != nil {
		t.Fatalf("flush source baselines: %v", err)
	}
	if flushed != 4 {
		t.Fatalf("flushed rows = %d, want 4", flushed)
	}
	rows, err := store.ListBaselinesByScope(ctx, sourceBaselineScopeType, sourceBaselineScopeID)
	if err != nil {
		t.Fatalf("list baselines: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("stored rows = %d, want 4", len(rows))
	}

	restored := sourcebaseline.New(sourcebaseline.Config{MinObs: 2, MinUpdatePPS: 1})
	loaded, err := loadRuntimeSourceBaselines(ctx, restored, store, 2*time.Second)
	if err != nil {
		t.Fatalf("load source baselines: %v", err)
	}
	if loaded != 1 {
		t.Fatalf("loaded profiles = %d, want 1", loaded)
	}
	profile, ok := restored.Get("10.0.0.1")
	if !ok {
		t.Fatal("restored source profile missing")
	}
	if !profile.Promoted || profile.EWMAPPS == 0 || profile.EWMABPS == 0 || profile.EWMASyn == 0 || profile.EWMAScan == 0 {
		t.Fatalf("restored profile incomplete: %#v", profile)
	}

	foundPPS := false
	for _, row := range rows {
		if row.Key.MetricID == adapterruntime.MetricNetworkPacketsPerSecond && row.Key.WindowSeconds == 2 {
			foundPPS = true
			break
		}
	}
	if !foundPPS {
		t.Fatalf("stored rows did not include %s with 2s window: %#v", adapterruntime.MetricNetworkPacketsPerSecond, rows)
	}
}
