// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sourcebaseline_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/sourcebaseline"
)

func TestSnapshotDirtyAndRestore(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	cache := sourcebaseline.New(sourcebaseline.Config{MinObs: 2, MinUpdatePPS: 1})
	cache.Update("10.0.0.1", 100, 1000, 10, 1, false, now)
	cache.Update("10.0.0.1", 120, 1200, 12, 2, false, now.Add(time.Second))

	dirty := cache.SnapshotDirty()
	if len(dirty) != 1 {
		t.Fatalf("dirty snapshots = %d, want 1", len(dirty))
	}
	if got := cache.SnapshotDirty(); len(got) != 0 {
		t.Fatalf("second dirty snapshot = %d, want 0", len(got))
	}

	restored := sourcebaseline.New(sourcebaseline.Config{MinObs: 2, MinUpdatePPS: 1})
	if n := restored.Restore(dirty); n != 1 {
		t.Fatalf("restored = %d, want 1", n)
	}
	profile, ok := restored.Get("10.0.0.1")
	if !ok {
		t.Fatal("restored profile missing")
	}
	if !profile.Promoted || profile.ObsCount != 2 || profile.EWMAPPS == 0 {
		t.Fatalf("restored profile mismatch: %#v", profile)
	}
	if got := restored.SnapshotDirty(); len(got) != 0 {
		t.Fatalf("restore must not mark profile dirty, got %d", len(got))
	}
}
