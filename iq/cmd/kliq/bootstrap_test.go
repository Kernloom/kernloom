// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- bootstrapConfigHash ----

func TestBootstrapConfigHash_Stable(t *testing.T) {
	c := cfg{
		BPFfsRoot:       "/sys/fs/bpf",
		BootstrapWindow: 14 * 24 * time.Hour,
		AutoFloorPPS:    100,
		AutoFloorSyn:    50,
		AutoFloorScan:   20,
		AutoFloorBPS:    0,
	}
	h1 := bootstrapConfigHash(&c)
	h2 := bootstrapConfigHash(&c)
	if h1 != h2 {
		t.Fatalf("hash not stable: %q vs %q", h1, h2)
	}
	if len(h1) == 0 {
		t.Fatal("empty hash")
	}
}

func TestBootstrapConfigHash_ChangesOnInterface(t *testing.T) {
	base := cfg{BPFfsRoot: "/sys/fs/bpf", BootstrapWindow: 14 * 24 * time.Hour, AutoFloorPPS: 100}
	other := base
	other.BPFfsRoot = "/sys/fs/bpf2"
	if bootstrapConfigHash(&base) == bootstrapConfigHash(&other) {
		t.Fatal("hash should change when BPFfsRoot changes")
	}
}

func TestBootstrapConfigHash_ChangesOnFloor(t *testing.T) {
	base := cfg{BPFfsRoot: "/sys/fs/bpf", BootstrapWindow: 14 * 24 * time.Hour, AutoFloorPPS: 100}
	other := base
	other.AutoFloorPPS = 200
	if bootstrapConfigHash(&base) == bootstrapConfigHash(&other) {
		t.Fatal("hash should change when AutoFloorPPS changes")
	}
}

// ---- bootstrapEffective with observed_seconds ----

func bootstrapInfoForTest(observed uint64, startedAt time.Time) bootstrapInfo {
	return bootstrapInfo{
		Enabled:         true,
		StartedAt:       startedAt,
		Window:          "336h",
		Phase:           "bootstrap-1",
		ObservedSeconds: observed,
	}
}

func defaultBootstrapPolicy() (time.Duration, time.Duration, time.Duration,
	time.Duration, time.Duration, time.Duration,
	float64, float64,
	float64, float64, float64, float64, float64, float64,
	float64, float64, float64,
	time.Duration, float64, float64, float64, float64,
) {
	window := 336 * time.Hour
	p1End := 48 * time.Hour
	p2End := 120 * time.Hour
	every1, every2, every3 := time.Hour, 6*time.Hour, 24*time.Hour
	kStart, kFinal := 4.0, 3.5
	maxUp1, maxDown1 := 0.10, 0.10
	maxUp2, maxDown2 := 0.08, 0.08
	maxUp3, maxDown3 := 0.05, 0.05
	alpha1, alpha2, alpha3 := 0.10, 0.15, 0.20
	steadyEvery := 84 * time.Hour
	steadyK, steadyUp, steadyDown, steadyAlpha := 3.5, 0.05, 0.05, 0.20
	return window, p1End, p2End, every1, every2, every3,
		kStart, kFinal, maxUp1, maxDown1, maxUp2, maxDown2, maxUp3, maxDown3,
		alpha1, alpha2, alpha3, steadyEvery, steadyK, steadyUp, steadyDown, steadyAlpha
}

func callBootstrapEffective(now time.Time, info bootstrapInfo) bootstrapPolicy {
	w, p1, p2, e1, e2, e3, ks, kf,
		mu1, md1, mu2, md2, mu3, md3,
		a1, a2, a3, se, sk, su, sd, sa := defaultBootstrapPolicy()
	return bootstrapEffective(now, info, w, p1, p2, e1, e2, e3, ks, kf,
		mu1, md1, mu2, md2, mu3, md3, a1, a2, a3, se, sk, su, sd, sa)
}

func TestBootstrapEffective_UsesObservedSeconds(t *testing.T) {
	// Bootstrap started 3 days ago wall-clock, but only 1 hour was observed.
	startedAt := time.Now().Add(-72 * time.Hour)
	info := bootstrapInfoForTest(3600, startedAt) // 1h observed

	pol := callBootstrapEffective(time.Now(), info)

	if !pol.Active {
		t.Fatal("bootstrap should still be active (only 1h observed)")
	}
	if pol.Phase != "bootstrap-1" {
		t.Fatalf("expected bootstrap-1 (1h observed < 48h), got %q", pol.Phase)
	}
}

func TestBootstrapEffective_WallClockFallbackWithoutObserved(t *testing.T) {
	// Old state file: ObservedSeconds == 0 → fall back to wall-clock.
	// StartedAt 60 hours ago → should be in bootstrap-2 (>48h).
	startedAt := time.Now().Add(-60 * time.Hour)
	info := bootstrapInfo{
		Enabled:         true,
		StartedAt:       startedAt,
		ObservedSeconds: 0, // no observed seconds → wall-clock fallback
	}
	pol := callBootstrapEffective(time.Now(), info)
	if pol.Phase != "bootstrap-2" {
		t.Fatalf("expected bootstrap-2 with wall-clock fallback, got %q", pol.Phase)
	}
}

func TestBootstrapEffective_Phase1At1HourObserved(t *testing.T) {
	// 1 hour observed → phase 1 (0–48h)
	info := bootstrapInfoForTest(3600, time.Now())
	pol := callBootstrapEffective(time.Now(), info)
	if pol.Phase != "bootstrap-1" {
		t.Fatalf("expected bootstrap-1 at 1h observed, got %q", pol.Phase)
	}
}

func TestBootstrapEffective_Phase2At50HoursObserved(t *testing.T) {
	// 50 hours observed → phase 2 (48h–120h)
	info := bootstrapInfoForTest(50*3600, time.Now())
	pol := callBootstrapEffective(time.Now(), info)
	if pol.Phase != "bootstrap-2" {
		t.Fatalf("expected bootstrap-2 at 50h observed, got %q", pol.Phase)
	}
}

func TestBootstrapEffective_SteadyAfterWindow(t *testing.T) {
	// 337 hours observed → past the 336h window → steady
	info := bootstrapInfoForTest(337*3600, time.Now())
	pol := callBootstrapEffective(time.Now(), info)
	if pol.Active {
		t.Fatalf("expected steady (inactive) after window, got phase=%q active=%v", pol.Phase, pol.Active)
	}
}

func TestBootstrapEffective_OfflineTimeDoeNotCount(t *testing.T) {
	// kliq ran 20 minutes, was offline for 5 days, came back.
	// Wall-clock: 5 days → would think bootstrap-3 or steady.
	// Observed: 1200s (20 min) → should be bootstrap-1.
	startedAt := time.Now().Add(-5 * 24 * time.Hour)
	info := bootstrapInfoForTest(1200, startedAt)
	pol := callBootstrapEffective(time.Now(), info)
	if !pol.Active || pol.Phase != "bootstrap-1" {
		t.Fatalf("offline time should not count: expected active bootstrap-1, got phase=%q active=%v",
			pol.Phase, pol.Active)
	}
}

// ---- state.json: ObservedSeconds persists across load/save ----

func TestObservedSecondsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st := &stateFile{
		Version: 2,
		Active: stateActive{
			Profile:    "test",
			ConfigHash: "abc123",
			Bootstrap: bootstrapInfo{
				Enabled:         true,
				StartedAt:       time.Now().Add(-time.Hour),
				ObservedSeconds: 1800,
				Phase:           "bootstrap-1",
			},
			Trig: trigState{TrigPPS: 200, TrigSyn: 50, TrigScan: 10},
		},
	}

	if err := writeStateAtomic(path, st); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := loadState(path, 0)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Active.Bootstrap.ObservedSeconds != 1800 {
		t.Fatalf("observed_seconds not preserved: got %d", loaded.Active.Bootstrap.ObservedSeconds)
	}
	if loaded.Active.ConfigHash != "abc123" {
		t.Fatalf("config_hash not preserved: got %q", loaded.Active.ConfigHash)
	}
}

func TestObservedSecondsIncrementsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Simulate first run: 1800s observed.
	st := &stateFile{
		Version: 2,
		Active: stateActive{
			Bootstrap: bootstrapInfo{
				Enabled:         true,
				StartedAt:       time.Now().Add(-time.Hour),
				ObservedSeconds: 1800,
				Phase:           "bootstrap-1",
			},
			Trig: trigState{TrigPPS: 200},
		},
	}
	if err := writeStateAtomic(path, st); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Simulate restart: load and add 600 more seconds.
	loaded, err := loadState(path, 0)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded.Active.Bootstrap.ObservedSeconds += 600
	if err := writeStateAtomic(path, loaded); err != nil {
		t.Fatalf("write after restart: %v", err)
	}

	final, err := loadState(path, 0)
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	if final.Active.Bootstrap.ObservedSeconds != 2400 {
		t.Fatalf("expected 2400 observed seconds after restart, got %d", final.Active.Bootstrap.ObservedSeconds)
	}
}

// ---- Config hash invalidation ----

func TestConfigHashInvalidatesBootstrapState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	oldHash := "deadbeef00000000"
	st := &stateFile{
		Version: 2,
		Active: stateActive{
			ConfigHash: oldHash,
			Bootstrap: bootstrapInfo{
				Enabled:         true,
				StartedAt:       time.Now().Add(-time.Hour),
				ObservedSeconds: 9000,
				Phase:           "bootstrap-2",
			},
			Trig: trigState{TrigPPS: 200},
		},
	}
	if err := writeStateAtomic(path, st); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := loadState(path, 0)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Simulate config-hash mismatch (new interface or floor).
	newHash := "cafebabe00000000"
	if loaded.Active.ConfigHash != "" && loaded.Active.ConfigHash != newHash {
		loaded.Active.Bootstrap = bootstrapInfo{} // invalidate
	}

	if loaded.Active.Bootstrap.ObservedSeconds != 0 {
		t.Fatalf("bootstrap state should have been invalidated, but ObservedSeconds=%d",
			loaded.Active.Bootstrap.ObservedSeconds)
	}
}

// ---- Atomic write: .tmp file must not remain on success ----

func TestWriteStateAtomic_NoTmpLeftover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st := &stateFile{Version: 2, Active: stateActive{Trig: trigState{TrigPPS: 100}}}
	if err := writeStateAtomic(path, st); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal(".tmp file left behind after successful atomic write")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state.json not created: %v", err)
	}
}

// ---- Corrupt JSON does not crash ----

func TestLoadState_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := os.WriteFile(path, []byte("{corrupt json{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := loadState(path, 0)
	if err == nil {
		t.Fatal("expected error on corrupt JSON, got nil")
	}
	if st != nil {
		t.Fatal("expected nil state on corrupt JSON")
	}
}

// ---- Missing state file returns error, not panic ----

func TestLoadState_Missing(t *testing.T) {
	st, err := loadState("/nonexistent/path/state.json", 0)
	if err == nil {
		t.Fatal("expected error for missing state file")
	}
	if st != nil {
		t.Fatal("expected nil for missing state file")
	}
}

// ---- Schema forward compat: old state without observed_seconds loads fine ----

func TestLoadState_OldFormatNoObservedSeconds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Write a state JSON that does NOT have observed_seconds (old format).
	old := map[string]interface{}{
		"version": 1,
		"active": map[string]interface{}{
			"profile":   "ziti-controller",
			"trig":      map[string]interface{}{"trig_pps": 80.0, "trig_syn": 20.0, "trig_scan": 5.0},
			"bootstrap": map[string]interface{}{"enabled": true, "started_at": time.Now().Add(-time.Hour)},
		},
	}
	raw, _ := json.MarshalIndent(old, "", "  ")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := loadState(path, 0)
	if err != nil {
		t.Fatalf("old state format should load without error: %v", err)
	}
	// observed_seconds should be 0 (not present in old format = zero value)
	if st.Active.Bootstrap.ObservedSeconds != 0 {
		t.Fatalf("expected 0 observed_seconds for old format, got %d", st.Active.Bootstrap.ObservedSeconds)
	}
	// triggers should load correctly
	if st.Active.Trig.TrigPPS != 80.0 {
		t.Fatalf("expected TrigPPS=80.0, got %f", st.Active.Trig.TrigPPS)
	}
}
