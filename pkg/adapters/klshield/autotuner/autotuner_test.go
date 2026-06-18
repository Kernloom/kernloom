// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package autotuner_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/klshield/autotuner"
)

func pol(every time.Duration) autotuner.Policy {
	return autotuner.Policy{
		Every: every, K: 3.0, MaxUp: 0.5, MaxDown: 0.5, Alpha: 0.3, Phase: "test",
	}
}

func cfg() autotuner.Config {
	return autotuner.Config{
		MinSamples: 10,
		FloorPPS:   50, FloorSyn: 50, FloorScan: 5, FloorBPS: 0,
	}
}

func TestAutotuner_BasicThresholdUpdate(t *testing.T) {
	initial := autotuner.Thresholds{TrigPPS: 1000, TrigSyn: 500, TrigScan: 50}
	a := autotuner.New(initial, cfg(), 1000)

	now := time.Now()
	// Feed 50 clean samples
	for i := 0; i < 50; i++ {
		a.RecordSample(200, 100, 10, 0, "10.0.0.1", true)
	}

	// First tick fires (lastTune=zero → any interval exceeded).
	result, ok := a.Tick(now, pol(time.Minute), 1.0)
	if !ok {
		t.Fatal("first tick should fire (lastTune starts at zero)")
	}
	if result.SampleCount < 50 {
		t.Errorf("sample count = %d, want ≥50", result.SampleCount)
	}

	// Tick too soon — should NOT fire.
	_, ok = a.Tick(now.Add(30*time.Second), pol(time.Minute), 1.0)
	if ok {
		t.Error("tick should not fire before interval has elapsed")
	}

	// Feed more samples; tick is now due.
	for i := 0; i < 50; i++ {
		a.RecordSample(200, 100, 10, 0, "10.0.0.1", true)
	}
	result, ok = a.Tick(now.Add(2*time.Minute), pol(time.Minute), 1.0)
	if !ok {
		t.Fatal("tick should fire after interval")
	}
	if result.SampleCount < 50 {
		t.Errorf("sample count = %d, want ≥50", result.SampleCount)
	}
	if result.NewThresholds.TrigPPS <= 0 {
		t.Error("new TrigPPS should be > 0")
	}
	// New threshold should be based on median+MAD, floored at 50
	if result.NewThresholds.TrigPPS < 50 {
		t.Errorf("TrigPPS = %.1f, must be ≥ floor 50", result.NewThresholds.TrigPPS)
	}
}

func TestAutotuner_SkipWhenInsufficientSamples(t *testing.T) {
	a := autotuner.New(autotuner.Thresholds{TrigPPS: 1000}, cfg(), 1000)
	// Only 5 samples — below MinSamples=10
	for i := 0; i < 5; i++ {
		a.RecordSample(200, 100, 10, 0, "10.0.0.1", true)
	}
	now := time.Now().Add(2 * time.Minute)
	result, ok := a.Tick(now, pol(time.Minute), 1.0)
	if ok {
		t.Error("should not update thresholds with too few samples")
	}
	if !result.Skipped {
		t.Error("result.Skipped should be true")
	}
}

func TestAutotuner_DirtyTicksNotLearned(t *testing.T) {
	initial := autotuner.Thresholds{TrigPPS: 1000}
	a := autotuner.New(initial, cfg(), 1000)
	// Feed 50 DIRTY samples (clean=false)
	for i := 0; i < 50; i++ {
		a.RecordSample(999_999, 999_999, 999_999, 0, "attacker", false)
	}
	now := time.Now().Add(2 * time.Minute)
	result, ok := a.Tick(now, pol(time.Minute), 1.0)
	// Not enough clean samples → skip
	if ok {
		t.Error("dirty samples should not trigger threshold update")
	}
	_ = result
}

func TestAutotuner_DownscaleGuardPreventsDecrease(t *testing.T) {
	initial := autotuner.Thresholds{TrigPPS: 2000, TrigSyn: 1000, TrigScan: 100}
	guardCfg := autotuner.Config{
		MinSamples:                10,
		FloorPPS:                  50,
		FloorSyn:                  50,
		FloorScan:                 5,
		MinWindowsBeforeDownscale: 5, // need 5 windows before downscale
	}
	a := autotuner.New(initial, guardCfg, 1000)
	for i := 0; i < 50; i++ {
		a.RecordSample(100, 50, 5, 0, "10.0.0.1", true) // much lower than current thresholds
	}
	guardPol := autotuner.Policy{
		Active: true, // bootstrap active
		Every:  time.Minute, K: 3.0, MaxUp: 0.5, MaxDown: 0.5, Phase: "bootstrap",
	}
	result, ok := a.Tick(time.Now().Add(2*time.Minute), guardPol, 1.0)
	if !ok {
		t.Fatal("should have run autotune")
	}
	// Guard: completedWindows=0 < MinWindowsBeforeDownscale=5 → no downscale
	if result.NewThresholds.TrigPPS < initial.TrigPPS {
		t.Errorf("guard failed: TrigPPS dropped from %.1f to %.1f", initial.TrigPPS, result.NewThresholds.TrigPPS)
	}
}

func TestAutotuner_CurrentThresholds(t *testing.T) {
	initial := autotuner.Thresholds{TrigPPS: 500, TrigSyn: 200, TrigScan: 20, TrigBPS: 1e6}
	a := autotuner.New(initial, cfg(), 1000)
	got := a.CurrentThresholds()
	if got != initial {
		t.Errorf("CurrentThresholds = %+v, want %+v", got, initial)
	}
}

func TestAutotuner_CompletedWindowsIncrement(t *testing.T) {
	a := autotuner.New(autotuner.Thresholds{TrigPPS: 1000}, cfg(), 1000)
	for i := 0; i < 50; i++ {
		a.RecordSample(200, 100, 10, 0, "src", true)
	}
	now := time.Now()
	r1, ok1 := a.Tick(now.Add(time.Minute), pol(30*time.Second), 1.0)
	if !ok1 {
		t.Fatal("first tick should succeed")
	}
	if r1.CompletedWindows != 1 {
		t.Errorf("after first tick: CompletedWindows = %d, want 1", r1.CompletedWindows)
	}
	// Add more samples for second tick
	for i := 0; i < 50; i++ {
		a.RecordSample(200, 100, 10, 0, "src", true)
	}
	r2, ok2 := a.Tick(now.Add(2*time.Minute), pol(30*time.Second), 1.0)
	if !ok2 {
		t.Fatal("second tick should succeed")
	}
	if r2.CompletedWindows != 2 {
		t.Errorf("after second tick: CompletedWindows = %d, want 2", r2.CompletedWindows)
	}
}
