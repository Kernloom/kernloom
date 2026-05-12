// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"math"
	"testing"
)

// applyAutotune mirrors the autotune step in kliq.go so we can test the
// convergence behaviour without running the full main loop.
func applyAutotune(old, target, maxUp, maxDown, alpha float64, bootstrapActive bool) float64 {
	v := capChangeDir(old, target, maxUp, maxDown)
	if !bootstrapActive && alpha > 0 && alpha < 1 {
		v = old*(1-alpha) + v*alpha
	}
	return v
}

// ---- Bootstrap: no EWMA, only cap ----

func TestAutotune_Bootstrap_ConvergesWithCap(t *testing.T) {
	// With maxDown=0.10 and no EWMA in bootstrap, each cycle drops 10%.
	// From 400 to floor=80: ceil(log(80/400)/log(0.90)) = 17 cycles.
	old := 400.0
	floor := 80.0
	maxDown := 0.10
	alpha := 0.10

	for i := 0; i < 17; i++ {
		old = applyAutotune(old, floor, maxDown, maxDown, alpha, true /* bootstrapActive */)
	}

	if old > 82.0 {
		t.Fatalf("expected convergence to ~80 within 17 cycles (bootstrap), got %.2f", old)
	}
}

func TestAutotune_Bootstrap_NoEWMA(t *testing.T) {
	// In bootstrap the cap alone moves the value; EWMA must NOT apply.
	// One cycle from 400 with maxDown=0.10: expect 360, not 396.
	got := applyAutotune(400, 80, 0.10, 0.10, 0.10, true)
	want := 360.0
	if math.Abs(got-want) > 0.01 {
		t.Fatalf("bootstrap: expected %.2f (cap only), got %.2f (EWMA would give 396)", want, got)
	}
}

// ---- Steady-state: EWMA applies on top of cap ----

func TestAutotune_Steady_EWMAApplies(t *testing.T) {
	// In steady-state with alpha=0.10 and maxDown=0.05:
	// cap: 400 * 0.95 = 380; EWMA: 400*0.9 + 380*0.1 = 360 + 38 = 398
	got := applyAutotune(400, 80, 0.05, 0.05, 0.10, false)
	want := 398.0
	if math.Abs(got-want) > 0.01 {
		t.Fatalf("steady: expected %.2f (cap+EWMA), got %.2f", want, got)
	}
}

func TestAutotune_Steady_SlowerThanBootstrap(t *testing.T) {
	// Steady-state converges slower than bootstrap because EWMA damps each step.
	bootstrapVal := 400.0
	steadyVal := 400.0
	floor := 80.0

	for i := 0; i < 17; i++ {
		bootstrapVal = applyAutotune(bootstrapVal, floor, 0.10, 0.10, 0.10, true)
		steadyVal = applyAutotune(steadyVal, floor, 0.05, 0.05, 0.20, false)
	}

	if bootstrapVal >= steadyVal {
		t.Fatalf("bootstrap (%.2f) should converge faster than steady (%.2f) after 17 cycles", bootstrapVal, steadyVal)
	}
}

// ---- Upward convergence: same in both modes (target > old) ----

func TestAutotune_UpwardSameInBothModes(t *testing.T) {
	// When target > old, maxUp cap applies in both modes.
	// Alpha in steady would slow it down, but upward is capped the same way.
	bootstrapVal := applyAutotune(100, 500, 0.10, 0.10, 0.10, true)
	// In bootstrap: cap at 100*1.10=110, no EWMA → 110
	if math.Abs(bootstrapVal-110.0) > 0.01 {
		t.Fatalf("bootstrap upward: expected 110, got %.2f", bootstrapVal)
	}

	steadyVal := applyAutotune(100, 500, 0.10, 0.10, 0.10, false)
	// In steady: cap at 110, EWMA: 100*0.9 + 110*0.1 = 90 + 11 = 101
	if math.Abs(steadyVal-101.0) > 0.01 {
		t.Fatalf("steady upward: expected 101, got %.2f", steadyVal)
	}
}

// ---- Floor is respected ----

func TestAutotune_FloorRespected(t *testing.T) {
	// capChangeDir receives the floor-clamped target; verify the floor holds.
	// target already at floor (80), old=100, maxDown=0.10: cap gives 90, floor gives 80.
	// capChangeDir(100, 80, 0.10, 0.10): lo=90, target=80 < lo → returns 90.
	// Floor is enforced by the caller (math.Max before capChangeDir), so here
	// we test that cap doesn't push below floor when target == floor.
	got := applyAutotune(100, 90, 0.10, 0.10, 0.0, true)
	if got < 90.0-0.01 {
		t.Fatalf("value went below target floor: got %.2f", got)
	}
}

// ---- Alpha=0 disables EWMA in both modes ----

func TestAutotune_AlphaZeroNoSmoothing(t *testing.T) {
	bootstrap := applyAutotune(400, 80, 0.10, 0.10, 0.0, true)
	steady := applyAutotune(400, 80, 0.10, 0.10, 0.0, false)
	if math.Abs(bootstrap-steady) > 0.01 {
		t.Fatalf("alpha=0: bootstrap (%.2f) and steady (%.2f) should be equal", bootstrap, steady)
	}
}
