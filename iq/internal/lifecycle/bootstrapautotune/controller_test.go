// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bootstrapautotune_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/lifecycle/bootstrapautotune"
	"github.com/kernloom/kernloom/pkg/core/bundle"
)

func TestController_DefaultPhases(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	c := bootstrapautotune.New(cfg, nil)

	// Fresh controller — phase 1.
	pol := c.Effective()
	if pol.Phase != "bootstrap-1" {
		t.Errorf("expected bootstrap-1, got %q", pol.Phase)
	}
	if !pol.Active {
		t.Error("bootstrap should be active")
	}
}

func TestController_AdvancesToSteady(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	cfg.Window = 100 * time.Second // short window for test

	state := &bootstrapautotune.State{
		Enabled:         true,
		ObservedSeconds: 101, // past the window
	}
	c := bootstrapautotune.New(cfg, state)

	pol := c.Effective()
	if pol.Phase != "steady" {
		t.Errorf("expected steady after window, got %q", pol.Phase)
	}
	if pol.Active {
		t.Error("bootstrap should not be active in steady")
	}
}

func TestController_IsBootstrapActive(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	cfg.Window = 10 * time.Second

	c := bootstrapautotune.New(cfg, nil)
	if !c.IsBootstrapActive() {
		t.Error("should be active at start")
	}

	// Record enough clean seconds to pass the window.
	for i := 0; i < 11; i++ {
		c.RecordTick(true, 1, nil)
	}
	if c.IsBootstrapActive() {
		t.Error("should not be active after window")
	}
}

func TestController_DownscaleGuard(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	cfg.MinWindowsBeforeDownscale = 3
	cfg.MinSourcesBeforeDownscale = 5

	c := bootstrapautotune.New(cfg, nil)

	// Initially blocked.
	if c.CanDownscale() {
		t.Error("downscale should be blocked initially")
	}

	// Add enough sources.
	c.RecordTick(true, 1, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"})

	// Still blocked: not enough windows.
	if c.CanDownscale() {
		t.Error("downscale still blocked: not enough windows")
	}

	// Complete 3 windows.
	c.RecordAutotuneCompleted()
	c.RecordAutotuneCompleted()
	c.RecordAutotuneCompleted()

	// Now allowed (sources reset per window, so 0 sources; only check windows).
	// Re-add sources for this window.
	c.RecordTick(true, 1, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"})
	if !c.CanDownscale() {
		t.Error("downscale should be allowed after windows and sources met")
	}
}

func TestController_CleanRatio(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	c := bootstrapautotune.New(cfg, nil)

	c.RecordTick(true, 1, nil)
	c.RecordTick(true, 1, nil)
	c.RecordTick(false, 1, nil) // dirty

	ratio := c.CleanRatio()
	if ratio < 0.66 || ratio > 0.67 {
		t.Errorf("expected clean ratio ~0.667, got %.4f", ratio)
	}
}

func TestController_SaveAndRestore(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	c := bootstrapautotune.New(cfg, nil)
	c.RecordTick(true, 3600, []string{"1.1.1.1"})
	c.RecordAutotuneCompleted()

	state := c.SaveState()

	c2 := bootstrapautotune.New(cfg, &state)
	if c2.ObservedSeconds() != 3600 {
		t.Errorf("observed seconds not restored: got %d", c2.ObservedSeconds())
	}
	if c2.CompletedWindows() != 1 {
		t.Errorf("completed windows not restored: got %d", c2.CompletedWindows())
	}
}

func TestController_FromBundle(t *testing.T) {
	plan := bundle.BootstrapAutotunePlan{
		Enabled: true,
		Window:  "48h",
		Floors:  bundle.BootstrapFloors{PPS: 200.0, SYN: 80.0},
		Phases: []bundle.BootstrapPhaseConfig{
			{Name: "bootstrap-1", Until: "12h", Interval: "30m", MaxUp: 0.15, MaxDown: 0.03, Alpha: 0.08},
		},
		Steady: bundle.SteadyAutotuneConfig{Interval: "48h", MaxUp: 0.04, MaxDown: 0.04, Alpha: 0.25},
	}
	cfg := bootstrapautotune.FromBundle(plan)

	if cfg.Window != 48*time.Hour {
		t.Errorf("Window: got %v, want 48h", cfg.Window)
	}
	if cfg.FloorPPS != 200.0 {
		t.Errorf("FloorPPS: got %.1f, want 200", cfg.FloorPPS)
	}
	if cfg.Phase1End != 12*time.Hour {
		t.Errorf("Phase1End: got %v, want 12h", cfg.Phase1End)
	}
	if cfg.Interval1 != 30*time.Minute {
		t.Errorf("Interval1: got %v, want 30m", cfg.Interval1)
	}
	if cfg.SteadyInterval != 48*time.Hour {
		t.Errorf("SteadyInterval: got %v, want 48h", cfg.SteadyInterval)
	}
}

func TestController_StatusReport(t *testing.T) {
	cfg := bootstrapautotune.DefaultConfig()
	cfg.Window = 1000 * time.Second
	c := bootstrapautotune.New(cfg, nil)
	c.RecordTick(true, 500, nil)

	triggers := bundle.TriggerSet{PPS: 420, SYN: 80, Scan: 20}
	status := c.StatusReport(triggers, time.Now())

	if !status.Enabled {
		t.Error("status.Enabled should be true")
	}
	if status.ObservedSeconds != 500 {
		t.Errorf("ObservedSeconds: got %d, want 500", status.ObservedSeconds)
	}
	if status.RequiredSeconds != 1000 {
		t.Errorf("RequiredSeconds: got %d, want 1000", status.RequiredSeconds)
	}
	if status.ReadyForSteady {
		t.Error("should not be ready for steady at 500/1000 seconds")
	}
	if status.ActiveTriggers.PPS != 420 {
		t.Errorf("trigger PPS: got %.1f", status.ActiveTriggers.PPS)
	}
}
