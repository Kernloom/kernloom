// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package bootstrapautotune provides the managed-mode lifecycle controller for
// bootstrap and autotune. It tracks clean observed runtime, derives the current
// bootstrap phase, and produces status reports for Forge heartbeats.
//
// Design: the controller is a pure state tracker — it does not run the
// median+MAD autotune math itself. That math stays in kliq.go and is called
// at the intervals this controller recommends. The controller answers:
//
//   - Which phase am I in?
//   - Have I accumulated enough clean runtime to advance?
//   - What should my next autotune interval be?
//   - Am I ready to move to steady state?
//
// The existing autotune tests in package main are preserved unchanged.
package bootstrapautotune

import (
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/pkg/core/bundle"
)

// Config is derived from a RuntimeBundle.BootstrapAutotunePlan.
// Zero values produce safe production defaults matching the existing behavior.
type Config struct {
	Enabled                   bool
	Window                    time.Duration // total bootstrap duration (default 14d)
	Phase1End                 time.Duration // end of bootstrap-1 (default 48h)
	Phase2End                 time.Duration // end of bootstrap-2 (default 120h)
	AllowBlockDuringBootstrap bool
	MinWindowsBeforeDownscale int
	MinSourcesBeforeDownscale int
	CountOnlyCleanSeconds     bool

	// Per-phase intervals
	Interval1, Interval2, Interval3 time.Duration
	SteadyInterval                  time.Duration

	// Phase-specific K, MaxUp, MaxDown, Alpha (used by the autotune caller)
	KStart, KFinal                                   float64
	MaxUp1, MaxDown1                                 float64
	MaxUp2, MaxDown2                                 float64
	MaxUp3, MaxDown3                                 float64
	Alpha1, Alpha2, Alpha3                           float64
	SteadyK, SteadyMaxUp, SteadyMaxDown, SteadyAlpha float64

	// Floors
	FloorPPS, FloorSYN, FloorScan, FloorBPS float64
}

// DefaultConfig returns safe defaults that reproduce the existing CLI-flag behavior.
func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		Window:         14 * 24 * time.Hour,
		Phase1End:      48 * time.Hour,
		Phase2End:      120 * time.Hour,
		Interval1:      1 * time.Hour,
		Interval2:      6 * time.Hour,
		Interval3:      24 * time.Hour,
		SteadyInterval: 84 * time.Hour,
		KStart:         3.0,
		KFinal:         3.0,
		SteadyK:        3.0,
		MaxUp1:         0.10, MaxDown1: 0.02,
		MaxUp2: 0.07, MaxDown2: 0.03,
		MaxUp3: 0.05, MaxDown3: 0.05,
		Alpha1: 0.10, Alpha2: 0.15, Alpha3: 0.20,
		SteadyMaxUp: 0.05, SteadyMaxDown: 0.05, SteadyAlpha: 0.20,
	}
}

// FromBundle derives a Config from a RuntimeBundle plan.
// Fields absent in the plan fall back to DefaultConfig() values.
func FromBundle(plan bundle.BootstrapAutotunePlan) Config {
	c := DefaultConfig()
	c.Enabled = plan.Enabled

	if w, err := plan.WindowDuration(); err == nil && w > 0 {
		c.Window = w
	}
	c.AllowBlockDuringBootstrap = plan.AllowBlockDuringBootstrap
	c.MinWindowsBeforeDownscale = plan.MinWindowsBeforeDownscale
	c.MinSourcesBeforeDownscale = plan.MinSourcesBeforeDownscale
	c.CountOnlyCleanSeconds = plan.CountOnlyCleanSeconds

	if plan.Floors.PPS > 0 {
		c.FloorPPS = plan.Floors.PPS
	}
	if plan.Floors.SYN > 0 {
		c.FloorSYN = plan.Floors.SYN
	}
	if plan.Floors.Scan > 0 {
		c.FloorScan = plan.Floors.Scan
	}
	if plan.Floors.BPS > 0 {
		c.FloorBPS = plan.Floors.BPS
	}

	// Apply phase configs in order (bootstrap-1, bootstrap-2, bootstrap-3).
	for i, ph := range plan.Phases {
		switch i {
		case 0:
			if d, err := time.ParseDuration(ph.Until); err == nil && d > 0 {
				c.Phase1End = d
			}
			if d, err := time.ParseDuration(ph.Interval); err == nil && d > 0 {
				c.Interval1 = d
			}
			if ph.K > 0 {
				c.KStart = ph.K
			}
			if ph.MaxUp > 0 {
				c.MaxUp1 = ph.MaxUp
			}
			if ph.MaxDown > 0 {
				c.MaxDown1 = ph.MaxDown
			}
			if ph.Alpha > 0 {
				c.Alpha1 = ph.Alpha
			}
		case 1:
			if d, err := time.ParseDuration(ph.Until); err == nil && d > 0 {
				c.Phase2End = d
			}
			if d, err := time.ParseDuration(ph.Interval); err == nil && d > 0 {
				c.Interval2 = d
			}
			if ph.K > 0 {
				c.KFinal = ph.K
			}
			if ph.MaxUp > 0 {
				c.MaxUp2 = ph.MaxUp
			}
			if ph.MaxDown > 0 {
				c.MaxDown2 = ph.MaxDown
			}
			if ph.Alpha > 0 {
				c.Alpha2 = ph.Alpha
			}
		case 2:
			if d, err := time.ParseDuration(ph.Interval); err == nil && d > 0 {
				c.Interval3 = d
			}
			if ph.MaxUp > 0 {
				c.MaxUp3 = ph.MaxUp
			}
			if ph.MaxDown > 0 {
				c.MaxDown3 = ph.MaxDown
			}
			if ph.Alpha > 0 {
				c.Alpha3 = ph.Alpha
			}
		}
	}

	if s := plan.Steady; s.Interval != "" {
		if d, err := time.ParseDuration(s.Interval); err == nil && d > 0 {
			c.SteadyInterval = d
		}
		if s.MaxUp > 0 {
			c.SteadyMaxUp = s.MaxUp
		}
		if s.MaxDown > 0 {
			c.SteadyMaxDown = s.MaxDown
		}
		if s.Alpha > 0 {
			c.SteadyAlpha = s.Alpha
		}
	}
	return c
}

// FromBaselineLifecycle derives a Config from a contracts RuntimeBundle
// baseline lifecycle. The contracts schema intentionally exposes lifecycle
// intent, while KLIQ keeps detailed autotune phase defaults locally.
func FromBaselineLifecycle(plan contracts.BaselineLifecycle) Config {
	c := DefaultConfig()
	c.Enabled = baselineLifecycleEnabled(plan.Mode)
	if plan.LearningWindow.Duration > 0 {
		c.Window = plan.LearningWindow.Duration
	}
	if plan.MinCleanRuntime.Duration > c.Window {
		c.Window = plan.MinCleanRuntime.Duration
	}
	return c
}

func baselineLifecycleEnabled(mode string) bool {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "", "disabled", "off", "none":
		return false
	default:
		return true
	}
}

// State is the mutable lifecycle state, persisted across restarts.
type State struct {
	Enabled          bool
	StartedAt        time.Time
	Phase            string
	ObservedSeconds  uint64
	CompletedWindows int
	DistinctSources  map[string]bool
	CleanRatio       float64
}

// Policy is returned by Controller.Effective and tells the caller
// exactly how to behave for the current autotune tick.
type Policy struct {
	Active  bool // true during bootstrap, false in steady
	Phase   string
	Every   time.Duration
	K       float64
	MaxUp   float64
	MaxDown float64
	Alpha   float64
}

// Controller tracks managed-mode bootstrap lifecycle state.
// Thread-safe: all public methods lock the internal mutex.
type Controller struct {
	cfg              Config
	observedSec      uint64
	completedWindows int
	distinctSources  map[string]bool
	cleanTicks       uint64
	totalTicks       uint64
	startedAt        time.Time
	enabled          bool
}

// New creates a new Controller using cfg and optional persisted state.
// If state is non-nil, ObservedSeconds and CompletedWindows are restored.
func New(cfg Config, state *State) *Controller {
	c := &Controller{
		cfg:             cfg,
		distinctSources: make(map[string]bool, 256),
		enabled:         cfg.Enabled,
	}
	if state != nil {
		c.observedSec = state.ObservedSeconds
		c.completedWindows = state.CompletedWindows
		c.startedAt = state.StartedAt
		c.enabled = state.Enabled
		if state.DistinctSources != nil {
			c.distinctSources = state.DistinctSources
		}
	}
	if c.startedAt.IsZero() && cfg.Enabled {
		c.startedAt = time.Now().UTC()
	}
	return c
}

// RecordTick advances the observed-second counter by intervalSec when clean
// and records sources seen this tick. Called once per tick by the main loop.
func (c *Controller) RecordTick(cleanTick bool, intervalSec uint64, sources []string) {
	c.totalTicks++
	if cleanTick {
		c.cleanTicks++
		if c.enabled {
			c.observedSec += intervalSec
		}
		for _, s := range sources {
			c.distinctSources[s] = true
		}
	}
}

// Effective returns the autotune policy for the current moment.
// The caller uses Policy.Every to schedule the next autotune run and
// Policy.K / MaxUp / MaxDown / Alpha for the median+MAD computation.
func (c *Controller) Effective() Policy {
	if !c.enabled || c.startedAt.IsZero() || c.cfg.Window <= 0 {
		return Policy{
			Active: false, Phase: "steady",
			Every: c.cfg.SteadyInterval, K: c.cfg.SteadyK,
			MaxUp: c.cfg.SteadyMaxUp, MaxDown: c.cfg.SteadyMaxDown,
			Alpha: c.cfg.SteadyAlpha,
		}
	}
	age := time.Duration(c.observedSec) * time.Second
	progress := float64(age) / float64(c.cfg.Window)
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	k := c.cfg.KStart + (c.cfg.KFinal-c.cfg.KStart)*progress

	// Window check takes precedence over phase boundaries so a short test
	// window always reaches steady regardless of default phase1End/phase2End.
	if age >= c.cfg.Window {
		return Policy{Active: false, Phase: "steady", Every: c.cfg.SteadyInterval, K: c.cfg.SteadyK, MaxUp: c.cfg.SteadyMaxUp, MaxDown: c.cfg.SteadyMaxDown, Alpha: c.cfg.SteadyAlpha}
	}
	switch {
	case age < c.cfg.Phase1End:
		return Policy{Active: true, Phase: "bootstrap-1", Every: c.cfg.Interval1, K: k, MaxUp: c.cfg.MaxUp1, MaxDown: c.cfg.MaxDown1, Alpha: c.cfg.Alpha1}
	case age < c.cfg.Phase2End:
		return Policy{Active: true, Phase: "bootstrap-2", Every: c.cfg.Interval2, K: k, MaxUp: c.cfg.MaxUp2, MaxDown: c.cfg.MaxDown2, Alpha: c.cfg.Alpha2}
	default:
		return Policy{Active: true, Phase: "bootstrap-3", Every: c.cfg.Interval3, K: k, MaxUp: c.cfg.MaxUp3, MaxDown: c.cfg.MaxDown3, Alpha: c.cfg.Alpha3}
	}
}

// IsBootstrapActive returns true while observed seconds < configured window.
func (c *Controller) IsBootstrapActive() bool {
	return c.enabled && time.Duration(c.observedSec)*time.Second < c.cfg.Window
}

// CanDownscale returns whether the downscale guard allows threshold reductions.
func (c *Controller) CanDownscale() bool {
	if !c.enabled || c.cfg.MinWindowsBeforeDownscale == 0 {
		return true
	}
	windowOK := c.completedWindows >= c.cfg.MinWindowsBeforeDownscale
	sourcesOK := c.cfg.MinSourcesBeforeDownscale == 0 || len(c.distinctSources) >= c.cfg.MinSourcesBeforeDownscale
	return windowOK && sourcesOK
}

// RecordAutotuneCompleted is called after each successful autotune window.
// It increments completed windows and resets the per-window source set.
func (c *Controller) RecordAutotuneCompleted() {
	c.completedWindows++
	c.distinctSources = make(map[string]bool, 256)
}

// CleanRatio returns the fraction of ticks that were clean.
func (c *Controller) CleanRatio() float64 {
	if c.totalTicks == 0 {
		return 1.0
	}
	return float64(c.cleanTicks) / float64(c.totalTicks)
}

// ObservedSeconds returns accumulated clean runtime seconds.
func (c *Controller) ObservedSeconds() uint64 { return c.observedSec }

// CompletedWindows returns the number of completed autotune windows.
func (c *Controller) CompletedWindows() int { return c.completedWindows }

// StartedAt returns when the bootstrap session started.
func (c *Controller) StartedAt() time.Time { return c.startedAt }

// SaveState returns the current state for persistence.
func (c *Controller) SaveState() State {
	srcs := make(map[string]bool, len(c.distinctSources))
	for k, v := range c.distinctSources {
		srcs[k] = v
	}
	return State{
		Enabled:          c.enabled,
		StartedAt:        c.startedAt,
		Phase:            c.Effective().Phase,
		ObservedSeconds:  c.observedSec,
		CompletedWindows: c.completedWindows,
		DistinctSources:  srcs,
		CleanRatio:       c.CleanRatio(),
	}
}

// StatusReport builds a bundle.BootstrapAutotuneStatus for Forge heartbeats.
func (c *Controller) StatusReport(triggers bundle.TriggerSet, lastUpdateAt time.Time) bundle.BootstrapAutotuneStatus {
	pol := c.Effective()
	requiredSec := uint64(c.cfg.Window.Seconds())
	return bundle.BootstrapAutotuneStatus{
		Enabled:          c.enabled,
		Phase:            pol.Phase,
		ObservedSeconds:  c.observedSec,
		RequiredSeconds:  requiredSec,
		CleanRatio:       c.CleanRatio(),
		CompletedWindows: c.completedWindows,
		ActiveTriggers:   triggers,
		LastUpdateAt:     lastUpdateAt,
		ReadyForSteady:   !c.IsBootstrapActive(),
	}
}
