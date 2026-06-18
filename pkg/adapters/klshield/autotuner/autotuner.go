// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package autotuner owns the KLShield-specific autotune logic:
// reservoir sampling, median+MAD statistics, and threshold calculation
// for PPS, SYN, Scan and BPS signals.
//
// This is KLShield-domain code (network packet rates) and must not live in
// the generic KLIQ orchestrator (iq/cmd/kliq/). The orchestrator calls
// RecordSample() each tick and Tick() when an autotune window is due.
package autotuner

import (
	"math"
	"math/rand"
	"sort"
	"time"
)

// Thresholds holds the current enforcement trigger thresholds.
// Written by the autotuner; read by the KLShield signal engine
// and processCandidate4/6.
type Thresholds struct {
	TrigPPS  float64
	TrigSyn  float64
	TrigScan float64
	TrigBPS  float64
}

// Policy is the autotune scheduling policy computed per tick by the caller
// (bootstrapEffective in kliq.go). Separating policy from mechanism keeps
// the autotuner free of bootstrap phase-state management.
type Policy struct {
	Active  bool          // true during bootstrap phase
	Every   time.Duration // how often to run autotune
	K       float64       // sigma multiplier (median + K × MAD)
	MaxUp   float64       // max fractional increase per cycle (0–1)
	MaxDown float64       // max fractional decrease per cycle (0–1)
	Alpha   float64       // EWMA smoothing factor (steady state only)
	Phase   string        // human-readable phase name for logging
}

// Config holds the autotuner configuration derived from PDPConfig / kliq flags.
type Config struct {
	MinSamples                int
	FloorPPS                  float64
	FloorSyn                  float64
	FloorScan                 float64
	FloorBPS                  float64
	MinWindowsBeforeDownscale int
	MinSourcesBeforeDownscale int
}

// TickResult contains the full output of a successful autotune run.
// The caller uses it for logging and state persistence.
type TickResult struct {
	OldThresholds Thresholds
	NewThresholds Thresholds

	// Statistics used for state history and log messages.
	MedianPPS  float64
	MadPPS     float64
	MedianSyn  float64
	MadSyn     float64
	MedianScan float64
	MadScan    float64
	MedianBPS  float64
	MadBPS     float64

	SampleCount      int
	CleanRatio       float64
	CompletedWindows int
	Phase            string

	// Skipped is true when autotune ran but produced no result (not enough samples).
	Skipped    bool
	SkipReason string
}

// Autotuner tracks KLShield per-source telemetry samples and computes
// updated enforcement thresholds using reservoir sampling + median/MAD.
//
// cleanRatio (fraction of clean ticks) is owned by the main loop because it
// is a per-tick counter, not a per-sample counter. The caller passes it into
// Tick() directly.
type Autotuner struct {
	resPPS, resSyn, resScan, resBps *reservoir
	thresholds                      Thresholds
	cfg                             Config

	lastTune         time.Time
	skipCount        int
	completedWindows int
	distinctSources  map[string]bool
}

// New creates an Autotuner with the given initial thresholds, config, and reservoir capacity.
// Storing the Config avoids rebuilding it from kliq.go every tick.
func New(initial Thresholds, cfg Config, reservoirCap int) *Autotuner {
	if reservoirCap <= 0 {
		reservoirCap = 50_000
	}
	return &Autotuner{
		resPPS:          newReservoir(reservoirCap),
		resSyn:          newReservoir(reservoirCap),
		resScan:         newReservoir(reservoirCap),
		resBps:          newReservoir(reservoirCap),
		thresholds:      initial,
		cfg:             cfg,
		distinctSources: make(map[string]bool, 256),
	}
}

// UpdateConfig replaces the stored autotune config. Safe to call at runtime
// when PDPConfig is reloaded from a new managed bundle.
func (a *Autotuner) UpdateConfig(cfg Config) { a.cfg = cfg }

// RecordSample adds one per-source telemetry sample to the reservoirs.
// source is the source IP string used for distinct-source counting.
// addToReservoir=false suppresses reservoir updates (anti-poisoning guard);
// call this when the tick is "dirty" (active attack, high severity, etc.).
func (a *Autotuner) RecordSample(pps, syn, scan, bps float64, source string, addToReservoir bool) {
	if addToReservoir {
		a.resPPS.Add(pps)
		a.resSyn.Add(syn)
		a.resScan.Add(scan)
		a.resBps.Add(bps)
		a.distinctSources[source] = true
	}
}

// CurrentThresholds returns the thresholds last computed by Tick().
func (a *Autotuner) CurrentThresholds() Thresholds { return a.thresholds }

// SampleCount returns the number of PPS samples currently held.
func (a *Autotuner) SampleCount() int { return a.resPPS.Len() }

// Tick runs the autotune calculation if the policy says it is due.
// cleanRatio is the fraction of clean ticks (totalLearnTicks / cleanLearnTicks)
// computed by the caller — it is a per-tick counter, not per-sample.
// Returns (result, true) when thresholds were updated, (zero, false) otherwise.
func (a *Autotuner) Tick(now time.Time, pol Policy, cleanRatio float64) (TickResult, bool) {
	cfg := a.cfg
	if pol.Every <= 0 || now.Sub(a.lastTune) < pol.Every {
		return TickResult{}, false
	}

	n := minInt3(a.resPPS.Len(), a.resSyn.Len(), a.resScan.Len())

	// Not enough samples — skip unless the failsafe kicks in.
	if n < cfg.MinSamples {
		a.skipCount++
		a.lastTune = now
		reason := "not enough samples"
		if n < 50 || a.skipCount < 2 {
			return TickResult{Skipped: true, SkipReason: reason, SampleCount: n, CleanRatio: cleanRatio, Phase: pol.Phase}, false
		}
		// 2× failsafe: proceed with whatever samples exist.
		reason = "limited samples (failsafe)"
		_ = reason
	}
	a.skipCount = 0

	old := a.thresholds
	distinctCount := len(a.distinctSources)

	// Downscale guard: when active, thresholds may only rise this cycle.
	guardEnabled := pol.Active && cfg.MinWindowsBeforeDownscale > 0
	canDownscale := !guardEnabled ||
		(a.completedWindows >= cfg.MinWindowsBeforeDownscale &&
			(cfg.MinSourcesBeforeDownscale == 0 || distinctCount >= cfg.MinSourcesBeforeDownscale))

	mPPS := median(a.resPPS.data)
	mdPPS := mad(a.resPPS.data, mPPS)
	mSyn := median(a.resSyn.data)
	mdSyn := mad(a.resSyn.data, mSyn)
	mScan := median(a.resScan.data)
	mdScan := mad(a.resScan.data, mScan)

	tPPS := math.Max(cfg.FloorPPS, mPPS+pol.K*mdPPS)
	tSyn := math.Max(cfg.FloorSyn, mSyn+pol.K*mdSyn)
	tScan := math.Max(cfg.FloorScan, mScan+pol.K*mdScan)

	if !canDownscale {
		if tPPS < old.TrigPPS {
			tPPS = old.TrigPPS
		}
		if tSyn < old.TrigSyn {
			tSyn = old.TrigSyn
		}
		if tScan < old.TrigScan {
			tScan = old.TrigScan
		}
	}

	tPPS = capChangeDir(old.TrigPPS, tPPS, pol.MaxUp, pol.MaxDown)
	tSyn = capChangeDir(old.TrigSyn, tSyn, pol.MaxUp, pol.MaxDown)
	tScan = capChangeDir(old.TrigScan, tScan, pol.MaxUp, pol.MaxDown)

	// EWMA smoothing only in steady state (not during bootstrap).
	if !pol.Active && pol.Alpha > 0 && pol.Alpha < 1 {
		tPPS = old.TrigPPS*(1-pol.Alpha) + tPPS*pol.Alpha
		tSyn = old.TrigSyn*(1-pol.Alpha) + tSyn*pol.Alpha
		tScan = old.TrigScan*(1-pol.Alpha) + tScan*pol.Alpha
	}

	// BPS (opt-in: only when FloorBPS > 0).
	mBps, mdBps := 0.0, 0.0
	tBPS := old.TrigBPS
	if cfg.FloorBPS > 0 && a.resBps.Len() >= cfg.MinSamples {
		mBps = median(a.resBps.data)
		mdBps = mad(a.resBps.data, mBps)
		tBPS = math.Max(cfg.FloorBPS, mBps+pol.K*mdBps)
		tBPS = capChangeDir(old.TrigBPS, tBPS, pol.MaxUp, pol.MaxDown)
		if !pol.Active && pol.Alpha > 0 && pol.Alpha < 1 {
			tBPS = old.TrigBPS*(1-pol.Alpha) + tBPS*pol.Alpha
		}
	}

	a.thresholds = Thresholds{TrigPPS: tPPS, TrigSyn: tSyn, TrigScan: tScan, TrigBPS: tBPS}
	a.lastTune = now
	a.completedWindows++
	a.distinctSources = make(map[string]bool, 256) // reset for next window

	return TickResult{
		OldThresholds:    old,
		NewThresholds:    a.thresholds,
		MedianPPS:        mPPS,
		MadPPS:           mdPPS,
		MedianSyn:        mSyn,
		MadSyn:           mdSyn,
		MedianScan:       mScan,
		MadScan:          mdScan,
		MedianBPS:        mBps,
		MadBPS:           mdBps,
		SampleCount:      n,
		CleanRatio:       cleanRatio,
		CompletedWindows: a.completedWindows,
		Phase:            pol.Phase,
	}, true
}

// ── statistics ──────────────────────────────────────────────────────────────

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sort.Float64s(cp)
	m := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[m]
	}
	return (cp[m-1] + cp[m]) / 2
}

func mad(xs []float64, m float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return median(dev)
}

// capChangeDir limits the fractional change per cycle in each direction.
func capChangeDir(current, target, maxUp, maxDown float64) float64 {
	if current <= 0 {
		return target
	}
	if maxUp > 0 && target > current*(1+maxUp) {
		target = current * (1 + maxUp)
	}
	if maxDown > 0 && target < current*(1-maxDown) {
		target = current * (1 - maxDown)
	}
	return target
}

func minInt3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// ── reservoir ────────────────────────────────────────────────────────────────

type reservoir struct {
	data   []float64
	cap    int
	seen   int
	rnd    *rand.Rand
	seeded bool
}

func newReservoir(capacity int) *reservoir {
	return &reservoir{cap: capacity, data: make([]float64, 0, capacity)}
}

func (r *reservoir) ensureSeed() {
	if r.seeded {
		return
	}
	r.seeded = true
	r.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func (r *reservoir) Len() int { return len(r.data) }

func (r *reservoir) Add(x float64) {
	if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 {
		return
	}
	r.ensureSeed()
	r.seen++
	if len(r.data) < r.cap {
		r.data = append(r.data, x)
		return
	}
	j := r.rnd.Intn(r.seen)
	if j < r.cap {
		r.data[j] = x
	}
}
