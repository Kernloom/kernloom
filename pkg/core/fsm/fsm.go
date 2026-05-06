// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package fsm provides the shared finite-state-machine logic for progressive
// enforcement levels used by KLIQ and any future components that share the same
// strike/streak/transition model.
package fsm

import "time"

// Level represents the current enforcement level of a source.
type Level int

const (
	// LevelObserve means the source is only observed; no enforcement applied.
	LevelObserve Level = iota
	// LevelSoft means a soft rate-limit is applied.
	LevelSoft
	// LevelHard means a hard (stricter) rate-limit is applied.
	LevelHard
	// LevelBlock means the source is fully blocked.
	LevelBlock
)

// String returns the human-readable name of the level.
func (l Level) String() string {
	switch l {
	case LevelObserve:
		return "OBSERVE"
	case LevelSoft:
		return "RATE_SOFT"
	case LevelHard:
		return "RATE_HARD"
	case LevelBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

// State holds the current FSM state for a single observed source (IP, etc.).
// It is intentionally free of any IP or identity information so that it can be
// used for both IPv4 and IPv6 sources.
type State struct {
	Level         Level
	Strikes       int
	ExpiresAt     time.Time
	CooldownUntil time.Time
	LastTrigger   time.Time

	HighSevSince     time.Time
	LastSeenWallTime time.Time

	UpStreak   int
	DownStreak int

	NonCompTicks int

	// ForceBlock bypasses the BlockMinSev/BlockMinDur gate for one transition.
	// Set by frozen-enforce graph signals; cleared after the BLOCK transition fires.
	ForceBlock bool
}

// Metrics contains the normalised numeric values derived from raw telemetry for
// a single source during one observation window.
// IP address and version are intentionally absent; they belong to the caller.
type Metrics struct {
	PPS        float64
	Bps        float64
	SynRate    float64
	ScanRate   float64
	DropRLRate float64
	Severity   float64
}

// Config contains all tunable parameters that drive the FSM.
// It mirrors the relevant fields of kliq's cfg struct so that callers can
// build a Config from their own configuration without depending on kliq.
type Config struct {
	// Strike mapping
	SevStep1      float64
	SevStep2      float64
	SevStep3      float64
	SevDelta1     int
	SevDelta2     int
	SevDelta3     int
	SevDecayBelow float64

	// FSM thresholds
	SoftAt  int
	HardAt  int
	BlockAt int

	// Anti-flap
	UpNeed      int
	DownNeed    int
	MinHoldSoft time.Duration
	MinHoldHard time.Duration

	// Block gating
	BlockMinSev float64
	BlockMinDur time.Duration

	// Cooldown applied after any level change
	Cooldown time.Duration

	// TTLs for each enforcement level (0 means no expiry)
	SoftTTL  time.Duration
	HardTTL  time.Duration
	BlockTTL time.Duration

	// Non-compliance escalation (active when Level >= LevelSoft)
	NonCompAt         int
	NonCompDrop       float64
	NonCompSev        float64
	NonCompResetBelow float64

	// Learning gate: add samples only up to this severity
	LearnMaxSev float64
}

// TransitionFunc is a callback that the caller uses to apply the actual
// enforcement side-effect for a level change.  It must return the updated State
// (with Level, ExpiresAt and CooldownUntil set appropriately).
// Advance never calls the transition function directly for no-op transitions.
type TransitionFunc func(st State, target Level) State

// Advance runs one FSM tick for a single source.
// It updates strike/streak counters, evaluates TTL stepdowns, determines the
// target level and calls doTransition when a level change is warranted.
//
// It does NOT emit log messages and does NOT add learning samples; the caller
// is responsible for both of those (keeping side-effects out of the core).
//
// clean is true when the current tick is considered clean for learning purposes.
// resPPS/resSyn/resScan may be nil; when non-nil they receive learning samples.
func Advance(m Metrics, st State, now time.Time, cfg Config, doTransition TransitionFunc) (State, bool) {
	// High-severity sustain tracking for block gating.
	if cfg.BlockMinSev > 0 && m.Severity >= cfg.BlockMinSev {
		if st.HighSevSince.IsZero() {
			st.HighSevSince = now
		}
	} else {
		st.HighSevSince = time.Time{}
	}

	// Anti-flap streak counters.
	highTick := m.Severity >= cfg.SevStep1 || (cfg.NonCompDrop > 0 && m.DropRLRate >= cfg.NonCompDrop)
	lowTick := m.Severity < cfg.SevDecayBelow && m.DropRLRate == 0

	if highTick {
		st.UpStreak++
		st.DownStreak = 0
	} else if lowTick {
		st.DownStreak++
		st.UpStreak = 0
	} else {
		if st.UpStreak > 0 {
			st.UpStreak--
		}
		if st.DownStreak > 0 {
			st.DownStreak--
		}
	}

	// Strike accumulation / decay.
	strikeDelta := 0
	switch {
	case m.Severity >= cfg.SevStep3:
		strikeDelta = cfg.SevDelta3
	case m.Severity >= cfg.SevStep2:
		strikeDelta = cfg.SevDelta2
	case m.Severity >= cfg.SevStep1:
		strikeDelta = cfg.SevDelta1
	}
	if strikeDelta > 0 {
		st.Strikes += strikeDelta
		st.LastTrigger = now
	} else if st.Strikes > 0 && lowTick && st.DownStreak >= cfg.DownNeed {
		st.Strikes--
	}

	// Non-compliance counter (only active while RL is applied).
	if st.Level >= LevelSoft && cfg.NonCompAt > 0 {
		if (cfg.NonCompDrop > 0 && m.DropRLRate >= cfg.NonCompDrop) ||
			(cfg.NonCompSev > 0 && m.Severity >= cfg.NonCompSev) {
			st.NonCompTicks++
		} else if m.Severity < cfg.NonCompResetBelow && m.DropRLRate == 0 {
			st.NonCompTicks = 0
		}
	} else {
		st.NonCompTicks = 0
	}

	// TTL stepdown: Block -> Hard when TTL elapsed + quiet streak + min hold + cooldown.
	if st.Level == LevelBlock && !st.ExpiresAt.IsZero() && now.After(st.ExpiresAt) &&
		st.DownStreak >= cfg.DownNeed && now.Sub(st.LastTrigger) >= cfg.MinHoldHard &&
		now.After(st.CooldownUntil) {
		st = doTransition(st, LevelHard)
	}

	// TTL stepdown: Soft -> Observe when TTL elapsed + quiet streak + min hold + cooldown.
	if st.Level == LevelSoft && !st.ExpiresAt.IsZero() && now.After(st.ExpiresAt) &&
		st.DownStreak >= cfg.DownNeed && now.Sub(st.LastTrigger) >= cfg.MinHoldSoft &&
		now.After(st.CooldownUntil) {
		st = doTransition(st, LevelObserve)
	}

	// TTL stepdown: Hard -> Soft when TTL elapsed + quiet streak + min hold + cooldown.
	if st.Level == LevelHard && !st.ExpiresAt.IsZero() && now.After(st.ExpiresAt) &&
		st.DownStreak >= cfg.DownNeed && now.Sub(st.LastTrigger) >= cfg.MinHoldHard &&
		now.After(st.CooldownUntil) {
		st = doTransition(st, LevelSoft)
	}

	// Determine desired target level.
	target := st.Level
	if st.Level == LevelHard && cfg.NonCompAt > 0 && st.NonCompTicks >= cfg.NonCompAt {
		target = LevelBlock
	} else {
		switch {
		case st.Strikes >= cfg.BlockAt:
			target = LevelBlock
		case st.Strikes >= cfg.HardAt:
			target = LevelHard
		case st.Strikes >= cfg.SoftAt:
			target = LevelSoft
		default:
			target = LevelObserve
		}
		// Anti-flap: require UpNeed consecutive high ticks before escalating.
		// ForceBlock bypasses this — a graph freeze violation is a deliberate
		// behavioral signal, not metric noise that anti-flap is designed to filter.
		if target > st.Level && st.UpStreak < cfg.UpNeed && !st.ForceBlock {
			target = st.Level
		}
	}

	// While BLOCK TTL is still active, suppress any strike-based downgrade.
	// Without this, a source generating no traffic (sev=0) would decay its
	// strikes below BlockAt within seconds and escape the block early.
	if st.Level == LevelBlock && !st.ExpiresAt.IsZero() && now.Before(st.ExpiresAt) &&
		target < st.Level {
		target = st.Level
	}

	// Block gating: require sustained high severity before escalating TO BLOCK.
	// Only applies when target > current level (i.e. escalating, not maintaining).
	// Once in BLOCK the gate does not fire — otherwise a successful block (which
	// drops traffic to sev=0) would immediately undo itself via the gate.
	// ForceBlock bypasses the gate for frozen-enforce graph violations.
	if target == LevelBlock && target > st.Level && cfg.BlockMinSev > 0 && !st.ForceBlock {
		if st.HighSevSince.IsZero() ||
			(cfg.BlockMinDur > 0 && now.Sub(st.HighSevSince) < cfg.BlockMinDur) {
			target = LevelHard
		}
	}

	// Apply transition if warranted and cooldown has elapsed.
	transitioned := false
	if target != st.Level && now.After(st.CooldownUntil) {
		st = doTransition(st, target)
		transitioned = true
		st.ForceBlock = false // consumed; normal gate applies on subsequent ticks
	}

	return st, transitioned
}

// CalcSeverity computes a composite severity score from PPS, SYN/s and scan/s.
// Each signal is normalised by its trigger threshold (capped at cap) and
// weighted.  A zero threshold disables that signal.
func CalcSeverity(pps, synps, scanps float64,
	trigPPS, trigSyn, trigScan float64,
	wPPS, wSyn, wScan float64,
	cap float64,
) float64 {
	nPPS := 0.0
	if trigPPS > 0 {
		nPPS = minf(pps/trigPPS, cap)
	}
	nSyn := 0.0
	if trigSyn > 0 {
		nSyn = minf(synps/trigSyn, cap)
	}
	nScan := 0.0
	if trigScan > 0 {
		nScan = minf(scanps/trigScan, cap)
	}
	return wPPS*nPPS + wSyn*nSyn + wScan*nScan
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
