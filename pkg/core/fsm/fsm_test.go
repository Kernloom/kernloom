// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package fsm_test

import (
	"math"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/fsm"
)

/* ---------------- helper -------------------------------------------------- */

// defaultConfig returns a Config with sensible defaults for testing.
func defaultConfig() fsm.Config {
	return fsm.Config{
		SevStep1:      1.0,
		SevStep2:      2.0,
		SevStep3:      3.0,
		SevDelta1:     1,
		SevDelta2:     2,
		SevDelta3:     3,
		SevDecayBelow: 0.25,

		SoftAt:  3,
		HardAt:  6,
		BlockAt: 12,

		UpNeed:      2,
		DownNeed:    3,
		MinHoldSoft: 10 * time.Second,
		MinHoldHard: 20 * time.Second,

		BlockMinSev: 2.5,
		BlockMinDur: 5 * time.Second,

		Cooldown: 1 * time.Second,
		SoftTTL:  30 * time.Second,
		HardTTL:  60 * time.Second,
		BlockTTL: 5 * time.Minute,

		NonCompAt:         10,
		NonCompDrop:       5.0,
		NonCompSev:        2.0,
		NonCompResetBelow: 0.30,

		LearnMaxSev: 0.8,
	}
}

// noopTransition just sets the level and TTL without side-effects.
func noopTransition(cfg fsm.Config) fsm.TransitionFunc {
	return func(st fsm.State, target fsm.Level) fsm.State {
		st.Level = target
		now := time.Now()
		st.CooldownUntil = now.Add(cfg.Cooldown)
		switch target {
		case fsm.LevelObserve:
			st.ExpiresAt = time.Time{}
		case fsm.LevelSoft:
			st.ExpiresAt = now.Add(cfg.SoftTTL)
		case fsm.LevelHard:
			st.ExpiresAt = now.Add(cfg.HardTTL)
		case fsm.LevelBlock:
			st.ExpiresAt = now.Add(cfg.BlockTTL)
		}
		return st
	}
}

/* ---------------- Level.String() ----------------------------------------- */

func TestLevelString(t *testing.T) {
	cases := []struct {
		l    fsm.Level
		want string
	}{
		{fsm.LevelObserve, "OBSERVE"},
		{fsm.LevelSoft, "RATE_SOFT"},
		{fsm.LevelHard, "RATE_HARD"},
		{fsm.LevelBlock, "BLOCK"},
		{fsm.Level(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		if got := tc.l.String(); got != tc.want {
			t.Errorf("Level(%d).String() = %q, want %q", tc.l, got, tc.want)
		}
	}
}

/* ---------------- CalcSeverity -------------------------------------------- */

func TestCalcSeverity_ZeroThresholds(t *testing.T) {
	sev := fsm.CalcSeverity(9999, 9999, 9999, 9999, 0, 0, 0, 0, 0.5, 0.3, 0.2, 0, 3.0)
	if sev != 0 {
		t.Errorf("expected 0 when all thresholds are 0, got %f", sev)
	}
}

func TestCalcSeverity_Partial(t *testing.T) {
	// Only PPS signal active (trig=100, w=1.0), pps=100 => nPPS=1.0, sev=1.0
	sev := fsm.CalcSeverity(100, 0, 0, 0, 100, 0, 0, 0, 1.0, 0, 0, 0, 3.0)
	if sev != 1.0 {
		t.Errorf("expected 1.0, got %f", sev)
	}
}

func TestCalcSeverity_Capped(t *testing.T) {
	// pps=10000, trig=100 => ratio=100 but cap=3.0 => nPPS=3.0; weight=1.0 => sev=3.0
	sev := fsm.CalcSeverity(10000, 0, 0, 0, 100, 0, 0, 0, 1.0, 0, 0, 0, 3.0)
	if sev != 3.0 {
		t.Errorf("expected 3.0 (capped), got %f", sev)
	}
}

func TestCalcSeverity_Combined(t *testing.T) {
	// pps trig=100,w=0.5: pps=200 => n=2.0 (below cap 3) => contrib=1.0
	// syn trig=50,w=0.5: syn=100 => n=2.0 => contrib=1.0
	// total = 2.0
	sev := fsm.CalcSeverity(200, 100, 0, 0, 100, 50, 0, 0, 0.5, 0.5, 0, 0, 3.0)
	if sev != 2.0 {
		t.Errorf("expected 2.0, got %f", sev)
	}
}

func TestCalcSeverity_BPS(t *testing.T) {
	// bps trig=1_000_000, w=0.2: bps=2_000_000 => n=2.0 => contrib=0.4
	// pps trig=1000, w=0.8: pps=1000 => n=1.0 => contrib=0.8
	// total = 1.2
	sev := fsm.CalcSeverity(1000, 0, 0, 2_000_000, 1000, 0, 0, 1_000_000, 0.8, 0, 0, 0.2, 3.0)
	if math.Abs(sev-1.2) > 1e-9 {
		t.Errorf("expected 1.2, got %f", sev)
	}
}

/* ---------------- Advance: strike accumulation ---------------------------- */

func TestAdvance_StrikeAccumulation(t *testing.T) {
	cfg := defaultConfig()
	do := noopTransition(cfg)
	st := fsm.State{}
	now := time.Now()

	m := fsm.Metrics{Severity: cfg.SevStep1 + 0.1} // exactly step1 band

	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Strikes != cfg.SevDelta1 {
		t.Errorf("after 1 tick at step1: strikes=%d want %d", st.Strikes, cfg.SevDelta1)
	}

	m.Severity = cfg.SevStep2 + 0.1
	st, _ = fsm.Advance(m, st, now.Add(time.Millisecond), cfg, do)
	wantStrikes := cfg.SevDelta1 + cfg.SevDelta2
	if st.Strikes != wantStrikes {
		t.Errorf("after step2 tick: strikes=%d want %d", st.Strikes, wantStrikes)
	}
}

/* ---------------- Advance: escalation Observe -> Soft -> Hard -> Block ---- */

func TestAdvance_Escalation(t *testing.T) {
	cfg := defaultConfig()
	// Disable block gating so escalation reaches BLOCK deterministically.
	cfg.BlockMinSev = 0
	cfg.BlockMinDur = 0
	// Disable anti-flap so we can escalate immediately.
	cfg.UpNeed = 1
	do := noopTransition(cfg)

	st := fsm.State{}
	now := time.Now()
	m := fsm.Metrics{Severity: cfg.SevStep3 + 0.1}

	// Accumulate enough strikes to reach each level.
	for i := 0; i < 100; i++ {
		now = now.Add(2 * time.Second) // advance past cooldown each tick
		st, _ = fsm.Advance(m, st, now, cfg, do)
		if st.Level == fsm.LevelBlock {
			break
		}
	}

	if st.Level != fsm.LevelBlock {
		t.Errorf("expected BLOCK after many step3 ticks, got %s (strikes=%d)", st.Level, st.Strikes)
	}
}

/* ---------------- Advance: TTL stepdown ----------------------------------- */

func TestAdvance_SoftStepdownToObserve(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpNeed = 1
	cfg.DownNeed = 1
	do := noopTransition(cfg)

	// Start in Soft with an already-expired TTL.
	past := time.Now().Add(-2 * time.Minute)
	st := fsm.State{
		Level:       fsm.LevelSoft,
		ExpiresAt:   past,
		LastTrigger: past,
		DownStreak:  cfg.DownNeed, // already quiet enough
	}

	now := time.Now().Add(2 * time.Second) // past cooldown
	m := fsm.Metrics{Severity: 0}          // low severity -> lowTick -> decay

	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelObserve {
		t.Errorf("expected OBSERVE after soft TTL expired + quiet streak, got %s", st.Level)
	}
}

func TestAdvance_HardStepdownToSoft(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpNeed = 1
	cfg.DownNeed = 1
	do := noopTransition(cfg)

	past := time.Now().Add(-5 * time.Minute)
	// Keep strikes >= SoftAt so the FSM stays at Soft (or above) after the
	// Hard->Soft TTL stepdown fires.  Without this the strike-based path
	// would immediately select target=Observe (strikes=0 < SoftAt) and step
	// down all the way in the same tick.
	st := fsm.State{
		Level:       fsm.LevelHard,
		ExpiresAt:   past,
		LastTrigger: past,
		DownStreak:  cfg.DownNeed,
		// SoftAt+1 so that after one decay tick strikes still land at SoftAt,
		// keeping the FSM at Soft rather than falling through to Observe.
		Strikes: cfg.SoftAt + 1,
	}

	now := time.Now().Add(2 * time.Second)
	m := fsm.Metrics{Severity: 0}

	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelSoft {
		t.Errorf("expected SOFT after hard TTL expired + quiet streak (with strikes>=SoftAt), got %s", st.Level)
	}
}

/* ---------------- Advance: block gating ----------------------------------- */

func TestAdvance_BlockGating_TooEarlyHighSev(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpNeed = 1
	cfg.BlockMinSev = 2.5
	cfg.BlockMinDur = 10 * time.Second // require 10s of high sev
	do := noopTransition(cfg)

	// Build up enough strikes to target BLOCK.
	st := fsm.State{Strikes: cfg.BlockAt}
	now := time.Now()
	m := fsm.Metrics{Severity: cfg.BlockMinSev + 0.1}

	// First tick sets HighSevSince but duration not yet met.
	st, _ = fsm.Advance(m, st, now, cfg, do)
	// Should be held at HARD, not BLOCK.
	if st.Level == fsm.LevelBlock {
		t.Errorf("expected HARD (block gate not met yet), got BLOCK")
	}
}

func TestAdvance_BlockGating_SufficientDuration(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpNeed = 1
	cfg.BlockMinSev = 2.5
	cfg.BlockMinDur = 5 * time.Second
	do := noopTransition(cfg)

	past := time.Now().Add(-10 * time.Second)
	st := fsm.State{
		Strikes:      cfg.BlockAt,
		HighSevSince: past,
	}
	now := time.Now().Add(2 * time.Second)
	m := fsm.Metrics{Severity: cfg.BlockMinSev + 0.5}

	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelBlock {
		t.Errorf("expected BLOCK when block gate duration met, got %s", st.Level)
	}
}

/* ---------------- Advance: anti-flap UpNeed ------------------------------ */

func TestAdvance_AntiFlap_UpNeed(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpNeed = 3    // need 3 consecutive high ticks before escalating
	cfg.HardAt = 100  // push HardAt far so we stay in Soft range
	cfg.BlockAt = 200 // same for Block
	cfg.BlockMinSev = 0
	do := noopTransition(cfg)

	// Pre-load strikes at SoftAt so the FSM immediately wants to escalate to
	// Soft on every tick — but anti-flap (UpNeed=3) should hold it back until
	// the third consecutive high-severity tick.
	st := fsm.State{Strikes: cfg.SoftAt}
	now := time.Now()
	m := fsm.Metrics{Severity: cfg.SevStep1 + 0.1}

	// Tick 1: UpStreak=1, not yet enough.
	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelObserve {
		t.Errorf("tick1: expected OBSERVE (UpNeed not met), got %s", st.Level)
	}

	// Tick 2: UpStreak=2, still not enough.
	now = now.Add(2 * time.Second)
	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelObserve {
		t.Errorf("tick2: expected OBSERVE (UpNeed not met), got %s", st.Level)
	}

	// Tick 3: UpStreak=3, should escalate.
	now = now.Add(2 * time.Second)
	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelSoft {
		t.Errorf("tick3: expected SOFT (UpNeed met), got %s", st.Level)
	}
}

/* ---------------- Advance: anti-flap DownNeed ---------------------------- */

func TestAdvance_AntiFlap_DownNeed(t *testing.T) {
	// DownNeed governs the TTL stepdown path.  For the stepdown to be held
	// back we also need strikes to stay >= SoftAt so that the strike-based
	// target selection doesn't independently trigger a drop to Observe.
	cfg := defaultConfig()
	cfg.DownNeed = 3
	cfg.UpNeed = 1
	do := noopTransition(cfg)

	past := time.Now().Add(-5 * time.Minute)
	// strikes=SoftAt keeps the strike-based target at Soft, so the only way
	// to reach Observe is through the TTL-stepdown path that requires DownNeed.
	// We set DownStreak=0 so we can watch it accumulate.
	st := fsm.State{
		Level:       fsm.LevelSoft,
		ExpiresAt:   past,
		LastTrigger: past,
		Strikes:     cfg.SoftAt, // stay at Soft via strike target
	}
	now := time.Now().Add(2 * time.Second)
	// low severity: counts as lowTick (DownStreak grows) but strike target stays Soft
	m := fsm.Metrics{Severity: 0}

	// Ticks 1 & 2: DownStreak growing but not yet DownNeed=3.
	for i := 0; i < 2; i++ {
		now = now.Add(2 * time.Second)
		st, _ = fsm.Advance(m, st, now, cfg, do)
		if st.Level == fsm.LevelObserve {
			t.Errorf("tick %d: expected still SOFT (DownNeed not met), got OBSERVE", i+1)
		}
	}

	// Tick 3: DownStreak == DownNeed=3, TTL-stepdown should fire.
	now = now.Add(2 * time.Second)
	st, _ = fsm.Advance(m, st, now, cfg, do)
	if st.Level != fsm.LevelObserve {
		t.Errorf("tick3: expected OBSERVE (DownNeed met), got %s", st.Level)
	}
}

/* ---------------- Advance: non-compliance escalation --------------------- */

func TestAdvance_NonCompliance_Escalation(t *testing.T) {
	cfg := defaultConfig()
	cfg.NonCompAt = 3
	cfg.NonCompDrop = 1.0
	cfg.UpNeed = 1
	cfg.BlockMinSev = 0
	cfg.BlockMinDur = 0
	do := noopTransition(cfg)

	// Start in HARD; simulate ongoing DropRL (non-compliance).
	past := time.Now().Add(-2 * time.Second)
	st := fsm.State{
		Level:         fsm.LevelHard,
		Strikes:       cfg.HardAt,
		ExpiresAt:     time.Now().Add(60 * time.Second),
		CooldownUntil: past,
	}

	now := time.Now().Add(2 * time.Second)
	m := fsm.Metrics{Severity: 0.5, DropRLRate: 5.0} // DropRL active

	for i := 0; i < cfg.NonCompAt; i++ {
		now = now.Add(2 * time.Second)
		st, _ = fsm.Advance(m, st, now, cfg, do)
	}

	if st.Level != fsm.LevelBlock {
		t.Errorf("expected BLOCK after NonCompAt ticks, got %s (NonCompTicks=%d)", st.Level, st.NonCompTicks)
	}
}

/* ---------------- transitioned flag -------------------------------------- */

func TestAdvance_TransitionedFlag(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpNeed = 1
	cfg.BlockMinSev = 0
	do := noopTransition(cfg)

	st := fsm.State{Strikes: cfg.SoftAt}
	now := time.Now()
	m := fsm.Metrics{Severity: cfg.SevStep1 + 0.1}

	_, transitioned := fsm.Advance(m, st, now, cfg, do)
	if !transitioned {
		t.Error("expected transitioned=true when level changes")
	}

	// No-op tick (below any threshold).
	st2 := fsm.State{}
	m2 := fsm.Metrics{Severity: 0}
	_, transitioned2 := fsm.Advance(m2, st2, now, cfg, do)
	if transitioned2 {
		t.Error("expected transitioned=false when no level change")
	}
}
