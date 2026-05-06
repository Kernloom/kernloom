// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
)

/* ---------------- FSM transition (enforcement) ---------------- */

func transitionV4(ip [4]byte, st ipState, target Level, now time.Time, cooldown time.Duration, dry bool,
	denyMap4, rlPolicyMap4 *ebpf.Map,
	softRate, softBurst uint64, softTTL time.Duration,
	hardRate, hardBurst uint64, hardTTL time.Duration,
	blockTTL time.Duration,
) ipState {

	if !dry {
		switch target {
		case LObserve:
			if rlPolicyMap4 != nil {
				_ = rlPolicyMap4.Delete(&ip)
			}
			if denyMap4 != nil {
				_ = denyMap4.Delete(&ip)
			}
		case LSoft:
			if denyMap4 != nil {
				_ = denyMap4.Delete(&ip)
			}
			if rlPolicyMap4 != nil {
				val := rlCfg{RatePPS: softRate, Burst: softBurst}
				_ = rlPolicyMap4.Update(&ip, &val, ebpf.UpdateAny)
			}
		case LHard:
			if denyMap4 != nil {
				_ = denyMap4.Delete(&ip)
			}
			if rlPolicyMap4 != nil {
				val := rlCfg{RatePPS: hardRate, Burst: hardBurst}
				_ = rlPolicyMap4.Update(&ip, &val, ebpf.UpdateAny)
			}
		case LBlock:
			if rlPolicyMap4 != nil {
				_ = rlPolicyMap4.Delete(&ip)
			}
			if denyMap4 != nil {
				v := uint8(1)
				_ = denyMap4.Update(&ip, &v, ebpf.UpdateAny)
			}
		}
	}

	st.Level = target
	st.CooldownUntil = now.Add(cooldown)
	switch target {
	case LObserve:
		st.ExpiresAt = time.Time{}
	case LSoft:
		st.ExpiresAt = now.Add(softTTL)
	case LHard:
		st.ExpiresAt = now.Add(hardTTL)
	case LBlock:
		st.ExpiresAt = now.Add(blockTTL)
	}
	return st
}

func transitionV6(ip [16]byte, st ipState, target Level, now time.Time, cooldown time.Duration, dry bool,
	denyMap6, rlPolicyMap6 *ebpf.Map,
	softRate, softBurst uint64, softTTL time.Duration,
	hardRate, hardBurst uint64, hardTTL time.Duration,
	blockTTL time.Duration,
) ipState {

	if !dry {
		krl := src6Key{IP: ip}
		kd := key6Bytes{IP: ip}

		switch target {
		case LObserve:
			if rlPolicyMap6 != nil {
				_ = rlPolicyMap6.Delete(&krl)
			}
			if denyMap6 != nil {
				_ = denyMap6.Delete(&kd)
			}
		case LSoft:
			if denyMap6 != nil {
				_ = denyMap6.Delete(&kd)
			}
			if rlPolicyMap6 != nil {
				val := rlCfg{RatePPS: softRate, Burst: softBurst}
				_ = rlPolicyMap6.Update(&krl, &val, ebpf.UpdateAny)
			}
		case LHard:
			if denyMap6 != nil {
				_ = denyMap6.Delete(&kd)
			}
			if rlPolicyMap6 != nil {
				val := rlCfg{RatePPS: hardRate, Burst: hardBurst}
				_ = rlPolicyMap6.Update(&krl, &val, ebpf.UpdateAny)
			}
		case LBlock:
			if rlPolicyMap6 != nil {
				_ = rlPolicyMap6.Delete(&krl)
			}
			if denyMap6 != nil {
				v := uint8(1)
				_ = denyMap6.Update(&kd, &v, ebpf.UpdateAny)
			}
		}
	}

	st.Level = target
	st.CooldownUntil = now.Add(cooldown)
	switch target {
	case LObserve:
		st.ExpiresAt = time.Time{}
	case LSoft:
		st.ExpiresAt = now.Add(softTTL)
	case LHard:
		st.ExpiresAt = now.Add(hardTTL)
	case LBlock:
		st.ExpiresAt = now.Add(blockTTL)
	}
	return st
}

/* ---------------- Per-candidate FSM logic ---------------- */

// applyFSM contains the shared strike/streak/transition logic for one IP.
// It updates st in place and adds learning samples when appropriate.
func applyFSM(m metrics, st ipState, nowWall time.Time, c cfg,
	doTransition func(st ipState, target Level) ipState,
	resPPS, resSyn, resScan *reservoir, clean bool,
) ipState {

	// High severity sustain tracking for block gate
	if c.BlockMinSev > 0 && m.Severity >= c.BlockMinSev {
		if st.HighSevSince.IsZero() {
			st.HighSevSince = nowWall
		}
	} else {
		st.HighSevSince = time.Time{}
	}

	// Anti-flap streaks
	highTick := m.Severity >= c.SevStep1 || (c.NonCompDrop > 0 && m.DropRLRate >= c.NonCompDrop)
	lowTick := m.Severity < c.SevDecayBelow && m.DropRLRate == 0

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

	// Strike update
	strikeDelta := 0
	switch {
	case m.Severity >= c.SevStep3:
		strikeDelta = c.SevDelta3
	case m.Severity >= c.SevStep2:
		strikeDelta = c.SevDelta2
	case m.Severity >= c.SevStep1:
		strikeDelta = c.SevDelta1
	}
	if strikeDelta > 0 {
		st.Strikes += strikeDelta
		st.LastTrigger = nowWall
	} else if st.Strikes > 0 && lowTick && st.DownStreak >= c.DownNeed {
		st.Strikes--
	}

	// Non-compliance (only while RL active)
	if st.Level >= LSoft && c.NonCompAt > 0 {
		if (c.NonCompDrop > 0 && m.DropRLRate >= c.NonCompDrop) || (c.NonCompSev > 0 && m.Severity >= c.NonCompSev) {
			st.NonCompTicks++
		} else if m.Severity < c.NonCompResetBelow && m.DropRLRate == 0 {
			st.NonCompTicks = 0
		}
	} else {
		st.NonCompTicks = 0
	}

	// TTL stepdown: requires quiet streak + min hold + cooldown elapsed
	if st.Level == LSoft && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) &&
		st.DownStreak >= c.DownNeed && nowWall.Sub(st.LastTrigger) >= c.MinHoldSoft &&
		nowWall.After(st.CooldownUntil) {
		st = doTransition(st, LObserve)
	}
	if st.Level == LHard && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) &&
		st.DownStreak >= c.DownNeed && nowWall.Sub(st.LastTrigger) >= c.MinHoldHard &&
		nowWall.After(st.CooldownUntil) {
		st = doTransition(st, LSoft)
	}

	// Determine target level
	target := st.Level
	if st.Level == LHard && c.NonCompAt > 0 && st.NonCompTicks >= c.NonCompAt {
		target = LBlock
	} else {
		switch {
		case st.Strikes >= c.BlockAt:
			target = LBlock
		case st.Strikes >= c.HardAt:
			target = LHard
		case st.Strikes >= c.SoftAt:
			target = LSoft
		default:
			target = LObserve
		}
		if target > st.Level && st.UpStreak < c.UpNeed {
			target = st.Level
		}
	}

	// Block gating
	if target == LBlock && c.BlockMinSev > 0 {
		if st.HighSevSince.IsZero() || (c.BlockMinDur > 0 && nowWall.Sub(st.HighSevSince) < c.BlockMinDur) {
			target = LHard
		}
	}

	// Apply transition (respects cooldown)
	if target != st.Level && nowWall.After(st.CooldownUntil) {
		prevLevel := st.Level
		st = doTransition(st, target)
		log.Printf("STATE %s %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
			m.ipString(), prevLevel.String(), st.Level.String(),
			st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
			m.Severity, m.PPS, m.SynRate, m.ScanRate, m.DropRLRate)
	}

	// Learning samples
	if clean && resPPS != nil && st.Level == LObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
		resPPS.Add(m.PPS)
		resSyn.Add(m.SynRate)
		resScan.Add(m.ScanRate)
	}

	return st
}

func processCandidate4(m metrics, st ipState, nowWall time.Time, c cfg,
	wl *whitelist, fb *feedbackManager, maps *bpfMaps,
	resPPS, resSyn, resScan *reservoir, clean bool,
) ipState {
	st.LastSeenWallTime = nowWall

	wlHit := wl.matchV4(m.IP4)
	fbHit := fb.matchV4(m.IP4)
	if wlHit || fbHit {
		if st.Level != LObserve {
			st = transitionV4(m.IP4, st, LObserve, nowWall, c.Cooldown, c.DryRun, maps.deny4, maps.rl4,
				c.SoftRate, c.SoftBurst, c.SoftTTL, c.HardRate, c.HardBurst, c.HardTTL, c.BlockTTL)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == LObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				resPPS.Add(m.PPS)
				resSyn.Add(m.SynRate)
				resScan.Add(m.ScanRate)
			}
		}
		return st
	}

	doTransition := func(st ipState, target Level) ipState {
		return transitionV4(m.IP4, st, target, nowWall, c.Cooldown, c.DryRun, maps.deny4, maps.rl4,
			c.SoftRate, c.SoftBurst, c.SoftTTL, c.HardRate, c.HardBurst, c.HardTTL, c.BlockTTL)
	}

	var rs, rsy, rsc *reservoir
	if c.AutoTune {
		rs, rsy, rsc = resPPS, resSyn, resScan
	}
	return applyFSM(m, st, nowWall, c, doTransition, rs, rsy, rsc, clean)
}

func processCandidate6(m metrics, st ipState, nowWall time.Time, c cfg,
	wl *whitelist, fb *feedbackManager, maps *bpfMaps,
	resPPS, resSyn, resScan *reservoir, clean bool,
) ipState {
	st.LastSeenWallTime = nowWall

	wlHit := wl.matchV6(m.IP6)
	fbHit := fb.matchV6(m.IP6)
	if wlHit || fbHit {
		if st.Level != LObserve {
			st = transitionV6(m.IP6, st, LObserve, nowWall, c.Cooldown, c.DryRun, maps.deny6, maps.rl6,
				c.SoftRate, c.SoftBurst, c.SoftTTL, c.HardRate, c.HardBurst, c.HardTTL, c.BlockTTL)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == LObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				resPPS.Add(m.PPS)
				resSyn.Add(m.SynRate)
				resScan.Add(m.ScanRate)
			}
		}
		return st
	}

	doTransition := func(st ipState, target Level) ipState {
		return transitionV6(m.IP6, st, target, nowWall, c.Cooldown, c.DryRun, maps.deny6, maps.rl6,
			c.SoftRate, c.SoftBurst, c.SoftTTL, c.HardRate, c.HardBurst, c.HardTTL, c.BlockTTL)
	}

	var rs, rsy, rsc *reservoir
	if c.AutoTune {
		rs, rsy, rsc = resPPS, resSyn, resScan
	}
	return applyFSM(m, st, nowWall, c, doTransition, rs, rsy, rsc, clean)
}
