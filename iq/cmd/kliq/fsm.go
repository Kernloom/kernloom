// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

/* ---------------- Per-candidate FSM logic ---------------- */

// processCandidate4 runs the FSM for a single IPv4 source.
// It handles whitelist/feedback de-enforcement, constructs the doTransition
// callback (which drives the shieldpep adapter), calls fsm.Advance and adds
// learning samples when appropriate.
func processCandidate4(m metrics, st fsm.State, nowWall time.Time, c cfg,
	wl *whitelist, fb *feedbackManager, resolver *actions.PolicyResolver, executor *actions.ShieldActionExecutor,
	resPPS, resSyn, resScan, resBps *reservoir, clean bool,
) fsm.State {
	st.LastSeenWallTime = nowWall

	pepParams := c.toPEPParams()

	wlHit := wl.matchV4(m.IP4)
	fbHit := fb.matchV4(m.IP4)
	if wlHit || fbHit {
		if st.Level != fsm.LevelObserve {
			st = executor.ApplyDeEnforce4(m.IP4, st, pepParams, nowWall)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				resPPS.Add(m.PPS)
				resSyn.Add(m.SynRate)
				resScan.Add(m.ScanRate)
				resBps.Add(m.Bps)
			}
		}
		return st
	}

	doTransition := func(st fsm.State, target fsm.Level) fsm.State {
		if c.BootstrapActive && !c.BootstrapAllowBlock && target == fsm.LevelBlock {
			target = fsm.LevelHard
		}
		proposal := actions.ActionProposal{
			Source:        "fsm",
			Reason:        "fsm_escalation",
			DesiredAction: actions.FsmLevelToCapability(target),
			DesiredLevel:  actions.FsmLevelName(target),
			Target:        actions.ActionTarget{Granularity: "src_ip", Value: m.ipString()},
			CreatedAt:     nowWall,
		}
		res := resolver.Resolve(proposal)
		if res.DenyReason != "" {
			kliqLog.Printf("ACTION-RESOLVER %s %s→%s reason=%q",
				m.ipString(), proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
		}
		newSt, _ := executor.Apply4(m.IP4, st, res, pepParams, nowWall)
		return newSt
	}

	prevLevel := st.Level
	st, _ = fsm.Advance(m.toFSMMetrics(), st, nowWall, c.toFSMConfig(), doTransition)

	if st.Level != prevLevel {
		kliqLog.Printf("STATE %s %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f bps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
			m.ipString(), prevLevel.String(), st.Level.String(),
			st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
			m.Severity, m.PPS, m.Bps, m.SynRate, m.ScanRate, m.DropRLRate)
	}

	if clean && c.AutoTune && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
		resPPS.Add(m.PPS)
		resSyn.Add(m.SynRate)
		resScan.Add(m.ScanRate)
		resBps.Add(m.Bps)
	}

	return st
}

// processCandidate6 runs the FSM for a single IPv6 source.
func processCandidate6(m metrics, st fsm.State, nowWall time.Time, c cfg,
	wl *whitelist, fb *feedbackManager, resolver *actions.PolicyResolver, executor *actions.ShieldActionExecutor,
	resPPS, resSyn, resScan, resBps *reservoir, clean bool,
) fsm.State {
	st.LastSeenWallTime = nowWall

	pepParams := c.toPEPParams()

	wlHit := wl.matchV6(m.IP6)
	fbHit := fb.matchV6(m.IP6)
	if wlHit || fbHit {
		if st.Level != fsm.LevelObserve {
			st = executor.ApplyDeEnforce6(m.IP6, st, pepParams, nowWall)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				resPPS.Add(m.PPS)
				resSyn.Add(m.SynRate)
				resScan.Add(m.ScanRate)
				resBps.Add(m.Bps)
			}
		}
		return st
	}

	doTransition := func(st fsm.State, target fsm.Level) fsm.State {
		if c.BootstrapActive && !c.BootstrapAllowBlock && target == fsm.LevelBlock {
			target = fsm.LevelHard
		}
		proposal := actions.ActionProposal{
			Source:        "fsm",
			Reason:        "fsm_escalation",
			DesiredAction: actions.FsmLevelToCapability(target),
			DesiredLevel:  actions.FsmLevelName(target),
			Target:        actions.ActionTarget{Granularity: "src_ip", Value: m.ipString()},
			CreatedAt:     nowWall,
		}
		res := resolver.Resolve(proposal)
		if res.DenyReason != "" {
			kliqLog.Printf("ACTION-RESOLVER %s %s→%s reason=%q",
				m.ipString(), proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
		}
		newSt, _ := executor.Apply6(m.IP6, st, res, pepParams, nowWall)
		return newSt
	}

	prevLevel := st.Level
	st, _ = fsm.Advance(m.toFSMMetrics(), st, nowWall, c.toFSMConfig(), doTransition)

	if st.Level != prevLevel {
		kliqLog.Printf("STATE %s %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f bps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
			m.ipString(), prevLevel.String(), st.Level.String(),
			st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
			m.Severity, m.PPS, m.Bps, m.SynRate, m.ScanRate, m.DropRLRate)
	}

	if clean && c.AutoTune && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
		resPPS.Add(m.PPS)
		resSyn.Add(m.SynRate)
		resScan.Add(m.ScanRate)
		resBps.Add(m.Bps)
	}

	return st
}

// toFSMMetrics converts a kliq metrics struct to fsm.Metrics.
func (m metrics) toFSMMetrics() fsm.Metrics {
	return fsm.Metrics{
		PPS:        m.PPS,
		Bps:        m.Bps,
		SynRate:    m.SynRate,
		ScanRate:   m.ScanRate,
		DropRLRate: m.DropRLRate,
		Severity:   m.Severity,
	}
}
