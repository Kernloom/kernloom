// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"log"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldpep"
	"github.com/adrianenderlin/kernloom/pkg/core/fsm"
)

/* ---------------- Per-candidate FSM logic ---------------- */

// processCandidate4 runs the FSM for a single IPv4 source.
// It handles whitelist/feedback de-enforcement, constructs the doTransition
// callback (which drives the shieldpep adapter), calls fsm.Advance and adds
// learning samples when appropriate.
func processCandidate4(m metrics, st fsm.State, nowWall time.Time, c cfg,
	wl *whitelist, fb *feedbackManager, pep *shieldpep.Adapter,
	resPPS, resSyn, resScan *reservoir, clean bool,
) fsm.State {
	st.LastSeenWallTime = nowWall

	pepParams := c.toPEPParams()

	wlHit := wl.matchV4(m.IP4)
	fbHit := fb.matchV4(m.IP4)
	if wlHit || fbHit {
		if st.Level != fsm.LevelObserve {
			st = pep.TransitionV4(m.IP4, st, fsm.LevelObserve, nowWall, pepParams)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				resPPS.Add(m.PPS)
				resSyn.Add(m.SynRate)
				resScan.Add(m.ScanRate)
			}
		}
		return st
	}

	doTransition := func(st fsm.State, target fsm.Level) fsm.State {
		return pep.TransitionV4(m.IP4, st, target, nowWall, pepParams)
	}

	prevLevel := st.Level
	var newSt fsm.State
	var transitioned bool
	if c.AutoTune {
		newSt, transitioned = fsm.Advance(m.toFSMMetrics(), st, nowWall, c.toFSMConfig(), doTransition)
	} else {
		newSt, transitioned = fsm.Advance(m.toFSMMetrics(), st, nowWall, c.toFSMConfig(), doTransition)
	}
	st = newSt

	if transitioned {
		log.Printf("STATE %s %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
			m.ipString(), prevLevel.String(), st.Level.String(),
			st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
			m.Severity, m.PPS, m.SynRate, m.ScanRate, m.DropRLRate)
	}

	if clean && c.AutoTune && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
		resPPS.Add(m.PPS)
		resSyn.Add(m.SynRate)
		resScan.Add(m.ScanRate)
	}

	return st
}

// processCandidate6 runs the FSM for a single IPv6 source.
func processCandidate6(m metrics, st fsm.State, nowWall time.Time, c cfg,
	wl *whitelist, fb *feedbackManager, pep *shieldpep.Adapter,
	resPPS, resSyn, resScan *reservoir, clean bool,
) fsm.State {
	st.LastSeenWallTime = nowWall

	pepParams := c.toPEPParams()

	wlHit := wl.matchV6(m.IP6)
	fbHit := fb.matchV6(m.IP6)
	if wlHit || fbHit {
		if st.Level != fsm.LevelObserve {
			st = pep.TransitionV6(m.IP6, st, fsm.LevelObserve, nowWall, pepParams)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				resPPS.Add(m.PPS)
				resSyn.Add(m.SynRate)
				resScan.Add(m.ScanRate)
			}
		}
		return st
	}

	doTransition := func(st fsm.State, target fsm.Level) fsm.State {
		return pep.TransitionV6(m.IP6, st, target, nowWall, pepParams)
	}

	prevLevel := st.Level
	var newSt fsm.State
	var transitioned bool
	newSt, transitioned = fsm.Advance(m.toFSMMetrics(), st, nowWall, c.toFSMConfig(), doTransition)
	st = newSt

	if transitioned {
		log.Printf("STATE %s %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
			m.ipString(), prevLevel.String(), st.Level.String(),
			st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
			m.Severity, m.PPS, m.SynRate, m.ScanRate, m.DropRLRate)
	}

	if clean && c.AutoTune && st.Level == fsm.LevelObserve && m.Severity <= c.LearnMaxSev && m.DropRLRate == 0 {
		resPPS.Add(m.PPS)
		resSyn.Add(m.SynRate)
		resScan.Add(m.ScanRate)
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
