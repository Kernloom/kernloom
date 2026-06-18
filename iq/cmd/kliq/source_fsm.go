// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

type sourceStateEntry struct {
	target adapterruntime.SourceTarget
	state  fsm.State
}

type sourceStates struct {
	entries map[string]sourceStateEntry
}

type processedSources map[string]bool

type feedbackFilter interface {
	Active() bool
	BeginSweep(time.Time, time.Duration) bool
	MatchSource(string) bool
}

func newSourceStates() *sourceStates {
	return &sourceStates{entries: make(map[string]sourceStateEntry, 64_000)}
}

func (s *sourceStates) reset(now time.Time, executor fsmActionExecutor, params adapterruntime.EnforcementParams) int {
	n := 0
	for id, entry := range s.entries {
		if entry.state.Level == fsm.LevelObserve {
			continue
		}
		entry.state = executor.ApplyDeEnforceSource(entry.target, entry.state, params, now)
		entry.state.Strikes, entry.state.UpStreak, entry.state.DownStreak, entry.state.NonCompTicks = 0, 0, 0, 0
		s.entries[id] = entry
		n++
	}
	return n
}

func (s *sourceStates) applyFeedback(now time.Time, fb feedbackFilter, executor fsmActionExecutor, params adapterruntime.EnforcementParams, sweep bool, every time.Duration, max int) {
	if fb == nil || !fb.Active() {
		return
	}
	if sweep {
		if max <= 0 || every <= 0 {
			return
		}
		if !fb.BeginSweep(now, every) {
			return
		}
	}

	budget := max
	changed := 0
	for id, entry := range s.entries {
		if entry.state.Level == fsm.LevelObserve || !fb.MatchSource(id) {
			continue
		}
		if sweep {
			if budget <= 0 {
				break
			}
			budget--
		}
		entry.state = executor.ApplyDeEnforceSource(entry.target, entry.state, params, now)
		entry.state.Strikes = 0
		entry.state.NonCompTicks = 0
		entry.state.UpStreak = 0
		entry.state.DownStreak = 0
		entry.state.HighSevSince = time.Time{}
		entry.state.ExpiresAt = time.Time{}
		entry.state.CooldownUntil = time.Time{}
		s.entries[id] = entry
		changed++
	}
	if changed > 0 {
		kliqLog.Printf("Feedback de-enforce: sources=%d budget_left=%d", changed, budget)
	}
}

func (s *sourceStates) applyGraphStrike(cands *[]metrics, gs graphStrikeMsg, now time.Time, c cfg) {
	if gs.sourceID == "" {
		return
	}
	entry := s.ensure(gs.sourceID, sourceTargetFromID(gs.sourceID))
	entry.state = applyGraphStrikeState(entry.state, gs, now, c)
	s.entries[gs.sourceID] = entry
	if gs.addToCands && !promoteCandidateForGraphStrike(*cands, gs, c) {
		*cands = append(*cands, graphStrikeMetrics(entry.target, gs, c))
	}
}

func applyGraphStrikeState(st fsm.State, gs graphStrikeMsg, now time.Time, c cfg) fsm.State {
	if gs.forceBlock {
		if needed := c.BlockAt + 1; st.Strikes < needed {
			st.Strikes = needed
		}
		st.ForceBlock = true
	} else {
		st.Strikes += gs.n
	}
	if st.UpStreak < c.UpNeed {
		st.UpStreak = c.UpNeed
	}
	if st.HighSevSince.IsZero() {
		st.HighSevSince = now
	}
	st.LastTrigger = now
	return st
}

func graphStrikeMetrics(target adapterruntime.SourceTarget, gs graphStrikeMsg, c cfg) metrics {
	severity := graphFSMSeverityFromScore(gs.signalScore, c)
	return metrics{
		Target: target,
		Score:  severity,
		Signals: map[string]float64{
			"graph.signal_score": float64(gs.signalScore),
			"graph.fsm_severity": severity,
		},
	}
}

func promoteCandidateForGraphStrike(cands []metrics, gs graphStrikeMsg, c cfg) bool {
	severity := graphFSMSeverityFromScore(gs.signalScore, c)
	for i := range cands {
		if cands[i].sourceID() != gs.sourceID {
			continue
		}
		if cands[i].Score < severity {
			cands[i].Score = severity
		}
		if cands[i].Signals == nil {
			cands[i].Signals = map[string]float64{}
		}
		cands[i].Signals["graph.signal_score"] = float64(gs.signalScore)
		cands[i].Signals["graph.fsm_severity"] = severity
		return true
	}
	return false
}

func graphFSMSeverityFromScore(score int, c cfg) float64 {
	switch {
	case score >= 90 && c.SevStep3 > 0:
		return c.SevStep3
	case score >= 75 && c.SevStep2 > 0:
		return c.SevStep2
	case c.SevStep1 > 0:
		return c.SevStep1
	default:
		return 1
	}
}

func (s *sourceStates) activeBlocks() int {
	n := 0
	for _, entry := range s.entries {
		if entry.state.Level == fsm.LevelBlock {
			n++
		}
	}
	return n
}

func (s *sourceStates) processCandidates(cands []metrics, now time.Time, c cfg, wl sourceMatcher, fb sourceMatcher, resolver *actions.PolicyResolver, executor fsmActionExecutor, tuner adapterruntime.Tuner, clean bool) processedSources {
	processed := make(processedSources, len(cands))
	for _, m := range cands {
		sourceID := m.sourceID()
		if sourceID == "" {
			continue
		}
		entry := s.ensure(sourceID, m.Target)
		entry.target = m.Target
		entry.state = processCandidate(m, entry.state, now, c, wl, fb, resolver, executor, tuner, clean)
		s.entries[sourceID] = entry
		processed[sourceID] = true
	}
	return processed
}

func (s *sourceStates) sweepInactive(processed processedSources, now time.Time, c cfg, resolver *actions.PolicyResolver, executor fsmActionExecutor, params adapterruntime.EnforcementParams) {
	zeroM := fsm.Metrics{}
	for sourceID, entry := range s.entries {
		if entry.state.Level == fsm.LevelObserve || processed[sourceID] {
			continue
		}
		entry := entry
		doTransition := func(current fsm.State, target fsm.Level) fsm.State {
			res := resolveHousekeepingTransition(sourceID, target, now, c, resolver)
			newSt, _ := executor.ApplySource(entry.target, current, res, params, now)
			return newSt
		}
		entry.state, _ = fsm.Advance(zeroM, entry.state, now, c.toFSMConfig(), doTransition)
		s.entries[sourceID] = entry
	}
}

func resolveHousekeepingTransition(sourceID string, target fsm.Level, now time.Time, c cfg, resolver *actions.PolicyResolver) actions.ActionResolution {
	proposal := actions.ActionProposal{
		Source:        "housekeeping",
		Reason:        "fsm_downscale",
		DesiredAction: actions.FsmLevelToCapability(target),
		DesiredLevel:  actions.FsmLevelName(target),
		Target:        actions.ActionTarget{Granularity: actions.TargetGranularitySource, Value: sourceID},
		TTL:           c.ttlForFSMLevel(target),
		CreatedAt:     now,
	}
	res := resolver.Resolve(proposal)
	if res.DenyReason != "" {
		kliqLog.Printf("ACTION-RESOLVER housekeeping %s %s->%s reason=%q",
			sourceID, proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
	}
	return res
}

func applyResolvedSourceAction(res actions.ActionResolution, executor fsmActionExecutor, params adapterruntime.EnforcementParams, now time.Time) bool {
	if res.Target.Value == "" {
		return false
	}
	target := adapterruntime.SourceTarget{
		SourceID:   res.Target.Value,
		Subject:    observation.EntityRef{ID: res.Target.Value},
		Attributes: copyStringMap(res.Target.Attributes),
	}
	executor.ApplySource(target, fsm.State{}, res, params, now)
	return true
}

func (s *sourceStates) levelCounts() (soft, hard, block int) {
	for _, entry := range s.entries {
		soft, hard, block = countLevel(entry.state, soft, hard, block)
	}
	return soft, hard, block
}

func countLevel(st fsm.State, soft, hard, block int) (int, int, int) {
	switch st.Level {
	case fsm.LevelSoft:
		soft++
	case fsm.LevelHard:
		hard++
	case fsm.LevelBlock:
		block++
	}
	return soft, hard, block
}

func (s *sourceStates) evictIdle(now time.Time, ttl time.Duration) {
	for id, entry := range s.entries {
		if entry.state.Level == fsm.LevelObserve && entry.state.Strikes == 0 && !entry.state.LastSeenWallTime.IsZero() && now.Sub(entry.state.LastSeenWallTime) > ttl {
			delete(s.entries, id)
		}
	}
}

func (s *sourceStates) ensure(sourceID string, target adapterruntime.SourceTarget) sourceStateEntry {
	if entry, ok := s.entries[sourceID]; ok {
		if entry.target.SourceID == "" {
			entry.target = target
		}
		return entry
	}
	return sourceStateEntry{target: target}
}

func sourceTargetFromID(sourceID string) adapterruntime.SourceTarget {
	return adapterruntime.SourceTarget{
		SourceID: sourceID,
		Subject:  observation.EntityRef{ID: sourceID},
	}
}
