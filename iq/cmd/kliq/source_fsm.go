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

func (s *sourceStates) reset(now time.Time, executor *brokeredActionExecutor, params adapterruntime.EnforcementParams) int {
	n := 0
	for id, entry := range s.entries {
		if entry.state.Level == fsm.LevelObserve {
			continue
		}
		entry.state, _ = executor.ApplySourceObserveOverride(entry.target, entry.state, params, now, "operator_reset")
		entry.state.Strikes, entry.state.UpStreak, entry.state.DownStreak, entry.state.NonCompTicks = 0, 0, 0, 0
		s.entries[id] = entry
		n++
	}
	return n
}

func (s *sourceStates) applyFeedback(now time.Time, fb feedbackFilter, executor *brokeredActionExecutor, params adapterruntime.EnforcementParams, sweep bool, every time.Duration, max int) {
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
		entry.state, _ = executor.ApplySourceObserveOverride(entry.target, entry.state, params, now, "operator_feedback")
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

func (s *sourceStates) processCandidates(
	cands []metrics,
	now time.Time,
	c cfg,
	wl sourceMatcher,
	fb sourceMatcher,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	tuner adapterruntime.Tuner,
	clean bool,
	runner *shadowPDPRunner,
	nodeID string,
	facts runtimePDPFactProvider,
	reactions *runtimeReactionEngine,
) processedSources {
	processed := make(processedSources, len(cands))
	for _, m := range cands {
		sourceID := m.sourceID()
		if sourceID == "" {
			continue
		}
		entry := s.ensure(sourceID, m.Target)
		entry.target = m.Target
		entry.state = processCandidateRuntimePDP(m, entry.state, now, c, wl, fb, resolver, executor, tuner, clean, runner, nodeID, facts, reactions)
		s.entries[sourceID] = entry
		processed[sourceID] = true
	}
	return processed
}

func (s *sourceStates) sweepInactive(processed processedSources, now time.Time, c cfg, resolver *actions.PolicyResolver, executor *brokeredActionExecutor, params adapterruntime.EnforcementParams, runner *shadowPDPRunner, nodeID string, facts runtimePDPFactProvider, reactions *runtimeReactionEngine) {
	for sourceID, entry := range s.entries {
		if entry.state.Level == fsm.LevelObserve || processed[sourceID] {
			continue
		}
		entry := entry
		m := metrics{Target: entry.target, Score: 0, Signals: map[string]float64{}}
		if m.Target.SourceID == "" {
			m.Target = sourceTargetFromID(sourceID)
		}
		intent := evaluateFSMIntent(m, entry.state, now, c)
		if reactions != nil {
			entry.state = reactions.EvaluateCandidate(m, entry.state, now, c, resolver, executor, nodeID)
		}
		entry.state = processRuntimePDPDecisionForCandidate(m, entry.state, intent, now, c, resolver, executor, runner, nodeID, facts)
		s.entries[sourceID] = entry
	}
}

func processCandidateRuntimePDP(
	m metrics,
	st fsm.State,
	now time.Time,
	c cfg,
	wl sourceMatcher,
	fb sourceMatcher,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	tuner adapterruntime.Tuner,
	clean bool,
	runner *shadowPDPRunner,
	nodeID string,
	facts runtimePDPFactProvider,
	reactions *runtimeReactionEngine,
) fsm.State {
	st.LastSeenWallTime = now

	sourceID := m.sourceID()
	if c.RuntimePDPMode == string(PDPModeActive) {
		st = projectRuntimePDPLeaseState(st, m, nodeID, facts, now)
	}

	wlHit := wl.MatchSource(sourceID)
	fbHit := fb.MatchSource(sourceID)
	overrideLearned := false
	if wlHit || fbHit {
		if m.Signals == nil {
			m.Signals = map[string]float64{}
		}
		if wlHit {
			m.Signals["policy.whitelist_hit"] = 1
		}
		if fbHit {
			m.Signals["policy.feedback_hit"] = 1
		}
		if c.AutoTune && clean && st.Level == fsm.LevelObserve && m.score() <= c.LearnMaxSev && m.enforcementFeedbackRate() == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				recordTuningSample(tuner, m, true)
				overrideLearned = true
			}
		}
	}

	intent := evaluateFSMIntent(m, st, now, c)
	reactionState := st
	if reactions != nil {
		reactionState = reactions.EvaluateCandidate(m, reactionState, now, c, resolver, executor, nodeID)
	}
	next := processRuntimePDPDecisionForCandidate(m, reactionState, intent, now, c, resolver, executor, runner, nodeID, facts)

	if next.Level != st.Level {
		kliqLog.Printf("STATE %s %s->%s authority=runtime-pdp strikes=%d up=%d down=%d noncomp=%d score=%.2f %s",
			sourceID, st.Level.String(), next.Level.String(),
			next.Strikes, next.UpStreak, next.DownStreak, next.NonCompTicks,
			m.score(), m.signalsSummary())
	} else if intent.Transitioned && intent.ProposedLevel != st.Level {
		kliqLog.Printf("STATE %s runtime-pdp held fsm_intent=%s current=%s strikes=%d score=%.2f %s",
			sourceID, actions.FsmLevelName(intent.ProposedLevel), st.Level.String(),
			intent.SignalState.Strikes, m.score(), m.signalsSummary())
	}

	shouldRecord := clean && c.AutoTune && intent.SignalState.Level == fsm.LevelObserve && m.score() <= c.LearnMaxSev && m.enforcementFeedbackRate() == 0
	if !overrideLearned {
		recordTuningSample(tuner, m, shouldRecord)
	}

	return next
}

func processRuntimePDPDecisionForCandidate(
	m metrics,
	current fsm.State,
	intent fsmIntent,
	now time.Time,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	runner *shadowPDPRunner,
	nodeID string,
	facts runtimePDPFactProvider,
) fsm.State {
	if runner == nil {
		return mergeFSMRuntimeState(current, intent.SignalState)
	}

	mode, _ := runner.getMode()
	prefix := runtimePDPDecisionLogPrefix(mode)
	input := runtimePDPInputForCandidate(nodeID, m, current, intent, c, facts, now)
	dec, matched, loaded, traces, err := runner.decideWithTrace(input)
	if err != nil {
		kliqLog.Printf("%s candidate decide error %s: %v", prefix, describeRuntimeCandidate(m, intent), err)
		return mergeFSMRuntimeState(current, intent.SignalState)
	}
	if !loaded {
		if mode == PDPModeActive {
			kliqLog.Printf("%s no policy pack loaded; candidate held %s", prefix, describeRuntimeCandidate(m, intent))
		}
		return mergeFSMRuntimeState(current, intent.SignalState)
	}
	if !matched {
		if trace := summarizeRuntimePDPTrace(traces); shouldLogRuntimePDPNoMatch(input, intent) && trace != "" {
			kliqLog.Printf("%s no rule matched %s trace=%s", prefix, describeRuntimeCandidate(m, intent), trace)
		}
		return mergeFSMRuntimeState(current, intent.SignalState)
	}
	if mode == PDPModeShadow {
		kliqLog.Printf("%s DECISION %s effect=%s reasons=%v (observe-only)",
			prefix, describeRuntimeCandidate(m, intent), dec.Effect, dec.ReasonCodes)
		return mergeFSMRuntimeState(current, intent.SignalState)
	}

	prop, ok, reason := runtimeDecisionToActionProposal(dec, m.sourceID(), input.Risk.Confidence, now)
	if !ok {
		kliqLog.Printf("%s decision skipped %s reason=%s", prefix, describeRuntimeCandidate(m, intent), reason)
		return mergeFSMRuntimeState(current, intent.SignalState)
	}
	prop = runtimePDPActionProposalWithEvidence(prop, input)
	res := resolver.Resolve(prop)
	if res.DenyReason != "" {
		kliqLog.Printf("ACTION-RESOLVER runtime-pdp %s %s->%s reason=%q",
			m.sourceID(), prop.DesiredLevel, res.ExecutableLevel, res.DenyReason)
	}

	switch res.Target.Granularity {
	case "", actions.TargetGranularitySource:
		target := m.Target
		if res.Target.Value != "" && res.Target.Value != m.sourceID() {
			target = sourceTargetFromID(res.Target.Value)
		}
		target.Attributes = copyStringMap(res.Target.Attributes)
		newSt, result := executor.ApplySource(target, current, res, c.toPEPParams(), now)
		if result.Status == "failed" {
			kliqLog.Printf("[runtime-pdp:active] source action failed subject=%s reason=%s", m.sourceID(), result.Reason)
			return mergeFSMRuntimeState(current, intent.SignalState)
		}
		return mergeFSMRuntimeState(newSt, intent.SignalState)

	case actions.TargetGranularityRelationship:
		target, ok := relationshipTargetFromActionTarget(res.Target)
		if !ok {
			kliqLog.Printf("[runtime-pdp:active] relationship target invalid: %#v", res.Target)
			return mergeFSMRuntimeState(current, intent.SignalState)
		}
		result := executor.ApplyRelationship(target, res, now)
		if result.Status == "failed" {
			kliqLog.Printf("[runtime-pdp:active] relationship action failed subject=%s reason=%s", m.sourceID(), result.Reason)
		}
		return mergeFSMRuntimeState(current, intent.SignalState)

	default:
		kliqLog.Printf("[runtime-pdp:active] unsupported target %s:%q", res.Target.Granularity, res.Target.Value)
		return mergeFSMRuntimeState(current, intent.SignalState)
	}
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
	current := fsm.State{}
	if brokered, ok := executor.(*brokeredActionExecutor); ok {
		current = brokered.activeSourceState(res.Target.Value, now)
	}
	executor.ApplySource(target, current, res, params, now)
	return true
}

func applyResolvedAction(res actions.ActionResolution, executor *brokeredActionExecutor, params adapterruntime.EnforcementParams, now time.Time) bool {
	switch res.Target.Granularity {
	case "", actions.TargetGranularitySource:
		return applyResolvedSourceAction(res, executor, params, now)
	case actions.TargetGranularityRelationship:
		target, ok := relationshipTargetFromActionTarget(res.Target)
		if !ok {
			return false
		}
		executor.ApplyRelationship(target, res, now)
		return true
	default:
		return false
	}
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
