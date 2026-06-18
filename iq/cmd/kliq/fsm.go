// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

/* ---------------- Per-candidate FSM logic ---------------- */

type fsmActionExecutor interface {
	ApplySource(adapterruntime.SourceTarget, fsm.State, actions.ActionResolution, adapterruntime.EnforcementParams, time.Time) (fsm.State, actions.ActionResult)
	ApplyDeEnforceSource(adapterruntime.SourceTarget, fsm.State, adapterruntime.EnforcementParams, time.Time) fsm.State
}

type sourceMatcher interface {
	MatchSource(string) bool
}

// processCandidate runs the legacy score-based FSM for one opaque source and
// feeds the adapter-owned tuner with accepted source observations.
func processCandidate(m metrics, st fsm.State, nowWall time.Time, c cfg,
	wl sourceMatcher, fb sourceMatcher, resolver *actions.PolicyResolver, executor fsmActionExecutor,
	tuner adapterruntime.Tuner, clean bool,
) fsm.State {
	st.LastSeenWallTime = nowWall

	pepParams := c.toPEPParams()
	sourceID := m.sourceID()

	wlHit := wl.MatchSource(sourceID)
	fbHit := fb.MatchSource(sourceID)
	if wlHit || fbHit {
		if st.Level != fsm.LevelObserve {
			st = executor.ApplyDeEnforceSource(m.Target, st, pepParams, nowWall)
		}
		st.Strikes, st.NonCompTicks, st.UpStreak, st.DownStreak = 0, 0, 0, 0
		st.HighSevSince = time.Time{}
		if c.AutoTune && clean && st.Level == fsm.LevelObserve && m.score() <= c.LearnMaxSev && m.enforcementFeedbackRate() == 0 {
			if (wlHit && c.WhitelistLearn) || (fbHit && c.FeedbackLearn) {
				recordTuningSample(tuner, m, true)
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
			Target:        actions.ActionTarget{Granularity: actions.TargetGranularitySource, Value: sourceID},
			TTL:           c.ttlForFSMLevel(target),
			CreatedAt:     nowWall,
		}
		res := resolver.Resolve(proposal)
		if res.DenyReason != "" {
			kliqLog.Printf("ACTION-RESOLVER %s %s->%s reason=%q",
				sourceID, proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
		}
		newSt, _ := executor.ApplySource(m.Target, st, res, pepParams, nowWall)
		return newSt
	}

	prevLevel := st.Level
	st, _ = fsm.Advance(m.toFSMMetrics(), st, nowWall, c.toFSMConfig(), doTransition)

	if st.Level != prevLevel {
		kliqLog.Printf("STATE %s %s->%s strikes=%d up=%d down=%d noncomp=%d score=%.2f %s",
			sourceID, prevLevel.String(), st.Level.String(),
			st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
			m.score(), m.signalsSummary())
	}

	shouldRecord := clean && c.AutoTune && st.Level == fsm.LevelObserve && m.score() <= c.LearnMaxSev && m.enforcementFeedbackRate() == 0
	recordTuningSample(tuner, m, shouldRecord)

	return st
}

func recordTuningSample(tuner adapterruntime.Tuner, m metrics, accepted bool) {
	if tuner == nil {
		return
	}
	tuner.RecordSample(adapterruntime.TuningSample{
		PacketsPerSecond:       m.signalValue(adapterruntime.MetricNetworkPacketsPerSecond),
		SynRate:                m.signalValue(adapterruntime.MetricNetworkSynRate),
		DestinationPortChanges: m.signalValue(adapterruntime.MetricNetworkDestinationPortChanges),
		BytesPerSecond:         m.signalValue(adapterruntime.MetricNetworkBytesPerSecond),
		SourceID:               m.sourceID(),
		Accepted:               accepted,
	})
}

// toFSMMetrics converts a kliq metrics struct to fsm.Metrics. The metric IDs
// are canonical; adapters decide which concrete observations populate them.
func (m metrics) toFSMMetrics() fsm.Metrics {
	return fsm.Metrics{
		PPS:        m.signalValue(adapterruntime.MetricNetworkPacketsPerSecond),
		Bps:        m.signalValue(adapterruntime.MetricNetworkBytesPerSecond),
		SynRate:    m.signalValue(adapterruntime.MetricNetworkSynRate),
		ScanRate:   m.signalValue(adapterruntime.MetricNetworkDestinationPortChanges),
		DropRLRate: m.enforcementFeedbackRate(),
		Severity:   m.score(),
	}
}
