// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

type fsmIntent struct {
	SignalState   fsm.State
	ProposedLevel fsm.Level
	Transitioned  bool
}

func evaluateFSMIntent(m metrics, st fsm.State, now time.Time, c cfg) fsmIntent {
	proposed := st.Level
	next, transitioned := fsm.Advance(m.toFSMMetrics(), st, now, c.toFSMConfig(), func(current fsm.State, target fsm.Level) fsm.State {
		proposed = target
		return syntheticFSMTransition(current, target, now, c)
	})
	if !transitioned {
		proposed = next.Level
	}
	return fsmIntent{SignalState: next, ProposedLevel: proposed, Transitioned: transitioned}
}

func syntheticFSMTransition(st fsm.State, target fsm.Level, now time.Time, c cfg) fsm.State {
	st.Level = target
	st.CooldownUntil = now.Add(c.Cooldown)
	switch target {
	case fsm.LevelSoft:
		st.ExpiresAt = expiryTime(now, c.SoftTTL)
	case fsm.LevelHard:
		st.ExpiresAt = expiryTime(now, c.HardTTL)
	case fsm.LevelBlock:
		st.ExpiresAt = expiryTime(now, c.BlockTTL)
	default:
		st.ExpiresAt = time.Time{}
	}
	return st
}

func expiryTime(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return now.Add(ttl)
}

func mergeFSMRuntimeState(actual, signal fsm.State) fsm.State {
	out := actual
	out.Strikes = signal.Strikes
	out.LastTrigger = signal.LastTrigger
	out.HighSevSince = signal.HighSevSince
	out.LastSeenWallTime = signal.LastSeenWallTime
	out.UpStreak = signal.UpStreak
	out.DownStreak = signal.DownStreak
	out.NonCompTicks = signal.NonCompTicks
	out.ForceBlock = signal.ForceBlock
	return out
}

func runtimePDPInputForCandidate(nodeID string, m metrics, current fsm.State, intent fsmIntent, c cfg, now time.Time) runtimepdp.Input {
	sourceID := m.sourceID()
	subject := contracts.EntityRef{
		Kind: "source",
		ID:   sourceID,
	}
	if m.Target.Subject.ID != "" {
		subject.ID = m.Target.Subject.ID
	}
	if m.Target.Subject.Kind != "" {
		subject.Kind = string(m.Target.Subject.Kind)
	}
	if subject.Kind == "" {
		subject.Kind = "source"
	}

	score := clampInt(int(math.Round(m.score())), 0, 100)
	confidence := float64(score) / 100.0
	if confidence < 0.1 {
		confidence = 0.1
	}

	return runtimepdp.Input{
		NodeID:  nodeID,
		Subject: subject,
		Risk: contracts.LocalRiskAssessment{
			TypeMeta: contracts.TypeMeta{
				APIVersion: contracts.RuntimeAPIVersion,
				Kind:       contracts.KindLocalRiskAssessment,
			},
			Metadata: contracts.ObjectMeta{
				NodeID:   nodeID,
				IssuedAt: now.UTC(),
			},
			Subject:      subject,
			Level:        riskLevelForScore(score),
			Score:        score,
			Confidence:   confidence,
			Completeness: 1.0,
			Domains:      domainsForCandidate(m),
			ValidUntil:   now.UTC().Add(2 * time.Minute),
			Model:        "kliq.candidate.v1",
		},
		Context: runtimepdp.ContextSnapshot{
			Metrics:  metricFactMap(m.Signals),
			Signals:  signalFactMap(m),
			Baseline: thresholdFactMap(c.tuningThresholds()),
			Graph:    graphFactMap(m.Signals),
			Adapter:  adapterFactMap(m),
			FSM:      fsmFactMap(current, intent, now),
			Features: featureFactMap(c),
		},
		Now: now,
	}
}

func runtimePDPInputForSignal(nodeID string, sig signal.Signal, now time.Time) runtimepdp.Input {
	subject := contracts.EntityRef{
		Kind: string(sig.Subject.Kind),
		ID:   sig.Subject.ID,
	}
	if subject.Kind == "" {
		subject.Kind = "source"
	}
	object := map[string]any{}
	if sig.Object.ID != "" {
		object["id"] = sig.Object.ID
		object["kind"] = string(sig.Object.Kind)
	}
	attrs := map[string]any{}
	for k, v := range sig.Attributes {
		attrs[k] = v
		insertNestedFact(attrs, k, v)
	}
	validUntil := now.UTC().Add(sig.TTL)
	if sig.TTL <= 0 {
		validUntil = now.UTC().Add(2 * time.Minute)
	}
	confidence := float64(clampInt(sig.Confidence, 0, 100)) / 100.0
	if confidence == 0 {
		confidence = 0.1
	}
	score := clampInt(sig.Score, 0, 100)
	domain := "unknown"
	if value := string(sig.Type); value != "" {
		domain = value
		if idx := strings.IndexByte(value, '.'); idx > 0 {
			domain = value[:idx]
		}
	}
	return runtimepdp.Input{
		NodeID:  nodeID,
		Subject: subject,
		Risk: contracts.LocalRiskAssessment{
			TypeMeta: contracts.TypeMeta{
				APIVersion: contracts.RuntimeAPIVersion,
				Kind:       contracts.KindLocalRiskAssessment,
			},
			Metadata: contracts.ObjectMeta{
				NodeID:   nodeID,
				IssuedAt: now.UTC(),
			},
			Subject:      subject,
			Level:        riskLevelForScore(score),
			Score:        score,
			Confidence:   confidence,
			Completeness: 1.0,
			Domains:      []string{domain},
			ValidUntil:   validUntil,
			Model:        "kliq.signal.v1",
		},
		Context: runtimepdp.ContextSnapshot{
			Signals: map[string]any{
				"type":         string(sig.Type),
				"score":        score,
				"confidence":   confidence,
				"reason_codes": append([]string(nil), sig.ReasonCodes...),
				"attributes":   attrs,
			},
			Graph: graphSignalFactMap(sig),
			Adapter: map[string]any{
				"source_id":  sig.Subject.ID,
				"subject_id": sig.Subject.ID,
				"object":     object,
			},
		},
		Now: now,
	}
}

func graphSignalFactMap(sig signal.Signal) map[string]any {
	out := map[string]any{}
	if strings.HasPrefix(string(sig.Type), "graph.") {
		out["signal_type"] = string(sig.Type)
		out["score"] = sig.Score
		out["confidence"] = sig.Confidence
		if sig.Subject.ID != "" {
			out["subject_id"] = sig.Subject.ID
		}
		if sig.Object.ID != "" {
			out["object_id"] = sig.Object.ID
		}
		for k, v := range sig.Attributes {
			out[k] = v
			insertNestedFact(out, k, v)
		}
	}
	return out
}

func riskLevelForScore(score int) contracts.RiskLevel {
	switch {
	case score >= 81:
		return contracts.RiskCritical
	case score >= 61:
		return contracts.RiskHigh
	case score >= 31:
		return contracts.RiskMedium
	default:
		return contracts.RiskLow
	}
}

func domainsForCandidate(m metrics) []string {
	seen := map[string]bool{}
	for metric := range m.Signals {
		domain := metric
		if idx := strings.IndexByte(metric, '.'); idx > 0 {
			domain = metric[:idx]
		}
		if domain != "" {
			seen[domain] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for domain := range seen {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func metricFactMap(values map[string]float64) map[string]any {
	out := map[string]any{}
	for key, value := range values {
		out[key] = value
		insertNestedFact(out, key, value)
	}
	return out
}

func thresholdFactMap(t adapterruntime.TuningThresholds) map[string]any {
	values := map[string]float64{}
	if t.PacketsPerSecond > 0 {
		values[adapterruntime.MetricNetworkPacketsPerSecond] = t.PacketsPerSecond
	}
	if t.SynRate > 0 {
		values[adapterruntime.MetricNetworkSynRate] = t.SynRate
	}
	if t.DestinationPortChanges > 0 {
		values[adapterruntime.MetricNetworkDestinationPortChanges] = t.DestinationPortChanges
	}
	if t.BytesPerSecond > 0 {
		values[adapterruntime.MetricNetworkBytesPerSecond] = t.BytesPerSecond
	}
	return metricFactMap(values)
}

func signalFactMap(m metrics) map[string]any {
	out := map[string]any{
		"score":                     m.score(),
		"severity":                  m.score(),
		"enforcement_feedback_rate": m.enforcementFeedbackRate(),
	}
	for key, value := range m.Signals {
		out[key] = value
		insertNestedFact(out, key, value)
	}
	return out
}

func graphFactMap(values map[string]float64) map[string]any {
	out := map[string]any{}
	for key, value := range values {
		if strings.HasPrefix(key, "graph.") {
			short := strings.TrimPrefix(key, "graph.")
			out[short] = value
			insertNestedFact(out, short, value)
		}
	}
	return out
}

func adapterFactMap(m metrics) map[string]any {
	out := map[string]any{
		"source_id": m.sourceID(),
	}
	if m.Target.Subject.ID != "" {
		out["subject_id"] = m.Target.Subject.ID
	}
	if m.Target.Subject.Kind != "" {
		out["subject_kind"] = string(m.Target.Subject.Kind)
	}
	if len(m.Target.Attributes) > 0 {
		attrs := map[string]any{}
		for k, v := range m.Target.Attributes {
			attrs[k] = v
		}
		out["attributes"] = attrs
	}
	return out
}

func fsmFactMap(current fsm.State, intent fsmIntent, now time.Time) map[string]any {
	return map[string]any{
		"current_level":   actions.FsmLevelName(current.Level),
		"signal_level":    actions.FsmLevelName(intent.SignalState.Level),
		"proposed_level":  actions.FsmLevelName(intent.ProposedLevel),
		"transitioned":    intent.Transitioned,
		"strikes":         intent.SignalState.Strikes,
		"up_streak":       intent.SignalState.UpStreak,
		"down_streak":     intent.SignalState.DownStreak,
		"noncomp_ticks":   intent.SignalState.NonCompTicks,
		"force_block":     intent.SignalState.ForceBlock,
		"cooldown_active": !current.CooldownUntil.IsZero() && now.Before(current.CooldownUntil),
	}
}

func featureFactMap(c cfg) map[string]any {
	out := map[string]any{
		"profile":               c.ProfileName,
		"mode":                  c.Mode,
		"runtime_pdp_mode":      c.RuntimePDPMode,
		"dry_run":               c.DryRun,
		"bootstrap_active":      c.BootstrapActive,
		"bootstrap_allow_block": c.BootstrapAllowBlock,
	}
	insertNestedFact(out, "bootstrap.active", c.BootstrapActive)
	insertNestedFact(out, "bootstrap.allow_block", c.BootstrapAllowBlock)
	return out
}

func insertNestedFact(out map[string]any, dotted string, value any) {
	parts := strings.Split(dotted, ".")
	if len(parts) < 2 {
		return
	}
	cursor := out
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return
		}
		next, ok := cursor[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cursor[part] = next
		}
		cursor = next
	}
	last := parts[len(parts)-1]
	if last != "" {
		cursor[last] = value
	}
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func (s *shadowPDPRunner) decide(input runtimepdp.Input) (contracts.RuntimeDecision, bool, bool, error) {
	pdp := s.current()
	if pdp == nil {
		return contracts.RuntimeDecision{}, false, false, nil
	}
	dec, matched, err := pdp.Decide(input)
	return dec, matched, true, err
}

func runtimePDPDecisionLogPrefix(mode runtimePDPMode) string {
	if mode == PDPModeActive {
		return "[runtime-pdp:active]"
	}
	return "[runtime-pdp:shadow]"
}

func describeRuntimeCandidate(m metrics, intent fsmIntent) string {
	return fmt.Sprintf("subject=%s score=%.0f fsm=%s proposed=%s",
		m.sourceID(), m.score(), actions.FsmLevelName(intent.SignalState.Level), actions.FsmLevelName(intent.ProposedLevel))
}
