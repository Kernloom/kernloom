// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/localrisk"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/reason"
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

func projectRuntimePDPLeaseState(st fsm.State, m metrics, nodeID string, facts runtimePDPFactProvider, now time.Time) fsm.State {
	if facts == nil || m.sourceID() == "" {
		return st
	}
	snapshot, err := facts.CandidateFacts(context.Background(), nodeID, m, now)
	if err != nil {
		return st
	}
	if projected, ok := runtimeStateFromActionFacts(st, snapshot.Actions, now); ok {
		return projected
	}
	return st
}

func runtimeStateFromActionFacts(st fsm.State, actionFacts map[string]any, now time.Time) (fsm.State, bool) {
	if len(actionFacts) == 0 {
		return st, false
	}
	if fact, ok := activeRuntimeActionFact(actionFacts, "enforce_traffic_drop", "enforce_access_deny", "enforce_network_quarantine", "enforce_identity_disable"); ok {
		return runtimeStateWithActionFact(st, fsm.LevelBlock, fact, now), true
	}
	if fact, ok := activeRuntimeActionFact(actionFacts, "enforce_traffic_rate_limit"); ok {
		level := actions.ParseFSMLevel(stringFactValue(fact, "level"))
		if level < fsm.LevelSoft {
			level = fsm.LevelHard
		}
		return runtimeStateWithActionFact(st, level, fact, now), true
	}
	return st, false
}

func activeRuntimeActionFact(actionFacts map[string]any, keys ...string) (map[string]any, bool) {
	for _, key := range keys {
		raw, ok := actionFacts[key]
		if !ok {
			continue
		}
		fact, ok := raw.(map[string]any)
		if !ok || !boolFactValue(fact, "active") {
			continue
		}
		return fact, true
	}
	return nil, false
}

func runtimeStateWithActionFact(st fsm.State, level fsm.Level, fact map[string]any, now time.Time) fsm.State {
	st.Level = level
	if expiresAt, ok := timeFactValue(fact, "expires_at"); ok {
		st.ExpiresAt = expiresAt
	} else if st.ExpiresAt.IsZero() {
		st.ExpiresAt = now
	}
	return st
}

func boolFactValue(fact map[string]any, key string) bool {
	switch value := fact[key].(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(value)
		return err == nil && parsed
	default:
		return false
	}
}

func stringFactValue(fact map[string]any, key string) string {
	switch value := fact[key].(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
}

func timeFactValue(fact map[string]any, key string) (time.Time, bool) {
	switch value := fact[key].(type) {
	case time.Time:
		return value.UTC(), !value.IsZero()
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return time.Time{}, false
		}
		return parsed.UTC(), true
	default:
		return time.Time{}, false
	}
}

func runtimePDPInputForCandidate(nodeID string, m metrics, current fsm.State, intent fsmIntent, c cfg, facts runtimePDPFactProvider, now time.Time) runtimepdp.Input {
	subject := runtimePDPSubjectForCandidate(m)
	risk := localRiskForCandidate(nodeID, subject, m, current, c, now)
	adapterFacts := adapterFactMap(m)
	subjectFacts := runtimeSubjectFactMap(subject, m.Target.Attributes)
	deviceFacts := scopedAttributeFactMap("device", m.Target.Attributes)
	sessionFacts := scopedAttributeFactMap("session", m.Target.Attributes)
	resourceFacts := scopedAttributeFactMap("resource", m.Target.Attributes)
	workloadFacts := scopedAttributeFactMap("workload", m.Target.Attributes)
	baselineFacts := thresholdFactsWithSnapshot(c.tuningThresholds())
	graphFacts := graphFactMap(m.Signals)
	detectionFacts := map[string]any{}
	actionFacts := map[string]any{}

	if facts != nil {
		snapshot, err := facts.CandidateFacts(context.Background(), nodeID, m, now)
		baselineFacts = mergeFactMaps(baselineFacts, snapshot.Baseline)
		graphFacts = mergeFactMaps(graphFacts, snapshot.Graph)
		detectionFacts = mergeFactMaps(detectionFacts, snapshot.Detections)
		actionFacts = mergeFactMaps(actionFacts, snapshot.Actions)
		subjectFacts = mergeFactMaps(subjectFacts, snapshot.Subject)
		deviceFacts = mergeFactMaps(deviceFacts, snapshot.Device)
		sessionFacts = mergeFactMaps(sessionFacts, snapshot.Session)
		resourceFacts = mergeFactMaps(resourceFacts, snapshot.Resource)
		workloadFacts = mergeFactMaps(workloadFacts, snapshot.Workload)
		if err != nil {
			adapterFacts["fact_lookup_error"] = err.Error()
		}
	}

	return runtimepdp.Input{
		NodeID:  nodeID,
		Subject: subject,
		Risk:    risk,
		Context: runtimepdp.ContextSnapshot{
			Subject:    subjectFacts,
			Device:     deviceFacts,
			Session:    sessionFacts,
			Resource:   resourceFacts,
			Workload:   workloadFacts,
			Metrics:    metricFactMap(m.Signals),
			Signals:    signalFactMap(m),
			Baseline:   baselineFacts,
			Graph:      graphFacts,
			Adapter:    adapterFacts,
			FSM:        fsmFactMap(current, intent, now),
			Features:   featureFactMap(c),
			Detections: detectionFacts,
			Actions:    actionFacts,
		},
		Now: now,
	}
}

func runtimePDPInputForSignal(nodeID string, sig signal.Signal, facts runtimePDPFactProvider, now time.Time) runtimepdp.Input {
	if sig.Time.IsZero() {
		sig.Time = now.UTC()
	}
	subject := contracts.EntityRef{
		Kind: string(sig.Subject.Kind),
		ID:   sig.Subject.ID,
	}
	if subject.Kind == "" {
		subject.Kind = "source"
	}
	risk := localRiskForSignal(nodeID, subject, sig, now)
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
	subjectAttrs := signalAttributeStringMap(sig.Attributes)
	subjectFacts := runtimeSubjectFactMap(subject, subjectAttrs)
	deviceFacts := scopedAttributeFactMap("device", subjectAttrs)
	sessionFacts := scopedAttributeFactMap("session", subjectAttrs)
	resourceFacts := scopedAttributeFactMap("resource", subjectAttrs)
	workloadFacts := scopedAttributeFactMap("workload", subjectAttrs)
	if sig.Object.ID != "" {
		resourceFacts["id"] = sig.Object.ID
		resourceFacts["kind"] = string(sig.Object.Kind)
	}
	score := clampInt(sig.Score, 0, 100)
	graphFacts := graphSignalFactMap(sig)
	baselineFacts := map[string]any{}
	detectionFacts := map[string]any{}
	actionFacts := map[string]any{}
	adapterFacts := map[string]any{
		"source_id":  sig.Subject.ID,
		"subject_id": sig.Subject.ID,
		"object":     object,
	}
	if facts != nil && subject.ID != "" {
		snapshot, err := facts.CandidateFacts(context.Background(), nodeID, metricsForRuntimeSubject(subject), now)
		baselineFacts = mergeFactMaps(baselineFacts, snapshot.Baseline)
		graphFacts = mergeFactMaps(graphFacts, snapshot.Graph)
		detectionFacts = mergeFactMaps(detectionFacts, snapshot.Detections)
		actionFacts = mergeFactMaps(actionFacts, snapshot.Actions)
		subjectFacts = mergeFactMaps(subjectFacts, snapshot.Subject)
		deviceFacts = mergeFactMaps(deviceFacts, snapshot.Device)
		sessionFacts = mergeFactMaps(sessionFacts, snapshot.Session)
		resourceFacts = mergeFactMaps(resourceFacts, snapshot.Resource)
		workloadFacts = mergeFactMaps(workloadFacts, snapshot.Workload)
		if err != nil {
			adapterFacts["fact_lookup_error"] = err.Error()
		}
	}
	signalFacts := enforcementSignalFactMapForSignal(sig)
	signalFacts["type"] = string(sig.Type)
	signalFacts["score"] = score
	signalFacts["confidence"] = risk.Confidence
	signalFacts["reason_codes"] = append([]string(nil), sig.ReasonCodes...)
	signalFacts["attributes"] = attrs

	return runtimepdp.Input{
		NodeID:  nodeID,
		Subject: subject,
		Risk:    risk,
		Context: runtimepdp.ContextSnapshot{
			Subject:  subjectFacts,
			Device:   deviceFacts,
			Session:  sessionFacts,
			Resource: resourceFacts,
			Workload: workloadFacts,
			Signals:  signalFacts,
			Baseline: baselineFacts,
			Graph:    graphFacts,
			Adapter:  adapterFacts,
			FSM: fsmFactMap(
				fsm.State{},
				fsmIntent{SignalState: fsm.State{}, ProposedLevel: fsm.LevelObserve},
				now,
			),
			Detections: detectionFacts,
			Actions:    actionFacts,
		},
		Now: now,
	}
}

func runtimePDPSubjectForCandidate(m metrics) contracts.EntityRef {
	subject := contracts.EntityRef{
		Kind: "source",
		ID:   m.sourceID(),
	}
	if m.Target.Subject.ID != "" {
		subject.ID = m.Target.Subject.ID
	}
	if m.Target.Subject.Kind != "" {
		subject.Kind = string(m.Target.Subject.Kind)
	}
	if m.Target.Subject.Namespace != "" {
		subject.Namespace = m.Target.Subject.Namespace
	}
	if subject.Kind == "" {
		subject.Kind = "source"
	}
	return subject
}

func metricsForRuntimeSubject(subject contracts.EntityRef) metrics {
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: subject.ID,
			Subject: observation.EntityRef{
				Kind:      observation.EntityKind(subject.Kind),
				ID:        subject.ID,
				Namespace: subject.Namespace,
			},
		},
	}
}

func localRiskForCandidate(nodeID string, subject contracts.EntityRef, m metrics, current fsm.State, c cfg, now time.Time) contracts.LocalRiskAssessment {
	score := clampInt(int(math.Round(m.score())), 0, 100)
	confidence := candidateConfidence(score)
	signals := candidateSignals(subject, m, score, confidence, now)
	if feedback, ok := enforcementFeedbackRiskSignal(subject, m, current, c, now); ok {
		signals = append(signals, feedback)
	}
	return localRiskFromSignals(nodeID, subject, signals, now, "kliq.candidate.v1", score, confidence, domainsForCandidate(m))
}

func localRiskForSignal(nodeID string, subject contracts.EntityRef, sig signal.Signal, now time.Time) contracts.LocalRiskAssessment {
	score := clampInt(sig.Score, 0, 100)
	confidence := clampInt(sig.Confidence, 0, 100)
	if confidence == 0 {
		confidence = candidateConfidence(score)
	}
	domain := domainForSignalType(sig.Type)
	return localRiskFromSignals(nodeID, subject, []signal.Signal{sig}, now, "kliq.signal.v1", score, confidence, []string{domain})
}

func localRiskFromSignals(nodeID string, subject contracts.EntityRef, signals []signal.Signal, now time.Time, model string, fallbackScore, fallbackConfidence int, fallbackDomains []string) contracts.LocalRiskAssessment {
	cfg := localrisk.DefaultConfig()
	cfg.Model = model
	assessments := localrisk.FromSignals(signals, now, cfg)
	for _, assessment := range assessments {
		if assessment.SubjectID != subject.ID {
			continue
		}
		risk := assessment.ToContract(subject, nodeID)
		risk.Metadata.IssuedAt = now.UTC()
		if risk.Confidence <= 0 {
			risk.Confidence = confidenceRatio(fallbackConfidence)
		}
		return risk
	}
	return fallbackLocalRisk(nodeID, subject, fallbackScore, fallbackConfidence, fallbackDomains, model, now)
}

func fallbackLocalRisk(nodeID string, subject contracts.EntityRef, score, confidence int, domains []string, model string, now time.Time) contracts.LocalRiskAssessment {
	return contracts.LocalRiskAssessment{
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
		Confidence:   confidenceRatio(confidence),
		Completeness: 1.0,
		Domains:      domains,
		ValidUntil:   now.UTC().Add(2 * time.Minute),
		Model:        model,
	}
}

func candidateSignals(subject contracts.EntityRef, m metrics, score, confidence int, now time.Time) []signal.Signal {
	ref := observation.EntityRef{
		Kind:      observation.EntityKind(subject.Kind),
		ID:        subject.ID,
		Namespace: subject.Namespace,
	}
	signals := make([]signal.Signal, 0, len(m.Signals))
	for metricID, value := range m.Signals {
		if value == 0 {
			continue
		}
		sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalType(metricID), ref).
			SetScore(score).
			SetConfidence(confidence).
			SetTTL(2*time.Minute).
			AddReasonCode(reasonCodeForMetric(metricID)).
			SetAttribute("metric_id", metricID).
			SetAttribute("value", fmt.Sprintf("%g", value))
		sig.Time = now.UTC()
		signals = append(signals, *sig)
	}
	if len(signals) == 0 && score > 0 {
		sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalType("runtime.candidate"), ref).
			SetScore(score).
			SetConfidence(confidence).
			SetTTL(2 * time.Minute).
			AddReasonCode("candidate_score")
		sig.Time = now.UTC()
		signals = append(signals, *sig)
	}
	return signals
}

func enforcementFeedbackRiskSignal(subject contracts.EntityRef, m metrics, current fsm.State, c cfg, now time.Time) (signal.Signal, bool) {
	dropRate := m.enforcementFeedbackRate()
	if dropRate <= 0 || current.Level < fsm.LevelSoft {
		return signal.Signal{}, false
	}

	score := 70
	if current.Level >= fsm.LevelHard {
		score = 75
	}
	if current.Level >= fsm.LevelBlock {
		score = 85
	}
	if c.NonCompDrop > 0 && dropRate >= c.NonCompDrop && score < 80 {
		score = 80
	}
	if candidateScore := clampInt(int(math.Round(m.score())), 0, 100); candidateScore > score {
		score = candidateScore
	}

	ref := observation.EntityRef{
		Kind:      observation.EntityKind(subject.Kind),
		ID:        subject.ID,
		Namespace: subject.Namespace,
	}
	sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalRateLimitDropsSustained, ref).
		SetScore(score).
		SetConfidence(90).
		SetTTL(2*time.Minute).
		AddReasonCode(reason.RateLimitDropsSustained).
		AddReasonCode("enforcement_hold").
		SetAttribute("metric_id", adapterruntime.MetricNetworkRateLimitDropRate).
		SetAttribute("drop_rate", fmt.Sprintf("%g", dropRate)).
		SetAttribute("current_level", actions.FsmLevelName(current.Level)).
		SetAttribute("evidence", "enforcement_feedback")
	sig.Time = now.UTC()
	return *sig, true
}

func candidateConfidence(score int) int {
	if score < 10 {
		return 10
	}
	return score
}

func confidenceRatio(confidence int) float64 {
	out := float64(clampInt(confidence, 0, 100)) / 100.0
	if out < 0.1 {
		return 0.1
	}
	return out
}

func reasonCodeForMetric(metricID string) string {
	code := strings.ReplaceAll(metricID, ".", "_")
	if code == "" {
		return "metric_signal"
	}
	return code
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
		domain := domainForMetricID(metric)
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

func domainForSignalType(sigType signal.SignalType) string {
	return domainForMetricID(string(sigType))
}

func domainForMetricID(metric string) string {
	if idx := strings.IndexByte(metric, '.'); idx > 0 {
		return metric[:idx]
	}
	if metric == "" {
		return "unknown"
	}
	return metric
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
	feedbackRate := m.enforcementFeedbackRate()
	out := map[string]any{
		"score":    m.score(),
		"severity": m.score(),
	}
	out = mergeFactMaps(out, enforcementSignalFactMap(feedbackRate, feedbackRate, 0, 0))
	for key, value := range m.Signals {
		out[key] = value
		insertNestedFact(out, key, value)
	}
	return out
}

func enforcementSignalFactMapForSignal(sig signal.Signal) map[string]any {
	dropRate := 0.0
	if sig.Type == signal.SignalRateLimitDropsSustained {
		dropRate = firstSignalAttrFloat(sig, "drop_rate", "drop_rl_rate")
	}
	return enforcementSignalFactMap(dropRate, dropRate, 0, 0)
}

func enforcementSignalFactMap(feedbackRate, dropRate, denyRate, throttleRate float64) map[string]any {
	active := feedbackRate > 0 || dropRate > 0 || denyRate > 0 || throttleRate > 0
	return map[string]any{
		// Backward-compatible alias used by existing RuntimePolicyPacks.
		"enforcement_feedback_rate": feedbackRate,
		"enforcement": map[string]any{
			"feedback_rate": feedbackRate,
			"drop_rate":     dropRate,
			"deny_rate":     denyRate,
			"throttle_rate": throttleRate,
			"active":        active,
		},
	}
}

func firstSignalAttrFloat(sig signal.Signal, keys ...string) float64 {
	for _, key := range keys {
		raw := strings.TrimSpace(sig.Attributes[key])
		if raw == "" {
			continue
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			return value
		}
	}
	return 0
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

func runtimeSubjectFactMap(subject contracts.EntityRef, attrs map[string]string) map[string]any {
	out := scopedAttributeFactMap("subject", attrs)
	if subject.ID != "" {
		out["id"] = subject.ID
	}
	if subject.Kind != "" {
		out["kind"] = subject.Kind
	}
	if subject.Namespace != "" {
		out["namespace"] = subject.Namespace
	}
	for _, key := range []string{"groups", "group", "roles", "role"} {
		for _, attrKey := range []string{"subject." + key, "subject_" + key, key} {
			if value := strings.TrimSpace(attrs[attrKey]); value != "" {
				out[key] = value
				insertNestedFact(out, key, value)
				break
			}
		}
	}
	return out
}

func scopedAttributeFactMap(scope string, attrs map[string]string) map[string]any {
	out := map[string]any{}
	prefix := scope + "."
	for key, value := range attrs {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		short := strings.TrimPrefix(key, prefix)
		if short == "" {
			continue
		}
		out[short] = value
		insertNestedFact(out, short, value)
	}
	return out
}

func signalAttributeStringMap(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		out[key] = value
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
	dec, matched, loaded, _, err := s.decideWithTrace(input)
	return dec, matched, loaded, err
}

func (s *shadowPDPRunner) decideWithTrace(input runtimepdp.Input) (contracts.RuntimeDecision, bool, bool, []runtimepdp.RuleTrace, error) {
	pdp := s.current()
	if pdp == nil {
		return contracts.RuntimeDecision{}, false, false, nil, nil
	}
	dec, matched, trace, err := pdp.DecideWithTrace(input)
	return dec, matched, true, trace, err
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

func shouldLogRuntimePDPNoMatch(input runtimepdp.Input, intent fsmIntent) bool {
	return input.Risk.Score >= 30
}

func summarizeRuntimePDPTrace(traces []runtimepdp.RuleTrace) string {
	if len(traces) == 0 {
		return ""
	}
	parts := make([]string, 0, len(traces))
	for _, trace := range traces {
		status := "false"
		switch {
		case trace.Matched:
			status = "matched"
		case trace.Skipped:
			status = "skipped:" + shortRuntimePDPTraceError(trace.Error)
		case trace.Error != "":
			status = "error:" + shortRuntimePDPTraceError(trace.Error)
		}
		parts = append(parts, trace.ID+"="+status)
		if len(parts) >= 8 {
			parts = append(parts, "...")
			break
		}
	}
	return strings.Join(parts, " ")
}

func shortRuntimePDPTraceError(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if idx := strings.Index(value, "\n"); idx >= 0 {
		value = value[:idx]
	}
	if len(value) > 96 {
		value = value[:96] + "..."
	}
	return value
}
