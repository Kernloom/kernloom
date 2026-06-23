// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"log"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestRuntimeReactionWindowedDetectionSetsRuntimePDPFact(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	c := newReactionTestCfg(PDPModeActive)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	if state.Level != fsm.LevelObserve || len(pep.levels) != 0 {
		t.Fatalf("first event should only fill the window, state=%s levels=%#v", state.Level, pep.levels)
	}

	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")
	if state.Level != fsm.LevelObserve {
		t.Fatalf("reaction engine must not enforce directly, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("reaction engine must not call PEP directly, levels=%#v", pep.levels)
	}
	facts, err := engine.CandidateFacts(context.Background(), "node-test", m, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("candidate facts: %v", err)
	}
	detection, ok := facts.Detections["denied_access_ziti_controller"].(map[string]any)
	if !ok || detection["active"] != true {
		t.Fatalf("active detection fact missing: %#v", facts.Detections)
	}
}

func TestRuntimeReactionShadowModeDoesNotApplyResponseAction(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 5, 0, 0, time.UTC)
	c := newReactionTestCfg(PDPModeShadow)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")
	if state.Level != fsm.LevelObserve {
		t.Fatalf("shadow response should keep observe, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("shadow response should not call PEP, levels=%#v", pep.levels)
	}
}

func TestRuntimeReactionPreviousActionRequirementBlocksWithoutActiveAction(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 7, 0, 0, time.UTC)
	c := newReactionPreviousActionTestCfg(false)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")

	if state.Level != fsm.LevelObserve {
		t.Fatalf("previous-action-gated response should keep observe, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("previous-action-gated response should not call PEP, levels=%#v", pep.levels)
	}
}

func TestRuntimeReactionPreviousActionAllowsLocalRuntimeStateEvidence(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 8, 0, 0, time.UTC)
	c := newReactionPreviousActionTestCfg(true)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{Level: fsm.LevelHard, ExpiresAt: now.Add(10 * time.Minute)}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")

	if state.Level != fsm.LevelHard {
		t.Fatalf("reaction engine must preserve local state while deferring enforcement to RuntimePDP, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("reaction engine must not call PEP directly, levels=%#v", pep.levels)
	}
}

func TestRuntimeReactionBlastRadiusRejectsHardActionOnUnknownTarget(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 9, 0, 0, time.UTC)
	c := newReactionBlastRadiusTestCfg()

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")

	if state.Level != fsm.LevelObserve {
		t.Fatalf("blast-radius unknown target should keep observe, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("blast-radius should block PEP calls, levels=%#v", pep.levels)
	}
}

func TestRuntimeReactionBlastRadiusAllowsKnownNonProtectedGroup(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 9, 30, 0, time.UTC)
	c := newReactionBlastRadiusTestCfg()

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()
	m.Target.Attributes["subject.groups"] = "developers,security-readers"

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")

	if state.Level != fsm.LevelObserve {
		t.Fatalf("reaction engine must defer blast-radius enforcement to RuntimePDP/resolver, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("reaction engine must not call PEP directly, levels=%#v", pep.levels)
	}
}

func TestRuntimeReactionIntegratedWithCandidateLoop(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 10, 0, 0, time.UTC)
	c := newReactionTestCfg(PDPModeActive)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	runner.SetMode(PDPModeActive, nil)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"detections.denied_access_ziti_controller.active == true",
		"enforce.traffic.rate_limit",
		"soft",
	)); err != nil {
		t.Fatalf("update runtime pack: %v", err)
	}
	sources := newSourceStates()
	cands := []metrics{reactionDeniedAccessMetrics()}
	wl := sourcefilters.NewWhitelist("")
	fb := sourcefilters.NewFeedback("")

	sources.processCandidates(cands, now, c, wl, fb, c.buildPolicyResolver(), executor, nil, false, runner, "node-test", engine, engine)
	processed := sources.processCandidates(cands, now.Add(time.Minute), c, wl, fb, c.buildPolicyResolver(), executor, nil, false, runner, "node-test", engine, engine)

	if !processed["10.0.0.8"] {
		t.Fatal("candidate should be processed")
	}
	if got := sources.entries["10.0.0.8"].state.Level; got != fsm.LevelSoft {
		t.Fatalf("candidate reaction state = %s, want soft", got)
	}
}

func TestRuntimeReactionDetectionKeyHonorsGroupBy(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 2, 0, 0, time.UTC)
	engine := newRuntimeReactionEngine()
	rule := contracts.RuntimeDetectionRule{
		ID:        "resource-grouped-deny",
		Type:      "access.denied_threshold",
		Threshold: 2,
		Window:    contracts.NewDuration(15 * time.Minute),
		Scope:     "source",
		Params: map[string]any{
			"group_by": []string{"resource.id"},
		},
	}
	first := reactionDeniedAccessMetrics()
	first.Target.Attributes["resource.id"] = "resource-a"
	second := reactionDeniedAccessMetrics()
	second.Target.Attributes["resource.id"] = "resource-b"
	third := reactionDeniedAccessMetrics()
	third.Target.Attributes["resource.id"] = "resource-a"

	if _, ok := engine.observeDetection(rule, first, now); ok {
		t.Fatal("first resource-a sample should not cross threshold")
	}
	if _, ok := engine.observeDetection(rule, second, now.Add(time.Minute)); ok {
		t.Fatal("resource-b sample must not share resource-a window")
	}
	if _, ok := engine.observeDetection(rule, third, now.Add(2*time.Minute)); !ok {
		t.Fatal("second resource-a sample should cross threshold")
	}
}

func TestRuntimeReactionSustainedDropRequiresFullWindow(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 5, 0, 0, time.UTC)
	engine := newRuntimeReactionEngine()
	rule := contracts.RuntimeDetectionRule{
		ID:          "sustained-pressure",
		Type:        "source.rate_limit_drops_sustained",
		ResourceRef: "public-edge",
		Threshold:   1,
		Window:      contracts.NewDuration(time.Minute),
		Scope:       "source",
	}
	m := metrics{
		Target: adapterruntime.SourceTarget{SourceID: "10.0.0.8"},
		Signals: map[string]float64{
			adapterruntime.MetricNetworkRateLimitDropRate: 100,
		},
	}

	if _, ok := engine.observeDetection(rule, m, now); ok {
		t.Fatal("first drop sample must not satisfy sustained window")
	}
	if _, ok := engine.observeDetection(rule, m, now.Add(30*time.Second)); ok {
		t.Fatal("partial window must not satisfy sustained detection")
	}
	if _, ok := engine.observeDetection(rule, m, now.Add(time.Minute)); !ok {
		t.Fatal("full sustained window should satisfy detection")
	}
}

func TestRuntimeReactionSustainedDropAllowsSamplingDriftAtWindowEdge(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 9, 14, 100_000_000, time.UTC)
	engine := newRuntimeReactionEngine()
	rule := contracts.RuntimeDetectionRule{
		ID:          "sustained-pressure",
		Type:        "source.rate_limit_drops_sustained",
		ResourceRef: "public-edge",
		Threshold:   1,
		Window:      contracts.NewDuration(time.Minute),
		Scope:       "source",
		Params: map[string]any{
			"group_by": []string{"source.identity_or_ip"},
		},
	}
	m := metrics{
		Target: adapterruntime.SourceTarget{SourceID: "10.0.0.8"},
		Signals: map[string]float64{
			adapterruntime.MetricNetworkRateLimitDropRate: 100,
		},
	}

	for i := 0; i < 60; i++ {
		if _, ok := engine.observeDetection(rule, m, now.Add(time.Duration(i)*time.Second)); ok {
			t.Fatalf("sustained detection fired too early at sample %d", i)
		}
	}
	if _, ok := engine.observeDetection(rule, m, now.Add(60*time.Second+400*time.Millisecond)); !ok {
		t.Fatal("sustained detection should tolerate normal sampling drift at the window edge")
	}
}

func TestRuntimeReactionSignalPathPublishesSustainedPressureFact(t *testing.T) {
	now := time.Date(2026, 6, 22, 23, 57, 49, 0, time.UTC)
	store := openReactionTestStore(t)
	engine := newRuntimeReactionEngine()
	if err := engine.Load(context.Background(), store, "node-test"); err != nil {
		t.Fatalf("load reaction state: %v", err)
	}
	c := sustainedPressureReactionCfg()

	engine.EvaluateSignal(rateLimitDropSignal("10.0.0.8", "100"), now, c, nil, nil, "node-test")
	engine.EvaluateSignal(rateLimitDropSignal("10.0.0.8", "100"), now.Add(30*time.Second), c, nil, nil, "node-test")
	facts, err := engine.CandidateFacts(context.Background(), "node-test", metricsForRuntimeSubject(contracts.EntityRef{Kind: "ip", ID: "10.0.0.8"}), now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("candidate facts: %v", err)
	}
	if detection, ok := facts.Detections["sustained_pressure"].(map[string]any); ok && detection["active"] == true {
		t.Fatalf("partial sustained window must not publish active detection: %#v", detection)
	}

	engine.EvaluateSignal(rateLimitDropSignal("10.0.0.8", "100"), now.Add(time.Minute), c, nil, nil, "node-test")
	facts, err = engine.CandidateFacts(context.Background(), "node-test", metricsForRuntimeSubject(contracts.EntityRef{Kind: "ip", ID: "10.0.0.8"}), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("candidate facts: %v", err)
	}
	detection, ok := facts.Detections["sustained_pressure"].(map[string]any)
	if !ok || detection["active"] != true {
		t.Fatalf("active sustained-pressure detection missing: %#v", facts.Detections)
	}
}

func TestRuntimePDPSelectsBlockAfterSustainedPressureAndRateLimitLease(t *testing.T) {
	now := time.Date(2026, 6, 22, 23, 57, 49, 0, time.UTC)
	store := openReactionTestStore(t)
	if err := store.UpsertActionLease(context.Background(), decision.ActionLease{
		LeaseID:      "lease-rate-limit",
		DecisionID:   "decision-rate-limit",
		NodeID:       "node-test",
		AdapterID:    "kliq-source-pep",
		Target:       "source:10.0.0.8",
		Action:       "enforce.traffic.rate_limit",
		Level:        "hard",
		Status:       decision.ActionLeaseActive,
		FencingToken: "token-rate-limit",
		AppliedAt:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Minute),
		Metadata:     map[string]string{"param.execution_dry_run": "false"},
	}); err != nil {
		t.Fatalf("insert rate-limit lease: %v", err)
	}

	engine := newRuntimeReactionEngine()
	if err := engine.Load(context.Background(), store, "node-test"); err != nil {
		t.Fatalf("load reaction state: %v", err)
	}
	c := sustainedPressureReactionCfg()
	engine.EvaluateSignal(rateLimitDropSignal("10.0.0.8", "100"), now.Add(-time.Minute), c, nil, nil, "node-test")
	engine.EvaluateSignal(rateLimitDropSignal("10.0.0.8", "100"), now, c, nil, nil, "node-test")

	pdp, err := runtimepdp.Compile(sustainedPressureRuntimePack())
	if err != nil {
		t.Fatalf("compile runtime pack: %v", err)
	}
	facts := newRuntimePDPCompositeFactProvider(newRuntimePDPFactStore(store), engine)
	input := runtimePDPInputForCandidate(
		"node-test",
		metrics{
			Target: adapterruntime.SourceTarget{
				SourceID: "10.0.0.8",
				Subject:  observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.8"},
			},
			Score: 80,
			Signals: map[string]float64{
				adapterruntime.MetricNetworkRateLimitDropRate: 100,
			},
		},
		fsm.State{},
		fsmIntent{SignalState: fsm.State{}, ProposedLevel: fsm.LevelObserve},
		newTestCfg(""),
		facts,
		now,
	)
	dec, matched, err := pdp.Decide(input)
	if err != nil {
		t.Fatalf("runtime pdp decide: %v", err)
	}
	if !matched {
		t.Fatal("runtime pdp did not match sustained-pressure block rule")
	}
	if dec.Action.Capability != "enforce.traffic.drop" || dec.Action.Level != "block" {
		t.Fatalf("runtime pdp action = %s/%s, want enforce.traffic.drop/block", dec.Action.Capability, dec.Action.Level)
	}
}

func TestRuntimeReactionSignalInputEmitsPersistedAlert(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	c := newReactionAlertTestCfg(1)
	store := openReactionTestStore(t)
	engine := newRuntimeReactionEngine()
	if err := engine.Load(context.Background(), store, "node-test"); err != nil {
		t.Fatalf("load reaction state: %v", err)
	}

	engine.EvaluateSignal(reactionDeniedAccessSignal(), now, c, nil, nil, "node-test")

	if got := countStoredSignals(t, store, string(signal.SignalReactionAlert)); got != 1 {
		t.Fatalf("stored reaction alerts = %d, want 1", got)
	}
}

func TestRuntimeReactionMetricThresholdComparesStringAttributes(t *testing.T) {
	rule := contracts.RuntimeDetectionRule{
		ID:        "risk-medium",
		Type:      "metric.threshold",
		Threshold: 1,
		Params: map[string]any{
			"key":      "subject.risk.level",
			"operator": "eq",
			"value":    "medium",
		},
	}
	m := metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.8",
			Attributes: map[string]string{
				"subject.risk.level": "medium",
			},
		},
	}
	if got := metricThresholdCount(rule, m); got != 1 {
		t.Fatalf("metricThresholdCount = %d, want 1", got)
	}

	m.Target.Attributes["subject.risk.level"] = "low"
	if got := metricThresholdCount(rule, m); got != 0 {
		t.Fatalf("metricThresholdCount = %d, want 0", got)
	}
}

func TestRuntimeReactionMetricThresholdComparesStringLists(t *testing.T) {
	rule := contracts.RuntimeDetectionRule{
		ID:        "risk-high",
		Type:      "metric.threshold",
		Threshold: 1,
		Params: map[string]any{
			"key":      "subject.risk.level",
			"operator": "in",
			"value":    []string{"high", "critical"},
		},
	}
	m := metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.8",
			Attributes: map[string]string{
				"subject_risk_level": "critical",
			},
		},
	}
	if got := metricThresholdCount(rule, m); got != 1 {
		t.Fatalf("metricThresholdCount = %d, want 1", got)
	}
}

func TestRuntimeReactionKnownSubjectExcludingGroupSelector(t *testing.T) {
	subject := contracts.RuntimeDetectionSubject{
		Type:     "group",
		Ref:      "kernloom-admins",
		Selector: "known_subject_excluding_group",
	}
	target := adapterruntime.SourceTarget{
		SourceID: "10.0.0.8",
		Subject:  observation.EntityRef{Kind: "user", ID: "alice"},
		Attributes: map[string]string{
			"subject.resolution.status": "known",
			"subject.groups":            "developers,security-readers",
		},
	}
	if !reactionSubjectMatches(subject, target) {
		t.Fatal("known non-admin subject should match")
	}
	target.Attributes["subject.groups"] = "developers,kernloom-admins"
	if reactionSubjectMatches(subject, target) {
		t.Fatal("admin subject must not match known non-admin selector")
	}
	delete(target.Attributes, "subject.groups")
	if reactionSubjectMatches(subject, target) {
		t.Fatal("missing group context must not match known non-admin selector")
	}
}

func TestRuntimeReactionWindowStatePersists(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 5, 0, 0, time.UTC)
	c := newReactionAlertTestCfg(2)
	store := openReactionTestStore(t)

	engine := newRuntimeReactionEngine()
	if err := engine.Load(context.Background(), store, "node-test"); err != nil {
		t.Fatalf("load reaction state: %v", err)
	}
	engine.EvaluateSignal(reactionDeniedAccessSignal(), now, c, nil, nil, "node-test")

	restarted := newRuntimeReactionEngine()
	if err := restarted.Load(context.Background(), store, "node-test"); err != nil {
		t.Fatalf("reload reaction state: %v", err)
	}
	restarted.EvaluateSignal(reactionDeniedAccessSignal(), now.Add(time.Minute), c, nil, nil, "node-test")

	if got := countStoredSignals(t, store, string(signal.SignalReactionAlert)); got != 1 {
		t.Fatalf("stored reaction alerts after restart = %d, want 1", got)
	}
}

func newReactionTestCfg(mode runtimePDPMode) cfg {
	c := newTestCfg("")
	c.RuntimePDPMode = string(mode)
	c.RuntimeDetectionRules = []contracts.RuntimeDetectionRule{{
		ID:          "denied-access-ziti-controller",
		Type:        "access.denied_threshold",
		ResourceRef: "ziti-controller",
		Threshold:   2,
		Window:      contracts.NewDuration(15 * time.Minute),
		Scope:       "source",
	}}
	c.RuntimeResponseRules = []contracts.RuntimeResponseRule{{
		ID: "rate-limit-denied-access",
		When: contracts.RuntimeResponseTrigger{
			Detection: "denied-access-ziti-controller",
		},
		Then: []contracts.RuntimeResponseAction{{
			ID:  "enforce.traffic.rate_limit",
			TTL: contracts.NewDuration(5 * time.Minute),
			Target: contracts.RuntimeResponseTarget{
				Scope: "source",
			},
		}},
	}}
	return c
}

func newReactionPreviousActionTestCfg(allowLocalState bool) cfg {
	c := newReactionTestCfg(PDPModeActive)
	params := map[string]any{
		"previous_action_id":     "enforce.traffic.rate_limit",
		"previous_action_active": true,
	}
	if allowLocalState {
		params["previous_action_evidence"] = []string{"runtime_response_state", "local_runtime_state"}
	}
	c.RuntimeResponseRules[0].Then[0] = contracts.RuntimeResponseAction{
		ID:  "enforce.traffic.drop",
		TTL: contracts.NewDuration(5 * time.Minute),
		Target: contracts.RuntimeResponseTarget{
			Scope: "source",
		},
		Params: params,
	}
	return c
}

func newReactionBlastRadiusTestCfg() cfg {
	c := newReactionTestCfg(PDPModeActive)
	c.RuntimeResponseRules[0].Then[0] = contracts.RuntimeResponseAction{
		ID:  "enforce.traffic.drop",
		TTL: contracts.NewDuration(5 * time.Minute),
		Target: contracts.RuntimeResponseTarget{
			Scope: "source",
		},
		Params: map[string]any{
			"blast_radius": map[string]any{
				"unknown_behavior": "reject_hard_action",
				"excludes": []map[string]any{{
					"type": "group",
					"ref":  "kernloom-admins",
				}},
			},
		},
	}
	return c
}

func newReactionAlertTestCfg(threshold int) cfg {
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeActive)
	c.RuntimeDetectionRules = []contracts.RuntimeDetectionRule{{
		ID:          "admin-deny",
		Type:        "access.denied_threshold",
		ResourceRef: "ziti-controller",
		Threshold:   threshold,
		Window:      contracts.NewDuration(15 * time.Minute),
		Scope:       "source",
	}}
	c.RuntimeResponseRules = []contracts.RuntimeResponseRule{{
		ID: "alert-admin-deny",
		When: contracts.RuntimeResponseTrigger{
			Detection: "admin-deny",
		},
		Then: []contracts.RuntimeResponseAction{{
			ID:       "notify.alert.emit",
			Route:    "alert-route.security-ops",
			Severity: "medium",
			Dedupe:   contracts.NewDuration(15 * time.Minute),
		}},
	}}
	c.RuntimeAlertRoutes = []contracts.RuntimeAlertRoute{{
		ID:              "alert-route.security-ops",
		DefaultSeverity: "medium",
		Deduplication: contracts.RuntimeAlertDeduplication{
			Enabled: true,
			Window:  contracts.NewDuration(15 * time.Minute),
		},
	}}
	return c
}

func reactionDeniedAccessMetrics() metrics {
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.8",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.8"},
			Attributes: map[string]string{
				"resource.ref": "ziti-controller",
			},
		},
		Signals: map[string]float64{
			"access.denied": 1,
		},
	}
}

func reactionDeniedAccessSignal() signal.Signal {
	return *signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalType("access.denied"), observation.EntityRef{
		Kind: "ip",
		ID:   "10.0.0.8",
	}).SetObject(observation.EntityRef{
		Kind: "service",
		ID:   "ziti-controller",
	}).SetScore(70).SetConfidence(90).SetTTL(time.Minute)
}

func rateLimitDropSignal(sourceID, dropRate string) signal.Signal {
	return *signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalRateLimitDropsSustained, observation.EntityRef{
		Kind: observation.KindIP,
		ID:   sourceID,
	}).
		SetScore(70).
		SetConfidence(90).
		SetTTL(2*time.Minute).
		AddReasonCode("rate_limit_drops_sustained").
		SetAttribute("drop_rl_rate", dropRate)
}

func sustainedPressureReactionCfg() cfg {
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeActive)
	c.RuntimeDetectionRules = []contracts.RuntimeDetectionRule{{
		ID:          "sustained-pressure",
		Type:        "source.rate_limit_drops_sustained",
		Subject:     contracts.RuntimeDetectionSubject{Selector: "unknown_source"},
		ResourceRef: "public-edge",
		Threshold:   1,
		Window:      contracts.NewDuration(time.Minute),
		Scope:       "source",
		Params: map[string]any{
			"group_by": []string{"source.identity_or_ip"},
		},
	}}
	c.RuntimeResponseRules = []contracts.RuntimeResponseRule{{
		ID: "on-sustained-pressure-enforce-traffic-drop",
		When: contracts.RuntimeResponseTrigger{
			Detection: "sustained-pressure",
		},
		Then: []contracts.RuntimeResponseAction{{
			ID:  "enforce.traffic.drop",
			TTL: contracts.NewDuration(time.Minute),
			Target: contracts.RuntimeResponseTarget{
				Scope: "source",
			},
			Params: map[string]any{
				"previous_action_id":       "enforce.traffic.rate_limit",
				"previous_action_active":   true,
				"previous_action_evidence": []string{"runtime_response_state", "local_runtime_state"},
			},
		}},
	}}
	return c
}

func sustainedPressureRuntimePack() contracts.RuntimePolicyPack {
	return contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{Name: "sustained-pressure-test"},
		Spec: contracts.RuntimePolicyPackSpec{
			DefaultEffect: "deny",
			Rules: []contracts.RuntimePolicyRule{
				{
					ID:   "response-on-risk-elevated",
					When: "risk.level in ['medium', 'high', 'critical']",
					Then: contracts.RuntimeActionSpec{
						Capability: "enforce.traffic.rate_limit",
						Level:      "hard",
						TTL:        contracts.NewDuration(time.Minute),
					},
					ReasonCodes: []string{"response_on_risk_elevated"},
				},
				{
					ID:   "response-on-sustained-pressure",
					When: "detections.sustained_pressure.active == true && actions.enforce_traffic_rate_limit.active == true",
					Then: contracts.RuntimeActionSpec{
						Capability: "enforce.traffic.drop",
						Level:      "block",
						TTL:        contracts.NewDuration(time.Minute),
					},
					ReasonCodes: []string{"response_on_sustained_pressure"},
				},
			},
		},
	}
}

func openReactionTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(sqlite.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func countStoredSignals(t *testing.T, store *sqlite.Store, signalType string) int {
	t.Helper()
	var count int
	row := store.DB().QueryRow(`SELECT COUNT(*) FROM signals WHERE signal_type=?`, signalType)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count signals: %v", err)
	}
	return count
}
