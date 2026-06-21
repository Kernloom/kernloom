// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"os"
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/catalog"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/policy"
)

// loadPackFromYAML writes yaml to a temp file, loads it as a LocalPolicyPack,
// applies it to a test cfg (with FSM thresholds set for testability), and returns it.
func loadPackFromYAML(t *testing.T, yaml string) cfg {
	t.Helper()
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	pp, err := policy.LoadFromFile(f.Name())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	// Start with a base cfg that has testable FSM thresholds.
	c := cfg{
		SevStep1: 1.0, SevStep2: 50.0, SevStep3: 75.0,
		SevDelta1: 1, SevDelta2: 2, SevDelta3: 3,
		SoftAt: 1, HardAt: 2, BlockAt: 3,
		SoftTTL: time.Minute, HardTTL: time.Minute, BlockTTL: time.Minute,
	}
	applyPolicyPackToCfg(pp, &c)
	rulesFromPolicyPack(pp, &c)
	c.adapterParams = catalog.DefaultCapabilityParams(catalog.DefaultAdapterID)
	return c
}

// ── normalizeCapabilityID ─────────────────────────────────────────────────────

func TestNormalizeCapabilityID_ForgeToKLIQ(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"enforce.traffic.rate_limit", "enforce.traffic.rate_limit"},
		{"enforce.access.deny", "enforce.access.deny"},
		{"enforce.traffic.drop", "enforce.traffic.drop"},
		{"enforce.traffic.quarantine", "enforce.traffic.quarantine"},
		{"enforce.access.allow", "enforce.access.allow"},
		{"enforce.access.default_deny", "enforce.access.default_deny"},
		{"enforce.network.deny", "enforce.network.deny"},
		{"enforce.network.rate_limit", "enforce.network.rate_limit"},
		// Legacy network IDs are mapped to current action IDs.
		{"network.rate_limit_source", "enforce.traffic.rate_limit"},
		{"network.block_source", "enforce.access.deny"},
		// Unknown IDs pass through (forward-compatible).
		{"x.vendor.custom_cap", "x.vendor.custom_cap"},
	}
	for _, tc := range cases {
		got := normalizeCapabilityID(tc.input)
		if got != tc.want {
			t.Errorf("normalizeCapabilityID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── capEnforcementLevel ───────────────────────────────────────────────────────

func TestCapEnforcementLevel_NoLimit(t *testing.T) {
	for _, maxAction := range []string{"", "block"} {
		for _, level := range []fsm.Level{fsm.LevelObserve, fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
			got := capEnforcementLevel(level, maxAction)
			if got != level {
				t.Errorf("capEnforcementLevel(%s, %q) = %s, want %s (no cap expected)",
					level, maxAction, got, level)
			}
		}
	}
}

func TestCapEnforcementLevel_RateLimit(t *testing.T) {
	cases := []struct {
		input fsm.Level
		want  fsm.Level
	}{
		{fsm.LevelObserve, fsm.LevelObserve}, // observe → observe (no change)
		{fsm.LevelSoft, fsm.LevelSoft},       // soft → soft (at ceiling)
		{fsm.LevelHard, fsm.LevelSoft},       // hard → soft (capped)
		{fsm.LevelBlock, fsm.LevelSoft},      // block → soft (capped)
	}
	for _, tc := range cases {
		got := capEnforcementLevel(tc.input, "rate_limit")
		if got != tc.want {
			t.Errorf("capEnforcementLevel(%s, rate_limit) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestCapEnforcementLevel_Observe(t *testing.T) {
	for _, level := range []fsm.Level{fsm.LevelObserve, fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		got := capEnforcementLevel(level, "observe")
		if got != fsm.LevelObserve {
			t.Errorf("capEnforcementLevel(%s, observe) = %s, want LevelObserve", level, got)
		}
	}
}

func TestCapEnforcementLevel_UnknownValueNoOp(t *testing.T) {
	// Unknown max_action values are forward-compatible: treated as no cap.
	got := capEnforcementLevel(fsm.LevelBlock, "unknown_future_value")
	if got != fsm.LevelBlock {
		t.Errorf("unknown max_action should not cap: got %s", got)
	}
}

// ── rulesFromPolicyPack ───────────────────────────────────────────────────────

func makeTestPack(rules []policy.RuleSpec, maxAction string, allowBlock bool) *policy.PolicyPack {
	return &policy.PolicyPack{
		APIVersion: "kernloom.io/kliq/v1alpha1",
		Kind:       "LocalPolicyPack",
		Metadata:   policy.Metadata{Name: "test-pack"},
		Spec: policy.Spec{
			Autonomy: policy.AutonomySpec{
				MaxAction:       maxAction,
				AllowLocalBlock: allowBlock,
			},
			Rules: rules,
		},
	}
}

func makeDuration(d time.Duration) policy.Duration {
	return policy.Duration{D: d}
}

func TestRulesFromPolicyPack_TTLsSet(t *testing.T) {
	pp := makeTestPack([]policy.RuleSpec{
		{When: policy.WhenSpec{FsmLevel: "soft"}, Then: policy.ThenSpec{TTL: makeDuration(10 * time.Minute)}},
		{When: policy.WhenSpec{FsmLevel: "hard"}, Then: policy.ThenSpec{TTL: makeDuration(20 * time.Minute)}},
		{When: policy.WhenSpec{FsmLevel: "block"}, Then: policy.ThenSpec{TTL: makeDuration(30 * time.Minute)}},
	}, "", false)

	var c cfg
	rulesFromPolicyPack(pp, &c)

	if c.SoftTTL != 10*time.Minute {
		t.Errorf("SoftTTL: got %v, want 10m", c.SoftTTL)
	}
	if c.HardTTL != 20*time.Minute {
		t.Errorf("HardTTL: got %v, want 20m", c.HardTTL)
	}
	if c.BlockTTL != 30*time.Minute {
		t.Errorf("BlockTTL: got %v, want 30m", c.BlockTTL)
	}
}

func TestRulesFromPolicyPack_CapabilityNormalised(t *testing.T) {
	// Forge capability IDs are normalised to KLIQ internal IDs.
	pp := makeTestPack([]policy.RuleSpec{
		{
			When: policy.WhenSpec{FsmLevel: "soft"},
			Then: policy.ThenSpec{
				Capability: "enforce.traffic.rate_limit",
				TTL:        makeDuration(10 * time.Minute),
			},
		},
		{
			When: policy.WhenSpec{FsmLevel: "block"},
			Then: policy.ThenSpec{
				Capability: "enforce.access.deny",
				TTL:        makeDuration(30 * time.Minute),
			},
		},
	}, "", false)

	var c cfg
	rulesFromPolicyPack(pp, &c)

	if c.SoftCapability != "enforce.traffic.rate_limit" {
		t.Errorf("SoftCapability: got %q, want enforce.traffic.rate_limit", c.SoftCapability)
	}
	if c.BlockCapability != "enforce.access.deny" {
		t.Errorf("BlockCapability: got %q, want enforce.access.deny", c.BlockCapability)
	}
}

func TestRulesFromPolicyPack_LegacyNetworkIDNormalised(t *testing.T) {
	// Existing packs using old network.* IDs still work.
	pp := makeTestPack([]policy.RuleSpec{
		{
			When: policy.WhenSpec{FsmLevel: "soft"},
			Then: policy.ThenSpec{
				Capability: "network.rate_limit_source",
				TTL:        makeDuration(5 * time.Minute),
			},
		},
	}, "", false)

	var c cfg
	rulesFromPolicyPack(pp, &c)

	if c.SoftCapability != "enforce.traffic.rate_limit" {
		t.Errorf("SoftCapability: got %q", c.SoftCapability)
	}
}

func TestRulesFromPolicyPack_GraphFreezePreserved(t *testing.T) {
	// Graph freeze rules are unchanged by the capability addition.
	pp := makeTestPack([]policy.RuleSpec{
		{
			When: policy.WhenSpec{Signal: "graph.new_edge_after_freeze"},
			Then: policy.ThenSpec{Action: "rate_limit", TTL: makeDuration(15 * time.Minute)},
		},
	}, "", false)

	var c cfg
	rulesFromPolicyPack(pp, &c)

	if c.GraphFreezeTTL != 15*time.Minute {
		t.Errorf("GraphFreezeTTL: got %v", c.GraphFreezeTTL)
	}
	if c.GraphFreezeAction != "rate_limit" {
		t.Errorf("GraphFreezeAction: got %q", c.GraphFreezeAction)
	}
}

// ── applyPolicyPackToCfg ──────────────────────────────────────────────────────

func TestApplyPolicyPackToCfg_MaxActionSetsMainFSM(t *testing.T) {
	pp := makeTestPack([]policy.RuleSpec{
		{When: policy.WhenSpec{FsmLevel: "soft"}, Then: policy.ThenSpec{TTL: makeDuration(time.Minute)}},
	}, "rate_limit", false)

	var c cfg
	applyPolicyPackToCfg(pp, &c)

	if c.PolicyMaxAction != "rate_limit" {
		t.Errorf("PolicyMaxAction: got %q, want rate_limit", c.PolicyMaxAction)
	}
	// Also applied to graph freeze (existing behaviour).
	if c.GraphFreezeMaxAction != "rate_limit" {
		t.Errorf("GraphFreezeMaxAction: got %q, want rate_limit", c.GraphFreezeMaxAction)
	}
}

func TestApplyPolicyPackToCfg_EmptyMaxActionNoOp(t *testing.T) {
	pp := makeTestPack([]policy.RuleSpec{
		{When: policy.WhenSpec{FsmLevel: "soft"}, Then: policy.ThenSpec{TTL: makeDuration(time.Minute)}},
	}, "", false)

	var c cfg
	c.PolicyMaxAction = "block" // pre-set, should not be overwritten by empty
	applyPolicyPackToCfg(pp, &c)

	if c.PolicyMaxAction != "block" {
		t.Errorf("PolicyMaxAction should not be overwritten by empty: got %q", c.PolicyMaxAction)
	}
}

func TestApplyPolicyPackToCfg_DryRun(t *testing.T) {
	pp := makeTestPack([]policy.RuleSpec{
		{When: policy.WhenSpec{FsmLevel: "soft"}, Then: policy.ThenSpec{TTL: makeDuration(time.Minute)}},
	}, "observe", false)
	pp.Spec.Autonomy.DryRun = true

	var c cfg
	applyPolicyPackToCfg(pp, &c)

	if !c.DryRun {
		t.Error("DryRun should be true")
	}
	if c.PolicyMaxAction != "observe" {
		t.Errorf("PolicyMaxAction: got %q, want observe", c.PolicyMaxAction)
	}
}

// ── FSM intent facts ──────────────────────────────────────────────────────────

// newTestCfg builds a minimal cfg for FSM intent and RuntimePDP integration tests.
// SevStep/Delta thresholds are set so that Severity=99 adds 3 strikes per tick.
// With BlockAt=3, a single tick is enough to reach LevelBlock (no cap).
func newTestCfg(maxAction string) cfg {
	c := cfg{
		// Severity bands: step1=1, step2=50, step3=75 → Severity=99 hits step3.
		SevStep1: 1.0, SevStep2: 50.0, SevStep3: 75.0,
		SevDelta1: 1, SevDelta2: 2, SevDelta3: 3,
		// FSM thresholds: reach each level after 1/2/3 strikes.
		SoftAt: 1, HardAt: 2, BlockAt: 3,
		SoftTTL: time.Minute, HardTTL: time.Minute, BlockTTL: time.Minute,
		Cooldown:        0,
		PolicyMaxAction: maxAction,
	}
	// PolicyMaxAction is only enforced in managed mode with a loaded pack.
	// Tests that verify cap behaviour must simulate a managed node with a pack.
	if maxAction != "" {
		c.Mode = string(policy.ModeManaged)
		c.HasPolicyPack = true
	}
	c.adapterParams = catalog.DefaultCapabilityParams(catalog.DefaultAdapterID)
	return c
}

func highSeverityMetrics() metrics {
	return metrics{
		Target: adapterruntime.SourceTarget{SourceID: "source-1"},
		Score:  99,
		Signals: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond: 50000,
			adapterruntime.MetricNetworkSynRate:          5000,
		},
	}
}

func runFSMIntent(n int, c cfg) fsmIntent {
	m := highSeverityMetrics()
	st := fsm.State{Level: fsm.LevelObserve}
	now := time.Now()
	intent := fsmIntent{SignalState: st, ProposedLevel: st.Level}

	for i := 0; i < n; i++ {
		intent = evaluateFSMIntent(m, st, now, c)
		st = intent.SignalState
		now = now.Add(time.Second)
	}
	return intent
}

func TestFSMIntentSuggestsBlockForHighSeverity(t *testing.T) {
	c := newTestCfg("")
	intent := runFSMIntent(3, c)
	if intent.ProposedLevel != fsm.LevelBlock {
		t.Errorf("expected FSM intent to propose block, got %s", intent.ProposedLevel)
	}
}

func TestFSMIntentDoesNotApplyPolicyCeiling(t *testing.T) {
	c := newTestCfg("observe")
	intent := runFSMIntent(3, c)
	if intent.ProposedLevel != fsm.LevelBlock {
		t.Errorf("expected FSM to provide raw signal intent before policy resolution, got %s", intent.ProposedLevel)
	}
}

func TestGraphBaselineStrikeProcessesSyntheticCandidate(t *testing.T) {
	c := newTestCfg("")
	c.HasPolicyPack = true
	c.PolicyMaxAction = "block"
	c.UpNeed = 1
	c.BlockMinSev = 0
	c.BlockMinDur = 0
	c.SoftTTL = 0
	c.HardTTL = 0
	c.BlockTTL = 0

	sources := newSourceStates()
	cands := []metrics{}
	now := time.Now()
	sources.applyGraphStrike(&cands, graphStrikeMsg{
		sourceID:    "source-1",
		signalScore: 99,
		addToCands:  true,
	}, now, c)
	if len(cands) != 1 {
		t.Fatalf("expected graph strike to add a synthetic candidate, got %d", len(cands))
	}

	resolver := c.buildPolicyResolver()
	executor := newBrokeredActionExecutor(buildExecutor(nil), nil, nil, nil, nil, nil, "node-test")
	wl := sourcefilters.NewWhitelist("")
	fb := sourcefilters.NewFeedback("")
	processed := sources.processCandidates(cands, now, c, wl, fb, resolver, executor, nil, false, nil, "node-test", nil, nil)
	if !processed["source-1"] {
		t.Fatal("expected source-1 to be processed")
	}
	entry := sources.entries["source-1"]
	if entry.state.Level != fsm.LevelObserve {
		t.Fatalf("shadow/no-pdp processing must not enforce graph baseline signal, got %s", entry.state.Level)
	}
	if entry.state.Strikes == 0 {
		t.Fatal("expected graph baseline signal to update FSM intent facts")
	}
}

// ── Phase 6a: Adaptive rate params ───────────────────────────────────────────

func TestToPEPParams_StaticMode(t *testing.T) {
	// Default: no factors → static params from adapterParams.
	c := cfg{}
	c.adapterParams.SoftRatePPS = 20
	c.adapterParams.SoftBurst = 40
	c.adapterParams.HardRatePPS = 5
	c.adapterParams.HardBurst = 10
	c.TrigPPS = 1000

	p := c.toPEPParams()
	if p.SoftRate != 20 {
		t.Errorf("static soft rate: got %d, want 20", p.SoftRate)
	}
	if p.HardRate != 5 {
		t.Errorf("static hard rate: got %d, want 5", p.HardRate)
	}
}

func TestToPEPParams_AdaptiveMode(t *testing.T) {
	// Adaptive: factors set → rates derived from TrigPPS.
	c := cfg{
		SoftRateFactor:       0.5,
		HardRateFactor:       0.1,
		LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 1000},
	}
	c.adapterParams.SoftRatePPS = 20 // ignored in adaptive mode
	c.adapterParams.HardRatePPS = 5  // ignored in adaptive mode

	p := c.toPEPParams()
	if p.SoftRate != 500 {
		t.Errorf("adaptive soft rate: got %d, want 500 (1000×0.5)", p.SoftRate)
	}
	if p.SoftBurst != 1000 {
		t.Errorf("adaptive soft burst: got %d, want 1000 (rate×2)", p.SoftBurst)
	}
	if p.HardRate != 100 {
		t.Errorf("adaptive hard rate: got %d, want 100 (1000×0.1)", p.HardRate)
	}
	if p.HardBurst != 200 {
		t.Errorf("adaptive hard burst: got %d, want 200 (rate×2)", p.HardBurst)
	}
}

func TestToPEPParams_AdaptiveTracksAutotune(t *testing.T) {
	// When TrigPPS changes (autotune), rates change accordingly.
	c := cfg{
		SoftRateFactor:       0.5,
		HardRateFactor:       0.1,
		LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 500},
	}

	p1 := c.toPEPParams()
	if p1.SoftRate != 250 {
		t.Errorf("before autotune: soft rate got %d, want 250", p1.SoftRate)
	}

	c.TrigPPS = 200 // autotune lowers threshold (traffic baseline dropped)
	p2 := c.toPEPParams()
	if p2.SoftRate != 100 {
		t.Errorf("after autotune: soft rate got %d, want 100", p2.SoftRate)
	}
}

func TestToPEPParams_AdaptiveMinimum(t *testing.T) {
	// Tiny TrigPPS must not produce zero rate.
	c := cfg{
		SoftRateFactor:       0.5,
		HardRateFactor:       0.1,
		LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 1},
	}
	p := c.toPEPParams()
	if p.SoftRate < 1 {
		t.Errorf("soft rate must be at least 1, got %d", p.SoftRate)
	}
	if p.HardRate < 1 {
		t.Errorf("hard rate must be at least 1, got %d", p.HardRate)
	}
}

// ── Phase 6b: Directive rate mode ────────────────────────────────────────────

func TestToPEPParams_DirectiveOverridesAdaptive(t *testing.T) {
	// Directive rate beats adaptive factor — Forge policy wins.
	c := cfg{
		SoftRateFactor:       0.5,
		HardRateFactor:       0.1,
		LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 1000},
		SoftDirectiveRatePPS: 200,
		HardDirectiveRatePPS: 50,
	}
	p := c.toPEPParams()
	if p.SoftRate != 200 {
		t.Errorf("directive soft rate: got %d, want 200", p.SoftRate)
	}
	if p.HardRate != 50 {
		t.Errorf("directive hard rate: got %d, want 50", p.HardRate)
	}
}

func TestToPEPParams_DirectiveOverridesStatic(t *testing.T) {
	// Directive rate also beats static adapter params.
	c := cfg{SoftDirectiveRatePPS: 100}
	c.adapterParams.SoftRatePPS = 20
	c.adapterParams.SoftBurst = 40
	c.adapterParams.HardRatePPS = 5

	p := c.toPEPParams()
	if p.SoftRate != 100 {
		t.Errorf("directive over static: got %d, want 100", p.SoftRate)
	}
	// Hard: no directive set → static value applies
	if p.HardRate != 5 {
		t.Errorf("hard unchanged: got %d, want 5", p.HardRate)
	}
}

func TestParseRatePPS(t *testing.T) {
	cases := []struct {
		params map[string]string
		want   uint64
	}{
		{map[string]string{"rate_pps": "100"}, 100},
		{map[string]string{"rate_pps": "0"}, 0},   // zero → not set
		{map[string]string{"rate_pps": "abc"}, 0}, // invalid → not set
		{map[string]string{"ttl": "10m"}, 0},      // absent → not set
		{nil, 0},
	}
	for _, tc := range cases {
		got := parseRatePPS(tc.params)
		if got != tc.want {
			t.Errorf("parseRatePPS(%v) = %d, want %d", tc.params, got, tc.want)
		}
	}
}

func TestRulesFromPolicyPack_DirectiveRatePPS(t *testing.T) {
	pp := makeTestPack([]policy.RuleSpec{
		{
			When: policy.WhenSpec{FsmLevel: "soft"},
			Then: policy.ThenSpec{
				Capability: "enforce.traffic.rate_limit",
				TTL:        makeDuration(10 * time.Minute),
				Params:     map[string]string{"rate_pps": "150"},
			},
		},
		{
			When: policy.WhenSpec{FsmLevel: "hard"},
			Then: policy.ThenSpec{
				Capability: "enforce.traffic.rate_limit",
				TTL:        makeDuration(20 * time.Minute),
				Params:     map[string]string{"rate_pps": "30"},
			},
		},
	}, "", false)

	var c cfg
	rulesFromPolicyPack(pp, &c)

	if c.SoftDirectiveRatePPS != 150 {
		t.Errorf("SoftDirectiveRatePPS: got %d, want 150", c.SoftDirectiveRatePPS)
	}
	if c.HardDirectiveRatePPS != 30 {
		t.Errorf("HardDirectiveRatePPS: got %d, want 30", c.HardDirectiveRatePPS)
	}
}

func TestV11PackWithDirectiveRate(t *testing.T) {
	const packWithRate = `
apiVersion: kernloom.io/kliq/v1alpha1
kind: LocalPolicyPack
metadata:
  name: api-rate-limit
spec:
  action_authorization:
    allowed_capabilities:
      - enforce.traffic.rate_limit
    default_effect: deny
  rules:
    - when:
        capability: enforce.traffic.rate_limit
      then:
        capability: enforce.traffic.rate_limit
        ttl: 10m
        params:
          rate_pps: "100"
`
	c := loadPackFromYAML(t, packWithRate)

	// Directive rate set → access-control mode.
	if c.SoftDirectiveRatePPS != 100 {
		t.Errorf("SoftDirectiveRatePPS: got %d, want 100", c.SoftDirectiveRatePPS)
	}
	// PolicyMaxAction still capped at rate_limit (no block in allowed_capabilities).
	if c.PolicyMaxAction != "rate_limit" {
		t.Errorf("PolicyMaxAction: got %q, want rate_limit", c.PolicyMaxAction)
	}
	// toPEPParams respects the directive.
	c.TrigPPS = 1000 // would give 500pps adaptively, directive should win
	c.SoftRateFactor = 0.5
	p := c.toPEPParams()
	if p.SoftRate != 100 {
		t.Errorf("toPEPParams soft rate: got %d, want 100 (directive wins over adaptive)", p.SoftRate)
	}
}
