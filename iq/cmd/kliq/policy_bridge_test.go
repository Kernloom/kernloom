// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"os"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
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
	c.adapterParams = shieldpep.DefaultCapabilityParams()
	return c
}

// ── normalizeCapabilityID ─────────────────────────────────────────────────────

func TestNormalizeCapabilityID_ForgeToKLIQ(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"enforce.traffic.rate_limit", "network.rate_limit_source"},
		{"enforce.access.deny", "network.block_source"},
		{"enforce.traffic.drop", "network.block_source"},
		{"enforce.traffic.quarantine", "network.block_source"},
		{"enforce.access.allow", "network.allow_source"},
		{"enforce.access.default_deny", "network.enforce_allowlist"},
		{"enforce.network.deny", "network.block_source"},
		{"enforce.network.rate_limit", "network.rate_limit_source"},
		// Already KLIQ IDs pass through unchanged.
		{"network.rate_limit_source", "network.rate_limit_source"},
		{"network.block_source", "network.block_source"},
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

	if c.SoftCapability != "network.rate_limit_source" {
		t.Errorf("SoftCapability: got %q, want network.rate_limit_source", c.SoftCapability)
	}
	if c.BlockCapability != "network.block_source" {
		t.Errorf("BlockCapability: got %q, want network.block_source", c.BlockCapability)
	}
}

func TestRulesFromPolicyPack_AlreadyKLIQIDPassThrough(t *testing.T) {
	// Existing packs using KLIQ-internal IDs still work.
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

	if c.SoftCapability != "network.rate_limit_source" {
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

// ── Integration: processCandidate4 with PolicyMaxAction ───────────────────────

// newTestCfg builds a minimal cfg for processCandidate4 integration tests.
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
	c.adapterParams = shieldpep.DefaultCapabilityParams()
	return c
}

// runFSM drives processCandidate4 n times with high-severity metrics and
// returns the final FSM state. Uses dryRun=true so no BPF maps are required.
func runFSM(n int, c cfg) fsm.State {
	pep := shieldpep.New(nil, true) // dryRun=true — no BPF maps needed
	resolver := c.buildPolicyResolver()
	executor := buildExecutor(pep)
	wl := newWhitelist("")
	fb := &feedbackManager{}
	r := newReservoir(16)

	m := metrics{
		IPVer:    4,
		IP4:      [4]byte{10, 0, 0, 1},
		PPS:      50000,
		SynRate:  5000,
		Severity: 99,
	}
	st := fsm.State{Level: fsm.LevelObserve}
	now := time.Now()

	for i := 0; i < n; i++ {
		st = processCandidate4(m, st, now, c, wl, fb, resolver, executor, r, r, r, r, false)
		now = now.Add(time.Second)
	}
	return st
}

func TestProcessCandidate4_DefaultAllowsBlock(t *testing.T) {
	// Without PolicyMaxAction the FSM can reach LevelBlock.
	c := newTestCfg("")
	st := runFSM(10, c)
	if st.Level < fsm.LevelHard {
		t.Errorf("expected FSM to reach at least LevelHard with no cap, got %s", st.Level)
	}
}

func TestProcessCandidate4_RateLimitCapPreventsBlock(t *testing.T) {
	// With max_action=rate_limit the FSM must not exceed LevelSoft.
	c := newTestCfg("rate_limit")
	st := runFSM(10, c)
	if st.Level > fsm.LevelSoft {
		t.Errorf("expected FSM capped at LevelSoft, got %s", st.Level)
	}
}

func TestProcessCandidate4_ObserveCapPreventsEnforcement(t *testing.T) {
	// With max_action=observe the FSM must stay at LevelObserve.
	c := newTestCfg("observe")
	st := runFSM(10, c)
	if st.Level != fsm.LevelObserve {
		t.Errorf("expected FSM at LevelObserve, got %s", st.Level)
	}
}

func TestProcessCandidate4_ExistingBehaviourUnchanged(t *testing.T) {
	// Regression: existing tests that depend on no PolicyMaxAction still pass.
	c := newTestCfg("")
	c.BootstrapActive = true
	c.BootstrapAllowBlock = false

	st := runFSM(10, c)
	// Bootstrap safety: block is capped at hard even without PolicyMaxAction.
	if st.Level == fsm.LevelBlock {
		t.Error("bootstrap safety should prevent LevelBlock when BootstrapAllowBlock=false")
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
		SoftRateFactor: 0.5,
		HardRateFactor: 0.1,
		TrigPPS:        1000,
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
		SoftRateFactor: 0.5,
		HardRateFactor: 0.1,
		TrigPPS:        500,
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
		SoftRateFactor: 0.5,
		HardRateFactor: 0.1,
		TrigPPS:        1, // very low threshold
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
		TrigPPS:              1000,
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
