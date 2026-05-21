// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions_test

import (
	"testing"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func proposal(level, action string) actions.ActionProposal {
	return actions.ActionProposal{
		DesiredLevel:  level,
		DesiredAction: action,
	}
}

func managed(maxAction string, caps ...string) actions.PolicyResolver {
	r := actions.PolicyResolver{
		Mode:            "managed",
		HasPolicyPack:   true,
		PolicyMaxAction: maxAction,
	}
	if len(caps) > 0 {
		r.CapabilitiesAllowed = make(map[string]bool, len(caps))
		for _, c := range caps {
			r.CapabilitiesAllowed[c] = true
		}
	}
	return r
}

// ── Rule 1: standalone pass-through ──────────────────────────────────────────

func TestResolve_Standalone_PassThrough(t *testing.T) {
	r := actions.PolicyResolver{Mode: "standalone"}
	cases := []string{"observe", "soft", "hard", "block"}
	for _, level := range cases {
		res := r.Resolve(proposal(level, "enforce.access.deny"))
		if !res.Allowed {
			t.Errorf("standalone %s: expected Allowed=true", level)
		}
		if res.ExecutableLevel != level {
			t.Errorf("standalone %s: got level %q, want %q", level, res.ExecutableLevel, level)
		}
		if res.DenyReason != "" {
			t.Errorf("standalone %s: unexpected DenyReason %q", level, res.DenyReason)
		}
	}
}

func TestResolve_EmptyMode_TreatedAsStandalone(t *testing.T) {
	r := actions.PolicyResolver{} // Mode=""
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if !res.Allowed || res.ExecutableLevel != "block" {
		t.Error("empty mode should behave like standalone (pass-through)")
	}
}

// ── Rule 2: managed mode, no policy pack ─────────────────────────────────────

func TestResolve_ManagedNoPack_ObserveOnly(t *testing.T) {
	r := actions.PolicyResolver{Mode: "managed", HasPolicyPack: false}
	for _, level := range []string{"soft", "hard", "block"} {
		res := r.Resolve(proposal(level, "enforce.access.deny"))
		if !res.Allowed {
			t.Errorf("managed-no-pack %s: should be Allowed=true (de-enforced to observe)", level)
		}
		if res.ExecutableLevel != "observe" {
			t.Errorf("managed-no-pack %s: got %q, want observe", level, res.ExecutableLevel)
		}
		if res.DenyReason != "managed_no_policy_pack" {
			t.Errorf("managed-no-pack %s: got reason %q", level, res.DenyReason)
		}
	}
}

func TestResolve_ManagedNoPack_ObservePassesThrough(t *testing.T) {
	r := actions.PolicyResolver{Mode: "managed", HasPolicyPack: false}
	res := r.Resolve(proposal("observe", ""))
	if res.DenyReason != "managed_no_policy_pack" {
		// Even observe gets the reason set so callers can detect the state
		t.Errorf("observe should still carry managed_no_policy_pack reason")
	}
}

// ── Rule 3: PolicyMaxAction ceiling ──────────────────────────────────────────

func TestResolve_Observe_Cap(t *testing.T) {
	r := managed("observe")
	for _, level := range []string{"soft", "hard", "block"} {
		res := r.Resolve(proposal(level, "enforce.traffic.rate_limit"))
		if res.ExecutableLevel != "observe" {
			t.Errorf("observe cap: %s → got %q, want observe", level, res.ExecutableLevel)
		}
		if res.DenyReason != "policy_max_action_observe" {
			t.Errorf("observe cap: %s → reason %q", level, res.DenyReason)
		}
	}
}

func TestResolve_Observe_Cap_ObservePassesWithoutReason(t *testing.T) {
	r := managed("observe")
	res := r.Resolve(proposal("observe", ""))
	if res.DenyReason != "" {
		t.Errorf("observe proposing observe should not carry a DenyReason, got %q", res.DenyReason)
	}
}

func TestResolve_RateLimit_Cap(t *testing.T) {
	r := managed("rate_limit", "enforce.traffic.rate_limit")
	cases := []struct {
		level      string
		wantLevel  string
		wantReason string
	}{
		{"soft", "soft", ""},
		{"hard", "soft", "policy_max_action_ceiling"},
		{"block", "soft", "policy_max_action_ceiling"},
		{"observe", "observe", ""},
	}
	for _, tc := range cases {
		res := r.Resolve(proposal(tc.level, "enforce.traffic.rate_limit"))
		if res.ExecutableLevel != tc.wantLevel {
			t.Errorf("rate_limit cap %s: got level %q, want %q", tc.level, res.ExecutableLevel, tc.wantLevel)
		}
		if res.DenyReason != tc.wantReason {
			t.Errorf("rate_limit cap %s: got reason %q, want %q", tc.level, res.DenyReason, tc.wantReason)
		}
	}
}

func TestResolve_RateLimitHard_Cap(t *testing.T) {
	r := managed("rate_limit_hard", "enforce.traffic.rate_limit")
	cases := []struct {
		level     string
		wantLevel string
		capped    bool
	}{
		{"soft", "soft", false},
		{"hard", "hard", false},
		{"block", "hard", true},
	}
	for _, tc := range cases {
		res := r.Resolve(proposal(tc.level, "enforce.traffic.rate_limit"))
		if res.ExecutableLevel != tc.wantLevel {
			t.Errorf("rate_limit_hard cap %s: got %q, want %q", tc.level, res.ExecutableLevel, tc.wantLevel)
		}
		if tc.capped && res.DenyReason != "policy_max_action_ceiling" {
			t.Errorf("rate_limit_hard cap %s: expected ceiling reason, got %q", tc.level, res.DenyReason)
		}
		if !tc.capped && res.DenyReason != "" {
			t.Errorf("rate_limit_hard cap %s: unexpected reason %q", tc.level, res.DenyReason)
		}
	}
}

func TestResolve_NoMaxAction_NoCap(t *testing.T) {
	r := managed("", "enforce.access.deny")
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if res.ExecutableLevel != "block" {
		t.Errorf("empty max_action should not cap: got %q", res.ExecutableLevel)
	}
	if res.DenyReason != "" {
		t.Errorf("unexpected reason: %q", res.DenyReason)
	}
}

// ── Rule 4: CapabilitiesAllowed ───────────────────────────────────────────────

func TestResolve_CapabilityNotAllowed_Denied(t *testing.T) {
	r := managed("", "enforce.traffic.rate_limit") // only rate_limit allowed
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if res.Allowed {
		t.Error("enforce.access.deny not in allowlist: should be denied")
	}
	if res.ExecutableLevel != "observe" {
		t.Errorf("denied capability: expected observe, got %q", res.ExecutableLevel)
	}
	if res.DenyReason == "" {
		t.Error("denied capability: expected a DenyReason")
	}
}

func TestResolve_CapabilityAllowed_Passes(t *testing.T) {
	r := managed("", "enforce.access.deny", "enforce.traffic.rate_limit")
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if !res.Allowed {
		t.Error("enforce.access.deny in allowlist: should be allowed")
	}
	if res.ExecutableLevel != "block" {
		t.Errorf("allowed capability: expected block, got %q", res.ExecutableLevel)
	}
}

func TestResolve_EmptyAllowlist_AllPassed(t *testing.T) {
	// Nil CapabilitiesAllowed = no restriction (pack doesn't restrict capabilities).
	r := managed("")
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if !res.Allowed {
		t.Error("empty allowlist should allow all capabilities")
	}
}

func TestResolve_EmptyAction_SkipsCapCheck(t *testing.T) {
	// Rule 4 only fires when execAction != "".
	r := managed("", "enforce.traffic.rate_limit")
	res := r.Resolve(proposal("observe", ""))
	if !res.Allowed {
		t.Error("empty action should pass capability check")
	}
}

// ── Rule interaction: ceiling then cap-check ──────────────────────────────────

func TestResolve_CeilingDowngradesBeforeCapCheck(t *testing.T) {
	// Policy: rate_limit ceiling, only rate_limit allowed.
	// Proposal: block with enforce.access.deny.
	// Expected: block → rate_limit ceiling → rate_limit is in allowlist → allowed at soft.
	r := managed("rate_limit", "enforce.traffic.rate_limit")
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if !res.Allowed {
		t.Errorf("ceiling-then-capcheck: should be allowed after downgrade, got denied: %s", res.DenyReason)
	}
	if res.ExecutableLevel != "soft" {
		t.Errorf("ceiling-then-capcheck: expected soft after downgrade, got %q", res.ExecutableLevel)
	}
	if res.ExecutableAction != "enforce.traffic.rate_limit" {
		t.Errorf("ceiling-then-capcheck: expected rate_limit action, got %q", res.ExecutableAction)
	}
}

func TestResolve_CeilingDowngradesBeforeCapCheck_StillDenied(t *testing.T) {
	// Policy: rate_limit ceiling, only enforce.access.deny allowed (unusual but valid to test).
	// Proposal: block → ceiling downgrades to soft (enforce.traffic.rate_limit) → not in allowlist → denied.
	r := managed("rate_limit", "enforce.access.deny")
	res := r.Resolve(proposal("block", "enforce.access.deny"))
	if res.Allowed {
		t.Error("after ceiling downgrade, rate_limit not in allowlist: should be denied")
	}
}

// ── ProposalID propagation ────────────────────────────────────────────────────

func TestResolve_ProposalIDPropagated(t *testing.T) {
	r := actions.PolicyResolver{Mode: "standalone"}
	p := proposal("soft", "enforce.traffic.rate_limit")
	p.ID = "test-proposal-123"
	res := r.Resolve(p)
	if res.ProposalID != "test-proposal-123" {
		t.Errorf("ProposalID not propagated: got %q", res.ProposalID)
	}
}

// ── FSM helpers ───────────────────────────────────────────────────────────────

func TestFsmLevelName(t *testing.T) {
	cases := []struct {
		level fsm.Level
		want  string
	}{
		{fsm.LevelObserve, "observe"},
		{fsm.LevelSoft, "soft"},
		{fsm.LevelHard, "hard"},
		{fsm.LevelBlock, "block"},
	}
	for _, tc := range cases {
		got := actions.FsmLevelName(tc.level)
		if got != tc.want {
			t.Errorf("FsmLevelName(%v) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestParseFSMLevel(t *testing.T) {
	cases := []struct {
		s    string
		want fsm.Level
	}{
		{"soft", fsm.LevelSoft},
		{"hard", fsm.LevelHard},
		{"block", fsm.LevelBlock},
		{"observe", fsm.LevelObserve},
		{"", fsm.LevelObserve},
		{"unknown", fsm.LevelObserve},
	}
	for _, tc := range cases {
		got := actions.ParseFSMLevel(tc.s)
		if got != tc.want {
			t.Errorf("ParseFSMLevel(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestFsmLevelName_ParseFSMLevel_Roundtrip(t *testing.T) {
	levels := []fsm.Level{fsm.LevelObserve, fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock}
	for _, l := range levels {
		name := actions.FsmLevelName(l)
		back := actions.ParseFSMLevel(name)
		if back != l {
			t.Errorf("roundtrip %v: FsmLevelName=%q ParseFSMLevel=%v", l, name, back)
		}
	}
}
