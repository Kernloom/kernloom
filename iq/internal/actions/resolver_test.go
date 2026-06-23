// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions_test

import (
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
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

func neverAutoBlockAdmins() contracts.RuntimeGuardrail {
	return contracts.RuntimeGuardrail{
		ID:   "never-auto-block-admins",
		Type: "never",
		Subject: contracts.RuntimeGuardrailSubject{
			Type: "group",
			Ref:  "kernloom-admins",
		},
		ForbiddenActions: []string{
			"enforce.access.deny",
			"enforce.traffic.drop",
			"enforce.network.quarantine",
			"enforce.identity.disable",
		},
		Enforcement: contracts.RuntimeGuardrailEnforcement{
			ViolationBehavior: "reject_action",
			UnknownBehavior:   "reject_hard_action",
		},
	}
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

func TestResolve_GuardrailRejectsProtectedSubjectBlock(t *testing.T) {
	r := managed("", "enforce.access.deny")
	r.RuntimeGuardrails = []contracts.RuntimeGuardrail{neverAutoBlockAdmins()}
	p := proposal("block", "enforce.access.deny")
	p.Target = actions.ActionTarget{
		Granularity: "subject",
		Value:       "group:kernloom-admins",
	}
	res := r.Resolve(p)
	if res.Allowed {
		t.Fatal("protected subject block should be denied")
	}
	if res.DenyReason != "guardrail_violation(never-auto-block-admins)" {
		t.Fatalf("deny reason = %q", res.DenyReason)
	}
	if res.ExecutableLevel != "observe" || res.ExecutableAction != "" {
		t.Fatalf("executable action should be observe/noop: %#v", res)
	}
}

func TestResolve_GuardrailRejectsUnknownBlastRadiusHardAction(t *testing.T) {
	r := managed("", "enforce.access.deny")
	r.RuntimeGuardrails = []contracts.RuntimeGuardrail{neverAutoBlockAdmins()}
	p := proposal("block", "enforce.access.deny")
	p.Target = actions.ActionTarget{
		Granularity: actions.TargetGranularitySource,
		Value:       "203.0.113.10",
	}
	res := r.Resolve(p)
	if res.Allowed {
		t.Fatal("source block with unknown protected-subject blast radius should be denied")
	}
	if res.DenyReason != "guardrail_unknown_match_for_hard_action(never-auto-block-admins)" {
		t.Fatalf("deny reason = %q", res.DenyReason)
	}
}

func TestResolve_GuardrailAllowsRateLimitUnknownBlastRadius(t *testing.T) {
	r := managed("", "enforce.traffic.rate_limit")
	r.RuntimeGuardrails = []contracts.RuntimeGuardrail{neverAutoBlockAdmins()}
	p := proposal("soft", "enforce.traffic.rate_limit")
	p.Target = actions.ActionTarget{
		Granularity: actions.TargetGranularitySource,
		Value:       "203.0.113.10",
	}
	res := r.Resolve(p)
	if !res.Allowed {
		t.Fatalf("rate limit should remain allowed, reason=%s", res.DenyReason)
	}
}

func TestResolve_ResponseBlastRadiusRejectsUnknownHardAction(t *testing.T) {
	r := managed("", "enforce.traffic.drop")
	p := proposal("block", "enforce.traffic.drop")
	p.Target = actions.ActionTarget{
		Granularity: actions.TargetGranularitySource,
		Value:       "203.0.113.10",
	}
	p.Parameters = map[string]any{
		"blast_radius": map[string]any{
			"unknown_behavior": "reject_hard_action",
			"excludes": []map[string]any{{
				"type": "group",
				"ref":  "kernloom-admins",
			}},
		},
	}
	res := r.Resolve(p)
	if res.Allowed {
		t.Fatal("unknown response blast radius should deny hard action")
	}
	if res.DenyReason != "blast_radius_unknown_target" {
		t.Fatalf("deny reason = %q", res.DenyReason)
	}
}

func TestResolve_AutonomyApprovalRequiredDeniesWithoutApproval(t *testing.T) {
	r := managed("block", "enforce.identity.disable")
	r.RuntimeAutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{
		ApprovalRequired: []contracts.RuntimeAutonomyApprovalRequirement{{
			Action: "enforce.identity.disable",
		}},
	}
	res := r.Resolve(proposal("block", "enforce.identity.disable"))
	if res.Allowed {
		t.Fatal("identity disable without approval should be denied")
	}
	if res.DenyReason != "autonomy_approval_required(enforce.identity.disable)" {
		t.Fatalf("deny reason = %q", res.DenyReason)
	}
}

func TestResolve_AutonomyApprovalEvidenceAllowsAction(t *testing.T) {
	r := managed("block", "enforce.identity.disable")
	r.RuntimeAutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{
		ApprovalRequired: []contracts.RuntimeAutonomyApprovalRequirement{{
			Action: "enforce.identity.disable",
		}},
	}
	p := proposal("block", "enforce.identity.disable")
	p.Parameters = map[string]any{"approval_granted": true}
	res := r.Resolve(p)
	if !res.Allowed {
		t.Fatalf("approved action denied: %s", res.DenyReason)
	}
}

func TestResolve_AutonomyMaxActionDurationClampsTTL(t *testing.T) {
	r := managed("block", "enforce.traffic.drop")
	r.RuntimeAutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{
		MaxActionDuration: []contracts.RuntimeAutonomyActionDurationLimit{{
			Action:   "enforce.traffic.drop",
			Duration: contracts.NewDuration(15 * time.Minute),
		}},
	}
	p := proposal("block", "enforce.traffic.drop")
	p.TTL = 30 * time.Minute
	res := r.Resolve(p)
	if !res.Allowed {
		t.Fatalf("action denied: %s", res.DenyReason)
	}
	if res.TTL != 15*time.Minute {
		t.Fatalf("ttl = %s, want 15m", res.TTL)
	}
	if res.DenyReason != "autonomy_max_action_duration_clamped" {
		t.Fatalf("reason = %q", res.DenyReason)
	}
}

func TestResolve_AutonomyRequiresAuditAnnotatesResolution(t *testing.T) {
	r := managed("block", "enforce.traffic.drop")
	r.RuntimeAutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{RequiresAudit: true}
	res := r.Resolve(proposal("block", "enforce.traffic.drop"))
	if !res.Allowed {
		t.Fatalf("action denied: %s", res.DenyReason)
	}
	if got := res.Parameters["requires_audit_receipt"]; got != true {
		t.Fatalf("requires_audit_receipt = %#v", got)
	}
}

func TestResolve_AutonomySubjectAllowanceRequiresUnknownSource(t *testing.T) {
	r := managed("block", "enforce.traffic.rate_limit")
	r.RuntimeAutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{
		Allow: []contracts.RuntimeAutonomyAllowance{{
			Action:  "enforce.traffic.rate_limit",
			Subject: contracts.RuntimeAutonomySubject{Type: "source", Ref: "unknown"},
		}},
	}
	res := r.Resolve(proposal("hard", "enforce.traffic.rate_limit"))
	if res.Allowed {
		t.Fatal("missing source classification should be denied")
	}
	if res.DenyReason != "autonomy_subject_not_allowed(source:unknown)" {
		t.Fatalf("deny reason = %q", res.DenyReason)
	}

	p := proposal("hard", "enforce.traffic.rate_limit")
	p.Parameters = map[string]any{"source_class": "unknown"}
	res = r.Resolve(p)
	if !res.Allowed {
		t.Fatalf("unknown source should be allowed: %s", res.DenyReason)
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
