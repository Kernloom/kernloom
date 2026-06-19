// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"testing"

	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/policy"
)

// ── resolveLevel ─────────────────────────────────────────────────────────────

func TestResolveLevel_StandaloneNoChange(t *testing.T) {
	// In standalone mode, resolveLevel must not change any level —
	// neither managed-no-pack nor PolicyMaxAction rules apply.
	c := cfg{Mode: string(policy.ModeStandalone)}
	for _, level := range []fsm.Level{fsm.LevelObserve, fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		got, reason := c.resolveLevel(level)
		if got != level {
			t.Errorf("standalone mode: resolveLevel(%s) = %s (want unchanged), reason=%q", level, got, reason)
		}
		if reason != "" {
			t.Errorf("standalone mode: unexpected reason %q for level %s", reason, level)
		}
	}
}

func TestResolveLevel_ManagedWithPackNoChange(t *testing.T) {
	// Managed mode WITH a valid pack: only PolicyMaxAction rules apply.
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: true, PolicyMaxAction: ""}
	for _, level := range []fsm.Level{fsm.LevelObserve, fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		got, reason := c.resolveLevel(level)
		if got != level {
			t.Errorf("managed+pack, no cap: resolveLevel(%s) = %s, reason=%q", level, got, reason)
		}
	}
}

func TestResolveLevel_ManagedNoPack_AlwaysObserve(t *testing.T) {
	// Managed mode WITHOUT a pack: ALL enforcement is blocked — observe only.
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: false}
	for _, level := range []fsm.Level{fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		got, reason := c.resolveLevel(level)
		if got != fsm.LevelObserve {
			t.Errorf("managed, no pack: resolveLevel(%s) = %s (want Observe)", level, got)
		}
		if reason != "managed_no_policy_pack" {
			t.Errorf("unexpected reason %q (want managed_no_policy_pack)", reason)
		}
	}
}

func TestResolveLevel_ManagedNoPack_ObserveUnchanged(t *testing.T) {
	// LevelObserve stays observe regardless.
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: false}
	got, _ := c.resolveLevel(fsm.LevelObserve)
	if got != fsm.LevelObserve {
		t.Errorf("observe should stay observe, got %s", got)
	}
}

func TestResolveLevel_ManagedWithPack_RateLimitCap(t *testing.T) {
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: true, PolicyMaxAction: "rate_limit"}
	cases := []struct {
		input fsm.Level
		want  fsm.Level
	}{
		{fsm.LevelObserve, fsm.LevelObserve},
		{fsm.LevelSoft, fsm.LevelSoft},
		{fsm.LevelHard, fsm.LevelSoft},
		{fsm.LevelBlock, fsm.LevelSoft},
	}
	for _, tc := range cases {
		got, _ := c.resolveLevel(tc.input)
		if got != tc.want {
			t.Errorf("rate_limit cap: resolveLevel(%s) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestResolveLevel_ManagedWithPack_ObserveCap(t *testing.T) {
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: true, PolicyMaxAction: "observe"}
	for _, level := range []fsm.Level{fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		got, _ := c.resolveLevel(level)
		if got != fsm.LevelObserve {
			t.Errorf("observe cap: resolveLevel(%s) = %s (want Observe)", level, got)
		}
	}
}

func TestResolveLevel_DowngradeReasonSet(t *testing.T) {
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: true, PolicyMaxAction: "rate_limit"}
	_, reason := c.resolveLevel(fsm.LevelBlock)
	if reason == "" {
		t.Error("expected a non-empty reason when level is downgraded")
	}
}

func TestResolveLevel_NoDowngradeNoReason(t *testing.T) {
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: true, PolicyMaxAction: "rate_limit"}
	_, reason := c.resolveLevel(fsm.LevelSoft) // soft ≤ rate_limit ceiling → no change
	if reason != "" {
		t.Errorf("expected empty reason when no downgrade, got %q", reason)
	}
}

// ── resolveDecisionAction ────────────────────────────────────────────────────

func TestResolveDecisionAction_StandaloneNoChange(t *testing.T) {
	c := cfg{Mode: string(policy.ModeStandalone)}
	for _, a := range []decision.ActionType{
		decision.ActionObserve, decision.ActionRateLimit, decision.ActionBlock,
	} {
		got := c.resolveDecisionAction(a)
		if got != a {
			t.Errorf("standalone: resolveDecisionAction(%s) = %s (want unchanged)", a, got)
		}
	}
}

func TestResolveDecisionAction_ManagedNoPack_AllObserve(t *testing.T) {
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: false}
	for _, a := range []decision.ActionType{decision.ActionRateLimit, decision.ActionBlock} {
		got := c.resolveDecisionAction(a)
		if got != decision.ActionObserve {
			t.Errorf("managed no-pack: resolveDecisionAction(%s) = %s (want Observe)", a, got)
		}
	}
}

func TestResolveDecisionAction_ManagedWithPack_RateLimitCap(t *testing.T) {
	c := cfg{Mode: string(policy.ModeManaged), HasPolicyPack: true, PolicyMaxAction: "rate_limit"}
	got := c.resolveDecisionAction(decision.ActionBlock)
	if got != decision.ActionRateLimit {
		t.Errorf("rate_limit cap: block → %s (want RateLimit)", got)
	}
	got = c.resolveDecisionAction(decision.ActionRateLimit)
	if got != decision.ActionRateLimit {
		t.Errorf("rate_limit cap: rate_limit stays → %s", got)
	}
}
