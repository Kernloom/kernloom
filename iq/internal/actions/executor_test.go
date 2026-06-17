// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

// newDryRunExecutor creates an executor backed by a dry-run adapter (no BPF maps).
func newDryRunExecutor() *actions.ShieldActionExecutor {
	return actions.NewShieldActionExecutor(shieldpep.New(nil, true))
}

func allowedResolution(level string) actions.ActionResolution {
	return actions.ActionResolution{
		Allowed:          true,
		ExecutableLevel:  level,
		ExecutableAction: "enforce.traffic.rate_limit",
	}
}

func deniedResolution(reason string) actions.ActionResolution {
	return actions.ActionResolution{
		Allowed:         false,
		DenyReason:      reason,
		ExecutableLevel: "observe",
	}
}

var (
	testIP4    = [4]byte{10, 0, 0, 1}
	testIP6    = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1}
	testState  = fsm.State{Level: fsm.LevelObserve}
	testParams = shieldpep.EnforcementParams{SoftRate: 100, SoftBurst: 200, HardRate: 20, HardBurst: 40}
	testNow    = time.Now()
)

// ── Apply4 ────────────────────────────────────────────────────────────────────

func TestApply4_Allowed_ReturnsApplied(t *testing.T) {
	ex := newDryRunExecutor()
	_, result := ex.Apply4(testIP4, testState, allowedResolution("soft"), testParams, testNow)
	if result.Status != "applied" {
		t.Errorf("allowed soft: expected status=applied, got %q", result.Status)
	}
}

func TestApply4_Allowed_LevelSetCorrectly(t *testing.T) {
	ex := newDryRunExecutor()
	cases := []struct {
		level     string
		wantLevel fsm.Level
	}{
		{"soft", fsm.LevelSoft},
		{"hard", fsm.LevelHard},
		{"block", fsm.LevelBlock},
		{"observe", fsm.LevelObserve},
	}
	for _, tc := range cases {
		newSt, _ := ex.Apply4(testIP4, testState, allowedResolution(tc.level), testParams, testNow)
		if newSt.Level != tc.wantLevel {
			t.Errorf("Apply4 level=%s: got FSM level %v, want %v", tc.level, newSt.Level, tc.wantLevel)
		}
	}
}

func TestApply4_Denied_DeEnforcesToObserve(t *testing.T) {
	ex := newDryRunExecutor()
	startState := fsm.State{Level: fsm.LevelHard}
	newSt, result := ex.Apply4(testIP4, startState, deniedResolution("capability_not_in_policy_pack(enforce.access.deny)"), testParams, testNow)
	if newSt.Level != fsm.LevelObserve {
		t.Errorf("denied: expected FSM level=observe, got %v", newSt.Level)
	}
	if result.Status != "denied" {
		t.Errorf("denied: expected status=denied, got %q", result.Status)
	}
	if result.Reason == "" {
		t.Error("denied: expected non-empty Reason")
	}
}

func TestApply4_Downgraded_StatusIsDowngraded(t *testing.T) {
	ex := newDryRunExecutor()
	res := actions.ActionResolution{
		Allowed:         true,
		ExecutableLevel: "soft",
		DenyReason:      "policy_max_action_ceiling",
	}
	_, result := ex.Apply4(testIP4, testState, res, testParams, testNow)
	if result.Status != "downgraded" {
		t.Errorf("downgraded: expected status=downgraded, got %q", result.Status)
	}
}

func TestApply4_ProposalIDPropagated(t *testing.T) {
	ex := newDryRunExecutor()
	res := allowedResolution("soft")
	res.ProposalID = "test-proposal-42"
	_, result := ex.Apply4(testIP4, testState, res, testParams, testNow)
	if result.ProposalID != "test-proposal-42" {
		t.Errorf("ProposalID not propagated: got %q", result.ProposalID)
	}
}

func TestApply4_AppliedAt_Set(t *testing.T) {
	ex := newDryRunExecutor()
	_, result := ex.Apply4(testIP4, testState, allowedResolution("soft"), testParams, testNow)
	if result.AppliedAt.IsZero() {
		t.Error("AppliedAt should not be zero")
	}
	if result.AppliedAt != testNow {
		t.Errorf("AppliedAt: got %v, want %v", result.AppliedAt, testNow)
	}
}

// ── Apply6 ────────────────────────────────────────────────────────────────────

func TestApply6_Allowed_ReturnsApplied(t *testing.T) {
	ex := newDryRunExecutor()
	_, result := ex.Apply6(testIP6, testState, allowedResolution("soft"), testParams, testNow)
	if result.Status != "applied" {
		t.Errorf("Apply6 allowed: expected applied, got %q", result.Status)
	}
}

func TestApply6_Denied_DeEnforcesToObserve(t *testing.T) {
	ex := newDryRunExecutor()
	newSt, result := ex.Apply6(testIP6, fsm.State{Level: fsm.LevelSoft}, deniedResolution("managed_no_policy_pack"), testParams, testNow)
	if newSt.Level != fsm.LevelObserve {
		t.Errorf("Apply6 denied: expected observe, got %v", newSt.Level)
	}
	if result.Status != "denied" {
		t.Errorf("Apply6 denied: expected denied, got %q", result.Status)
	}
}

// ── ApplyDeEnforce4 ───────────────────────────────────────────────────────────

func TestApplyDeEnforce4_AlwaysObserve(t *testing.T) {
	ex := newDryRunExecutor()
	for _, startLevel := range []fsm.Level{fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		st := fsm.State{Level: startLevel}
		newSt := ex.ApplyDeEnforce4(testIP4, st, testParams, testNow)
		if newSt.Level != fsm.LevelObserve {
			t.Errorf("ApplyDeEnforce4 from %v: expected observe, got %v", startLevel, newSt.Level)
		}
	}
}

func TestApplyDeEnforce4_ObserveIsNoop(t *testing.T) {
	ex := newDryRunExecutor()
	st := fsm.State{Level: fsm.LevelObserve}
	newSt := ex.ApplyDeEnforce4(testIP4, st, testParams, testNow)
	if newSt.Level != fsm.LevelObserve {
		t.Errorf("ApplyDeEnforce4 from observe: expected observe, got %v", newSt.Level)
	}
}

// ── ApplyDeEnforce6 ───────────────────────────────────────────────────────────

func TestApplyDeEnforce6_AlwaysObserve(t *testing.T) {
	ex := newDryRunExecutor()
	newSt := ex.ApplyDeEnforce6(testIP6, fsm.State{Level: fsm.LevelBlock}, testParams, testNow)
	if newSt.Level != fsm.LevelObserve {
		t.Errorf("ApplyDeEnforce6: expected observe, got %v", newSt.Level)
	}
}

// ── ApplyTuple4 ───────────────────────────────────────────────────────────────

var testEdgeKey, _ = shieldclient.NewEdge4Key("10.0.0.1", 443, "tcp")

func TestApplyTuple4_Allowed_Block_Applied(t *testing.T) {
	ex := newDryRunExecutor()
	res := actions.ActionResolution{Allowed: true, ExecutableLevel: "block", ExecutableAction: "enforce.access.deny"}
	result := ex.ApplyTuple4(testEdgeKey, res, testNow)
	if result.Status != "applied" {
		t.Errorf("ApplyTuple4 block: expected applied, got %q", result.Status)
	}
}

func TestApplyTuple4_Denied_StatusIsDenied(t *testing.T) {
	ex := newDryRunExecutor()
	result := ex.ApplyTuple4(testEdgeKey, deniedResolution("managed_no_policy_pack"), testNow)
	if result.Status != "denied" {
		t.Errorf("ApplyTuple4 denied: expected denied, got %q", result.Status)
	}
	if result.Reason == "" {
		t.Error("denied tuple: expected non-empty Reason")
	}
}

func TestApplyTuple4_AllowedButNotBlock_Skipped(t *testing.T) {
	// Tuple enforcement is binary: only block is applied; rate_limit downgrades to skipped.
	ex := newDryRunExecutor()
	res := actions.ActionResolution{Allowed: true, ExecutableLevel: "soft", DenyReason: "policy_max_action_ceiling"}
	result := ex.ApplyTuple4(testEdgeKey, res, testNow)
	if result.Status != "skipped" {
		t.Errorf("ApplyTuple4 non-block: expected skipped, got %q", result.Status)
	}
}
