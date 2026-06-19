// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

type mockSourcePEP struct{}

func (mockSourcePEP) TransitionSource(_ adapterruntime.SourceTarget, st fsm.State, target fsm.Level, now time.Time, params adapterruntime.EnforcementParams) (fsm.State, error) {
	return applyMockState(st, target, now, params), nil
}

func applyMockState(st fsm.State, target fsm.Level, now time.Time, params adapterruntime.EnforcementParams) fsm.State {
	st.Level = target
	st.CooldownUntil = now.Add(params.Cooldown)
	return st
}

// newDryRunExecutor creates an executor backed by an in-memory source PEP.
func newDryRunExecutor() *actions.SourceActionExecutor {
	return actions.NewSourceActionExecutor(mockSourcePEP{})
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
	testTarget = adapterruntime.SourceTarget{SourceID: "source-1"}
	testState  = fsm.State{Level: fsm.LevelObserve}
	testParams = adapterruntime.EnforcementParams{SoftRate: 100, SoftBurst: 200, HardRate: 20, HardBurst: 40}
	testNow    = time.Now()
)

// ── ApplySource ────────────────────────────────────────────────────────────────

func TestApplySource_Allowed_ReturnsApplied(t *testing.T) {
	ex := newDryRunExecutor()
	_, result := ex.ApplySource(testTarget, testState, allowedResolution("soft"), testParams, testNow)
	if result.Status != "applied" {
		t.Errorf("allowed soft: expected status=applied, got %q", result.Status)
	}
}

func TestApplySource_Allowed_LevelSetCorrectly(t *testing.T) {
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
		newSt, _ := ex.ApplySource(testTarget, testState, allowedResolution(tc.level), testParams, testNow)
		if newSt.Level != tc.wantLevel {
			t.Errorf("ApplySource level=%s: got FSM level %v, want %v", tc.level, newSt.Level, tc.wantLevel)
		}
	}
}

func TestApplySource_Denied_DeEnforcesToObserve(t *testing.T) {
	ex := newDryRunExecutor()
	startState := fsm.State{Level: fsm.LevelHard}
	newSt, result := ex.ApplySource(testTarget, startState, deniedResolution("capability_not_in_policy_pack(enforce.access.deny)"), testParams, testNow)
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

func TestApplySource_Downgraded_StatusIsDowngraded(t *testing.T) {
	ex := newDryRunExecutor()
	res := actions.ActionResolution{
		Allowed:         true,
		ExecutableLevel: "soft",
		DenyReason:      "policy_max_action_ceiling",
	}
	_, result := ex.ApplySource(testTarget, testState, res, testParams, testNow)
	if result.Status != "downgraded" {
		t.Errorf("downgraded: expected status=downgraded, got %q", result.Status)
	}
}

func TestApplySource_ProposalIDPropagated(t *testing.T) {
	ex := newDryRunExecutor()
	res := allowedResolution("soft")
	res.ProposalID = "test-proposal-42"
	_, result := ex.ApplySource(testTarget, testState, res, testParams, testNow)
	if result.ProposalID != "test-proposal-42" {
		t.Errorf("ProposalID not propagated: got %q", result.ProposalID)
	}
}

func TestApplySource_AppliedAt_Set(t *testing.T) {
	ex := newDryRunExecutor()
	_, result := ex.ApplySource(testTarget, testState, allowedResolution("soft"), testParams, testNow)
	if result.AppliedAt.IsZero() {
		t.Error("AppliedAt should not be zero")
	}
	if result.AppliedAt != testNow {
		t.Errorf("AppliedAt: got %v, want %v", result.AppliedAt, testNow)
	}
}

// ── ApplyDeEnforceSource ──────────────────────────────────────────────────────

func TestApplyDeEnforceSource_AlwaysObserve(t *testing.T) {
	ex := newDryRunExecutor()
	for _, startLevel := range []fsm.Level{fsm.LevelSoft, fsm.LevelHard, fsm.LevelBlock} {
		st := fsm.State{Level: startLevel}
		newSt := ex.ApplyDeEnforceSource(testTarget, st, testParams, testNow)
		if newSt.Level != fsm.LevelObserve {
			t.Errorf("ApplyDeEnforceSource from %v: expected observe, got %v", startLevel, newSt.Level)
		}
	}
}

func TestApplyDeEnforceSource_ObserveIsNoop(t *testing.T) {
	ex := newDryRunExecutor()
	st := fsm.State{Level: fsm.LevelObserve}
	newSt := ex.ApplyDeEnforceSource(testTarget, st, testParams, testNow)
	if newSt.Level != fsm.LevelObserve {
		t.Errorf("ApplyDeEnforceSource from observe: expected observe, got %v", newSt.Level)
	}
}
