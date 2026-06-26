// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtimepdp_test

import (
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
)

func TestDecideMatchesRiskRule(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("risk.level in ['high', 'critical'] && risk.confidence >= 0.8"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID:  "node-1",
		Subject: contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		Risk: contracts.LocalRiskAssessment{
			TypeMeta:     contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindLocalRiskAssessment},
			Subject:      contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:        contracts.RiskHigh,
			Score:        72,
			Confidence:   0.9,
			Completeness: 1.0,
			ValidUntil:   now.Add(2 * time.Minute),
			Model:        "kliq.localrisk.v1",
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected rule match")
	}
	if decision.Action.Capability != "enforce.traffic.rate_limit" {
		t.Fatalf("capability: %s", decision.Action.Capability)
	}
	if decision.Effect != "apply" {
		t.Fatalf("effect: %s", decision.Effect)
	}
	if !decision.ValidUntil.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("validUntil: %s", decision.ValidUntil)
	}
}

func TestDecideDefaultWhenNoRuleMatches(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("risk.level == 'critical'"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskMedium,
			Score:      50,
			ValidUntil: now.Add(time.Minute),
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if matched {
		t.Fatal("did not expect match")
	}
	if decision.Effect != "deny" {
		t.Fatalf("default effect: %s", decision.Effect)
	}
	if decision.Action.Capability != "" {
		t.Fatalf("default decision should not carry action: %#v", decision.Action)
	}
}

func TestDecideMatchesGenericMetricFacts(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("metrics.network.packets_per_second > baseline.network.packets_per_second * 2.0 && fsm.proposed_level == 'hard'"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID:  "node-1",
		Subject: contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		Risk: contracts.LocalRiskAssessment{
			Subject:      contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:        contracts.RiskHigh,
			Score:        72,
			Confidence:   0.9,
			Completeness: 1.0,
			ValidUntil:   now.Add(time.Minute),
		},
		Context: runtimepdp.ContextSnapshot{
			Metrics: map[string]any{
				"network": map[string]any{"packets_per_second": 3000.0},
			},
			Baseline: map[string]any{
				"network": map[string]any{"packets_per_second": 1000.0},
			},
			FSM: map[string]any{"proposed_level": "hard"},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected metric fact rule to match")
	}
	if decision.Action.Level != "soft" {
		t.Fatalf("action level: %s", decision.Action.Level)
	}
}

func TestDecideDefaultsMissingDevicePostureToUnknown(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("device.posture.status in ['degraded', 'unhealthy', 'unknown']"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskLow,
			Score:      10,
			ValidUntil: now.Add(time.Minute),
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected missing posture to evaluate as unknown")
	}
	if decision.Action.Capability != "enforce.traffic.rate_limit" {
		t.Fatalf("capability: %s", decision.Action.Capability)
	}
}

func TestDecideUsesCanonicalFlatDeviceAndSessionFacts(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("device.posture.status == 'healthy' && session.authentication.strength == 'mfa'"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskLow,
			Score:      10,
			ValidUntil: now.Add(time.Minute),
		},
		Context: runtimepdp.ContextSnapshot{
			Device: map[string]any{
				"device.posture.status": "healthy",
			},
			Session: map[string]any{
				"session.authentication.strength": "mfa",
			},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected canonical flat facts to be available as nested CEL facts")
	}
}

func TestDecideMatchesDetectionAndActionFacts(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("detections.sustained_pressure.active == true && actions.enforce_traffic_rate_limit.active == true"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskMedium,
			Score:      45,
			ValidUntil: now.Add(time.Minute),
		},
		Context: runtimepdp.ContextSnapshot{
			Detections: map[string]any{
				"sustained_pressure": map[string]any{"active": true},
			},
			Actions: map[string]any{
				"enforce_traffic_rate_limit": map[string]any{"active": true},
			},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected detection/action fact rule to match")
	}
}

func TestDecideTreatsMissingDetectionAndActionFactsAsInactive(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 44, 49, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("detections.sustained_pressure.active == true && actions.enforce_traffic_rate_limit.active == true"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, matched, traces, err := pdp.DecideWithTrace(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskMedium,
			Score:      52,
			ValidUntil: now.Add(time.Minute),
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if matched {
		t.Fatal("did not expect inactive facts to match")
	}
	if len(traces) != 1 {
		t.Fatalf("trace count: %d", len(traces))
	}
	if traces[0].Skipped || traces[0].Error != "" {
		t.Fatalf("missing facts should evaluate false, not skip: %#v", traces[0])
	}
}

func TestDecideMatchesRiskQualityFacts(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	pdp, err := runtimepdp.Compile(testPack("risk.confidence >= 0.8 && risk.age_seconds <= 120 && risk.independent_signal_count >= 2"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Metadata:   contracts.ObjectMeta{IssuedAt: now.Add(-30 * time.Second)},
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskHigh,
			Score:      80,
			Confidence: 0.9,
			Domains:    []string{"source"},
			Contributions: []contracts.RiskContribution{
				{SignalType: "source.pps_high", Domain: "source", Score: 80, Confidence: 0.9},
				{SignalType: "source.rate_limit_drops_sustained", Domain: "source", Score: 80, Confidence: 0.9},
			},
			ValidUntil: now.Add(time.Minute),
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected risk quality rule to match")
	}
}

func TestDecideChoosesStrongestMatchingRule(t *testing.T) {
	now := time.Date(2026, 6, 22, 23, 40, 0, 0, time.UTC)
	pack := testPack("risk.level in ['medium', 'high', 'critical']")
	pack.Spec.Rules[0].ID = "risk-elevated"
	pack.Spec.Rules[0].Then.Level = "hard"
	pack.Spec.Rules = append(pack.Spec.Rules, contracts.RuntimePolicyRule{
		ID:   "sustained-pressure",
		When: "detections.sustained_pressure.active == true && actions.enforce_traffic_rate_limit.active == true",
		Then: contracts.RuntimeActionSpec{
			Capability: "enforce.traffic.drop",
			Level:      "block",
			TTL:        contracts.NewDuration(time.Minute),
		},
		ReasonCodes: []string{"sustained_pressure"},
	})
	pdp, err := runtimepdp.Compile(pack)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskHigh,
			Score:      80,
			ValidUntil: now.Add(time.Minute),
		},
		Context: runtimepdp.ContextSnapshot{
			Detections: map[string]any{
				"sustained_pressure": map[string]any{"active": true},
			},
			Actions: map[string]any{
				"enforce_traffic_rate_limit": map[string]any{"active": true},
			},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected a matching rule")
	}
	if decision.Action.Capability != "enforce.traffic.drop" || decision.Action.Level != "block" {
		t.Fatalf("expected strongest block rule, got %#v", decision.Action)
	}
}

func TestDecideExpandsAutonomyHoldLifecycle(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 0, 0, 0, time.UTC)
	pack := testPack("risk.level == 'critical'")
	pack.Spec.AutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{
		Hold: []contracts.RuntimeAutonomyHoldRule{{
			ID: "hold-enforcement-feedback",
			While: contracts.RuntimeAutonomyHoldCondition{
				EnforcementFeedbackActive: true,
				Levels:                    []string{"soft", "hard", "block"},
			},
			Action: contracts.RuntimeActionSpec{
				Capability: "enforce.traffic.rate_limit",
				Level:      "hard",
				TTL:        contracts.NewDuration(30 * time.Second),
				Params:     map[string]any{"rate_pps": 100},
			},
			ReasonCodes: []string{"enforcement_hold"},
		}},
		StepDown: contracts.RuntimeAutonomyStepDown{
			CleanAfter:   contracts.NewDuration(30 * time.Second),
			ObserveAfter: contracts.NewDuration(2 * time.Minute),
		},
		MaxRenewals: 3,
	}
	if got := runtimepdp.EffectiveRuleCount(pack); got != 2 {
		t.Fatalf("effective rules = %d, want 2", got)
	}
	pdp, err := runtimepdp.Compile(pack)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskMedium,
			Score:      50,
			ValidUntil: now.Add(time.Minute),
		},
		Context: runtimepdp.ContextSnapshot{
			FSM:     map[string]any{"current_level": "hard"},
			Signals: map[string]any{"enforcement": map[string]any{"active": true}},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected autonomy hold rule to match")
	}
	if decision.Action.Level != "hard" || decision.Action.TTL.Duration != 30*time.Second {
		t.Fatalf("action = %#v", decision.Action)
	}
	if len(decision.ReasonCodes) != 2 || decision.ReasonCodes[0] != "autonomy_lifecycle_hold" || decision.ReasonCodes[1] != "enforcement_hold" {
		t.Fatalf("reason codes = %#v", decision.ReasonCodes)
	}
}

func TestDecideSkipsRuleWithMissingOptionalFacts(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	pack := testPack("metrics.missing.value > 0")
	pack.Spec.Rules = append(pack.Spec.Rules, contracts.RuntimePolicyRule{
		ID:   "risk-fallback",
		When: "risk.level == 'high'",
		Then: contracts.RuntimeActionSpec{
			Capability: "enforce.access.deny",
			Level:      "block",
			TTL:        contracts.NewDuration(time.Minute),
		},
		ReasonCodes: []string{"risk_high"},
	})
	pdp, err := runtimepdp.Compile(pack)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision, matched, err := pdp.Decide(runtimepdp.Input{
		NodeID: "node-1",
		Risk: contracts.LocalRiskAssessment{
			Subject:    contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			Level:      contracts.RiskHigh,
			Score:      70,
			ValidUntil: now.Add(time.Minute),
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !matched {
		t.Fatal("expected fallback rule to match")
	}
	if decision.Action.Capability != "enforce.access.deny" {
		t.Fatalf("capability: %s", decision.Action.Capability)
	}
}

func TestCompileRejectsInvalidCEL(t *testing.T) {
	_, err := runtimepdp.Compile(testPack("risk.level in ["))
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func testPack(expr string) contracts.RuntimePolicyPack {
	return contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{Name: "test-pack"},
		Spec: contracts.RuntimePolicyPackSpec{
			DefaultEffect: "deny",
			Rules: []contracts.RuntimePolicyRule{{
				ID:   "risk-rule",
				When: expr,
				Then: contracts.RuntimeActionSpec{
					Capability: "enforce.traffic.rate_limit",
					Level:      "soft",
					TTL:        contracts.NewDuration(10 * time.Minute),
				},
				ReasonCodes: []string{"risk_high"},
			}},
		},
	}
}
