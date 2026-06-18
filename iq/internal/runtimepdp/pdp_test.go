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
