// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
)

func TestRuntimeDecisionToActionProposalSource(t *testing.T) {
	now := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	dec := contracts.RuntimeDecision{
		Metadata: contracts.ObjectMeta{ID: "decision-1"},
		Subject:  contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		Effect:   "apply",
		Action: contracts.RuntimeActionSpec{
			Capability: "enforce.traffic.rate_limit",
			Level:      "hard",
			TTL:        contracts.NewDuration(2 * time.Minute),
			Params: map[string]any{
				"source_id": "10.0.0.2",
				"rate_pps":  100,
			},
		},
		ReasonCodes: []string{"risk_high"},
	}

	prop, ok, reason := runtimeDecisionToActionProposal(dec, "", 0.9, now)
	if !ok {
		t.Fatalf("mapper rejected decision: %s", reason)
	}
	if prop.ID != "decision-1" || prop.DesiredAction != "enforce.traffic.rate_limit" || prop.DesiredLevel != "hard" {
		t.Fatalf("bad proposal: %#v", prop)
	}
	if prop.Target.Granularity != actions.TargetGranularitySource || prop.Target.Value != "10.0.0.2" {
		t.Fatalf("bad source target: %#v", prop.Target)
	}
	if prop.TTL != 2*time.Minute {
		t.Fatalf("ttl: %v", prop.TTL)
	}
	if prop.Parameters["rate_pps"] != 100 {
		t.Fatalf("params not preserved: %#v", prop.Parameters)
	}
}

func TestRuntimeDecisionToActionProposalRelationship(t *testing.T) {
	now := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	dec := contracts.RuntimeDecision{
		Subject: contracts.EntityRef{Kind: "ip", ID: "source-1"},
		Effect:  "apply",
		Action: contracts.RuntimeActionSpec{
			Capability: "enforce.access.deny",
			Level:      "block",
			TTL:        contracts.NewDuration(time.Minute),
			Params: map[string]any{
				"target_granularity": "relationship",
				"target_id":          "service-1",
				"dimension.port":     "443",
				"dimension.proto":    "tcp",
			},
		},
	}

	prop, ok, reason := runtimeDecisionToActionProposal(dec, "", 0.8, now)
	if !ok {
		t.Fatalf("mapper rejected relationship decision: %s", reason)
	}
	if prop.Target.Granularity != actions.TargetGranularityRelationship {
		t.Fatalf("granularity: %#v", prop.Target)
	}
	if prop.Target.Attributes[actions.TargetAttrSubjectID] != "source-1" {
		t.Fatalf("subject attr missing: %#v", prop.Target.Attributes)
	}
	if prop.Target.Attributes[actions.TargetAttrTargetID] != "service-1" {
		t.Fatalf("target attr missing: %#v", prop.Target.Attributes)
	}
	if prop.Target.Attributes[actions.TargetAttrDimensionPrefix+"port"] != "443" {
		t.Fatalf("dimension attr missing: %#v", prop.Target.Attributes)
	}
}

func TestRuntimeDecisionToActionProposalObserve(t *testing.T) {
	now := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	dec := contracts.RuntimeDecision{
		Subject: contracts.EntityRef{Kind: "ip", ID: "source-1"},
		Effect:  "apply",
		Action: contracts.RuntimeActionSpec{
			Level: "observe",
		},
	}

	prop, ok, reason := runtimeDecisionToActionProposal(dec, "", 0.8, now)
	if !ok {
		t.Fatalf("mapper rejected observe decision: %s", reason)
	}
	if prop.DesiredLevel != "observe" || prop.DesiredAction != "" {
		t.Fatalf("bad observe proposal: %#v", prop)
	}
	if prop.Target.Granularity != actions.TargetGranularitySource || prop.Target.Value != "source-1" {
		t.Fatalf("bad observe target: %#v", prop.Target)
	}
}

func TestRuntimeDecisionToActionProposalSkipsNonApplyEffect(t *testing.T) {
	_, ok, reason := runtimeDecisionToActionProposal(contracts.RuntimeDecision{
		Effect: "deny",
		Action: contracts.RuntimeActionSpec{Capability: "enforce.access.deny"},
	}, "source-1", 0.5, time.Now())
	if ok || reason == "" {
		t.Fatalf("expected non-apply effect to be skipped, ok=%v reason=%q", ok, reason)
	}
}

func TestRuntimePDPActionProposalWithEvidenceAddsDropRate(t *testing.T) {
	prop := actions.ActionProposal{
		DesiredAction: "enforce.traffic.drop",
		DesiredLevel:  "block",
	}
	prop = runtimePDPActionProposalWithEvidence(prop, runtimepdp.Input{
		Context: runtimepdp.ContextSnapshot{
			Signals: map[string]any{
				"enforcement": map[string]any{
					"drop_rate": 37.5,
				},
			},
		},
	})

	if got := prop.Parameters["evidence_drop_rl_rate"]; got != 37.5 {
		t.Fatalf("evidence_drop_rl_rate = %#v", got)
	}
}
