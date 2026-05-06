// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package decision

import (
	"testing"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/observation"
)

func TestNewDecision(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "203.0.113.55"}
	action := Action{
		Type:       ActionRateLimit,
		Capability: "network.rate_limit_source",
		Params: map[string]string{
			"source":   "203.0.113.55",
			"rate_pps": "100",
		},
	}

	dec := NewDecision(DeciderKLIQ, "node-001", subject, action)

	if dec.ID == "" {
		t.Error("expected non-empty ID")
	}
	if dec.Time.IsZero() {
		t.Error("expected non-zero Time")
	}
	if dec.Decider != DeciderKLIQ {
		t.Errorf("expected decider=kliq, got %s", dec.Decider)
	}
	if dec.NodeID != "node-001" {
		t.Errorf("expected nodeID=node-001, got %s", dec.NodeID)
	}
	if dec.Action.Type != ActionRateLimit {
		t.Errorf("expected action type=rate_limit, got %s", dec.Action.Type)
	}
	if !dec.DryRun {
		t.Error("expected DryRun=true by default")
	}
	if dec.Severity != 50 {
		t.Errorf("expected default severity=50, got %d", dec.Severity)
	}
}

func TestDecisionChaining(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "203.0.113.55"}
	action := Action{Type: ActionBlock, Capability: "network.block_source"}

	dec := NewDecision(DeciderForge, "node-001", subject, action).
		SetSeverity(90).
		AddReasonCode("pps_high").
		AddReasonCode("scan_suspected").
		SetDryRun(false).
		SetAttribute("policy_pack_id", "baseline-001").
		SetAttribute("confidence", "85")

	if dec.Severity != 90 {
		t.Errorf("expected severity=90, got %d", dec.Severity)
	}
	if len(dec.ReasonCodes) != 2 {
		t.Errorf("expected 2 reason codes, got %d", len(dec.ReasonCodes))
	}
	if dec.DryRun {
		t.Error("expected DryRun=false after SetDryRun(false)")
	}
	if dec.Attributes["policy_pack_id"] != "baseline-001" {
		t.Errorf("expected policy_pack_id, got %s", dec.Attributes["policy_pack_id"])
	}
}

func TestDecisionSeverityClamping(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	action := Action{Type: ActionObserve}

	dec1 := NewDecision(DeciderKLIQ, "node-001", subject, action)
	dec1.SetSeverity(-10)
	if dec1.Severity != 0 {
		t.Errorf("expected severity clamped to 0, got %d", dec1.Severity)
	}

	dec2 := NewDecision(DeciderKLIQ, "node-001", subject, action)
	dec2.SetSeverity(150)
	if dec2.Severity != 100 {
		t.Errorf("expected severity clamped to 100, got %d", dec2.Severity)
	}
}

func TestDecisionExpiry(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	action := Action{Type: ActionBlock}

	dec := NewDecision(DeciderKLIQ, "node-001", subject, action)
	if dec.ExpiresAt != nil {
		t.Error("expected no expiry by default")
	}

	// Set absolute expiry
	futureTime := time.Now().Add(10 * time.Minute)
	dec.SetExpiry(futureTime)
	if dec.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
	if dec.ExpiresAt.Sub(futureTime) > 1*time.Second {
		t.Errorf("expected expiry ~%v, got %v", futureTime, dec.ExpiresAt)
	}

	// Check not expired
	if dec.IsExpired() {
		t.Error("expected decision not to be expired")
	}
}

func TestDecisionExpiryDuration(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	action := Action{Type: ActionRateLimit}

	dec := NewDecision(DeciderKLIQ, "node-001", subject, action)
	beforeSet := time.Now()
	dec.SetExpiryDuration(5 * time.Minute)
	afterSet := time.Now()

	if dec.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}

	// Check it's roughly 5 minutes in the future
	expectedMin := beforeSet.Add(5 * time.Minute)
	expectedMax := afterSet.Add(5 * time.Minute)
	if dec.ExpiresAt.Before(expectedMin) || dec.ExpiresAt.After(expectedMax.Add(1*time.Second)) {
		t.Errorf("expected expiry ~5min from now, got %v (now=%v)", dec.ExpiresAt, time.Now())
	}
}

func TestDecisionIsExpired(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	action := Action{Type: ActionBlock}

	// Fresh decision
	dec1 := NewDecision(DeciderKLIQ, "node-001", subject, action)
	futureTime := time.Now().Add(10 * time.Minute)
	dec1.SetExpiry(futureTime)
	if dec1.IsExpired() {
		t.Error("expected fresh decision not to be expired")
	}

	// Expired decision
	dec2 := NewDecision(DeciderKLIQ, "node-001", subject, action)
	pastTime := time.Now().Add(-5 * time.Minute)
	dec2.SetExpiry(pastTime)
	if !dec2.IsExpired() {
		t.Error("expected expired decision to be expired")
	}
}

func TestActionTypes(t *testing.T) {
	actionTypes := []ActionType{
		ActionObserve, ActionSignal, ActionRateLimit, ActionBlock, ActionAllow, ActionIsolate, ActionTag, ActionNotify,
	}

	for _, act := range actionTypes {
		action := Action{Type: act}
		if action.Type != act {
			t.Errorf("expected action type=%s, got %s", act, action.Type)
		}
	}
}

func TestDeciderTypes(t *testing.T) {
	deciders := []Decider{DeciderKLIQ, DeciderForge, DeciderCorrelate}
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	action := Action{Type: ActionObserve}

	for _, decider := range deciders {
		dec := NewDecision(decider, "node-001", subject, action)
		if dec.Decider != decider {
			t.Errorf("expected decider=%s, got %s", decider, dec.Decider)
		}
	}
}

func TestEnforcementReceipt(t *testing.T) {
	receipt := NewEnforcementReceipt("dec-123", "node-001", "shield-pep", StatusApplied)

	if receipt.ID == "" {
		t.Error("expected non-empty receipt ID")
	}
	if receipt.DecisionID != "dec-123" {
		t.Errorf("expected DecisionID=dec-123, got %s", receipt.DecisionID)
	}
	if receipt.NodeID != "node-001" {
		t.Errorf("expected NodeID=node-001, got %s", receipt.NodeID)
	}
	if receipt.AdapterID != "shield-pep" {
		t.Errorf("expected AdapterID=shield-pep, got %s", receipt.AdapterID)
	}
	if receipt.Status != StatusApplied {
		t.Errorf("expected Status=applied, got %s", receipt.Status)
	}
	if receipt.AppliedAt.IsZero() {
		t.Error("expected non-zero AppliedAt")
	}
}

func TestEnforcementReceiptWithMessage(t *testing.T) {
	receipt := NewEnforcementReceipt("dec-123", "node-001", "shield-pep", StatusFailed).
		SetMessage("eBPF map update failed: permission denied")

	if receipt.Status != StatusFailed {
		t.Errorf("expected Status=failed, got %s", receipt.Status)
	}
	if receipt.Message != "eBPF map update failed: permission denied" {
		t.Errorf("expected message, got %s", receipt.Message)
	}
}

func TestReceiptStatuses(t *testing.T) {
	statuses := []ReceiptStatus{StatusApplied, StatusFailed, StatusSkipped, StatusUnsupported, StatusDryRun}

	for _, status := range statuses {
		receipt := NewEnforcementReceipt("dec-123", "node-001", "adapter", status)
		if receipt.Status != status {
			t.Errorf("expected status=%s, got %s", status, receipt.Status)
		}
	}
}

func TestActionParams(t *testing.T) {
	action := Action{
		Type:       ActionRateLimit,
		Capability: "network.rate_limit_source",
		Params: map[string]string{
			"source":   "203.0.113.55",
			"rate_pps": "100",
			"burst":    "200",
			"ttl":      "10m",
		},
	}

	if action.Params["source"] != "203.0.113.55" {
		t.Errorf("expected source param, got %s", action.Params["source"])
	}
	if action.Params["rate_pps"] != "100" {
		t.Errorf("expected rate_pps param, got %s", action.Params["rate_pps"])
	}
}

func TestAttributesNilInitialization(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	action := Action{Type: ActionObserve}

	dec := NewDecision(DeciderKLIQ, "node-001", subject, action)
	if dec.Attributes == nil {
		t.Error("expected Attributes to be initialized, got nil")
	}
}
