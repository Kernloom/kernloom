// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package signal

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/observation"
)

func TestNewSignal(t *testing.T) {
	subject := observation.EntityRef{
		Kind: observation.KindIP,
		ID:   "203.0.113.55",
	}

	sig := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)

	if sig.ID == "" {
		t.Error("expected non-empty ID")
	}
	if sig.Time.IsZero() {
		t.Error("expected non-zero Time")
	}
	if sig.Producer != ProducerKLIQ {
		t.Errorf("expected producer=kliq, got %s", sig.Producer)
	}
	if sig.Scope != ScopeLocal {
		t.Errorf("expected scope=local, got %s", sig.Scope)
	}
	if sig.Type != SignalPPSHigh {
		t.Errorf("expected type=%s, got %s", SignalPPSHigh, sig.Type)
	}
	if sig.Score != 50 {
		t.Errorf("expected default score=50, got %d", sig.Score)
	}
	if sig.Confidence != 50 {
		t.Errorf("expected default confidence=50, got %d", sig.Confidence)
	}
}

func TestSignalChaining(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "203.0.113.55"}
	object := observation.EntityRef{Kind: observation.KindNode, ID: "node-web-01"}

	sig := NewSignal(ProducerCorrelate, ScopeGlobal, SignalCampaignDistributedScan, subject).
		SetObject(object).
		SetScore(92).
		SetConfidence(85).
		SetTTL(30*time.Minute).
		AddReasonCode("seen_on_12_nodes").
		AddReasonCode("high_port_diversity").
		SetAttribute("nodes_affected", "12").
		SetAttribute("duration", "30m")

	if sig.Object.ID != "node-web-01" {
		t.Errorf("expected object, got %s", sig.Object.ID)
	}
	if sig.Score != 92 {
		t.Errorf("expected score=92, got %d", sig.Score)
	}
	if sig.Confidence != 85 {
		t.Errorf("expected confidence=85, got %d", sig.Confidence)
	}
	if sig.TTL != 30*time.Minute {
		t.Errorf("expected TTL=30m, got %v", sig.TTL)
	}
	if len(sig.ReasonCodes) != 2 {
		t.Errorf("expected 2 reason codes, got %d", len(sig.ReasonCodes))
	}
	if sig.Attributes["nodes_affected"] != "12" {
		t.Errorf("expected nodes_affected=12, got %s", sig.Attributes["nodes_affected"])
	}
}

func TestSignalScoreClamping(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}

	sig1 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig1.SetScore(-10)
	if sig1.Score != 0 {
		t.Errorf("expected score clamped to 0, got %d", sig1.Score)
	}

	sig2 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig2.SetScore(150)
	if sig2.Score != 100 {
		t.Errorf("expected score clamped to 100, got %d", sig2.Score)
	}
}

func TestSignalConfidenceClamping(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}

	sig1 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig1.SetConfidence(-5)
	if sig1.Confidence != 0 {
		t.Errorf("expected confidence clamped to 0, got %d", sig1.Confidence)
	}

	sig2 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig2.SetConfidence(200)
	if sig2.Confidence != 100 {
		t.Errorf("expected confidence clamped to 100, got %d", sig2.Confidence)
	}
}

func TestSignalProducers(t *testing.T) {
	producers := []SignalProducer{ProducerKLIQ, ProducerCorrelate, ProducerTrust, ProducerForge}
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}

	for _, prod := range producers {
		sig := NewSignal(prod, ScopeLocal, SignalPPSHigh, subject)
		if sig.Producer != prod {
			t.Errorf("expected producer=%s, got %s", prod, sig.Producer)
		}
	}
}

func TestSignalScopes(t *testing.T) {
	scopes := []SignalScope{ScopeLocal, ScopeSite, ScopeTenant, ScopeGlobal}
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}

	for _, scope := range scopes {
		sig := NewSignal(ProducerKLIQ, scope, SignalPPSHigh, subject)
		if sig.Scope != scope {
			t.Errorf("expected scope=%s, got %s", scope, sig.Scope)
		}
	}
}

func TestSignalTypes(t *testing.T) {
	types := []SignalType{
		SignalScanSuspected, SignalPPSHigh, SignalSYNRateHigh, SignalRateLimitDropsSustained,
		SignalGraphNewEdgeAfterFreeze, SignalNodeTrustDegraded, SignalCampaignDistributedScan,
	}
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}

	for _, sigType := range types {
		sig := NewSignal(ProducerKLIQ, ScopeLocal, sigType, subject)
		if sig.Type != sigType {
			t.Errorf("expected type=%s, got %s", sigType, sig.Type)
		}
	}
}

func TestSignalIsExpired(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}

	// Fresh signal (not expired)
	sig1 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig1.Time = time.Now().Add(-1 * time.Minute)
	sig1.TTL = 10 * time.Minute
	if sig1.IsExpired() {
		t.Error("expected signal not to be expired")
	}

	// Expired signal
	sig2 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig2.Time = time.Now().Add(-20 * time.Minute)
	sig2.TTL = 10 * time.Minute
	if !sig2.IsExpired() {
		t.Error("expected signal to be expired")
	}

	// No expiration
	sig3 := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig3.Time = time.Now().Add(-1 * time.Hour)
	sig3.TTL = 0
	if sig3.IsExpired() {
		t.Error("expected signal with TTL=0 not to expire")
	}
}

func TestSignalExpiresAt(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	sig := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)

	baseTime := time.Now()
	sig.Time = baseTime
	sig.TTL = 15 * time.Minute

	expiry := sig.ExpiresAt()
	expectedExpiry := baseTime.Add(15 * time.Minute)

	if expiry.Sub(expectedExpiry) > 1*time.Second {
		t.Errorf("expected expiry ~%v, got %v", expectedExpiry, expiry)
	}
}

func TestSignalNoExpirationWhenZeroTTL(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	sig := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)
	sig.TTL = 0

	if !sig.ExpiresAt().IsZero() {
		t.Errorf("expected zero expiry with TTL=0, got %v", sig.ExpiresAt())
	}
}

func TestSignalMultipleReasonCodes(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "203.0.113.55"}
	sig := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject).
		AddReasonCode("pps_high").
		AddReasonCode("syn_rate_high").
		AddReasonCode("global_risk_signal")

	if len(sig.ReasonCodes) != 3 {
		t.Errorf("expected 3 reason codes, got %d", len(sig.ReasonCodes))
	}
	if sig.ReasonCodes[0] != "pps_high" {
		t.Errorf("expected first code=pps_high, got %s", sig.ReasonCodes[0])
	}
	if sig.ReasonCodes[2] != "global_risk_signal" {
		t.Errorf("expected third code=global_risk_signal, got %s", sig.ReasonCodes[2])
	}
}

func TestSignalAttributesNilInitialization(t *testing.T) {
	subject := observation.EntityRef{Kind: observation.KindIP, ID: "1.1.1.1"}
	sig := NewSignal(ProducerKLIQ, ScopeLocal, SignalPPSHigh, subject)

	if sig.Attributes == nil {
		t.Error("expected Attributes to be initialized, got nil")
	}
}
