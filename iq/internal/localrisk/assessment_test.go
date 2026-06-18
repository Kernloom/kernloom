// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package localrisk_test

import (
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/localrisk"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

func testSignal(subject string, typ signal.SignalType, score, confidence int, ttl time.Duration) signal.Signal {
	s := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, typ, observation.EntityRef{
		Kind: observation.KindIP,
		ID:   subject,
	})
	s.SetScore(score)
	s.SetConfidence(confidence)
	s.SetTTL(ttl)
	return *s
}

func TestFromSignalsProducesAssessment(t *testing.T) {
	now := time.Now().UTC()
	sigs := []signal.Signal{
		testSignal("10.0.0.1", signal.SignalPPSHigh, 70, 80, time.Minute),
		testSignal("10.0.0.1", signal.SignalSYNRateHigh, 90, 60, 30*time.Second),
	}

	assessments := localrisk.FromSignals(sigs, now, localrisk.DefaultConfig())
	if len(assessments) != 1 {
		t.Fatalf("expected one assessment, got %d", len(assessments))
	}
	a := assessments[0]
	if a.SubjectID != "10.0.0.1" {
		t.Fatalf("subject: got %q", a.SubjectID)
	}
	if a.Score != 90 || a.Level != localrisk.LevelCritical {
		t.Fatalf("risk: score=%d level=%s", a.Score, a.Level)
	}
	if a.Confidence != 0.7 {
		t.Fatalf("confidence: got %f want 0.7", a.Confidence)
	}
	if len(a.Domains) != 1 || a.Domains[0] != "source" {
		t.Fatalf("domains: %#v", a.Domains)
	}
	if len(a.Contributions) != 2 {
		t.Fatalf("contributions: got %d", len(a.Contributions))
	}
	if a.ValidUntil.After(now.Add(31 * time.Second)) {
		t.Fatalf("validUntil should use shortest signal TTL, got %s", a.ValidUntil)
	}
}

func TestFromSignalsGroupsBySubject(t *testing.T) {
	now := time.Now().UTC()
	sigs := []signal.Signal{
		testSignal("10.0.0.1", signal.SignalPPSHigh, 70, 80, time.Minute),
		testSignal("10.0.0.2", signal.SignalScanSuspected, 40, 90, time.Minute),
	}

	assessments := localrisk.FromSignals(sigs, now, localrisk.DefaultConfig())
	if len(assessments) != 2 {
		t.Fatalf("expected two assessments, got %d", len(assessments))
	}
	bySubject := map[string]localrisk.Assessment{}
	for _, assessment := range assessments {
		bySubject[assessment.SubjectID] = assessment
	}
	if bySubject["10.0.0.1"].Level != localrisk.LevelHigh {
		t.Fatalf("10.0.0.1 level: %s", bySubject["10.0.0.1"].Level)
	}
	if bySubject["10.0.0.2"].Level != localrisk.LevelMedium {
		t.Fatalf("10.0.0.2 level: %s", bySubject["10.0.0.2"].Level)
	}
}

func TestAssessmentToContract(t *testing.T) {
	now := time.Now().UTC()
	assessment := localrisk.FromSignals([]signal.Signal{
		testSignal("10.0.0.1", signal.SignalPPSHigh, 70, 80, time.Minute),
	}, now, localrisk.DefaultConfig())[0]

	contract := assessment.ToContract(contracts.EntityRef{Kind: "ip", ID: "10.0.0.1"}, "node-1")
	if contract.APIVersion != contracts.RuntimeAPIVersion || contract.Kind != contracts.KindLocalRiskAssessment {
		t.Fatalf("bad typemeta: %#v", contract.TypeMeta)
	}
	if contract.Metadata.NodeID != "node-1" {
		t.Fatalf("node id: %q", contract.Metadata.NodeID)
	}
	if contract.Level != contracts.RiskHigh {
		t.Fatalf("level: %s", contract.Level)
	}
	if len(contract.Contributions) != 1 || contract.Contributions[0].SignalType != string(signal.SignalPPSHigh) {
		t.Fatalf("contributions: %#v", contract.Contributions)
	}
}
