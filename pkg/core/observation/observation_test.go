// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package observation

import (
	"testing"
	"time"
)

func TestNewObservation(t *testing.T) {
	subject := EntityRef{
		Kind: KindIP,
		ID:   "192.168.1.1",
	}
	subject.Labels = map[string]string{"role": "client"}

	obs := NewObservation(SourceShield, TypeFlow, "node-001", subject)

	if obs.ID == "" {
		t.Error("expected non-empty ID")
	}
	if obs.Time.IsZero() {
		t.Error("expected non-zero Time")
	}
	if obs.Source != SourceShield {
		t.Errorf("expected source=%s, got %s", SourceShield, obs.Source)
	}
	if obs.Type != TypeFlow {
		t.Errorf("expected type=%s, got %s", TypeFlow, obs.Type)
	}
	if obs.NodeID != "node-001" {
		t.Errorf("expected nodeID=node-001, got %s", obs.NodeID)
	}
	if obs.Subject.ID != "192.168.1.1" {
		t.Errorf("expected subject ID, got %s", obs.Subject.ID)
	}
}

func TestObservationChaining(t *testing.T) {
	subject := EntityRef{Kind: KindIP, ID: "203.0.113.55"}
	object := EntityRef{Kind: KindService, ID: "api-gateway"}

	obs := NewObservation(SourceShield, TypeDrop, "node-001", subject).
		SetObject(object).
		SetMetric("packets", 42.0).
		SetMetric("bytes", 4096.0).
		SetAttribute("protocol", "tcp").
		SetAttribute("destination_port", "443").
		SetSeverityHint(75)

	if obs.Object.ID != "api-gateway" {
		t.Errorf("expected object ID, got %s", obs.Object.ID)
	}
	if obs.Metrics["packets"] != 42.0 {
		t.Errorf("expected packets=42, got %f", obs.Metrics["packets"])
	}
	if obs.Attributes["protocol"] != "tcp" {
		t.Errorf("expected protocol=tcp, got %s", obs.Attributes["protocol"])
	}
	if obs.SeverityHint != 75 {
		t.Errorf("expected severity=75, got %d", obs.SeverityHint)
	}
}

func TestSeverityHintClamping(t *testing.T) {
	subject := EntityRef{Kind: KindIP, ID: "1.1.1.1"}

	obs1 := NewObservation(SourceShield, TypeFlow, "node-001", subject)
	obs1.SetSeverityHint(-10)
	if obs1.SeverityHint != 0 {
		t.Errorf("expected severity clamped to 0, got %d", obs1.SeverityHint)
	}

	obs2 := NewObservation(SourceShield, TypeFlow, "node-001", subject)
	obs2.SetSeverityHint(150)
	if obs2.SeverityHint != 100 {
		t.Errorf("expected severity clamped to 100, got %d", obs2.SeverityHint)
	}
}

func TestEntityRef(t *testing.T) {
	tests := []struct {
		name string
		kind EntityKind
		id   string
	}{
		{"IP", KindIP, "192.168.1.1"},
		{"CIDR", KindCIDR, "10.0.0.0/8"},
		{"Node", KindNode, "node-web-01"},
		{"Service", KindService, "postgres"},
		{"User", KindUser, "alice"},
		{"Workload", KindWorkload, "pod-abc123"},
		{"Process", KindProcess, "sshd-1234"},
		{"Namespace", KindNamespace, "default"},
	}

	for _, tc := range tests {
		ref := EntityRef{Kind: tc.kind, ID: tc.id}
		if ref.Kind != tc.kind {
			t.Errorf("%s: expected kind=%s, got %s", tc.name, tc.kind, ref.Kind)
		}
		if ref.ID != tc.id {
			t.Errorf("%s: expected id=%s, got %s", tc.name, tc.id, ref.ID)
		}
	}
}

func TestObservationSources(t *testing.T) {
	sources := []ObservationSource{
		SourceShield, SourceNginx, SourceZiti, SourceTrustd, SourceApp, SourceSyslog, SourceCilium, SourceCorrelate,
	}

	for _, src := range sources {
		obs := NewObservation(src, TypeFlow, "node-001", EntityRef{Kind: KindIP, ID: "1.1.1.1"})
		if obs.Source != src {
			t.Errorf("expected source=%s, got %s", src, obs.Source)
		}
	}
}

func TestObservationTypes(t *testing.T) {
	types := []ObservationType{
		TypeFlow, TypeDrop, TypeScan, TypeRateLimit, TypeHTTP, TypeDNS, TypeAuth, TypeProcess, TypeTrust, TypeIntegrity, TypeConnection,
	}

	for _, obsType := range types {
		obs := NewObservation(SourceShield, obsType, "node-001", EntityRef{Kind: KindIP, ID: "1.1.1.1"})
		if obs.Type != obsType {
			t.Errorf("expected type=%s, got %s", obsType, obs.Type)
		}
	}
}

func TestMetricsNilInitialization(t *testing.T) {
	obs := NewObservation(SourceShield, TypeFlow, "node-001", EntityRef{Kind: KindIP, ID: "1.1.1.1"})
	if obs.Metrics == nil {
		t.Error("expected Metrics to be initialized, got nil")
	}
	if obs.Attributes == nil {
		t.Error("expected Attributes to be initialized, got nil")
	}
}

func TestBatchTimestamps(t *testing.T) {
	from := time.Now().Add(-1 * time.Minute)
	to := time.Now()

	batch := Batch{
		NodeID: "node-001",
		From:   from,
		To:     to,
	}

	if batch.From != from {
		t.Errorf("expected From=%v, got %v", from, batch.From)
	}
	if batch.To != to {
		t.Errorf("expected To=%v, got %v", to, batch.To)
	}
}

func TestObservationWithLabels(t *testing.T) {
	subject := EntityRef{
		Kind:   KindNode,
		ID:     "node-web-01",
		Labels: map[string]string{"role": "public-api", "env": "prod"},
	}

	obs := NewObservation(SourceShield, TypeFlow, "node-web-01", subject)
	if obs.Subject.Labels["role"] != "public-api" {
		t.Errorf("expected label role=public-api, got %s", obs.Subject.Labels["role"])
	}
	if obs.Subject.Labels["env"] != "prod" {
		t.Errorf("expected label env=prod, got %s", obs.Subject.Labels["env"])
	}
}
