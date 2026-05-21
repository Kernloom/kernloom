// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metric_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/metric"
)

func TestMetricCreation(t *testing.T) {
	m := metric.New(
		"network.pps",
		"shieldtelemetry",
		metric.ScopeSourceIP,
		metric.Subject{Type: "ip", Value: "10.0.0.1"},
		42.0,
		time.Second,
	)

	if m.ID != "network.pps" {
		t.Errorf("ID: got %q, want %q", m.ID, "network.pps")
	}
	if m.Value != 42.0 {
		t.Errorf("Value: got %f, want 42.0", m.Value)
	}
	if m.Scope != metric.ScopeSourceIP {
		t.Errorf("Scope: got %q, want src_ip", m.Scope)
	}
	if m.Subject.Value != "10.0.0.1" {
		t.Errorf("Subject.Value: got %q", m.Subject.Value)
	}
	if m.Timestamp.IsZero() {
		t.Error("Timestamp must not be zero")
	}
}

func TestMetricWithUnit(t *testing.T) {
	m := metric.New("network.pps", "src", metric.ScopeGlobal, metric.Subject{}, 1.0, time.Second).
		WithUnit("pps")
	if m.Unit != "pps" {
		t.Errorf("Unit: got %q, want pps", m.Unit)
	}
}

func TestMetricWithLabel(t *testing.T) {
	m := metric.New("http.rps", "nginx", metric.ScopeSourceIP, metric.Subject{Type: "ip", Value: "1.2.3.4"}, 10.0, time.Second).
		WithLabel("host", "app.example.com").
		WithLabel("route_group", "/login")

	if m.Labels["host"] != "app.example.com" {
		t.Errorf("Labels[host]: got %q", m.Labels["host"])
	}
	if m.Labels["route_group"] != "/login" {
		t.Errorf("Labels[route_group]: got %q", m.Labels["route_group"])
	}
}

func TestMetricWithLabelDoesNotMutateOriginal(t *testing.T) {
	base := metric.New("http.rps", "nginx", metric.ScopeSourceIP, metric.Subject{}, 10.0, time.Second).
		WithLabel("host", "a.example.com")
	extended := base.WithLabel("route_group", "/login")

	if _, ok := base.Labels["route_group"]; ok {
		t.Error("WithLabel must not mutate the original metric's labels map")
	}
	if extended.Labels["host"] != "a.example.com" {
		t.Error("extended must inherit existing labels")
	}
}

func TestMetricJSONRoundTrip(t *testing.T) {
	m := metric.New(
		"http.auth_fail_rate",
		"nginxtelemetry",
		metric.ScopeSourceIP,
		metric.Subject{Type: "ip", Value: "192.168.1.1"},
		0.42,
		60*time.Second,
	).WithUnit("ratio").WithLabel("host", "api.example.com")

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded metric.Metric
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != m.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, m.ID)
	}
	if decoded.Value != m.Value {
		t.Errorf("Value: got %f, want %f", decoded.Value, m.Value)
	}
	if decoded.Labels["host"] != "api.example.com" {
		t.Errorf("Labels[host]: got %q", decoded.Labels["host"])
	}
}

func TestBatch(t *testing.T) {
	now := time.Now().UTC()
	b := metric.NewBatch("shieldtelemetry", now.Add(-time.Second), now)

	m1 := metric.New("network.pps", "shield", metric.ScopeSourceIP, metric.Subject{Type: "ip", Value: "1.1.1.1"}, 100, time.Second)
	m2 := metric.New("network.syn_rate", "shield", metric.ScopeSourceIP, metric.Subject{Type: "ip", Value: "1.1.1.1"}, 50, time.Second)

	b.Add(m1)
	b.Add(m2)

	if b.Len() != 2 {
		t.Errorf("Len: got %d, want 2", b.Len())
	}
	if b.Source != "shieldtelemetry" {
		t.Errorf("Source: got %q", b.Source)
	}
}

func TestZeroValueSafety(t *testing.T) {
	var m metric.Metric
	if m.Value != 0 {
		t.Error("zero Metric.Value should be 0")
	}
	if m.Labels != nil {
		t.Error("zero Metric.Labels should be nil")
	}

	var b metric.Batch
	if b.Len() != 0 {
		t.Error("zero Batch.Len should be 0")
	}
}

func TestKnownScopes(t *testing.T) {
	scopes := []metric.Scope{
		metric.ScopeSourceIP,
		metric.ScopeNode,
		metric.ScopeService,
		metric.ScopePath,
		metric.ScopeUser,
		metric.ScopeEdge,
		metric.ScopeGlobal,
	}
	for _, s := range scopes {
		if string(s) == "" {
			t.Errorf("scope constant must not be empty: %v", s)
		}
	}
}
