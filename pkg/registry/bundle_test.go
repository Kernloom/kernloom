// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry_test

import (
	"testing"

	"github.com/kernloom/kernloom/pkg/registry"
)

func TestDefaultBundle_HasNetworkMetrics(t *testing.T) {
	b := registry.DefaultBundle()
	for _, id := range []string{
		"network.packets_per_second",
		"network.bytes_per_second",
		"network.syn_rate",
		"network.scan_rate",
	} {
		if !b.HasMetric(id) {
			t.Errorf("expected metric %q in default bundle", id)
		}
	}
}

func TestDefaultBundle_MetricScopeAllowed(t *testing.T) {
	b := registry.DefaultBundle()
	if !b.MetricScopeAllowed("network.packets_per_second", "src_ip") {
		t.Error("src_ip should be allowed for network.packets_per_second")
	}
	if b.MetricScopeAllowed("http.latency_p95_ms", "src_ip") {
		t.Error("src_ip should NOT be allowed for http.latency_p95_ms (service only)")
	}
}

func TestDefaultBundle_LabelPolicy_Allowed(t *testing.T) {
	b := registry.DefaultBundle()
	for _, label := range []string{"host", "status_class", "service", "protocol"} {
		if !b.IsLabelAllowed(label) {
			t.Errorf("label %q should be allowed", label)
		}
	}
}

func TestDefaultBundle_LabelPolicy_Forbidden(t *testing.T) {
	b := registry.DefaultBundle()
	for _, label := range []string{"path", "uri", "user_agent", "session_id", "username", "cookie"} {
		if b.IsLabelAllowed(label) {
			t.Errorf("label %q should be FORBIDDEN", label)
		}
	}
}

func TestDefaultBundle_UnknownLabel_NotAllowed(t *testing.T) {
	b := registry.DefaultBundle()
	if b.IsLabelAllowed("totally_unknown_label") {
		t.Error("unknown labels should not be allowed (fail-safe)")
	}
}

func TestValidateSelectedLabels_FiltersOutForbidden(t *testing.T) {
	b := registry.DefaultBundle()
	requested := []string{"host", "path", "status_class", "user_agent"}
	allowed, rejected := registry.ValidateSelectedLabels(b, requested)

	if len(allowed) != 2 {
		t.Errorf("expected 2 allowed labels, got %d: %v", len(allowed), allowed)
	}
	if len(rejected) != 2 {
		t.Errorf("expected 2 rejected labels, got %d: %v", len(rejected), rejected)
	}
}

func TestValidateSelectedLabels_NilBundle_AllowsAll(t *testing.T) {
	requested := []string{"host", "path", "unknown"}
	allowed, rejected := registry.ValidateSelectedLabels(nil, requested)
	if len(allowed) != 3 {
		t.Errorf("nil bundle should allow all labels, got %d allowed", len(allowed))
	}
	if len(rejected) != 0 {
		t.Errorf("nil bundle should reject nothing, got %d rejected", len(rejected))
	}
}

func TestDefaultBundle_HasSignals(t *testing.T) {
	b := registry.DefaultBundle()
	if !b.HasSignal("source.pps_high") {
		t.Error("expected source.pps_high in default bundle")
	}
	if !b.HasSignal("signals.http.credential_stuffing_suspected") {
		t.Error("expected HTTP signals in default bundle")
	}
}

func TestDefaultBundle_HasCapabilities(t *testing.T) {
	b := registry.DefaultBundle()
	if !b.HasCapability("enforce.network.rate_limit") {
		t.Error("expected enforce.network.rate_limit in default bundle")
	}
}

func TestNilBundle_Permissive(t *testing.T) {
	var b *registry.Bundle
	// nil bundle should not panic and should return permissive/false values
	if b.HasMetric("anything") {
		t.Error("nil bundle HasMetric should return false")
	}
	if b.HasSignal("anything") {
		t.Error("nil bundle HasSignal should return false")
	}
	if b.IsLabelAllowed("host") {
		t.Error("nil bundle IsLabelAllowed should return false")
	}
	// MetricScopeAllowed on nil returns true (permissive)
	if !b.MetricScopeAllowed("any", "any") {
		t.Error("nil bundle MetricScopeAllowed should be permissive (true)")
	}
}
