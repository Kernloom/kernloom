// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry_test

import (
	"testing"

	registries "github.com/kernloom/kernloom-registries"
	"github.com/kernloom/kernloom/pkg/registry"
)

func testBundle(t *testing.T) *registry.Bundle {
	t.Helper()
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		t.Fatalf("EmbeddedSnapshot: %v", err)
	}
	b, err := registry.FromSnapshot(snapshot)
	if err != nil {
		t.Fatalf("FromSnapshot: %v", err)
	}
	return b
}

func TestSnapshotBundle_HasNetworkMetrics(t *testing.T) {
	b := testBundle(t)
	for _, id := range []string{
		"network.packets_per_second",
		"network.bytes_per_second",
		"network.syn_rate",
		"network.scan_rate",
	} {
		if !b.HasMetric(id) {
			t.Errorf("expected metric %q in registry snapshot", id)
		}
	}
}

func TestSnapshotBundle_MetricScopeAllowed(t *testing.T) {
	b := testBundle(t)
	if !b.MetricScopeAllowed("network.packets_per_second", "src_ip") {
		t.Error("src_ip should be allowed for network.packets_per_second")
	}
	if b.MetricScopeAllowed("http.latency_p95_ms", "src_ip") {
		t.Error("src_ip should NOT be allowed for http.latency_p95_ms (service only)")
	}
}

func TestSnapshotBundle_LabelPolicy_Allowed(t *testing.T) {
	b := testBundle(t)
	for _, label := range []string{"host", "status_class", "service", "protocol"} {
		if !b.IsLabelAllowed(label) {
			t.Errorf("label %q should be allowed", label)
		}
	}
}

func TestSnapshotBundle_LabelPolicy_Forbidden(t *testing.T) {
	b := testBundle(t)
	for _, label := range []string{"path", "uri", "user_agent", "session_id", "username", "cookie"} {
		if b.IsLabelAllowed(label) {
			t.Errorf("label %q should be FORBIDDEN", label)
		}
	}
}

func TestSnapshotBundle_UnknownLabel_NotAllowed(t *testing.T) {
	b := testBundle(t)
	if b.IsLabelAllowed("totally_unknown_label") {
		t.Error("unknown labels should not be allowed (fail-safe)")
	}
}

func TestValidateSelectedLabels_FiltersOutForbidden(t *testing.T) {
	b := testBundle(t)
	requested := []string{"host", "path", "status_class", "user_agent"}
	allowed, rejected := registry.ValidateSelectedLabels(b, requested)

	if len(allowed) != 2 {
		t.Errorf("expected 2 allowed labels, got %d: %v", len(allowed), allowed)
	}
	if len(rejected) != 2 {
		t.Errorf("expected 2 rejected labels, got %d: %v", len(rejected), rejected)
	}
}

func TestValidateSelectedLabels_NilBundle_RejectsAll(t *testing.T) {
	requested := []string{"host", "path", "unknown"}
	allowed, rejected := registry.ValidateSelectedLabels(nil, requested)
	if len(allowed) != 0 {
		t.Errorf("nil bundle should allow no labels, got %d allowed", len(allowed))
	}
	if len(rejected) != 3 {
		t.Errorf("nil bundle should reject all labels, got %d rejected", len(rejected))
	}
}

func TestSnapshotBundle_HasSignals(t *testing.T) {
	b := testBundle(t)
	if !b.HasSignal("source.pps_high") {
		t.Error("expected source.pps_high in registry snapshot")
	}
	if !b.HasSignal("http.credential_stuffing_suspected") {
		t.Error("expected HTTP signals in registry snapshot")
	}
}

func TestSnapshotBundle_HasCapabilities(t *testing.T) {
	b := testBundle(t)
	if !b.HasCapability("enforce.network.rate_limit") {
		t.Error("expected enforce.network.rate_limit in registry snapshot")
	}
	if !b.HasRuntimeActionCapability("enforce.network.rate_limit") {
		t.Error("expected enforce.network.rate_limit to be runtime executable")
	}
	if !b.HasCapability("enforce.network.allow") {
		t.Error("expected enforce.network.allow in registry snapshot")
	}
	if b.HasRuntimeActionCapability("enforce.network.allow") {
		t.Error("enforce.network.allow must not be runtime executable")
	}
}

func TestNilBundle_FailClosed(t *testing.T) {
	var b *registry.Bundle
	// nil bundle should not panic and should fail closed.
	if b.HasMetric("anything") {
		t.Error("nil bundle HasMetric should return false")
	}
	if b.HasSignal("anything") {
		t.Error("nil bundle HasSignal should return false")
	}
	if b.IsLabelAllowed("host") {
		t.Error("nil bundle IsLabelAllowed should return false")
	}
	if b.MetricScopeAllowed("any", "any") {
		t.Error("nil bundle MetricScopeAllowed should fail closed")
	}
}
