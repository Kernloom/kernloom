// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package adapterruntime

import (
	"testing"

	"github.com/adrianenderlin/kernloom/pkg/core/capability"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()

	caps := []*capability.Capability{
		WellKnownNetworkBlockSource(),
		WellKnownNetworkRateLimitSource(),
	}

	if err := r.Register("shield-pep", caps); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	c, ok := r.Lookup(CapIDNetworkBlockSource)
	if !ok {
		t.Fatal("expected network.block_source to be registered")
	}
	if c.Adapter != "shield-pep" {
		t.Errorf("expected adapter=shield-pep, got %s", c.Adapter)
	}
}

func TestRegistryHas(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("shield-pep", []*capability.Capability{WellKnownNetworkBlockSource()})

	if !r.Has(CapIDNetworkBlockSource) {
		t.Error("expected Has to return true for registered capability")
	}
	if r.Has("nonexistent.capability") {
		t.Error("expected Has to return false for unknown capability")
	}
}

func TestRegistryHasAll(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("shield-pep", []*capability.Capability{
		WellKnownNetworkBlockSource(),
		WellKnownNetworkRateLimitSource(),
	})

	missing := r.HasAll([]string{CapIDNetworkBlockSource, CapIDNetworkRateLimitSource})
	if len(missing) != 0 {
		t.Errorf("expected no missing capabilities, got %v", missing)
	}

	missing = r.HasAll([]string{CapIDNetworkBlockSource, CapIDGraphLearnEdges})
	if len(missing) != 1 || missing[0] != CapIDGraphLearnEdges {
		t.Errorf("expected [graph.learn_edges] missing, got %v", missing)
	}
}

func TestRegistryUnregister(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("shield-pep", []*capability.Capability{WellKnownNetworkBlockSource()})
	r.Unregister("shield-pep")

	if r.Has(CapIDNetworkBlockSource) {
		t.Error("expected capability to be gone after Unregister")
	}
}

func TestRegistryReregister(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("shield-pep", []*capability.Capability{WellKnownNetworkBlockSource()})
	_ = r.Register("shield-pep", []*capability.Capability{WellKnownNetworkRateLimitSource()})

	if r.Has(CapIDNetworkBlockSource) {
		t.Error("old capability should be replaced on re-register")
	}
	if !r.Has(CapIDNetworkRateLimitSource) {
		t.Error("new capability should be present after re-register")
	}
}

func TestRegistryByAdapter(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("shield-pep", []*capability.Capability{
		WellKnownNetworkBlockSource(),
		WellKnownNetworkAllowSource(),
	})
	_ = r.Register("graph-learner", []*capability.Capability{
		WellKnownGraphLearnEdges(),
	})

	pep := r.ByAdapter("shield-pep")
	if len(pep) != 2 {
		t.Errorf("expected 2 capabilities for shield-pep, got %d", len(pep))
	}

	graph := r.ByAdapter("graph-learner")
	if len(graph) != 1 {
		t.Errorf("expected 1 capability for graph-learner, got %d", len(graph))
	}
}

func TestRegistryAll(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("a1", []*capability.Capability{WellKnownNetworkBlockSource()})
	_ = r.Register("a2", []*capability.Capability{WellKnownGraphLearnEdges(), WellKnownTrustConsumeAssertion()})

	all := r.All()
	if len(all) != 3 {
		t.Errorf("expected 3 total capabilities, got %d", len(all))
	}
}

func TestRegistryEmptyIDError(t *testing.T) {
	r := NewRegistry()
	bad := capability.NewCapability("", "v1", capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput, "bad")
	if err := r.Register("some-adapter", []*capability.Capability{bad}); err == nil {
		t.Error("expected error for capability with empty ID")
	}
}

func TestWellKnownIDs(t *testing.T) {
	// Verify that factory functions produce capabilities with the matching ID constant.
	cases := []struct {
		id  string
		cap *capability.Capability
	}{
		{CapIDNetworkBlockSource, WellKnownNetworkBlockSource()},
		{CapIDNetworkRateLimitSource, WellKnownNetworkRateLimitSource()},
		{CapIDGraphLearnEdges, WellKnownGraphLearnEdges()},
		{CapIDTrustConsumeAssertion, WellKnownTrustConsumeAssertion()},
		{CapIDSignalEmitLocalRisk, WellKnownSignalEmitLocalRisk()},
		{CapIDAdapterReportHealth, WellKnownAdapterReportHealth()},
	}

	for _, tc := range cases {
		if tc.cap.ID != tc.id {
			t.Errorf("WellKnown function returned ID=%q, expected constant %q", tc.cap.ID, tc.id)
		}
	}
}
