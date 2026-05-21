// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"context"
	"testing"
)

func TestProbe_NocrashOnAnyHost(t *testing.T) {
	// Probe must never panic regardless of what is installed.
	result := Probe(context.Background())
	t.Logf("selected backend: %q", result.Selected)
	t.Logf("nftables: available=%v path=%q json=%v",
		result.NFTables.Available, result.NFTables.Path, result.NFTables.JSONOutput)
	t.Logf("iptables: available=%v path=%q backend=%q ipset=%v hashlimit=%v",
		result.IPTables.Available, result.IPTables.Path, result.IPTables.Backend,
		result.IPTables.IPSet.Available, result.IPTables.HasLimit)
	t.Logf("conntrack: available=%v accounting=%v",
		result.Conntrack.Available, result.Conntrack.Accounting)
}

func TestAdapter_InitAndCapabilities(t *testing.T) {
	a := NewDefault()
	err := a.Init(context.Background(), nil)
	if err != nil {
		t.Skipf("no Netfilter backend available on this host: %v", err)
	}

	caps := a.Capabilities()
	if len(caps) == 0 {
		t.Error("expected at least one capability after successful init")
	}
	for _, c := range caps {
		t.Logf("capability: %s", c.ID)
	}

	health := a.Health(context.Background())
	if !health.Healthy {
		t.Errorf("expected healthy after successful init, got: %s", health.Message)
	}
}

func TestAdapter_InitDryRun_NeverApplies(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeDryRun
	a := New(cfg)

	err := a.Init(context.Background(), nil)
	if err != nil {
		t.Skipf("no Netfilter backend available: %v", err)
	}
	// Cleanup in dry-run should never return an error.
	if err := a.Cleanup(context.Background()); err != nil {
		t.Errorf("dry-run Cleanup returned error: %v", err)
	}
}

func TestSelectBackend_Priority(t *testing.T) {
	cases := []struct {
		name     string
		probe    ProbeResult
		expected BackendType
	}{
		{
			name:     "nftables preferred over iptables",
			probe:    ProbeResult{NFTables: NFTablesProbe{Available: true}, IPTables: IPTablesProbe{Available: true}},
			expected: BackendNFTables,
		},
		{
			name:     "iptables-nft when no nftables",
			probe:    ProbeResult{IPTables: IPTablesProbe{Available: true, Backend: "nft"}},
			expected: BackendIPTablesNFT,
		},
		{
			name:     "iptables-legacy fallback",
			probe:    ProbeResult{IPTables: IPTablesProbe{Available: true, Backend: "legacy"}},
			expected: BackendIPTablesLegacy,
		},
		{
			name:     "nothing available",
			probe:    ProbeResult{},
			expected: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectBackend(tc.probe)
			if got != tc.expected {
				t.Errorf("selectBackend() = %q, want %q", got, tc.expected)
			}
		})
	}
}
