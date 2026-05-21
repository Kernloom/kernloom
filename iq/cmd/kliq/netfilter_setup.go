// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

// netfilter_setup.go wires the netfilter adapter with its backend.
// It lives in the main package so it can import the parent adapter package
// AND the backend sub-packages without creating a circular import — the
// backend sub-packages import the parent for shared types, and the parent
// never imports the backends directly.

import (
	"context"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/backends/iptables"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/backends/nftables"
)

// initNetfilterAdapter probes the host for Netfilter tools, selects the best
// backend and returns a fully wired Adapter ready to be registered as a
// PEPSidecar on the ShieldActionExecutor.
// The conntrack observer is started later in adapter.Start() when the bus
// is available.
//
// Returns nil when no supported backend is found (nft/iptables not available).
func initNetfilterAdapter(ctx context.Context, c cfg) *netfilter.Adapter {
	probe := netfilter.Probe(ctx)
	if probe.Selected == "" {
		kliqLog.Printf("Netfilter: no supported backend found (nft/iptables not available)")
		return nil
	}

	nfCfg := netfilter.DefaultConfig()
	nfCfg.Mode = netfilter.Mode(modeFromDryRun(c.DryRun))

	var backend netfilter.BackendIface
	switch probe.Selected {
	case netfilter.BackendNFTables:
		backend = nftables.New(probe.NFTables, nfCfg)
	case netfilter.BackendIPTablesNFT, netfilter.BackendIPTablesLegacy:
		backend = iptables.New(probe.IPTables, nfCfg)
	default:
		kliqLog.Printf("Netfilter: unknown backend %q — skipping", probe.Selected)
		return nil
	}

	adapter := netfilter.New(nfCfg)
	adapter.SetBackend(probe, backend)
	if err := adapter.Init(ctx, nil); err != nil {
		kliqLog.Printf("Netfilter adapter init failed: %v — skipping", err)
		return nil
	}
	return adapter
}

// modeFromDryRun maps the KLIQ dry-run flag to a netfilter mode string.
func modeFromDryRun(dryRun bool) string {
	if dryRun {
		return "dry-run"
	}
	return "enforce"
}
