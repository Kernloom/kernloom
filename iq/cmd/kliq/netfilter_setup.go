// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

// netfilter_setup.go wires the netfilter adapter and the conntrack observer.
// It lives in the main package so it can import the parent adapter package
// AND the backend sub-packages without creating a circular import — the
// backend sub-packages import the parent for shared types, and the parent
// never imports the backends directly.

import (
	"context"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/backends/iptables"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/backends/nftables"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/observer/conntrack"
)

// initNetfilterAdapter probes the host for Netfilter tools, selects the best
// backend and returns a fully wired Adapter ready to be registered as a
// PEPSidecar on the ShieldActionExecutor.
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
	if c.PDPConfig != "" {
		spec, ok, err := netfilter.LoadPDPAdapterSpec(c.PDPConfig)
		if err != nil {
			kliqLog.Printf("Netfilter adapter config ignored: %v", err)
		} else if ok {
			var applyErr error
			nfCfg, applyErr = netfilter.ApplyAdapterSpec(nfCfg, spec)
			if applyErr != nil {
				kliqLog.Printf("Netfilter adapter config invalid: %v — skipping", applyErr)
				return nil
			}
		}
	}

	var backend netfilter.BackendIface
	probe = netfilter.ResolveBackend(ctx, probe, nfCfg.Backend)
	selected := probe.Selected
	if selected == "" {
		kliqLog.Printf("Netfilter: requested backend %q not available — skipping", nfCfg.Backend)
		return nil
	}
	switch selected {
	case netfilter.BackendNFTables:
		backend = nftables.New(probe.NFTables, nfCfg)
	case netfilter.BackendIPTablesNFT, netfilter.BackendIPTablesLegacy:
		backend = iptables.New(probe.IPTables, nfCfg)
	default:
		kliqLog.Printf("Netfilter: unknown backend %q — skipping", selected)
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

// startConntrackObserver starts the conntrack observer for topology-only graph
// learning when klshield is absent. Observations have pps=0/bps=0 so the
// GraphLearner skips EWMA baseline updates (pps < BaselineMinUpdatePPS) but
// still upserts graph edges — recording who communicates with this machine.
func startConntrackObserver(ctx context.Context, bus adapterruntime.EventBus, nodeID string, nfCfg netfilter.Config) {
	if !nfCfg.Observation.Enabled || !nfCfg.Observation.ConntrackSnapshot {
		kliqLog.Printf("Conntrack: snapshot observer disabled by netfilter adapter config")
		return
	}
	probe := netfilter.Probe(ctx)
	if !probe.Conntrack.Available {
		kliqLog.Printf("Conntrack: not available — graph topology learning disabled (install conntrack or check /proc/net/nf_conntrack)")
		return
	}

	cfg := conntrack.Config{
		ConntrackPath: probe.Conntrack.Path,
		ProcPath:      probe.Conntrack.ProcPath,
		PollInterval:  nfCfg.Observation.ConntrackPollInterval,
		MaxFlows:      10000,
		NodeID:        nodeID,
	}
	obs, err := conntrack.New(cfg)
	if err != nil {
		kliqLog.Printf("Conntrack observer init failed: %v", err)
		return
	}
	go obs.Start(ctx, bus)
	kliqLog.Printf("Conntrack observer started: source=%s poll=%s (topology-only, no baselines)", obs.Source(), cfg.PollInterval)
}

// modeFromDryRun maps the KLIQ dry-run flag to a netfilter mode string.
func modeFromDryRun(dryRun bool) string {
	if dryRun {
		return "dry-run"
	}
	return "enforce"
}
