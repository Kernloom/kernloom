// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/backends/iptables"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/backends/nftables"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/observer/conntrack"
)

type Logger interface {
	Printf(string, ...any)
}

type Adapter = netfilter.Adapter

type SetupConfig struct {
	DryRun    bool
	PDPConfig string
}

func InitAdapter(ctx context.Context, cfg SetupConfig, log Logger) *netfilter.Adapter {
	probe := netfilter.Probe(ctx)
	if probe.Selected == "" {
		log.Printf("Netfilter: no supported backend found (nft/iptables not available)")
		return nil
	}

	nfCfg := netfilter.DefaultConfig()
	nfCfg.Mode = netfilter.Mode(modeFromDryRun(cfg.DryRun))
	if cfg.PDPConfig != "" {
		spec, ok, err := netfilter.LoadPDPAdapterSpec(cfg.PDPConfig)
		if err != nil {
			log.Printf("Netfilter adapter config ignored: %v", err)
		} else if ok {
			var applyErr error
			nfCfg, applyErr = netfilter.ApplyAdapterSpec(nfCfg, spec)
			if applyErr != nil {
				log.Printf("Netfilter adapter config invalid: %v — skipping", applyErr)
				return nil
			}
		}
	}

	var backend netfilter.BackendIface
	probe = netfilter.ResolveBackend(ctx, probe, nfCfg.Backend)
	selected := probe.Selected
	if selected == "" {
		log.Printf("Netfilter: requested backend %q not available — skipping", nfCfg.Backend)
		return nil
	}
	switch selected {
	case netfilter.BackendNFTables:
		backend = nftables.New(probe.NFTables, nfCfg)
	case netfilter.BackendIPTablesNFT, netfilter.BackendIPTablesLegacy:
		backend = iptables.New(probe.IPTables, nfCfg)
	default:
		log.Printf("Netfilter: unknown backend %q — skipping", selected)
		return nil
	}

	adapter := netfilter.New(nfCfg)
	adapter.SetBackend(probe, backend)
	if err := adapter.Init(ctx, nil); err != nil {
		log.Printf("Netfilter adapter init failed: %v — skipping", err)
		return nil
	}
	return adapter
}

func StartTopologyFallbackObserver(
	ctx context.Context,
	bus adapterruntime.EventBus,
	nodeID string,
	graphEnabled bool,
	primaryTelemetryActive bool,
	adapter *netfilter.Adapter,
	log Logger,
) {
	if primaryTelemetryActive || !graphEnabled {
		return
	}
	nfCfg := netfilter.DefaultConfig()
	if adapter != nil {
		nfCfg = adapter.Config()
	}
	startConntrackObserver(ctx, bus, nodeID, nfCfg, log)
}

func startConntrackObserver(ctx context.Context, bus adapterruntime.EventBus, nodeID string, nfCfg netfilter.Config, log Logger) {
	if !nfCfg.Observation.Enabled || !nfCfg.Observation.ConntrackSnapshot {
		log.Printf("Conntrack: snapshot observer disabled by netfilter adapter config")
		return
	}
	probe := netfilter.Probe(ctx)
	if !probe.Conntrack.Available {
		log.Printf("Conntrack: not available — graph topology learning disabled (install conntrack or check /proc/net/nf_conntrack)")
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
		log.Printf("Conntrack observer init failed: %v", err)
		return
	}
	go obs.Start(ctx, bus)
	log.Printf("Conntrack observer started: source=%s poll=%s (topology-only, no baselines)", obs.Source(), cfg.PollInterval)
}

func modeFromDryRun(dryRun bool) string {
	if dryRun {
		return "dry-run"
	}
	return "enforce"
}
