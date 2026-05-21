// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync/atomic"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/capability"
)

var logger = log.New(os.Stderr, "[netfilter] ", log.LstdFlags)

// Adapter is the Kernloom Netfilter PEP adapter.
// It implements adapterruntime.Adapter and selects the best available
// Netfilter backend (nftables, iptables-nft, iptables-legacy) at Init time.
//
// The adapter is intentionally conservative:
//   - Default mode is dry-run.
//   - It never modifies objects it does not own.
//   - Cleanup removes only Kernloom-prefixed chains/tables/sets.
type Adapter struct {
	cfg   Config
	probe ProbeResult

	healthy uint32 // atomic: 1 = healthy, 0 = degraded/error
}

// New creates a new netfilter adapter with the given configuration.
// Call Init before use.
func New(cfg Config) *Adapter {
	return &Adapter{cfg: cfg}
}

// NewDefault creates a new netfilter adapter with safe defaults (dry-run).
func NewDefault() *Adapter {
	return New(DefaultConfig())
}

/* ── adapterruntime.Adapter ─────────────────────────────────────────────── */

// ID returns the unique adapter identifier.
func (a *Adapter) ID() string { return "kernloom.netfilter" }

// Kind returns AdapterPEP.
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterPEP }

// Capabilities returns the set of capabilities this adapter can provide,
// based on what was detected during Init. Called once after Init.
func (a *Adapter) Capabilities() []*capability.Capability {
	if atomic.LoadUint32(&a.healthy) == 0 {
		return nil
	}
	return buildCapabilities(a.probe, a.cfg)
}

// Init probes the host for available Netfilter tools and selects the backend.
// Sets healthy=true on success; does not apply any rules.
func (a *Adapter) Init(ctx context.Context, _ adapterruntime.AdapterConfig) error {
	a.probe = Probe(ctx)

	if a.cfg.Backend != BackendAuto && a.cfg.Backend != "" {
		a.probe.Selected = a.cfg.Backend
	}

	if a.probe.Selected == "" {
		return fmt.Errorf("netfilter adapter: no supported backend found on this host " +
			"(nft, iptables not available or not executable)")
	}

	logger.Printf("backend=%s mode=%s directions={input=%v forward=%v output=%v} dry_run=%v",
		a.probe.Selected,
		a.cfg.Mode,
		a.cfg.Directions.Input,
		a.cfg.Directions.Forward,
		a.cfg.Directions.Output,
		a.cfg.Mode == ModeDryRun,
	)
	logProbe(a.probe)

	atomic.StoreUint32(&a.healthy, 1)
	return nil
}

// Start connects the adapter to the event bus.
// For now it is a no-op — enforcement is triggered synchronously via Apply.
func (a *Adapter) Start(_ context.Context, _ adapterruntime.EventBus) error {
	return nil
}

// Health reports whether the adapter initialised successfully.
func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
	if atomic.LoadUint32(&a.healthy) == 1 {
		return adapterruntime.HealthStatus{Healthy: true}
	}
	return adapterruntime.HealthStatus{
		Healthy: false,
		Message: "netfilter adapter: not initialised or no backend available",
	}
}

// Stop is a no-op unless CleanupOnExit is set.
func (a *Adapter) Stop(ctx context.Context) error {
	if a.cfg.Ownership.CleanupOnExit {
		return a.Cleanup(ctx)
	}
	return nil
}

/* ── Enforcement ─────────────────────────────────────────────────────────── */

// Cleanup removes all Kernloom-owned chains, tables and sets from the host.
// It never touches foreign rules.
func (a *Adapter) Cleanup(_ context.Context) error {
	if a.cfg.Mode == ModeDryRun {
		logger.Printf("[dry-run] Cleanup: would remove all %s-owned objects", a.cfg.Ownership.ChainPrefix)
		return nil
	}
	// Backend-specific cleanup will be implemented in Phase 2/6.
	return fmt.Errorf("netfilter: Cleanup not yet implemented for backend %s", a.probe.Selected)
}

/* ── Probe summary logging ───────────────────────────────────────────────── */

func logProbe(p ProbeResult) {
	if p.NFTables.Available {
		logger.Printf("nftables: path=%s json=%v timeout_sets=%v meters=%v",
			p.NFTables.Path, p.NFTables.JSONOutput, p.NFTables.SetTimeout, p.NFTables.Meters)
	} else {
		logger.Printf("nftables: not available")
	}

	if p.IPTables.Available {
		logger.Printf("iptables: path=%s backend=%s ipset=%v hashlimit=%v connlimit=%v",
			p.IPTables.Path,
			p.IPTables.Backend,
			p.IPTables.IPSet.Available,
			p.IPTables.HasLimit,
			p.IPTables.ConnLimit,
		)
	} else {
		logger.Printf("iptables: not available")
	}

	logger.Printf("conntrack: available=%v accounting=%v",
		p.Conntrack.Available, p.Conntrack.Accounting)
}

/* ── Capability construction ─────────────────────────────────────────────── */

// buildCapabilities returns the capability slice reflecting what was probed.
// Capabilities are declared conditionally — only what the backend can actually do.
func buildCapabilities(p ProbeResult, cfg Config) []*capability.Capability {
	var caps []*capability.Capability

	// enforce.network.deny — always available when any backend is selected.
	caps = append(caps, capability.NewCapability(
		"enforce.network.deny", "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Drop traffic from a source IP or CIDR via Netfilter",
	).AddTag("network").AddTag("enforcement").AddTag("netfilter"))

	// enforce.network.allow — always available.
	caps = append(caps, capability.NewCapability(
		"enforce.network.allow", "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Allow or return traffic from a source IP or CIDR via Netfilter",
	).AddTag("network").AddTag("enforcement").AddTag("netfilter"))

	// enforce.network.rate_limit — conditional on hashlimit (iptables) or meters (nftables).
	if cfg.Enforcement.EnableRateLimit {
		hasRateLimit := (p.Selected == BackendNFTables && p.NFTables.Meters) ||
			(p.Selected != BackendNFTables && p.IPTables.HasLimit)
		if hasRateLimit {
			caps = append(caps, capability.NewCapability(
				"enforce.network.rate_limit", "v1",
				capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
				"Rate-limit traffic via hashlimit (iptables) or meter (nftables)",
			).AddTag("network").AddTag("enforcement").AddTag("netfilter"))
		}
	}

	// observe.network.rule_counters — available when enforcement is active.
	caps = append(caps, capability.NewCapability(
		"observe.network.rule_counters", "v1",
		capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput,
		"Read packet/byte counters from Netfilter rules and sets",
	).AddTag("network").AddTag("telemetry").AddTag("netfilter"))

	// observe.network.flow_edges — conditional on conntrack.
	if p.Conntrack.Available {
		caps = append(caps, capability.NewCapability(
			"observe.network.flow_edges", "v1",
			capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput,
			"Observe L3/L4 communication edges for graph learning via conntrack",
		).AddTag("network").AddTag("telemetry").AddTag("netfilter").AddTag("conntrack"))
	}

	return caps
}
