// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/netfilter/observer/conntrack"
	"github.com/kernloom/kernloom/pkg/core/capability"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

var logger = log.New(os.Stderr, "[netfilter] ", log.LstdFlags)

// BackendIface is the common interface both iptables and nftables backends
// implement. It is satisfied by backends/iptables.Backend and
// backends/nftables.Backend. Defined here so the parent package does NOT need
// to import the backend sub-packages (which would create a cycle, because the
// backends import the parent for shared types).
//
// The concrete backend is injected from outside (kliq.go) via SetBackend.
type BackendIface interface {
	Apply(ctx context.Context, plan NetfilterPlan) error
	Cleanup(ctx context.Context) error
}

// activeRule tracks an enforcement rule currently installed by the adapter.
type activeRule struct {
	srcIP   string
	level   fsm.Level
	expires time.Time // zero = no expiry
}

// Adapter is the Kernloom Netfilter PEP adapter.
//
// It implements adapterruntime.Adapter so it can be registered in KLIQ's
// adapter registry, and implements the actions.PEPSidecar interface so it
// receives FSM transition notifications from the ShieldActionExecutor.
//
// Usage:
//
//	probe := netfilter.Probe(ctx)
//	backend := iptables.New(probe.IPTables, cfg)   // or nftables.New(...)
//	adapter := netfilter.New(cfg)
//	adapter.SetBackend(probe, backend)
//	adapter.Init(ctx, nil)
type Adapter struct {
	cfg     Config
	probe   ProbeResult
	backend BackendIface

	mu      sync.Mutex
	rules   map[string]activeRule // key: srcIP string
	healthy uint32                // atomic: 1 = healthy
}

// New creates a new Adapter. Call SetBackend then Init before use.
func New(cfg Config) *Adapter {
	return &Adapter{cfg: cfg, rules: make(map[string]activeRule)}
}

// NewDefault creates an Adapter with safe dry-run defaults.
func NewDefault() *Adapter { return New(DefaultConfig()) }

// SetBackend injects the backend and probe result. Must be called before Init.
// This is kept separate from Init so that kliq.go (which imports both the
// netfilter parent and the backend sub-packages) can wire them together
// without creating an import cycle inside this package.
func (a *Adapter) SetBackend(probe ProbeResult, b BackendIface) {
	a.probe = probe
	a.backend = b
}

/* ── adapterruntime.Adapter ─────────────────────────────────────────────── */

func (a *Adapter) ID() string                       { return "kernloom.netfilter" }
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterPEP }

// SelectedBackend returns the backend type string selected during probe.
func (a *Adapter) SelectedBackend() string { return string(a.probe.Selected) }

func (a *Adapter) Capabilities() []*capability.Capability {
	if atomic.LoadUint32(&a.healthy) == 0 {
		return nil
	}
	return buildCapabilities(a.probe, a.cfg)
}

// Init validates that a backend was injected and marks the adapter healthy.
func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error {
	if a.backend == nil {
		return fmt.Errorf("netfilter adapter: no backend set — call SetBackend before Init")
	}
	logger.Printf("init: backend=%s mode=%s", a.probe.Selected, a.cfg.Mode)
	logProbe(a.probe)
	atomic.StoreUint32(&a.healthy, 1)
	return nil
}

// Start connects to the event bus, launches the TTL GC goroutine, and starts
// the conntrack observer when conntrack is available on the host.
func (a *Adapter) Start(ctx context.Context, bus adapterruntime.EventBus) error {
	go a.gcLoop(ctx)

	if a.probe.Conntrack.Available && a.cfg.Observation.ConntrackSnapshot {
		cfg := conntrack.Config{
			ConntrackPath: a.probe.Conntrack.Path,
			PollInterval:  a.cfg.Observation.ConntrackPollInterval,
			MaxFlows:      a.cfg.Observation.MaxObservationsPerTick,
		}
		obs, err := conntrack.New(cfg)
		if err == nil {
			go obs.Start(ctx, bus)
			logger.Printf("conntrack observer started (poll=%s)", cfg.PollInterval)
		} else {
			logger.Printf("conntrack observer unavailable: %v", err)
		}
	}
	return nil
}

func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
	if atomic.LoadUint32(&a.healthy) == 1 {
		return adapterruntime.HealthStatus{Healthy: true}
	}
	return adapterruntime.HealthStatus{
		Healthy: false,
		Message: "netfilter adapter: not initialised or backend unavailable",
	}
}

func (a *Adapter) Stop(ctx context.Context) error {
	atomic.StoreUint32(&a.healthy, 0)
	if a.cfg.Ownership.CleanupOnExit && a.backend != nil {
		return a.backend.Cleanup(ctx)
	}
	return nil
}

/* ── actions.PEPSidecar ─────────────────────────────────────────────────── */

// NotifyTransition4 mirrors an IPv4 FSM transition into Netfilter rules.
// Called synchronously by ShieldActionExecutor after every authorized action.
func (a *Adapter) NotifyTransition4(ip [4]byte, prev, next fsm.Level, ttl time.Duration) {
	if atomic.LoadUint32(&a.healthy) == 0 {
		return
	}
	a.applyLevel(context.Background(), net.IP(ip[:]).String(), prev, next, ttl)
}

// NotifyTransition6 mirrors an IPv6 FSM transition into Netfilter rules.
func (a *Adapter) NotifyTransition6(ip [16]byte, prev, next fsm.Level, ttl time.Duration) {
	if atomic.LoadUint32(&a.healthy) == 0 {
		return
	}
	a.applyLevel(context.Background(), net.IP(ip[:]).String(), prev, next, ttl)
}

/* ── Enforcement ─────────────────────────────────────────────────────────── */

func (a *Adapter) applyLevel(ctx context.Context, ipStr string, prev, next fsm.Level, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch next {
	case fsm.LevelObserve:
		delete(a.rules, ipStr)
	default:
		exp := time.Time{}
		if ttl > 0 {
			exp = time.Now().Add(ttl)
		}
		a.rules[ipStr] = activeRule{srcIP: ipStr, level: next, expires: exp}
	}

	plan := a.buildPlan()
	if err := a.backend.Apply(ctx, plan); err != nil {
		logger.Printf("ERROR apply %s→%s for %s: %v", prev, next, ipStr, err)
		return
	}
	if next == fsm.LevelObserve && prev != fsm.LevelObserve {
		logger.Printf("de-enforced src=%s (%s→observe)", ipStr, prev)
	} else if next != fsm.LevelObserve {
		logger.Printf("enforced src=%s %s→%s", ipStr, prev, next)
	}
}

// buildPlan constructs the full desired-state NetfilterPlan from active rules.
// Must be called with a.mu held.
func (a *Adapter) buildPlan() NetfilterPlan {
	plan := NetfilterPlan{TableName: a.cfg.Ownership.TableName}
	if plan.TableName == "" {
		plan.TableName = "filter"
	}

	prefix := a.cfg.Ownership.ChainPrefix
	if a.cfg.Directions.Input {
		plan.Chains = append(plan.Chains, ChainPlan{Name: prefix + "_INPUT", Hook: "input", Policy: "accept"})
	}
	if a.cfg.Directions.Forward {
		plan.Chains = append(plan.Chains, ChainPlan{Name: prefix + "_FORWARD", Hook: "forward", Policy: "accept"})
	}
	if a.cfg.Directions.Output {
		plan.Chains = append(plan.Chains, ChainPlan{Name: prefix + "_OUTPUT", Hook: "output", Policy: "accept"})
	}

	chain := prefix + "_INPUT"

	// Management allowlist: RETURN rules at priority -100 (always evaluated first).
	for _, cidr := range a.cfg.Safety.ManagementAllowlist {
		plan.Rules = append(plan.Rules, RulePlan{
			ID:       RuleID(a.ID(), "management", Selector{SrcCIDR: cidr}, VerdictReturn, nil),
			Chain:    chain,
			Selector: Selector{SrcCIDR: cidr},
			Verdict:  VerdictReturn,
			Priority: -100,
		})
	}

	for _, rule := range a.rules {
		verdict := levelToVerdict(rule.level, a.probe)
		cap := levelToCapability(rule.level)
		ruleID := RuleID(a.ID(), cap, Selector{SrcIP: rule.srcIP}, verdict, nil)
		rp := RulePlan{
			ID:       ruleID,
			Chain:    chain,
			Selector: Selector{SrcIP: rule.srcIP},
			Verdict:  verdict,
		}
		if verdict == VerdictRateLimit {
			rate := ratePPSForLevel(rule.level)
			rp.RateLimit = &RateLimitParams{
				RatePPS: rate,
				Name:    "kl_" + ruleID[:8],
			}
		}
		plan.Rules = append(plan.Rules, rp)
	}
	return plan
}

/* ── TTL GC ──────────────────────────────────────────────────────────────── */

func (a *Adapter) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.gcExpired(ctx)
		}
	}
}

func (a *Adapter) gcExpired(ctx context.Context) {
	a.mu.Lock()
	now := time.Now()
	removed := 0
	for k, r := range a.rules {
		if !r.expires.IsZero() && now.After(r.expires) {
			delete(a.rules, k)
			removed++
		}
	}
	if removed == 0 {
		a.mu.Unlock()
		return
	}
	plan := a.buildPlan()
	a.mu.Unlock()

	logger.Printf("GC: expired %d rules", removed)
	if err := a.backend.Apply(ctx, plan); err != nil {
		logger.Printf("GC apply error: %v", err)
	}
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

func levelToVerdict(level fsm.Level, probe ProbeResult) Verdict {
	switch level {
	case fsm.LevelBlock:
		return VerdictDrop
	case fsm.LevelSoft, fsm.LevelHard:
		// Use native rate-limit when the backend supports it.
		hasRL := (probe.Selected == BackendNFTables && probe.NFTables.Meters) ||
			(probe.Selected != BackendNFTables && probe.IPTables.HasLimit)
		if hasRL {
			return VerdictRateLimit
		}
		return VerdictDrop
	default:
		return VerdictReturn
	}
}

// ratePPSForLevel returns a conservative default rate for SOFT/HARD levels.
// These are fallback values; in managed mode the bundle's enforcement_bounds
// or PDPConfig adapter rates take precedence.
func ratePPSForLevel(level fsm.Level) uint64 {
	switch level {
	case fsm.LevelHard:
		return 20
	default: // LevelSoft
		return 100
	}
}

func levelToCapability(level fsm.Level) string {
	switch level {
	case fsm.LevelBlock:
		return "enforce.network.deny"
	case fsm.LevelSoft, fsm.LevelHard:
		return "enforce.network.rate_limit"
	default:
		return "enforce.network.allow"
	}
}

func buildCapabilities(p ProbeResult, cfg Config) []*capability.Capability {
	var caps []*capability.Capability

	caps = append(caps, capability.NewCapability(
		"enforce.network.deny", "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Drop traffic from a source IP or CIDR via Netfilter",
	).AddTag("network").AddTag("enforcement").AddTag("netfilter"))

	caps = append(caps, capability.NewCapability(
		"enforce.network.allow", "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Allow or return traffic from a source IP or CIDR via Netfilter",
	).AddTag("network").AddTag("enforcement").AddTag("netfilter"))

	if cfg.Enforcement.EnableRateLimit {
		hasRL := (p.Selected == BackendNFTables && p.NFTables.Meters) ||
			(p.Selected != BackendNFTables && p.IPTables.HasLimit)
		if hasRL {
			caps = append(caps, capability.NewCapability(
				"enforce.network.rate_limit", "v1",
				capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
				"Rate-limit traffic via hashlimit (iptables) or meter (nftables)",
			).AddTag("network").AddTag("enforcement").AddTag("netfilter"))
		}
	}

	caps = append(caps, capability.NewCapability(
		"observe.network.rule_counters", "v1",
		capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput,
		"Read packet/byte counters from Netfilter rules and sets",
	).AddTag("network").AddTag("telemetry").AddTag("netfilter"))

	if p.Conntrack.Available {
		caps = append(caps, capability.NewCapability(
			"observe.network.flow_edges", "v1",
			capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput,
			"Observe L3/L4 flow edges for graph learning via conntrack",
		).AddTag("network").AddTag("telemetry").AddTag("netfilter").AddTag("conntrack"))
	}
	return caps
}

func logProbe(p ProbeResult) {
	if p.NFTables.Available {
		logger.Printf("nftables: path=%s json=%v", p.NFTables.Path, p.NFTables.JSONOutput)
	} else {
		logger.Printf("nftables: not available")
	}
	if p.IPTables.Available {
		logger.Printf("iptables: path=%s backend=%s ipset=%v hashlimit=%v",
			p.IPTables.Path, p.IPTables.Backend,
			p.IPTables.IPSet.Available, p.IPTables.HasLimit)
	} else {
		logger.Printf("iptables: not available")
	}
	logger.Printf("conntrack: available=%v accounting=%v",
		p.Conntrack.Available, p.Conntrack.Accounting)
}
