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
// Responsibilities:
//   - Translate FSM transitions (observe/soft/hard/block) into iptables/nftables rules
//   - Maintain rule state and TTL expiry
//   - Operate as a PEP sidecar alongside or instead of klshield
//
// NOT a telemetry source. The netfilter adapter does not observe traffic or
// feed the graph learner. Graph learning requires klshield (XDP) or an
// external telemetry source. This is an intentional design decision:
// conntrack-based telemetry has different time granularity than XDP telemetry,
// mixing them distorts EWMA baselines. If klshield is unavailable, the graph
// learner simply has no telemetry input.
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

// Config returns the effective adapter configuration.
func (a *Adapter) Config() Config { return a.cfg }

// SetBackend injects the backend and probe result. Must be called before Init.
func (a *Adapter) SetBackend(probe ProbeResult, b BackendIface) {
	a.probe = probe
	a.backend = b
}

/* ── adapterruntime.Adapter ─────────────────────────────────────────────── */

func (a *Adapter) ID() string                       { return "kernloom.netfilter" }
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterPEP }

// SelectedBackend returns the backend type string selected during probe.
func (a *Adapter) SelectedBackend() string { return string(a.probe.Selected) }

// Capabilities returns the enforcement capabilities of this adapter.
// No observation capabilities — netfilter is enforcement-only.
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

// Start launches the TTL GC goroutine. No telemetry is started.
func (a *Adapter) Start(ctx context.Context, _ adapterruntime.EventBus) error {
	go a.gcLoop(ctx)
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

	snapshot := make(map[string]activeRule, len(a.rules))
	for k, v := range a.rules {
		snapshot[k] = v
	}

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
		a.rules = snapshot
		logger.Printf("ERROR apply %s→%s for %s: %v — state rolled back", prev, next, ipStr, err)
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

	chains := make([]ChainPlan, len(plan.Chains))
	copy(chains, plan.Chains)

	for _, chain := range chains {
		for _, cidr := range a.cfg.Safety.ManagementAllowlist {
			sel := Selector{SrcCIDR: cidr, Direction: chain.Hook}
			plan.Rules = append(plan.Rules, RulePlan{
				ID:       RuleID(a.ID(), "management", sel, VerdictReturn, nil),
				Chain:    chain.Name,
				Selector: sel,
				Verdict:  VerdictReturn,
				Priority: -100,
			})
		}
	}

	for _, rule := range a.rules {
		verdict := levelToVerdict(rule.level, a.probe)
		cap := levelToCapability(rule.level)
		for _, chain := range chains {
			sel := Selector{SrcIP: rule.srcIP, Direction: chain.Hook}
			ruleID := RuleID(a.ID(), cap, sel, verdict, nil)
			rp := RulePlan{
				ID:       ruleID,
				Chain:    chain.Name,
				Selector: sel,
				Verdict:  verdict,
			}
			if verdict == VerdictRateLimit {
				rate := a.ratePPSForLevel(rule.level)
				rp.RateLimit = &RateLimitParams{
					RatePPS: rate,
					Name:    "kl_" + ruleID[:8],
				}
			}
			plan.Rules = append(plan.Rules, rp)
		}
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

	snapshot := make(map[string]activeRule, len(a.rules))
	for k, v := range a.rules {
		snapshot[k] = v
	}

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

	logger.Printf("GC: expiring %d rules", removed)
	if err := a.backend.Apply(ctx, plan); err != nil {
		a.mu.Lock()
		for k, v := range snapshot {
			if _, exists := a.rules[k]; !exists {
				a.rules[k] = v
			}
		}
		a.mu.Unlock()
		logger.Printf("GC apply error (rolled back %d entries): %v", removed, err)
	}
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

func levelToVerdict(level fsm.Level, probe ProbeResult) Verdict {
	switch level {
	case fsm.LevelBlock:
		return VerdictDrop
	case fsm.LevelSoft, fsm.LevelHard:
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

func (a *Adapter) ratePPSForLevel(level fsm.Level) uint64 {
	switch level {
	case fsm.LevelHard:
		if a.cfg.Enforcement.HardRatePPS > 0 {
			return a.cfg.Enforcement.HardRatePPS
		}
		return 20
	default:
		if a.cfg.Enforcement.SoftRatePPS > 0 {
			return a.cfg.Enforcement.SoftRatePPS
		}
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

// buildCapabilities returns enforcement-only capabilities.
// No observation capabilities — telemetry requires klshield.
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
