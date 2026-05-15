// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package shieldpep implements the Shield PEP (Policy Enforcement Point) adapter.
// It applies L3/L4 enforcement decisions by writing into the pinned eBPF maps
// exposed by Kernloom Shield.
package shieldpep

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/capability"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/shieldclient"
	"github.com/cilium/ebpf"
)

var logger = log.New(os.Stderr, "[shield-pep] ", log.LstdFlags)

// EnforcementParams carries the per-level rate-limit and timing configuration
// needed by the PEP adapter when transitioning a source to a new level.
type EnforcementParams struct {
	SoftRate  uint64
	SoftBurst uint64
	SoftTTL   time.Duration

	HardRate  uint64
	HardBurst uint64
	HardTTL   time.Duration

	BlockTTL time.Duration
	Cooldown time.Duration
}

// Adapter is the Shield PEP adapter.
// It is intentionally synchronous: enforcement calls are made inline from the
// KLIQ tick loop (via TransitionV4/TransitionV6), not via the event bus.
type Adapter struct {
	maps   *shieldclient.Maps
	dryRun bool

	healthy uint32 // 1 = healthy, 0 = unhealthy (atomic)
}

// New creates a new Shield PEP adapter.
func New(maps *shieldclient.Maps, dryRun bool) *Adapter {
	return &Adapter{maps: maps, dryRun: dryRun}
}

/* ---------------- adapterruntime.Adapter interface ----------------------- */

// ID returns the unique adapter identifier.
func (a *Adapter) ID() string { return "shield-pep" }

// Kind returns AdapterPEP.
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterPEP }

// Capabilities returns the capabilities provided by this adapter.
func (a *Adapter) Capabilities() []*capability.Capability {
	return []*capability.Capability{
		adapterruntime.WellKnownNetworkBlockSource(),
		adapterruntime.WellKnownNetworkRateLimitSource(),
		adapterruntime.WellKnownNetworkAllowSource(),
		adapterruntime.WellKnownNetworkEnforceAllowlist(),
	}
}

// Init validates that the required maps are present when not in dry-run mode.
func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error {
	atomic.StoreUint32(&a.healthy, 1)
	return nil
}

// Start is a no-op for the PEP adapter; enforcement is synchronous via Transition*.
func (a *Adapter) Start(_ context.Context, _ adapterruntime.EventBus) error {
	return nil
}

// Health reports whether the adapter is operating normally.
func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
	if atomic.LoadUint32(&a.healthy) == 1 {
		return adapterruntime.HealthStatus{Healthy: true}
	}
	return adapterruntime.HealthStatus{Healthy: false, Message: "shield-pep: maps not available"}
}

// Stop is a no-op; map lifecycle is managed by the caller.
func (a *Adapter) Stop(_ context.Context) error {
	return nil
}

/* ---------------- Enforcement transitions --------------------------------- */

// TransitionV4 applies the enforcement action for an IPv4 source.
// It writes into the Shield deny / rl-policy maps (unless dryRun is set) and
// returns the updated fsm.State with Level, ExpiresAt and CooldownUntil set.
func (a *Adapter) TransitionV4(
	ip [4]byte, st fsm.State, target fsm.Level,
	now time.Time, p EnforcementParams,
) fsm.State {
	logger.Printf("ACTION ip=%s %s->%s dry_run=%v", net.IPv4(ip[0], ip[1], ip[2], ip[3]).String(), st.Level, target, a.dryRun)
	if !a.dryRun && a.maps != nil {
		switch target {
		case fsm.LevelObserve:
			if a.maps.RL4 != nil {
				_ = a.maps.RL4.Delete(&ip)
			}
			if a.maps.Deny4 != nil {
				_ = a.maps.Deny4.Delete(&ip)
			}
		case fsm.LevelSoft:
			if a.maps.Deny4 != nil {
				_ = a.maps.Deny4.Delete(&ip)
			}
			if a.maps.RL4 != nil {
				val := shieldclient.RLConfig{RatePPS: p.SoftRate, Burst: p.SoftBurst}
				_ = a.maps.RL4.Update(&ip, &val, ebpf.UpdateAny)
			}
		case fsm.LevelHard:
			if a.maps.Deny4 != nil {
				_ = a.maps.Deny4.Delete(&ip)
			}
			if a.maps.RL4 != nil {
				val := shieldclient.RLConfig{RatePPS: p.HardRate, Burst: p.HardBurst}
				_ = a.maps.RL4.Update(&ip, &val, ebpf.UpdateAny)
			}
		case fsm.LevelBlock:
			if a.maps.RL4 != nil {
				_ = a.maps.RL4.Delete(&ip)
			}
			if a.maps.Deny4 != nil {
				v := uint8(1)
				_ = a.maps.Deny4.Update(&ip, &v, ebpf.UpdateAny)
			}
		}
	}

	return applyStateFields(st, target, now, p)
}

// TransitionV6 applies the enforcement action for an IPv6 source.
func (a *Adapter) TransitionV6(
	ip [16]byte, st fsm.State, target fsm.Level,
	now time.Time, p EnforcementParams,
) fsm.State {
	logger.Printf("ACTION ip=%s %s->%s dry_run=%v", net.IP(ip[:]).String(), st.Level, target, a.dryRun)
	if !a.dryRun && a.maps != nil {
		krl := shieldclient.Src6Key{IP: ip}
		kd := shieldclient.Key6Bytes{IP: ip}

		switch target {
		case fsm.LevelObserve:
			if a.maps.RL6 != nil {
				_ = a.maps.RL6.Delete(&krl)
			}
			if a.maps.Deny6 != nil {
				_ = a.maps.Deny6.Delete(&kd)
			}
		case fsm.LevelSoft:
			if a.maps.Deny6 != nil {
				_ = a.maps.Deny6.Delete(&kd)
			}
			if a.maps.RL6 != nil {
				val := shieldclient.RLConfig{RatePPS: p.SoftRate, Burst: p.SoftBurst}
				_ = a.maps.RL6.Update(&krl, &val, ebpf.UpdateAny)
			}
		case fsm.LevelHard:
			if a.maps.Deny6 != nil {
				_ = a.maps.Deny6.Delete(&kd)
			}
			if a.maps.RL6 != nil {
				val := shieldclient.RLConfig{RatePPS: p.HardRate, Burst: p.HardBurst}
				_ = a.maps.RL6.Update(&krl, &val, ebpf.UpdateAny)
			}
		case fsm.LevelBlock:
			if a.maps.RL6 != nil {
				_ = a.maps.RL6.Delete(&krl)
			}
			if a.maps.Deny6 != nil {
				v := uint8(1)
				_ = a.maps.Deny6.Update(&kd, &v, ebpf.UpdateAny)
			}
		}
	}

	return applyStateFields(st, target, now, p)
}

/* ---------------- Tuple (edge) enforcement -------------------------------- */

// DenyEdge4 inserts an edge4_deny entry so XDP drops all future packets
// matching (srcIP, dstPort, proto) before they reach userspace.
// Returns ErrTupleUnavailable when the Shield BPF version does not have
// edge maps (run `klshield attach-xdp` with the new .bpf.o to activate).
func (a *Adapter) DenyEdge4(key shieldclient.Edge4Key) error {
	if a.dryRun {
		logger.Printf("[dry-run] DenyEdge4 src=%v port=%d proto=%d", key.SrcIP, key.DstPort, key.Proto)
		return nil
	}
	if a.maps.Edge4Deny == nil {
		return ErrTupleUnavailable
	}
	return a.maps.WriteEdge4Deny(key)
}

// RevokeEdgeDeny4 removes an edge4_deny entry — the XDP deny is lifted.
func (a *Adapter) RevokeEdgeDeny4(key shieldclient.Edge4Key) error {
	if a.dryRun || a.maps.Edge4Deny == nil {
		return nil
	}
	return a.maps.DeleteEdge4Deny(key)
}

// RateLimitEdge4 installs a per-edge XDP token-bucket rate limit.
func (a *Adapter) RateLimitEdge4(key shieldclient.Edge4Key, ratePPS, burst uint64) error {
	if a.dryRun {
		logger.Printf("[dry-run] RateLimitEdge4 src=%v port=%d proto=%d rate=%d burst=%d",
			key.SrcIP, key.DstPort, key.Proto, ratePPS, burst)
		return nil
	}
	if a.maps.Edge4RL == nil {
		return ErrTupleUnavailable
	}
	return a.maps.WriteEdge4RL(key, ratePPS, burst)
}

// RevokeEdgeRL4 removes a per-edge rate-limit entry.
func (a *Adapter) RevokeEdgeRL4(key shieldclient.Edge4Key) error {
	if a.dryRun || a.maps.Edge4RL == nil {
		return nil
	}
	return a.maps.DeleteEdge4RL(key)
}

// SetTupleEnforce enables deny-mode or disables XDP tuple enforcement.
func (a *Adapter) SetTupleEnforce(on bool) error {
	if a.dryRun {
		logger.Printf("[dry-run] SetTupleEnforce on=%v", on)
		return nil
	}
	return a.maps.SetTupleEnforce(on)
}

// SetTupleAllowMode switches XDP to allow-mode (default-deny).
// Call only AFTER AllowEdge4 has been called for all frozen/approved edges,
// otherwise legitimate traffic is blocked immediately.
func (a *Adapter) SetTupleAllowMode() error {
	if a.dryRun {
		logger.Printf("[dry-run] SetTupleAllowMode")
		return nil
	}
	return a.maps.SetTupleMode(shieldclient.TupleModeAllow)
}

// AllowEdge4 inserts a tuple into the XDP allowlist (edge4_allow).
// Must be called for every frozen/approved graph edge before activating
// allow-mode so legitimate traffic is not blocked.
func (a *Adapter) AllowEdge4(key shieldclient.Edge4Key) error {
	if a.dryRun {
		logger.Printf("[dry-run] AllowEdge4 src=%v port=%d proto=%d", key.SrcIP, key.DstPort, key.Proto)
		return nil
	}
	if a.maps.Edge4Allow == nil {
		return ErrTupleUnavailable
	}
	return a.maps.WriteEdge4Allow(key)
}

// RevokeEdgeAllow4 removes a tuple from the XDP allowlist.
func (a *Adapter) RevokeEdgeAllow4(key shieldclient.Edge4Key) error {
	if a.dryRun || a.maps.Edge4Allow == nil {
		return nil
	}
	return a.maps.DeleteEdge4Allow(key)
}

// TupleAvailable reports whether the edge maps are present (Shield reloaded
// with XDP tuple support).
func (a *Adapter) TupleAvailable() bool {
	return a.maps.Edge4Deny != nil && a.maps.Edge4RL != nil
}

// ErrTupleUnavailable is returned when edge maps are not present.
// Solution: reload klshield with the new .bpf.o that includes edge maps.
var ErrTupleUnavailable = fmt.Errorf(
	"XDP tuple maps not available — reload klshield: klshield attach-xdp --force")

// applyStateFields sets Level, CooldownUntil and ExpiresAt on the state after a transition.
func applyStateFields(st fsm.State, target fsm.Level, now time.Time, p EnforcementParams) fsm.State {
	st.Level = target
	st.CooldownUntil = now.Add(p.Cooldown)
	switch target {
	case fsm.LevelObserve:
		st.ExpiresAt = time.Time{}
	case fsm.LevelSoft:
		st.ExpiresAt = now.Add(p.SoftTTL)
	case fsm.LevelHard:
		st.ExpiresAt = now.Add(p.HardTTL)
	case fsm.LevelBlock:
		st.ExpiresAt = now.Add(p.BlockTTL)
	}
	return st
}
