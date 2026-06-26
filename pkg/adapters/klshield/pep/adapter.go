// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package shieldpep implements the Shield PEP (Policy Enforcement Point) adapter.
// It applies L3/L4 enforcement decisions by writing into the pinned eBPF maps
// exposed by Kernloom Shield.
package shieldpep

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	"github.com/kernloom/kernloom/pkg/core/capability"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

var logger = log.New(os.Stderr, "[shield-pep] ", log.LstdFlags)

// EnforcementParams carries the per-level rate-limit and timing configuration
// needed by the PEP adapter when transitioning a source to a new level.
type EnforcementParams = adapterruntime.EnforcementParams

// Adapter is the Shield PEP adapter.
// It is intentionally synchronous: enforcement calls are made inline from the
// generic source PEP boundary, not via the event bus.
type Adapter struct {
	maps   *shieldclient.Maps
	dryRun bool

	accessMu       sync.Mutex
	accessPolicies map[string]contracts.RuntimeAccessPolicy

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
		adapterruntime.WellKnownAccessPolicyApply(),
		adapterruntime.WellKnownAccessPolicyDrift(),
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

// TransitionSource applies the enforcement action for an adapter-owned source.
// KLShield treats SourceID as an IP address; that interpretation stays here
// rather than leaking into the generic orchestrator.
func (a *Adapter) TransitionSource(
	target adapterruntime.SourceTarget, st fsm.State, level fsm.Level,
	now time.Time, p EnforcementParams,
) (fsm.State, error) {
	id := target.SourceID
	if id == "" {
		id = target.Subject.ID
	}
	ip := net.ParseIP(id)
	if ip == nil {
		return st, fmt.Errorf("klshield source target %q is not an IP address", id)
	}
	if v4 := ip.To4(); v4 != nil {
		var key [4]byte
		copy(key[:], v4)
		return a.transitionV4(key, st, level, now, p)
	}
	if v6 := ip.To16(); v6 != nil {
		var key [16]byte
		copy(key[:], v6)
		return a.transitionV6(key, st, level, now, p)
	}
	return st, fmt.Errorf("klshield source target %q has unsupported IP representation", id)
}

// transitionV4 applies the enforcement action for an IPv4 source.
// It writes into the Shield deny / rl-policy maps (unless dryRun is set) and
// returns the updated fsm.State with Level, ExpiresAt and CooldownUntil set.
func (a *Adapter) transitionV4(
	ip [4]byte, st fsm.State, target fsm.Level,
	now time.Time, p EnforcementParams,
) (fsm.State, error) {
	ipString := net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
	logger.Printf("ACTION ip=%s %s->%s dry_run=%v %s", ipString, st.Level, target, a.dryRun, actionParamSummary(target, p))
	if !a.dryRun && a.maps != nil {
		switch target {
		case fsm.LevelObserve:
			if a.maps.RL4 != nil {
				if err := ignoreMissing(a.maps.RL4.Delete(&ip)); err != nil {
					return st, fmt.Errorf("delete v4 rate-limit %s: %w", ipString, err)
				}
			}
			if a.maps.Deny4 != nil {
				if err := ignoreMissing(a.maps.Deny4.Delete(&ip)); err != nil {
					return st, fmt.Errorf("delete v4 deny %s: %w", ipString, err)
				}
			}
		case fsm.LevelSoft:
			if a.maps.Deny4 != nil {
				if err := ignoreMissing(a.maps.Deny4.Delete(&ip)); err != nil {
					return st, fmt.Errorf("delete v4 deny %s: %w", ipString, err)
				}
			}
			if a.maps.RL4 != nil {
				val := shieldclient.RLConfig{RatePPS: p.SoftRate, Burst: p.SoftBurst}
				if err := a.maps.RL4.Update(&ip, &val, ebpf.UpdateAny); err != nil {
					return st, fmt.Errorf("update v4 rate-limit %s rate=%d burst=%d: %w", ipString, val.RatePPS, val.Burst, err)
				}
			} else {
				return st, fmt.Errorf("v4 rate-limit map unavailable")
			}
		case fsm.LevelHard:
			if a.maps.Deny4 != nil {
				if err := ignoreMissing(a.maps.Deny4.Delete(&ip)); err != nil {
					return st, fmt.Errorf("delete v4 deny %s: %w", ipString, err)
				}
			}
			if a.maps.RL4 != nil {
				val := shieldclient.RLConfig{RatePPS: p.HardRate, Burst: p.HardBurst}
				if err := a.maps.RL4.Update(&ip, &val, ebpf.UpdateAny); err != nil {
					return st, fmt.Errorf("update v4 rate-limit %s rate=%d burst=%d: %w", ipString, val.RatePPS, val.Burst, err)
				}
			} else {
				return st, fmt.Errorf("v4 rate-limit map unavailable")
			}
		case fsm.LevelBlock:
			if a.maps.RL4 != nil {
				if err := ignoreMissing(a.maps.RL4.Delete(&ip)); err != nil {
					return st, fmt.Errorf("delete v4 rate-limit %s: %w", ipString, err)
				}
			}
			if a.maps.Deny4 != nil {
				v := uint8(1)
				if err := a.maps.Deny4.Update(&ip, &v, ebpf.UpdateAny); err != nil {
					return st, fmt.Errorf("update v4 deny %s: %w", ipString, err)
				}
			} else {
				return st, fmt.Errorf("v4 deny map unavailable")
			}
		}
	} else if !a.dryRun && a.maps == nil {
		return st, fmt.Errorf("klshield maps unavailable")
	}

	return applyStateFields(st, target, now, p), nil
}

// transitionV6 applies the enforcement action for an IPv6 source.
func (a *Adapter) transitionV6(
	ip [16]byte, st fsm.State, target fsm.Level,
	now time.Time, p EnforcementParams,
) (fsm.State, error) {
	ipString := net.IP(ip[:]).String()
	logger.Printf("ACTION ip=%s %s->%s dry_run=%v %s", ipString, st.Level, target, a.dryRun, actionParamSummary(target, p))
	if !a.dryRun && a.maps != nil {
		krl := shieldclient.Src6Key{IP: ip}
		kd := shieldclient.Key6Bytes{IP: ip}

		switch target {
		case fsm.LevelObserve:
			if a.maps.RL6 != nil {
				if err := ignoreMissing(a.maps.RL6.Delete(&krl)); err != nil {
					return st, fmt.Errorf("delete v6 rate-limit %s: %w", ipString, err)
				}
			}
			if a.maps.Deny6 != nil {
				if err := ignoreMissing(a.maps.Deny6.Delete(&kd)); err != nil {
					return st, fmt.Errorf("delete v6 deny %s: %w", ipString, err)
				}
			}
		case fsm.LevelSoft:
			if a.maps.Deny6 != nil {
				if err := ignoreMissing(a.maps.Deny6.Delete(&kd)); err != nil {
					return st, fmt.Errorf("delete v6 deny %s: %w", ipString, err)
				}
			}
			if a.maps.RL6 != nil {
				val := shieldclient.RLConfig{RatePPS: p.SoftRate, Burst: p.SoftBurst}
				if err := a.maps.RL6.Update(&krl, &val, ebpf.UpdateAny); err != nil {
					return st, fmt.Errorf("update v6 rate-limit %s rate=%d burst=%d: %w", ipString, val.RatePPS, val.Burst, err)
				}
			} else {
				return st, fmt.Errorf("v6 rate-limit map unavailable")
			}
		case fsm.LevelHard:
			if a.maps.Deny6 != nil {
				if err := ignoreMissing(a.maps.Deny6.Delete(&kd)); err != nil {
					return st, fmt.Errorf("delete v6 deny %s: %w", ipString, err)
				}
			}
			if a.maps.RL6 != nil {
				val := shieldclient.RLConfig{RatePPS: p.HardRate, Burst: p.HardBurst}
				if err := a.maps.RL6.Update(&krl, &val, ebpf.UpdateAny); err != nil {
					return st, fmt.Errorf("update v6 rate-limit %s rate=%d burst=%d: %w", ipString, val.RatePPS, val.Burst, err)
				}
			} else {
				return st, fmt.Errorf("v6 rate-limit map unavailable")
			}
		case fsm.LevelBlock:
			if a.maps.RL6 != nil {
				if err := ignoreMissing(a.maps.RL6.Delete(&krl)); err != nil {
					return st, fmt.Errorf("delete v6 rate-limit %s: %w", ipString, err)
				}
			}
			if a.maps.Deny6 != nil {
				v := uint8(1)
				if err := a.maps.Deny6.Update(&kd, &v, ebpf.UpdateAny); err != nil {
					return st, fmt.Errorf("update v6 deny %s: %w", ipString, err)
				}
			} else {
				return st, fmt.Errorf("v6 deny map unavailable")
			}
		}
	} else if !a.dryRun && a.maps == nil {
		return st, fmt.Errorf("klshield maps unavailable")
	}

	return applyStateFields(st, target, now, p), nil
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

// RelationshipAvailable reports whether relationship enforcement maps are present.
func (a *Adapter) RelationshipAvailable() bool {
	return a.TupleAvailable()
}

// SetRelationshipEnforcement enables or disables relationship enforcement.
func (a *Adapter) SetRelationshipEnforcement(on bool) error {
	return a.SetTupleEnforce(on)
}

// DenyRelationship denies an adapter-neutral relationship target.
func (a *Adapter) DenyRelationship(target adapterruntime.RelationshipTarget) error {
	port, proto, ok := klshieldRelationshipDimension(target)
	if !ok {
		return fmt.Errorf("invalid klshield relationship target %s", target.Canonical())
	}
	key, ok := shieldclient.NewEdge4Key(target.SubjectID, port, proto)
	if !ok {
		return fmt.Errorf("invalid klshield relationship target %s", target.Canonical())
	}
	return a.DenyEdge4(key)
}

// AllowRelationship allowlists an adapter-neutral relationship target.
func (a *Adapter) AllowRelationship(target adapterruntime.RelationshipTarget) error {
	port, proto, ok := klshieldRelationshipDimension(target)
	if !ok {
		return fmt.Errorf("invalid klshield relationship target %s", target.Canonical())
	}
	key, ok := shieldclient.NewEdge4Key(target.SubjectID, port, proto)
	if !ok {
		return fmt.Errorf("invalid klshield relationship target %s", target.Canonical())
	}
	return a.AllowEdge4(key)
}

func (a *Adapter) ApplyAccessPolicy(ctx context.Context, policy contracts.RuntimeAccessPolicy, opts adapterruntime.AccessPolicyApplyOptions) (adapterruntime.AccessPolicyApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return adapterruntime.AccessPolicyApplyResult{}, err
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	id := strings.TrimSpace(policy.ID)
	if id == "" {
		return adapterruntime.AccessPolicyApplyResult{}, fmt.Errorf("runtime access policy has empty id")
	}
	a.accessMu.Lock()
	if a.accessPolicies == nil {
		a.accessPolicies = map[string]contracts.RuntimeAccessPolicy{}
	}
	a.accessPolicies[id] = policy
	a.accessMu.Unlock()

	mode := "recorded"
	if opts.DryRun || a.dryRun {
		mode = "dry_run"
	}
	msg := "klshield records access desired state for audit/drift; native group/resource access enforcement is not available"
	logger.Printf("ACCESS-POLICY apply id=%s subject=%s:%s resource=%s:%s effect=%s mode=%s native=false",
		id, policy.Subject.Type, policy.Subject.Ref, policy.Resource.Type, policy.Resource.Ref, policy.Effect, mode)
	return adapterruntime.AccessPolicyApplyResult{
		PolicyID:          id,
		AdapterID:         a.ID(),
		Status:            mode,
		Applied:           true,
		NativeEnforcement: false,
		Message:           msg,
		Warnings:          []string{"klshield_access_policy_audit_only"},
		AppliedAt:         now,
	}, nil
}

func (a *Adapter) CheckAccessPolicyDrift(ctx context.Context, policy contracts.RuntimeAccessPolicy) (adapterruntime.AccessPolicyDrift, error) {
	if err := ctx.Err(); err != nil {
		return adapterruntime.AccessPolicyDrift{}, err
	}
	id := strings.TrimSpace(policy.ID)
	if id == "" {
		return adapterruntime.AccessPolicyDrift{}, fmt.Errorf("runtime access policy has empty id")
	}
	a.accessMu.Lock()
	applied, ok := a.accessPolicies[id]
	a.accessMu.Unlock()
	drift := adapterruntime.AccessPolicyDrift{
		PolicyID:          id,
		AdapterID:         a.ID(),
		InSync:            true,
		NativeEnforcement: false,
		Reason:            "audit_only_native_enforcement_unavailable",
		CheckedAt:         time.Now().UTC(),
	}
	switch {
	case !ok:
		drift.InSync = false
		drift.Reason = "not_applied"
	case !reflect.DeepEqual(applied, policy):
		drift.InSync = false
		drift.Reason = "desired_state_changed"
	}
	return drift, nil
}

func klshieldRelationshipDimension(target adapterruntime.RelationshipTarget) (uint16, string, bool) {
	rawPort := target.Dimension["port"]
	if rawPort == "" {
		rawPort = target.Dimension["destination_port"]
	}
	proto := target.Dimension["proto"]
	if proto == "" {
		proto = target.Dimension["protocol"]
	}
	if rawPort == "" || proto == "" {
		return 0, "", false
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return 0, "", false
	}
	return uint16(port), proto, true
}

// ErrTupleUnavailable is returned when edge maps are not present.
// Solution: reload klshield with the new .bpf.o that includes edge maps.
var ErrTupleUnavailable = fmt.Errorf(
	"XDP tuple maps not available — reload klshield: klshield attach-xdp --force")

func ignoreMissing(err error) error {
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func actionParamSummary(level fsm.Level, p EnforcementParams) string {
	switch level {
	case fsm.LevelSoft:
		return fmt.Sprintf("rate_pps=%d burst=%d ttl=%s", p.SoftRate, p.SoftBurst, p.SoftTTL)
	case fsm.LevelHard:
		return fmt.Sprintf("rate_pps=%d burst=%d ttl=%s", p.HardRate, p.HardBurst, p.HardTTL)
	case fsm.LevelBlock:
		return fmt.Sprintf("ttl=%s", p.BlockTTL)
	default:
		return ""
	}
}

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
