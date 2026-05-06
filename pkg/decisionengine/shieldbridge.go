// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package decisionengine

import (
	"context"
	"fmt"
	"net"

	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldpep"
	"github.com/adrianenderlin/kernloom/pkg/core/decision"
	"github.com/adrianenderlin/kernloom/pkg/shieldclient"
	"github.com/cilium/ebpf"
)

// ShieldBridge implements PEPAdapter backed by the Shield eBPF PEP.
// It translates Decision actions to direct eBPF map writes for signal-driven
// enforcement. The heuristic FSM still uses shieldpep.Adapter.TransitionV4/V6
// directly — this bridge handles the signal path only.
type ShieldBridge struct {
	maps   *shieldclient.Maps
	dryRun bool
	nodeID string
	params shieldpep.EnforcementParams
}

// NewShieldBridge constructs a ShieldBridge.
func NewShieldBridge(maps *shieldclient.Maps, dryRun bool, nodeID string, params shieldpep.EnforcementParams) *ShieldBridge {
	return &ShieldBridge{
		maps:   maps,
		dryRun: dryRun,
		nodeID: nodeID,
		params: params,
	}
}

// EnforceDecision applies dec to the Shield eBPF maps and returns a receipt.
func (b *ShieldBridge) EnforceDecision(ctx context.Context, dec *decision.Decision) (*decision.EnforcementReceipt, error) {
	const adapterID = "shield-bridge"

	ip := net.ParseIP(dec.Subject.ID)
	if ip == nil {
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusFailed)
		r.SetMessage(fmt.Sprintf("cannot parse IP from subject %q", dec.Subject.ID))
		return r, nil
	}

	if b.dryRun {
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusDryRun)
		r.SetMessage("dry-run mode; no map write performed")
		return r, nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		return b.enforceV4(dec, [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}, adapterID)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusFailed)
		r.SetMessage(fmt.Sprintf("subject %q is not a valid IPv4 or IPv6 address", dec.Subject.ID))
		return r, nil
	}
	var arr [16]byte
	copy(arr[:], ip16)
	return b.enforceV6(dec, arr, adapterID)
}

func (b *ShieldBridge) enforceV4(dec *decision.Decision, ip [4]byte, adapterID string) (*decision.EnforcementReceipt, error) {
	var mapErr error

	switch dec.Action.Type {
	case decision.ActionBlock:
		if b.maps.RL4 != nil {
			_ = b.maps.RL4.Delete(&ip)
		}
		if b.maps.Deny4 != nil {
			v := uint8(1)
			mapErr = b.maps.Deny4.Update(&ip, &v, ebpf.UpdateAny)
		}

	case decision.ActionRateLimit:
		if b.maps.Deny4 != nil {
			_ = b.maps.Deny4.Delete(&ip)
		}
		if b.maps.RL4 != nil {
			val := shieldclient.RLConfig{RatePPS: b.params.SoftRate, Burst: b.params.SoftBurst}
			mapErr = b.maps.RL4.Update(&ip, &val, ebpf.UpdateAny)
		}

	case decision.ActionObserve, decision.ActionAllow:
		if b.maps.Deny4 != nil {
			_ = b.maps.Deny4.Delete(&ip)
		}
		if b.maps.RL4 != nil {
			_ = b.maps.RL4.Delete(&ip)
		}

	default:
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusUnsupported)
		r.SetMessage(fmt.Sprintf("action %q not supported by shield-bridge", dec.Action.Type))
		return r, nil
	}

	if mapErr != nil {
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusFailed)
		r.SetMessage(fmt.Sprintf("eBPF map write failed: %v", mapErr))
		return r, nil
	}

	return decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusApplied), nil
}

func (b *ShieldBridge) enforceV6(dec *decision.Decision, ip [16]byte, adapterID string) (*decision.EnforcementReceipt, error) {
	krl := shieldclient.Src6Key{IP: ip}
	kd := shieldclient.Key6Bytes{IP: ip}

	var mapErr error

	switch dec.Action.Type {
	case decision.ActionBlock:
		if b.maps.RL6 != nil {
			_ = b.maps.RL6.Delete(&krl)
		}
		if b.maps.Deny6 != nil {
			v := uint8(1)
			mapErr = b.maps.Deny6.Update(&kd, &v, ebpf.UpdateAny)
		}

	case decision.ActionRateLimit:
		if b.maps.Deny6 != nil {
			_ = b.maps.Deny6.Delete(&kd)
		}
		if b.maps.RL6 != nil {
			val := shieldclient.RLConfig{RatePPS: b.params.SoftRate, Burst: b.params.SoftBurst}
			mapErr = b.maps.RL6.Update(&krl, &val, ebpf.UpdateAny)
		}

	case decision.ActionObserve, decision.ActionAllow:
		if b.maps.Deny6 != nil {
			_ = b.maps.Deny6.Delete(&kd)
		}
		if b.maps.RL6 != nil {
			_ = b.maps.RL6.Delete(&krl)
		}

	default:
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusUnsupported)
		r.SetMessage(fmt.Sprintf("action %q not supported by shield-bridge", dec.Action.Type))
		return r, nil
	}

	if mapErr != nil {
		r := decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusFailed)
		r.SetMessage(fmt.Sprintf("eBPF map write failed: %v", mapErr))
		return r, nil
	}

	return decision.NewEnforcementReceipt(dec.ID, b.nodeID, adapterID, decision.StatusApplied), nil
}
