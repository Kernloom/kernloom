// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package conformance validates Forge/KLIQ runtime contract fixtures before a
// node treats a signed Forge artifact as activatable.
package conformance

import (
	"crypto/ed25519"
	"fmt"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
)

type NodeRuntime struct {
	NodeID            string
	Capabilities      map[string]bool
	MaxAction         string
	SupportedPDPModes map[string]bool
	Now               time.Time
}

func ValidateRuntimeBundle(bundle contracts.RuntimeBundle, pubKey ed25519.PublicKey, node NodeRuntime) error {
	now := node.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := contracts.VerifyRuntimeBundle(bundle, pubKey, now); err != nil {
		return err
	}
	if node.NodeID != "" && bundle.Metadata.NodeID != node.NodeID {
		return fmt.Errorf("runtime bundle node_id %q does not match node %q", bundle.Metadata.NodeID, node.NodeID)
	}
	if mode := bundle.Spec.RuntimePDPProfile.Mode; mode != "" && len(node.SupportedPDPModes) > 0 && !node.SupportedPDPModes[mode] {
		return fmt.Errorf("runtime PDP mode %q is not supported", mode)
	}
	return ValidateRuntimePolicyPack(bundle.Spec.RuntimePolicyPack, node)
}

func ValidateRuntimePolicyPack(pack contracts.RuntimePolicyPack, node NodeRuntime) error {
	if _, err := runtimepdp.Compile(pack); err != nil {
		return err
	}
	for _, cap := range runtimePolicyCapabilities(pack) {
		if len(node.Capabilities) > 0 && !node.Capabilities[cap] {
			return fmt.Errorf("required capability %q is unavailable", cap)
		}
		if _, ok := capabilitySeverity[cap]; !ok {
			return fmt.Errorf("runtime action capability %q is not supported", cap)
		}
	}
	maxAllowed := maxActionSeverity(node.MaxAction)
	for _, rule := range pack.Spec.Rules {
		sev := runtimeActionSeverity(rule.Then)
		if sev > maxAllowed {
			return fmt.Errorf("runtime action %q level %q exceeds node max_action %q", rule.Then.Capability, rule.Then.Level, node.MaxAction)
		}
	}
	return nil
}

func ValidateOfflineLastKnownGood(bundle contracts.RuntimeBundle, pubKey ed25519.PublicKey, node NodeRuntime) error {
	if err := ValidateRuntimeBundle(bundle, pubKey, node); err != nil {
		return err
	}
	if bundle.Spec.Failover.Behavior != "fail_static" {
		return fmt.Errorf("offline LKG requires failover.behavior=fail_static, got %q", bundle.Spec.Failover.Behavior)
	}
	return nil
}

func runtimePolicyCapabilities(pack contracts.RuntimePolicyPack) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(cap string) {
		if cap == "" || seen[cap] {
			return
		}
		seen[cap] = true
		out = append(out, cap)
	}
	for _, cap := range pack.Spec.CapabilitiesRequired {
		add(cap)
	}
	for _, rule := range pack.Spec.Rules {
		add(rule.Then.Capability)
	}
	return out
}

func runtimeActionSeverity(action contracts.RuntimeActionSpec) int {
	sev := capabilitySeverity[action.Capability]
	switch action.Level {
	case "block":
		sev = 3
	case "hard":
		if sev < 2 {
			sev = 2
		}
	case "soft":
		if sev < 1 {
			sev = 1
		}
	}
	return sev
}

func maxActionSeverity(maxAction string) int {
	switch maxAction {
	case "observe":
		return 0
	case "rate_limit":
		return 1
	case "rate_limit_hard":
		return 2
	default:
		return 3
	}
}

var capabilitySeverity = map[string]int{
	"enforce.access.allow": 0,

	"enforce.traffic.rate_limit":       1,
	"enforce.traffic.connection_limit": 1,
	"enforce.traffic.bandwidth_limit":  1,
	"enforce.network.rate_limit":       1,
	"enforce.network.syn_protect":      1,

	"enforce.traffic.tarpit": 2,

	"enforce.access.deny":          3,
	"enforce.access.default_deny":  3,
	"enforce.traffic.drop":         3,
	"enforce.traffic.quarantine":   3,
	"enforce.network.deny":         3,
	"enforce.network.default_deny": 3,
	"enforce.network.quarantine":   3,
}
