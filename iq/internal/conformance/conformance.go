// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package conformance validates Forge/KLIQ runtime contract fixtures before a
// node treats a signed Forge artifact as activatable.
package conformance

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
)

type NodeRuntime struct {
	NodeID            string
	Capabilities      map[string]bool
	MaxAction         string
	SupportedPDPModes map[string]bool
	RegistrySnapshot  contracts.RegistrySnapshot
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
	if bundle.Spec.RegistrySnapshot.Ref.Name == "" {
		return fmt.Errorf("runtime bundle registry snapshot is required")
	}
	node.RegistrySnapshot = bundle.Spec.RegistrySnapshot
	return ValidateRuntimePolicyPack(bundle.Spec.RuntimePolicyPack, node)
}

func ValidateRuntimePolicyPack(pack contracts.RuntimePolicyPack, node NodeRuntime) error {
	if node.RegistrySnapshot.Ref.Name == "" {
		return fmt.Errorf("registry snapshot is required")
	}
	if _, err := runtimepdp.Compile(pack); err != nil {
		return err
	}
	if err := validateKnownContextRefs(pack, node.RegistrySnapshot); err != nil {
		return err
	}
	severities := capabilitySeverities(node.RegistrySnapshot)
	levels := actionLevels(node.RegistrySnapshot)
	for _, cap := range runtimePolicyCapabilities(pack) {
		if len(node.Capabilities) > 0 && !node.Capabilities[cap] {
			return fmt.Errorf("required capability %q is unavailable", cap)
		}
		if _, ok := severities[cap]; !ok {
			return fmt.Errorf("runtime action capability %q is not supported", cap)
		}
	}
	maxAllowed := maxActionSeverity(node.MaxAction, levels)
	for _, rule := range pack.Spec.Rules {
		sev := runtimeActionSeverity(rule.Then, severities, levels)
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

func runtimeActionSeverity(action contracts.RuntimeActionSpec, severities map[string]int, levels map[string]int) int {
	sev := severities[action.Capability]
	if action.Level != "" {
		if levelSeverity, ok := levels[action.Level]; ok && sev < levelSeverity {
			sev = levelSeverity
		}
	}
	return sev
}

func maxActionSeverity(maxAction string, levels map[string]int) int {
	if sev, ok := levels[maxAction]; ok {
		return sev
	}
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

func capabilitySeverities(snapshot contracts.RegistrySnapshot) map[string]int {
	out := make(map[string]int, len(snapshot.Capabilities))
	for _, cap := range snapshot.Capabilities {
		if cap.RuntimeAction {
			out[cap.ID] = cap.Severity
		}
	}
	return out
}

func actionLevels(snapshot contracts.RegistrySnapshot) map[string]int {
	out := make(map[string]int, len(snapshot.ActionLevels))
	for _, level := range snapshot.ActionLevels {
		out[level.ID] = level.MaxSeverity
	}
	return out
}

var runtimeContextRef = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.])((?:subject|device|session|resource|environment|workload|network)\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)`)

func validateKnownContextRefs(pack contracts.RuntimePolicyPack, snapshot contracts.RegistrySnapshot) error {
	known := make(map[string]bool, len(snapshot.ContextKeys))
	for _, key := range snapshot.ContextKeys {
		known[key.ID] = true
	}
	for _, rule := range pack.Spec.Rules {
		for _, match := range runtimeContextRef.FindAllStringSubmatch(rule.When, -1) {
			key := match[1]
			if !known[key] {
				return fmt.Errorf("runtime rule %q references unknown context key %q", rule.ID, key)
			}
		}
	}
	return nil
}
