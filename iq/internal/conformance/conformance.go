// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package conformance validates Forge/KLIQ runtime contract fixtures before a
// node treats a signed Forge artifact as activatable.
package conformance

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"
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
	if err := validateRuntimeActions(pack, node.RegistrySnapshot); err != nil {
		return err
	}
	if err := validateResponseRules(pack, node.RegistrySnapshot); err != nil {
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
	for _, rule := range runtimepdp.EffectiveRules(pack) {
		sev := runtimeActionSeverity(rule.Then, severities, levels)
		if sev > maxAllowed {
			return fmt.Errorf("runtime action %q level %q exceeds node max_action %q", rule.Then.Capability, rule.Then.Level, node.MaxAction)
		}
	}
	return nil
}

func validateRuntimeActions(pack contracts.RuntimePolicyPack, snapshot contracts.RegistrySnapshot) error {
	capabilities := capabilityEntries(snapshot)
	contractsByID := actionContracts(snapshot)
	for _, rule := range runtimepdp.EffectiveRules(pack) {
		if err := validateRuntimeActionSpec(rule.Then, capabilities, contractsByID); err != nil {
			return fmt.Errorf("runtime rule %q: %w", rule.ID, err)
		}
	}
	return nil
}

func validateRuntimeActionSpec(action contracts.RuntimeActionSpec, capabilities map[string]contracts.CapabilityEntry, contractsByID map[string]contracts.RuntimeActionContractEntry) error {
	if strings.TrimSpace(action.Capability) == "" {
		return fmt.Errorf("action capability is required")
	}
	capability, ok := capabilities[action.Capability]
	if !ok {
		return fmt.Errorf("unknown runtime action capability %q", action.Capability)
	}
	if !capability.RuntimeAction {
		return fmt.Errorf("capability %q is not a runtime action", action.Capability)
	}
	if capability.Effect == "grant" {
		return fmt.Errorf("capability %q grants access and is not allowed in runtime packs", action.Capability)
	}
	contractID := capability.ActionContract
	if contractID == "" {
		contractID = action.Capability
	}
	contract, ok := contractsByID[contractID]
	if !ok {
		return fmt.Errorf("capability %q references unknown action contract %q", action.Capability, contractID)
	}
	if !contract.RuntimeAllowed {
		return fmt.Errorf("action contract %q is not runtime allowed", contract.ID)
	}
	if contract.CanGrantAccess {
		return fmt.Errorf("action contract %q can grant access and is not allowed in runtime packs", contract.ID)
	}
	if contract.RequiresTTL && action.TTL.Duration <= 0 {
		return fmt.Errorf("action contract %q requires ttl", contract.ID)
	}
	if maxTTL, err := parseOptionalDuration(contract.MaxTTL); err != nil {
		return fmt.Errorf("action contract %q maxTTL: %w", contract.ID, err)
	} else if maxTTL > 0 && action.TTL.Duration > maxTTL {
		return fmt.Errorf("action contract %q ttl %s exceeds maxTTL %s", contract.ID, action.TTL.Duration, maxTTL)
	}
	return nil
}

func validateResponseRules(pack contracts.RuntimePolicyPack, snapshot contracts.RegistrySnapshot) error {
	detections := map[string]bool{}
	for _, detection := range pack.Spec.DetectionRules {
		if detection.ID == "" {
			return fmt.Errorf("detection rule id is required")
		}
		if detections[detection.ID] {
			return fmt.Errorf("duplicate detection rule %q", detection.ID)
		}
		detections[detection.ID] = true
	}
	routes := map[string]contracts.RuntimeAlertRoute{}
	for _, route := range pack.Spec.AlertRoutes {
		if route.ID == "" {
			return fmt.Errorf("alert route id is required")
		}
		if _, exists := routes[route.ID]; exists {
			return fmt.Errorf("duplicate alert route %q", route.ID)
		}
		routes[route.ID] = route
	}

	capabilities := capabilityEntries(snapshot)
	contractsByID := actionContracts(snapshot)
	responseIDs := map[string]bool{}
	for _, response := range pack.Spec.ResponseRules {
		if response.ID == "" {
			return fmt.Errorf("response rule id is required")
		}
		if responseIDs[response.ID] {
			return fmt.Errorf("duplicate response rule %q", response.ID)
		}
		responseIDs[response.ID] = true
		if response.When.Detection != "" && !detectionExists(response.When.Detection, detections) {
			return fmt.Errorf("response rule %q references unknown detection %q", response.ID, response.When.Detection)
		}
		if len(response.Then) == 0 {
			return fmt.Errorf("response rule %q has no actions", response.ID)
		}
		for i, action := range response.Then {
			if err := validateResponseAction(action, routes, capabilities, contractsByID); err != nil {
				return fmt.Errorf("response rule %q action[%d]: %w", response.ID, i, err)
			}
		}
	}
	return nil
}

func validateResponseAction(
	action contracts.RuntimeResponseAction,
	routes map[string]contracts.RuntimeAlertRoute,
	capabilities map[string]contracts.CapabilityEntry,
	contractsByID map[string]contracts.RuntimeActionContractEntry,
) error {
	if strings.TrimSpace(action.ID) == "" {
		return fmt.Errorf("id is required")
	}
	capability, hasCapability := capabilities[action.ID]
	contract, hasContract := contractsByID[action.ID]
	if !hasCapability && !hasContract {
		return fmt.Errorf("unknown response action %q", action.ID)
	}
	if action.ID == "notify.alert.emit" {
		route, ok := routes[action.Route]
		if action.Route == "" || !ok {
			return fmt.Errorf("notify.alert.emit references unknown alert route %q", action.Route)
		}
		if action.Severity != "" && !validSeverity(action.Severity) {
			return fmt.Errorf("notify.alert.emit has unsupported severity %q", action.Severity)
		}
		if action.Dedupe.Duration <= 0 && route.Deduplication.Window.Duration <= 0 {
			return fmt.Errorf("notify.alert.emit requires action dedupe or route deduplication.window")
		}
		return nil
	}
	if hasCapability && capability.Effect == "grant" {
		return fmt.Errorf("action %q grants access and is not allowed in runtime response", action.ID)
	}
	if hasContract {
		if contract.CanGrantAccess {
			return fmt.Errorf("action %q can grant access and is not allowed in runtime response", action.ID)
		}
		effect := contract.Effect
		if effect == "" && hasCapability {
			effect = capability.Effect
		}
		if effect != "restrictive" {
			return nil
		}
		if !contract.RuntimeAllowed {
			return fmt.Errorf("action %q is not runtime allowed", action.ID)
		}
		if contract.RequiresTTL && action.TTL.Duration <= 0 {
			return fmt.Errorf("action %q requires ttl", action.ID)
		}
		if maxTTL, err := parseOptionalDuration(contract.MaxTTL); err != nil {
			return fmt.Errorf("action %q maxTTL: %w", action.ID, err)
		} else if maxTTL > 0 && action.TTL.Duration > maxTTL {
			return fmt.Errorf("action %q ttl %s exceeds maxTTL %s", action.ID, action.TTL.Duration, maxTTL)
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
	for _, rule := range runtimepdp.EffectiveRules(pack) {
		add(rule.Then.Capability)
	}
	for _, response := range pack.Spec.ResponseRules {
		for _, action := range response.Then {
			if strings.HasPrefix(action.ID, "enforce.") {
				add(action.ID)
			}
		}
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

func capabilityEntries(snapshot contracts.RegistrySnapshot) map[string]contracts.CapabilityEntry {
	out := make(map[string]contracts.CapabilityEntry, len(snapshot.Capabilities))
	for _, capability := range snapshot.Capabilities {
		out[capability.ID] = capability
	}
	return out
}

func actionContracts(snapshot contracts.RegistrySnapshot) map[string]contracts.RuntimeActionContractEntry {
	out := make(map[string]contracts.RuntimeActionContractEntry, len(snapshot.ActionContracts))
	for _, contract := range snapshot.ActionContracts {
		out[contract.ID] = contract
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
	for _, rule := range runtimepdp.EffectiveRules(pack) {
		for _, match := range runtimeContextRef.FindAllStringSubmatch(rule.When, -1) {
			key := match[1]
			if !known[key] {
				return fmt.Errorf("runtime rule %q references unknown context key %q", rule.ID, key)
			}
		}
	}
	return nil
}

func detectionExists(ref string, detections map[string]bool) bool {
	if detections[ref] {
		return true
	}
	for id := range detections {
		if strings.HasSuffix(ref, "/"+id) {
			return true
		}
	}
	return false
}

func validSeverity(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func parseOptionalDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}
