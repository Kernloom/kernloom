// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package componentinventory

import "time"

// KliqConfigAssetReport summarises the security-relevant configuration of a
// running KLIQ instance. It is produced at startup, saved alongside the state
// file, and included in Forge enrollment/heartbeat payloads so that Forge can
// evaluate whether the node's configuration is compliant.
//
// Secret values (enrollment keys, certificate paths) are never included.
type KliqConfigAssetReport struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind"       yaml:"kind"`
	Metadata   struct {
		NodeID    string    `json:"node_id"   yaml:"node_id"`
		Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	} `json:"metadata" yaml:"metadata"`

	// Enforcement authority
	Mode                  string `json:"mode"                    yaml:"mode"`
	HasPolicyPack         bool   `json:"has_policy_pack"         yaml:"has_policy_pack"`
	PolicyMaxAction       string `json:"policy_max_action"       yaml:"policy_max_action"`
	AllowLocalBlock       bool   `json:"allow_local_block"       yaml:"allow_local_block"`
	DryRun                bool   `json:"dry_run"                 yaml:"dry_run"`
	AutonomousEnforcement bool   `json:"autonomous_enforcement"  yaml:"autonomous_enforcement"`
	PolicyAuthority       string `json:"policy_authority"        yaml:"policy_authority"` // "forge" or "local"

	// Allowed capabilities from the loaded pack (empty = no restriction)
	AllowedCapabilities []string `json:"allowed_capabilities,omitempty" yaml:"allowed_capabilities,omitempty"`

	// Rate enforcement mode and parameters.
	// EnforcementMode: "directive" (rate from policy pack) or "autonomy" (KLIQ decides).
	EnforcementMode string `json:"enforcement_mode" yaml:"enforcement_mode"`

	// Directive rates — only set when EnforcementMode == "directive".
	SoftDirectiveRatePPS uint64 `json:"soft_directive_rate_pps,omitempty" yaml:"soft_directive_rate_pps,omitempty"`
	HardDirectiveRatePPS uint64 `json:"hard_directive_rate_pps,omitempty" yaml:"hard_directive_rate_pps,omitempty"`

	// Adaptive factors — only set when adaptive mode is enabled (> 0).
	// EffectiveSoftRatePPS / EffectiveHardRatePPS are the computed rates at
	// startup based on the initial TrigPPS and the configured factors.
	SoftRateFactor       float64 `json:"soft_rate_factor,omitempty"        yaml:"soft_rate_factor,omitempty"`
	HardRateFactor       float64 `json:"hard_rate_factor,omitempty"        yaml:"hard_rate_factor,omitempty"`
	InitialTrigPPS       float64 `json:"initial_trig_pps,omitempty"        yaml:"initial_trig_pps,omitempty"`
	EffectiveSoftRatePPS uint64  `json:"effective_soft_rate_pps,omitempty" yaml:"effective_soft_rate_pps,omitempty"`
	EffectiveHardRatePPS uint64  `json:"effective_hard_rate_pps,omitempty" yaml:"effective_hard_rate_pps,omitempty"`

	// Active adapters and analyzers
	Adapters  []AdapterSummary `json:"adapters"  yaml:"adapters"`
	Analyzers []string         `json:"analyzers" yaml:"analyzers"`

	Safety SafetyConfig `json:"safety" yaml:"safety"`
}

// AdapterSummary is a single-line summary of a local adapter/plugin.
type AdapterSummary struct {
	ID      string `json:"id"      yaml:"id"`
	Plugin  string `json:"plugin"  yaml:"plugin"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
}

// SafetyConfig documents the fail-safe posture of the node.
type SafetyConfig struct {
	DefaultIfNoPolicyPack string `json:"default_if_no_policy_pack" yaml:"default_if_no_policy_pack"`
	MaxActionWithoutForge string `json:"max_action_without_forge"  yaml:"max_action_without_forge"`
}
