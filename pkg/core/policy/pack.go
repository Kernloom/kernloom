// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package policy defines the LocalPolicyPack format used by kliq in standalone
// mode. The format is a Forge-compatible subset: when Kernloom Forge is
// integrated it will push cryptographically signed PolicyPacks using the same
// schema instead of reading a local file.
//
// Architecture:
//
//	PolicyPack (this file) — abstract, PEP-agnostic policy rules
//	AdapterManifest (pkg/adapters/shieldpep/manifest.go) — PEP-specific capability params
//	profiles.go in iq/cmd/kliq — PDP (kliq) internal FSM behavior defaults
package policy

import (
	"fmt"
	"time"
)

// Mode controls how kliq obtains its policy.
type Mode string

const (
	// ModeStandalone loads policy from a local file or built-in profile.
	ModeStandalone Mode = "standalone"
	// ModeManaged signals that Forge will push policy. Currently falls back to
	// standalone; the Forge client is not yet implemented.
	ModeManaged Mode = "managed"
)

// PolicyPack is the top-level struct for a LocalPolicyPack YAML file.
// It mirrors the Forge-compatible API object layout so that the same file
// can later be signed and distributed by Forge without schema changes.
type PolicyPack struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata holds the policy identity fields.
type Metadata struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

// Spec is the policy body.
// It is intentionally PEP-agnostic: it references abstract capability IDs
// (network.rate_limit_source, network.block_source) rather than Shield-specific
// parameters (rate_pps, burst). The concrete PEP parameters live in the
// adapter manifest (pkg/adapters/shieldpep/manifest.go).
type Spec struct {
	// TargetSelector is used by Forge to match this policy to nodes.
	// Ignored in standalone mode but preserved for forward-compatibility.
	TargetSelector TargetSelectorSpec `yaml:"target_selector,omitempty"`

	// CapabilitiesRequired lists the abstract capability IDs that this policy
	// needs. Preserved for backward compatibility; new packs use
	// ActionAuthorization.AllowedCapabilities instead.
	CapabilitiesRequired []string `yaml:"capabilities_required,omitempty"`

	// ActionAuthorization is the v1.1 authorization section that replaces the
	// Autonomy section. It uses Forge capability IDs throughout. KLIQ derives
	// the enforcement ceiling from AllowedCapabilities — no max_action shorthand.
	ActionAuthorization ActionAuthorizationSpec `yaml:"action_authorization,omitempty"`

	// Autonomy is the v1.0 authorization section. Kept for backward compat with
	// packs generated before v1.1. New packs must use ActionAuthorization.
	// Deprecated: DryRun belongs in KliqDeploymentConfig; MaxAction and
	// AllowLocalBlock are replaced by ActionAuthorization.
	Autonomy AutonomySpec `yaml:"autonomy,omitempty"`

	// Rules express the enforcement policy as when/then pairs.
	Rules []RuleSpec `yaml:"rules"`

	// Exports configures where kliq sends telemetry, decisions and receipts.
	Exports ExportsSpec `yaml:"exports,omitempty"`
}

// TargetSelectorSpec matches nodes for policy delivery (Forge use).
type TargetSelectorSpec struct {
	MatchLabels map[string]string `yaml:"match_labels,omitempty"`
}

// ActionAuthorizationSpec is the v1.1 replacement for AutonomySpec.
// It uses Forge capability IDs throughout and avoids KLIQ-internal shorthands.
type ActionAuthorizationSpec struct {
	// AllowedCapabilities is the explicit set of Forge capability IDs that this
	// policy authorises. KLIQ derives the enforcement ceiling from this list:
	// the highest-severity capability in the list becomes the effective cap.
	// Empty means no capability restriction (all capabilities allowed).
	AllowedCapabilities []string `yaml:"allowed_capabilities,omitempty"`

	// DefaultEffect determines what happens when a proposed capability is not
	// in AllowedCapabilities. "deny" (default) de-enforces to observe.
	DefaultEffect string `yaml:"default_effect,omitempty"` // "deny" | "allow"
}

// AutonomySpec is the v1.0 authorization section. Deprecated in v1.1.
// See ActionAuthorizationSpec for the replacement.
type AutonomySpec struct {
	// DryRun: deprecated — move to KliqDeploymentConfig.runtime.dry_run.
	DryRun bool `yaml:"dry_run,omitempty"`

	// MaxAction: deprecated — derived automatically from ActionAuthorization.AllowedCapabilities.
	// Valid values: observe, rate_limit, rate_limit_hard, block.
	MaxAction string `yaml:"max_action,omitempty"`

	// AllowLocalBlock: deprecated — implicit when enforce.access.deny is in AllowedCapabilities.
	AllowLocalBlock bool `yaml:"allow_local_block,omitempty"`
}

// RuleSpec expresses a single enforcement rule as a when/then pair.
// The PDP evaluates the when condition; when matched it invokes the PEP adapter
// with the abstract action and capability. The adapter translates this into
// its concrete implementation (e.g. writing to eBPF maps, nginx config, etc.).
type RuleSpec struct {
	Name string   `yaml:"name"`
	When WhenSpec `yaml:"when"`
	Then ThenSpec `yaml:"then"`
}

// WhenSpec describes the condition that triggers a rule.
type WhenSpec struct {
	// Capability is the v1.1 trigger: the Forge capability ID that this rule
	// applies to. KLIQ maps the capability to its FSM level internally.
	Capability string `yaml:"capability,omitempty"`

	// FsmLevel is the v1.0 trigger. Deprecated in v1.1; use Capability instead.
	// Kept for backward compatibility with packs generated before v1.1.
	FsmLevel string `yaml:"fsm_level,omitempty"`

	// Signal matches a specific signal type (e.g. graph.new_edge_after_freeze).
	Signal string `yaml:"signal,omitempty"`
}

// ThenSpec describes the enforcement action to take when a rule matches.
type ThenSpec struct {
	// Capability is the Forge capability ID the PEP adapter must implement.
	Capability string `yaml:"capability"`
	// TTL is how long the enforcement entry should remain active.
	TTL Duration `yaml:"ttl,omitempty"`
	// Params are optional capability-specific parameters.
	Params map[string]string `yaml:"params,omitempty"`

	// Action is the v1.0 action shorthand. Deprecated in v1.1; the capability
	// ID is now the sole source of truth for what action to take.
	Action string `yaml:"action,omitempty"`
}

// ExportsSpec configures telemetry export destinations.
type ExportsSpec struct {
	Correlate ExportTargetSpec `yaml:"correlate,omitempty"`
	Forge     ExportTargetSpec `yaml:"forge,omitempty"`
}

type ExportTargetSpec struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint,omitempty"`
}

// Duration is a YAML-serialisable wrapper around time.Duration.
// It marshals as a human-readable string (e.g. "30m", "10s").
type Duration struct{ D time.Duration }

func (d Duration) MarshalYAML() (interface{}, error) {
	return d.D.String(), nil
}

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("policy: invalid duration %q: %w", s, err)
	}
	d.D = parsed
	return nil
}

const (
	expectedAPIVersion = "kernloom.io/v1alpha1"
	expectedKind       = "LocalPolicyPack"
)

// Validate checks required fields and structural constraints.
func (p *PolicyPack) Validate() error {
	if p.APIVersion != expectedAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (want %q)", p.APIVersion, expectedAPIVersion)
	}
	if p.Kind != expectedKind {
		return fmt.Errorf("unsupported kind %q (want %q)", p.Kind, expectedKind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	// Backward compat: validate max_action only when Autonomy section is used.
	if p.Spec.ActionAuthorization.AllowedCapabilities == nil {
		validActions := map[string]bool{"observe": true, "signal": true, "rate_limit": true, "rate_limit_hard": true, "block": true, "": true}
		if !validActions[p.Spec.Autonomy.MaxAction] {
			return fmt.Errorf("spec.autonomy.max_action %q is not valid (observe|rate_limit|rate_limit_hard|block)", p.Spec.Autonomy.MaxAction)
		}
	}
	if len(p.Spec.Rules) == 0 {
		return fmt.Errorf("spec.rules must contain at least one rule")
	}
	return nil
}
