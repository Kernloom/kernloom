// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package kliqconfig defines the deployment- and component-config types for
// KLIQ. These types are intentionally separate from the LocalPolicyPack:
//
//	KliqDeploymentConfig  — HOW the node starts, connects, and fails safe.
//	KliqComponentConfig   — WHICH local engines and adapters are active.
//	LocalPolicyPack       — WHAT effects are authorised and when.
//
// The first two belong to the deployment pipeline. The third belongs to Forge.
package kliqconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	DeploymentConfigAPIVersion = "kernloom.io/v1alpha1"
	DeploymentConfigKind       = "KliqDeploymentConfig"
)

// KliqDeploymentConfig captures node identity, connectivity to Forge, runtime
// paths, and local safety defaults. It must not contain signal thresholds,
// enforcement conditions, or any value that directly authorises an effect.
type KliqDeploymentConfig struct {
	APIVersion string             `yaml:"apiVersion"`
	Kind       string             `yaml:"kind"`
	Metadata   DeploymentMetadata `yaml:"metadata"`
	Spec       DeploymentSpec     `yaml:"spec"`
}

type DeploymentMetadata struct {
	Name string `yaml:"name"`
}

type DeploymentSpec struct {
	Node        NodeConfig        `yaml:"node,omitempty"`
	Forge       ForgeConfig       `yaml:"forge,omitempty"`
	Runtime     RuntimeConfig     `yaml:"runtime,omitempty"`
	LocalSafety LocalSafetyConfig `yaml:"local_safety,omitempty"`
}

// NodeConfig identifies the node and its operational mode.
type NodeConfig struct {
	// ID is the stable node identifier used in graph edges and enrollment.
	// Defaults to the system hostname when empty.
	ID string `yaml:"id,omitempty"`

	// Mode is "standalone" (local policy only) or "managed" (Forge-controlled).
	Mode string `yaml:"mode,omitempty"`
}

// ForgeConfig holds the coordinates needed to reach the Forge control plane.
// Fields are optional until forge serve is available.
type ForgeConfig struct {
	URL               string `yaml:"url,omitempty"`
	EnrollmentKeyFile string `yaml:"enrollment_key_file,omitempty"`
	TrustBundle       string `yaml:"trust_bundle,omitempty"`
}

// RuntimeConfig specifies paths and operational flags that are set by the
// deployment pipeline, not by policy.
type RuntimeConfig struct {
	// DryRun disables all eBPF map writes. Use a pointer so that an absent
	// field (nil) can be distinguished from an explicit false.
	DryRun *bool `yaml:"dry_run,omitempty"`

	// StateDir is the directory for runtime state files (state.json,
	// feedback.json, kliq-report.json). Individual paths are derived from it.
	StateDir string `yaml:"state_dir,omitempty"`

	// BPFfsRoot is the bpffs mount point where Shield pins its maps.
	BPFfsRoot string `yaml:"bpffs_root,omitempty"`

	// WhitelistPath is the IMA-attested static allowlist file.
	WhitelistPath string `yaml:"whitelist_path,omitempty"`

	// PolicyFile is the LocalPolicyPack loaded at startup (--policy-file).
	PolicyFile string `yaml:"policy_file,omitempty"`

	// PDPConfigFile is the PDPConfig loaded at startup (--pdp-config).
	PDPConfigFile string `yaml:"pdp_config_file,omitempty"`

	// FailMode controls behaviour when Forge is unreachable in managed mode.
	// "fail_static" (default): keep last-known-good policy, no new enforcement.
	// "fail_open": fall back to standalone behaviour.
	FailMode string `yaml:"fail_mode,omitempty"`
}

// LocalSafetyConfig documents the fail-safe posture; values are enforced by
// the runtime, not by the policy.
type LocalSafetyConfig struct {
	DefaultIfNoPolicyPack string `yaml:"default_if_no_policy_pack,omitempty"`
	MaxActionWithoutForge string `yaml:"max_action_without_forge,omitempty"`
}

// LoadDeploymentConfig reads and unmarshals a KliqDeploymentConfig YAML file.
func LoadDeploymentConfig(path string) (*KliqDeploymentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c KliqDeploymentConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse deployment config: %w", err)
	}
	if c.Kind != DeploymentConfigKind && c.Kind != "" {
		return nil, fmt.Errorf("unexpected kind %q (want %s)", c.Kind, DeploymentConfigKind)
	}
	return &c, nil
}
