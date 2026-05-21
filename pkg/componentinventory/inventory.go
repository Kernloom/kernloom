// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package componentinventory defines the runtime inventory and config-asset
// report types that KLIQ produces to describe what it can do and how it is
// configured. These types are consumed by Forge during enrollment/heartbeat.
package componentinventory

import "time"

// CapabilityStatus describes a single Forge capability and its runtime
// availability on a specific component.
type CapabilityStatus struct {
	ID          string   `json:"id"                    yaml:"id"`
	Status      string   `json:"status"                yaml:"status"` // available, degraded, unavailable
	Granularity []string `json:"granularity,omitempty" yaml:"granularity,omitempty"`
	Reason      string   `json:"reason,omitempty"      yaml:"reason,omitempty"`
}

// ComponentRuntimeInventory describes what a single component (e.g. KLShield)
// can actually do at runtime, based on open maps and compile-time features.
// It is serialised as JSON/YAML and included in enrollment requests and
// heartbeats so that Forge can compile packs that match real capabilities.
type ComponentRuntimeInventory struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind"       yaml:"kind"`
	Metadata   struct {
		ID        string    `json:"id"        yaml:"id"`
		Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	} `json:"metadata" yaml:"metadata"`

	ControlledBy struct {
		NodeID        string `json:"node_id"                  yaml:"node_id"`
		PluginAdapter string `json:"plugin_adapter,omitempty" yaml:"plugin_adapter,omitempty"`
	} `json:"controlled_by" yaml:"controlled_by"`

	Component struct {
		Product string `json:"product"           yaml:"product"`
		Version string `json:"version,omitempty" yaml:"version,omitempty"`
	} `json:"component" yaml:"component"`

	Roles    []string `json:"roles"    yaml:"roles"`
	Profiles []string `json:"profiles" yaml:"profiles"`

	EffectiveCapabilities   []CapabilityStatus `json:"effective_capabilities"             yaml:"effective_capabilities"`
	UnavailableCapabilities []CapabilityStatus `json:"unavailable_capabilities,omitempty" yaml:"unavailable_capabilities,omitempty"`
}
