// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package capability

// CapabilityType categorizes what a capability does.
type CapabilityType string

const (
	TypeTelemetry   CapabilityType = "telemetry"   // Observes and reports metrics
	TypeEnforcement CapabilityType = "enforcement" // Takes action on traffic/service
	TypeSignal      CapabilityType = "signal"      // Emits or consumes signals
	TypePolicy      CapabilityType = "policy"      // Manages or evaluates policy
	TypeManagement  CapabilityType = "management"  // Manages adapters/runtime
	TypeAnalysis    CapabilityType = "analysis"    // Analyzes data (graph, correlate)
	TypeExport      CapabilityType = "export"      // Exports data to external systems
)

// Layer describes the network/application layer where the capability operates.
type Layer string

const (
	LayerL3L4       Layer = "L3L4"       // IP/TCP/UDP level (network layer)
	LayerL7         Layer = "L7"         // Application layer (HTTP, DNS, etc.)
	LayerContext    Layer = "context"    // Identity, workload, namespace context
	LayerTrust      Layer = "trust"      // Attestation and integrity
	LayerPolicy     Layer = "policy"     // Policy/configuration
	LayerManagement Layer = "management" // System management/metadata
)

// Direction describes data flow for a capability.
type Direction string

const (
	DirectionInput  Direction = "input"  // Receives data (telemetry, signals, policy)
	DirectionOutput Direction = "output" // Produces/sends data
	DirectionBoth   Direction = "both"   // Bidirectional (e.g., policy pull + receipt push)
)

// Capability describes a discrete capability that an adapter or component can provide.
// Capabilities are the bridge between abstract policy desires and concrete enforcement.
//
// Example: A policy might say "block suspicious sources". That maps to the capability
// "network.block_source" which must be implemented by a PEP adapter.
type Capability struct {
	// ID is a unique identifier like "network.block_source" or "signal.consume_global_risk".
	// Format: domain.action or domain.resource.action
	ID string `json:"id"`

	// Version is the capability schema version (e.g., "v1", "v2").
	// This allows capabilities to evolve without breaking dependent policies.
	Version string `json:"version"`

	// Type categorizes the capability's role.
	Type CapabilityType `json:"type"`

	// Layer describes which layer this operates at.
	Layer Layer `json:"layer"`

	// Direction describes whether it inputs, outputs, or both.
	Direction Direction `json:"direction"`

	// Description is a human-readable explanation.
	Description string `json:"description"`

	// Params describes what parameters the capability accepts.
	// Examples: ["source", "rate_pps", "burst"] for rate limiting.
	Params []CapabilityParam `json:"params,omitempty"`

	// Tags provide additional classification for organizing capabilities.
	// Examples: ["network", "enforcement"], ["trust", "critical"]
	Tags []string `json:"tags,omitempty"`

	// Adapter is the adapter that provides this capability.
	// Not populated in catalog; filled when reported by an adapter.
	Adapter string `json:"adapter,omitempty"`
}

// CapabilityParam describes a parameter that a capability accepts.
type CapabilityParam struct {
	// Name is the parameter identifier (e.g., "source", "rate_pps", "ttl").
	Name string `json:"name"`

	// Type is the parameter data type.
	// Examples: "entity.ip", "entity.cidr", "integer", "duration", "string"
	Type string `json:"type"`

	// Required indicates whether this parameter must be provided.
	Required bool `json:"required"`

	// Default is a suggested default value.
	Default string `json:"default,omitempty"`

	// Description explains the parameter.
	Description string `json:"description,omitempty"`
}

// NewCapability creates a new capability definition.
func NewCapability(id, version string, capType CapabilityType, layer Layer, direction Direction, description string) *Capability {
	return &Capability{
		ID:          id,
		Version:     version,
		Type:        capType,
		Layer:       layer,
		Direction:   direction,
		Description: description,
		Params:      []CapabilityParam{},
		Tags:        []string{},
	}
}

// AddParam adds a parameter to the capability.
func (c *Capability) AddParam(name, paramType string, required bool, description string) *Capability {
	c.Params = append(c.Params, CapabilityParam{
		Name:        name,
		Type:        paramType,
		Required:    required,
		Description: description,
	})
	return c
}

// AddTag adds a tag.
func (c *Capability) AddTag(tag string) *Capability {
	c.Tags = append(c.Tags, tag)
	return c
}
