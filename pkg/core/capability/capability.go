// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package capability

// CapabilityType categorizes what a capability does.
type CapabilityType string

const (
	TypeTelemetry   CapabilityType = "telemetry"  // Observes and reports metrics
	TypeEnforcement CapabilityType = "enforcement" // Takes action on traffic/service
	TypeSignal      CapabilityType = "signal"     // Emits or consumes signals
	TypePolicy      CapabilityType = "policy"     // Manages or evaluates policy
	TypeManagement  CapabilityType = "management" // Manages adapters/runtime
	TypeAnalysis    CapabilityType = "analysis"   // Analyzes data (graph, correlate)
	TypeExport      CapabilityType = "export"     // Exports data to external systems
)

// Layer describes the network/application layer where the capability operates.
type Layer string

const (
	LayerL3L4      Layer = "L3L4"      // IP/TCP/UDP level (network layer)
	LayerL7        Layer = "L7"        // Application layer (HTTP, DNS, etc.)
	LayerContext   Layer = "context"   // Identity, workload, namespace context
	LayerTrust     Layer = "trust"     // Attestation and integrity
	LayerPolicy    Layer = "policy"    // Policy/configuration
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

// ===== Standard Capability Catalog =====

// Network L3/L4 Capabilities

// CapabilityNetworkObserveFlow: Observe and report on packet flows.
func CapabilityNetworkObserveFlow() *Capability {
	return NewCapability(
		"network.observe_flow", "v1",
		TypeTelemetry, LayerL3L4, DirectionOutput,
		"Observe packet/flow counters and generate observations",
	).AddTag("network").AddTag("telemetry")
}

// CapabilityNetworkBlockSource: Block traffic from a source IP or CIDR.
func CapabilityNetworkBlockSource() *Capability {
	return NewCapability(
		"network.block_source", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Block traffic from a source IP or CIDR",
	).
		AddParam("source", "entity.ip or entity.cidr", true, "Source IP or CIDR to block").
		AddParam("ttl", "duration", false, "How long to maintain the block (e.g., '10m')").
		AddTag("network").AddTag("enforcement")
}

// CapabilityNetworkAllowSource: Allow traffic from a source IP or CIDR.
func CapabilityNetworkAllowSource() *Capability {
	return NewCapability(
		"network.allow_source", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Allow traffic from a source IP or CIDR",
	).
		AddParam("source", "entity.ip or entity.cidr", true, "Source IP or CIDR to allow").
		AddTag("network").AddTag("enforcement")
}

// CapabilityNetworkRateLimitSource: Apply rate limiting to a source IP.
func CapabilityNetworkRateLimitSource() *Capability {
	return NewCapability(
		"network.rate_limit_source", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Apply token-bucket rate limit to source IP",
	).
		AddParam("source", "entity.ip or entity.cidr", true, "Source IP to rate limit").
		AddParam("rate_pps", "integer", true, "Packets per second limit").
		AddParam("burst", "integer", false, "Burst size (default: rate_pps)").
		AddParam("ttl", "duration", false, "How long to maintain the rate limit").
		AddTag("network").AddTag("enforcement")
}

// CapabilityNetworkEnforceAllowlist: Drop sources not in allowlist.
func CapabilityNetworkEnforceAllowlist() *Capability {
	return NewCapability(
		"network.enforce_allowlist", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Drop sources not in allowlist",
	).
		AddParam("allowlist", "list[entity.ip or entity.cidr]", true, "Allowed sources").
		AddTag("network").AddTag("enforcement")
}

// CapabilityNetworkObserveScan: Report port scan behavior.
func CapabilityNetworkObserveScan() *Capability {
	return NewCapability(
		"network.observe_scan", "v1",
		TypeTelemetry, LayerL3L4, DirectionOutput,
		"Report increasing destination port diversity (scan pattern)",
	).AddTag("network").AddTag("telemetry")
}

// Graph Capabilities

// CapabilityGraphLearnEdges: Learn and track communication edges.
func CapabilityGraphLearnEdges() *Capability {
	return NewCapability(
		"graph.learn_edges", "v1",
		TypeAnalysis, LayerContext, DirectionOutput,
		"Learn observed communication edges and promote candidates to learned state",
	).AddTag("graph").AddTag("analysis")
}

// CapabilityGraphFreezeNode: Freeze node graph and flag anomalies.
func CapabilityGraphFreezeNode() *Capability {
	return NewCapability(
		"graph.freeze_node", "v1",
		TypePolicy, LayerContext, DirectionOutput,
		"Freeze node graph baseline and emit signals on new edges",
	).
		AddParam("freeze_policy", "string", false, "Policy for handling new edges").
		AddTag("graph").AddTag("policy")
}

// CapabilityGraphDetectNewEdge: Signal new edges after freeze.
func CapabilityGraphDetectNewEdge() *Capability {
	return NewCapability(
		"graph.detect_new_edge", "v1",
		TypeSignal, LayerContext, DirectionOutput,
		"Emit signal when new communication edge appears after graph freeze",
	).AddTag("graph").AddTag("signal")
}

// CapabilityGraphExportProposal: Export learned graph.
func CapabilityGraphExportProposal() *Capability {
	return NewCapability(
		"graph.export_proposal", "v1",
		TypeExport, LayerContext, DirectionOutput,
		"Export learned graph as policy proposal",
	).AddTag("graph").AddTag("export")
}

// Signal Capabilities

// CapabilitySignalConsumeGlobalRisk: Consume global risk signals from Correlate.
func CapabilitySignalConsumeGlobalRisk() *Capability {
	return NewCapability(
		"signal.consume_global_risk", "v1",
		TypeSignal, LayerContext, DirectionInput,
		"Consume global risk signals from Correlate",
	).AddTag("signal").AddTag("input")
}

// CapabilitySignalEmitLocalRisk: Emit local risk signals.
func CapabilitySignalEmitLocalRisk() *Capability {
	return NewCapability(
		"signal.emit_local_risk", "v1",
		TypeSignal, LayerContext, DirectionOutput,
		"Emit local risk signals to Correlate or SIEM",
	).AddTag("signal").AddTag("output")
}

// CapabilitySignalSetNodeRisk: Set risk score for entity.
func CapabilitySignalSetNodeRisk() *Capability {
	return NewCapability(
		"signal.set_node_risk", "v1",
		TypeSignal, LayerContext, DirectionOutput,
		"Set risk score for node/source/service",
	).
		AddParam("subject", "entity.node or entity.ip", true, "Entity to score").
		AddParam("score", "integer 0-100", true, "Risk score").
		AddTag("signal").AddTag("output")
}

// Trust Capabilities

// CapabilityTrustConsumeAssertion: Consume trust assertions.
func CapabilityTrustConsumeAssertion() *Capability {
	return NewCapability(
		"trust.consume_assertion", "v1",
		TypeTelemetry, LayerTrust, DirectionInput,
		"Consume signed trust assertions from trustd or kernloom-verifier",
	).AddTag("trust").AddTag("input")
}

// CapabilityTrustRequireMinScore: Gate policy on trust score.
func CapabilityTrustRequireMinScore() *Capability {
	return NewCapability(
		"trust.require_min_score", "v1",
		TypePolicy, LayerTrust, DirectionBoth,
		"Require minimum trust score before applying policy pack",
	).
		AddParam("min_score", "integer 0-100", true, "Minimum trust score required").
		AddTag("trust").AddTag("policy")
}

// CapabilityTrustEmitDegraded: Emit signal on trust degradation.
func CapabilityTrustEmitDegraded() *Capability {
	return NewCapability(
		"trust.emit_degraded", "v1",
		TypeSignal, LayerTrust, DirectionOutput,
		"Emit signal when trust state degrades",
	).AddTag("trust").AddTag("signal")
}

// Adapter/Runtime Capabilities

// CapabilityAdapterReportCapabilities: Report adapter capabilities to Forge.
func CapabilityAdapterReportCapabilities() *Capability {
	return NewCapability(
		"adapter.report_capabilities", "v1",
		TypeManagement, LayerManagement, DirectionOutput,
		"Report adapter capabilities to Forge",
	).AddTag("management").AddTag("output")
}

// CapabilityAdapterReportHealth: Report adapter health.
func CapabilityAdapterReportHealth() *Capability {
	return NewCapability(
		"adapter.report_health", "v1",
		TypeManagement, LayerManagement, DirectionOutput,
		"Report adapter health status",
	).AddTag("management").AddTag("output")
}

// CapabilityAdapterApplyPolicyPack: Apply signed policy pack.
func CapabilityAdapterApplyPolicyPack() *Capability {
	return NewCapability(
		"adapter.apply_policy_pack", "v1",
		TypePolicy, LayerManagement, DirectionInput,
		"Apply signed policy pack from Forge",
	).AddTag("management").AddTag("policy")
}

// BuildCatalog creates the standard capability catalog.
func BuildCatalog() []*Capability {
	return []*Capability{
		// Network
		CapabilityNetworkObserveFlow(),
		CapabilityNetworkBlockSource(),
		CapabilityNetworkAllowSource(),
		CapabilityNetworkRateLimitSource(),
		CapabilityNetworkEnforceAllowlist(),
		CapabilityNetworkObserveScan(),
		// Graph
		CapabilityGraphLearnEdges(),
		CapabilityGraphFreezeNode(),
		CapabilityGraphDetectNewEdge(),
		CapabilityGraphExportProposal(),
		// Signal
		CapabilitySignalConsumeGlobalRisk(),
		CapabilitySignalEmitLocalRisk(),
		CapabilitySignalSetNodeRisk(),
		// Trust
		CapabilityTrustConsumeAssertion(),
		CapabilityTrustRequireMinScore(),
		CapabilityTrustEmitDegraded(),
		// Adapter
		CapabilityAdapterReportCapabilities(),
		CapabilityAdapterReportHealth(),
		CapabilityAdapterApplyPolicyPack(),
	}
}
