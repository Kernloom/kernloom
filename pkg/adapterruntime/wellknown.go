// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package adapterruntime

import "github.com/adrianenderlin/kernloom/pkg/core/capability"

// Well-known capability IDs used across adapters, policy packs, and Forge.
// Adapters reference these constants when registering; policy packs use the
// same string values. New capability IDs can always be defined locally by
// adapters — these constants exist only to prevent typos for the standard set.
const (
	// Network L3/L4
	CapIDNetworkObserveFlow      = "network.observe_flow"
	CapIDNetworkBlockSource      = "network.block_source"
	CapIDNetworkAllowSource      = "network.allow_source"
	CapIDNetworkRateLimitSource  = "network.rate_limit_source"
	CapIDNetworkEnforceAllowlist = "network.enforce_allowlist"
	CapIDNetworkObserveScan      = "network.observe_scan"

	// Graph
	CapIDGraphLearnEdges     = "graph.learn_edges"
	CapIDGraphFreezeNode     = "graph.freeze_node"
	CapIDGraphDetectNewEdge  = "graph.detect_new_edge"
	CapIDGraphExportProposal = "graph.export_proposal"

	// Signal
	CapIDSignalConsumeGlobalRisk = "signal.consume_global_risk"
	CapIDSignalEmitLocalRisk     = "signal.emit_local_risk"
	CapIDSignalSetNodeRisk       = "signal.set_node_risk"

	// Trust
	CapIDTrustConsumeAssertion = "trust.consume_assertion"
	CapIDTrustRequireMinScore  = "trust.require_min_score"
	CapIDTrustEmitDegraded     = "trust.emit_degraded"

	// Adapter/Runtime management
	CapIDAdapterReportCapabilities = "adapter.report_capabilities"
	CapIDAdapterReportHealth       = "adapter.report_health"
	CapIDAdapterApplyPolicyPack    = "adapter.apply_policy_pack"
)

// The functions below are reference constructors for the well-known capabilities.
// Adapters call these when building the slice passed to Registry.Register.
// They are not a closed catalog — adapters may define additional capabilities
// using capability.NewCapability directly.

// Network L3/L4

func WellKnownNetworkObserveFlow() *capability.Capability {
	return capability.NewCapability(
		CapIDNetworkObserveFlow, "v1",
		capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput,
		"Observe packet/flow counters and generate observations",
	).AddTag("network").AddTag("telemetry")
}

func WellKnownNetworkBlockSource() *capability.Capability {
	return capability.NewCapability(
		CapIDNetworkBlockSource, "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Block traffic from a source IP or CIDR",
	).
		AddParam("source", "entity.ip or entity.cidr", true, "Source IP or CIDR to block").
		AddParam("ttl", "duration", false, "How long to maintain the block").
		AddTag("network").AddTag("enforcement")
}

func WellKnownNetworkAllowSource() *capability.Capability {
	return capability.NewCapability(
		CapIDNetworkAllowSource, "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Allow traffic from a source IP or CIDR",
	).
		AddParam("source", "entity.ip or entity.cidr", true, "Source IP or CIDR to allow").
		AddTag("network").AddTag("enforcement")
}

func WellKnownNetworkRateLimitSource() *capability.Capability {
	return capability.NewCapability(
		CapIDNetworkRateLimitSource, "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Apply token-bucket rate limit to source IP",
	).
		AddParam("source", "entity.ip or entity.cidr", true, "Source IP to rate limit").
		AddParam("rate_pps", "integer", true, "Packets per second limit").
		AddParam("burst", "integer", false, "Burst size (default: rate_pps)").
		AddParam("ttl", "duration", false, "How long to maintain the rate limit").
		AddTag("network").AddTag("enforcement")
}

func WellKnownNetworkEnforceAllowlist() *capability.Capability {
	return capability.NewCapability(
		CapIDNetworkEnforceAllowlist, "v1",
		capability.TypeEnforcement, capability.LayerL3L4, capability.DirectionOutput,
		"Drop sources not in allowlist",
	).
		AddParam("allowlist", "list[entity.ip or entity.cidr]", true, "Allowed sources").
		AddTag("network").AddTag("enforcement")
}

func WellKnownNetworkObserveScan() *capability.Capability {
	return capability.NewCapability(
		CapIDNetworkObserveScan, "v1",
		capability.TypeTelemetry, capability.LayerL3L4, capability.DirectionOutput,
		"Report increasing destination port diversity (scan pattern)",
	).AddTag("network").AddTag("telemetry")
}

// Graph

func WellKnownGraphLearnEdges() *capability.Capability {
	return capability.NewCapability(
		CapIDGraphLearnEdges, "v1",
		capability.TypeAnalysis, capability.LayerContext, capability.DirectionOutput,
		"Learn observed communication edges and promote candidates to learned state",
	).AddTag("graph").AddTag("analysis")
}

func WellKnownGraphFreezeNode() *capability.Capability {
	return capability.NewCapability(
		CapIDGraphFreezeNode, "v1",
		capability.TypePolicy, capability.LayerContext, capability.DirectionOutput,
		"Freeze node graph baseline and emit signals on new edges",
	).
		AddParam("freeze_policy", "string", false, "Policy for handling new edges").
		AddTag("graph").AddTag("policy")
}

func WellKnownGraphDetectNewEdge() *capability.Capability {
	return capability.NewCapability(
		CapIDGraphDetectNewEdge, "v1",
		capability.TypeSignal, capability.LayerContext, capability.DirectionOutput,
		"Emit signal when new communication edge appears after graph freeze",
	).AddTag("graph").AddTag("signal")
}

func WellKnownGraphExportProposal() *capability.Capability {
	return capability.NewCapability(
		CapIDGraphExportProposal, "v1",
		capability.TypeExport, capability.LayerContext, capability.DirectionOutput,
		"Export learned graph as policy proposal",
	).AddTag("graph").AddTag("export")
}

// Signal

func WellKnownSignalConsumeGlobalRisk() *capability.Capability {
	return capability.NewCapability(
		CapIDSignalConsumeGlobalRisk, "v1",
		capability.TypeSignal, capability.LayerContext, capability.DirectionInput,
		"Consume global risk signals from Correlate",
	).AddTag("signal").AddTag("input")
}

func WellKnownSignalEmitLocalRisk() *capability.Capability {
	return capability.NewCapability(
		CapIDSignalEmitLocalRisk, "v1",
		capability.TypeSignal, capability.LayerContext, capability.DirectionOutput,
		"Emit local risk signals to Correlate or SIEM",
	).AddTag("signal").AddTag("output")
}

func WellKnownSignalSetNodeRisk() *capability.Capability {
	return capability.NewCapability(
		CapIDSignalSetNodeRisk, "v1",
		capability.TypeSignal, capability.LayerContext, capability.DirectionOutput,
		"Set risk score for node/source/service",
	).
		AddParam("subject", "entity.node or entity.ip", true, "Entity to score").
		AddParam("score", "integer 0-100", true, "Risk score").
		AddTag("signal").AddTag("output")
}

// Trust

func WellKnownTrustConsumeAssertion() *capability.Capability {
	return capability.NewCapability(
		CapIDTrustConsumeAssertion, "v1",
		capability.TypeTelemetry, capability.LayerTrust, capability.DirectionInput,
		"Consume signed trust assertions from trustd or kernloom-verifier",
	).AddTag("trust").AddTag("input")
}

func WellKnownTrustRequireMinScore() *capability.Capability {
	return capability.NewCapability(
		CapIDTrustRequireMinScore, "v1",
		capability.TypePolicy, capability.LayerTrust, capability.DirectionBoth,
		"Require minimum trust score before applying policy pack",
	).
		AddParam("min_score", "integer 0-100", true, "Minimum trust score required").
		AddTag("trust").AddTag("policy")
}

func WellKnownTrustEmitDegraded() *capability.Capability {
	return capability.NewCapability(
		CapIDTrustEmitDegraded, "v1",
		capability.TypeSignal, capability.LayerTrust, capability.DirectionOutput,
		"Emit signal when trust state degrades",
	).AddTag("trust").AddTag("signal")
}

// Adapter/Runtime

func WellKnownAdapterReportCapabilities() *capability.Capability {
	return capability.NewCapability(
		CapIDAdapterReportCapabilities, "v1",
		capability.TypeManagement, capability.LayerManagement, capability.DirectionOutput,
		"Report adapter capabilities to Forge",
	).AddTag("management").AddTag("output")
}

func WellKnownAdapterReportHealth() *capability.Capability {
	return capability.NewCapability(
		CapIDAdapterReportHealth, "v1",
		capability.TypeManagement, capability.LayerManagement, capability.DirectionOutput,
		"Report adapter health status",
	).AddTag("management").AddTag("output")
}

func WellKnownAdapterApplyPolicyPack() *capability.Capability {
	return capability.NewCapability(
		CapIDAdapterApplyPolicyPack, "v1",
		capability.TypePolicy, capability.LayerManagement, capability.DirectionInput,
		"Apply signed policy pack from Forge",
	).AddTag("management").AddTag("policy")
}
