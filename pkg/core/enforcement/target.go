// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package enforcement defines the EnforcementTarget abstraction for Sprint 8.
// It prepares the PEP interface for future tuple-based (edge-level) enforcement
// without changing the current source-based DoS FSM.
//
// Usage today: all targets are TargetSource.
// Usage with graph-enforce: TargetEdge enables XDP tuple map enforcement
// (once the eBPF maps are added to klshield).
package enforcement

// TargetType identifies what level the enforcement action applies to.
type TargetType string

const (
	// TargetSource applies the action to all traffic from a source IP.
	// This is the current (and default) enforcement model.
	TargetSource TargetType = "source"

	// TargetEdge applies the action to a specific (src, dst, port, proto) tuple.
	// Requires TupleEnforcement=true in the FeatureSet and XDP tuple maps in klshield.
	TargetEdge TargetType = "edge"
)

// EdgeKey identifies a 4-tuple communication edge.
type EdgeKey struct {
	SrcIP  string
	DstIP  string
	DstPort uint16
	Proto  string
}

// Target is the unified enforcement address used by PEP adapters.
// Adapters must check the Type field and return ErrTupleEnforcementDisabled
// if they do not support TargetEdge.
type Target struct {
	Type TargetType

	// SrcIP is set for both TargetSource and TargetEdge.
	SrcIP string

	// Edge is set only for TargetEdge. Nil for TargetSource.
	Edge *EdgeKey
}

// ForSource creates a Target for source-level enforcement.
func ForSource(srcIP string) Target {
	return Target{Type: TargetSource, SrcIP: srcIP}
}

// ForEdge creates a Target for edge-level tuple enforcement.
func ForEdge(srcIP string, edge EdgeKey) Target {
	return Target{Type: TargetEdge, SrcIP: srcIP, Edge: &edge}
}
