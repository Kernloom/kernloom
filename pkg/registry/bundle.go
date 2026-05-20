// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package registry provides a lightweight runtime view of the Kernloom registries
// that KLIQ uses for adapter manifest validation and metric pipeline validation.
//
// The authoritative source for signals and capabilities is Forge (signals.yaml,
// capabilities.yaml). The authoritative source for metrics and label policies is
// Forge (metrics.yaml, label_policies.yaml). This package provides runtime views of
// those registries — not a second independent copy.
//
// In standalone mode, embedded defaults cover the core Kernloom metric IDs.
// In managed mode, KLIQ should prefer a Forge-delivered registry snapshot.
package registry

import "strings"

// MetricEntry describes one canonical metric ID.
type MetricEntry struct {
	ID                  string
	Domain              string
	ValueType           string // rate|ratio|count|percentile|gauge
	Unit                string
	AllowedScopes       []string
	BaselineAllowed     bool
	HighCardinalityRisk string // low|medium|high
}

// LabelPolicyEntry defines whether a label key is allowed in baseline profile keys.
type LabelPolicyEntry struct {
	ID                    string
	Allowed               bool
	Cardinality           string // low|medium|high
	PIIRisk               string
	RequiresNormalization bool
	Reason                string // explanation for forbidden labels
}

// SignalView is a minimal runtime view of a signal entry from Forge signals.yaml.
type SignalView struct {
	ID            string
	Domain        string
	AllowedScopes []string
}

// CapabilityView is a minimal runtime view of a capability entry from Forge capabilities.yaml.
type CapabilityView struct {
	ID       string
	Category string
	Domain   string
}

// Bundle is the runtime registry available to KLIQ for validation.
// It is populated either from embedded defaults or from a Forge registry snapshot.
type Bundle struct {
	// Metrics holds canonical metric IDs by metric ID string.
	Metrics map[string]*MetricEntry

	// LabelPolicies holds label policy entries by label key.
	LabelPolicies map[string]*LabelPolicyEntry

	// Signals holds signal views by signal ID (from Forge signals.yaml).
	Signals map[string]*SignalView

	// Capabilities holds capability views by capability ID (from Forge capabilities.yaml).
	Capabilities map[string]*CapabilityView
}

// ── Lookup helpers ────────────────────────────────────────────────────────────

// HasMetric returns true if the metric ID is registered.
func (b *Bundle) HasMetric(id string) bool {
	if b == nil {
		return false
	}
	_, ok := b.Metrics[id]
	return ok
}

// MetricScopeAllowed returns true when scope is valid for the given metric.
func (b *Bundle) MetricScopeAllowed(metricID, scope string) bool {
	if b == nil {
		return true // permissive when no registry
	}
	m, ok := b.Metrics[metricID]
	if !ok {
		return false
	}
	for _, s := range m.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsLabelAllowed returns true when the label key is explicitly allowed.
// Unknown labels return false (fail-safe: unknown = not allowed).
func (b *Bundle) IsLabelAllowed(label string) bool {
	if b == nil {
		return false
	}
	p, ok := b.LabelPolicies[label]
	if !ok {
		return false
	}
	return p.Allowed
}

// HasSignal returns true if the signal ID is registered.
func (b *Bundle) HasSignal(id string) bool {
	if b == nil {
		return false
	}
	_, ok := b.Signals[id]
	return ok
}

// HasCapability returns true if the capability ID is registered.
func (b *Bundle) HasCapability(id string) bool {
	if b == nil {
		return false
	}
	_, ok := b.Capabilities[id]
	return ok
}

// ── Validation mode ───────────────────────────────────────────────────────────

// UnknownBehavior controls how unknown metric/signal IDs are handled.
type UnknownBehavior string

const (
	UnknownWarn UnknownBehavior = "warn"
	UnknownDrop UnknownBehavior = "drop"
)

// ValidationConfig controls registry validation strictness.
type ValidationConfig struct {
	UnknownMetrics      UnknownBehavior
	UnknownSignals      UnknownBehavior
	UnknownCapabilities UnknownBehavior
}

// DefaultValidationConfig returns the recommended defaults for standalone mode.
func DefaultValidationConfig() ValidationConfig {
	return ValidationConfig{
		UnknownMetrics:      UnknownWarn,
		UnknownSignals:      UnknownWarn,
		UnknownCapabilities: UnknownDrop,
	}
}

// StrictValidationConfig is used in managed mode where all IDs must be known.
func StrictValidationConfig() ValidationConfig {
	return ValidationConfig{
		UnknownMetrics:      UnknownDrop,
		UnknownSignals:      UnknownDrop,
		UnknownCapabilities: UnknownDrop,
	}
}

// ── Label validation ──────────────────────────────────────────────────────────

// ValidateSelectedLabels returns labels from the requested list that are allowed
// by the registry. Unknown or forbidden labels are excluded.
// When bundle is nil, all labels are allowed (standalone permissive mode).
func ValidateSelectedLabels(b *Bundle, requested []string) (allowed []string, rejected []string) {
	if b == nil {
		return requested, nil
	}
	for _, l := range requested {
		if b.IsLabelAllowed(l) {
			allowed = append(allowed, l)
		} else {
			rejected = append(rejected, l)
		}
	}
	return
}

// ── Merge signal/capability IDs from string lists ────────────────────────────

// SignalIDsFromStrings creates SignalView entries for a list of IDs.
// Used when building a Bundle from a flat list of known signal IDs.
func SignalIDsFromStrings(ids []string) map[string]*SignalView {
	m := make(map[string]*SignalView, len(ids))
	for _, id := range ids {
		parts := strings.SplitN(id, ".", 2)
		domain := ""
		if len(parts) > 0 {
			domain = parts[0]
		}
		m[id] = &SignalView{ID: id, Domain: domain}
	}
	return m
}

// CapabilityIDsFromStrings creates CapabilityView entries for a list of IDs.
func CapabilityIDsFromStrings(ids []string) map[string]*CapabilityView {
	m := make(map[string]*CapabilityView, len(ids))
	for _, id := range ids {
		parts := strings.SplitN(id, ".", 3)
		cat, domain := "", ""
		if len(parts) >= 1 {
			cat = parts[0]
		}
		if len(parts) >= 2 {
			domain = parts[1]
		}
		m[id] = &CapabilityView{ID: id, Category: cat, Domain: domain}
	}
	return m
}
