// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapterruntime

import (
	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/registry"
)

// ManifestAdapterType classifies the pipeline role of an adapter.
// Distinct from the existing AdapterKind (which describes system integration role).
type ManifestAdapterType string

const (
	ManifestTypeObservation  ManifestAdapterType = "observation"       // emits observations
	ManifestTypeExtractor    ManifestAdapterType = "feature_extractor" // obs → metrics
	ManifestTypeSignalEngine ManifestAdapterType = "signal_engine"     // metrics → signals
	ManifestTypePEP          ManifestAdapterType = "pep"               // executes ResolvedActions
	ManifestTypeExport       ManifestAdapterType = "export"            // forwards data externally
)

// AdapterProvides declares what an adapter produces.
type AdapterProvides struct {
	// Observations lists the observation types this adapter emits.
	Observations []observation.ObservationType

	// Metrics lists the canonical metric IDs this adapter can produce.
	Metrics []metric.MetricID

	// Signals lists the canonical signal IDs this adapter can emit.
	Signals []signal.SignalType
}

// AdapterConsumes declares what an adapter needs as input.
type AdapterConsumes struct {
	// Observations lists the observation types this adapter processes.
	Observations []observation.ObservationType

	// Metrics lists the metric IDs this adapter reads.
	Metrics []metric.MetricID

	// Signals lists the signal IDs this adapter reads (for export/PEP adapters).
	Signals []signal.SignalType

	// Actions lists the capability IDs this adapter can execute (PEP adapters only).
	Actions []string
}

// AdapterLabelPolicy declares the label handling policy for this adapter.
type AdapterLabelPolicy struct {
	// DefaultSelectedLabels is the set of labels this adapter includes in metric keys.
	// MUST default to [] — adapters that need labels must opt in explicitly.
	DefaultSelectedLabels []string

	// ForbiddenLabels are labels this adapter must never attach to metrics.
	ForbiddenLabels []string
}

// AdapterManifest declares the contracts of one adapter: what it produces, what it
// consumes, and its label policy. Used for registry validation and pipeline wiring.
//
// An adapter does not need to implement the full Adapter interface to have a manifest —
// manifests can also describe adapters that are still in development or partially wired.
type AdapterManifest struct {
	// ID is the unique adapter identifier, e.g. "klshield", "nginxobs", "shieldpep".
	ID string

	// Type classifies the adapter's pipeline role.
	Type ManifestAdapterType

	// Version is the adapter's semantic version string.
	Version string

	// Provides declares what the adapter outputs.
	Provides AdapterProvides

	// Consumes declares what the adapter needs as input.
	Consumes AdapterConsumes

	// LabelPolicy controls label handling. DefaultSelectedLabels must default to [].
	LabelPolicy AdapterLabelPolicy
}

// ── Validation ────────────────────────────────────────────────────────────────

// ValidationResult holds the outcome of manifest validation against a registry bundle.
type ManifestValidationResult struct {
	// Valid is true when all declared IDs are known and label policy is sound.
	Valid bool

	// UnknownMetrics are metric IDs declared in Provides but absent from the registry.
	UnknownMetrics []string

	// UnknownSignals are signal IDs declared in Provides but absent from the registry.
	UnknownSignals []string

	// UnknownActions are capability IDs declared in Consumes but absent from the registry.
	UnknownActions []string

	// ForbiddenLabels are default_selected_labels that the registry disallows.
	ForbiddenLabels []string
}

// Validate checks the manifest against a registry bundle.
// If bundle is nil, validation is skipped and Valid=true is returned (standalone mode).
func (m *AdapterManifest) Validate(b *registry.Bundle) ManifestValidationResult {
	res := ManifestValidationResult{Valid: true}
	if b == nil {
		return res
	}

	for _, id := range m.Provides.Metrics {
		if !b.HasMetric(string(id)) {
			res.UnknownMetrics = append(res.UnknownMetrics, string(id))
		}
	}
	for _, id := range m.Provides.Signals {
		if !b.HasSignal(string(id)) {
			res.UnknownSignals = append(res.UnknownSignals, string(id))
		}
	}
	for _, id := range m.Consumes.Actions {
		if !b.HasCapability(id) {
			res.UnknownActions = append(res.UnknownActions, id)
		}
	}
	for _, label := range m.LabelPolicy.DefaultSelectedLabels {
		if !b.IsLabelAllowed(label) {
			res.ForbiddenLabels = append(res.ForbiddenLabels, label)
		}
	}

	res.Valid = len(res.UnknownMetrics) == 0 &&
		len(res.UnknownSignals) == 0 &&
		len(res.UnknownActions) == 0 &&
		len(res.ForbiddenLabels) == 0
	return res
}

// ── Known manifests ───────────────────────────────────────────────────────────

// KLShieldManifest is the manifest for the combined KLShield telemetry+PEP adapter.
var KLShieldManifest = AdapterManifest{
	ID:      "klshield",
	Type:    ManifestTypeObservation,
	Version: "1",
	Provides: AdapterProvides{
		Observations: []observation.ObservationType{observation.TypeFlow, observation.TypeDrop, observation.TypeRateLimit, observation.TypeScan},
		Metrics: []metric.MetricID{
			"network.packets_per_second",
			"network.bytes_per_second",
			"network.syn_rate",
			"network.scan_rate",
			"network.rate_limit_drop_rate",
		},
		Signals: []signal.SignalType{
			signal.SignalPPSHigh,
			signal.SignalBPSHigh,
			signal.SignalSYNRateHigh,
			signal.SignalScanSuspected,
			signal.SignalRateLimitDropsSustained,
		},
	},
	Consumes: AdapterConsumes{
		Actions: []string{"enforce.network.rate_limit", "enforce.network.deny", "enforce.network.allow"},
	},
	LabelPolicy: AdapterLabelPolicy{
		DefaultSelectedLabels: []string{}, // cardinality-safe default
	},
}
