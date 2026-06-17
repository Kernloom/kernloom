// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package baseline

// Key uniquely identifies a metric baseline bucket.
//
// A baseline is NEVER shared across adapters or truth classes.  The measurement
// semantics fields (SourceClass, VisibilityPoint, MeasurementType, TruthClass)
// ensure that XDP packet-rate baselines and conntrack snapshot baselines are
// stored in completely separate buckets even if the metric ID and subject entity
// are identical.
type Key struct {
	// MetricID names the metric (e.g. "pps", "bps", "syn_rate", "http_error_rate").
	MetricID string

	// ScopeType / ScopeID narrow the baseline to a logical scope
	// (e.g. ScopeType="role", ScopeID="web-server").
	ScopeType string
	ScopeID   string

	// SubjectEntityID is the stable ID of the source entity (e.g. IP stable hash).
	SubjectEntityID string

	// ObjectEntityID is the stable ID of the destination entity, if edge-scoped.
	// Empty for host-scoped or role-scoped baselines.
	ObjectEntityID string

	// DimensionsHash is the stable SHA-256 hex of any additional dimensions
	// (e.g. protocol, destination_port).  Empty string if no extra dimensions.
	DimensionsHash string

	// SourceClass identifies the adapter sub-class (e.g. "xdp", "proc_net", "access_log").
	SourceClass string

	// VisibilityPoint is the stack layer where the measurement was captured.
	// See measurement.VisibilityPoint.
	VisibilityPoint string

	// MeasurementType is the mathematical nature of the value.
	// See measurement.Type.
	MeasurementType string

	// TruthClass is the epistemic quality of the observation.
	// See measurement.TruthClass.
	TruthClass string

	// WindowSeconds is the aggregation window length in seconds.
	// Baselines with different window sizes are kept separate.
	WindowSeconds int
}
