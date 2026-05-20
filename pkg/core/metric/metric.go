// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package metric defines the normalized metric data model used across KLIQ's
// generic adapter pipeline.
//
// A Metric is an aggregated, numeric measurement derived from one or more
// Observations over a time window. It sits between raw Observations (what
// an adapter sees) and Baseline scoring (what KLIQ learns as normal).
//
// Naming convention for MetricIDs:
//
//	<domain>.<name>                 e.g. network.pps
//	<domain>.<sub>.<name>           e.g. http.auth_fail_rate
//
// Known domains: network, http, ziti, trust, app, overlay
//
// Metrics do NOT belong to the Forge signal registry — they are an internal
// KLIQ concept. The Forge signal registry describes what KLIQ reports outward.
// Internally, Metrics are what the pipeline learns from.
package metric

import "time"

// MetricID is a stable, dot-separated identifier for a metric type.
// Example IDs:
//
//	network.pps
//	network.bps
//	network.syn_rate
//	network.scan_rate
//	http.requests_per_second
//	http.auth_fail_rate
//	http.status_4xx_rate
//	http.status_5xx_rate
//	http.path_diversity
//	http.latency_p95_ms
//	http.request_body_size_p95
//	http.user_agent_diversity
//	ziti.session_failure_rate
//	trust.attestation_fail_rate
type MetricID string

// Scope is the aggregation dimension of the metric — at what level the metric
// is measured for a given subject entity.
type Scope string

const (
	ScopeSourceIP Scope = "src_ip"  // per source IP address
	ScopeNode     Scope = "node"    // per KLIQ node
	ScopeService  Scope = "service" // per service/listener
	ScopePath     Scope = "path"    // per URL path or route group
	ScopeUser     Scope = "user"    // per authenticated user identity
	ScopeEdge     Scope = "edge"    // per src→dst:port tuple
	ScopeGlobal   Scope = "global"  // node-wide aggregate
)

// Subject identifies what entity the metric is measured for.
// It is intentionally simpler than observation.EntityRef so that the metric
// package does not import the observation package.
type Subject struct {
	// Type is the entity kind: "ip", "node", "service", "user", "edge", etc.
	Type string `json:"type" yaml:"type"`

	// Value is the entity identifier, e.g. "10.0.0.1", "nginx-proxy-01".
	Value string `json:"value" yaml:"value"`
}

// Metric is a normalized, timestamped numeric measurement derived from observations
// over a time window. It is the input to the generic metric baseline engine.
type Metric struct {
	// ID identifies the metric type.
	ID MetricID `json:"id" yaml:"id"`

	// Source is the adapter or engine that produced this metric, e.g. "shieldtelemetry".
	Source string `json:"source" yaml:"source"`

	// Scope is the aggregation dimension.
	Scope Scope `json:"scope" yaml:"scope"`

	// Subject is the entity this metric describes.
	Subject Subject `json:"subject" yaml:"subject"`

	// Value is the numeric measurement.
	Value float64 `json:"value" yaml:"value"`

	// Unit is a human-readable unit string, e.g. "pps", "ratio", "ms", "count".
	// Not used for computation — informational only.
	Unit string `json:"unit,omitempty" yaml:"unit,omitempty"`

	// Window is the aggregation window over which Value was computed.
	// Example: pps measured over the last 1s tick.
	Window time.Duration `json:"window" yaml:"window"`

	// Timestamp is when the metric was computed (end of the window).
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// Labels are optional low-cardinality annotations.
	// WARNING: only include labels with bounded cardinality (e.g. "host", "route_group").
	// Never include high-cardinality labels (path, user_agent, session_id) directly —
	// normalize them first in the feature extractor.
	// The metric baseline engine selects which labels to use for keying via config.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// Batch is a collection of metrics produced in one processing cycle.
type Batch struct {
	// Metrics contains all metrics in this batch.
	Metrics []Metric `json:"metrics" yaml:"metrics"`

	// From is the start of the observation window.
	From time.Time `json:"from" yaml:"from"`

	// To is the end of the observation window (== Metric.Timestamp for most metrics).
	To time.Time `json:"to" yaml:"to"`

	// Source is the adapter or extractor that produced this batch.
	Source string `json:"source" yaml:"source"`
}

// New creates a Metric with required fields set and the current time as Timestamp.
func New(id MetricID, source string, scope Scope, subject Subject, value float64, window time.Duration) Metric {
	return Metric{
		ID:        id,
		Source:    source,
		Scope:     scope,
		Subject:   subject,
		Value:     value,
		Window:    window,
		Timestamp: time.Now().UTC(),
	}
}

// WithUnit returns a copy of m with Unit set.
func (m Metric) WithUnit(unit string) Metric {
	m.Unit = unit
	return m
}

// WithLabel returns a copy of m with the given label added.
func (m Metric) WithLabel(key, value string) Metric {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	} else {
		// Copy to avoid mutating the original map.
		labels := make(map[string]string, len(m.Labels)+1)
		for k, v := range m.Labels {
			labels[k] = v
		}
		m.Labels = labels
	}
	m.Labels[key] = value
	return m
}

// NewBatch creates an empty Batch for the given source and time window.
func NewBatch(source string, from, to time.Time) Batch {
	return Batch{Source: source, From: from, To: to}
}

// Add appends a metric to the batch.
func (b *Batch) Add(m Metric) {
	b.Metrics = append(b.Metrics, m)
}

// Len returns the number of metrics in the batch.
func (b *Batch) Len() int { return len(b.Metrics) }
