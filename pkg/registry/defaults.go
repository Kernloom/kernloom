// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

// DefaultBundle returns a Bundle populated with the embedded Kernloom defaults.
// Used in standalone mode when no Forge-delivered registry snapshot is available.
// Managed mode should replace this with a Forge-signed registry snapshot.
func DefaultBundle() *Bundle {
	return &Bundle{
		Metrics:       defaultMetrics(),
		LabelPolicies: defaultLabelPolicies(),
		Signals:       defaultSignals(),
		Capabilities:  defaultCapabilities(),
	}
}

func defaultMetrics() map[string]*MetricEntry {
	entries := []*MetricEntry{
		// Network (KLShield)
		{ID: "network.packets_per_second", Domain: "network", ValueType: "rate", Unit: "packets/s", AllowedScopes: []string{"src_ip", "node", "global"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "network.bytes_per_second", Domain: "network", ValueType: "rate", Unit: "bytes/s", AllowedScopes: []string{"src_ip", "node", "global"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "network.syn_rate", Domain: "network", ValueType: "rate", Unit: "packets/s", AllowedScopes: []string{"src_ip"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "network.scan_rate", Domain: "network", ValueType: "rate", Unit: "ports/window", AllowedScopes: []string{"src_ip"}, BaselineAllowed: true, HighCardinalityRisk: "medium"},
		{ID: "network.rate_limit_drop_rate", Domain: "network", ValueType: "rate", Unit: "drops/s", AllowedScopes: []string{"src_ip", "node"}, BaselineAllowed: false, HighCardinalityRisk: "low"},
		// HTTP (future)
		{ID: "http.requests_per_second", Domain: "http", ValueType: "rate", Unit: "requests/s", AllowedScopes: []string{"src_ip", "service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.auth_fail_rate", Domain: "http", ValueType: "ratio", Unit: "ratio", AllowedScopes: []string{"src_ip", "service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.status_4xx_rate", Domain: "http", ValueType: "ratio", Unit: "ratio", AllowedScopes: []string{"src_ip", "service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.status_5xx_rate", Domain: "http", ValueType: "ratio", Unit: "ratio", AllowedScopes: []string{"src_ip", "service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.path_diversity", Domain: "http", ValueType: "count", Unit: "distinct_paths/window", AllowedScopes: []string{"src_ip"}, BaselineAllowed: true, HighCardinalityRisk: "medium"},
		{ID: "http.method_diversity", Domain: "http", ValueType: "count", Unit: "distinct_methods/window", AllowedScopes: []string{"src_ip"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.request_bytes_per_second", Domain: "http", ValueType: "rate", Unit: "bytes/s", AllowedScopes: []string{"src_ip", "service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.latency_p95_ms", Domain: "http", ValueType: "percentile", Unit: "ms", AllowedScopes: []string{"service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		{ID: "http.upstream_error_rate", Domain: "http", ValueType: "ratio", Unit: "ratio", AllowedScopes: []string{"service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
		// Trust
		{ID: "trust.attestation_fail_rate", Domain: "trust", ValueType: "ratio", Unit: "ratio", AllowedScopes: []string{"node", "service"}, BaselineAllowed: false, HighCardinalityRisk: "low"},
		// Overlay
		{ID: "overlay.session_failure_rate", Domain: "overlay", ValueType: "ratio", Unit: "ratio", AllowedScopes: []string{"src_ip", "service"}, BaselineAllowed: true, HighCardinalityRisk: "low"},
	}
	m := make(map[string]*MetricEntry, len(entries))
	for _, e := range entries {
		m[e.ID] = e
	}
	return m
}

func defaultLabelPolicies() map[string]*LabelPolicyEntry {
	entries := []*LabelPolicyEntry{
		// Allowed
		{ID: "host", Allowed: true, Cardinality: "medium", PIIRisk: "low"},
		{ID: "status_class", Allowed: true, Cardinality: "low", PIIRisk: "none"},
		{ID: "route_group", Allowed: true, Cardinality: "medium", PIIRisk: "low"},
		{ID: "path_template", Allowed: true, Cardinality: "medium", PIIRisk: "medium", RequiresNormalization: true},
		{ID: "service", Allowed: true, Cardinality: "low", PIIRisk: "none"},
		{ID: "protocol", Allowed: true, Cardinality: "low", PIIRisk: "none"},
		// Forbidden
		{ID: "path", Allowed: false, Reason: "raw path has high cardinality and may contain sensitive data"},
		{ID: "uri", Allowed: false, Reason: "raw URI may include query strings and identifiers"},
		{ID: "full_url", Allowed: false, Reason: "high cardinality, may contain credentials or session tokens"},
		{ID: "user_agent", Allowed: false, Reason: "very high cardinality"},
		{ID: "session_id", Allowed: false, Reason: "sensitive and extremely high cardinality"},
		{ID: "request_id", Allowed: false, Reason: "unique per request — guaranteed 1:1 cardinality"},
		{ID: "username", Allowed: false, Reason: "sensitive PII"},
		{ID: "authorization", Allowed: false, Reason: "contains credentials"},
		{ID: "cookie", Allowed: false, Reason: "sensitive and high cardinality"},
	}
	m := make(map[string]*LabelPolicyEntry, len(entries))
	for _, e := range entries {
		m[e.ID] = e
	}
	return m
}

func defaultSignals() map[string]*SignalView {
	return SignalIDsFromStrings([]string{
		// Network heuristic signals (pkg/core/signal constants — source.* namespace)
		"source.pps_high",
		"source.bps_high",
		"source.syn_rate_high",
		"source.scan_suspected",
		"source.rate_limit_drops_sustained",
		// Graph signals
		"graph.new_edge_after_freeze",
		"graph.new_destination_port",
		"graph.new_peer",
		"graph.direction_change",
		"graph.volume_deviation",
		"graph.time_window_deviation",
		"graph.edge_baseline_pps_deviation",
		"graph.edge_baseline_bytes_deviation",
		"graph.edge_baseline_pps_peak_exceeded",
		"graph.edge_baseline_bps_peak_exceeded",
		// Trust signals
		"node.trust_degraded",
		"node.trust_untrusted",
		"node.trust_recovered",
		// HTTP signals (future — httpheuristic)
		"signals.http.credential_stuffing_suspected",
		"signals.http.path_scan_suspected",
		"signals.http.status_5xx_source_pressure",
		"signals.http.auth_fail_rate_high",
	})
}

func defaultCapabilities() map[string]*CapabilityView {
	return CapabilityIDsFromStrings([]string{
		// Enforcement
		"enforce.network.rate_limit",
		"enforce.network.deny",
		"enforce.network.allow",
		"enforce.http.rate_limit_source",
		// Observation
		"observe.signal.emit",
		"observe.metric.baseline",
		// Assessment
		"assess.config.asset",
	})
}
