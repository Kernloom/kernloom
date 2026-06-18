// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package measurement defines how observations are characterised with respect to
// their truth quality and visibility point.  These semantics are embedded in
// every baseline key so that baselines from different adapters are NEVER mixed.
package measurement

import "time"

// Type describes the mathematical nature of a measured value.
type Type string

const (
	// TypeCounterDelta is a rate derived from a hardware counter (e.g. XDP packet count).
	TypeCounterDelta Type = "counter_delta"
	// TypeSnapshotGauge is a point-in-time state snapshot (e.g. conntrack table entry).
	TypeSnapshotGauge Type = "snapshot_gauge"
	// TypeEventCounterDelta is derived from counted events (e.g. nginx log lines per window).
	TypeEventCounterDelta Type = "event_counter_delta"
	// TypeLogCounterDelta is derived from log parsing (e.g. syslog authentication failures).
	TypeLogCounterDelta Type = "log_counter_delta"
)

// TruthClass describes the epistemic quality of an observation.
// Baselines must NEVER be shared across truth classes.
type TruthClass string

const (
	// TruthPrimaryPacketObservation is direct, synchronous, per-packet telemetry (XDP hook).
	// This is the ground truth for network traffic.
	TruthPrimaryPacketObservation TruthClass = "primary_packet_observation"

	// TruthSampledState is indirect observation via OS state tables (conntrack).
	// May miss short-lived flows; not suitable for PPS baselines.
	TruthSampledState TruthClass = "sampled_state"

	// TruthApplicationObserved is self-reported by an application (nginx, ziti).
	// Subject to application-level filtering, buffering and bias.
	TruthApplicationObserved TruthClass = "application_observed"

	// TruthIdentityObserved comes from an identity/auth plane (LDAP, Ziti identity).
	TruthIdentityObserved TruthClass = "identity_observed"

	// TruthTrustObserved comes from a TPM/attestation plane (Keylime/trustd).
	TruthTrustObserved TruthClass = "trust_observed"

	// TruthDerived is computed from other observations (e.g. Correlate risk score).
	TruthDerived TruthClass = "derived"
)

// VisibilityPoint describes where in the network/software stack the observation
// was captured.  Different visibility points see fundamentally different traffic
// volumes and patterns.
type VisibilityPoint string

const (
	// VisibilityPreStackIngress is before the Linux network stack — XDP hook.
	// Sees all packets including those dropped by the stack.
	VisibilityPreStackIngress VisibilityPoint = "pre_stack_ingress"

	// VisibilityPostXDPConntrack is after XDP, from the conntrack table.
	// Misses XDP-dropped packets and very short flows.
	VisibilityPostXDPConntrack VisibilityPoint = "post_xdp_conntrack"

	// VisibilityApplicationEdge is at the application boundary (nginx, reverse proxy).
	// Only sees application-level connections that passed all lower layers.
	VisibilityApplicationEdge VisibilityPoint = "application_edge"

	// VisibilityIdentityPlane is at the identity/auth layer (Ziti, LDAP).
	VisibilityIdentityPlane VisibilityPoint = "identity_plane"

	// VisibilityTrustPlane is at the attestation layer (Keylime/trustd).
	VisibilityTrustPlane VisibilityPoint = "trust_plane"
)

// Model carries the full measurement semantics for an observation or baseline key.
// When stored on a baseline key, it ensures baselines are adapter-isolated.
type Model struct {
	SourceAdapter   string // e.g. "klshield", "conntrack", "nginx", "ziti"
	SourceClass     string // e.g. "xdp", "proc_net", "access_log"
	SourceLayer     string // e.g. "l3", "l7", "identity"
	VisibilityPoint VisibilityPoint
	Type            Type
	TruthClass      TruthClass

	// Windowed observations carry the time bounds of the measurement window.
	Windowed    bool
	WindowStart time.Time
	WindowEnd   time.Time

	ObservedAt time.Time
	IngestedAt time.Time

	// Coverage is the fraction of the window that was actually observed (0–1).
	// 1.0 for XDP (every packet); <1.0 for conntrack (poll interval gaps).
	Coverage float64

	// Confidence is the overall quality score of this measurement (0–1).
	Confidence float64

	// BaselineAllowed is false when enforcement was active during this window
	// and the data should be treated as evidence-only (not learned).
	BaselineAllowed bool

	// MergeStrategy describes how this measurement can be combined with others
	// from the same adapter across windows: "sum", "ewma", "max", "last".
	MergeStrategy string
}
