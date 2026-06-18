// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package reason

// Reason codes are machine-readable explanations for observations, signals, and decisions.
// They form a standard vocabulary that can be understood by policy engines, correlation systems,
// and audit/compliance tools.
//
// Naming convention: snake_case, prefixed by domain for easier searching/filtering.

// ===== Heuristic scoring reasons (KLIQ) =====

// PPS-related reasons
const (
	PPSHigh     = "pps_high"      // Packets per second exceeds threshold
	PPSVeryHigh = "pps_very_high" // Packets per second extremely elevated
)

// BPS-related reasons
const (
	BPSHigh = "bps_high" // Bytes per second exceeds threshold (large-packet flood or exfil)
)

// SYN-related reasons
const (
	SYNRateHigh     = "syn_rate_high" // SYN packet rate exceeds threshold (SYN flood pattern)
	SYNRateVeryHigh = "syn_rate_very_high"
)

// Scan-related reasons
const (
	ScanRateHigh      = "scan_rate_high" // Destination port diversity exceeds threshold
	PortScanSuspected = "port_scan_suspected"
)

// Rate-limit signal reasons
const (
	RateLimitDropsSustained = "rate_limit_drops_sustained" // RL drops observed while in HARD
	RateLimitDropsResume    = "rate_limit_drops_resume"    // RL drops reappeared
)

// ===== Graph learning reasons =====

const (
	GraphNewEdgeAfterFreeze    = "graph_new_edge_after_freeze"    // Edge appears post-freeze
	GraphNewRelationshipDim    = "graph_new_relationship_dim"     // Known subject/object, new dimension
	GraphNewPeer               = "graph_new_peer"                 // Completely new peer
	GraphDirectionChange       = "graph_direction_change"         // Relationship direction changed
	GraphMetricDeviation       = "graph_metric_deviation"         // Unusual metric for known edge
	GraphTimeWindowDeviation   = "graph_time_window_deviation"    // Off-hours relationship
	GraphEdgeCandidate         = "graph_edge_candidate"           // First observation of edge
	GraphEdgeLearned           = "graph_edge_learned"             // Edge promoted to learned
	GraphEdgeFrozen            = "graph_edge_frozen"              // Edge included in frozen baseline
	GraphEdgeMetricPeakExceeds = "graph_edge_metric_peak_exceeds" // Metric exceeded learned peak
)

// ===== Trust/Integrity reasons =====

const (
	TrustAttestationOK     = "trust_attestation_ok"     // Keylime attestation passed
	TrustAttestationFailed = "trust_attestation_failed" // Keylime attestation failed
	TrustAssertionExpired  = "trust_assertion_expired"  // Trust assertion TTL exceeded
	TrustAssertionFresh    = "trust_assertion_fresh"    // Trust assertion recently issued
	TrustIMAViolation      = "trust_ima_violation"      // IMA measurement list violation
	TrustPCRMismatch       = "trust_pcr_mismatch"       // PCR does not match expected
	TrustTPMUnavailable    = "trust_tpm_unavailable"    // TPM not present or unreachable
	TrustMode              = "trust_mode"               // Generic trust mode info
)

// ===== Policy/Signature reasons =====

const (
	PolicyPackSignatureOK       = "policy_pack_signature_ok"       // Signature verification passed
	PolicyPackSignatureBad      = "policy_pack_signature_bad"      // Signature invalid
	PolicyPackRollbackAttempt   = "policy_pack_rollback_attempt"   // Version downgrade detected
	PolicyPackExpired           = "policy_pack_expired"            // Pack is past expiration
	PolicyPackCapabilityMissing = "policy_pack_capability_missing" // Required capability unavailable
	PolicyPackTargetMismatch    = "policy_pack_target_mismatch"    // Target selector doesn't match node
	PolicyViolation             = "policy_violation"               // Decision violates policy
)

// ===== Global/Correlate reasons =====

const (
	CampaignDistributedScan  = "campaign_distributed_scan"  // Slow scan across fleet
	CampaignWormlikeBehavior = "campaign_wormlike_behavior" // Lateral movement pattern
	CampaignDataExfil        = "campaign_data_exfil"        // Unusual egress across fleet
	GlobalRiskSignal         = "global_risk_signal"         // Global signal elevated risk
	FleetAnomalyDetected     = "fleet_anomaly_detected"     // Cross-node anomaly
	ServiceAnomalyDetected   = "service_anomaly_detected"   // Service-level anomaly
)

// ===== Local autonomy reasons =====

const (
	LocalAutonomyAllowed   = "local_autonomy_allowed"   // Local enforcement permitted
	LocalAutonomyDenied    = "local_autonomy_denied"    // Local enforcement blocked by policy
	LocalAutonomyThrottled = "local_autonomy_throttled" // Rate-limited by policy
	SeverityBelowThreshold = "severity_below_threshold" // Too low to trigger action
	TrustGateFailed        = "trust_gate_failed"        // Trust score below minimum
)

// ===== Whitelist/exemption reasons =====

const (
	WhitelistMatch = "whitelist_match" // Entity is whitelisted
	FeedbackMatch  = "feedback_match"  // Entity has feedback exemption
	ExemptionMatch = "exemption_match" // Generic exemption applied
)

// ===== Enforcement state reasons =====

const (
	EnforcementStateObserve   = "enforcement_state_observe"    // OBSERVE level
	EnforcementStateSoftLimit = "enforcement_state_soft_limit" // SOFT rate limit
	EnforcementStateHardLimit = "enforcement_state_hard_limit" // HARD rate limit
	EnforcementStateBlocked   = "enforcement_state_blocked"    // BLOCK level
	EnforcementStateCooldown  = "enforcement_state_cooldown"   // In cooldown period
	EnforcementStateExpired   = "enforcement_state_expired"    // Action expired
)

// ===== Bootstrap/auto-tune reasons =====

const (
	BootstrapPhase1   = "bootstrap_phase_1"   // Bootstrap phase 1 active
	BootstrapPhase2   = "bootstrap_phase_2"   // Bootstrap phase 2 active
	BootstrapPhase3   = "bootstrap_phase_3"   // Bootstrap phase 3 active
	AutoTuneApplied   = "autotune_applied"    // Autotune threshold updated
	AutoTuneSkipped   = "autotune_skipped"    // Autotune skipped (insufficient data)
	LowConfidenceData = "low_confidence_data" // Data quality insufficient
)

// ===== Health/operational reasons =====

const (
	AdapterHealthy    = "adapter_healthy"     // Adapter operational
	AdapterDegraded   = "adapter_degraded"    // Adapter has warnings
	AdapterFailing    = "adapter_failing"     // Adapter unavailable
	MapReadError      = "map_read_error"      // eBPF map read failed
	StateRestored     = "state_restored"      // State loaded from persistence
	StateNotAvailable = "state_not_available" // Previous state not found
)

// IsValidReasonCode checks if a string is a known reason code.
// This is a simple check; production might use a registry.
func IsValidReasonCode(code string) bool {
	// In production, maintain a set of all valid codes.
	// For now, just check it's non-empty.
	return code != ""
}
