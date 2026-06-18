// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package learning defines the eligibility model for graph and baseline learning.
// The central concept is an Exclusion: a time-bounded record that prevents an
// entity from being used as training data while enforcement is active against it.
package learning

import "time"

// ExclusionReason describes why learning was suspended for an entity.
type ExclusionReason string

const (
	ReasonEnforcementActive  ExclusionReason = "enforcement_active"  // klshield/netfilter blocking this source
	ReasonRateLimited        ExclusionReason = "rate_limited"        // rate-limit action in effect
	ReasonBlocked            ExclusionReason = "blocked"             // full-block action in effect
	ReasonSuspiciousSignal   ExclusionReason = "suspicious_signal"   // SuspiciousRegistry entry
	ReasonDownstreamCensored ExclusionReason = "downstream_censored" // blocked upstream, downstream data is tainted
	ReasonAdminOverride      ExclusionReason = "admin_override"      // explicit operator exclusion
	ReasonForgePolicy        ExclusionReason = "forge_policy"        // Forge policy excludes this entity
	ReasonCorrelateAlert     ExclusionReason = "correlate_alert"     // Correlate global risk alert
	ReasonAttestationFailure ExclusionReason = "attestation_failure" // Keylime/trustd failure
)

// AppliesTo names the learning dimension that an Exclusion affects.
type AppliesTo string

const (
	AppliesMetricBaseline       AppliesTo = "metric_baseline"       // EWMA baseline updates
	AppliesRelationshipLearning AppliesTo = "relationship_learning" // graph edge promotion
	AppliesGraphAcceptance      AppliesTo = "graph_acceptance"      // new edge candidate acceptance
	AppliesEntityPromotion      AppliesTo = "entity_promotion"      // entity confidence promotion
)

// Exclusion records that learning is suspended for a specific entity/scope.
// Exclusions are time-bounded and scoped to the relevant learning dimensions.
type Exclusion struct {
	ID         string // UUIDv4
	EntityID   string
	EntityKind string

	ScopeType string
	ScopeID   string

	Reason   ExclusionReason
	Severity float64 // 0–1; high severity exclusions block all dimensions

	// DecisionID links back to the decision that triggered this exclusion.
	DecisionID string
	// SignalID links back to the signal that triggered this exclusion.
	SignalID string

	AppliesTo []AppliesTo

	StartsAt  time.Time
	ExpiresAt time.Time

	SourceComponent string
	Status          string // "active", "expired", "revoked"
	Metadata        map[string]string
}
