// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package learning

import (
	"context"

	"github.com/kernloom/kernloom/pkg/core/measurement"
	"github.com/kernloom/kernloom/pkg/core/relationship"
)

// EligibilityDecision is the outcome of a Guard check.
type EligibilityDecision string

const (
	// AllowLearning permits the data point to update baselines and promote relationships.
	AllowLearning EligibilityDecision = "allow_learning"
	// DenyLearning rejects the data point entirely — do not update any baseline or relationship.
	DenyLearning EligibilityDecision = "deny_learning"
	// EvidenceOnly allows the data point to be stored as evidence but not used for learning.
	EvidenceOnly EligibilityDecision = "evidence_only"
	// CandidateOnly allows a new relationship to be stored as a candidate but not promoted.
	CandidateOnly EligibilityDecision = "candidate_only"
)

// CheckResult is returned by Guard check methods.
type CheckResult struct {
	Decision EligibilityDecision
	Reason   ExclusionReason
	Details  string
}

// MetricCheck carries the subject entity and measurement model for a baseline update check.
type MetricCheck struct {
	SubjectEntityID string
	SourceAdapter   string
	Measurement     measurement.Model
}

// RelationshipCheck carries the relationship to be evaluated for learning eligibility.
type RelationshipCheck struct {
	Relationship relationship.Relationship
}

// Guard is the central learning eligibility gate.
// All baseline updates and relationship promotions must be approved by the Guard.
//
// The Guard prevents downstream contamination: if klshield is blocking a source,
// conntrack/nginx data for that same source must not update baselines, even though
// those adapters cannot see the enforcement decision directly.
type Guard interface {
	// CheckMetric returns the learning eligibility for a metric baseline update.
	CheckMetric(ctx context.Context, m MetricCheck) CheckResult

	// CheckRelationship returns the learning eligibility for a relationship state change.
	CheckRelationship(ctx context.Context, r RelationshipCheck) CheckResult

	// AddExclusion records a new exclusion. Thread-safe; updates in-memory and SQLite.
	AddExclusion(ctx context.Context, e Exclusion) error

	// RevokeExclusion removes an exclusion before its natural expiry.
	RevokeExclusion(ctx context.Context, exclusionID string) error

	// IsExcluded returns true if any active exclusion applies to the given entity
	// for the given AppliesTo dimension.
	IsExcluded(ctx context.Context, entityID string, dimension AppliesTo) bool
}
