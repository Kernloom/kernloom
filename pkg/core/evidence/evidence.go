// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package evidence defines the Evidence record — a durable, immutable snapshot
// of a single observation that is retained for forensics and audit, even when
// the observation itself was excluded from learning.
package evidence

import "time"

// Evidence is an immutable record of an observation, retained independently of
// whether the data was used for learning.  It links observations to the entities,
// relationships, and decisions they influenced.
type Evidence struct {
	ID string // UUIDv4

	// ObservationType mirrors observation.ObservationType ("flow", "auth", etc.)
	ObservationType string
	SourceAdapter   string
	SourceNodeID    string

	SubjectEntityID string
	ObjectEntityID  string

	// Summary is a human-readable summary of the observation (free-form KVs).
	Summary map[string]any

	// Metrics are the numeric measurements from the observation.
	Metrics map[string]float64

	// Context carries protocol-level or application-level context.
	Context map[string]string

	ObservedAt time.Time
	IngestedAt time.Time
	ExpiresAt  time.Time

	// LearningEligible records whether this evidence was used for learning
	// at the time of ingest.  False means it was excluded.
	LearningEligible    bool
	LearningBlockReason string
}
