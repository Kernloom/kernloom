// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package relationshiplearner provides the generic relationship learning pipeline.
//
// Flow:
//
//	[]Observation
//	  -> Extractor.Extract()   (produces candidate Relationships)
//	  -> Learner.Learn()       (checks Guard, upserts/promotes, signals on freeze)
//	  -> Store.UpsertRelationship()
package relationshiplearner

import (
	"context"

	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
)

// Extractor derives candidate Relationships from a batch of Observations.
// Each domain (network L3/L4, HTTP, Ziti, Trust) provides its own Extractor.
type Extractor interface {
	// Name identifies the extractor (e.g. "network", "http", "ziti").
	Name() string

	// Extract returns zero or more candidate Relationships from the observations.
	// Candidates have State=candidate; the Learner decides whether to promote them.
	Extract(ctx context.Context, obs []observation.Observation) ([]relationship.Relationship, error)
}
