// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package ziti provides the OpenZiti relationship extractor.
// It is part of the OpenZiti adapter package (pkg/adapters/openziti/).
//
// It produces "ziti.dials" relationships from TypeConnection observations
// where source=openziti. This is currently a stub/test extractor for pipeline
// validation — a real implementation will add controller API enrichment.
package ziti

import (
	"context"
	"time"

	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const (
	PredicateDials = "ziti.dials"
	SourceOpenZiti = observation.ObservationSource("openziti")
)

// Extractor derives ziti.dials relationships from TypeConnection observations.
type Extractor struct {
	nodeID string
}

// New creates a Ziti Extractor.
func New(nodeID string) *Extractor {
	return &Extractor{nodeID: nodeID}
}

func (e *Extractor) Name() string { return "ziti" }

// Extract returns ziti.dials candidates from Ziti connection observations.
//
// Expected observation:
//
//	Source: SourceOpenZiti
//	Type:   TypeConnection
//	Subject: identity:<id>
//	Object:  service:<name>
//	Attributes: posture, trust_level
func (e *Extractor) Extract(_ context.Context, obs []observation.Observation) ([]relationship.Relationship, error) {
	now := time.Now().UTC()
	var result []relationship.Relationship

	for _, o := range obs {
		if o.Source != SourceOpenZiti {
			continue
		}
		if o.Type != observation.TypeConnection {
			continue
		}
		if o.Subject.ID == "" || o.Object.ID == "" {
			continue
		}

		subjectID := sqlite.StableEntityID(string(entity.KindUser), o.Subject.ID, "")
		objectID := sqlite.StableEntityID(string(entity.KindService), o.Object.ID, "")

		dims := map[string]string{}
		if p := o.Attributes["posture"]; p != "" {
			dims["posture"] = p
		}
		if tl := o.Attributes["trust_level"]; tl != "" {
			dims["trust_level"] = tl
		}

		result = append(result, relationship.Relationship{
			NodeID:          e.nodeID,
			SubjectEntityID: subjectID,
			Predicate:       PredicateDials,
			ObjectEntityID:  objectID,
			Dimensions:      dims,
			DimensionsHash:  sqlite.DimensionsHash(dims),
			State:           relationship.StateCandidate,
			SeenCount:       1,
			DistinctWindows: 1,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			LearnedBy:       relationship.LearnedByLocal,
			SourceAdapter:   string(o.Source),
			SubjectLabel:    o.Subject.ID,
			SubjectKind:     string(entity.KindUser),
			ObjectLabel:     o.Object.ID,
			ObjectKind:      string(entity.KindService),
		})
	}
	return result, nil
}
