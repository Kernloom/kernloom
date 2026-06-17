// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package http provides the HTTP relationship extractor.
// It produces "http.calls" and "http.uses_route" relationships from TypeHTTP observations.
// This is a fake/test extractor for validating the generic pipeline with L7 data.
package http

import (
	"context"
	"time"

	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const (
	PredicateCalls    = "http.calls"
	PredicateUsesRoute = "http.uses_route"
)

// Extractor derives HTTP relationships from TypeHTTP observations.
type Extractor struct {
	nodeID string
}

// New creates an HTTP Extractor.
func New(nodeID string) *Extractor {
	return &Extractor{nodeID: nodeID}
}

func (e *Extractor) Name() string { return "http" }

// Extract returns http.calls and http.uses_route candidates from HTTP observations.
//
// Expected attributes:
//
//	http_method  — e.g. "GET"
//	http_route   — e.g. "/api/orders/{id}"
//	http_status  — e.g. "200"
func (e *Extractor) Extract(_ context.Context, obs []observation.Observation) ([]relationship.Relationship, error) {
	now := time.Now().UTC()
	var result []relationship.Relationship

	for _, o := range obs {
		if o.Type != observation.TypeHTTP {
			continue
		}
		if o.Subject.ID == "" || o.Object.ID == "" {
			continue
		}

		subjectID := sqlite.StableEntityID(string(o.Subject.Kind), o.Subject.ID, o.Subject.Namespace)
		objectID := sqlite.StableEntityID(string(o.Object.Kind), o.Object.ID, o.Object.Namespace)

		// http.calls: subject workload → object service
		callDims := map[string]string{}
		if st := o.Attributes["http_status"]; st != "" {
			callDims["http_status_class"] = st[:1] + "xx"
		}
		result = append(result, relationship.Relationship{
			NodeID:          e.nodeID,
			SubjectEntityID: subjectID,
			Predicate:       PredicateCalls,
			ObjectEntityID:  objectID,
			Dimensions:      callDims,
			DimensionsHash:  sqlite.DimensionsHash(callDims),
			State:           relationship.StateCandidate,
			SeenCount:       1,
			DistinctWindows: 1,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			LearnedBy:       relationship.LearnedByLocal,
			SourceAdapter:   string(o.Source),
			SubjectLabel:    o.Subject.ID,
			SubjectKind:     string(o.Subject.Kind),
			ObjectLabel:     o.Object.ID,
			ObjectKind:      string(o.Object.Kind),
		})

		// http.uses_route: subject → http_route entity (if route present)
		method := o.Attributes["http_method"]
		route := o.Attributes["http_route"]
		if method != "" && route != "" {
			routeID := method + " " + route
			routeEntityID := sqlite.StableEntityID(string(entity.KindHTTPRoute), routeID, "")
			routeDims := map[string]string{"method": method, "route": route}
			result = append(result, relationship.Relationship{
				NodeID:          e.nodeID,
				SubjectEntityID: subjectID,
				Predicate:       PredicateUsesRoute,
				ObjectEntityID:  routeEntityID,
				Dimensions:      routeDims,
				DimensionsHash:  sqlite.DimensionsHash(routeDims),
				State:           relationship.StateCandidate,
				SeenCount:       1,
				DistinctWindows: 1,
				FirstSeenAt:     now,
				LastSeenAt:      now,
				LearnedBy:       relationship.LearnedByLocal,
				SourceAdapter:   string(o.Source),
				SubjectLabel:    o.Subject.ID,
				SubjectKind:     string(o.Subject.Kind),
				ObjectLabel:     routeID,
				ObjectKind:      string(entity.KindHTTPRoute),
			})
		}
	}
	return result, nil
}
