// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package ziti_test

import (
	"context"
	"testing"

	zitiext "github.com/kernloom/kernloom/pkg/adapters/openziti/relationshiplearner"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

func zitiObs(identity, service, posture, trustLevel string) observation.Observation {
	return observation.Observation{
		Source:  zitiext.SourceOpenZiti,
		Type:    observation.TypeConnection,
		Subject: observation.EntityRef{Kind: observation.KindUser, ID: identity},
		Object:  observation.EntityRef{Kind: observation.KindService, ID: service},
		Attributes: map[string]string{
			"posture":     posture,
			"trust_level": trustLevel,
		},
		Metrics: map[string]float64{"dials": 1},
	}
}

func TestZitiExtract_Dials(t *testing.T) {
	e := zitiext.New("node-1")
	obs := []observation.Observation{zitiObs("laptop-adrian", "nas-admin", "healthy", "attested")}
	rels, err := e.Extract(context.Background(), obs)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("want 1 relationship, got %d", len(rels))
	}
	if rels[0].Predicate != zitiext.PredicateDials {
		t.Errorf("want ziti.dials, got %q", rels[0].Predicate)
	}
	if rels[0].Dimensions["posture"] != "healthy" {
		t.Errorf("dimension posture: want healthy, got %q", rels[0].Dimensions["posture"])
	}
}

func TestZitiExtract_SkipsNonZiti(t *testing.T) {
	e := zitiext.New("node-1")
	obs := []observation.Observation{{
		Source:  observation.ObservationSource("shield"),
		Type:    observation.TypeConnection,
		Subject: observation.EntityRef{ID: "x"},
		Object:  observation.EntityRef{ID: "y"},
	}}
	rels, _ := e.Extract(context.Background(), obs)
	if len(rels) != 0 {
		t.Errorf("non-ziti should be ignored, got %d", len(rels))
	}
}
