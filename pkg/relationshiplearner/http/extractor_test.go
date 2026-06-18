// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package http_test

import (
	"context"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/observation"
	httpext "github.com/kernloom/kernloom/pkg/relationshiplearner/http"
)

func httpObs(subj, obj, method, route, status string) observation.Observation {
	return observation.Observation{
		Type:    observation.TypeHTTP,
		Source:  observation.ObservationSource("nginx"),
		Subject: observation.EntityRef{Kind: observation.KindWorkload, ID: subj},
		Object:  observation.EntityRef{Kind: observation.KindService, ID: obj},
		Attributes: map[string]string{
			"http_method": method,
			"http_route":  route,
			"http_status": status,
		},
	}
}

func TestHTTPExtract_CallsAndRoute(t *testing.T) {
	e := httpext.New("node-1")
	obs := []observation.Observation{httpObs("frontend-api", "orders-api", "GET", "/api/orders/{id}", "200")}
	rels, err := e.Extract(context.Background(), obs)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// Expect http.calls + http.uses_route
	if len(rels) != 2 {
		t.Fatalf("want 2 relationships (calls + uses_route), got %d", len(rels))
	}
	preds := map[string]bool{}
	for _, r := range rels {
		preds[r.Predicate] = true
	}
	if !preds[httpext.PredicateCalls] {
		t.Error("missing http.calls")
	}
	if !preds[httpext.PredicateUsesRoute] {
		t.Error("missing http.uses_route")
	}
}

func TestHTTPExtract_SkipsNonHTTP(t *testing.T) {
	e := httpext.New("node-1")
	obs := []observation.Observation{{Type: observation.TypeFlow, Subject: observation.EntityRef{ID: "x"}, Object: observation.EntityRef{ID: "y"}}}
	rels, _ := e.Extract(context.Background(), obs)
	if len(rels) != 0 {
		t.Errorf("non-HTTP observation should be ignored, got %d", len(rels))
	}
}

func TestHTTPExtract_NoRoute_OnlyCalls(t *testing.T) {
	e := httpext.New("node-1")
	obs := []observation.Observation{httpObs("frontend", "backend", "", "", "201")}
	rels, _ := e.Extract(context.Background(), obs)
	// No route → only http.calls
	if len(rels) != 1 {
		t.Fatalf("want 1 (calls only), got %d", len(rels))
	}
	if rels[0].Predicate != httpext.PredicateCalls {
		t.Errorf("want http.calls, got %q", rels[0].Predicate)
	}
}
