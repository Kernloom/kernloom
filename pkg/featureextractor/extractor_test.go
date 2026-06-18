// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package featureextractor_test

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/featureextractor"
)

// fakeExtractor is a test-only implementation that satisfies the Extractor interface.
type fakeExtractor struct {
	name      string
	appliesTo []observation.ObservationType
}

func (f *fakeExtractor) Name() string                             { return f.name }
func (f *fakeExtractor) AppliesTo() []observation.ObservationType { return f.appliesTo }

func (f *fakeExtractor) Extract(_ context.Context, obs []observation.Observation) (metric.Batch, error) {
	batch := metric.NewBatch("fake", time.Now(), time.Now())
	for _, o := range obs {
		if v, ok := o.Metrics["packets"]; ok {
			m := metric.New("network.pps", f.name, metric.ScopeSourceIP,
				metric.Subject{Type: string(o.Subject.Kind), Value: o.Subject.ID},
				v, time.Second)
			batch.Add(m)
		}
	}
	return batch, nil
}

// compile-time interface check
var _ featureextractor.Extractor = (*fakeExtractor)(nil)

func TestFakeExtractor_Interface(t *testing.T) {
	ext := &fakeExtractor{
		name:      "fake",
		appliesTo: []observation.ObservationType{observation.TypeFlow},
	}

	if ext.Name() != "fake" {
		t.Errorf("Name: got %q, want %q", ext.Name(), "fake")
	}
	if len(ext.AppliesTo()) != 1 || ext.AppliesTo()[0] != observation.TypeFlow {
		t.Error("AppliesTo: unexpected result")
	}
}

func TestFakeExtractor_Extract(t *testing.T) {
	ext := &fakeExtractor{name: "fake", appliesTo: []observation.ObservationType{observation.TypeFlow}}

	obs := observation.NewObservation(observation.ObservationSource("shield"), observation.TypeFlow, "node-1",
		observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.1"})
	obs.SetMetric("packets", 42.0)

	batch, err := ext.Extract(context.Background(), []observation.Observation{*obs})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if batch.Len() != 1 {
		t.Errorf("expected 1 metric in batch, got %d", batch.Len())
	}
}

func TestFakeExtractor_EmptyObservations(t *testing.T) {
	ext := &fakeExtractor{name: "fake", appliesTo: []observation.ObservationType{observation.TypeFlow}}
	batch, err := ext.Extract(context.Background(), nil)
	if err != nil {
		t.Fatalf("Extract returned error on empty input: %v", err)
	}
	if batch.Len() != 0 {
		t.Errorf("expected 0 metrics for empty observations, got %d", batch.Len())
	}
}
