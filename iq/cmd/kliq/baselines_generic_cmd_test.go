// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/entity"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestDeleteMetricBaselinesDryRunKeepsRows(t *testing.T) {
	ctx := context.Background()
	s := openBaselineDeleteTestStore(t)
	defer s.Close()

	upsertBaselineForDeleteTest(t, s, "172.21.112.1", "network.xdp.edge.packets_per_second", "relationship", "edge-a", "xdp", "candidate")
	upsertBaselineForDeleteTest(t, s, "172.21.112.2", "application.http.requests_per_second", "service", "svc-a", "app", "candidate")

	n, err := deleteMetricBaselines(ctx, s, baselineDeleteFilters{
		Metric: "network.xdp.edge",
		Scope:  "relationship",
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run delete: %v", err)
	}
	if n != 1 {
		t.Fatalf("dry-run matched %d rows, want 1", n)
	}
	if got := countBaselinesForDeleteTest(t, s); got != 2 {
		t.Fatalf("dry-run deleted rows: got %d rows, want 2", got)
	}
}

func TestDeleteMetricBaselinesFiltersBySubjectAndSource(t *testing.T) {
	ctx := context.Background()
	s := openBaselineDeleteTestStore(t)
	defer s.Close()

	upsertBaselineForDeleteTest(t, s, "172.21.112.1", "network.xdp.edge.packets_per_second", "relationship", "edge-a", "xdp", "candidate")
	upsertBaselineForDeleteTest(t, s, "172.21.112.2", "network.xdp.edge.packets_per_second", "relationship", "edge-b", "xdp", "candidate")
	upsertBaselineForDeleteTest(t, s, "172.21.112.1", "network.xdp.edge.bytes_per_second", "relationship", "edge-a", "conntrack", "candidate")

	n, err := deleteMetricBaselines(ctx, s, baselineDeleteFilters{
		Metric:      "network.xdp.edge",
		Scope:       "relationship",
		SourceClass: "xdp",
		Subject:     "172.21.112.1",
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d rows, want 1", n)
	}
	if got := countBaselinesForDeleteTest(t, s); got != 2 {
		t.Fatalf("remaining rows: got %d, want 2", got)
	}
}

func TestDeleteMetricBaselinesRequiresFilterUnlessAll(t *testing.T) {
	ctx := context.Background()
	s := openBaselineDeleteTestStore(t)
	defer s.Close()

	upsertBaselineForDeleteTest(t, s, "172.21.112.1", "network.xdp.edge.packets_per_second", "relationship", "edge-a", "xdp", "candidate")

	if _, err := deleteMetricBaselines(ctx, s, baselineDeleteFilters{}); err == nil {
		t.Fatal("expected unfiltered delete to fail")
	}
	if got := countBaselinesForDeleteTest(t, s); got != 1 {
		t.Fatalf("guard should keep row, got %d rows", got)
	}

	n, err := deleteMetricBaselines(ctx, s, baselineDeleteFilters{All: true})
	if err != nil {
		t.Fatalf("delete all: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d rows, want 1", n)
	}
	if got := countBaselinesForDeleteTest(t, s); got != 0 {
		t.Fatalf("all delete left %d rows, want 0", got)
	}
}

func TestSortBaselineListRows(t *testing.T) {
	rows := []baselineListRow{
		{MetricID: "metric.b", Subject: "src-b", Observations: 2, Baseline: 90, LastUpdated: time.Unix(20, 0)},
		{MetricID: "metric.a", Subject: "src-a", Observations: 9, Baseline: 10, LastUpdated: time.Unix(10, 0)},
	}

	key, desc, err := parseBaselineSortSpec("-obs")
	if err != nil {
		t.Fatalf("parse sort: %v", err)
	}
	sortBaselineListRows(rows, key, desc)
	if rows[0].Subject != "src-a" {
		t.Fatalf("expected src-a first by descending observations, got %s", rows[0].Subject)
	}

	key, desc, err = parseBaselineSortSpec("baseline")
	if err != nil {
		t.Fatalf("parse sort: %v", err)
	}
	sortBaselineListRows(rows, key, desc)
	if rows[0].Subject != "src-a" {
		t.Fatalf("expected src-a first by ascending baseline, got %s", rows[0].Subject)
	}
}

func openBaselineDeleteTestStore(t *testing.T) *sstore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := sstore.Open(sstore.DefaultConfig(path))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	return s
}

func upsertBaselineForDeleteTest(
	t *testing.T,
	s *sstore.Store,
	subjectID, metricID, scopeType, scopeID, sourceClass, state string,
) {
	t.Helper()
	ctx := context.Background()
	e := entity.Entity{
		Kind:          entity.KindIP,
		ID:            subjectID,
		DisplayName:   subjectID,
		SourceAdapter: sourceClass,
		Confidence:    1,
	}
	if err := s.UpsertEntity(ctx, e); err != nil {
		t.Fatalf("upsert entity: %v", err)
	}
	subjectStableID := sstore.StableEntityID(string(entity.KindIP), subjectID, "")
	if err := s.UpsertBaseline(ctx, sstore.BaselineRow{
		Key: baseline.Key{
			MetricID:        metricID,
			ScopeType:       scopeType,
			ScopeID:         scopeID,
			SubjectEntityID: subjectStableID,
			SourceClass:     sourceClass,
			TruthClass:      "primary_packet_observation",
			WindowSeconds:   60,
		},
		State:        state,
		EWMAState:    map[string]any{"ewma": 42.0, "peak": 99.0, "confidence": 0.5},
		Observations: 7,
		LastUpdated:  time.Now(),
	}); err != nil {
		t.Fatalf("upsert baseline: %v", err)
	}
}

func countBaselinesForDeleteTest(t *testing.T, s *sstore.Store) int64 {
	t.Helper()
	var n int64
	if err := s.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM metric_baselines`).Scan(&n); err != nil {
		t.Fatalf("count baselines: %v", err)
	}
	return n
}
