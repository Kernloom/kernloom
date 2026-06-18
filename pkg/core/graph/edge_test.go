// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package graph_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/graph"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

func srcRef(id string) observation.EntityRef {
	return observation.EntityRef{Kind: observation.KindIP, ID: id}
}

func dstRef(id string) observation.EntityRef {
	return observation.EntityRef{Kind: observation.KindIP, ID: id}
}

func networkDims(port string) map[string]string {
	return map[string]string{"protocol": "tcp", "destination_port": port}
}

func TestNewEdge_InitialState(t *testing.T) {
	now := time.Now()
	e := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"),
		"network.connects_to", networkDims("443"), graph.DirectionEgress, now)

	if e.State != graph.EdgeCandidate {
		t.Errorf("expected candidate, got %s", e.State)
	}
	if e.SeenCount != 1 {
		t.Errorf("expected SeenCount=1, got %d", e.SeenCount)
	}
	if e.ID == "" {
		t.Error("expected non-empty ID")
	}
	if e.NodeID != "node-1" {
		t.Errorf("expected node-1, got %s", e.NodeID)
	}
}

func TestEdge_Key_Deduplication(t *testing.T) {
	now := time.Now()
	e1 := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, now)
	e2 := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, now)

	if e1.Key() != e2.Key() {
		t.Error("same flow should produce equal EdgeKey")
	}

	e3 := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("80"), graph.DirectionEgress, now)
	if e1.Key() == e3.Key() {
		t.Error("different dimensions should produce different EdgeKey")
	}
}

func TestEdge_ShouldPromote(t *testing.T) {
	cfg := graph.PromotionConfig{
		MinSeenCount:       5,
		MinDistinctWindows: 3,
		MinFirstSeenAge:    10 * time.Minute,
	}
	now := time.Now()
	old := now.Add(-15 * time.Minute)

	t.Run("not enough seen count", func(t *testing.T) {
		e := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, old)
		e.SeenCount = 3
		e.DistinctWindows = 5
		if e.ShouldPromote(cfg, now) {
			t.Error("should not promote with insufficient SeenCount")
		}
	})

	t.Run("not enough distinct windows", func(t *testing.T) {
		e := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, old)
		e.SeenCount = 10
		e.DistinctWindows = 2
		if e.ShouldPromote(cfg, now) {
			t.Error("should not promote with insufficient DistinctWindows")
		}
	})

	t.Run("too young", func(t *testing.T) {
		e := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, now)
		e.SeenCount = 10
		e.DistinctWindows = 5
		if e.ShouldPromote(cfg, now) {
			t.Error("should not promote edge that is too young")
		}
	})

	t.Run("ready to promote", func(t *testing.T) {
		e := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, old)
		e.SeenCount = 10
		e.DistinctWindows = 5
		if !e.ShouldPromote(cfg, now) {
			t.Error("should promote edge meeting all criteria")
		}
	})

	t.Run("only candidate edges are promoted", func(t *testing.T) {
		e := graph.NewEdge("node-1", srcRef("1.2.3.4"), dstRef("10.0.0.1"), "network.connects_to", networkDims("443"), graph.DirectionEgress, old)
		e.SeenCount = 10
		e.DistinctWindows = 5
		e.State = graph.EdgeLearned
		if e.ShouldPromote(cfg, now) {
			t.Error("should not re-promote a learned edge")
		}
	})
}
