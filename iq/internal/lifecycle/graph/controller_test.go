// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package graph_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/lifecycle/graph"
	"github.com/kernloom/kernloom/pkg/core/bundle"
)

func readyStats() graph.GraphStats {
	return graph.GraphStats{
		LearnedEdges:      10,
		TotalLearnedEdges: 10,
		EdgesWithBaseline: 8, // 80% coverage
		CleanLearningSec:  uint64((250 * time.Hour).Seconds()),
		BootstrapPhase:    "steady",
		LastBlockEventAt:  time.Time{}, // no recent block events
	}
}

func TestController_InitialPhase(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	c := graph.New(cfg, "", time.Time{})
	if c.Phase() != graph.PhaseLearning {
		t.Errorf("expected learning, got %q", c.Phase())
	}
}

func TestController_DisabledPhase(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = false
	c := graph.New(cfg, "", time.Time{})
	if c.Phase() != graph.PhaseDisabled {
		t.Errorf("expected disabled, got %q", c.Phase())
	}
}

func TestController_RestorePhase(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	c := graph.New(cfg, graph.PhaseFrozenObserve, time.Now())
	if c.Phase() != graph.PhaseFrozenObserve {
		t.Errorf("phase not restored: got %q", c.Phase())
	}
}

func TestReadinessCheck_AllMet(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	c := graph.New(cfg, "", time.Time{})
	blocked := c.ReadinessCheck(readyStats(), time.Now())
	if len(blocked) != 0 {
		t.Errorf("expected no blockers, got %v", blocked)
	}
}

func TestReadinessCheck_NotEnoughEdges(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	cfg.MinLearnedEdges = 20
	c := graph.New(cfg, "", time.Time{})
	stats := readyStats()
	stats.LearnedEdges = 3
	blocked := c.ReadinessCheck(stats, time.Now())
	found := false
	for _, b := range blocked {
		if b == "learned_edges_below_minimum" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected learned_edges_below_minimum blocker, got %v", blocked)
	}
}

func TestReadinessCheck_NotSteady(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	cfg.RequireAutotunePhase = "steady"
	c := graph.New(cfg, "", time.Time{})
	stats := readyStats()
	stats.BootstrapPhase = "bootstrap-3"
	blocked := c.ReadinessCheck(stats, time.Now())
	found := false
	for _, b := range blocked {
		if b == "bootstrap_autotune_not_steady" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected bootstrap_autotune_not_steady blocker, got %v", blocked)
	}
}

func TestReadinessCheck_RecentBlock(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	cfg.RequireNoBlockFor = 24 * time.Hour
	c := graph.New(cfg, "", time.Time{})
	stats := readyStats()
	stats.LastBlockEventAt = time.Now().Add(-1 * time.Hour) // 1h ago
	blocked := c.ReadinessCheck(stats, time.Now())
	found := false
	for _, b := range blocked {
		if b == "recent_block_event" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected recent_block_event blocker, got %v", blocked)
	}
}

func TestTick_AdvancesToFreezeReady(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	cfg.AutoFreeze = true
	c := graph.New(cfg, "", time.Time{})

	changed := c.Tick(readyStats(), time.Now())
	if !changed {
		t.Error("expected phase change to freeze_ready")
	}
	if c.Phase() != graph.PhaseFreezeReady {
		t.Errorf("expected freeze_ready, got %q", c.Phase())
	}
}

func TestMarkProposalSent(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	cfg.AutoFreeze = true
	c := graph.New(cfg, graph.PhaseFreezeReady, time.Now())
	c.MarkProposalSent(time.Now())
	if c.Phase() != graph.PhaseFreezePending {
		t.Errorf("expected freeze_pending, got %q", c.Phase())
	}
}

func TestApplyFreeze(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	c := graph.New(cfg, graph.PhaseFreezePending, time.Now())
	c.ApplyFreeze(time.Now())
	if c.Phase() != graph.PhaseFrozenObserve {
		t.Errorf("expected frozen_observe, got %q", c.Phase())
	}
}

func TestAutoAdvanceToEnforce(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	cfg.ObserveAfterFreeze = 100 * time.Millisecond
	cfg.FinalPhase = graph.PhaseFrozenEnforce
	c := graph.New(cfg, graph.PhaseFrozenObserve, time.Now())
	c.ApplyFreeze(time.Now().Add(-200 * time.Millisecond))
	changed := c.Tick(readyStats(), time.Now())
	if !changed {
		t.Error("expected auto-advance to frozen_enforce")
	}
	if c.Phase() != graph.PhaseFrozenEnforce {
		t.Errorf("expected frozen_enforce, got %q", c.Phase())
	}
}

func TestMaxAction(t *testing.T) {
	bounds := bundle.EnforcementBounds{
		MaxActionDuringBootstrap:     "observe",
		MaxActionDuringFrozenObserve: "observe",
		MaxActionDuringFrozenEnforce: "rate_limit",
	}
	cfg := graph.DefaultConfig()
	cfg.Enabled = true

	tests := []struct {
		phase    string
		expected string
	}{
		{graph.PhaseLearning, "observe"},
		{graph.PhaseFrozenObserve, "observe"},
		{graph.PhaseFrozenEnforce, "rate_limit"},
	}
	for _, tt := range tests {
		c := graph.New(cfg, tt.phase, time.Now())
		got := c.MaxAction(bounds)
		if got != tt.expected {
			t.Errorf("phase=%s: got %q, want %q", tt.phase, got, tt.expected)
		}
	}
}

func TestKLIQGraphMode(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	tests := []struct{ phase, expected string }{
		{graph.PhaseLearning, "learn"},
		{graph.PhaseFrozenObserve, "frozen-observe"},
		{graph.PhaseFrozenEnforce, "frozen-enforce"},
	}
	for _, tt := range tests {
		c := graph.New(cfg, tt.phase, time.Now())
		if got := c.KLIQGraphMode(); got != tt.expected {
			t.Errorf("phase=%s: got %q, want %q", tt.phase, got, tt.expected)
		}
	}
}

func TestBuildProposal(t *testing.T) {
	cfg := graph.DefaultConfig()
	cfg.Enabled = true
	c := graph.New(cfg, graph.PhaseFreezeReady, time.Now())

	stats := readyStats()
	triggers := bundle.TriggerSet{PPS: 420, SYN: 80}
	proposal := c.BuildProposal("test-node", stats, nil, triggers, 1200000, 0.99)

	if proposal.Metadata.NodeID != "test-node" {
		t.Errorf("NodeID: got %q", proposal.Metadata.NodeID)
	}
	if proposal.Spec.GraphSummary.LearnedEdges != 10 {
		t.Errorf("LearnedEdges: got %d", proposal.Spec.GraphSummary.LearnedEdges)
	}
	if proposal.Spec.BootstrapAutotune.Triggers.PPS != 420 {
		t.Errorf("Trigger PPS: got %.1f", proposal.Spec.BootstrapAutotune.Triggers.PPS)
	}
}

func TestFromBundle(t *testing.T) {
	plan := bundle.GraphLifecyclePlan{
		Enabled: true,
		Mode:    "managed",
		Learning: bundle.GraphLearningConfig{
			MinCleanLearning:     "200h",
			MinLearnedEdges:      10,
			MinBaselineCoverage:  0.80,
			RequireAutotunePhase: "steady",
		},
		Freeze: bundle.GraphFreezeConfig{
			AutoFreeze: true,
			Approval:   "forge-auto",
		},
		Rollout: bundle.GraphRolloutConfig{
			ObserveAfterFreeze: "168h",
			FinalPhase:         "frozen_enforce",
		},
	}
	cfg := graph.FromBundle(plan)
	if cfg.MinLearnedEdges != 10 {
		t.Errorf("MinLearnedEdges: got %d", cfg.MinLearnedEdges)
	}
	if cfg.MinBaselineCoverage != 0.80 {
		t.Errorf("MinBaselineCoverage: got %.2f", cfg.MinBaselineCoverage)
	}
	if cfg.ObserveAfterFreeze != 168*time.Hour {
		t.Errorf("ObserveAfterFreeze: got %v", cfg.ObserveAfterFreeze)
	}
}
