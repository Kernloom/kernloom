// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package graph implements the managed-mode graph lifecycle controller.
// It tracks learning progress, computes freeze readiness, builds baseline
// proposals, and hot-switches the graph mode without requiring a KLIQ restart.
//
// Lifecycle phases:
//
//	disabled       → graph learner not started
//	learning       → collecting edges and edge baselines
//	freeze_ready   → all readiness conditions met, waiting for Forge approval
//	freeze_pending → proposal uploaded, waiting for Forge confirmation
//	frozen_observe → graph frozen, new edges generate signals (no enforcement)
//	frozen_enforce → frozen, new edges generate enforcement actions
package graph

import (
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/pkg/core/bundle"
)

// Phase constants.
const (
	PhaseDisabled      = "disabled"
	PhaseLearning      = "learning"
	PhaseFreezeReady   = "freeze_ready"
	PhaseFreezePending = "freeze_pending"
	PhaseFrozenObserve = "frozen_observe"
	PhaseFrozenEnforce = "frozen_enforce"
)

// GraphStats is provided by the caller each tick to let the controller
// assess freeze readiness.
type GraphStats struct {
	LearnedEdges          int
	CandidateEdges        int
	ApprovedEdges         int
	DeniedEdges           int
	FrozenEdges           int
	EdgesWithBaseline     int
	TotalLearnedEdges     int // used for baseline coverage denominator
	LastBlockEventAt      time.Time
	CleanLearningSec      uint64
	BootstrapPhase        string // "steady" unlocks freeze
	TrackedSources        int
	HighConfidenceSources int
	AvgConfidence         float64
}

// Config is derived from a RuntimeBundle graph lifecycle.
type Config struct {
	Enabled              bool
	Mode                 string // managed | local-auto
	MinCleanLearning     time.Duration
	MinLearnedEdges      int
	MinBaselineCoverage  float64
	RequireAutotunePhase string // empty = no requirement; "steady" = wait for steady
	RequireNoBlockFor    time.Duration
	AutoFreeze           bool
	Approval             string // forge-auto | forge-manual | local
	ProposalUpload       bool
	IncludeEdgeBaselines bool
	ObserveAfterFreeze   time.Duration
	FinalPhase           string
}

// DefaultConfig returns safe defaults for managed graph lifecycle.
func DefaultConfig() Config {
	return Config{
		Enabled:              false, // opt-in
		Mode:                 "managed",
		MinCleanLearning:     240 * time.Hour,
		MinLearnedEdges:      5,
		MinBaselineCoverage:  0.70,
		RequireAutotunePhase: "steady",
		RequireNoBlockFor:    24 * time.Hour,
		AutoFreeze:           true,
		Approval:             "forge-auto",
		ProposalUpload:       true,
		IncludeEdgeBaselines: true,
		ObserveAfterFreeze:   7 * 24 * time.Hour,
		FinalPhase:           PhaseFrozenEnforce,
	}
}

// FromBundle derives a Config from a contracts RuntimeBundle graph lifecycle.
func FromBundle(plan contracts.GraphLifecycle) Config {
	c := DefaultConfig()
	c.Enabled = lifecycleModeEnabled(plan.Mode)
	if plan.Mode != "" {
		c.Mode = plan.Mode
	}
	if plan.MinCleanLearning.Duration > 0 {
		c.MinCleanLearning = plan.MinCleanLearning.Duration
	}
	if plan.MinLearnedEdges > 0 {
		c.MinLearnedEdges = plan.MinLearnedEdges
	}
	if plan.MinBaselineCoverage > 0 {
		c.MinBaselineCoverage = plan.MinBaselineCoverage
	}
	if plan.RequireNoBlockFor.Duration > 0 {
		c.RequireNoBlockFor = plan.RequireNoBlockFor.Duration
	}
	if plan.FreezeApproval != "" {
		c.Approval = plan.FreezeApproval
	}
	if plan.IncludeEdgeBaselines {
		c.IncludeEdgeBaselines = true
	}
	if plan.ObserveAfterFreeze.Duration > 0 {
		c.ObserveAfterFreeze = plan.ObserveAfterFreeze.Duration
	}
	if plan.FinalPhase != "" {
		c.FinalPhase = plan.FinalPhase
	}
	return c
}

func lifecycleModeEnabled(mode string) bool {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "", "disabled", "off", "none":
		return false
	default:
		return true
	}
}

// Controller manages the graph lifecycle state machine.
type Controller struct {
	cfg            Config
	phase          string
	startedAt      time.Time
	frozenAt       time.Time
	proposalSentAt time.Time
}

// New creates a Controller. If persistedPhase is non-empty it restores that phase.
func New(cfg Config, persistedPhase string, startedAt time.Time) *Controller {
	phase := PhaseLearning
	if !cfg.Enabled {
		phase = PhaseDisabled
	} else if persistedPhase != "" {
		phase = persistedPhase
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	return &Controller{cfg: cfg, phase: phase, startedAt: startedAt}
}

// Phase returns the current lifecycle phase.
func (c *Controller) Phase() string { return c.phase }

// ReadinessCheck evaluates freeze readiness conditions against current stats.
// Returns a list of blocking reasons; empty means ready to freeze.
func (c *Controller) ReadinessCheck(stats GraphStats, now time.Time) []string {
	if c.phase != PhaseLearning {
		return nil
	}
	var blocked []string

	cleanSec := time.Duration(stats.CleanLearningSec) * time.Second
	if cleanSec < c.cfg.MinCleanLearning {
		blocked = append(blocked, "clean_learning_duration_insufficient")
	}
	if stats.LearnedEdges < c.cfg.MinLearnedEdges {
		blocked = append(blocked, "learned_edges_below_minimum")
	}
	if c.cfg.MinBaselineCoverage > 0 && stats.TotalLearnedEdges > 0 {
		coverage := float64(stats.EdgesWithBaseline) / float64(stats.TotalLearnedEdges)
		if coverage < c.cfg.MinBaselineCoverage {
			blocked = append(blocked, "edge_baseline_coverage_below_minimum")
		}
	}
	if c.cfg.RequireAutotunePhase == "steady" && stats.BootstrapPhase != "steady" {
		blocked = append(blocked, "bootstrap_autotune_not_steady")
	}
	if c.cfg.RequireNoBlockFor > 0 && !stats.LastBlockEventAt.IsZero() {
		if now.Sub(stats.LastBlockEventAt) < c.cfg.RequireNoBlockFor {
			blocked = append(blocked, "recent_block_event")
		}
	}
	return blocked
}

// Tick is called each tick with current graph stats and may advance the phase.
// Returns true if the phase changed (caller should persist state).
func (c *Controller) Tick(stats GraphStats, now time.Time) bool {
	if c.phase == PhaseDisabled || c.phase == PhaseFrozenEnforce {
		return false
	}

	switch c.phase {
	case PhaseLearning:
		if c.cfg.AutoFreeze && len(c.ReadinessCheck(stats, now)) == 0 {
			c.phase = PhaseFreezeReady
			return true
		}
	case PhaseFreezeReady:
		if c.cfg.Approval == "local" || c.cfg.Approval == "forge-auto" {
			// Proposal upload is triggered externally; controller advances to pending
			// when the caller tells it the proposal was sent.
		}
	case PhaseFrozenObserve:
		// Advance to frozen-enforce after observe duration, if configured.
		if c.cfg.FinalPhase == PhaseFrozenEnforce &&
			c.cfg.ObserveAfterFreeze > 0 &&
			!c.frozenAt.IsZero() &&
			now.Sub(c.frozenAt) >= c.cfg.ObserveAfterFreeze {
			c.phase = PhaseFrozenEnforce
			return true
		}
	}
	return false
}

// MarkProposalSent advances the phase from freeze_ready to freeze_pending.
func (c *Controller) MarkProposalSent(now time.Time) {
	if c.phase == PhaseFreezeReady {
		c.phase = PhaseFreezePending
		c.proposalSentAt = now
	}
}

// ApplyFreeze transitions to frozen_observe (called when Forge approves the proposal
// or when local-auto mode triggers locally).
func (c *Controller) ApplyFreeze(now time.Time) {
	c.phase = PhaseFrozenObserve
	c.frozenAt = now
}

// ApplyEnforce transitions from frozen_observe to frozen_enforce.
// Used for explicit operator or Forge-triggered promotion.
func (c *Controller) ApplyEnforce() {
	if c.phase == PhaseFrozenObserve {
		c.phase = PhaseFrozenEnforce
	}
}

// MaxAction returns the configured enforcement ceiling for the current lifecycle phase.
// Values match the action names used by the ActionResolver.
func (c *Controller) MaxAction(bounds contracts.EnforcementBounds) string {
	switch c.phase {
	case PhaseDisabled, PhaseLearning, PhaseFreezeReady, PhaseFreezePending:
		return bounds.MaxActionDuringBootstrap
	case PhaseFrozenObserve:
		return bounds.MaxActionDuringFrozenObserve
	case PhaseFrozenEnforce:
		return bounds.MaxActionDuringFrozenEnforce
	default:
		return ""
	}
}

// StartedAt returns when this lifecycle session began.
func (c *Controller) StartedAt() time.Time { return c.startedAt }

// ProposalUpload reports whether freeze-ready proposals should be uploaded.
func (c *Controller) ProposalUpload() bool { return c.cfg.ProposalUpload }

// KLIQGraphMode maps the current lifecycle phase to the kliq --graph-mode value.
func (c *Controller) KLIQGraphMode() string {
	switch c.phase {
	case PhaseFrozenObserve:
		return "frozen-observe"
	case PhaseFrozenEnforce:
		return "frozen-enforce"
	default:
		return "learn"
	}
}

// StatusReport builds a bundle.GraphLifecycleStatus for Forge heartbeats.
func (c *Controller) StatusReport(stats GraphStats, now time.Time) bundle.GraphLifecycleStatus {
	blocked := c.ReadinessCheck(stats, now)
	coverage := 0.0
	if stats.TotalLearnedEdges > 0 {
		coverage = float64(stats.EdgesWithBaseline) / float64(stats.TotalLearnedEdges)
	}
	return bundle.GraphLifecycleStatus{
		Phase:                c.phase,
		StartedAt:            c.startedAt,
		CleanLearningSeconds: stats.CleanLearningSec,
		LearnedEdges:         stats.LearnedEdges,
		CandidateEdges:       stats.CandidateEdges,
		BaselineCoverage:     coverage,
		ReadyToFreeze:        len(blocked) == 0 && c.phase == PhaseLearning,
		FreezeBlockedBy:      blocked,
	}
}

// BuildProposal constructs a BaselineProposal from current stats.
func (c *Controller) BuildProposal(nodeID string, stats GraphStats, edges []bundle.GraphEdgeEntry, triggers bundle.TriggerSet, observedSec uint64, cleanRatio float64) bundle.BaselineProposal {
	coverage := 0.0
	if stats.TotalLearnedEdges > 0 {
		coverage = float64(stats.EdgesWithBaseline) / float64(stats.TotalLearnedEdges)
	}
	return bundle.BaselineProposal{
		APIVersion: bundle.ProposalAPIVersion,
		Kind:       bundle.ProposalKind,
		Metadata: bundle.ProposalMetadata{
			NodeID:      nodeID,
			GeneratedAt: time.Now().UTC(),
		},
		Spec: bundle.BaselineProposalSpec{
			BootstrapAutotune: bundle.BootstrapProposalSummary{
				Phase:           stats.BootstrapPhase,
				ObservedSeconds: observedSec,
				CleanRatio:      cleanRatio,
				Triggers:        triggers,
			},
			SourceBaselineSummary: bundle.SourceProposalSummary{
				TrackedSources:        stats.TrackedSources,
				HighConfidenceSources: stats.HighConfidenceSources,
				AverageConfidence:     stats.AvgConfidence,
			},
			GraphSummary: bundle.GraphProposalSummary{
				CandidateEdges: stats.CandidateEdges,
				LearnedEdges:   stats.LearnedEdges,
				ApprovedEdges:  stats.ApprovedEdges,
				DeniedEdges:    stats.DeniedEdges,
				FrozenEdges:    stats.FrozenEdges,
			},
			EdgeBaselineSummary: bundle.EdgeProposalSummary{
				EdgesWithBaseline: stats.EdgesWithBaseline,
				BaselineCoverage:  coverage,
			},
			GraphEdges: edges,
		},
	}
}
