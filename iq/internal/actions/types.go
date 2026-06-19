// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package actions defines the proposal/resolution/result pipeline that all
// KLIQ enforcement decisions must flow through.
//
// Architecture:
//
//	RuntimePDP → ActionProposal → PolicyResolver → ActionResolution → ActionExecutor → PEP
//
// In managed mode, no component may write to a PEP directly. All enforcement
// must be authorized by the PolicyResolver before an ActionExecutor applies it.
package actions

import (
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

const (
	TargetGranularitySource       = "source"
	TargetGranularityRelationship = "relationship"

	TargetAttrSourceID        = "source_id"
	TargetAttrSubjectID       = "subject_id"
	TargetAttrTargetID        = "target_id"
	TargetAttrDimensionPrefix = "dimension."
)

// PEPSidecar is an additional Policy Enforcement Point that runs alongside the
// primary enforcement adapter. Every authorized source transition is also delivered
// to all registered sidecars so they can mirror the enforcement.
//
// Sidecars must be non-blocking (they run synchronously in the tick loop).
// Errors are logged but never propagate back to the caller — a failed sidecar
// must not prevent the primary enforcement path from completing.
type PEPSidecar interface {
	// NotifySourceTransition is called after every authorized source transition.
	// prev is the level before the transition, next is the level after.
	// ttl is how long the new level should be maintained (0 = adapter default).
	NotifySourceTransition(target adapterruntime.SourceTarget, prev, next fsm.Level, ttl time.Duration)
}

// ActionTarget describes the entity that an enforcement action targets.
type ActionTarget struct {
	Granularity string            `json:"granularity"`
	Value       string            `json:"value"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// ActionProposal is a request for enforcement produced by RuntimePDP.
// It carries the desired action in Forge vocabulary.
// Only the PolicyResolver may authorize or downgrade this proposal.
type ActionProposal struct {
	ID            string         `json:"id"`
	Source        string         `json:"source"`         // "fsm", "graph", "baseline", "manual"
	Reason        string         `json:"reason"`         // human-readable trigger reason
	DesiredAction string         `json:"desired_action"` // Forge capability ID
	DesiredLevel  string         `json:"desired_level"`  // "observe", "soft", "hard", "block"
	Target        ActionTarget   `json:"target"`
	Parameters    map[string]any `json:"parameters,omitempty"`
	TTL           time.Duration  `json:"ttl"`
	Confidence    float64        `json:"confidence,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// ActionResolution is the output of the PolicyResolver.
// It contains the authorized executable action, which may differ from the
// requested action if it was downgraded by a PolicyMaxAction ceiling.
type ActionResolution struct {
	ProposalID string `json:"proposal_id"`

	// Allowed is false when the resolver denies the action entirely.
	// The executor must not call the PEP when Allowed is false.
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`

	// RequestedAction/Level: what was proposed (Forge vocab).
	RequestedAction string `json:"requested_action"`
	RequestedLevel  string `json:"requested_level"`

	// ExecutableAction/Level: what is authorized (may be downgraded).
	// Empty or "observe" means no PEP mutation beyond de-enforcement.
	ExecutableAction string `json:"executable_action,omitempty"`
	ExecutableLevel  string `json:"executable_level,omitempty"`

	Target     ActionTarget   `json:"target"`
	Parameters map[string]any `json:"parameters,omitempty"`
	TTL        time.Duration  `json:"ttl"`
	PolicyID   string         `json:"policy_id,omitempty"`
	DecisionID string         `json:"decision_id,omitempty"`
}

// ActionResult is produced by an ActionExecutor after applying or denying an
// ActionResolution.
type ActionResult struct {
	ProposalID string         `json:"proposal_id"`
	DecisionID string         `json:"decision_id,omitempty"`
	Action     string         `json:"action"`
	Status     string         `json:"status"` // "applied", "downgraded", "denied", "skipped", "failed"
	Reason     string         `json:"reason,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	AppliedAt  time.Time      `json:"applied_at"`
}
