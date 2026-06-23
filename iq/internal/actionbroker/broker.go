// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package actionbroker persists TTL-bounded enforcement leases and produces
// receipts for apply/revert outcomes. It is intentionally independent from the
// KLIQ main loop so future Runtime PDP decisions can share one enforcement path.
package actionbroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/core/decision"
)

// LeaseStore is the durable journal used by the broker.
type LeaseStore interface {
	UpsertActionLease(context.Context, decision.ActionLease) error
	FindActiveActionLease(context.Context, string, string, string, string) (decision.ActionLease, bool, error)
	ListActionLeasesByStatus(context.Context, decision.ActionLeaseStatus) ([]decision.ActionLease, error)
	ListExpiredActionLeases(context.Context, time.Time) ([]decision.ActionLease, error)
	UpdateActionLeaseStatus(context.Context, decision.ActionLease) error
}

// PEP is the minimal adapter contract needed by the action broker.
type PEP interface {
	AdapterID() string
	Apply(context.Context, decision.ActionLease) (fencingToken string, err error)
	CurrentFencingToken(context.Context, decision.ActionLease) (fencingToken string, err error)
	Revert(context.Context, decision.ActionLease) error
}

// Broker applies authorized actions through a PEP and records their lease.
type Broker struct {
	nodeID string
	store  LeaseStore
	pep    PEP
	now    func() time.Time

	autonomyAllowances  []contracts.RuntimeAutonomyAllowance
	maxRenewals         int
	requireAuditReceipt bool
}

// Config controls broker construction.
type Config struct {
	NodeID string
	Store  LeaseStore
	PEP    PEP
	Now    func() time.Time

	AutonomyAllowances  []contracts.RuntimeAutonomyAllowance
	MaxRenewals         int
	RequireAuditReceipt bool
}

// New creates a Broker.
func New(cfg Config) (*Broker, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("actionbroker: store is required")
	}
	if cfg.PEP == nil {
		return nil, fmt.Errorf("actionbroker: PEP is required")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Broker{
		nodeID:              cfg.NodeID,
		store:               cfg.Store,
		pep:                 cfg.PEP,
		now:                 cfg.Now,
		autonomyAllowances:  append([]contracts.RuntimeAutonomyAllowance(nil), cfg.AutonomyAllowances...),
		maxRenewals:         cfg.MaxRenewals,
		requireAuditReceipt: cfg.RequireAuditReceipt,
	}, nil
}

// UpdateAutonomyConstraints refreshes policy-derived broker gates after a
// managed RuntimePolicyPack update.
func (b *Broker) UpdateAutonomyConstraints(allowances []contracts.RuntimeAutonomyAllowance, maxRenewals int, requireAuditReceipt bool) {
	if b == nil {
		return
	}
	b.autonomyAllowances = append([]contracts.RuntimeAutonomyAllowance(nil), allowances...)
	b.maxRenewals = maxRenewals
	b.requireAuditReceipt = requireAuditReceipt
}

// Apply applies an ActionResolution and returns the local lease, if one was
// needed, plus an enforcement receipt for the attempt.
func (b *Broker) Apply(ctx context.Context, r actions.ActionResolution) (decision.ActionLease, *decision.EnforcementReceipt, error) {
	now := b.now().UTC()
	decisionID := r.DecisionID
	if decisionID == "" {
		decisionID = "decision-" + generateID()
	}
	receipt := decision.NewEnforcementReceipt(decisionID, b.nodeID, b.pep.AdapterID(), decision.StatusSkipped)
	receipt.AppliedAt = now

	if !r.Allowed {
		receipt.Status = decision.StatusSkipped
		receipt.SetMessage(r.DenyReason)
		return decision.ActionLease{}, receipt, nil
	}
	if r.ExecutableLevel == "" || r.ExecutableLevel == "observe" || r.TTL <= 0 {
		receipt.Status = decision.StatusApplied
		receipt.Action = r.ExecutableAction
		receipt.Target = targetString(r.Target)
		if r.TTL <= 0 {
			receipt.SetMessage("no lease: action has no TTL")
		}
		return decision.ActionLease{}, receipt, nil
	}

	metadata := map[string]string{
		"requested_action":     r.RequestedAction,
		"requested_level":      r.RequestedLevel,
		"target_granularity":   r.Target.Granularity,
		"target_value":         r.Target.Value,
		"broker.renewal_count": "0",
	}
	for k, v := range r.Target.Attributes {
		metadata["target_attr."+k] = v
	}
	for k, v := range r.Parameters {
		if v != nil {
			metadata["param."+k] = fmt.Sprint(v)
		}
	}
	if b.requireAuditReceipt {
		metadata["policy.requires_audit_receipt"] = "true"
	}
	target := targetString(r.Target)
	if reason, err := b.autonomyPrerequisiteDenyReason(ctx, r, target); err != nil {
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return decision.ActionLease{}, receipt, err
	} else if reason != "" {
		receipt.Status = decision.StatusSkipped
		receipt.Action = r.ExecutableAction
		receipt.Target = target
		receipt.SetMessage(reason)
		return decision.ActionLease{}, receipt, nil
	}
	if reason, err := b.strongerActiveLeaseDenyReason(ctx, r, target); err != nil {
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return decision.ActionLease{}, receipt, err
	} else if reason != "" {
		receipt.Status = decision.StatusSkipped
		receipt.Action = r.ExecutableAction
		receipt.Target = target
		receipt.SetMessage(reason)
		return decision.ActionLease{}, receipt, nil
	}
	if lease, ok, skipReason, err := b.renewActiveLease(ctx, r, decisionID, target, metadata, now); err != nil {
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return lease, receipt.SetLease(lease), err
	} else if skipReason != "" {
		receipt.Status = decision.StatusSkipped
		receipt.SetMessage(skipReason)
		return lease, receipt.SetLease(lease), nil
	} else if ok {
		receipt.Status = decision.StatusApplied
		receipt.SetMessage(receiptMessageWithExecutionSummary("lease renewed", metadata))
		return lease, receipt.SetLease(lease), nil
	}

	lease := decision.ActionLease{
		LeaseID:    "lease-" + generateID(),
		DecisionID: decisionID,
		ProposalID: r.ProposalID,
		NodeID:     b.nodeID,
		AdapterID:  b.pep.AdapterID(),
		Target:     target,
		Action:     r.ExecutableAction,
		Level:      r.ExecutableLevel,
		Status:     decision.ActionLeasePending,
		PolicyID:   r.PolicyID,
		Reason:     r.DenyReason,
		AppliedAt:  now,
		ExpiresAt:  now.Add(r.TTL),
		Metadata:   metadata,
	}
	lease.FencingToken = buildFencingToken(lease)
	if err := b.store.UpsertActionLease(ctx, lease); err != nil {
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return lease, receipt.SetLease(lease), err
	}
	fencingToken, err := b.pep.Apply(ctx, lease)
	if err != nil {
		lease.Status = decision.ActionLeaseFailed
		lease.LastError = err.Error()
		_ = b.store.UpdateActionLeaseStatus(ctx, lease)
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return lease, receipt.SetLease(lease), err
	}
	if fencingToken != "" && fencingToken != lease.FencingToken {
		lease.Status = decision.ActionLeaseConflict
		lease.LastError = fmt.Sprintf("PEP returned unexpected fencing token: expected %q got %q", lease.FencingToken, fencingToken)
		_ = b.store.UpdateActionLeaseStatus(ctx, lease)
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(lease.LastError)
		return lease, receipt.SetLease(lease), fmt.Errorf("%s", lease.LastError)
	}
	lease.Status = decision.ActionLeaseActive
	if err := b.store.UpdateActionLeaseStatus(ctx, lease); err != nil {
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return lease, receipt.SetLease(lease), err
	}
	if err := b.supersedeWeakerActiveLeases(ctx, lease, now); err != nil {
		receipt.Status = decision.StatusFailed
		receipt.SetMessage(err.Error())
		return lease, receipt.SetLease(lease), err
	}
	receipt.Status = decision.StatusApplied
	if msg := receiptMessageWithExecutionSummary("", metadata); msg != "" {
		receipt.SetMessage(msg)
	}
	return lease, receipt.SetLease(lease), nil
}

func (b *Broker) autonomyPrerequisiteDenyReason(ctx context.Context, r actions.ActionResolution, target string) (string, error) {
	for _, allowance := range b.autonomyAllowances {
		if strings.TrimSpace(allowance.Action) != r.ExecutableAction {
			continue
		}
		previous := strings.TrimSpace(allowance.RequiresPreviousAction)
		if previous == "" {
			continue
		}
		ok, err := b.hasActiveActionLease(ctx, target, previous)
		if err != nil {
			return "", err
		}
		if !ok {
			return "autonomy_previous_action_not_active(" + previous + ")", nil
		}
	}
	return "", nil
}

func (b *Broker) hasActiveActionLease(ctx context.Context, target, action string) (bool, error) {
	for _, level := range []string{"soft", "hard", "block"} {
		if _, ok, err := b.store.FindActiveActionLease(ctx, b.pep.AdapterID(), target, action, level); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}

var orderedRuntimeActions = []string{
	"enforce.traffic.drop",
	"enforce.access.deny",
	"enforce.network.quarantine",
	"enforce.identity.disable",
	"enforce.traffic.rate_limit",
}

func (b *Broker) strongerActiveLeaseDenyReason(ctx context.Context, r actions.ActionResolution, target string) (string, error) {
	requested := actionLeaseStrength(r.ExecutableAction, r.ExecutableLevel)
	if requested <= 0 {
		return "", nil
	}
	strongest, ok, err := b.strongestActiveLease(ctx, target, r.ExecutableAction)
	if err != nil || !ok {
		return "", err
	}
	if actionLeaseStrength(strongest.Action, strongest.Level) <= requested {
		return "", nil
	}
	return "stronger_action_active(" + strongest.Action + ":" + strongest.Level + ")", nil
}

func (b *Broker) strongestActiveLease(ctx context.Context, target, requestedAction string) (decision.ActionLease, bool, error) {
	var strongest decision.ActionLease
	strongestWeight := 0
	for _, action := range runtimeActionsWithRequested(requestedAction) {
		for _, level := range []string{"block", "hard", "soft"} {
			lease, ok, err := b.store.FindActiveActionLease(ctx, b.pep.AdapterID(), target, action, level)
			if err != nil {
				return decision.ActionLease{}, false, err
			}
			if !ok {
				continue
			}
			weight := actionLeaseStrength(lease.Action, lease.Level)
			if weight > strongestWeight {
				strongest = lease
				strongestWeight = weight
			}
		}
	}
	return strongest, strongestWeight > 0, nil
}

func (b *Broker) supersedeWeakerActiveLeases(ctx context.Context, applied decision.ActionLease, now time.Time) error {
	appliedStrength := actionLeaseStrength(applied.Action, applied.Level)
	if appliedStrength <= 0 {
		return nil
	}
	for _, action := range runtimeActionsWithRequested(applied.Action) {
		for _, level := range []string{"soft", "hard", "block"} {
			lease, ok, err := b.store.FindActiveActionLease(ctx, b.pep.AdapterID(), applied.Target, action, level)
			if err != nil {
				return err
			}
			if !ok || lease.LeaseID == applied.LeaseID {
				continue
			}
			if actionLeaseStrength(lease.Action, lease.Level) >= appliedStrength {
				continue
			}
			lease.Status = decision.ActionLeaseSuperseded
			lease.LastError = "superseded by stronger action " + applied.Action + ":" + applied.Level
			nowCopy := now
			lease.RevertedAt = &nowCopy
			if err := b.store.UpdateActionLeaseStatus(ctx, lease); err != nil {
				return err
			}
		}
	}
	return nil
}

func runtimeActionsWithRequested(requested string) []string {
	actions := make([]string, 0, len(orderedRuntimeActions)+1)
	seen := map[string]struct{}{}
	add := func(action string) {
		action = strings.TrimSpace(action)
		if action == "" {
			return
		}
		if _, ok := seen[action]; ok {
			return
		}
		seen[action] = struct{}{}
		actions = append(actions, action)
	}
	add(requested)
	for _, action := range orderedRuntimeActions {
		add(action)
	}
	return actions
}

func actionLeaseStrength(action, level string) int {
	switch strings.TrimSpace(action) {
	case "enforce.traffic.drop", "enforce.access.deny", "enforce.network.quarantine", "enforce.identity.disable":
		return 300
	}
	switch strings.TrimSpace(level) {
	case "block":
		return 300
	case "hard":
		return 200
	case "soft":
		return 100
	default:
		return 0
	}
}

func (b *Broker) renewActiveLease(ctx context.Context, r actions.ActionResolution, decisionID, target string, metadata map[string]string, now time.Time) (decision.ActionLease, bool, string, error) {
	existing, ok, err := b.store.FindActiveActionLease(ctx, b.pep.AdapterID(), target, r.ExecutableAction, r.ExecutableLevel)
	if err != nil || !ok {
		return existing, false, "", err
	}
	if key, changed := executionMetadataChanged(existing.Metadata, metadata); changed {
		existing.Status = decision.ActionLeaseSuperseded
		existing.LastError = "superseded by execution metadata change: " + key
		nowCopy := now
		existing.RevertedAt = &nowCopy
		if updateErr := b.store.UpdateActionLeaseStatus(ctx, existing); updateErr != nil {
			return existing, false, "", updateErr
		}
		return decision.ActionLease{}, false, "", nil
	}
	currentToken, err := b.pep.CurrentFencingToken(ctx, existing)
	if err != nil {
		return existing, false, "", err
	}
	if currentToken != existing.FencingToken {
		existing.Status = decision.ActionLeaseConflict
		existing.LastError = fmt.Sprintf("fencing token mismatch during renewal: expected %q got %q", existing.FencingToken, currentToken)
		nowCopy := now
		existing.RevertedAt = &nowCopy
		if updateErr := b.store.UpdateActionLeaseStatus(ctx, existing); updateErr != nil {
			return existing, false, "", updateErr
		}
		return decision.ActionLease{}, false, "", nil
	}
	renewalCount := leaseRenewalCount(existing.Metadata)
	if b.maxRenewals > 0 && renewalCount >= b.maxRenewals {
		return existing, true, "autonomy_max_renewals_exceeded", nil
	}
	existing.DecisionID = decisionID
	existing.ProposalID = r.ProposalID
	existing.PolicyID = r.PolicyID
	existing.Reason = r.DenyReason
	existing.ExpiresAt = now.Add(r.TTL)
	existing.Metadata = metadata
	existing.Metadata["broker.renewal_count"] = strconv.Itoa(renewalCount + 1)
	existing.Status = decision.ActionLeaseActive
	existing.LastError = ""
	existing.RevertedAt = nil
	if err := b.store.UpsertActionLease(ctx, existing); err != nil {
		return existing, false, "", err
	}
	return existing, true, "", nil
}

func receiptMessageWithExecutionSummary(base string, metadata map[string]string) string {
	summary := executionMetadataSummary(metadata)
	if base == "" {
		return summary
	}
	if summary == "" {
		return base
	}
	return base + " " + summary
}

func executionMetadataSummary(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}
	parts := []string{}
	if value := nonZeroMetadataValue(metadata, "param.evidence_drop_rl_rate"); value != "" {
		parts = append(parts, "drop_rl_rate="+value)
	}
	if strings.TrimSpace(metadata["requested_action"]) == "enforce.traffic.rate_limit" {
		if value := nonZeroMetadataValue(metadata, "param.execution_soft_rate"); value != "" {
			parts = append(parts, "soft_rate_pps="+value)
		}
		if value := nonZeroMetadataValue(metadata, "param.execution_soft_burst"); value != "" {
			parts = append(parts, "soft_burst="+value)
		}
		if value := nonZeroMetadataValue(metadata, "param.execution_hard_rate"); value != "" {
			parts = append(parts, "hard_rate_pps="+value)
		}
		if value := nonZeroMetadataValue(metadata, "param.execution_hard_burst"); value != "" {
			parts = append(parts, "hard_burst="+value)
		}
	}
	return strings.Join(parts, " ")
}

func nonZeroMetadataValue(metadata map[string]string, key string) string {
	value := strings.TrimSpace(metadata[key])
	if value == "" || value == "0" {
		return ""
	}
	return value
}

func leaseRenewalCount(metadata map[string]string) int {
	if len(metadata) == 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(metadata["broker.renewal_count"]))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func executionMetadataChanged(existing, next map[string]string) (string, bool) {
	keys := map[string]struct{}{}
	for key := range existing {
		if strings.HasPrefix(key, "param.execution_") {
			keys[key] = struct{}{}
		}
	}
	for key := range next {
		if strings.HasPrefix(key, "param.execution_") {
			keys[key] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		if existing[key] != next[key] {
			return key, true
		}
	}
	return "", false
}

// RevertExpired reverts every active lease whose expiry is at or before now.
func (b *Broker) RevertExpired(ctx context.Context, now time.Time) ([]*decision.EnforcementReceipt, error) {
	leases, err := b.store.ListExpiredActionLeases(ctx, now.UTC())
	if err != nil {
		return nil, err
	}
	receipts := make([]*decision.EnforcementReceipt, 0, len(leases))
	for _, lease := range leases {
		receipt, err := b.Revert(ctx, lease)
		receipts = append(receipts, receipt)
		if err != nil {
			return receipts, err
		}
	}
	return receipts, nil
}

// ReconcilePending marks leases that were persisted before PEP apply completed
// as failed. This handles crashes between the pending journal write and the
// active status update without guessing whether enforcement happened.
func (b *Broker) ReconcilePending(ctx context.Context) ([]*decision.EnforcementReceipt, error) {
	leases, err := b.store.ListActionLeasesByStatus(ctx, decision.ActionLeasePending)
	if err != nil {
		return nil, err
	}
	now := b.now().UTC()
	receipts := make([]*decision.EnforcementReceipt, 0, len(leases))
	for _, lease := range leases {
		lease.Status = decision.ActionLeaseFailed
		lease.LastError = "pending lease found during broker startup; apply outcome unknown"
		receipt := decision.NewEnforcementReceipt(lease.DecisionID, b.nodeID, lease.AdapterID, decision.StatusFailed).SetLease(lease)
		receipt.AppliedAt = lease.AppliedAt
		receipt.RevertedAt = &now
		receipt.RevertStatus = decision.RevertStatusFailed
		receipt.SetMessage(lease.LastError)
		if err := b.store.UpdateActionLeaseStatus(ctx, lease); err != nil {
			return receipts, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

// Revert attempts to remove a lease. If the current fencing token differs from
// the lease token, the broker marks the lease conflict and does not call Revert.
func (b *Broker) Revert(ctx context.Context, lease decision.ActionLease) (*decision.EnforcementReceipt, error) {
	now := b.now().UTC()
	receipt := decision.NewEnforcementReceipt(lease.DecisionID, b.nodeID, lease.AdapterID, decision.StatusReverted).SetLease(lease)
	receipt.AppliedAt = lease.AppliedAt
	receipt.RevertedAt = &now

	currentToken, err := b.pep.CurrentFencingToken(ctx, lease)
	if err != nil {
		lease.Status = decision.ActionLeaseFailed
		lease.LastError = err.Error()
		lease.RevertedAt = &now
		receipt.Status = decision.StatusFailed
		receipt.RevertStatus = decision.RevertStatusFailed
		receipt.SetMessage(err.Error())
		_ = b.store.UpdateActionLeaseStatus(ctx, lease)
		return receipt, err
	}
	if currentToken != lease.FencingToken {
		lease.Status = decision.ActionLeaseConflict
		lease.LastError = fmt.Sprintf("fencing token mismatch: expected %q got %q", lease.FencingToken, currentToken)
		lease.RevertedAt = &now
		receipt.Status = decision.StatusConflict
		receipt.RevertStatus = decision.RevertStatusConflict
		receipt.SetMessage(lease.LastError)
		if err := b.store.UpdateActionLeaseStatus(ctx, lease); err != nil {
			return receipt, err
		}
		return receipt, nil
	}
	if err := b.pep.Revert(ctx, lease); err != nil {
		lease.Status = decision.ActionLeaseFailed
		lease.LastError = err.Error()
		lease.RevertedAt = &now
		receipt.Status = decision.StatusFailed
		receipt.RevertStatus = decision.RevertStatusFailed
		receipt.SetMessage(err.Error())
		_ = b.store.UpdateActionLeaseStatus(ctx, lease)
		return receipt, err
	}
	lease.Status = decision.ActionLeaseReverted
	lease.RevertedAt = &now
	receipt.Status = decision.StatusReverted
	receipt.RevertStatus = decision.RevertStatusReverted
	if err := b.store.UpdateActionLeaseStatus(ctx, lease); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func targetString(t actions.ActionTarget) string {
	if t.Granularity == "" {
		return t.Value
	}
	return t.Granularity + ":" + t.Value
}

func TargetFromLease(lease decision.ActionLease) actions.ActionTarget {
	granularity := lease.Metadata["target_granularity"]
	value := lease.Metadata["target_value"]
	if granularity == "" || value == "" {
		if before, after, ok := strings.Cut(lease.Target, ":"); ok {
			granularity = before
			value = after
		} else {
			value = lease.Target
		}
	}
	attrs := make(map[string]string)
	for k, v := range lease.Metadata {
		if attr, ok := strings.CutPrefix(k, "target_attr."); ok {
			attrs[attr] = v
		}
	}
	if len(attrs) == 0 {
		attrs = nil
	}
	return actions.ActionTarget{Granularity: granularity, Value: value, Attributes: attrs}
}

func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func buildFencingToken(lease decision.ActionLease) string {
	sum := sha256.Sum256([]byte(lease.AdapterID + "|" + lease.Target + "|" + lease.Action + "|" + lease.Level + "|" + lease.DecisionID + "|" + lease.LeaseID))
	return fmt.Sprintf("%x", sum[:])[:32]
}
