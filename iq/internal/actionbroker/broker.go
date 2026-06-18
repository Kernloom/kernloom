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
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/core/decision"
)

// LeaseStore is the durable journal used by the broker.
type LeaseStore interface {
	UpsertActionLease(context.Context, decision.ActionLease) error
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
}

// Config controls broker construction.
type Config struct {
	NodeID string
	Store  LeaseStore
	PEP    PEP
	Now    func() time.Time
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
		nodeID: cfg.NodeID,
		store:  cfg.Store,
		pep:    cfg.PEP,
		now:    cfg.Now,
	}, nil
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

	lease := decision.ActionLease{
		LeaseID:    "lease-" + generateID(),
		DecisionID: decisionID,
		ProposalID: r.ProposalID,
		NodeID:     b.nodeID,
		AdapterID:  b.pep.AdapterID(),
		Target:     targetString(r.Target),
		Action:     r.ExecutableAction,
		Level:      r.ExecutableLevel,
		Status:     decision.ActionLeasePending,
		PolicyID:   r.PolicyID,
		Reason:     r.DenyReason,
		AppliedAt:  now,
		ExpiresAt:  now.Add(r.TTL),
		Metadata: map[string]string{
			"requested_action": r.RequestedAction,
			"requested_level":  r.RequestedLevel,
		},
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
	receipt.Status = decision.StatusApplied
	return lease, receipt.SetLease(lease), nil
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
