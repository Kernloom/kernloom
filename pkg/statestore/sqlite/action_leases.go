// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/decision"
)

// UpsertActionLease stores or replaces an action lease.
func (s *Store) UpsertActionLease(ctx context.Context, lease decision.ActionLease) error {
	metadata, err := json.Marshal(lease.Metadata)
	if err != nil {
		return fmt.Errorf("marshal action lease metadata: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO action_leases (
    lease_id, decision_id, proposal_id, node_id, adapter_id, target, action, level,
    status, fencing_token, policy_id, bundle_id, reason, applied_at, expires_at,
    reverted_at, last_error, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(lease_id) DO UPDATE SET
    decision_id=excluded.decision_id,
    proposal_id=excluded.proposal_id,
    node_id=excluded.node_id,
    adapter_id=excluded.adapter_id,
    target=excluded.target,
    action=excluded.action,
    level=excluded.level,
    status=excluded.status,
    fencing_token=excluded.fencing_token,
    policy_id=excluded.policy_id,
    bundle_id=excluded.bundle_id,
    reason=excluded.reason,
    applied_at=excluded.applied_at,
    expires_at=excluded.expires_at,
    reverted_at=excluded.reverted_at,
    last_error=excluded.last_error,
    metadata=excluded.metadata`,
		lease.LeaseID,
		lease.DecisionID,
		lease.ProposalID,
		lease.NodeID,
		lease.AdapterID,
		lease.Target,
		lease.Action,
		lease.Level,
		string(lease.Status),
		lease.FencingToken,
		lease.PolicyID,
		lease.BundleID,
		lease.Reason,
		formatTime(lease.AppliedAt),
		formatTime(lease.ExpiresAt),
		formatOptionalTime(lease.RevertedAt),
		lease.LastError,
		string(metadata),
	)
	if err != nil {
		return fmt.Errorf("upsert action lease %s: %w", lease.LeaseID, err)
	}
	return nil
}

// GetActionLease loads one action lease by ID.
func (s *Store) GetActionLease(ctx context.Context, leaseID string) (decision.ActionLease, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT lease_id, decision_id, proposal_id, node_id, adapter_id, target, action,
       level, status, fencing_token, policy_id, bundle_id, reason, applied_at,
       expires_at, reverted_at, last_error, metadata
FROM action_leases WHERE lease_id=?`, leaseID)
	lease, err := scanActionLease(row)
	if err != nil {
		if isNoRows(err) {
			return decision.ActionLease{}, false, nil
		}
		return decision.ActionLease{}, false, fmt.Errorf("get action lease %s: %w", leaseID, err)
	}
	return lease, true, nil
}

// ListActionLeasesByStatus loads leases with the given status.
func (s *Store) ListActionLeasesByStatus(ctx context.Context, status decision.ActionLeaseStatus) ([]decision.ActionLease, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT lease_id, decision_id, proposal_id, node_id, adapter_id, target, action,
       level, status, fencing_token, policy_id, bundle_id, reason, applied_at,
       expires_at, reverted_at, last_error, metadata
FROM action_leases WHERE status=? ORDER BY expires_at, lease_id`, string(status))
	if err != nil {
		return nil, fmt.Errorf("list action leases status=%s: %w", status, err)
	}
	defer rows.Close()

	var leases []decision.ActionLease
	for rows.Next() {
		lease, err := scanActionLease(rows)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate action leases: %w", err)
	}
	return leases, nil
}

// ListExpiredActionLeases loads active leases whose expiry is at or before now.
func (s *Store) ListExpiredActionLeases(ctx context.Context, now time.Time) ([]decision.ActionLease, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT lease_id, decision_id, proposal_id, node_id, adapter_id, target, action,
       level, status, fencing_token, policy_id, bundle_id, reason, applied_at,
       expires_at, reverted_at, last_error, metadata
FROM action_leases WHERE status=? AND expires_at <= ? ORDER BY expires_at, lease_id`,
		string(decision.ActionLeaseActive), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("list expired action leases: %w", err)
	}
	defer rows.Close()

	var leases []decision.ActionLease
	for rows.Next() {
		lease, err := scanActionLease(rows)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expired action leases: %w", err)
	}
	return leases, nil
}

// UpdateActionLeaseStatus updates the status and optional revert metadata.
func (s *Store) UpdateActionLeaseStatus(ctx context.Context, lease decision.ActionLease) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE action_leases
   SET status=?, reverted_at=?, last_error=?
 WHERE lease_id=?`,
		string(lease.Status),
		formatOptionalTime(lease.RevertedAt),
		lease.LastError,
		lease.LeaseID,
	)
	if err != nil {
		return fmt.Errorf("update action lease status %s: %w", lease.LeaseID, err)
	}
	return nil
}

type actionLeaseScanner interface {
	Scan(dest ...any) error
}

func scanActionLease(scanner actionLeaseScanner) (decision.ActionLease, error) {
	var lease decision.ActionLease
	var status, appliedAt, expiresAt, revertedAt, metadata string
	if err := scanner.Scan(
		&lease.LeaseID,
		&lease.DecisionID,
		&lease.ProposalID,
		&lease.NodeID,
		&lease.AdapterID,
		&lease.Target,
		&lease.Action,
		&lease.Level,
		&status,
		&lease.FencingToken,
		&lease.PolicyID,
		&lease.BundleID,
		&lease.Reason,
		&appliedAt,
		&expiresAt,
		&revertedAt,
		&lease.LastError,
		&metadata,
	); err != nil {
		return decision.ActionLease{}, err
	}
	lease.Status = decision.ActionLeaseStatus(status)
	var err error
	lease.AppliedAt, err = parseTime(appliedAt)
	if err != nil {
		return decision.ActionLease{}, fmt.Errorf("parse applied_at: %w", err)
	}
	lease.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return decision.ActionLease{}, fmt.Errorf("parse expires_at: %w", err)
	}
	if revertedAt != "" {
		t, err := parseTime(revertedAt)
		if err != nil {
			return decision.ActionLease{}, fmt.Errorf("parse reverted_at: %w", err)
		}
		lease.RevertedAt = &t
	}
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &lease.Metadata); err != nil {
			return decision.ActionLease{}, fmt.Errorf("unmarshal action lease metadata: %w", err)
		}
	}
	if lease.Metadata == nil {
		lease.Metadata = map[string]string{}
	}
	return lease, nil
}
