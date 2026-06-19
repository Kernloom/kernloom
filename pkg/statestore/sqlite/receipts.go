// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/decision"
)

const (
	receiptUploadPending  = "pending"
	receiptUploadUploaded = "uploaded"
	receiptUploadFailed   = "failed"
)

// PersistReceipt saves an EnforcementReceipt to the durable receipts table.
// The receipt starts with upload_status = "pending" so the upload goroutine
// can pick it up and deliver it to Forge.
func (s *Store) PersistReceipt(ctx context.Context, r decision.EnforcementReceipt) error {
	expiresAt := ""
	if r.ExpiresAt != nil {
		expiresAt = formatTime(*r.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO action_receipts (
    id, decision_id, lease_id, node_id, adapter_id,
    status, action, target, message, fencing_token,
    applied_at, expires_at, upload_status, uploaded_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')`,
		r.ID, r.DecisionID, r.LeaseID, r.NodeID, r.AdapterID,
		string(r.Status), r.Action, r.Target, r.Message, r.FencingToken,
		formatTime(r.AppliedAt), expiresAt, receiptUploadPending,
	)
	if err != nil {
		return fmt.Errorf("persist receipt %s: %w", r.ID, err)
	}
	return nil
}

// ListPendingReceipts returns receipts that have not yet been uploaded to Forge.
// Callers should mark them uploaded after a successful Forge POST.
func (s *Store) ListPendingReceipts(ctx context.Context, limit int) ([]decision.EnforcementReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, decision_id, lease_id, node_id, adapter_id,
       status, action, target, message, fencing_token,
       applied_at, expires_at
FROM action_receipts
WHERE upload_status IN (?, ?)
ORDER BY applied_at ASC
LIMIT ?`, receiptUploadPending, receiptUploadFailed, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending receipts: %w", err)
	}
	defer rows.Close()

	var out []decision.EnforcementReceipt
	for rows.Next() {
		var r decision.EnforcementReceipt
		var statusStr, appliedStr, expiresStr string
		if err := rows.Scan(
			&r.ID, &r.DecisionID, &r.LeaseID, &r.NodeID, &r.AdapterID,
			&statusStr, &r.Action, &r.Target, &r.Message, &r.FencingToken,
			&appliedStr, &expiresStr,
		); err != nil {
			return nil, fmt.Errorf("scan receipt: %w", err)
		}
		r.Status = decision.ReceiptStatus(statusStr)
		if t, err := parseTime(appliedStr); err == nil {
			r.AppliedAt = t
		}
		if expiresStr != "" {
			if t, err := parseTime(expiresStr); err == nil {
				r.ExpiresAt = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkReceiptsUploaded marks a batch of receipt IDs as successfully uploaded.
func (s *Store) MarkReceiptsUploaded(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := formatTime(time.Now().UTC())
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE action_receipts SET upload_status=?, uploaded_at=? WHERE id=?`,
			receiptUploadUploaded, now, id,
		); err != nil {
			return fmt.Errorf("mark receipt %s uploaded: %w", id, err)
		}
	}
	return nil
}

// MarkReceiptsFailed marks a batch of receipt IDs as upload-failed so they
// will be retried on the next cycle.
func (s *Store) MarkReceiptsFailed(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE action_receipts SET upload_status=? WHERE id=?`,
			receiptUploadFailed, id,
		); err != nil {
			return fmt.Errorf("mark receipt %s failed: %w", id, err)
		}
	}
	return nil
}

// PruneUploadedReceipts deletes successfully uploaded receipts older than cutoff.
func (s *Store) PruneUploadedReceipts(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM action_receipts WHERE upload_status=? AND applied_at<?`,
		receiptUploadUploaded, formatTime(cutoff),
	)
	if err != nil {
		return 0, fmt.Errorf("prune uploaded receipts: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
