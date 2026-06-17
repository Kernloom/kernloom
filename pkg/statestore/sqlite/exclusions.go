// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kernloom/kernloom/pkg/core/learning"
)

// UpsertExclusion inserts or replaces a learning exclusion.
func (s *Store) UpsertExclusion(ctx context.Context, e learning.Exclusion) error {
	appliesToJSON, err := json.Marshal(e.AppliesTo)
	if err != nil {
		appliesToJSON = []byte("[]")
	}
	metaJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO learning_exclusions
			(id, entity_id, entity_kind, scope_type, scope_id,
			 reason, severity, decision_id, signal_id, applies_to,
			 starts_at, expires_at, source_component, status, metadata)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			expires_at       = excluded.expires_at,
			status           = excluded.status,
			severity         = excluded.severity,
			applies_to       = excluded.applies_to,
			metadata         = excluded.metadata
	`,
		e.ID, e.EntityID, e.EntityKind, e.ScopeType, e.ScopeID,
		string(e.Reason), e.Severity, e.DecisionID, e.SignalID, string(appliesToJSON),
		e.StartsAt.UTC().Format(time.RFC3339Nano),
		e.ExpiresAt.UTC().Format(time.RFC3339Nano),
		e.SourceComponent, e.Status, string(metaJSON),
	)
	return err
}

// RevokeExclusion marks an exclusion as revoked.
func (s *Store) RevokeExclusion(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE learning_exclusions SET status='revoked' WHERE id=?`, id)
	return err
}

// ActiveExclusionsFor returns all active exclusions for a given entity ID.
func (s *Store) ActiveExclusionsFor(ctx context.Context, entityID string) ([]learning.Exclusion, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, entity_id, entity_kind, scope_type, scope_id,
		       reason, severity, decision_id, signal_id, applies_to,
		       starts_at, expires_at, source_component, status, metadata
		FROM learning_exclusions
		WHERE entity_id=? AND status='active' AND expires_at > ?
	`, entityID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []learning.Exclusion
	for rows.Next() {
		var ex learning.Exclusion
		var appliesToJSON, metaJSON, startsAt, expiresAt string
		if err := rows.Scan(
			&ex.ID, &ex.EntityID, &ex.EntityKind, &ex.ScopeType, &ex.ScopeID,
			(*string)(&ex.Reason), &ex.Severity, &ex.DecisionID, &ex.SignalID, &appliesToJSON,
			&startsAt, &expiresAt, &ex.SourceComponent, &ex.Status, &metaJSON,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(appliesToJSON), &ex.AppliesTo)
		_ = json.Unmarshal([]byte(metaJSON), &ex.Metadata)
		ex.StartsAt, _ = time.Parse(time.RFC3339Nano, startsAt)
		ex.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
		result = append(result, ex)
	}
	return result, rows.Err()
}
