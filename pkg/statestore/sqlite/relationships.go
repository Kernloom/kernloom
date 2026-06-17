// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/core/relationship"
)

// UpsertRelationship inserts or updates a relationship.
// On conflict (unique subject+predicate+object+scope+dimensions_hash), seen_count
// and last_seen_at are bumped; state may be promoted by the caller before calling.
//
// If the subject or object entity does not yet exist in the entities table,
// a minimal stub record is created so display queries can resolve the stable_id.
func (s *Store) UpsertRelationship(ctx context.Context, r relationship.Relationship) error {
	// Auto-create minimal entity stubs so CLI queries can resolve hashes to IPs.
	// SubjectLabel/ObjectLabel carry the raw IP set by the extractor; fall back to hash.
	subjLabel := r.SubjectLabel
	if subjLabel == "" {
		subjLabel = r.SubjectEntityID
	}
	objLabel := r.ObjectLabel
	if objLabel == "" {
		objLabel = r.ObjectEntityID
	}
	if r.SubjectEntityID != "" {
		_, _ = s.db.ExecContext(ctx, `
			INSERT INTO entities
				(stable_id, kind, id, namespace, source_adapter, confidence, first_seen_at, last_seen_at)
			VALUES (?, 'ip', ?, '', ?, 0.0,
				strftime('%Y-%m-%dT%H:%M:%SZ','now'),
				strftime('%Y-%m-%dT%H:%M:%SZ','now'))
			ON CONFLICT(stable_id) DO UPDATE SET
				id = excluded.id
			WHERE entities.id = entities.stable_id`,
			r.SubjectEntityID, subjLabel, r.SourceAdapter)
	}
	if r.ObjectEntityID != "" {
		_, _ = s.db.ExecContext(ctx, `
			INSERT INTO entities
				(stable_id, kind, id, namespace, source_adapter, confidence, first_seen_at, last_seen_at)
			VALUES (?, 'ip', ?, '', ?, 0.0,
				strftime('%Y-%m-%dT%H:%M:%SZ','now'),
				strftime('%Y-%m-%dT%H:%M:%SZ','now'))
			ON CONFLICT(stable_id) DO UPDATE SET
				id = excluded.id
			WHERE entities.id = entities.stable_id`,
			r.ObjectEntityID, objLabel, r.SourceAdapter)
	}
	dimsJSON, _ := json.Marshal(r.Dimensions)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	firstSeen := r.FirstSeenAt.UTC().Format(time.RFC3339Nano)
	lastSeen := r.LastSeenAt.UTC().Format(time.RFC3339Nano)
	if r.FirstSeenAt.IsZero() {
		firstSeen = now
	}
	if r.LastSeenAt.IsZero() {
		lastSeen = now
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO relationships
			(id, node_id, subject_entity_id, predicate, object_entity_id,
			 scope_type, scope_id, dimensions, dimensions_hash,
			 state, weight, confidence, seen_count, distinct_windows,
			 first_seen_at, last_seen_at, last_evidence_id,
			 learned_by, source_adapter, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id, subject_entity_id, predicate, object_entity_id,
		            scope_type, scope_id, dimensions_hash)
		DO UPDATE SET
			seen_count       = seen_count + excluded.seen_count,
			distinct_windows = distinct_windows + excluded.distinct_windows,
			last_seen_at     = excluded.last_seen_at,
			last_evidence_id = excluded.last_evidence_id,
			state            = excluded.state,
			weight           = excluded.weight,
			confidence       = excluded.confidence,
			updated_at       = excluded.updated_at
	`,
		r.ID, r.NodeID, r.SubjectEntityID, r.Predicate, r.ObjectEntityID,
		r.ScopeType, r.ScopeID, string(dimsJSON), r.DimensionsHash,
		string(r.State), r.Weight, r.Confidence, r.SeenCount, r.DistinctWindows,
		firstSeen, lastSeen, r.LastEvidenceID,
		string(r.LearnedBy), r.SourceAdapter, now, now,
	)
	return err
}

// GetRelationship looks up a relationship by its stable unique key fields.
func (s *Store) GetRelationship(ctx context.Context, nodeID, subjectID, predicate, objectID, scopeType, scopeID, dimsHash string) (*relationship.Relationship, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, node_id, subject_entity_id, predicate, object_entity_id,
		       scope_type, scope_id, dimensions, dimensions_hash,
		       state, weight, confidence, seen_count, distinct_windows,
		       first_seen_at, last_seen_at, last_evidence_id,
		       learned_by, source_adapter
		FROM relationships
		WHERE node_id=? AND subject_entity_id=? AND predicate=?
		  AND object_entity_id=? AND scope_type=? AND scope_id=? AND dimensions_hash=?
	`, nodeID, subjectID, predicate, objectID, scopeType, scopeID, dimsHash)

	return scanRelationship(row.Scan)
}

// ListRelationships returns relationships for a node, optionally filtered by predicate and state.
// Empty predicate/state means no filter.
func (s *Store) ListRelationships(ctx context.Context, nodeID, predicate, state string) ([]relationship.Relationship, error) {
	q := `SELECT id, node_id, subject_entity_id, predicate, object_entity_id,
		         scope_type, scope_id, dimensions, dimensions_hash,
		         state, weight, confidence, seen_count, distinct_windows,
		         first_seen_at, last_seen_at, last_evidence_id,
		         learned_by, source_adapter
		  FROM relationships WHERE node_id=?`
	args := []any{nodeID}

	if predicate != "" {
		q += " AND predicate=?"
		args = append(args, predicate)
	}
	if state != "" {
		q += " AND state=?"
		args = append(args, state)
	}
	q += " ORDER BY last_seen_at DESC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []relationship.Relationship
	for rows.Next() {
		r, err := scanRelationship(rows.Scan)
		if err != nil {
			return nil, err
		}
		result = append(result, *r)
	}
	return result, rows.Err()
}

// SetRelationshipState updates the state (and confidence) of a relationship by ID.
func (s *Store) SetRelationshipState(ctx context.Context, id string, state relationship.State, confidence float64) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx,
		`UPDATE relationships SET state=?, confidence=?, updated_at=? WHERE id=?`,
		string(state), confidence, now, id)
	return err
}

// FreezeRelationships sets all learned/approved relationships for a node to frozen.
// Returns the count of affected rows.
func (s *Store) FreezeRelationships(ctx context.Context, nodeID string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`UPDATE relationships SET state='frozen', updated_at=?
		 WHERE node_id=? AND state IN ('learned','approved')`,
		now, nodeID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteRelationships removes relationships for a node.
// If keepStates is non-empty, relationships in those states are preserved.
// Returns the count of deleted rows.
func (s *Store) DeleteRelationships(ctx context.Context, nodeID string, keepStates []relationship.State) (int64, error) {
	if len(keepStates) == 0 {
		res, err := s.db.ExecContext(ctx, `DELETE FROM relationships WHERE node_id=?`, nodeID)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	placeholders := make([]string, len(keepStates))
	args := make([]any, 0, len(keepStates)+1)
	args = append(args, nodeID)
	for i, st := range keepStates {
		placeholders[i] = "?"
		args = append(args, string(st))
	}
	q := fmt.Sprintf(`DELETE FROM relationships WHERE node_id=? AND state NOT IN (%s)`,
		strings.Join(placeholders, ","))
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RelationshipStats returns a count per state for a node.
func (s *Store) RelationshipStats(ctx context.Context, nodeID string) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT state, COUNT(*) FROM relationships WHERE node_id=? GROUP BY state`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	m := make(map[string]int64)
	for rows.Next() {
		var st string
		var n int64
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		m[st] = n
	}
	return m, rows.Err()
}

// scanRelationship wraps the common scan logic for a relationship row.
func scanRelationship(scan func(...any) error) (*relationship.Relationship, error) {
	var r relationship.Relationship
	var dimsJSON, state, learnedBy, firstSeen, lastSeen string

	err := scan(
		&r.ID, &r.NodeID, &r.SubjectEntityID, &r.Predicate, &r.ObjectEntityID,
		&r.ScopeType, &r.ScopeID, &dimsJSON, &r.DimensionsHash,
		&state, &r.Weight, &r.Confidence, &r.SeenCount, &r.DistinctWindows,
		&firstSeen, &lastSeen, &r.LastEvidenceID,
		&learnedBy, &r.SourceAdapter,
	)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan relationship: %w", err)
	}
	r.State = relationship.State(state)
	r.LearnedBy = relationship.LearnedBy(learnedBy)
	r.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, firstSeen)
	r.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
	_ = json.Unmarshal([]byte(dimsJSON), &r.Dimensions)
	return &r, nil
}
