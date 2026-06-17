// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/entity"
)

// stableID computes the deterministic stable_id for an entity (package-private).
func stableID(kind entity.Kind, id, namespace string) string {
	h := sha256.Sum256([]byte(string(kind) + ":" + id + ":" + namespace))
	return fmt.Sprintf("%x", h)
}

// StableEntityID is the exported form of stableID for use by extractors and
// other packages that need to compute stable IDs without importing entity.Kind.
func StableEntityID(kind, id, namespace string) string {
	h := sha256.Sum256([]byte(kind + ":" + id + ":" + namespace))
	return fmt.Sprintf("%x", h)
}

// UpsertEntity inserts or updates an entity record.
// If the entity already exists, first_seen_at is preserved and last_seen_at is updated.
func (s *Store) UpsertEntity(ctx context.Context, e entity.Entity) error {
	sid := stableID(e.Kind, e.ID, e.Namespace)

	labels, err := json.Marshal(e.Labels)
	if err != nil {
		labels = []byte("{}")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	firstSeen := e.FirstSeenAt.UTC().Format(time.RFC3339Nano)
	lastSeen := e.LastSeenAt.UTC().Format(time.RFC3339Nano)
	if e.FirstSeenAt.IsZero() {
		firstSeen = now
	}
	if e.LastSeenAt.IsZero() {
		lastSeen = now
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO entities
			(stable_id, kind, id, namespace, display_name, labels,
			 source_adapter, confidence, first_seen_at, last_seen_at,
			 created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(stable_id) DO UPDATE SET
			last_seen_at   = excluded.last_seen_at,
			display_name   = excluded.display_name,
			labels         = excluded.labels,
			source_adapter = excluded.source_adapter,
			confidence     = excluded.confidence,
			updated_at     = excluded.updated_at
	`,
		sid, string(e.Kind), e.ID, e.Namespace, e.DisplayName, string(labels),
		e.SourceAdapter, e.Confidence, firstSeen, lastSeen, now, now,
	)
	return err
}

// GetEntityByStableID looks up an entity directly by its stable_id primary key.
// Returns nil, nil if not found.
func (s *Store) GetEntityByStableID(ctx context.Context, stableID string) (*entity.Entity, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT stable_id, kind, id, namespace, display_name, labels,
		        source_adapter, confidence, first_seen_at, last_seen_at
		 FROM entities WHERE stable_id = ?`, stableID)

	var e entity.Entity
	var labelsJSON, firstSeen, lastSeen string
	err := row.Scan(&e.StableID, (*string)(&e.Kind), &e.ID, &e.Namespace,
		&e.DisplayName, &labelsJSON, &e.SourceAdapter, &e.Confidence,
		&firstSeen, &lastSeen)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(labelsJSON), &e.Labels)
	e.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, firstSeen)
	e.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
	return &e, nil
}

// GetEntity looks up an entity by kind+id+namespace.
// Returns nil, nil if not found.
func (s *Store) GetEntity(ctx context.Context, kind entity.Kind, id, namespace string) (*entity.Entity, error) {
	sid := stableID(kind, id, namespace)

	row := s.db.QueryRowContext(ctx,
		`SELECT stable_id, kind, id, namespace, display_name, labels,
		        source_adapter, confidence, first_seen_at, last_seen_at
		 FROM entities WHERE stable_id = ?`, sid)

	var e entity.Entity
	var labelsJSON string
	var firstSeen, lastSeen string

	err := row.Scan(&e.StableID, (*string)(&e.Kind), &e.ID, &e.Namespace,
		&e.DisplayName, &labelsJSON, &e.SourceAdapter, &e.Confidence,
		&firstSeen, &lastSeen)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}

	_ = json.Unmarshal([]byte(labelsJSON), &e.Labels)
	e.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, firstSeen)
	e.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
	return &e, nil
}
