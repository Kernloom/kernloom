// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kernloom/kernloom/pkg/core/baseline"
)

// baselineID computes a deterministic ID for a baseline key.
func baselineID(k baseline.Key) string {
	h := sha256.Sum256([]byte(fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d",
		k.MetricID, k.ScopeType, k.ScopeID,
		k.SubjectEntityID, k.ObjectEntityID, k.DimensionsHash,
		k.SourceClass, k.VisibilityPoint, k.MeasurementType, k.TruthClass,
		k.WindowSeconds,
	)))
	return fmt.Sprintf("%x", h)
}

// DimensionsHash computes the canonical SHA-256 hash of a dimensions map.
// Returns empty string for nil/empty maps.
func DimensionsHash(dims map[string]string) string {
	if len(dims) == 0 {
		return ""
	}
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var s string
	for _, k := range keys {
		s += k + "=" + dims[k] + ";"
	}
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// BaselineRow is the persisted form of a metric baseline bucket.
type BaselineRow struct {
	ID           string
	Key          baseline.Key
	State        string
	EWMAState    map[string]any // adapter-defined EWMA fields
	Observations int64
	LastUpdated  time.Time
	CreatedAt    time.Time
}

// UpsertBaseline writes or updates a baseline row.
// EWMAState is stored as a JSON blob so the schema never needs changing for new metrics.
func (s *Store) UpsertBaseline(ctx context.Context, row BaselineRow) error {
	id := baselineID(row.Key)
	ewmaJSON, err := json.Marshal(row.EWMAState)
	if err != nil {
		ewmaJSON = []byte("{}")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	lastUpdated := row.LastUpdated.UTC().Format(time.RFC3339Nano)
	if row.LastUpdated.IsZero() {
		lastUpdated = now
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO metric_baselines
			(id, metric_id, scope_type, scope_id, subject_entity_id,
			 object_entity_id, dimensions_hash, source_class, visibility_point,
			 measurement_type, truth_class, window_seconds,
			 state, ewma_state, observations, last_updated_at, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(metric_id, scope_type, scope_id, subject_entity_id,
		            object_entity_id, dimensions_hash, source_class,
		            visibility_point, measurement_type, truth_class, window_seconds)
		DO UPDATE SET
			state          = excluded.state,
			ewma_state     = excluded.ewma_state,
			observations   = excluded.observations,
			last_updated_at = excluded.last_updated_at
	`,
		id,
		row.Key.MetricID, row.Key.ScopeType, row.Key.ScopeID, row.Key.SubjectEntityID,
		row.Key.ObjectEntityID, row.Key.DimensionsHash, row.Key.SourceClass,
		row.Key.VisibilityPoint, row.Key.MeasurementType, row.Key.TruthClass, row.Key.WindowSeconds,
		row.State, string(ewmaJSON), row.Observations, lastUpdated, now,
	)
	return err
}

// GetBaseline retrieves a baseline row by key.  Returns nil, nil if not found.
func (s *Store) GetBaseline(ctx context.Context, k baseline.Key) (*BaselineRow, error) {
	id := baselineID(k)
	row := s.db.QueryRowContext(ctx,
		`SELECT id, state, ewma_state, observations, last_updated_at, created_at
		 FROM metric_baselines WHERE id=?`, id)

	var r BaselineRow
	r.Key = k
	r.ID = id
	var ewmaJSON, lastUpdated, createdAt string
	err := row.Scan(&r.ID, &r.State, &ewmaJSON, &r.Observations, &lastUpdated, &createdAt)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(ewmaJSON), &r.EWMAState)
	r.LastUpdated, _ = time.Parse(time.RFC3339Nano, lastUpdated)
	r.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &r, nil
}

// ListBaselinesBySubject returns all baseline rows for a given subject entity.
func (s *Store) ListBaselinesBySubject(ctx context.Context, subjectEntityID string) ([]BaselineRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, metric_id, scope_type, scope_id, subject_entity_id,
		       object_entity_id, dimensions_hash, source_class, visibility_point,
		       measurement_type, truth_class, window_seconds,
		       state, ewma_state, observations, last_updated_at, created_at
		FROM metric_baselines WHERE subject_entity_id=?
	`, subjectEntityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []BaselineRow
	for rows.Next() {
		var r BaselineRow
		var ewmaJSON, lastUpdated, createdAt string
		if err := rows.Scan(
			&r.ID,
			&r.Key.MetricID, &r.Key.ScopeType, &r.Key.ScopeID, &r.Key.SubjectEntityID,
			&r.Key.ObjectEntityID, &r.Key.DimensionsHash, &r.Key.SourceClass,
			&r.Key.VisibilityPoint, &r.Key.MeasurementType, &r.Key.TruthClass, &r.Key.WindowSeconds,
			&r.State, &ewmaJSON, &r.Observations, &lastUpdated, &createdAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ewmaJSON), &r.EWMAState)
		r.LastUpdated, _ = time.Parse(time.RFC3339Nano, lastUpdated)
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		result = append(result, r)
	}
	return result, rows.Err()
}
