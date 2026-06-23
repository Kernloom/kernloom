// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UpsertAdapterState stores an opaque checkpoint blob for an adapter or local
// runtime component.
func (s *Store) UpsertAdapterState(ctx context.Context, adapterID, nodeID string, stateBlob []byte) error {
	if adapterID == "" {
		return fmt.Errorf("adapter_id is required")
	}
	if len(stateBlob) == 0 {
		stateBlob = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO adapter_state (adapter_id, node_id, state_blob, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(adapter_id) DO UPDATE SET
	node_id=excluded.node_id,
	state_blob=excluded.state_blob,
	updated_at=excluded.updated_at`,
		adapterID, nodeID, string(stateBlob), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("upsert adapter_state %q: %w", adapterID, err)
	}
	return nil
}

// GetAdapterState returns an opaque checkpoint blob for an adapter or local
// runtime component.
func (s *Store) GetAdapterState(ctx context.Context, adapterID string) ([]byte, bool, error) {
	if adapterID == "" {
		return nil, false, fmt.Errorf("adapter_id is required")
	}
	var blob string
	row := s.db.QueryRowContext(ctx, `SELECT state_blob FROM adapter_state WHERE adapter_id=?`, adapterID)
	if err := row.Scan(&blob); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get adapter_state %q: %w", adapterID, err)
	}
	return []byte(blob), true, nil
}
