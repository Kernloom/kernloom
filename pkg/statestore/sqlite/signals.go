// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/signal"
)

// PersistSignal stores a signal in the TTL-bounded signal journal.
func (s *Store) PersistSignal(ctx context.Context, sig signal.Signal, nodeID string) error {
	if sig.ID == "" {
		sig.ID = generateStoreID("sig")
	}
	if sig.Time.IsZero() {
		sig.Time = time.Now().UTC()
	}
	expiresAt := sig.Time.Add(sig.TTL)
	if sig.TTL <= 0 {
		expiresAt = sig.Time.Add(7 * 24 * time.Hour)
	}
	attrs, err := json.Marshal(sig.Attributes)
	if err != nil {
		return fmt.Errorf("marshal signal attributes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT OR REPLACE INTO signals (
	id, signal_type, producer, scope, subject_id, subject_kind, object_id,
	severity, attributes, emitted_at, expires_at, node_id, acknowledged
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sig.ID, string(sig.Type), string(sig.Producer), string(sig.Scope),
		sig.Subject.ID, sig.Subject.Kind, sig.Object.ID, sig.Score,
		string(attrs), sig.Time.UTC().Format(time.RFC3339Nano),
		expiresAt.UTC().Format(time.RFC3339Nano), nodeID, 0)
	if err != nil {
		return fmt.Errorf("persist signal %q: %w", sig.ID, err)
	}
	return nil
}

func generateStoreID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}
