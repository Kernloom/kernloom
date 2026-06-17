// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package sqlite implements the Kernloom state store on top of SQLite.
//
// The store is the single durable backing for:
//   - Entity registry
//   - Relationship (trust graph edge) state
//   - Metric baseline EWMA snapshots
//   - Learning exclusions
//   - Evidence records (TTL-bounded)
//   - Signals and Decisions (TTL-bounded)
//   - Per-adapter checkpoints
//   - Registry version tracking
//
// Hot-path writes go through an async batch writer (see BatchWriter) so that
// per-packet telemetry never blocks on SQLite I/O.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

// Store is the Kernloom SQLite state store.
type Store struct {
	db   *sql.DB
	path string
	mu   sync.RWMutex // guards schema migration; row-level ops use DB transactions
}

// Config controls store behaviour.
type Config struct {
	// Path is the SQLite file path.  Use ":memory:" for tests.
	Path string

	// MaxSizeMB is the soft cap for the DB file.  When exceeded, the GC loop
	// prunes expired evidence/signals more aggressively.  0 = disabled.
	MaxSizeMB int64

	// GCInterval is how often the GC loop runs.  Default: 5 minutes.
	GCInterval time.Duration

	// EvidenceTTL is the default TTL for evidence rows when not specified by the caller.
	EvidenceTTL time.Duration

	// SignalTTL is the default TTL for signal rows.
	SignalTTL time.Duration
}

// DefaultConfig returns a Config with sensible production defaults.
func DefaultConfig(path string) Config {
	return Config{
		Path:        path,
		MaxSizeMB:   256,
		GCInterval:  5 * time.Minute,
		EvidenceTTL: 24 * time.Hour,
		SignalTTL:   7 * 24 * time.Hour,
	}
}

// Open opens (or creates) a SQLite state store and runs schema migrations.
func Open(cfg Config) (*Store, error) {
	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("statestore open %q: %w", cfg.Path, err)
	}
	// SQLite is single-writer; keep one write connection.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: cfg.Path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("statestore migrate: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the raw *sql.DB for callers that need direct access (e.g. batch writers).
// Prefer the typed methods on Store over raw SQL where possible.
func (s *Store) DB() *sql.DB {
	return s.db
}

// migrate applies the schema DDL and records the current version.
func (s *Store) migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("apply schema DDL: %w", err)
	}

	var applied int
	row := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`)
	if err := row.Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	// Version 2: remove FK constraints from relationships (SQLite requires table recreation).
	// Also disables foreign_keys during recreation to avoid constraint errors.
	if applied < 2 {
		steps := []string{
			`PRAGMA foreign_keys = OFF`,
			`CREATE TABLE IF NOT EXISTS relationships_v2 (
				id                TEXT    PRIMARY KEY,
				node_id           TEXT    NOT NULL,
				subject_entity_id TEXT    NOT NULL,
				predicate         TEXT    NOT NULL,
				object_entity_id  TEXT    NOT NULL,
				scope_type        TEXT    NOT NULL DEFAULT '',
				scope_id          TEXT    NOT NULL DEFAULT '',
				dimensions        TEXT    NOT NULL DEFAULT '{}',
				dimensions_hash   TEXT    NOT NULL DEFAULT '',
				state             TEXT    NOT NULL DEFAULT 'candidate',
				weight            REAL    NOT NULL DEFAULT 0.0,
				confidence        REAL    NOT NULL DEFAULT 0.0,
				seen_count        INTEGER NOT NULL DEFAULT 1,
				distinct_windows  INTEGER NOT NULL DEFAULT 1,
				first_seen_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
				last_seen_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
				last_evidence_id  TEXT    NOT NULL DEFAULT '',
				learned_by        TEXT    NOT NULL DEFAULT 'local',
				source_adapter    TEXT    NOT NULL DEFAULT '',
				created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
				updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
			)`,
			`INSERT OR IGNORE INTO relationships_v2 SELECT * FROM relationships`,
			`DROP TABLE relationships`,
			`ALTER TABLE relationships_v2 RENAME TO relationships`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_relationships_unique
				ON relationships (node_id, subject_entity_id, predicate, object_entity_id, scope_type, scope_id, dimensions_hash)`,
			`CREATE INDEX IF NOT EXISTS idx_relationships_subject  ON relationships (subject_entity_id)`,
			`CREATE INDEX IF NOT EXISTS idx_relationships_state    ON relationships (state)`,
			`CREATE INDEX IF NOT EXISTS idx_relationships_last_seen ON relationships (last_seen_at)`,
			`PRAGMA foreign_keys = ON`,
			`INSERT OR IGNORE INTO schema_migrations (version) VALUES (2)`,
		}
		for _, step := range steps {
			if _, err := s.db.Exec(step); err != nil {
				return fmt.Errorf("migration v2: %w\nSQL: %s", err, step)
			}
		}
	}

	if applied < 3 {
		steps := []string{
			`CREATE TABLE IF NOT EXISTS action_leases (
				lease_id      TEXT    PRIMARY KEY,
				decision_id   TEXT    NOT NULL,
				proposal_id   TEXT    NOT NULL DEFAULT '',
				node_id       TEXT    NOT NULL DEFAULT '',
				adapter_id    TEXT    NOT NULL,
				target        TEXT    NOT NULL,
				action        TEXT    NOT NULL,
				level         TEXT    NOT NULL DEFAULT '',
				status        TEXT    NOT NULL,
				fencing_token TEXT    NOT NULL,
				policy_id     TEXT    NOT NULL DEFAULT '',
				bundle_id     TEXT    NOT NULL DEFAULT '',
				reason        TEXT    NOT NULL DEFAULT '',
				applied_at    TEXT    NOT NULL,
				expires_at    TEXT    NOT NULL,
				reverted_at   TEXT    NOT NULL DEFAULT '',
				last_error    TEXT    NOT NULL DEFAULT '',
				metadata      TEXT    NOT NULL DEFAULT '{}'
			)`,
			`CREATE INDEX IF NOT EXISTS idx_action_leases_status_expires ON action_leases (status, expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_action_leases_decision ON action_leases (decision_id)`,
			`CREATE INDEX IF NOT EXISTS idx_action_leases_target ON action_leases (adapter_id, target, status)`,
			`INSERT OR IGNORE INTO schema_migrations (version) VALUES (3)`,
		}
		for _, step := range steps {
			if _, err := s.db.Exec(step); err != nil {
				return fmt.Errorf("migration v3: %w\nSQL: %s", err, step)
			}
		}
	}

	return nil
}

// GC deletes expired rows from evidence, signals, decisions, and learning_exclusions.
// Call this on a timer (see Config.GCInterval).
func (s *Store) GC(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339)
	tables := []struct{ table, col string }{
		{"evidence", "expires_at"},
		{"signals", "expires_at"},
		{"decisions", "expires_at"},
	}
	for _, t := range tables {
		q := fmt.Sprintf(`DELETE FROM %s WHERE %s < ?`, t.table, t.col)
		if _, err := s.db.ExecContext(ctx, q, now); err != nil {
			return fmt.Errorf("gc %s: %w", t.table, err)
		}
	}
	// Expire learning_exclusions by status.
	_, err := s.db.ExecContext(ctx,
		`UPDATE learning_exclusions SET status='expired'
		 WHERE status='active' AND expires_at < ?`, now)
	if err != nil {
		return fmt.Errorf("gc learning_exclusions: %w", err)
	}
	return nil
}

// RunGCLoop starts a background GC loop that runs until ctx is cancelled.
func (s *Store) RunGCLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.GC(ctx)
		}
	}
}
