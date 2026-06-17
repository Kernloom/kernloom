// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

// schema is the canonical DDL for the Kernloom state store.
//
// Design principles:
//   - WAL mode + NORMAL sync: durable enough for operational state, fast enough for the hot path.
//   - Bounded size: evidence and signals have TTL columns; the GC loop prunes expired rows.
//   - Separation of concerns: metric_baselines are *not* the graph_edges table from graphstore.
//     This store is for generic baselines and learning exclusions; graph topology lives in
//     the existing graphstore/sqlite package until the two are unified.
//   - No foreign-key cycles: entities are the root; everything else references them.
const schema = `
PRAGMA journal_mode  = WAL;
PRAGMA synchronous   = NORMAL;
PRAGMA temp_store    = MEMORY;
PRAGMA foreign_keys  = ON;
PRAGMA busy_timeout  = 1000;

-- ── Schema migrations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- ── Entities ──────────────────────────────────────────────────────────────────
-- stable_id = SHA-256(kind || ":" || id || ":" || namespace), hex-encoded.
CREATE TABLE IF NOT EXISTS entities (
    stable_id      TEXT    PRIMARY KEY,
    kind           TEXT    NOT NULL,
    id             TEXT    NOT NULL,
    namespace      TEXT    NOT NULL DEFAULT '',
    display_name   TEXT    NOT NULL DEFAULT '',
    labels         TEXT    NOT NULL DEFAULT '{}',  -- JSON object
    source_adapter TEXT    NOT NULL DEFAULT '',
    confidence     REAL    NOT NULL DEFAULT 0.0,
    first_seen_at  TEXT    NOT NULL,
    last_seen_at   TEXT    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_entities_kind_id ON entities (kind, id);
CREATE INDEX IF NOT EXISTS idx_entities_last_seen ON entities (last_seen_at);

-- ── Relationships ─────────────────────────────────────────────────────────────
-- Generic Subject → Predicate → Object triples with dimension hashing.
CREATE TABLE IF NOT EXISTS relationships (
    id                TEXT    PRIMARY KEY,
    node_id           TEXT    NOT NULL,
    subject_entity_id TEXT    NOT NULL,
    predicate         TEXT    NOT NULL,
    object_entity_id  TEXT    NOT NULL,
    scope_type        TEXT    NOT NULL DEFAULT '',
    scope_id          TEXT    NOT NULL DEFAULT '',
    dimensions        TEXT    NOT NULL DEFAULT '{}',  -- JSON object
    dimensions_hash   TEXT    NOT NULL DEFAULT '',    -- SHA-256 hex of sorted dimensions
    state             TEXT    NOT NULL DEFAULT 'candidate',
    weight            REAL    NOT NULL DEFAULT 0.0,
    confidence        REAL    NOT NULL DEFAULT 0.0,
    seen_count        INTEGER NOT NULL DEFAULT 1,
    distinct_windows  INTEGER NOT NULL DEFAULT 1,
    first_seen_at     TEXT    NOT NULL,
    last_seen_at      TEXT    NOT NULL,
    last_evidence_id  TEXT    NOT NULL DEFAULT '',
    learned_by        TEXT    NOT NULL DEFAULT 'local',
    source_adapter    TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_relationships_unique
    ON relationships (node_id, subject_entity_id, predicate, object_entity_id, scope_type, scope_id, dimensions_hash);
CREATE INDEX IF NOT EXISTS idx_relationships_subject  ON relationships (subject_entity_id);
CREATE INDEX IF NOT EXISTS idx_relationships_state    ON relationships (state);
CREATE INDEX IF NOT EXISTS idx_relationships_last_seen ON relationships (last_seen_at);

-- ── Metric baselines ──────────────────────────────────────────────────────────
-- One row per unique baseline key (metric_id + scope + subject + object +
-- dimensions_hash + measurement semantics + window_seconds).
-- EWMA state is stored as JSON to allow adding fields without schema migration.
CREATE TABLE IF NOT EXISTS metric_baselines (
    id               TEXT    PRIMARY KEY,
    metric_id        TEXT    NOT NULL,
    scope_type       TEXT    NOT NULL DEFAULT '',
    scope_id         TEXT    NOT NULL DEFAULT '',
    subject_entity_id TEXT   NOT NULL,
    object_entity_id TEXT    NOT NULL DEFAULT '',
    dimensions_hash  TEXT    NOT NULL DEFAULT '',
    source_class     TEXT    NOT NULL DEFAULT '',
    visibility_point TEXT    NOT NULL DEFAULT '',
    measurement_type TEXT    NOT NULL DEFAULT '',
    truth_class      TEXT    NOT NULL DEFAULT '',
    window_seconds   INTEGER NOT NULL DEFAULT 60,
    state            TEXT    NOT NULL DEFAULT 'candidate',
    ewma_state       TEXT    NOT NULL DEFAULT '{}',  -- JSON: median, mad, peak, observations
    observations     INTEGER NOT NULL DEFAULT 0,
    last_updated_at  TEXT    NOT NULL,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_metric_baselines_key
    ON metric_baselines (metric_id, scope_type, scope_id, subject_entity_id,
                         object_entity_id, dimensions_hash, source_class,
                         visibility_point, measurement_type, truth_class, window_seconds);
CREATE INDEX IF NOT EXISTS idx_metric_baselines_subject ON metric_baselines (subject_entity_id);

-- ── Learning exclusions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_exclusions (
    id               TEXT    PRIMARY KEY,
    entity_id        TEXT    NOT NULL,
    entity_kind      TEXT    NOT NULL DEFAULT '',
    scope_type       TEXT    NOT NULL DEFAULT '',
    scope_id         TEXT    NOT NULL DEFAULT '',
    reason           TEXT    NOT NULL,
    severity         REAL    NOT NULL DEFAULT 0.0,
    decision_id      TEXT    NOT NULL DEFAULT '',
    signal_id        TEXT    NOT NULL DEFAULT '',
    applies_to       TEXT    NOT NULL DEFAULT '[]',  -- JSON array of AppliesTo values
    starts_at        TEXT    NOT NULL,
    expires_at       TEXT    NOT NULL,
    source_component TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'active',
    metadata         TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_exclusions_entity   ON learning_exclusions (entity_id, status);
CREATE INDEX IF NOT EXISTS idx_exclusions_expires  ON learning_exclusions (expires_at, status);

-- ── Evidence ──────────────────────────────────────────────────────────────────
-- Bounded by expires_at; GC loop prunes rows past TTL.
CREATE TABLE IF NOT EXISTS evidence (
    id                     TEXT    PRIMARY KEY,
    observation_type       TEXT    NOT NULL DEFAULT '',
    source_adapter         TEXT    NOT NULL DEFAULT '',
    source_node_id         TEXT    NOT NULL DEFAULT '',
    subject_entity_id      TEXT    NOT NULL DEFAULT '',
    object_entity_id       TEXT    NOT NULL DEFAULT '',
    summary                TEXT    NOT NULL DEFAULT '{}',  -- JSON
    metrics                TEXT    NOT NULL DEFAULT '{}',  -- JSON
    context                TEXT    NOT NULL DEFAULT '{}',  -- JSON
    observed_at            TEXT    NOT NULL,
    ingested_at            TEXT    NOT NULL,
    expires_at             TEXT    NOT NULL,
    learning_eligible      INTEGER NOT NULL DEFAULT 1,
    learning_block_reason  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_subject  ON evidence (subject_entity_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_evidence_expires  ON evidence (expires_at);

-- ── Signals ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS signals (
    id             TEXT    PRIMARY KEY,
    signal_type    TEXT    NOT NULL,
    producer       TEXT    NOT NULL DEFAULT '',
    scope          TEXT    NOT NULL DEFAULT '',
    subject_id     TEXT    NOT NULL DEFAULT '',
    subject_kind   TEXT    NOT NULL DEFAULT '',
    object_id      TEXT    NOT NULL DEFAULT '',
    severity       INTEGER NOT NULL DEFAULT 0,
    attributes     TEXT    NOT NULL DEFAULT '{}',  -- JSON
    emitted_at     TEXT    NOT NULL,
    expires_at     TEXT    NOT NULL,
    node_id        TEXT    NOT NULL DEFAULT '',
    acknowledged   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_signals_subject  ON signals (subject_id, emitted_at);
CREATE INDEX IF NOT EXISTS idx_signals_expires  ON signals (expires_at);
CREATE INDEX IF NOT EXISTS idx_signals_type     ON signals (signal_type);

-- ── Decisions ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS decisions (
    id             TEXT    PRIMARY KEY,
    subject_id     TEXT    NOT NULL,
    subject_kind   TEXT    NOT NULL DEFAULT '',
    action         TEXT    NOT NULL,
    reason         TEXT    NOT NULL DEFAULT '',
    decider        TEXT    NOT NULL DEFAULT '',
    severity       INTEGER NOT NULL DEFAULT 0,
    attributes     TEXT    NOT NULL DEFAULT '{}',  -- JSON
    decided_at     TEXT    NOT NULL,
    expires_at     TEXT    NOT NULL,
    node_id        TEXT    NOT NULL DEFAULT '',
    revoked        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_decisions_subject ON decisions (subject_id, decided_at);
CREATE INDEX IF NOT EXISTS idx_decisions_expires ON decisions (expires_at, revoked);

-- ── Action leases / revert journal ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS action_leases (
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
);
CREATE INDEX IF NOT EXISTS idx_action_leases_status_expires ON action_leases (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_action_leases_decision ON action_leases (decision_id);
CREATE INDEX IF NOT EXISTS idx_action_leases_target ON action_leases (adapter_id, target, status);

-- ── Adapter state ─────────────────────────────────────────────────────────────
-- Opaque per-adapter checkpoint blobs (cursor positions, sequence numbers, etc.)
CREATE TABLE IF NOT EXISTS adapter_state (
    adapter_id  TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL DEFAULT '',
    state_blob  TEXT    NOT NULL DEFAULT '{}',  -- JSON, adapter-defined
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- ── Registry versions ─────────────────────────────────────────────────────────
-- Tracks which Forge registry versions KLIQ has applied.
CREATE TABLE IF NOT EXISTS registry_versions (
    registry_id  TEXT    PRIMARY KEY,
    version      TEXT    NOT NULL,
    applied_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    checksum     TEXT    NOT NULL DEFAULT ''
);
`

// currentSchemaVersion is incremented whenever schema changes are made.
// The migrate() function applies missing versions in order.
const currentSchemaVersion = 3
