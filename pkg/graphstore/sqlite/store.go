// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package sqlite provides a SQLite-backed store for graph edges.
package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS graph_edges (
	id                TEXT    NOT NULL PRIMARY KEY,
	node_id           TEXT    NOT NULL,
	source_kind       TEXT    NOT NULL,
	source_id         TEXT    NOT NULL,
	destination_kind  TEXT    NOT NULL,
	destination_id    TEXT    NOT NULL,
	protocol          TEXT    NOT NULL,
	destination_port  INTEGER NOT NULL DEFAULT 0,
	direction         TEXT    NOT NULL,
	first_seen_at     INTEGER NOT NULL,
	last_seen_at      INTEGER NOT NULL,
	seen_count        INTEGER NOT NULL DEFAULT 1,
	distinct_windows  INTEGER NOT NULL DEFAULT 1,
	packets_total     INTEGER NOT NULL DEFAULT 0,
	bytes_total       INTEGER NOT NULL DEFAULT 0,
	confidence        INTEGER NOT NULL DEFAULT 0,
	state             TEXT    NOT NULL,
	learned_by        TEXT    NOT NULL,
	attributes_json   TEXT    NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_key ON graph_edges (
	node_id, source_kind, source_id,
	destination_kind, destination_id,
	protocol, destination_port, direction
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_node       ON graph_edges (node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_last_seen  ON graph_edges (last_seen_at);
CREATE INDEX IF NOT EXISTS idx_graph_edges_state      ON graph_edges (state);
`

// Store is a SQLite-backed graph edge store.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at path and applies the schema.
// Use ":memory:" for an in-memory database (tests).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite does not support concurrent writers
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Upsert inserts a new edge or, if the edge key already exists, merges the
// observation counters and updates LastSeenAt, State and Confidence.
// It returns the current (post-upsert) edge.
func (s *Store) Upsert(e *graph.Edge) (*graph.Edge, error) {
	attrs, err := json.Marshal(e.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal attributes: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO graph_edges (
			id, node_id,
			source_kind, source_id,
			destination_kind, destination_id,
			protocol, destination_port, direction,
			first_seen_at, last_seen_at,
			seen_count, distinct_windows,
			packets_total, bytes_total,
			confidence, state, learned_by, attributes_json
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id,source_kind,source_id,destination_kind,destination_id,protocol,destination_port,direction)
		DO UPDATE SET
			last_seen_at     = MAX(last_seen_at, excluded.last_seen_at),
			seen_count       = seen_count + excluded.seen_count,
			distinct_windows = distinct_windows + excluded.distinct_windows,
			packets_total    = packets_total + excluded.packets_total,
			bytes_total      = bytes_total + excluded.bytes_total,
			confidence       = excluded.confidence,
			attributes_json  = excluded.attributes_json
	`,
		e.ID, e.NodeID,
		string(e.Source.Kind), e.Source.ID,
		string(e.Destination.Kind), e.Destination.ID,
		e.Protocol, e.DestinationPort, string(e.Direction),
		e.FirstSeenAt.UnixNano(), e.LastSeenAt.UnixNano(),
		e.SeenCount, e.DistinctWindows,
		e.PacketsTotal, e.BytesTotal,
		e.Confidence, string(e.State), string(e.LearnedBy),
		string(attrs),
	)
	if err != nil {
		return nil, fmt.Errorf("upsert edge: %w", err)
	}
	return s.GetByKey(e.Key())
}

// GetByKey returns the edge matching the given key, or nil if not found.
func (s *Store) GetByKey(key graph.EdgeKey) (*graph.Edge, error) {
	row := s.db.QueryRow(`
		SELECT id, node_id,
		       source_kind, source_id,
		       destination_kind, destination_id,
		       protocol, destination_port, direction,
		       first_seen_at, last_seen_at,
		       seen_count, distinct_windows,
		       packets_total, bytes_total,
		       confidence, state, learned_by, attributes_json
		FROM graph_edges
		WHERE node_id=? AND source_kind=? AND source_id=?
		  AND destination_kind=? AND destination_id=?
		  AND protocol=? AND destination_port=? AND direction=?
	`,
		key.NodeID,
		string(key.SourceKind), key.SourceID,
		string(key.DestinationKind), key.DestinationID,
		key.Protocol, key.DestinationPort, string(key.Direction),
	)
	return scanEdge(row)
}

// UpdateState updates only the state and learned_by fields for an existing edge.
func (s *Store) UpdateState(id string, state graph.EdgeState, by graph.LearnedBy) error {
	_, err := s.db.Exec(
		`UPDATE graph_edges SET state=?, learned_by=? WHERE id=?`,
		string(state), string(by), id,
	)
	return err
}

// ListByNode returns all edges for a node, optionally filtered by state.
// Pass an empty string to return all states.
func (s *Store) ListByNode(nodeID string, state graph.EdgeState) ([]*graph.Edge, error) {
	var rows *sql.Rows
	var err error
	if state == "" {
		rows, err = s.db.Query(`
			SELECT id, node_id,
			       source_kind, source_id,
			       destination_kind, destination_id,
			       protocol, destination_port, direction,
			       first_seen_at, last_seen_at,
			       seen_count, distinct_windows,
			       packets_total, bytes_total,
			       confidence, state, learned_by, attributes_json
			FROM graph_edges WHERE node_id=?
			ORDER BY last_seen_at DESC
		`, nodeID)
	} else {
		rows, err = s.db.Query(`
			SELECT id, node_id,
			       source_kind, source_id,
			       destination_kind, destination_id,
			       protocol, destination_port, direction,
			       first_seen_at, last_seen_at,
			       seen_count, distinct_windows,
			       packets_total, bytes_total,
			       confidence, state, learned_by, attributes_json
			FROM graph_edges WHERE node_id=? AND state=?
			ORDER BY last_seen_at DESC
		`, nodeID, string(state))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectEdges(rows)
}

// PromoteCandidates promotes all candidate edges for nodeID that meet cfg criteria.
// Returns the number of edges promoted.
func (s *Store) PromoteCandidates(nodeID string, cfg graph.PromotionConfig, now time.Time) (int, error) {
	candidates, err := s.ListByNode(nodeID, graph.EdgeCandidate)
	if err != nil {
		return 0, err
	}
	promoted := 0
	for _, e := range candidates {
		if !e.ShouldPromote(cfg, now) {
			continue
		}
		if err := s.UpdateState(e.ID, graph.EdgeLearned, graph.LearnedByLocal); err != nil {
			return promoted, err
		}
		promoted++
	}
	return promoted, nil
}

// MarkExpired marks as expired all edges not seen since before cutoff.
func (s *Store) MarkExpired(nodeID string, cutoff time.Time) (int, error) {
	res, err := s.db.Exec(`
		UPDATE graph_edges SET state=?
		WHERE node_id=? AND last_seen_at < ? AND state NOT IN (?,?,?)
	`,
		string(graph.EdgeExpired),
		nodeID, cutoff.UnixNano(),
		string(graph.EdgeDenied), string(graph.EdgeExpired), string(graph.EdgeFrozen),
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Stats returns a count of edges per state for a node.
func (s *Store) Stats(nodeID string) (map[graph.EdgeState]int, error) {
	rows, err := s.db.Query(
		`SELECT state, COUNT(*) FROM graph_edges WHERE node_id=? GROUP BY state`, nodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[graph.EdgeState]int)
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[graph.EdgeState(st)] = n
	}
	return out, rows.Err()
}

// scanEdge scans one row into an Edge. Returns nil, nil when no row is found.
func scanEdge(row *sql.Row) (*graph.Edge, error) {
	var (
		e                                       graph.Edge
		srcKind, dstKind, dir, state, learnedBy string
		firstNano, lastNano                     int64
		attrsJSON                               string
	)
	err := row.Scan(
		&e.ID, &e.NodeID,
		&srcKind, &e.Source.ID,
		&dstKind, &e.Destination.ID,
		&e.Protocol, &e.DestinationPort, &dir,
		&firstNano, &lastNano,
		&e.SeenCount, &e.DistinctWindows,
		&e.PacketsTotal, &e.BytesTotal,
		&e.Confidence, &state, &learnedBy, &attrsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Source.Kind = observation.EntityKind(srcKind)
	e.Destination.Kind = observation.EntityKind(dstKind)
	e.Direction = graph.Direction(dir)
	e.State = graph.EdgeState(state)
	e.LearnedBy = graph.LearnedBy(learnedBy)
	e.FirstSeenAt = time.Unix(0, firstNano).UTC()
	e.LastSeenAt = time.Unix(0, lastNano).UTC()
	if err := json.Unmarshal([]byte(attrsJSON), &e.Attributes); err != nil {
		e.Attributes = make(map[string]string)
	}
	return &e, nil
}

// collectEdges collects all rows into a slice of edges.
func collectEdges(rows *sql.Rows) ([]*graph.Edge, error) {
	var out []*graph.Edge
	for rows.Next() {
		var (
			e                                       graph.Edge
			srcKind, dstKind, dir, state, learnedBy string
			firstNano, lastNano                     int64
			attrsJSON                               string
		)
		if err := rows.Scan(
			&e.ID, &e.NodeID,
			&srcKind, &e.Source.ID,
			&dstKind, &e.Destination.ID,
			&e.Protocol, &e.DestinationPort, &dir,
			&firstNano, &lastNano,
			&e.SeenCount, &e.DistinctWindows,
			&e.PacketsTotal, &e.BytesTotal,
			&e.Confidence, &state, &learnedBy, &attrsJSON,
		); err != nil {
			return nil, err
		}
		e.Source.Kind = observation.EntityKind(srcKind)
		e.Destination.Kind = observation.EntityKind(dstKind)
		e.Direction = graph.Direction(dir)
		e.State = graph.EdgeState(state)
		e.LearnedBy = graph.LearnedBy(learnedBy)
		e.FirstSeenAt = time.Unix(0, firstNano).UTC()
		e.LastSeenAt = time.Unix(0, lastNano).UTC()
		if err := json.Unmarshal([]byte(attrsJSON), &e.Attributes); err != nil {
			e.Attributes = make(map[string]string)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
