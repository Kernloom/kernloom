// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package sqlite provides a SQLite-backed store for graph edges.
package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	_ "modernc.org/sqlite"
)

// isDuplicateColumn returns true when a SQLite ALTER TABLE error is caused by
// an already-existing column — the expected outcome when migrating an older DB.
func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

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
	attributes_json   TEXT    NOT NULL DEFAULT '{}',
	-- Per-edge traffic baseline (EWMA). Populated automatically while the edge
	-- is in the graph learner's observation loop.
	bl_pps_median     REAL    NOT NULL DEFAULT 0,
	bl_pps_mad        REAL    NOT NULL DEFAULT 0,
	bl_bytes_median   REAL    NOT NULL DEFAULT 0,
	bl_bytes_mad      REAL    NOT NULL DEFAULT 0,
	bl_obs            INTEGER NOT NULL DEFAULT 0,
	bl_state          TEXT    NOT NULL DEFAULT 'candidate'
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
		return nil, fmt.Errorf("apply graph schema: %w", err)
	}
	// Migrate existing DBs: add baseline columns if they don't exist yet.
	for _, col := range []string{
		"ALTER TABLE graph_edges ADD COLUMN bl_pps_median   REAL    NOT NULL DEFAULT 0",
		"ALTER TABLE graph_edges ADD COLUMN bl_pps_mad      REAL    NOT NULL DEFAULT 0",
		"ALTER TABLE graph_edges ADD COLUMN bl_bytes_median REAL    NOT NULL DEFAULT 0",
		"ALTER TABLE graph_edges ADD COLUMN bl_bytes_mad    REAL    NOT NULL DEFAULT 0",
		"ALTER TABLE graph_edges ADD COLUMN bl_obs          INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE graph_edges ADD COLUMN bl_state        TEXT    NOT NULL DEFAULT 'candidate'",
	} {
		if _, err := db.Exec(col); err != nil {
			// "duplicate column name" is expected on fresh DBs — ignore it.
			if !isDuplicateColumn(err) {
				db.Close()
				return nil, fmt.Errorf("migrate baseline columns: %w", err)
			}
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// ResetEdges deletes graph edges for nodeID. When keepAdminStates is true only
// candidate, learned and expired edges are removed — frozen and approved edges
// (explicit admin decisions) are preserved. Pass keepAdminStates=false to wipe
// everything.
func (s *Store) ResetEdges(nodeID string, keepAdminStates bool) (int, error) {
	var res sql.Result
	var err error
	if keepAdminStates {
		res, err = s.db.Exec(`
			DELETE FROM graph_edges
			WHERE node_id=? AND state NOT IN (?,?)`,
			nodeID,
			string(graph.EdgeFrozen), string(graph.EdgeApproved),
		)
	} else {
		res, err = s.db.Exec(`DELETE FROM graph_edges WHERE node_id=?`, nodeID)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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
			-- Expired edges restart the learning cycle from scratch.
			-- Denied and frozen edges are intentional admin decisions and are never overwritten.
			state            = CASE WHEN state = 'expired' THEN excluded.state ELSE state END,
			first_seen_at    = CASE WHEN state = 'expired' THEN excluded.first_seen_at ELSE first_seen_at END,
			last_seen_at     = MAX(last_seen_at, excluded.last_seen_at),
			seen_count       = CASE WHEN state = 'expired' THEN excluded.seen_count ELSE seen_count + excluded.seen_count END,
			distinct_windows = CASE WHEN state = 'expired' THEN excluded.distinct_windows ELSE distinct_windows + excluded.distinct_windows END,
			packets_total    = CASE WHEN state = 'expired' THEN excluded.packets_total ELSE packets_total + excluded.packets_total END,
			bytes_total      = CASE WHEN state = 'expired' THEN excluded.bytes_total ELSE bytes_total + excluded.bytes_total END,
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
// Admin decisions (approved, denied, frozen) are never auto-expired.
// Candidate edges that have not yet reached minSeenCount are also protected:
// they are still being learned and should not be discarded before they have
// had a fair chance to accumulate enough observations for promotion.
func (s *Store) MarkExpired(nodeID string, cutoff time.Time, minSeenCount uint64) (int, error) {
	res, err := s.db.Exec(`
		UPDATE graph_edges SET state=?
		WHERE node_id=? AND last_seen_at < ?
		  AND state NOT IN (?,?,?,?)
		  AND (state != ? OR seen_count >= ?)
	`,
		string(graph.EdgeExpired),
		nodeID, cutoff.UnixNano(),
		string(graph.EdgeApproved), string(graph.EdgeDenied),
		string(graph.EdgeExpired), string(graph.EdgeFrozen),
		string(graph.EdgeCandidate), minSeenCount,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ExpireCandidatesBySource marks as expired fresh candidate edges for nodeID
// whose source_id matches sourceID. Only candidates with seen_count < minSeenCount
// are removed — these are the edges that "snuck in" during an attack burst before
// the signal fired. Established candidates (seen_count >= minSeenCount) represent
// real historical traffic from the source and are preserved even when the source
// momentarily triggers a suspicious signal.
func (s *Store) ExpireCandidatesBySource(nodeID, sourceID string, minSeenCount uint64) (int, error) {
	res, err := s.db.Exec(`
		UPDATE graph_edges SET state=?
		WHERE node_id=? AND source_id=? AND state=? AND seen_count < ?
	`,
		string(graph.EdgeExpired),
		nodeID, sourceID,
		string(graph.EdgeCandidate), minSeenCount,
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

// UpdateEdgeBaseline updates the EWMA baseline stats for a specific edge.
// alphaStable is the long-run adaptation speed (e.g. 0.02).
// alphaBootstrap is used while obs < minObs (candidate phase) to converge
// faster during initial learning (e.g. 0.10). Pass 0 to always use alphaStable.
// Only call this when the source is NOT flagged as suspicious (anti-poisoning).
func (s *Store) UpdateEdgeBaseline(key graph.EdgeKey, pps, bytesPS, alphaStable, alphaBootstrap float64, minObs uint64) error {
	// Load current stats.
	row := s.db.QueryRow(`
		SELECT bl_pps_median, bl_pps_mad, bl_bytes_median, bl_bytes_mad, bl_obs, bl_state, id
		FROM graph_edges
		WHERE node_id=? AND source_kind=? AND source_id=?
		  AND destination_kind=? AND destination_id=?
		  AND protocol=? AND destination_port=? AND direction=?`,
		key.NodeID, string(key.SourceKind), key.SourceID,
		string(key.DestinationKind), key.DestinationID,
		key.Protocol, key.DestinationPort, string(key.Direction),
	)
	var ppsMedian, ppsMad, bytesMedian, bytesMad float64
	var obs uint64
	var blState, edgeID string
	if err := row.Scan(&ppsMedian, &ppsMad, &bytesMedian, &bytesMad, &obs, &blState, &edgeID); err != nil {
		return nil // edge not found yet — upsert hasn't run, skip
	}

	// Choose alpha: bootstrap phase uses faster adaptation until min_observations
	// is reached, then switches to the stable (slower) alpha.
	a := alphaStable
	if alphaBootstrap > alphaStable && obs < minObs {
		a = alphaBootstrap
	}

	// EWMA update.
	if obs == 0 {
		ppsMedian, bytesMedian = pps, bytesPS
	} else {
		ppsMad = (1-a)*ppsMad + a*abs64(pps-ppsMedian)
		ppsMedian = (1-a)*ppsMedian + a*pps
		bytesMad = (1-a)*bytesMad + a*abs64(bytesPS-bytesMedian)
		bytesMedian = (1-a)*bytesMedian + a*bytesPS
	}
	obs++

	newState := blState
	if blState == "candidate" && obs >= minObs {
		newState = "learned"
	}

	_, err := s.db.Exec(`
		UPDATE graph_edges SET
			bl_pps_median=?, bl_pps_mad=?, bl_bytes_median=?, bl_bytes_mad=?,
			bl_obs=?, bl_state=?
		WHERE id=?`,
		ppsMedian, ppsMad, bytesMedian, bytesMad, obs, newState, edgeID,
	)
	return err
}

// EdgeBaselineDeviation returns deviation factors for a specific edge's current
// traffic vs its learned baseline. Returns 0,0 if not yet learned.
func (s *Store) EdgeBaselineDeviation(key graph.EdgeKey, pps, bytesPS float64) (devPPS, devBytes float64) {
	row := s.db.QueryRow(`
		SELECT bl_pps_median, bl_pps_mad, bl_bytes_median, bl_bytes_mad, bl_state
		FROM graph_edges
		WHERE node_id=? AND source_kind=? AND source_id=?
		  AND destination_kind=? AND destination_id=?
		  AND protocol=? AND destination_port=? AND direction=?`,
		key.NodeID, string(key.SourceKind), key.SourceID,
		string(key.DestinationKind), key.DestinationID,
		key.Protocol, key.DestinationPort, string(key.Direction),
	)
	var ppsMedian, ppsMad, bytesMedian, bytesMad float64
	var blState string
	if err := row.Scan(&ppsMedian, &ppsMad, &bytesMedian, &bytesMad, &blState); err != nil {
		return 0, 0
	}
	if blState != "learned" {
		return 0, 0
	}
	if ppsMad > 0.001 {
		devPPS = abs64(pps-ppsMedian) / ppsMad
	}
	if bytesMad > 0.001 {
		devBytes = abs64(bytesPS-bytesMedian) / bytesMad
	}
	return
}

func abs64(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// EdgeBaselineSummary holds the per-edge baseline stats alongside the edge key
// fields needed for display (source, destination, protocol, port, direction).
type EdgeBaselineSummary struct {
	SourceID        string
	DestinationID   string
	Protocol        string
	DestinationPort uint16
	Direction       string
	GraphState      string
	BLState         string
	BLObs           uint64
	BLPPSMedian     float64
	BLPPSMad        float64
	BLBytesMedian   float64
	BLBytesMad      float64
}

// ResetEdgeBaselines zeros the bl_* columns for all edges belonging to nodeID.
// Graph state, seen counts and other edge fields are preserved.
func (s *Store) ResetEdgeBaselines(nodeID string) (int, error) {
	res, err := s.db.Exec(`
		UPDATE graph_edges
		SET bl_pps_median=0, bl_pps_mad=0, bl_bytes_median=0, bl_bytes_mad=0,
		    bl_obs=0, bl_state='candidate'
		WHERE node_id=?`, nodeID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListEdgeBaselines returns all edges for nodeID that have at least one
// baseline observation, ordered by bl_state (learned first) then by obs count.
func (s *Store) ListEdgeBaselines(nodeID string) ([]EdgeBaselineSummary, error) {
	rows, err := s.db.Query(`
		SELECT source_id, destination_id, protocol, destination_port, direction,
		       state, bl_state, bl_obs,
		       bl_pps_median, bl_pps_mad, bl_bytes_median, bl_bytes_mad
		FROM graph_edges
		WHERE node_id=? AND bl_obs > 0
		ORDER BY
			CASE bl_state WHEN 'learned' THEN 0 ELSE 1 END,
			bl_obs DESC
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EdgeBaselineSummary
	for rows.Next() {
		var e EdgeBaselineSummary
		if err := rows.Scan(
			&e.SourceID, &e.DestinationID, &e.Protocol, &e.DestinationPort, &e.Direction,
			&e.GraphState, &e.BLState, &e.BLObs,
			&e.BLPPSMedian, &e.BLPPSMad, &e.BLBytesMedian, &e.BLBytesMad,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
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
