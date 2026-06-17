// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package graph defines the communication graph model used by KLIQ for
// local graph learning and anomaly detection.
package graph

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/entity"
)

// EdgeState represents the lifecycle state of a graph edge.
type EdgeState string

const (
	// EdgeCandidate is a newly observed edge; not yet confirmed as normal.
	EdgeCandidate EdgeState = "candidate"
	// EdgeLearned has been observed repeatedly and is considered baseline.
	EdgeLearned EdgeState = "learned"
	// EdgeApproved has been explicitly confirmed by policy, admin or Forge.
	EdgeApproved EdgeState = "approved"
	// EdgeFrozen belongs to a frozen graph; new edges trigger signals.
	EdgeFrozen EdgeState = "frozen"
	// EdgeDenied must not be permitted.
	EdgeDenied EdgeState = "denied"
	// EdgeExpired has not been seen for a long time and may be pruned.
	EdgeExpired EdgeState = "expired"
)

// Direction describes the flow direction of an edge relative to the local node.
type Direction string

const (
	DirectionIngress  Direction = "ingress"
	DirectionEgress   Direction = "egress"
	DirectionEastWest Direction = "eastwest"
)

// LearnedBy describes what caused the edge to transition to its current state.
type LearnedBy string

const (
	LearnedByLocal     LearnedBy = "local"
	LearnedByForge     LearnedBy = "forge"
	LearnedByAdmin     LearnedBy = "admin"
	LearnedByCorrelate LearnedBy = "correlate"
)

// EdgeKey uniquely identifies a communication edge on a node.
type EdgeKey struct {
	NodeID          string
	SourceKind      entity.Kind
	SourceID        string
	DestinationKind entity.Kind
	DestinationID   string
	Protocol        string
	DestinationPort uint16
	Direction       Direction
}

// Edge represents a single directed communication relationship observed by KLIQ.
// The state machine follows: candidate → learned → approved → frozen.
// Any state can transition to denied or expired.
type Edge struct {
	// ID is a unique identifier for this edge (UUIDv4).
	ID string `json:"id"`

	// NodeID is the KLIQ node where this edge was observed.
	NodeID string `json:"node_id"`

	// Source is the originating entity.
	Source entity.Ref `json:"source"`

	// Destination is the target entity.
	Destination entity.Ref `json:"destination"`

	// Protocol is the network protocol (tcp, udp, icmp, ...).
	Protocol string `json:"protocol"`

	// DestinationPort is the destination port (0 if not applicable).
	DestinationPort uint16 `json:"destination_port,omitempty"`

	// Direction is ingress, egress, or eastwest relative to the node.
	Direction Direction `json:"direction"`

	// FirstSeenAt is when the edge was first observed.
	FirstSeenAt time.Time `json:"first_seen_at"`

	// LastSeenAt is when the edge was most recently observed.
	LastSeenAt time.Time `json:"last_seen_at"`

	// SeenCount is the total number of times this edge has been observed.
	SeenCount uint64 `json:"seen_count"`

	// DistinctWindows is the number of distinct observation windows this edge appeared in.
	// Used for promotion: an edge seen in many separate windows is more trustworthy.
	DistinctWindows int `json:"distinct_windows"`

	// PacketsTotal is the cumulative packet count across all observations.
	PacketsTotal uint64 `json:"packets_total"`

	// BytesTotal is the cumulative byte count across all observations.
	BytesTotal uint64 `json:"bytes_total"`

	// Confidence is a 0–100 score reflecting how well-established this edge is.
	Confidence int `json:"confidence"`

	// State is the current lifecycle state of this edge.
	State EdgeState `json:"state"`

	// LearnedBy describes what caused the current state.
	LearnedBy LearnedBy `json:"learned_by"`

	// Attributes provide additional context (e.g. "service_hint": "postgres").
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Key returns the EdgeKey for this edge, used for deduplication and lookup.
func (e *Edge) Key() EdgeKey {
	return EdgeKey{
		NodeID:          e.NodeID,
		SourceKind:      e.Source.Kind,
		SourceID:        e.Source.ID,
		DestinationKind: e.Destination.Kind,
		DestinationID:   e.Destination.ID,
		Protocol:        e.Protocol,
		DestinationPort: e.DestinationPort,
		Direction:       e.Direction,
	}
}

// PromotionConfig controls when a candidate edge is promoted to learned.
type PromotionConfig struct {
	// MinSeenCount is the minimum number of observations required.
	MinSeenCount uint64

	// MinDistinctWindows is the minimum number of distinct time windows.
	MinDistinctWindows int

	// MinFirstSeenAge is how old the edge must be before promotion is allowed.
	MinFirstSeenAge time.Duration

	// MaxRiskScore: edges with a confidence-derived risk above this are not promoted.
	// 0 means disabled.
	MaxRiskScore int
}

// ShouldPromote returns true when a candidate edge meets all promotion criteria.
func (e *Edge) ShouldPromote(cfg PromotionConfig, now time.Time) bool {
	if e.State != EdgeCandidate {
		return false
	}
	if e.SeenCount < cfg.MinSeenCount {
		return false
	}
	if e.DistinctWindows < cfg.MinDistinctWindows {
		return false
	}
	if cfg.MinFirstSeenAge > 0 && now.Sub(e.FirstSeenAt) < cfg.MinFirstSeenAge {
		return false
	}
	return true
}

// NewEdge creates a new candidate edge from an observed flow.
func NewEdge(nodeID string, src, dst entity.Ref, proto string, dstPort uint16, dir Direction, now time.Time) *Edge {
	return &Edge{
		ID:              generateID(),
		NodeID:          nodeID,
		Source:          src,
		Destination:     dst,
		Protocol:        proto,
		DestinationPort: dstPort,
		Direction:       dir,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		SeenCount:       1,
		DistinctWindows: 1,
		Confidence:      0,
		State:           EdgeCandidate,
		LearnedBy:       LearnedByLocal,
		Attributes:      make(map[string]string),
	}
}

// generateID returns a random UUIDv4 string.
func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
