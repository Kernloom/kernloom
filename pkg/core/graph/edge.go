// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package graph defines an adapter-neutral relationship graph model. Concrete
// adapters express domain-specific edge identity through Predicate and
// Dimensions instead of adding vendor/network fields to core.
package graph

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"
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

// Direction describes edge direction relative to the local node.
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

// EdgeKey uniquely identifies a relationship edge on a node.
type EdgeKey struct {
	NodeID          string
	SourceKind      entity.Kind
	SourceID        string
	DestinationKind entity.Kind
	DestinationID   string
	Predicate       string
	DimensionsHash  string
	Direction       Direction
}

// Edge represents a single directed relationship observed by KLIQ. The state
// machine follows candidate -> learned -> approved -> frozen. Any state can
// transition to denied or expired.
type Edge struct {
	ID string `json:"id"`

	// NodeID is the KLIQ node where this edge was observed.
	NodeID string `json:"node_id"`

	// Source is the subject entity.
	Source entity.Ref `json:"source"`

	// Destination is the object entity.
	Destination entity.Ref `json:"destination"`

	// Predicate names the relationship kind, e.g. "network.connects_to",
	// "ziti.dials", "http.calls" or "process.opens_file".
	Predicate string `json:"predicate"`

	// Dimensions are adapter-defined values that make the edge unique. Network
	// adapters may use protocol/destination_port; identity adapters may use
	// service/role/terminator. Core treats them as opaque.
	Dimensions     map[string]string `json:"dimensions,omitempty"`
	DimensionsHash string            `json:"dimensions_hash,omitempty"`

	// Direction is ingress, egress, or eastwest relative to the node.
	Direction Direction `json:"direction"`

	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`

	SeenCount       uint64 `json:"seen_count"`
	DistinctWindows int    `json:"distinct_windows"`

	// MetricTotals carries optional cumulative adapter metrics such as packets,
	// bytes, requests, auth_failures or session_count.
	MetricTotals map[string]float64 `json:"metric_totals,omitempty"`

	Confidence int       `json:"confidence"`
	State      EdgeState `json:"state"`
	LearnedBy  LearnedBy `json:"learned_by"`

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
		Predicate:       e.Predicate,
		DimensionsHash:  e.DimensionsHash,
		Direction:       e.Direction,
	}
}

// PromotionConfig controls when a candidate edge is promoted to learned.
type PromotionConfig struct {
	MinSeenCount       uint64
	MinDistinctWindows int
	MinFirstSeenAge    time.Duration

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

// NewEdge creates a new candidate edge from an observed relationship.
func NewEdge(nodeID string, src, dst entity.Ref, predicate string, dimensions map[string]string, dir Direction, now time.Time) *Edge {
	dims := cloneDimensions(dimensions)
	return &Edge{
		ID:              generateID(),
		NodeID:          nodeID,
		Source:          src,
		Destination:     dst,
		Predicate:       predicate,
		Dimensions:      dims,
		DimensionsHash:  DimensionsHash(dims),
		Direction:       dir,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		SeenCount:       1,
		DistinctWindows: 1,
		MetricTotals:    make(map[string]float64),
		Confidence:      0,
		State:           EdgeCandidate,
		LearnedBy:       LearnedByLocal,
		Attributes:      make(map[string]string),
	}
}

// DimensionsHash computes a stable SHA-256 hash of sorted dimensions.
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

func cloneDimensions(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
