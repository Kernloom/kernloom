// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package relationship defines the generic directed-edge model for the
// Kernloom trust graph.  A Relationship is a Subject → (Predicate) → Object
// triple enriched with state, confidence, and evidence metadata.
//
// Standard predicates (open for extension):
//
//	network.connects_to   — IP/port-level TCP/UDP flow
//	http.calls            — HTTP request from service A to service B
//	http.uses_route       — HTTP client uses a specific method+path
//	ziti.dials            — OpenZiti service dial
//	trust.has_state       — attestation/trust state assertion
package relationship

import "time"

// State is the lifecycle state of a relationship.
type State string

const (
	StateCandidate State = "candidate" // observed but not yet confirmed
	StateLearned   State = "learned"   // repeated observation; considered normal
	StateApproved  State = "approved"  // explicitly confirmed by policy/admin/Forge
	StateFrozen    State = "frozen"    // graph frozen; unexpected additions trigger signals
	StateDenied    State = "denied"    // must not be allowed
	StateExpired   State = "expired"   // not seen for configured TTL; pending pruning
)

// LearnedBy describes what caused the current state transition.
type LearnedBy string

const (
	LearnedByLocal     LearnedBy = "local"     // KLIQ local observation
	LearnedByForge     LearnedBy = "forge"     // Forge policy distribution
	LearnedByAdmin     LearnedBy = "admin"     // explicit operator action
	LearnedByCorrelate LearnedBy = "correlate" // Correlate global signal
)

// Relationship is a single directed, labelled edge in the Kernloom trust graph.
// It generalises the former L3/L4-specific Edge struct to any entity-predicate-entity triple.
type Relationship struct {
	ID string // UUIDv4

	// NodeID is the KLIQ node where this relationship was observed.
	NodeID string

	// Subject → Predicate → Object triple.
	SubjectEntityID string
	Predicate       string // e.g. "network.connects_to", "http.calls"
	ObjectEntityID  string

	// Scope narrows the relationship to a specific context (e.g. a Ziti service, a namespace).
	ScopeType string
	ScopeID   string

	// Dimensions are additional key=value pairs that make this relationship unique
	// beyond the subject/predicate/object triple (e.g. protocol, destination_port).
	Dimensions     map[string]string
	DimensionsHash string // stable SHA-256 hex of sorted Dimensions

	State      State
	Weight     float64
	Confidence float64

	SeenCount       uint64
	DistinctWindows int

	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	LastEvidenceID string

	LearnedBy     LearnedBy
	SourceAdapter string

	// SubjectLabel/ObjectLabel are the human-readable IDs (e.g. raw IP, identity name).
	// SubjectKind/ObjectKind carry the entity.Kind for display (e.g. "ip", "user").
	// None of these are stored in the DB or included in DimensionsHash.
	SubjectLabel string `json:"-"`
	ObjectLabel  string `json:"-"`
	SubjectKind  string `json:"-"` // entity.Kind string, e.g. "ip", "user", "ziti_service"
	ObjectKind   string `json:"-"`

	CreatedAt time.Time
	UpdatedAt time.Time
}
