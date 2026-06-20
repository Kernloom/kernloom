// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package relationshiplearner

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/learning"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// Mode controls how the learner behaves.
type Mode string

const (
	// ModeLearn accumulates relationships and promotes candidates.
	ModeLearn Mode = "learn"
	// ModeFrozenObserve: the graph is fixed; new relationships emit signals.
	ModeFrozenObserve Mode = "frozen-observe"
	// ModeFrozenEnforce: new relationships emit high-score signals → enforcement.
	ModeFrozenEnforce Mode = "frozen-enforce"
)

// Store is the persistence interface required by the Learner.
type Store interface {
	UpsertRelationship(ctx context.Context, r relationship.Relationship) error
	GetRelationship(ctx context.Context, nodeID, subjectID, predicate, objectID, scopeType, scopeID, dimsHash string) (*relationship.Relationship, error)
	ListRelationships(ctx context.Context, nodeID, predicate, state string) ([]relationship.Relationship, error)
	SetRelationshipState(ctx context.Context, id string, state relationship.State, confidence float64) error
	FreezeRelationships(ctx context.Context, nodeID string) (int64, error)
	RelationshipStats(ctx context.Context, nodeID string) (map[string]int64, error)
}

// SignalPublisher allows the Learner to emit signals without coupling to adapterruntime.
type SignalPublisher interface {
	PublishSignal(ctx context.Context, sig signal.Signal) error
}

// PromotionConfig controls when a candidate relationship is promoted to learned.
type PromotionConfig struct {
	MinSeenCount       uint64
	MinDistinctWindows int
	MinAge             time.Duration
}

// DefaultPromotionConfig returns safe defaults.
func DefaultPromotionConfig() PromotionConfig {
	return PromotionConfig{
		MinSeenCount:       5,
		MinDistinctWindows: 3,
		MinAge:             5 * time.Minute,
	}
}

// Config controls Learner behaviour.
type Config struct {
	NodeID    string
	Mode      Mode
	Promotion PromotionConfig

	// MaxCachedRelationships bounds the in-memory relationship cache.
	MaxCachedRelationships int
}

// DefaultConfig returns safe defaults.
func DefaultConfig(nodeID string) Config {
	return Config{
		NodeID:                 nodeID,
		Mode:                   ModeLearn,
		Promotion:              DefaultPromotionConfig(),
		MaxCachedRelationships: 50_000,
	}
}

// cacheEntry is the in-memory copy of a relationship.
type cacheEntry struct {
	rel          relationship.Relationship
	dirtyAt      time.Time // zero means clean
	firstSeen    time.Time
	lastSignalAt time.Time // last time a freeze-violation signal was emitted
}

// freezeSignalCooldown is the minimum interval between repeated freeze-violation
// signals for the same relationship.  Without this, every single observation from
// an unrecognised source fires a signal, flooding the log and decision engine.
const freezeSignalCooldown = 5 * time.Minute

// Learner is the generic, thread-safe relationship learning engine.
// It holds an in-memory cache of relationships and flushes dirty entries
// to a Store asynchronously.
type Learner struct {
	cfg   Config
	guard learning.Guard  // may be nil
	store Store           // may be nil (in-memory only)
	pub   SignalPublisher // may be nil

	mu    sync.Mutex
	cache map[string]*cacheEntry // key: stableKey(r)
}

// New creates a Learner. guard and store may be nil (in-memory-only / no enforcement).
func New(cfg Config, guard learning.Guard, store Store, pub SignalPublisher) *Learner {
	if cfg.MaxCachedRelationships <= 0 {
		cfg.MaxCachedRelationships = 50_000
	}
	return &Learner{
		cfg:   cfg,
		guard: guard,
		store: store,
		pub:   pub,
		cache: make(map[string]*cacheEntry),
	}
}

// Learn processes a batch of candidate relationships from an Extractor.
// For each relationship:
//  1. Guard check — skip (evidence-only / deny) if excluded.
//  2. Upsert into cache; increment seen_count.
//  3. Promote candidate → learned if PromotionConfig is met.
//  4. In frozen modes, emit signals for unrecognised relationships.
func (l *Learner) Learn(ctx context.Context, candidates []relationship.Relationship) {
	now := time.Now().UTC()
	for _, c := range candidates {
		l.learn(ctx, c, now)
	}
}

func (l *Learner) learn(ctx context.Context, c relationship.Relationship, now time.Time) {
	// Guard check.
	if l.guard != nil {
		result := l.guard.CheckRelationship(ctx, learning.RelationshipCheck{Relationship: c})
		switch result.Decision {
		case learning.DenyLearning:
			return
		case learning.EvidenceOnly, learning.CandidateOnly:
			// Allow storing as candidate, but do not promote.
			c.State = relationship.StateCandidate
		case learning.AllowLearning:
			// normal path
		}
	}

	key := stableKey(c)
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.cache[key]
	if !exists {
		if len(l.cache) >= l.cfg.MaxCachedRelationships {
			return // cardinality guard
		}
		if c.ID == "" {
			c.ID = generateID()
		}
		c.NodeID = l.cfg.NodeID
		if c.FirstSeenAt.IsZero() {
			c.FirstSeenAt = now
		}
		c.LastSeenAt = now
		c.State = relationship.StateCandidate
		c.LearnedBy = relationship.LearnedByLocal
		entry = &cacheEntry{rel: c, firstSeen: now}
		l.cache[key] = entry
	} else {
		entry.rel.SeenCount++
		entry.rel.DistinctWindows++
		entry.rel.LastSeenAt = now
		// Propagate labels from the new observation if the cache entry has none.
		// This repairs entity stubs that were loaded from DB before SubjectLabel was implemented.
		if entry.rel.SubjectLabel == "" && c.SubjectLabel != "" {
			entry.rel.SubjectLabel = c.SubjectLabel
			entry.rel.SubjectKind = c.SubjectKind
		}
		if entry.rel.ObjectLabel == "" && c.ObjectLabel != "" {
			entry.rel.ObjectLabel = c.ObjectLabel
			entry.rel.ObjectKind = c.ObjectKind
		}
	}

	// Promotion logic (only in learn mode).
	if l.cfg.Mode == ModeLearn && entry.rel.State == relationship.StateCandidate {
		if l.shouldPromote(entry, now) {
			entry.rel.State = relationship.StateLearned
			entry.rel.Confidence = 0.8
		}
	}

	// In frozen modes: signal any relationship that is not frozen/approved.
	// Rate-limited to freezeSignalCooldown to avoid flooding the log and
	// decision engine when a source communicates repeatedly.
	if (l.cfg.Mode == ModeFrozenObserve || l.cfg.Mode == ModeFrozenEnforce) &&
		entry.rel.State != relationship.StateFrozen &&
		entry.rel.State != relationship.StateApproved {
		if now.Sub(entry.lastSignalAt) >= freezeSignalCooldown {
			entry.lastSignalAt = now
			l.emitFreezeSignal(ctx, entry.rel)
		}
	}

	// Mark dirty for flush.
	entry.dirtyAt = now
}

// shouldPromote returns true when the cache entry meets the PromotionConfig criteria.
// Must be called with l.mu held.
func (l *Learner) shouldPromote(e *cacheEntry, now time.Time) bool {
	p := l.cfg.Promotion
	if p.MinSeenCount > 0 && e.rel.SeenCount < p.MinSeenCount {
		return false
	}
	if p.MinDistinctWindows > 0 && e.rel.DistinctWindows < p.MinDistinctWindows {
		return false
	}
	if p.MinAge > 0 && now.Sub(e.firstSeen) < p.MinAge {
		return false
	}
	return true
}

// emitFreezeSignal publishes a freeze-violation signal.
// Must be called without l.mu held (pub may block briefly).
func (l *Learner) emitFreezeSignal(ctx context.Context, r relationship.Relationship) {
	if l.pub == nil {
		return
	}
	score := 70
	if l.cfg.Mode == ModeFrozenEnforce {
		score = 95
	}
	sub := subjectRef(r)
	sig := signal.NewSignal(
		signal.ProducerKLIQ, signal.ScopeLocal,
		signal.SignalGraphNewEdgeAfterFreeze, sub,
	).
		SetScore(score).
		SetConfidence(80).
		SetTTL(30*time.Minute).
		AddReasonCode("relationship_new_after_freeze").
		SetAttribute("predicate", r.Predicate).
		SetAttribute("target_id", r.ObjectEntityID).
		SetAttribute("object_entity_id", r.ObjectEntityID)
	for k, v := range r.Dimensions {
		sig.SetAttribute(adapterruntime.RelationshipDimensionPrefix+k, v)
	}
	_ = l.pub.PublishSignal(ctx, *sig)
}

// FlushDirty persists all dirty cache entries to the Store.
// Returns (flushed, error). Safe to call concurrently.
func (l *Learner) FlushDirty(ctx context.Context) (int, error) {
	if l.store == nil {
		return 0, nil
	}

	now := time.Now().UTC()
	l.mu.Lock()
	// Promote eligible candidates before flushing so that a shutdown or
	// periodic flush does not persist stale candidate state when the
	// MinAge/MinSeen criteria are already met.
	if l.cfg.Mode == ModeLearn {
		for _, e := range l.cache {
			if e.rel.State == relationship.StateCandidate && l.shouldPromote(e, now) {
				e.rel.State = relationship.StateLearned
				e.rel.Confidence = 0.8
				e.dirtyAt = now
			}
		}
	}
	var dirty []relationship.Relationship
	for _, e := range l.cache {
		if !e.dirtyAt.IsZero() {
			dirty = append(dirty, e.rel)
			e.dirtyAt = time.Time{}
		}
	}
	l.mu.Unlock()

	var firstErr error
	flushed := 0
	for _, r := range dirty {
		if err := l.store.UpsertRelationship(ctx, r); err != nil && firstErr == nil {
			firstErr = err
		} else {
			flushed++
		}
	}
	return flushed, firstErr
}

// Freeze sets the learner mode to frozen-observe and persists the current graph.
func (l *Learner) Freeze(ctx context.Context) error {
	l.mu.Lock()
	l.cfg.Mode = ModeFrozenObserve
	for _, e := range l.cache {
		if e.rel.State == relationship.StateLearned || e.rel.State == relationship.StateApproved {
			e.rel.State = relationship.StateFrozen
			e.dirtyAt = time.Now()
		}
	}
	l.mu.Unlock()

	if l.store != nil {
		_, err := l.store.FreezeRelationships(ctx, l.cfg.NodeID)
		return err
	}
	return nil
}

// List returns a snapshot of relationships filtered by predicate and/or state.
// Empty strings mean no filter.
func (l *Learner) List(predicate, state string) []relationship.Relationship {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result []relationship.Relationship
	for _, e := range l.cache {
		if predicate != "" && e.rel.Predicate != predicate {
			continue
		}
		if state != "" && string(e.rel.State) != state {
			continue
		}
		result = append(result, e.rel)
	}
	return result
}

// Len returns the number of cached relationships.
func (l *Learner) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.cache)
}

// LoadFromStore loads all relationships for the node from the Store.
// Existing in-memory entries are NOT overwritten.
func (l *Learner) LoadFromStore(ctx context.Context) error {
	if l.store == nil {
		return nil
	}
	rels, err := l.store.ListRelationships(ctx, l.cfg.NodeID, "", "")
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range rels {
		key := stableKey(r)
		if _, exists := l.cache[key]; exists {
			continue
		}
		if len(l.cache) >= l.cfg.MaxCachedRelationships {
			break
		}
		l.cache[key] = &cacheEntry{rel: r, firstSeen: r.FirstSeenAt}
	}
	return nil
}

// stableKey returns a stable string key for cache deduplication.
func stableKey(r relationship.Relationship) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		r.NodeID, r.SubjectEntityID, r.Predicate, r.ObjectEntityID,
		r.ScopeType, r.ScopeID, r.DimensionsHash)
}

// subjectRef returns an entity.Ref for signal emission.
// Uses SubjectLabel (e.g. raw IP or identity name) and SubjectKind when available.
func subjectRef(r relationship.Relationship) entity.Ref {
	id := r.SubjectLabel
	if id == "" {
		id = r.SubjectEntityID
	}
	kind := entity.Kind(r.SubjectKind)
	if kind == "" {
		kind = entity.KindIP
	}
	return entity.Ref{Kind: kind, ID: id}
}

func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
