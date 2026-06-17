// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package learningguard implements the learning.Guard interface.
//
// The Guard solves the downstream contamination problem: when klshield is
// blocking or rate-limiting a source, conntrack and nginx downstream adapters
// still see traffic from that source.  Their observations must NOT update
// baselines or promote relationships, because the data is enforcement-affected.
//
// Architecture:
//
//	┌─────────────────────────────────────────────────────────┐
//	│  Guard (in-memory hot path)                              │
//	│                                                          │
//	│  exclusionCache: entityID → []Exclusion (TTL-bounded)   │
//	│  SuspiciousRegistry bridge: IsSourceSuspicious()        │
//	│                                                          │
//	│  SQLite: authoritative exclusion store                   │
//	│  (writes are async; reads hit cache first)               │
//	└─────────────────────────────────────────────────────────┘
package learningguard

import (
	"context"
	"sync"
	"time"

	"github.com/kernloom/kernloom/pkg/core/learning"
	"github.com/kernloom/kernloom/pkg/core/suspicious"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

// Config controls Guard behaviour.
type Config struct {
	// ExclusionGracePeriod is how long after enforcement ends before learning
	// is re-allowed.  Prevents edge cases where the last few tainted observations
	// arrive just as the exclusion expires.
	// Default: 30s.
	ExclusionGracePeriod time.Duration

	// CacheTTL is how long the in-memory exclusion cache entry is considered
	// fresh before a DB re-check.  Default: 10s.
	CacheTTL time.Duration

	// DefaultExclusionTTL is the TTL assigned to exclusions created from
	// SuspiciousRegistry entries (which don't carry an explicit expiry).
	// Default: 5 minutes.
	DefaultExclusionTTL time.Duration
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() Config {
	return Config{
		ExclusionGracePeriod: 30 * time.Second,
		CacheTTL:             10 * time.Second,
		DefaultExclusionTTL:  5 * time.Minute,
	}
}

// Guard is the concrete implementation of learning.Guard.
// It is safe for concurrent use from multiple adapters.
type Guard struct {
	cfg        Config
	store      *sqlite.Store // may be nil (in-memory-only mode)
	suspicious *suspicious.Registry

	mu    sync.RWMutex
	cache map[string]*cacheEntry // entityID → cache entry
}

type cacheEntry struct {
	exclusions []learning.Exclusion
	loadedAt   time.Time
}

// New creates a Guard.  store may be nil for tests / in-memory-only mode.
// suspicious may be nil if no SuspiciousRegistry is available.
func New(cfg Config, store *sqlite.Store, susp *suspicious.Registry) *Guard {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 10 * time.Second
	}
	if cfg.ExclusionGracePeriod <= 0 {
		cfg.ExclusionGracePeriod = 30 * time.Second
	}
	if cfg.DefaultExclusionTTL <= 0 {
		cfg.DefaultExclusionTTL = 5 * time.Minute
	}
	return &Guard{
		cfg:        cfg,
		store:      store,
		suspicious: susp,
		cache:      make(map[string]*cacheEntry),
	}
}

// CheckMetric returns the learning eligibility for a metric baseline update.
// Decision order:
//  1. SuspiciousRegistry (in-memory, zero-alloc)
//  2. In-memory exclusion cache
//  3. SQLite (when cache is stale)
func (g *Guard) CheckMetric(ctx context.Context, m learning.MetricCheck) learning.CheckResult {
	return g.check(ctx, m.SubjectEntityID, learning.AppliesMetricBaseline)
}

// CheckRelationship returns the learning eligibility for a relationship promotion.
func (g *Guard) CheckRelationship(ctx context.Context, r learning.RelationshipCheck) learning.CheckResult {
	return g.check(ctx, r.Relationship.SubjectEntityID, learning.AppliesRelationshipLearning)
}

// IsExcluded returns true if any active exclusion applies to the entity for the
// given dimension.
func (g *Guard) IsExcluded(ctx context.Context, entityID string, dimension learning.AppliesTo) bool {
	result := g.check(ctx, entityID, dimension)
	return result.Decision != learning.AllowLearning
}

// AddExclusion records a new exclusion in the cache and persists it to SQLite.
func (g *Guard) AddExclusion(ctx context.Context, e learning.Exclusion) error {
	g.invalidateCache(e.EntityID)

	if g.store != nil {
		if err := g.store.UpsertExclusion(ctx, e); err != nil {
			return err
		}
	}

	// Write to cache immediately so the next check doesn't need a DB round-trip.
	g.mu.Lock()
	entry := g.cache[e.EntityID]
	if entry == nil {
		entry = &cacheEntry{}
		g.cache[e.EntityID] = entry
	}
	entry.exclusions = append(entry.exclusions, e)
	entry.loadedAt = time.Now()
	g.mu.Unlock()

	return nil
}

// RevokeExclusion removes an exclusion before its natural expiry.
func (g *Guard) RevokeExclusion(ctx context.Context, exclusionID string) error {
	if g.store != nil {
		if err := g.store.RevokeExclusion(ctx, exclusionID); err != nil {
			return err
		}
	}
	// Flush entire cache — we don't know which entityID the exclusion belongs to
	// without a DB lookup.  Cache will be repopulated on next check.
	g.mu.Lock()
	g.cache = make(map[string]*cacheEntry)
	g.mu.Unlock()
	return nil
}

// check is the unified eligibility check for a given entity + dimension.
func (g *Guard) check(ctx context.Context, entityID string, dimension learning.AppliesTo) learning.CheckResult {
	// 1. SuspiciousRegistry — fastest path, no allocation.
	if g.suspicious != nil && g.suspicious.IsSourceSuspicious(entityID) {
		return learning.CheckResult{
			Decision: learning.DenyLearning,
			Reason:   learning.ReasonSuspiciousSignal,
			Details:  "entity in SuspiciousRegistry",
		}
	}

	// 2. Cache + SQLite.
	exclusions := g.loadExclusions(ctx, entityID)
	now := time.Now()
	for _, ex := range exclusions {
		if ex.Status != "active" {
			continue
		}
		if now.After(ex.ExpiresAt) {
			continue
		}
		if !appliesToDimension(ex.AppliesTo, dimension) {
			continue
		}
		return learning.CheckResult{
			Decision: decisionFromReason(ex.Reason),
			Reason:   ex.Reason,
			Details:  "active exclusion: " + string(ex.Reason),
		}
	}

	return learning.CheckResult{Decision: learning.AllowLearning}
}

// loadExclusions returns the current exclusion list for an entity,
// using the cache when fresh and falling back to SQLite when stale.
func (g *Guard) loadExclusions(ctx context.Context, entityID string) []learning.Exclusion {
	g.mu.RLock()
	entry := g.cache[entityID]
	if entry != nil && time.Since(entry.loadedAt) < g.cfg.CacheTTL {
		exclusions := entry.exclusions
		g.mu.RUnlock()
		return exclusions
	}
	g.mu.RUnlock()

	// Cache miss or stale — reload from SQLite.
	if g.store == nil {
		return nil
	}
	exclusions, err := g.store.ActiveExclusionsFor(ctx, entityID)
	if err != nil {
		// Don't block learning on a DB error; log is not available here.
		return nil
	}

	g.mu.Lock()
	g.cache[entityID] = &cacheEntry{exclusions: exclusions, loadedAt: time.Now()}
	g.mu.Unlock()

	return exclusions
}

// invalidateCache removes the cache entry for an entity.
func (g *Guard) invalidateCache(entityID string) {
	g.mu.Lock()
	delete(g.cache, entityID)
	g.mu.Unlock()
}

// decisionFromReason maps exclusion reasons to eligibility decisions.
// Enforcement-related reasons block completely; signal-based reasons allow evidence-only.
func decisionFromReason(r learning.ExclusionReason) learning.EligibilityDecision {
	switch r {
	case learning.ReasonEnforcementActive,
		learning.ReasonBlocked,
		learning.ReasonRateLimited,
		learning.ReasonDownstreamCensored,
		learning.ReasonAdminOverride,
		learning.ReasonForgePolicy,
		learning.ReasonAttestationFailure:
		return learning.DenyLearning
	case learning.ReasonSuspiciousSignal,
		learning.ReasonCorrelateAlert:
		return learning.EvidenceOnly
	default:
		return learning.DenyLearning
	}
}

// appliesToDimension returns true if the exclusion's AppliesTo list covers
// the requested dimension, or if the list is empty (applies to all).
func appliesToDimension(applies []learning.AppliesTo, dim learning.AppliesTo) bool {
	if len(applies) == 0 {
		return true
	}
	for _, a := range applies {
		if a == dim {
			return true
		}
	}
	return false
}
