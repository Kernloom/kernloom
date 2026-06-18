// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package suspicious provides a thread-safe registry for tracking suspicious
// subjects and relationship edges during KLIQ's learning phase. It supports
// both subject-level and edge-level suspicious state with TTL eviction and
// historical tracking for the pending-baseline-commit pattern.
//
// The registry is intentionally simple and cheap — it must not become a bottleneck
// in the observation hot path.
package suspicious

import (
	"sync"
	"time"
)

// EdgeKey identifies a specific communication edge.
type EdgeKey struct {
	SourceID       string
	DestinationID  string
	Predicate      string
	DimensionsHash string
}

type entry struct {
	expiresAt time.Time
	markedAt  time.Time // most recent marking — used for WasSince queries
}

// Registry tracks suspicious sources and edges with TTL-based eviction.
// All methods are safe for concurrent use.
type Registry struct {
	mu      sync.Mutex
	sources map[string]entry
	edges   map[EdgeKey]entry
}

// New creates a new Registry.
func New() *Registry {
	return &Registry{
		sources: make(map[string]entry, 64),
		edges:   make(map[EdgeKey]entry, 128),
	}
}

// MarkSource marks a source IP as suspicious for the given TTL.
// If already marked, the expiry and markedAt are updated to extend the window.
func (r *Registry) MarkSource(src string, ttl time.Duration) {
	now := time.Now()
	r.mu.Lock()
	r.sources[src] = entry{expiresAt: now.Add(ttl), markedAt: now}
	r.mu.Unlock()
}

// MarkEdge marks a specific edge as suspicious for the given TTL.
func (r *Registry) MarkEdge(key EdgeKey, ttl time.Duration) {
	now := time.Now()
	r.mu.Lock()
	r.edges[key] = entry{expiresAt: now.Add(ttl), markedAt: now}
	r.mu.Unlock()
}

// IsSourceSuspicious returns true if the source is currently flagged.
// Expired entries are evicted lazily.
func (r *Registry) IsSourceSuspicious(src string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.sources[src]
	if !ok {
		return false
	}
	if now.After(e.expiresAt) {
		delete(r.sources, src)
		return false
	}
	return true
}

// IsEdgeSuspicious returns true if the specific edge is currently flagged.
func (r *Registry) IsEdgeSuspicious(key EdgeKey) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.edges[key]
	if !ok {
		return false
	}
	if now.After(e.expiresAt) {
		delete(r.edges, key)
		return false
	}
	return true
}

// WasSourceSuspiciousSince returns true if the source was marked suspicious
// at any time >= since. Used by the pending baseline commit to decide whether
// to drop a buffered update that was observed before the signal fired.
func (r *Registry) WasSourceSuspiciousSince(src string, since time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.sources[src]
	if !ok {
		return false
	}
	// markedAt >= since: a signal fired after the observation was buffered.
	// Also require entry not fully expired (still within TTL window).
	return !e.markedAt.Before(since) && time.Now().Before(e.expiresAt)
}

// WasEdgeSuspiciousSince returns true if the edge was marked suspicious at any
// time >= since.
func (r *Registry) WasEdgeSuspiciousSince(key EdgeKey, since time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.edges[key]
	if !ok {
		return false
	}
	return !e.markedAt.Before(since) && time.Now().Before(e.expiresAt)
}

// Evict removes all expired entries. Call periodically to bound memory.
func (r *Registry) Evict() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, e := range r.sources {
		if now.After(e.expiresAt) {
			delete(r.sources, k)
		}
	}
	for k, e := range r.edges {
		if now.After(e.expiresAt) {
			delete(r.edges, k)
		}
	}
}

// Len returns the number of active (source, edge) entries. Useful for metrics.
func (r *Registry) Len() (sources, edges int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sources), len(r.edges)
}
