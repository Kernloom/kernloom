// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package metricbaseline provides a generic in-memory EWMA baseline engine
// for arbitrary metrics. It learns the normal distribution of any numeric
// metric identified by a (MetricID, Scope, Subject, optional-label-hash) key
// and produces normalised deviation scores.
//
// Design principles:
//
//   - Generic: knows nothing about network, HTTP, or any specific domain.
//   - Cardinality-safe: label keying is opt-in; default ignores all labels.
//   - Anti-poisoning: suspicious updates are scored but not learned.
//   - Additive: does not replace pkg/adapters/sourcebaseline.
//
// This package is Track A of the generic adapter pipeline proposal (v2).
// Track B (pipeline runner, risk aggregator) is NOT part of this package.
package metricbaseline

import (
	"sync"
	"time"

	corebaseline "github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/metric"
)

// UpdateOptions controls how a single metric update is processed.
type UpdateOptions struct {
	// Suspicious marks this update as coming from a potentially attack-influenced
	// window. When true, the EWMA is not updated (anti-poisoning) but the metric
	// is still scored against the current baseline.
	//
	// The caller is responsible for deciding whether a window is suspicious.
	// For KLShield this may be derived from existing severity/autotune logic.
	// For NGINX/HTTP this would come from a domain-specific LearningGuard.
	// Do not implement global suspicious logic inside this package.
	Suspicious bool

	// Now is the timestamp to use for FirstSeen/LastSeen. If zero, time.Now() is used.
	Now time.Time
}

// Engine is a thread-safe in-memory metric baseline engine.
// It stores one Profile per unique Key and supports TTL-based eviction.
type Engine struct {
	mu       sync.Mutex
	profiles map[string]*Profile          // key: Key.String() or baselineKeyString()
	dirty    map[string]corebaseline.Key  // keys needing SQLite flush; nil until first write
	cfg      Config
}

// New creates a new Engine with the given configuration.
func New(cfg Config) *Engine {
	if cfg.Alpha <= 0 {
		cfg.Alpha = 0.10
	}
	if cfg.AlphaPromoted <= 0 {
		cfg.AlphaPromoted = 0.02
	}
	if cfg.MinCount == 0 {
		cfg.MinCount = 30
	}
	if cfg.MaxProfiles <= 0 {
		cfg.MaxProfiles = 10_000
	}
	if cfg.ProfileTTL <= 0 {
		cfg.ProfileTTL = 24 * time.Hour
	}
	if cfg.DeviationThreshold <= 0 {
		cfg.DeviationThreshold = 4.0
	}
	if cfg.SigmaFloor <= 0 {
		cfg.SigmaFloor = 0.01
	}
	return &Engine{
		profiles: make(map[string]*Profile),
		cfg:      cfg,
	}
}

// Update learns from or scores a metric value.
// Returns the Result containing the current deviation score and profile snapshot.
//
// If opts.Suspicious is true, the EWMA is not updated but the metric is scored.
// This prevents attack traffic from poisoning the learned baseline.
func (e *Engine) Update(m metric.Metric, opts UpdateOptions) Result {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	key := keyFromMetric(m, e.cfg.SelectedLabels)
	ks := key.String()

	e.mu.Lock()
	defer e.mu.Unlock()

	p, ok := e.profiles[ks]
	if !ok {
		// Enforce max profile limit before creating a new one.
		if len(e.profiles) >= e.cfg.MaxProfiles {
			e.evictLocked()
		}
		p = &Profile{Key: key, FirstSeen: now}
		e.profiles[ks] = p
	}

	learned := !opts.Suspicious
	p.update(m.Value, opts.Suspicious, now, e.cfg.Alpha, e.cfg.AlphaPromoted, e.cfg.MinCount)
	return resultFromProfile(p, m.Value, opts.Suspicious, learned, e.cfg)
}

// Get returns the current profile snapshot for a metric, or false if not found.
func (e *Engine) Get(m metric.Metric) (Profile, bool) {
	key := keyFromMetric(m, e.cfg.SelectedLabels)
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.profiles[key.String()]
	if !ok {
		return Profile{}, false
	}
	return *p, true
}

// Evict removes profiles that have not been updated since cutoff.
// Returns the number of profiles removed.
func (e *Engine) Evict(cutoff time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := 0
	for ks, p := range e.profiles {
		if p.LastSeen.Before(cutoff) {
			delete(e.profiles, ks)
			removed++
		}
	}
	return removed
}

// EvictByTTL removes profiles older than the configured ProfileTTL.
func (e *Engine) EvictByTTL() int {
	return e.Evict(time.Now().UTC().Add(-e.cfg.ProfileTTL))
}

// Len returns the current number of stored profiles.
func (e *Engine) Len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.profiles)
}

// evictLocked removes the lowest-confidence profile when MaxProfiles is reached.
// Must be called with e.mu held.
func (e *Engine) evictLocked() {
	if len(e.profiles) == 0 {
		return
	}
	// Find the profile with the lowest confidence.
	var victim string
	minConf := 2.0
	for ks, p := range e.profiles {
		if p.Confidence < minConf {
			minConf = p.Confidence
			victim = ks
		}
	}
	if victim != "" {
		delete(e.profiles, victim)
	}
}
