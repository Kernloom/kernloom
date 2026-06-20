// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package sourcebaseline maintains a lightweight per-source traffic baseline.
// It is NOT a vendor adapter — it contains zero vendor-specific code and is
// generic KLIQ infrastructure. It lives in pkg/sourcebaseline/ (not pkg/adapters/).
//
// It sits between the global heuristic triggers (TrigPPS, TrigSyn, ...) and
// the per-edge EWMA baselines: it learns what is "normal" for each source IP
// so that high-traffic but legitimate sources do not trip the global guardrails.
//
// Data flow:
//
//	kliq main loop → Update(src, pps, bps, syn, scan)
//	               → EffectiveTrig*(src, globalTrig) → engine.EvaluateAt(...)
//
// Storage: in-memory with snapshot/restore hooks for batched external
// persistence. The cache is bounded by MaxSources and entries expire after TTL.
package sourcebaseline

import (
	"math"
	"sync"
	"time"
)

// Profile holds the learned traffic profile for a single source IP.
type Profile struct {
	// EWMA values (exponential weighted moving average).
	EWMAPPS  float64
	EWMABPS  float64
	EWMASyn  float64
	EWMAScan float64

	// Running peak (highest observed value after baseline is promoted).
	PeakPPS  float64
	PeakBPS  float64
	PeakSyn  float64
	PeakScan float64

	// Observation counters.
	ObsCount   uint64
	Windows    uint64 // ticks where pps >= MinUpdatePPS
	FirstSeen  time.Time
	LastSeen   time.Time
	Promoted   bool    // true once obs >= MinObs
	Confidence float64 // 0..1; computed from obs/windows/age
}

// Snapshot is a point-in-time copy of one per-source traffic profile.
type Snapshot struct {
	SourceID string
	Profile  Profile
}

// recomputeConfidence updates the Confidence field.
// Confidence grows with observation count, active windows and source age.
func (p *Profile) recomputeConfidence(minConfObs uint64) {
	obsScore := math.Min(float64(p.ObsCount)/float64(max64(minConfObs, 100)), 1)
	winScore := math.Min(float64(p.Windows)/24.0, 1)
	ageSec := time.Since(p.FirstSeen).Seconds()
	ageScore := math.Min(ageSec/float64(7*24*3600), 1)
	p.Confidence = 0.4*obsScore + 0.4*winScore + 0.2*ageScore
}

// Config controls Cache behaviour.
type Config struct {
	// Alpha is the EWMA adaptation speed (default 0.10 = ~7 obs half-life).
	Alpha float64

	// AlphaPromoted is the slower EWMA speed used after promotion (default 0.02).
	AlphaPromoted float64

	// MinUpdatePPS: skip EWMA update when pps < this (default 3).
	// Prevents idle keepalive ticks from pulling the EWMA down.
	MinUpdatePPS float64

	// MinObs is the minimum observation count before promotion (default 30).
	MinObs uint64

	// MinConfObs is used for confidence scoring (default 100).
	MinConfObs uint64

	// MaxSources caps the cache size (default 100 000).
	MaxSources int

	// TTL evicts profiles not seen within this duration (default 24h).
	TTL time.Duration

	// PeakMultiplier: effective trig = max(global, peak * PeakMultiplier).
	// Default 1.2 — allows 20% above the learned peak before flagging.
	PeakMultiplier float64

	// MinConfidence: minimum confidence required to use the source baseline
	// as effective trigger. Below this the global trigger is used. Default 0.4.
	MinConfidence float64
}

func (c *Config) applyDefaults() {
	if c.Alpha <= 0 {
		c.Alpha = 0.10
	}
	if c.AlphaPromoted <= 0 {
		c.AlphaPromoted = 0.02
	}
	if c.MinUpdatePPS <= 0 {
		c.MinUpdatePPS = 3
	}
	if c.MinObs == 0 {
		c.MinObs = 30
	}
	if c.MinConfObs == 0 {
		c.MinConfObs = 100
	}
	if c.MaxSources <= 0 {
		c.MaxSources = 100_000
	}
	if c.TTL <= 0 {
		c.TTL = 24 * time.Hour
	}
	if c.PeakMultiplier <= 0 {
		c.PeakMultiplier = 1.2
	}
	if c.MinConfidence <= 0 {
		c.MinConfidence = 0.4
	}
}

// Cache is the in-memory source baseline store.
// All methods are safe for concurrent use.
type Cache struct {
	mu    sync.RWMutex
	cfg   Config
	m     map[string]*Profile
	dirty map[string]struct{}
}

// New creates a new Cache with the provided Config.
func New(cfg Config) *Cache {
	cfg.applyDefaults()
	return &Cache{cfg: cfg, m: make(map[string]*Profile, 1024), dirty: make(map[string]struct{}, 1024)}
}

// Update records a new observation for srcIP.
// Called from the kliq main loop for every source seen in the tick.
// isSuspicious: when true the update is skipped (anti-poisoning).
func (c *Cache) Update(srcIP string, pps, bps, syn, scan float64, isSuspicious bool, now time.Time) {
	if isSuspicious {
		return
	}
	if pps < c.cfg.MinUpdatePPS {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	p, ok := c.m[srcIP]
	if !ok {
		if len(c.m) >= c.cfg.MaxSources {
			return // cache full — eviction is handled by Evict()
		}
		p = &Profile{FirstSeen: now}
		c.m[srcIP] = p
	}

	alpha := c.cfg.Alpha
	if p.Promoted {
		alpha = c.cfg.AlphaPromoted
	}

	if p.ObsCount == 0 {
		// Seed EWMA on first observation.
		p.EWMAPPS = pps
		p.EWMABPS = bps
		p.EWMASyn = syn
		p.EWMAScan = scan
	} else {
		p.EWMAPPS = (1-alpha)*p.EWMAPPS + alpha*pps
		p.EWMABPS = (1-alpha)*p.EWMABPS + alpha*bps
		p.EWMASyn = (1-alpha)*p.EWMASyn + alpha*syn
		p.EWMAScan = (1-alpha)*p.EWMAScan + alpha*scan
	}

	// Update peaks only after promotion (prevents poisoning by early spikes).
	if p.Promoted {
		if pps > p.PeakPPS {
			p.PeakPPS = pps
		}
		if bps > p.PeakBPS {
			p.PeakBPS = bps
		}
		if syn > p.PeakSyn {
			p.PeakSyn = syn
		}
		if scan > p.PeakScan {
			p.PeakScan = scan
		}
	}

	p.ObsCount++
	p.Windows++
	p.LastSeen = now
	c.dirty[srcIP] = struct{}{}

	if !p.Promoted && p.ObsCount >= c.cfg.MinObs {
		p.Promoted = true
		// Seed peak from current EWMA at promotion time.
		p.PeakPPS = p.EWMAPPS * 1.5
		p.PeakBPS = p.EWMABPS * 1.5
		p.PeakSyn = p.EWMASyn * 1.5
		p.PeakScan = p.EWMAScan * 1.5
	}

	p.recomputeConfidence(c.cfg.MinConfObs)
}

// Get returns a copy of the profile for srcIP, or false if not found.
func (c *Cache) Get(srcIP string) (Profile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.m[srcIP]
	if !ok {
		return Profile{}, false
	}
	return *p, true
}

// EffectiveTrigPPS returns the effective PPS trigger for srcIP.
// If the source has a confident baseline with a higher peak, the trigger
// is raised so legitimate high-traffic sources are not false-positived.
// Falls back to globalTrig when the source is unknown or not yet confident.
func (c *Cache) EffectiveTrigPPS(srcIP string, globalTrig float64) float64 {
	if globalTrig <= 0 {
		return 0
	}
	return c.effectiveTrigger(srcIP, globalTrig, func(p *Profile) float64 { return p.PeakPPS })
}

// EffectiveTrigBPS returns the effective BPS trigger for srcIP.
func (c *Cache) EffectiveTrigBPS(srcIP string, globalTrig float64) float64 {
	if globalTrig <= 0 {
		return 0
	}
	return c.effectiveTrigger(srcIP, globalTrig, func(p *Profile) float64 { return p.PeakBPS })
}

// EffectiveTrigSyn returns the effective SYN/s trigger for srcIP.
func (c *Cache) EffectiveTrigSyn(srcIP string, globalTrig float64) float64 {
	if globalTrig <= 0 {
		return 0
	}
	return c.effectiveTrigger(srcIP, globalTrig, func(p *Profile) float64 { return p.PeakSyn })
}

// EffectiveTrigScan returns the effective scan-rate trigger for srcIP.
func (c *Cache) EffectiveTrigScan(srcIP string, globalTrig float64) float64 {
	if globalTrig <= 0 {
		return 0
	}
	return c.effectiveTrigger(srcIP, globalTrig, func(p *Profile) float64 { return p.PeakScan })
}

func (c *Cache) effectiveTrigger(srcIP string, globalTrig float64, value func(*Profile) float64) float64 {
	c.mu.RLock()
	p, ok := c.m[srcIP]
	if !ok || !p.Promoted || p.Confidence < c.cfg.MinConfidence {
		c.mu.RUnlock()
		return globalTrig
	}
	effective := value(p) * c.cfg.PeakMultiplier
	c.mu.RUnlock()
	if effective > globalTrig {
		return effective
	}
	return globalTrig
}

// Len returns the number of cached source profiles.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Snapshot returns a copy of all cached source profiles.
func (c *Cache) Snapshot() []Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Snapshot, 0, len(c.m))
	for sourceID, p := range c.m {
		out = append(out, Snapshot{SourceID: sourceID, Profile: *p})
	}
	return out
}

// SnapshotDirty returns profiles updated since the previous dirty snapshot.
func (c *Cache) SnapshotDirty() []Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.dirty) == 0 {
		return nil
	}
	out := make([]Snapshot, 0, len(c.dirty))
	for sourceID := range c.dirty {
		if p, ok := c.m[sourceID]; ok {
			out = append(out, Snapshot{SourceID: sourceID, Profile: *p})
		}
	}
	c.dirty = make(map[string]struct{}, 1024)
	return out
}

// Restore inserts persisted profiles without marking them dirty.
func (c *Cache) Restore(snapshots []Snapshot) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	restored := 0
	for _, snap := range snapshots {
		if snap.SourceID == "" {
			continue
		}
		if current, ok := c.m[snap.SourceID]; ok {
			if !current.LastSeen.Before(snap.Profile.LastSeen) {
				continue
			}
		} else if len(c.m) >= c.cfg.MaxSources {
			break
		}
		profile := snap.Profile
		if profile.FirstSeen.IsZero() {
			profile.FirstSeen = profile.LastSeen
		}
		c.m[snap.SourceID] = &profile
		restored++
	}
	return restored
}

// Evict removes profiles not seen since cutoff.
// Call periodically to bound memory (e.g. every 5 minutes).
func (c *Cache) Evict(cutoff time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, p := range c.m {
		if p.LastSeen.Before(cutoff) {
			delete(c.m, k)
			delete(c.dirty, k)
			n++
		}
	}
	return n
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
