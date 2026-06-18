// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sourcefilters

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type expiringRange struct {
	net   *net.IPNet
	until time.Time
}

type Feedback struct {
	path      string
	modTime   time.Time
	lastCheck time.Time

	exactSubjects map[string]time.Time
	exact4        map[[4]byte]time.Time
	exact6        map[[16]byte]time.Time
	cidrs4        []expiringRange
	cidrs6        []expiringRange

	lastSweep time.Time
}

type feedbackEntry struct {
	Target string `json:"target"`
	Action string `json:"action"`
	TTL    string `json:"ttl,omitempty"`
	Until  string `json:"until,omitempty"`
	Notes  string `json:"notes,omitempty"`
}

func NewFeedback(path string) *Feedback {
	return &Feedback{
		exactSubjects: make(map[string]time.Time, 64),
		path:          path,
		exact4:        make(map[[4]byte]time.Time, 64),
		exact6:        make(map[[16]byte]time.Time, 64),
		cidrs4:        make([]expiringRange, 0, 32),
		cidrs6:        make([]expiringRange, 0, 32),
	}
}

func (f *Feedback) Active() bool {
	return f.path != ""
}

func (f *Feedback) Stats() Stats {
	return Stats{Subjects: len(f.exactSubjects), Entries4: len(f.exact4), Entries6: len(f.exact6), Ranges4: len(f.cidrs4), Ranges6: len(f.cidrs6)}
}

func (f *Feedback) Load(now time.Time) error {
	if f.path == "" {
		return nil
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}

	var entries []feedbackEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}

	exactSubjects := make(map[string]time.Time, 256)
	ex4 := make(map[[4]byte]time.Time, 256)
	ex6 := make(map[[16]byte]time.Time, 256)
	cidrs4 := make([]expiringRange, 0, 64)
	cidrs6 := make([]expiringRange, 0, 64)

	for _, e := range entries {
		target := strings.TrimSpace(e.Target)
		if target == "" {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(e.Action))
		if action == "" {
			action = "forgive"
		}
		if action != "forgive" && action != "whitelist" {
			continue
		}

		until := feedbackExpiry(now, e)
		fam, isRange, ip4, ip6, n, ok := parseSourceToken(target)
		if !ok {
			exactSubjects[target] = until
			continue
		}
		if isRange {
			if fam == 4 {
				cidrs4 = append(cidrs4, expiringRange{net: n, until: until})
			} else if fam == 6 {
				cidrs6 = append(cidrs6, expiringRange{net: n, until: until})
			}
			continue
		}
		if fam == 4 {
			ex4[ip4] = until
		} else if fam == 6 {
			ex6[ip6] = until
		}
	}

	f.exactSubjects = exactSubjects
	f.exact4 = ex4
	f.exact6 = ex6
	f.cidrs4 = cidrs4
	f.cidrs6 = cidrs6
	return nil
}

func (f *Feedback) MarkLoaded() {
	if f.path == "" {
		return
	}
	if fi, err := os.Stat(f.path); err == nil {
		f.modTime = fi.ModTime()
	}
}

func (f *Feedback) MaybeReload(every time.Duration) {
	if f.path == "" || every <= 0 {
		return
	}
	now := time.Now()
	if !f.lastCheck.IsZero() && now.Sub(f.lastCheck) < every {
		return
	}
	f.lastCheck = now

	fi, err := os.Stat(f.path)
	if err != nil {
		return
	}
	if fi.ModTime().Equal(f.modTime) {
		return
	}
	if err := f.Load(now); err == nil {
		f.modTime = fi.ModTime()
		st := f.Stats()
		log.Printf("Feedback reloaded: %s subjects=%d entries=%d ranges=%d", f.path, st.Subjects, st.Entries(), st.Ranges())
	}
}

func (f *Feedback) BeginSweep(now time.Time, every time.Duration) bool {
	if f.path == "" || every <= 0 {
		return false
	}
	if !f.lastSweep.IsZero() && now.Sub(f.lastSweep) < every {
		return false
	}
	f.lastSweep = now
	return true
}

func (f *Feedback) MatchSource(sourceID string) bool {
	if f.path == "" {
		return false
	}
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return false
	}
	now := time.Now()
	if until, ok := f.exactSubjects[sourceID]; ok {
		if now.Before(until) {
			return true
		}
		delete(f.exactSubjects, sourceID)
		return false
	}
	ip := net.ParseIP(sourceID)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		var b [4]byte
		copy(b[:], v4)
		return f.matchV4(b)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	var b [16]byte
	copy(b[:], ip16)
	return f.matchV6(b)
}

func (f *Feedback) matchV4(ip4 [4]byte) bool {
	now := time.Now()
	if until, ok := f.exact4[ip4]; ok {
		if now.Before(until) {
			return true
		}
		delete(f.exact4, ip4)
		return false
	}
	if len(f.cidrs4) == 0 {
		return false
	}
	ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	keep := f.cidrs4[:0]
	matched := false
	for _, r := range f.cidrs4 {
		if now.After(r.until) {
			continue
		}
		keep = append(keep, r)
		if !matched && r.net.Contains(ip) {
			matched = true
		}
	}
	f.cidrs4 = keep
	return matched
}

func (f *Feedback) matchV6(ip6 [16]byte) bool {
	now := time.Now()
	if until, ok := f.exact6[ip6]; ok {
		if now.Before(until) {
			return true
		}
		delete(f.exact6, ip6)
		return false
	}
	if len(f.cidrs6) == 0 {
		return false
	}
	ip := net.IP(ip6[:])
	keep := f.cidrs6[:0]
	matched := false
	for _, r := range f.cidrs6 {
		if now.After(r.until) {
			continue
		}
		keep = append(keep, r)
		if !matched && r.net.Contains(ip) {
			matched = true
		}
	}
	f.cidrs6 = keep
	return matched
}

func feedbackExpiry(now time.Time, e feedbackEntry) time.Time {
	if e.Until != "" {
		if t, err := time.Parse(time.RFC3339, e.Until); err == nil {
			return t
		}
	}
	ttl := 24 * time.Hour
	if e.TTL != "" {
		if d, err := time.ParseDuration(e.TTL); err == nil && d > 0 {
			ttl = d
		}
	}
	return now.Add(ttl)
}
