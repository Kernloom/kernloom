// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sourcefilters

import (
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type Whitelist struct {
	exactSubjects map[string]struct{}
	exact4        map[[4]byte]struct{}
	exact6        map[[16]byte]struct{}
	cidrs4        []*net.IPNet
	cidrs6        []*net.IPNet

	path      string
	modTime   time.Time
	lastCheck time.Time
}

type Stats struct {
	Subjects int
	Entries4 int
	Entries6 int
	Ranges4  int
	Ranges6  int
}

func (s Stats) Entries() int {
	return s.Entries4 + s.Entries6
}

func (s Stats) Ranges() int {
	return s.Ranges4 + s.Ranges6
}

func NewWhitelist(path string) *Whitelist {
	return &Whitelist{
		exactSubjects: make(map[string]struct{}),
		exact4:        make(map[[4]byte]struct{}),
		exact6:        make(map[[16]byte]struct{}),
		cidrs4:        make([]*net.IPNet, 0, 64),
		cidrs6:        make([]*net.IPNet, 0, 64),
		path:          path,
	}
}

func (w *Whitelist) Stats() Stats {
	return Stats{Subjects: len(w.exactSubjects), Entries4: len(w.exact4), Entries6: len(w.exact6), Ranges4: len(w.cidrs4), Ranges6: len(w.cidrs6)}
}

func (w *Whitelist) Load() error {
	if w.path == "" {
		return nil
	}
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}

	exactSubjects := make(map[string]struct{}, 256)
	ex4 := make(map[[4]byte]struct{}, 256)
	ex6 := make(map[[16]byte]struct{}, 256)
	cidrs4 := make([]*net.IPNet, 0, 64)
	cidrs6 := make([]*net.IPNet, 0, 64)

	lines := strings.Split(string(raw), "\n")
	for _, ln := range lines {
		subject := sourceRuleSubject(ln)
		if subject == "" {
			continue
		}
		fam, isRange, ip4, ip6, n, ok := parseSourceRule(ln)
		if !ok {
			exactSubjects[subject] = struct{}{}
			continue
		}
		if isRange {
			if fam == 4 {
				cidrs4 = append(cidrs4, n)
			} else if fam == 6 {
				cidrs6 = append(cidrs6, n)
			}
			continue
		}
		if fam == 4 {
			ex4[ip4] = struct{}{}
		} else if fam == 6 {
			ex6[ip6] = struct{}{}
		}
	}

	w.exactSubjects = exactSubjects
	w.exact4 = ex4
	w.exact6 = ex6
	w.cidrs4 = cidrs4
	w.cidrs6 = cidrs6
	return nil
}

func (w *Whitelist) MarkLoaded() {
	if w.path == "" {
		return
	}
	if fi, err := os.Stat(w.path); err == nil {
		w.modTime = fi.ModTime()
	}
}

func (w *Whitelist) MaybeReload(every time.Duration) {
	if w.path == "" || every <= 0 {
		return
	}
	now := time.Now()
	if !w.lastCheck.IsZero() && now.Sub(w.lastCheck) < every {
		return
	}
	w.lastCheck = now

	fi, err := os.Stat(w.path)
	if err != nil {
		return
	}
	if fi.ModTime().Equal(w.modTime) {
		return
	}
	if err := w.Load(); err == nil {
		w.modTime = fi.ModTime()
		st := w.Stats()
		log.Printf("Whitelist reloaded: %s subjects=%d entries=%d ranges=%d", w.path, st.Subjects, st.Entries(), st.Ranges())
	}
}

func (w *Whitelist) MatchSource(sourceID string) bool {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return false
	}
	if _, ok := w.exactSubjects[sourceID]; ok {
		return true
	}
	ip := net.ParseIP(sourceID)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		var b [4]byte
		copy(b[:], v4)
		return w.matchV4(b)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	var b [16]byte
	copy(b[:], ip16)
	return w.matchV6(b)
}

func (w *Whitelist) matchV4(ip4 [4]byte) bool {
	if _, ok := w.exact4[ip4]; ok {
		return true
	}
	if len(w.cidrs4) == 0 {
		return false
	}
	ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	for _, n := range w.cidrs4 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *Whitelist) matchV6(ip6 [16]byte) bool {
	if _, ok := w.exact6[ip6]; ok {
		return true
	}
	if len(w.cidrs6) == 0 {
		return false
	}
	ip := net.IP(ip6[:])
	for _, n := range w.cidrs6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseSourceRule(line string) (family int, isRange bool, ip4 [4]byte, ip6 [16]byte, n *net.IPNet, ok bool) {
	s := sourceRuleSubject(line)
	if s == "" {
		return 0, false, ip4, ip6, nil, false
	}
	return parseSourceToken(s)
}

func sourceRuleSubject(line string) string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func parseSourceToken(s string) (family int, isRange bool, ip4 [4]byte, ip6 [16]byte, n *net.IPNet, ok bool) {
	if strings.Contains(s, "/") {
		_, nn, err := net.ParseCIDR(s)
		if err != nil || nn == nil {
			return 0, false, ip4, ip6, nil, false
		}
		if nn.IP.To4() != nil {
			return 4, true, ip4, ip6, nn, true
		}
		ip16 := nn.IP.To16()
		if ip16 == nil {
			return 0, false, ip4, ip6, nil, false
		}
		return 6, true, ip4, ip6, nn, true
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false, ip4, ip6, nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		copy(ip4[:], v4[:4])
		return 4, false, ip4, ip6, nil, true
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, false, ip4, ip6, nil, false
	}
	copy(ip6[:], ip16[:16])
	return 6, false, ip4, ip6, nil, true
}
