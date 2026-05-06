// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"log"
	"net"
	"os"
	"strings"
	"time"
)

/* ---------------- Whitelist ---------------- */

type whitelist struct {
	exact4 map[[4]byte]struct{}
	exact6 map[[16]byte]struct{}
	cidrs4 []*net.IPNet
	cidrs6 []*net.IPNet

	path      string
	modTime   time.Time
	lastCheck time.Time
}

func newWhitelist(path string) *whitelist {
	return &whitelist{
		exact4: make(map[[4]byte]struct{}),
		exact6: make(map[[16]byte]struct{}),
		cidrs4: make([]*net.IPNet, 0, 64),
		cidrs6: make([]*net.IPNet, 0, 64),
		path:   path,
	}
}

func (w *whitelist) matchV4(ip4 [4]byte) bool {
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

func (w *whitelist) matchV6(ip6 [16]byte) bool {
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

func parseWhitelistLine(line string) (family int, isCIDR bool, ip4 [4]byte, ip6 [16]byte, n *net.IPNet, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return 0, false, ip4, ip6, nil, false
	}
	// strip inline comments
	if i := strings.Index(s, "#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return 0, false, ip4, ip6, nil, false
	}

	// CIDR?
	if strings.Contains(s, "/") {
		_, nn, err := net.ParseCIDR(s)
		if err != nil || nn == nil {
			return 0, false, ip4, ip6, nil, false
		}
		if nn.IP.To4() != nil {
			return 4, true, ip4, ip6, nn, true
		}
		// v6
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
	v6p := ip.To16()
	if v6p == nil {
		return 0, false, ip4, ip6, nil, false
	}
	copy(ip6[:], v6p[:16])
	return 6, false, ip4, ip6, nil, true
}

func (w *whitelist) load() error {
	if w.path == "" {
		return nil
	}
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}

	ex4 := make(map[[4]byte]struct{}, 256)
	ex6 := make(map[[16]byte]struct{}, 256)
	cidrs4 := make([]*net.IPNet, 0, 64)
	cidrs6 := make([]*net.IPNet, 0, 64)

	lines := strings.Split(string(raw), "\n")
	for _, ln := range lines {
		fam, isCIDR, ip4, ip6, n, ok := parseWhitelistLine(ln)
		if !ok {
			continue
		}
		if isCIDR {
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

	w.exact4 = ex4
	w.exact6 = ex6
	w.cidrs4 = cidrs4
	w.cidrs6 = cidrs6
	return nil
}

func (w *whitelist) maybeReload(every time.Duration) {
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
	if err := w.load(); err == nil {
		w.modTime = fi.ModTime()
		log.Printf("Whitelist reloaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d", w.path, len(w.exact4), len(w.cidrs4), len(w.exact6), len(w.cidrs6))
	}
}
