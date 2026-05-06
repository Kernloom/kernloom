// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

/* ---------------- Feedback / Forgive ---------------- */

type fbCIDR struct {
	net   *net.IPNet
	until time.Time
	fam   int // 4 or 6
}

type feedbackManager struct {
	path      string
	modTime   time.Time
	lastCheck time.Time

	exact4 map[[4]byte]time.Time
	exact6 map[[16]byte]time.Time
	cidrs4 []fbCIDR
	cidrs6 []fbCIDR

	lastCIDRApply time.Time
}

type feedbackEntry struct {
	Target string `json:"target"`
	Action string `json:"action"` // forgive|whitelist
	TTL    string `json:"ttl,omitempty"`
	Until  string `json:"until,omitempty"` // RFC3339
	Notes  string `json:"notes,omitempty"`
}

func newFeedbackManager(path string) *feedbackManager {
	return &feedbackManager{
		path:   path,
		exact4: make(map[[4]byte]time.Time, 64),
		exact6: make(map[[16]byte]time.Time, 64),
		cidrs4: make([]fbCIDR, 0, 32),
		cidrs6: make([]fbCIDR, 0, 32),
	}
}

func parseFBTarget(s string) (family int, isCIDR bool, ip4 [4]byte, ip6 [16]byte, n *net.IPNet, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false, ip4, ip6, nil, false
	}
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

func (fm *feedbackManager) load(now time.Time) error {
	if fm.path == "" {
		return nil
	}
	raw, err := os.ReadFile(fm.path)
	if err != nil {
		return err
	}

	var entries []feedbackEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}

	ex4 := make(map[[4]byte]time.Time, 256)
	ex6 := make(map[[16]byte]time.Time, 256)
	cidrs4 := make([]fbCIDR, 0, 64)
	cidrs6 := make([]fbCIDR, 0, 64)

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

		var until time.Time
		if e.Until != "" {
			if t, err := time.Parse(time.RFC3339, e.Until); err == nil {
				until = t
			}
		}
		if until.IsZero() {
			ttl := 24 * time.Hour
			if e.TTL != "" {
				if d, err := time.ParseDuration(e.TTL); err == nil && d > 0 {
					ttl = d
				}
			}
			until = now.Add(ttl)
		}

		fam, isCIDR, ip4, ip6, n, ok := parseFBTarget(target)
		if !ok {
			continue
		}
		if isCIDR {
			if fam == 4 {
				cidrs4 = append(cidrs4, fbCIDR{net: n, until: until, fam: 4})
			} else if fam == 6 {
				cidrs6 = append(cidrs6, fbCIDR{net: n, until: until, fam: 6})
			}
			continue
		}
		if fam == 4 {
			ex4[ip4] = until
		} else if fam == 6 {
			ex6[ip6] = until
		}
	}

	fm.exact4 = ex4
	fm.exact6 = ex6
	fm.cidrs4 = cidrs4
	fm.cidrs6 = cidrs6
	return nil
}

func (fm *feedbackManager) maybeReload(every time.Duration) {
	if fm.path == "" || every <= 0 {
		return
	}
	now := time.Now()
	if !fm.lastCheck.IsZero() && now.Sub(fm.lastCheck) < every {
		return
	}
	fm.lastCheck = now

	fi, err := os.Stat(fm.path)
	if err != nil {
		return
	}
	if fi.ModTime().Equal(fm.modTime) {
		return
	}
	if err := fm.load(now); err == nil {
		fm.modTime = fi.ModTime()
		log.Printf("Feedback reloaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d", fm.path, len(fm.exact4), len(fm.cidrs4), len(fm.exact6), len(fm.cidrs6))
	}
}

func (fm *feedbackManager) matchV4(ip4 [4]byte) bool {
	if fm.path == "" {
		return false
	}
	now := time.Now()
	if until, ok := fm.exact4[ip4]; ok {
		if now.Before(until) {
			return true
		}
		delete(fm.exact4, ip4)
		return false
	}
	if len(fm.cidrs4) == 0 {
		return false
	}
	ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	keep := fm.cidrs4[:0]
	matched := false
	for _, c := range fm.cidrs4 {
		if now.After(c.until) {
			continue
		}
		keep = append(keep, c)
		if !matched && c.net.Contains(ip) {
			matched = true
		}
	}
	fm.cidrs4 = keep
	return matched
}

func (fm *feedbackManager) matchV6(ip6 [16]byte) bool {
	if fm.path == "" {
		return false
	}
	now := time.Now()
	if until, ok := fm.exact6[ip6]; ok {
		if now.Before(until) {
			return true
		}
		delete(fm.exact6, ip6)
		return false
	}
	if len(fm.cidrs6) == 0 {
		return false
	}
	ip := net.IP(ip6[:])
	keep := fm.cidrs6[:0]
	matched := false
	for _, c := range fm.cidrs6 {
		if now.After(c.until) {
			continue
		}
		keep = append(keep, c)
		if !matched && c.net.Contains(ip) {
			matched = true
		}
	}
	fm.cidrs6 = keep
	return matched
}

// applyV4 best-effort de-enforcement for exact feedback IPs (v4).
func (fm *feedbackManager) applyV4(now time.Time, denyMap4, rlPolicyMap4 *ebpf.Map, state4 map[[4]byte]ipState, dry bool) {
	if fm.path == "" {
		return
	}
	for ip, until := range fm.exact4 {
		if now.After(until) {
			delete(fm.exact4, ip)
			continue
		}
		if dry {
			continue
		}
		if rlPolicyMap4 != nil {
			_ = rlPolicyMap4.Delete(&ip)
		}
		if denyMap4 != nil {
			_ = denyMap4.Delete(&ip)
		}
		if st, ok := state4[ip]; ok {
			if st.Level != LObserve {
				st.Level = LObserve
			}
			st.Strikes = 0
			st.NonCompTicks = 0
			st.UpStreak = 0
			st.DownStreak = 0
			st.HighSevSince = time.Time{}
			st.ExpiresAt = time.Time{}
			state4[ip] = st
		}
	}
}

// applyV6 best-effort de-enforcement for exact feedback IPs (v6).
func (fm *feedbackManager) applyV6(now time.Time, denyMap6, rlPolicyMap6 *ebpf.Map, state6 map[[16]byte]ipState, dry bool) {
	if fm.path == "" {
		return
	}
	for ip, until := range fm.exact6 {
		if now.After(until) {
			delete(fm.exact6, ip)
			continue
		}
		if dry {
			continue
		}
		if rlPolicyMap6 != nil {
			krl := src6Key{IP: ip}
			_ = rlPolicyMap6.Delete(&krl)
		}
		if denyMap6 != nil {
			kd := key6Bytes{IP: ip}
			_ = denyMap6.Delete(&kd)
		}
		if st, ok := state6[ip]; ok {
			if st.Level != LObserve {
				st.Level = LObserve
			}
			st.Strikes = 0
			st.NonCompTicks = 0
			st.UpStreak = 0
			st.DownStreak = 0
			st.HighSevSince = time.Time{}
			st.ExpiresAt = time.Time{}
			state6[ip] = st
		}
	}
}

/* ---------------- Feedback CIDR de-enforcement ---------------- */

// applyCIDRsIfDue best-effort de-enforcement for CIDR feedback entries (v4 + v6).
// WARNING: iterating large maps can be expensive. Use a reasonable interval and a maxDeletes cap.
func (fm *feedbackManager) applyCIDRsIfDue(
	now time.Time,
	denyMap4, rlPolicyMap4 *ebpf.Map, state4 map[[4]byte]ipState,
	denyMap6, rlPolicyMap6 *ebpf.Map, state6 map[[16]byte]ipState,
	dry bool, every time.Duration, maxDeletes int,
) {
	if fm.path == "" || dry || every <= 0 || maxDeletes <= 0 {
		return
	}
	if (denyMap4 == nil && rlPolicyMap4 == nil) && (denyMap6 == nil && rlPolicyMap6 == nil) {
		return
	}
	if len(fm.cidrs4) == 0 && len(fm.cidrs6) == 0 {
		return
	}
	if !fm.lastCIDRApply.IsZero() && now.Sub(fm.lastCIDRApply) < every {
		return
	}
	fm.lastCIDRApply = now

	// Build active lists and drop expired.
	active4 := make([]*net.IPNet, 0, len(fm.cidrs4))
	keep4 := fm.cidrs4[:0]
	for _, c := range fm.cidrs4 {
		if now.After(c.until) {
			continue
		}
		keep4 = append(keep4, c)
		active4 = append(active4, c.net)
	}
	fm.cidrs4 = keep4

	active6 := make([]*net.IPNet, 0, len(fm.cidrs6))
	keep6 := fm.cidrs6[:0]
	for _, c := range fm.cidrs6 {
		if now.After(c.until) {
			continue
		}
		keep6 = append(keep6, c)
		active6 = append(active6, c.net)
	}
	fm.cidrs6 = keep6

	matchAny4 := func(ip4 [4]byte) bool {
		if len(active4) == 0 {
			return false
		}
		ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
		for _, n := range active4 {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	matchAny6 := func(ip6 [16]byte) bool {
		if len(active6) == 0 {
			return false
		}
		ip := net.IP(ip6[:])
		for _, n := range active6 {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}

	// v4 delete from RL policy map (value rlCfg)
	deleteRL4 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active4) == 0 {
			return 0
		}
		delKeys := make([][4]byte, 0, 1024)
		it := m.Iterate()
		var k [4]byte
		var v rlCfg
		for it.Next(&k, &v) {
			if !matchAny4(k) {
				continue
			}
			delKeys = append(delKeys, k)
			if len(delKeys) >= 1024 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, kk := range delKeys {
			if *budget <= 0 {
				break
			}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state4[kk]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state4[kk] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: rl_policy4 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	// v4 delete from deny map (value u8)
	deleteDeny4 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active4) == 0 {
			return 0
		}
		delKeys := make([][4]byte, 0, 1024)
		it := m.Iterate()
		var k [4]byte
		var v uint8
		for it.Next(&k, &v) {
			if !matchAny4(k) {
				continue
			}
			delKeys = append(delKeys, k)
			if len(delKeys) >= 1024 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, kk := range delKeys {
			if *budget <= 0 {
				break
			}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state4[kk]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state4[kk] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: deny4 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	// v6 delete from RL policy map (key src6Key, value rlCfg)
	deleteRL6 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active6) == 0 {
			return 0
		}
		delKeys := make([][16]byte, 0, 512)
		it := m.Iterate()
		var k src6Key
		var v rlCfg
		for it.Next(&k, &v) {
			ip := k.IP
			if !matchAny6(ip) {
				continue
			}
			delKeys = append(delKeys, ip)
			if len(delKeys) >= 512 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, ip := range delKeys {
			if *budget <= 0 {
				break
			}
			kk := src6Key{IP: ip}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state6[ip]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state6[ip] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: rl_policy6 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	// v6 delete from deny map (key key6Bytes, value u8)
	deleteDeny6 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active6) == 0 {
			return 0
		}
		delKeys := make([][16]byte, 0, 512)
		it := m.Iterate()
		var k key6Bytes
		var v uint8
		for it.Next(&k, &v) {
			ip := k.IP
			if !matchAny6(ip) {
				continue
			}
			delKeys = append(delKeys, ip)
			if len(delKeys) >= 512 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, ip := range delKeys {
			if *budget <= 0 {
				break
			}
			kk := key6Bytes{IP: ip}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state6[ip]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state6[ip] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: deny6 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	budget := maxDeletes
	_ = deleteRL4(rlPolicyMap4, &budget)
	_ = deleteDeny4(denyMap4, &budget)
	_ = deleteRL6(rlPolicyMap6, &budget)
	_ = deleteDeny6(denyMap6, &budget)
}
