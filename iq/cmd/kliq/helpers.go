// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

/* ---------------- misc helpers ---------------- */

// fmtBPS formats a bytes/s trigger for log output.
// Returns "off" when the trigger is disabled (0), otherwise the numeric value.
func fmtBPS(v float64) string {
	if v <= 0 {
		return "off"
	}
	return fmt.Sprintf("%.0f", v)
}

func ip4String(k [4]byte) string  { return net.IPv4(k[0], k[1], k[2], k[3]).String() }
func ip6String(k [16]byte) string { return net.IP(k[:]).String() }

func capChange(old, target, maxRel float64) float64 {
	if maxRel <= 0 {
		return target
	}
	lo := old * (1 - maxRel)
	hi := old * (1 + maxRel)
	if target < lo {
		return lo
	}
	if target > hi {
		return hi
	}
	return target
}

// capChangeDir applies different relative caps depending on direction.
// - If target > old: maxUp is used.
// - If target < old: maxDown is used.
func capChangeDir(old, target, maxUp, maxDown float64) float64 {
	if target >= old {
		return capChange(old, target, maxUp)
	}
	return capChange(old, target, maxDown)
}

/* ---------------- Bootstrap ---------------- */

type bootstrapPolicy struct {
	Active  bool
	Phase   string
	Every   time.Duration
	K       float64
	MaxUp   float64
	MaxDown float64
	Alpha   float64
}

func bootstrapEffective(now time.Time, info bootstrapInfo, window, p1End, p2End time.Duration,
	every1, every2, every3 time.Duration,
	kStart, kFinal float64,
	maxUp1, maxDown1, maxUp2, maxDown2, maxUp3, maxDown3 float64,
	alpha1, alpha2, alpha3 float64,
	steadyEvery time.Duration, steadyK, steadyUp, steadyDown, steadyAlpha float64,
) bootstrapPolicy {
	if !info.Enabled || info.StartedAt.IsZero() || window <= 0 {
		return bootstrapPolicy{Active: false, Phase: "steady", Every: steadyEvery, K: steadyK, MaxUp: steadyUp, MaxDown: steadyDown, Alpha: steadyAlpha}
	}
	age := now.Sub(info.StartedAt)
	if age < 0 {
		age = 0
	}
	progress := float64(age) / float64(window)
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	k := kStart + (kFinal-kStart)*progress

	if age < p1End {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-1", Every: every1, K: k, MaxUp: maxUp1, MaxDown: maxDown1, Alpha: alpha1}
	}
	if age < p2End {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-2", Every: every2, K: k, MaxUp: maxUp2, MaxDown: maxDown2, Alpha: alpha2}
	}
	if age < window {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-3", Every: every3, K: k, MaxUp: maxUp3, MaxDown: maxDown3, Alpha: alpha3}
	}
	return bootstrapPolicy{Active: false, Phase: "steady", Every: steadyEvery, K: steadyK, MaxUp: steadyUp, MaxDown: steadyDown, Alpha: steadyAlpha}
}

// parseGraphExcludeCIDRs parses a comma-separated list of CIDR strings.
// Invalid entries are logged and skipped.
func parseGraphExcludeCIDRs(s string) []net.IPNet {
	if s == "" {
		return nil
	}
	var out []net.IPNet
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			log.Printf("graph: ignoring invalid exclude CIDR %q: %v", raw, err)
			continue
		}
		out = append(out, *cidr)
	}
	return out
}

/* ---------------- Utility ---------------- */

// graphStrikesFromScore converts a graph signal score (0-100) to FSM strike credits.
// Higher confidence violations escalate the FSM faster.
func graphStrikesFromScore(score int) int {
	switch {
	case score >= 90:
		return 3
	case score >= 75:
		return 2
	default:
		return 1
	}
}

// sendStrike parses subjectID as an IP address and sends a graphStrikeMsg to ch.
// No-op if the IP cannot be parsed or the channel is full.
func sendStrike(ch chan<- graphStrikeMsg, subjectID string, n int, forceBlock bool) {
	ip := net.ParseIP(subjectID)
	if ip == nil {
		return
	}
	var msg graphStrikeMsg
	msg.n = n
	msg.forceBlock = forceBlock
	if ip4 := ip.To4(); ip4 != nil {
		copy(msg.ip4[:], ip4)
	} else {
		msg.isV6 = true
		copy(msg.ip6[:], ip.To16())
	}
	select {
	case ch <- msg:
	default:
		kliqLog.Printf("STRIKE dropped (channel full) subject=%s", subjectID)
	}
}

func minInt(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
