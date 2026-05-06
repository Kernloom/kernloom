// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

/* ---------------- misc helpers ---------------- */

func openPinnedMap(path string) (*ebpf.Map, error) { return ebpf.LoadPinnedMap(path, nil) }

func ip4String(k [4]byte) string  { return net.IPv4(k[0], k[1], k[2], k[3]).String() }
func ip6String(k [16]byte) string { return net.IP(k[:]).String() }

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func calcSeverity(pps, synps, scanps float64, trigPPS, trigSyn, trigScan float64, wPPS, wSyn, wScan float64, cap float64) float64 {
	nPPS := 0.0
	if trigPPS > 0 {
		nPPS = minf(pps/trigPPS, cap)
	}
	nSyn := 0.0
	if trigSyn > 0 {
		nSyn = minf(synps/trigSyn, cap)
	}
	nScan := 0.0
	if trigScan > 0 {
		nScan = minf(scanps/trigScan, cap)
	}
	return wPPS*nPPS + wSyn*nSyn + wScan*nScan
}

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

/* ---------------- totals helper (optional) ---------------- */

func readTotalsSum(m *ebpf.Map) (xdpTotals, error) {
	var out xdpTotals
	if m == nil {
		return out, fmt.Errorf("nil totals map")
	}
	var k uint32 = 0
	var perCPU []xdpTotals
	if err := m.Lookup(&k, &perCPU); err != nil {
		return out, err
	}
	for _, v := range perCPU {
		out.Pkts += v.Pkts
		out.Pass += v.Pass
		out.DropAllow += v.DropAllow
		out.DropDeny += v.DropDeny
		out.DropRL += v.DropRL
	}
	return out, nil
}

/* ---------------- Utility ---------------- */

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
