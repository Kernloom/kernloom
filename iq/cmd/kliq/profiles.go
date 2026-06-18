// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
)

/* ---------------- Profiles ---------------- */

// profile holds PDP (kliq) internal behavior parameters. It is intentionally
// separate from the PolicyPack: the PolicyPack expresses abstract enforcement
// rules, while the profile controls how kliq's signal engine and FSM evaluate
// those rules internally.
//
// PEP-specific parameters (rate_pps, burst, cooldown) are NOT here; they live
// behind the selected adapter binding.
//
// TTLs (SoftTTL, HardTTL, BlockTTL) are kept here because they control how
// long the PDP keeps a source at each enforcement level — a PDP scheduling
// concern, not a PEP implementation detail.
type profile struct {
	Name string

	// Legacy network scoring parameters.
	adapterruntime.LegacyNetworkScoring

	SoftAt  int
	HardAt  int
	BlockAt int

	// TTLs: how long the PDP holds each enforcement level (PDP scheduling).
	// In policy-file mode these are overridden by rule TTLs.
	SoftTTL  time.Duration
	HardTTL  time.Duration
	BlockTTL time.Duration

	BlockMinSev float64
	BlockMinDur time.Duration

	UpNeed      int
	DownNeed    int
	MinHoldSoft time.Duration
	MinHoldHard time.Duration

	NonCompAt    int
	NonCompDrop  float64
	NonCompSev   float64
	NonCompReset float64
}

func profileByName(name string) profile {
	n := strings.ToLower(strings.TrimSpace(name))

	// Backward-compatible aliases
	switch n {
	case "router":
		n = "ziti-router"
	case "controller", "ziri-controller":
		n = "ziti-controller"
	case "internal":
		n = "internal-app"
	}

	switch n {

	// =========================
	// Generic / Unknown
	// =========================

	case "generic":
		// Safe starting point for any unknown workload. High triggers, no blocking.
		// Autotune adapts the actual thresholds within hours of first traffic.
		return profile{
			Name:                 "generic",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 5000, TrigSyn: 500, TrigScan: 50, WPPS: 0.50, WSyn: 0.30, WScan: 0.20, SevCap: 3.0},
			SoftAt:               3, HardAt: 7, BlockAt: 999,
			SoftTTL: 60 * time.Second, HardTTL: 5 * time.Minute, BlockTTL: 30 * time.Minute,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 10, MinHoldSoft: 30 * time.Second, MinHoldHard: 2 * time.Minute,
			NonCompAt: 999, NonCompDrop: 999, NonCompSev: 999, NonCompReset: 0.30,
		}

	// =========================
	// OpenZiti Profiles
	// =========================

	case "ziti-router":
		// High throughput / many data packets, NAT-friendly. Block only if sustained.
		return profile{
			Name:                 "ziti-router",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 8000, TrigSyn: 200, TrigScan: 30, WPPS: 0.60, WSyn: 0.25, WScan: 0.15, SevCap: 3.0},
			SoftAt:               2, HardAt: 5, BlockAt: 12,
			SoftTTL: 30 * time.Second, HardTTL: 2 * time.Minute, BlockTTL: 10 * time.Minute,
			BlockMinSev: 3.0, BlockMinDur: 60 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 20, NonCompDrop: 20, NonCompSev: 2.5, NonCompReset: 0.30,
		}

	case "ziti-controller":
		// Public enrolment/API surface. More SYN-sensitive, cautious blocking.
		return profile{
			Name:                 "ziti-controller",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 80, TrigSyn: 20, TrigScan: 5, WPPS: 0.35, WSyn: 0.40, WScan: 0.25, SevCap: 3.0},
			SoftAt:               1, HardAt: 3, BlockAt: 9,
			SoftTTL: 60 * time.Second, HardTTL: 10 * time.Minute, BlockTTL: 30 * time.Minute,
			BlockMinSev: 2.0, BlockMinDur: 15 * time.Second,
			UpNeed: 2, DownNeed: 6, MinHoldSoft: 15 * time.Second, MinHoldHard: 30 * time.Second,
			NonCompAt: 8, NonCompDrop: 1.0, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	// -------------------------
	// Bootstrap variants (safe start)
	// -------------------------

	case "ziti-router-bootstrap":
		// Start tolerant (high trig-*), prefer rate-limit, avoid blocks early.
		return profile{
			Name:                 "ziti-router-bootstrap",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 25000, TrigSyn: 600, TrigScan: 120, WPPS: 0.60, WSyn: 0.25, WScan: 0.15, SevCap: 3.0},
			SoftAt:               3, HardAt: 8, BlockAt: 999, // avoid blocking during bootstrap
			SoftTTL: 45 * time.Second, HardTTL: 3 * time.Minute, BlockTTL: 10 * time.Minute,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 10, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 40, NonCompDrop: 50, NonCompSev: 2.5, NonCompReset: 0.30,
		}

	case "ziti-controller-bootstrap":
		// Start tolerant to avoid FPs during onboarding. Rate-limit earlier, block disabled by default.
		return profile{
			Name:                 "ziti-controller-bootstrap",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 400, TrigSyn: 120, TrigScan: 30, WPPS: 0.35, WSyn: 0.45, WScan: 0.20, SevCap: 3.0},
			SoftAt:               2, HardAt: 6, BlockAt: 999,
			SoftTTL: 90 * time.Second, HardTTL: 10 * time.Minute, BlockTTL: 30 * time.Minute,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 8, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 12, NonCompDrop: 2.0, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	// =========================
	// Generic Public-Facing
	// =========================

	case "public-web":
		// Public website (HTTP/HTTPS). Mostly PPS + SYN. Port-scan less relevant.
		return profile{
			Name:                 "public-web",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 1200, TrigSyn: 250, TrigScan: 20, WPPS: 0.55, WSyn: 0.30, WScan: 0.15, SevCap: 3.0},
			SoftAt:               2, HardAt: 5, BlockAt: 12,
			SoftTTL: 60 * time.Second, HardTTL: 10 * time.Minute, BlockTTL: 10 * time.Minute,
			BlockMinSev: 2.8, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 15, NonCompDrop: 10, NonCompSev: 2.0, NonCompReset: 0.30,
		}

	case "public-api":
		// Public JSON/API endpoint: bursty, higher PPS.
		return profile{
			Name:                 "public-api",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 2500, TrigSyn: 500, TrigScan: 30, WPPS: 0.55, WSyn: 0.30, WScan: 0.15, SevCap: 3.0},
			SoftAt:               2, HardAt: 4, BlockAt: 10,
			SoftTTL: 60 * time.Second, HardTTL: 10 * time.Minute, BlockTTL: 15 * time.Minute,
			BlockMinSev: 2.8, BlockMinDur: 25 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 12, NonCompDrop: 15, NonCompSev: 2.0, NonCompReset: 0.30,
		}

	case "idp":
		// Identity Provider / Auth endpoints: SYN-sensitive, protect against auth abuse. NAT-friendly gating.
		return profile{
			Name:                 "idp",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 350, TrigSyn: 180, TrigScan: 10, WPPS: 0.30, WSyn: 0.55, WScan: 0.15, SevCap: 3.0},
			SoftAt:               1, HardAt: 3, BlockAt: 8,
			SoftTTL: 2 * time.Minute, HardTTL: 15 * time.Minute, BlockTTL: 30 * time.Minute,
			BlockMinSev: 2.5, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 10, NonCompDrop: 1.0, NonCompSev: 1.8, NonCompReset: 0.30,
		}

	// =========================
	// Generic Internal / East-West
	// =========================

	case "internal-app":
		// Internal app: scanning/lateral movement more relevant; avoid blocking by default.
		return profile{
			Name:                 "internal-app",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 800, TrigSyn: 150, TrigScan: 8, WPPS: 0.25, WSyn: 0.20, WScan: 0.55, SevCap: 3.0},
			SoftAt:               3, HardAt: 6, BlockAt: 999,
			SoftTTL: 3 * time.Minute, HardTTL: 15 * time.Minute, BlockTTL: 10 * time.Minute,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 2, DownNeed: 10, MinHoldSoft: 45 * time.Second, MinHoldHard: 2 * time.Minute,
			NonCompAt: 999, NonCompDrop: 999, NonCompSev: 999, NonCompReset: 0.30,
		}

	// =========================
	// NAS / Storage
	// =========================

	case "nas":
		// NAS (Synology, QNAP, TrueNAS). Few trusted LAN clients; burst-tolerant for SMB/NFS
		// file transfers but strict on SYN spikes and port scans (brute-force, ransomware).
		// Long block TTL: if something scans your NAS it should stay blocked.
		return profile{
			Name:                 "nas",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 1500, TrigSyn: 30, TrigScan: 8, WPPS: 0.30, WSyn: 0.35, WScan: 0.35, SevCap: 3.0},
			SoftAt:               2, HardAt: 5, BlockAt: 14,
			SoftTTL: 2 * time.Minute, HardTTL: 15 * time.Minute, BlockTTL: 24 * time.Hour,
			BlockMinSev: 2.5, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 60 * time.Second, MinHoldHard: 5 * time.Minute,
			NonCompAt: 10, NonCompDrop: 2.0, NonCompSev: 1.8, NonCompReset: 0.30,
		}

	case "nas-bootstrap":
		// NAS initial learning phase: tolerant to avoid blocking legitimate clients before
		// the graph is learned. Blocking disabled; rate-limiting only.
		return profile{
			Name:                 "nas-bootstrap",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 4000, TrigSyn: 100, TrigScan: 30, WPPS: 0.30, WSyn: 0.40, WScan: 0.30, SevCap: 3.0},
			SoftAt:               3, HardAt: 7, BlockAt: 999,
			SoftTTL: 3 * time.Minute, HardTTL: 20 * time.Minute, BlockTTL: 24 * time.Hour,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 10, MinHoldSoft: 2 * time.Minute, MinHoldHard: 10 * time.Minute,
			NonCompAt: 999, NonCompDrop: 999, NonCompSev: 999, NonCompReset: 0.30,
		}

	case "ssh-bastion":
		// Protect SSH/bastion: low normal PPS, suspicious SYN/scan. Blocking ok but gated.
		return profile{
			Name:                 "ssh-bastion",
			LegacyNetworkScoring: adapterruntime.LegacyNetworkScoring{TrigPPS: 60, TrigSyn: 25, TrigScan: 5, WPPS: 0.30, WSyn: 0.55, WScan: 0.15, SevCap: 3.0},
			SoftAt:               1, HardAt: 2, BlockAt: 6,
			SoftTTL: 5 * time.Minute, HardTTL: 30 * time.Minute, BlockTTL: 60 * time.Minute,
			BlockMinSev: 2.0, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 10, MinHoldSoft: 60 * time.Second, MinHoldHard: 5 * time.Minute,
			NonCompAt: 6, NonCompDrop: 0.5, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	default:
		return profileByName("generic")
	}
}
