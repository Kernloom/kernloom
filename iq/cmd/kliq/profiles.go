// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"strings"
	"time"
)

/* ---------------- Profiles ---------------- */

type profile struct {
	Name string

	TrigPPS  float64
	TrigSyn  float64
	TrigScan float64

	WPPS   float64
	WSyn   float64
	WScan  float64
	SevCap float64

	SoftAt  int
	HardAt  int
	BlockAt int

	SoftRate  uint64
	SoftBurst uint64
	SoftTTL   time.Duration

	HardRate  uint64
	HardBurst uint64
	HardTTL   time.Duration

	BlockTTL time.Duration
	Cooldown time.Duration

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
	// OpenZiti Profiles
	// =========================

	case "ziti-router":
		// High throughput / many data packets, NAT-friendly. Block only if sustained.
		return profile{
			Name:    "ziti-router",
			TrigPPS: 8000, TrigSyn: 200, TrigScan: 30,
			WPPS: 0.60, WSyn: 0.25, WScan: 0.15, SevCap: 3.0,
			SoftAt: 2, HardAt: 5, BlockAt: 12,
			SoftRate: 3000, SoftBurst: 6000, SoftTTL: 30 * time.Second,
			HardRate: 800, HardBurst: 1600, HardTTL: 2 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 8 * time.Second,
			BlockMinSev: 3.0, BlockMinDur: 60 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 20, NonCompDrop: 20, NonCompSev: 2.5, NonCompReset: 0.30,
		}

	case "ziti-controller":
		// Public enrolment/API surface. More SYN-sensitive, cautious blocking.
		return profile{
			Name:    "ziti-controller",
			TrigPPS: 80, TrigSyn: 20, TrigScan: 5,
			WPPS: 0.35, WSyn: 0.40, WScan: 0.25, SevCap: 3.0,
			SoftAt: 1, HardAt: 3, BlockAt: 9,
			SoftRate: 20, SoftBurst: 40, SoftTTL: 60 * time.Second,
			HardRate: 5, HardBurst: 10, HardTTL: 10 * time.Minute,
			BlockTTL: 30 * time.Minute, Cooldown: 5 * time.Second,
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
			Name:    "ziti-router-bootstrap",
			TrigPPS: 25000, TrigSyn: 600, TrigScan: 120,
			WPPS: 0.60, WSyn: 0.25, WScan: 0.15, SevCap: 3.0,
			SoftAt: 3, HardAt: 8, BlockAt: 999, // avoid blocking during bootstrap
			SoftRate: 6000, SoftBurst: 12000, SoftTTL: 45 * time.Second,
			HardRate: 1500, HardBurst: 3000, HardTTL: 3 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 10 * time.Second,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 10, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 40, NonCompDrop: 50, NonCompSev: 2.5, NonCompReset: 0.30,
		}

	case "ziti-controller-bootstrap":
		// Start tolerant to avoid FPs during onboarding. Rate-limit earlier, block disabled by default.
		return profile{
			Name:    "ziti-controller-bootstrap",
			TrigPPS: 400, TrigSyn: 120, TrigScan: 30,
			WPPS: 0.35, WSyn: 0.45, WScan: 0.20, SevCap: 3.0,
			SoftAt: 2, HardAt: 6, BlockAt: 999,
			SoftRate: 60, SoftBurst: 120, SoftTTL: 90 * time.Second,
			HardRate: 20, HardBurst: 40, HardTTL: 10 * time.Minute,
			BlockTTL: 30 * time.Minute, Cooldown: 8 * time.Second,
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
			Name:    "public-web",
			TrigPPS: 1200, TrigSyn: 250, TrigScan: 20,
			WPPS: 0.55, WSyn: 0.30, WScan: 0.15, SevCap: 3.0,
			SoftAt: 2, HardAt: 5, BlockAt: 12,
			SoftRate: 500, SoftBurst: 1500, SoftTTL: 60 * time.Second,
			HardRate: 120, HardBurst: 300, HardTTL: 10 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 10 * time.Second,
			BlockMinSev: 2.8, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 15, NonCompDrop: 10, NonCompSev: 2.0, NonCompReset: 0.30,
		}

	case "public-api":
		// Public JSON/API endpoint: bursty, higher PPS.
		return profile{
			Name:    "public-api",
			TrigPPS: 2500, TrigSyn: 500, TrigScan: 30,
			WPPS: 0.55, WSyn: 0.30, WScan: 0.15, SevCap: 3.0,
			SoftAt: 2, HardAt: 4, BlockAt: 10,
			SoftRate: 1000, SoftBurst: 2500, SoftTTL: 60 * time.Second,
			HardRate: 300, HardBurst: 600, HardTTL: 10 * time.Minute,
			BlockTTL: 15 * time.Minute, Cooldown: 10 * time.Second,
			BlockMinSev: 2.8, BlockMinDur: 25 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 12, NonCompDrop: 15, NonCompSev: 2.0, NonCompReset: 0.30,
		}

	case "idp":
		// Identity Provider / Auth endpoints: SYN-sensitive, protect against auth abuse. NAT-friendly gating.
		return profile{
			Name:    "idp",
			TrigPPS: 350, TrigSyn: 180, TrigScan: 10,
			WPPS: 0.30, WSyn: 0.55, WScan: 0.15, SevCap: 3.0,
			SoftAt: 1, HardAt: 3, BlockAt: 8,
			SoftRate: 50, SoftBurst: 100, SoftTTL: 2 * time.Minute,
			HardRate: 10, HardBurst: 20, HardTTL: 15 * time.Minute,
			BlockTTL: 30 * time.Minute, Cooldown: 8 * time.Second,
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
			Name:    "internal-app",
			TrigPPS: 800, TrigSyn: 150, TrigScan: 8,
			WPPS: 0.25, WSyn: 0.20, WScan: 0.55, SevCap: 3.0,
			SoftAt: 3, HardAt: 6, BlockAt: 999,
			SoftRate: 200, SoftBurst: 400, SoftTTL: 3 * time.Minute,
			HardRate: 50, HardBurst: 100, HardTTL: 15 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 15 * time.Second,
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
			Name:    "nas",
			TrigPPS: 1500, TrigSyn: 30, TrigScan: 8,
			WPPS: 0.30, WSyn: 0.35, WScan: 0.35, SevCap: 3.0,
			SoftAt: 2, HardAt: 5, BlockAt: 14,
			SoftRate: 600, SoftBurst: 1500, SoftTTL: 2 * time.Minute,
			HardRate: 150, HardBurst: 300, HardTTL: 15 * time.Minute,
			BlockTTL: 24 * time.Hour, Cooldown: 30 * time.Second,
			BlockMinSev: 2.5, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 60 * time.Second, MinHoldHard: 5 * time.Minute,
			NonCompAt: 10, NonCompDrop: 2.0, NonCompSev: 1.8, NonCompReset: 0.30,
		}

	case "nas-bootstrap":
		// NAS initial learning phase: tolerant to avoid blocking legitimate clients before
		// the graph is learned. Blocking disabled; rate-limiting only.
		return profile{
			Name:    "nas-bootstrap",
			TrigPPS: 4000, TrigSyn: 100, TrigScan: 30,
			WPPS: 0.30, WSyn: 0.40, WScan: 0.30, SevCap: 3.0,
			SoftAt: 3, HardAt: 7, BlockAt: 999,
			SoftRate: 1500, SoftBurst: 4000, SoftTTL: 3 * time.Minute,
			HardRate: 400, HardBurst: 800, HardTTL: 20 * time.Minute,
			BlockTTL: 24 * time.Hour, Cooldown: 30 * time.Second,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 10, MinHoldSoft: 2 * time.Minute, MinHoldHard: 10 * time.Minute,
			NonCompAt: 999, NonCompDrop: 999, NonCompSev: 999, NonCompReset: 0.30,
		}

	case "ssh-bastion":
		// Protect SSH/bastion: low normal PPS, suspicious SYN/scan. Blocking ok but gated.
		return profile{
			Name:    "ssh-bastion",
			TrigPPS: 60, TrigSyn: 25, TrigScan: 5,
			WPPS: 0.30, WSyn: 0.55, WScan: 0.15, SevCap: 3.0,
			SoftAt: 1, HardAt: 2, BlockAt: 6,
			SoftRate: 5, SoftBurst: 10, SoftTTL: 5 * time.Minute,
			HardRate: 1, HardBurst: 3, HardTTL: 30 * time.Minute,
			BlockTTL: 60 * time.Minute, Cooldown: 20 * time.Second,
			BlockMinSev: 2.0, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 10, MinHoldSoft: 60 * time.Second, MinHoldHard: 5 * time.Minute,
			NonCompAt: 6, NonCompDrop: 0.5, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	default:
		return profileByName("ziti-controller")
	}
}
