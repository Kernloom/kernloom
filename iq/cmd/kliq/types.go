// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"net"
	"time"
)

const (
	// Telemetry
	mapPinSrc4   = "/sys/fs/bpf/kernloom_src4_stats"
	mapPinSrc6   = "/sys/fs/bpf/kernloom_src6_stats"
	mapPinTotals = "/sys/fs/bpf/kernloom_totals"

	// Enforcement
	mapPinDeny4     = "/sys/fs/bpf/kernloom_deny4_hash"
	mapPinDeny6     = "/sys/fs/bpf/kernloom_deny6_hash"
	mapPinRLPolicy4 = "/sys/fs/bpf/kernloom_rl_policy4"
	mapPinRLPolicy6 = "/sys/fs/bpf/kernloom_rl_policy6"
)

/* ---------------- Types (must match Shield C layouts) ---------------- */

// MUST match Shield per-source v4 stats layout + explicit padding.
type xdpSrcStatsV4 struct {
	Pkts  uint64
	Bytes uint64

	Tcp  uint64
	Udp  uint64
	Icmp uint64

	Syn    uint64
	Synack uint64
	Rst    uint64
	Ack    uint64

	Pass      uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64

	FirstSeenNs uint64
	LastSeenNs  uint64

	LastSport uint16
	LastDport uint16
	Pad0      [4]byte

	DportChanges uint64

	LastTTL      uint8
	LastTCPFlags uint8
	Pad1         [2]byte
	Pad2         [4]byte
}

// MUST match Shield per-source v6 stats layout (xdp_src_stats_v6_t).
type xdpSrcStatsV6 struct {
	Pkts  uint64
	Bytes uint64

	Tcp  uint64
	Udp  uint64
	Icmp uint64

	Syn    uint64
	Synack uint64
	Rst    uint64
	Ack    uint64

	Pass      uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64

	FirstSeenNs uint64
	LastSeenNs  uint64

	LastSport uint16
	LastDport uint16
	Pad0      [4]byte

	DportChanges uint64

	LastHLIM     uint8
	LastTCPFlags uint8
	Pad1         [2]byte
	Pad2         [4]byte // tail padding (struct align 8)
}

// Totals: MUST match Shield layout for xdp_totals_t.
type xdpTotals struct {
	Pkts       uint64
	Bytes      uint64
	Pass       uint64
	DropAllow  uint64
	DropDeny   uint64
	DropRL     uint64
	V4         uint64
	V6         uint64
	TCP        uint64
	UDP        uint64
	ICMP       uint64
	SYN        uint64
	SYNACK     uint64
	RST        uint64
	ACK        uint64
	IPv4Frags  uint64
	DportChg   uint64
	NewSources uint64
	AllowHits  uint64
	DenyHits   uint64
	RLHits     uint64
}

// RL policy value for Shield.
type rlCfg struct {
	RatePPS uint64
	Burst   uint64
}

// Keys
type src6Key struct{ IP [16]byte }
type key6Bytes struct{ IP [16]byte }

// ---- FSM levels ----
type Level int

const (
	LObserve Level = iota
	LSoft
	LHard
	LBlock
)

func (l Level) String() string {
	switch l {
	case LObserve:
		return "OBSERVE"
	case LSoft:
		return "RATE_SOFT"
	case LHard:
		return "RATE_HARD"
	case LBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

type ipState struct {
	Level         Level
	Strikes       int
	ExpiresAt     time.Time
	CooldownUntil time.Time
	LastTrigger   time.Time

	HighSevSince     time.Time
	LastSeenWallTime time.Time

	UpStreak   int
	DownStreak int

	NonCompTicks int
}

// ---- prev snapshots for deltas ----
type prevV4 struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

type prevV6 struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

type metrics struct {
	IPVer uint8
	IP4   [4]byte
	IP6   [16]byte

	PPS        float64
	Bps        float64
	SynRate    float64
	ScanRate   float64
	DropRLRate float64
	Severity   float64
}

func (m metrics) ipString() string {
	if m.IPVer == 6 {
		return net.IP(m.IP6[:]).String()
	}
	return net.IPv4(m.IP4[0], m.IP4[1], m.IP4[2], m.IP4[3]).String()
}
