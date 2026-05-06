// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package shieldclient provides Go types and helpers for accessing
// the pinned eBPF maps exposed by Kernloom Shield.
//
// All struct layouts MUST match the corresponding C types in the Shield BPF
// program exactly (same field order, same sizes, same padding).  Do not
// reorder or remove fields without also updating the Shield C source.
package shieldclient

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

var logger = log.New(os.Stderr, "[shield-client] ", log.LstdFlags)

// Map pin paths (relative to bpffs root, default /sys/fs/bpf).
const (
	MapPinSrc4      = "kernloom_src4_stats"
	MapPinSrc6      = "kernloom_src6_stats"
	MapPinFlow4     = "kernloom_flow4_stats"
	MapPinTotals    = "kernloom_totals"
	MapPinDeny4     = "kernloom_deny4_hash"
	MapPinDeny6     = "kernloom_deny6_hash"
	MapPinRLPolicy4 = "kernloom_rl_policy4"
	MapPinRLPolicy6 = "kernloom_rl_policy6"
)

/* ---------------- eBPF struct types (MUST match Shield C layouts) --------- */

// SrcStatsV4 matches xdp_src_stats_v4_t in the Shield BPF program.
// Fields and padding are identical to the C layout; do not change order.
type SrcStatsV4 struct {
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

// SrcStatsV6 matches xdp_src_stats_v6_t in the Shield BPF program.
type SrcStatsV6 struct {
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

// Totals matches xdp_totals_t in the Shield BPF program.
type Totals struct {
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

// RLConfig is the rate-limit policy value stored in kernloom_rl_policy4/6.
type RLConfig struct {
	RatePPS uint64
	Burst   uint64
}

// Flow4Key matches flow4_key in the Shield BPF program.
// DstPort is in host byte order (converted by bpf_ntohs in XDP).
// SrcIP is in network byte order (as loaded from the packet).
type Flow4Key struct {
	SrcIP   [4]byte
	DstPort uint16
	Proto   uint8
	Pad     uint8
}

// Flow4Stats matches flow4_stats in the Shield BPF program.
// Values are totals since the last map clear by KLIQ (Option B pattern).
type Flow4Stats struct {
	Pkts  uint64
	Bytes uint64
	Syn   uint64
}

// Src6Key is the map key for kernloom_rl_policy6.
type Src6Key struct{ IP [16]byte }

// Key6Bytes is the map key for kernloom_deny6_hash.
type Key6Bytes struct{ IP [16]byte }

/* ---------------- Maps struct --------------------------------------------- */

// Maps holds handles to all Shield pinned eBPF maps.
// Optional maps (Src6, Flow4, Totals, Deny6, RL6) may be nil when not available.
type Maps struct {
	Src4   *ebpf.Map // mandatory telemetry map (IPv4)
	Src6   *ebpf.Map // optional telemetry map (IPv6)
	Flow4  *ebpf.Map // optional per-flow telemetry map (Option B, LRU_HASH)
	Deny4  *ebpf.Map // mandatory enforcement map (IPv4 deny) when !dryRun
	RL4    *ebpf.Map // mandatory enforcement map (IPv4 rate-limit) when !dryRun
	Deny6  *ebpf.Map // optional enforcement map (IPv6 deny)
	RL6    *ebpf.Map // optional enforcement map (IPv6 rate-limit)
	Totals *ebpf.Map // optional totals/per-cpu array
}

// Close closes all non-nil map handles.
func (m *Maps) Close() {
	for _, mp := range []*ebpf.Map{m.Src4, m.Src6, m.Flow4, m.Deny4, m.RL4, m.Deny6, m.RL6, m.Totals} {
		if mp != nil {
			mp.Close()
		}
	}
}

// Open opens the Shield pinned maps from root (e.g. "/sys/fs/bpf").
// When dryRun is true the enforcement maps (Deny*, RL*) are not opened.
func Open(root string, dryRun bool) (*Maps, error) {
	m := &Maps{}

	src4, err := OpenPinnedMap(filepath.Join(root, MapPinSrc4))
	if err != nil {
		return nil, fmt.Errorf("open src4 map: %w", err)
	}
	m.Src4 = src4

	if m6, err := OpenPinnedMap(filepath.Join(root, MapPinSrc6)); err == nil {
		m.Src6 = m6
	} else {
		logger.Printf("IPv6 telemetry map not available (optional): %v", err)
	}

	if f4, err := OpenPinnedMap(filepath.Join(root, MapPinFlow4)); err == nil {
		m.Flow4 = f4
	} else {
		logger.Printf("flow4 map not available (optional): %v", err)
	}

	if tm, err := OpenPinnedMap(filepath.Join(root, MapPinTotals)); err == nil {
		m.Totals = tm
	} else {
		logger.Printf("totals map not available (optional): %v", err)
	}

	if dryRun {
		return m, nil
	}

	deny4, err := OpenPinnedMap(filepath.Join(root, MapPinDeny4))
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("open deny4 map: %w", err)
	}
	m.Deny4 = deny4

	rl4, err := OpenPinnedMap(filepath.Join(root, MapPinRLPolicy4))
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("open rl_policy4 map: %w", err)
	}
	m.RL4 = rl4

	if m6, err := OpenPinnedMap(filepath.Join(root, MapPinDeny6)); err == nil {
		m.Deny6 = m6
	} else {
		logger.Printf("IPv6 deny map not available (optional): %v", err)
	}
	if m6, err := OpenPinnedMap(filepath.Join(root, MapPinRLPolicy6)); err == nil {
		m.RL6 = m6
	} else {
		logger.Printf("IPv6 rl policy map not available (optional): %v", err)
	}

	return m, nil
}

// OpenPinnedMap is a thin wrapper around ebpf.LoadPinnedMap.
func OpenPinnedMap(path string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(path, nil)
}

// ReadTotalsSum sums the per-CPU values from the totals map into a single Totals.
func ReadTotalsSum(m *ebpf.Map) (Totals, error) {
	var out Totals
	if m == nil {
		return out, fmt.Errorf("nil totals map")
	}
	var k uint32 = 0
	var perCPU []Totals
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
