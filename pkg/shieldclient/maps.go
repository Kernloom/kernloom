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
	"net"
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

	// Tuple (edge) enforcement maps — Sprint 8 / XDP tuple map integration.
	MapPinEdge4Deny = "kernloom_edge4_deny"
	MapPinEdge4RL   = "kernloom_edge4_rl_policy"
	MapPinEdge4Cfg  = "kernloom_edge4_cfg"
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

// Edge4Key matches struct edge4_key in the Shield BPF program.
// It identifies an ingress flow by (src_ip, dst_port, proto).
//
// SrcIP:   4-byte network-byte-order IPv4 address (as loaded from packet).
// DstPort: destination port in HOST byte order (0 for ICMP).
// Proto:   IP protocol number (IPPROTO_TCP=6, UDP=17, ICMP=1).
// Pad:     must be zero — BPF verifier requires consistent key bytes.
type Edge4Key struct {
	SrcIP   [4]byte
	DstPort uint16
	Proto   uint8
	Pad     uint8
}

// ProtoTCP, ProtoUDP, ProtoICMP are convenience constants for Edge4Key.Proto.
const (
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
	ProtoICMP uint8 = 1
)

// NewEdge4Key builds an Edge4Key from a parsed IPv4 address string, port and
// proto string ("tcp", "udp", "icmp"). Returns false when the IP cannot be
// parsed as IPv4.
func NewEdge4Key(srcIP string, dstPort uint16, proto string) (Edge4Key, bool) {
	ip := parseIPv4(srcIP)
	if ip == nil {
		return Edge4Key{}, false
	}
	var p uint8
	switch proto {
	case "tcp":
		p = ProtoTCP
	case "udp":
		p = ProtoUDP
	case "icmp":
		p = ProtoICMP
	default:
		return Edge4Key{}, false
	}
	var k Edge4Key
	copy(k.SrcIP[:], ip)
	k.DstPort = dstPort
	k.Proto = p
	return k, true
}

func parseIPv4(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

/* ---------------- Maps struct --------------------------------------------- */

// Maps holds handles to all Shield pinned eBPF maps.
// Optional maps (Src6, Flow4, Totals, Deny6, RL6, Edge4*) may be nil when not available.
type Maps struct {
	Src4   *ebpf.Map // mandatory telemetry map (IPv4)
	Src6   *ebpf.Map // optional telemetry map (IPv6)
	Flow4  *ebpf.Map // optional per-flow telemetry map (LRU_HASH)
	Deny4  *ebpf.Map // mandatory enforcement map (IPv4 deny) when !dryRun
	RL4    *ebpf.Map // mandatory enforcement map (IPv4 rate-limit) when !dryRun
	Deny6  *ebpf.Map // optional enforcement map (IPv6 deny)
	RL6    *ebpf.Map // optional enforcement map (IPv6 rate-limit)
	Totals *ebpf.Map // optional totals/per-cpu array

	// Tuple (edge) enforcement maps — nil when TupleEnforcement feature is disabled
	// or when the Shield BPF version does not yet have these maps loaded.
	Edge4Deny *ebpf.Map // edge4_deny LRU hash: Edge4Key → u8
	Edge4RL   *ebpf.Map // edge4_rl_policy hash: Edge4Key → RLConfig
	Edge4Cfg  *ebpf.Map // edge4_cfg array: index 0 → {enforce u32, _pad u32}
}

// Close closes all non-nil map handles.
func (m *Maps) Close() {
	for _, mp := range []*ebpf.Map{
		m.Src4, m.Src6, m.Flow4,
		m.Deny4, m.RL4, m.Deny6, m.RL6,
		m.Totals,
		m.Edge4Deny, m.Edge4RL, m.Edge4Cfg,
	} {
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

	// Tuple (edge) enforcement maps — optional; only present when Shield has been
	// built with XDP tuple support and the program reloaded.
	if em, err := OpenPinnedMap(filepath.Join(root, MapPinEdge4Deny)); err == nil {
		m.Edge4Deny = em
	} else {
		logger.Printf("edge4_deny map not available (tuple enforcement disabled): %v", err)
	}
	if em, err := OpenPinnedMap(filepath.Join(root, MapPinEdge4RL)); err == nil {
		m.Edge4RL = em
	} else {
		logger.Printf("edge4_rl_policy map not available (tuple enforcement disabled): %v", err)
	}
	if em, err := OpenPinnedMap(filepath.Join(root, MapPinEdge4Cfg)); err == nil {
		m.Edge4Cfg = em
	}

	return m, nil
}

/* ---------------- Edge enforcement helpers -------------------------------- */

// WriteEdge4Deny inserts or overwrites an edge4_deny entry.
// After this call every packet matching (srcIP, dstPort, proto) is dropped
// in XDP before reaching userspace — regardless of source-level RL/allow.
func (m *Maps) WriteEdge4Deny(key Edge4Key) error {
	if m.Edge4Deny == nil {
		return fmt.Errorf("edge4_deny map not available (reload Shield with tuple support)")
	}
	v := uint8(1)
	return m.Edge4Deny.Update(&key, &v, ebpf.UpdateAny)
}

// DeleteEdge4Deny removes an edge deny entry. No-op if the key is not present.
func (m *Maps) DeleteEdge4Deny(key Edge4Key) error {
	if m.Edge4Deny == nil {
		return fmt.Errorf("edge4_deny map not available")
	}
	err := m.Edge4Deny.Delete(&key)
	if err != nil && err.Error() == "key does not exist" {
		return nil
	}
	return err
}

// WriteEdge4RL sets a per-edge token-bucket rate limit.
// The XDP token bucket kicks in immediately for matching flows.
func (m *Maps) WriteEdge4RL(key Edge4Key, ratePPS, burst uint64) error {
	if m.Edge4RL == nil {
		return fmt.Errorf("edge4_rl_policy map not available")
	}
	cfg := RLConfig{RatePPS: ratePPS, Burst: burst}
	return m.Edge4RL.Update(&key, &cfg, ebpf.UpdateAny)
}

// DeleteEdge4RL removes a per-edge rate-limit entry.
func (m *Maps) DeleteEdge4RL(key Edge4Key) error {
	if m.Edge4RL == nil {
		return fmt.Errorf("edge4_rl_policy map not available")
	}
	err := m.Edge4RL.Delete(&key)
	if err != nil && err.Error() == "key does not exist" {
		return nil
	}
	return err
}

// edge4CfgValue is the value stored in the edge4_cfg ARRAY map.
type edge4CfgValue struct {
	Enforce uint32
	Pad     uint32
}

// SetTupleEnforce enables (true) or disables (false) XDP tuple enforcement.
// When disabled the edge deny/rl maps are present but not consulted in the
// packet path — useful for loading entries before activating enforcement.
func (m *Maps) SetTupleEnforce(on bool) error {
	if m.Edge4Cfg == nil {
		return fmt.Errorf("edge4_cfg map not available (reload Shield with tuple support)")
	}
	var k uint32 = 0
	v := edge4CfgValue{}
	if on {
		v.Enforce = 1
	}
	return m.Edge4Cfg.Update(&k, &v, ebpf.UpdateAny)
}

// TupleEnforceActive returns true when XDP tuple enforcement is currently active.
func (m *Maps) TupleEnforceActive() bool {
	if m.Edge4Cfg == nil {
		return false
	}
	var k uint32 = 0
	var v edge4CfgValue
	if err := m.Edge4Cfg.Lookup(&k, &v); err != nil {
		return false
	}
	return v.Enforce != 0
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
