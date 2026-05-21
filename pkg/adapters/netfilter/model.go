// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// NetfilterPlan is the desired enforcement state for one adapter tick.
// Backends render this into backend-specific rule syntax.
type NetfilterPlan struct {
	TableName string      // nftables: "kernloom"; iptables: "filter"
	Chains    []ChainPlan // chains owned by Kernloom
	Sets      []SetPlan   // ipsets / nft sets
	Rules     []RulePlan  // ordered enforcement rules
}

// ChainPlan describes a Kernloom-owned chain.
type ChainPlan struct {
	Name     string // e.g. "KERNLOOM_INPUT"
	Hook     string // "input" | "forward" | "output"
	Priority int    // nftables priority; 0 = filter
	Policy   string // always "accept" — Kernloom never changes host default
}

// SetPlan describes an ipset or nftables set for bulk IP operations.
type SetPlan struct {
	Name     string       // e.g. "kernloom_deny4"
	Family   string       // "ipv4" | "ipv6"
	KeyType  string       // "ip" (ipset) | "ipv4_addr" (nft)
	Timeout  bool         // supports per-entry TTL
	Counters bool         // tracks hit counts per entry
	Elements []SetElement // initial/desired elements
}

// SetElement is one entry in a set, optionally with a TTL.
type SetElement struct {
	Value  string        // IP address or CIDR
	TTL    time.Duration // 0 = no expiry
	RuleID string        // trace back to the decision that added it
}

// RateLimitParams carries rate/burst for VerdictRateLimit rules.
type RateLimitParams struct {
	RatePPS uint64        // packets per second limit
	Burst   uint64        // burst size (0 = 2× RatePPS)
	TTL     time.Duration // timeout for hashlimit/meter entry (0 = no expiry)
	Name    string        // unique name for hashlimit table / nft meter (auto-derived from RuleID when empty)
}

// Burst returns the effective burst (2× rate when zero).
func (r RateLimitParams) EffectiveBurst() uint64 {
	if r.Burst > 0 {
		return r.Burst
	}
	return r.RatePPS * 2
}

// RulePlan is one enforcement rule.
type RulePlan struct {
	ID          string           // stable hash; see RuleID()
	Chain       string           // target chain, e.g. "KERNLOOM_INPUT"
	Selector    Selector         // match criteria
	Verdict     Verdict          // what to do when the selector matches
	RateLimit   *RateLimitParams // set when Verdict == VerdictRateLimit
	Counter     bool             // include packet/byte counter
	Comment     string           // appended to kernloom owner comment
	Constraints map[string]any   // reserved for future use
	Priority    int              // lower = evaluated first within chain
}

// Selector describes the L3/L4 match criteria for a rule.
// Zero values mean "match any" for that field.
type Selector struct {
	SrcIP     string  // e.g. "192.0.2.10"
	SrcCIDR   string  // e.g. "192.0.2.0/24"
	DstIP     string  // e.g. "10.0.0.1"
	DstCIDR   string  // e.g. "10.0.0.0/8"
	Proto     string  // "tcp" | "udp" | "icmp" | "" (any)
	SrcPort   *uint16 // source port; nil = any
	DstPort   *uint16 // destination port; nil = any
	Direction string  // "input" | "forward" | "output"
	Interface string  // interface name; "" = any
	SetName   string  // match against a set (deny/allow list)
	SetDir    string  // "src" | "dst" — which address to match in set
}

// Verdict is the action taken when a rule matches.
type Verdict string

const (
	VerdictDrop      Verdict = "DROP"
	VerdictAccept    Verdict = "ACCEPT"
	VerdictReturn    Verdict = "RETURN" // exit Kernloom chain, continue host rules
	VerdictLog       Verdict = "LOG"
	VerdictRateLimit Verdict = "RATE_LIMIT" // rendered as hashlimit (iptables) or meter (nftables)
)

// RuleID computes a stable, opaque ID for a rule from its semantic content.
// The same selector+verdict+constraints always produces the same ID, which
// allows idempotent apply (detect if a rule is already installed).
func RuleID(adapterID, capability string, sel Selector, verdict Verdict, constraints map[string]any) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%v|%s|%v", adapterID, capability, sel, verdict, constraints)
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

// OwnerComment returns the standard Kernloom rule comment for the given ID.
// This comment is used by the parser to identify Kernloom-owned rules.
func OwnerComment(prefix, ruleID, action string) string {
	return fmt.Sprintf("%s action=%s id=%s", prefix, action, ruleID)
}

// EnforcementAction is an abstract enforcement request from KLIQ or Forge.
// The backend translates this into a RulePlan.
type EnforcementAction struct {
	ID         string        // stable decision ID from the policy engine
	Capability string        // e.g. "enforce.network.deny"
	Selector   Selector      // what to match
	Verdict    Verdict       // what to do
	TTL        time.Duration // 0 = permanent
	Reason     string        // human-readable; stored in comment
	Severity   float64       // 0–1; carried through for logging
	DryRun     bool          // if true, plan but do not apply
}
