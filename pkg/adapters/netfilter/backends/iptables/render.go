// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package iptables implements the iptables backend for the netfilter adapter.
// It renders a NetfilterPlan into iptables-restore(8) format and applies it
// atomically. The backend only ever writes to KERNLOOM_* chains — it never
// flushes the filter table or modifies non-Kernloom rules.
package iptables

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

const (
	defaultCommentPrefix = "kernloom"
	filterTable          = "*filter"
	commitMarker         = "COMMIT"
)

// RenderOptions controls how the plan is rendered.
type RenderOptions struct {
	// CommentPrefix is prepended to every rule comment.
	CommentPrefix string
	// ChainPrefix is prepended to every Kernloom chain name.
	ChainPrefix string
	// IPv6 renders ip6tables rules instead of iptables rules.
	IPv6 bool
}

// DefaultRenderOptions returns the standard rendering options.
func DefaultRenderOptions() RenderOptions {
	return RenderOptions{
		CommentPrefix: defaultCommentPrefix,
		ChainPrefix:   "KERNLOOM",
	}
}

// Render converts a NetfilterPlan into an iptables-restore compatible string.
//
// The output is a self-contained iptables-restore script that:
//   - Declares KERNLOOM_* chains
//   - Inserts jump rules from INPUT/FORWARD/OUTPUT into KERNLOOM_* chains
//   - Flushes only KERNLOOM_* chains (never the host filter table)
//   - Appends enforcement rules into the correct KERNLOOM_* chain
//
// The caller writes this string to iptables-restore stdin or a temp file.
func Render(plan netfilter.NetfilterPlan, opts RenderOptions) string {
	var sb strings.Builder

	sb.WriteString(filterTable + "\n")

	// Declare all KERNLOOM chains (no default policy — managed by host).
	for _, chain := range plan.Chains {
		sb.WriteString(fmt.Sprintf(":%s - [0:0]\n", chain.Name))
	}

	// Flush only KERNLOOM chains so host rules in INPUT/FORWARD/OUTPUT survive.
	for _, chain := range plan.Chains {
		sb.WriteString(fmt.Sprintf("-F %s\n", chain.Name))
	}

	// Insert jump rules at the top of the parent hook chains (idempotent via -C check
	// at apply time — render always outputs them; apply skips if already present).
	for _, chain := range plan.Chains {
		hook := hookChain(chain.Hook)
		sb.WriteString(fmt.Sprintf("-I %s 1 -j %s\n", hook, chain.Name))
	}

	// Management allowlist rules go first (never block management CIDRs).
	// Written as RETURN rules at the top of each KERNLOOM chain.
	// (Populated by the Apply layer from SafetyConfig.ManagementAllowlist.)

	// Sort rules by priority (lower = first), then by ID for stability.
	rules := make([]netfilter.RulePlan, len(plan.Rules))
	copy(rules, plan.Rules)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})

	for _, rule := range rules {
		line := renderRule(rule, opts)
		if line != "" {
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteString(commitMarker + "\n")
	return sb.String()
}

// RenderSetOps renders the ipset commands needed to apply a SetPlan.
// These are separate from the iptables-restore script and must be executed
// before applying the filter rules.
func RenderSetOps(sets []netfilter.SetPlan) []string {
	var cmds []string
	for _, set := range sets {
		family := "hash:ip"
		opts := []string{"-exist"}
		if set.Timeout {
			opts = append(opts, "timeout 0")
		}
		if set.Counters {
			opts = append(opts, "counters")
		}
		cmds = append(cmds, fmt.Sprintf("ipset create %s %s %s",
			set.Name, family, strings.Join(opts, " ")))

		for _, el := range set.Elements {
			addOpts := "-exist"
			if el.TTL > 0 {
				addOpts += fmt.Sprintf(" timeout %d", int(el.TTL.Seconds()))
			}
			cmds = append(cmds, fmt.Sprintf("ipset add %s %s %s",
				set.Name, el.Value, addOpts))
		}
	}
	return cmds
}

// renderRule converts a single RulePlan into an iptables -A line.
// Returns empty string for rules that cannot be expressed in iptables syntax.
func renderRule(rule netfilter.RulePlan, opts RenderOptions) string {
	var parts []string
	parts = append(parts, "-A", rule.Chain)

	sel := rule.Selector

	// Interface match.
	if sel.Interface != "" {
		parts = append(parts, "-i", sel.Interface)
	}

	// Protocol — must come before port matches.
	if sel.Proto != "" {
		parts = append(parts, "-p", sel.Proto)
	}

	// Source address (prefer CIDR over single IP).
	switch {
	case sel.SetName != "" && sel.SetDir == "src":
		parts = append(parts, "-m", "set", "--match-set", sel.SetName, "src")
	case sel.SrcCIDR != "":
		parts = append(parts, "-s", sel.SrcCIDR)
	case sel.SrcIP != "":
		parts = append(parts, "-s", sel.SrcIP)
	}

	// Destination address.
	switch {
	case sel.SetName != "" && sel.SetDir == "dst":
		parts = append(parts, "-m", "set", "--match-set", sel.SetName, "dst")
	case sel.DstCIDR != "":
		parts = append(parts, "-d", sel.DstCIDR)
	case sel.DstIP != "":
		parts = append(parts, "-d", sel.DstIP)
	}

	// Source port (requires -p tcp/udp).
	if sel.SrcPort != nil && sel.Proto != "" {
		parts = append(parts, "--sport", fmt.Sprintf("%d", *sel.SrcPort))
	}

	// Destination port (requires -p tcp/udp).
	if sel.DstPort != nil && sel.Proto != "" {
		parts = append(parts, "--dport", fmt.Sprintf("%d", *sel.DstPort))
	}

	// Comment — always included so parser can identify Kernloom rules.
	comment := buildComment(opts.CommentPrefix, rule)
	parts = append(parts, "-m", "comment", "--comment", fmt.Sprintf("%q", comment))

	// Verdict / rate-limit.
	if rule.Verdict == netfilter.VerdictRateLimit && rule.RateLimit != nil {
		rl := rule.RateLimit
		name := rl.Name
		if name == "" {
			name = "kl_" + rule.ID
		}
		burst := rl.EffectiveBurst()
		parts = append(parts,
			"-m", "hashlimit",
			fmt.Sprintf("--hashlimit-above %d/second", rl.RatePPS),
			fmt.Sprintf("--hashlimit-burst %d", burst),
			"--hashlimit-mode", "srcip",
			fmt.Sprintf("--hashlimit-name %s", name),
			"-j", "DROP",
		)
	} else {
		parts = append(parts, "-j", string(rule.Verdict))
	}

	return strings.Join(parts, " ")
}

// buildComment constructs the rule comment: "kernloom action=<x> id=<id> [reason]"
func buildComment(prefix string, rule netfilter.RulePlan) string {
	action := verdictToAction(rule.Verdict)
	s := fmt.Sprintf("%s action=%s id=%s", prefix, action, rule.ID)
	if rule.Comment != "" {
		s += " " + rule.Comment
	}
	return s
}

func verdictToAction(v netfilter.Verdict) string {
	switch v {
	case netfilter.VerdictDrop:
		return "deny"
	case netfilter.VerdictAccept:
		return "allow"
	case netfilter.VerdictReturn:
		return "allow_return"
	case netfilter.VerdictRateLimit:
		return "rate_limit"
	default:
		return strings.ToLower(string(v))
	}
}

// hookChain maps a direction string to the standard iptables hook chain name.
func hookChain(hook string) string {
	switch strings.ToLower(hook) {
	case "input":
		return "INPUT"
	case "forward":
		return "FORWARD"
	case "output":
		return "OUTPUT"
	default:
		return strings.ToUpper(hook)
	}
}
