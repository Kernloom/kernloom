// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package nftables implements the nftables backend for the netfilter adapter.
// It renders a NetfilterPlan into an nft(8) compatible ruleset and applies
// it atomically via "nft -f". The backend owns exactly one table:
// "table inet kernloom" — it never touches other tables.
package nftables

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

const defaultTableName = "kernloom"

// RenderOptions controls nftables rendering behaviour.
type RenderOptions struct {
	// TableName is the nftables table name. Default: "kernloom".
	TableName string
	// CommentPrefix is prepended to all rule comments.
	CommentPrefix string
	// ChainPrefix is unused for nftables (chains live inside the table),
	// but kept for symmetry with the iptables backend.
	ChainPrefix string
}

// DefaultRenderOptions returns the standard nftables rendering options.
func DefaultRenderOptions() RenderOptions {
	return RenderOptions{
		TableName:     defaultTableName,
		CommentPrefix: "kernloom",
		ChainPrefix:   "kernloom",
	}
}

// RenderTable converts a NetfilterPlan into a complete "table inet kernloom"
// nft ruleset string suitable for "nft -f".
//
// The output atomically replaces the Kernloom table on apply — other tables
// (ip filter, ip6 filter, etc.) are never touched.
//
// Format:
//
//	table inet kernloom {
//	  set deny4 { type ipv4_addr; flags timeout; counter; }
//	  chain input {
//	    type filter hook input priority filter - 10; policy accept;
//	    <rules>
//	  }
//	}
func RenderTable(plan netfilter.NetfilterPlan, opts RenderOptions) string {
	table := opts.TableName
	if table == "" {
		table = defaultTableName
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("table inet %s {\n", table))

	// Sets — must come before chains so chain rules can reference them.
	for _, set := range plan.Sets {
		renderSet(&sb, set)
	}

	// Sort chains by hook priority for deterministic output.
	chains := make([]netfilter.ChainPlan, len(plan.Chains))
	copy(chains, plan.Chains)
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Priority != chains[j].Priority {
			return chains[i].Priority < chains[j].Priority
		}
		return chains[i].Hook < chains[j].Hook
	})

	// Sort rules by priority then ID for stable deterministic output.
	rules := make([]netfilter.RulePlan, len(plan.Rules))
	copy(rules, plan.Rules)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})

	for _, chain := range chains {
		renderChain(&sb, chain, rules, opts)
	}

	sb.WriteString("}\n")
	return sb.String()
}

// RenderDeleteTable returns the nft command to remove the Kernloom table.
// Used by Cleanup to remove all Kernloom-owned objects atomically.
func RenderDeleteTable(opts RenderOptions) string {
	table := opts.TableName
	if table == "" {
		table = defaultTableName
	}
	return fmt.Sprintf("delete table inet %s\n", table)
}

// RenderAddElements returns nft commands to add elements to an existing set.
// Called when new dynamic entries (deny/allow TTLs) arrive between full applies.
func RenderAddElements(tableName, setName string, elements []netfilter.SetElement) []string {
	if tableName == "" {
		tableName = defaultTableName
	}
	var cmds []string
	for _, el := range elements {
		if el.TTL > 0 {
			secs := int(el.TTL.Seconds())
			cmds = append(cmds, fmt.Sprintf(
				"add element inet %s %s { %s timeout %ds }",
				tableName, setName, el.Value, secs,
			))
		} else {
			cmds = append(cmds, fmt.Sprintf(
				"add element inet %s %s { %s }",
				tableName, setName, el.Value,
			))
		}
	}
	return cmds
}

/* ── internal renderers ─────────────────────────────────────────────────── */

func renderSet(sb *strings.Builder, set netfilter.SetPlan) {
	sb.WriteString(fmt.Sprintf("\tset %s {\n", set.Name))

	keyType := set.KeyType
	if keyType == "" {
		if set.Family == "ipv6" {
			keyType = "ipv6_addr"
		} else {
			keyType = "ipv4_addr"
		}
	}
	sb.WriteString(fmt.Sprintf("\t\ttype %s\n", keyType))

	var flags []string
	if set.Timeout {
		flags = append(flags, "timeout")
	}
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf("\t\tflags %s\n", strings.Join(flags, ", ")))
	}
	if set.Counters {
		sb.WriteString("\t\tcounter\n")
	}

	// Initial elements (if any).
	if len(set.Elements) > 0 {
		sb.WriteString("\t\telements = {\n")
		for _, el := range set.Elements {
			if el.TTL > 0 {
				secs := int(el.TTL.Seconds())
				sb.WriteString(fmt.Sprintf("\t\t\t%s timeout %ds,\n", el.Value, secs))
			} else {
				sb.WriteString(fmt.Sprintf("\t\t\t%s,\n", el.Value))
			}
		}
		sb.WriteString("\t\t}\n")
	}

	sb.WriteString("\t}\n\n")
}

func renderChain(sb *strings.Builder, chain netfilter.ChainPlan, rules []netfilter.RulePlan, opts RenderOptions) {
	sb.WriteString(fmt.Sprintf("\tchain %s {\n", chain.Hook))

	// Chain type declaration — always filter, priority just below host rules.
	priority := "filter - 10"
	if chain.Priority != 0 {
		priority = fmt.Sprintf("filter + %d", chain.Priority)
	}
	sb.WriteString(fmt.Sprintf(
		"\t\ttype filter hook %s priority %s; policy accept;\n",
		chain.Hook, priority,
	))

	// Rules that belong to this chain (matched by Hook/Direction).
	for _, rule := range rules {
		if !ruleInChain(rule, chain) {
			continue
		}
		line := renderRule(rule, opts)
		if line != "" {
			sb.WriteString("\t\t" + line + "\n")
		}
	}

	sb.WriteString("\t}\n\n")
}

// ruleInChain checks whether a RulePlan belongs in a given ChainPlan.
// A rule belongs in a chain when its Direction matches the chain's Hook,
// or when Direction is empty (applies to all chains with matching hook).
func ruleInChain(rule netfilter.RulePlan, chain netfilter.ChainPlan) bool {
	if rule.Selector.Direction == "" {
		return true
	}
	return strings.EqualFold(rule.Selector.Direction, chain.Hook)
}

// renderRule converts a RulePlan into a single nftables rule statement.
func renderRule(rule netfilter.RulePlan, opts RenderOptions) string {
	var parts []string
	sel := rule.Selector

	// Interface match.
	if sel.Interface != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", sel.Interface))
	}

	// Source address — prefer set match over individual CIDR/IP.
	switch {
	case sel.SetName != "" && sel.SetDir == "src":
		family := "ip"
		if strings.Contains(sel.SetName, "6") {
			family = "ip6"
		}
		parts = append(parts, fmt.Sprintf("%s saddr @%s", family, sel.SetName))
	case sel.SrcCIDR != "":
		family := ipFamily(sel.SrcCIDR)
		parts = append(parts, fmt.Sprintf("%s saddr %s", family, sel.SrcCIDR))
	case sel.SrcIP != "":
		family := ipFamily(sel.SrcIP)
		parts = append(parts, fmt.Sprintf("%s saddr %s", family, sel.SrcIP))
	}

	// Destination address.
	switch {
	case sel.SetName != "" && sel.SetDir == "dst":
		family := "ip"
		if strings.Contains(sel.SetName, "6") {
			family = "ip6"
		}
		parts = append(parts, fmt.Sprintf("%s daddr @%s", family, sel.SetName))
	case sel.DstCIDR != "":
		family := ipFamily(sel.DstCIDR)
		parts = append(parts, fmt.Sprintf("%s daddr %s", family, sel.DstCIDR))
	case sel.DstIP != "":
		family := ipFamily(sel.DstIP)
		parts = append(parts, fmt.Sprintf("%s daddr %s", family, sel.DstIP))
	}

	// Protocol.
	if sel.Proto != "" {
		parts = append(parts, sel.Proto)
	}

	// Source port.
	if sel.SrcPort != nil {
		parts = append(parts, fmt.Sprintf("sport %d", *sel.SrcPort))
	}

	// Destination port.
	if sel.DstPort != nil {
		parts = append(parts, fmt.Sprintf("dport %d", *sel.DstPort))
	}

	// Counter (always include for observability).
	parts = append(parts, "counter")

	// Comment for rule identification.
	comment := buildComment(opts.CommentPrefix, rule)
	parts = append(parts, fmt.Sprintf("comment %q", comment))

	// Verdict.
	parts = append(parts, strings.ToLower(string(rule.Verdict)))

	return strings.Join(parts, " ")
}

// buildComment constructs "kernloom action=<x> id=<id> [extra]"
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
	default:
		return strings.ToLower(string(v))
	}
}

// ipFamily returns "ip" or "ip6" based on whether the address contains ":".
func ipFamily(addr string) string {
	if strings.Contains(addr, ":") {
		return "ip6"
	}
	return "ip"
}
