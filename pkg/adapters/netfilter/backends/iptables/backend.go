// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package iptables

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

var logger = log.New(os.Stderr, "[netfilter/iptables] ", log.LstdFlags)

// Backend implements the iptables enforcement backend.
type Backend struct {
	probe  netfilter.IPTablesProbe
	cfg    netfilter.Config
	opts   RenderOptions
	dryRun bool
}

// New creates an iptables backend from a completed probe result.
func New(probe netfilter.IPTablesProbe, cfg netfilter.Config) *Backend {
	opts := DefaultRenderOptions()
	opts.ChainPrefix = cfg.Ownership.ChainPrefix
	opts.CommentPrefix = cfg.Ownership.CommentPrefix
	return &Backend{
		probe:  probe,
		cfg:    cfg,
		opts:   opts,
		dryRun: cfg.Mode == netfilter.ModeDryRun,
	}
}

// Apply applies a NetfilterPlan to the host.
// In dry-run mode it logs planned operations without executing any commands.
func (b *Backend) Apply(ctx context.Context, plan netfilter.NetfilterPlan) error {
	// Ensure KERNLOOM_* chains and jump rules exist before restore.
	// iptables-restore with --noflush requires the chains to already exist.
	if err := b.EnsureChains(ctx); err != nil {
		return fmt.Errorf("iptables: ensure chains: %w", err)
	}

	// Apply ipset operations first (sets must exist before rules reference them).
	if b.cfg.Enforcement.PreferSets && len(plan.Sets) > 0 {
		if err := b.applySets(ctx, plan.Sets); err != nil {
			return fmt.Errorf("iptables: apply sets: %w", err)
		}
	}

	script := Render(plan, b.opts)

	if b.dryRun {
		logger.Printf("[dry-run] would apply iptables-restore script:\n%s", script)
		return nil
	}

	return b.restore(ctx, script)
}

// RuleCounter holds a packet/byte count for one Kernloom rule.
type RuleCounter struct {
	RuleID  string
	Chain   string
	Packets uint64
	Bytes   uint64
}

// ReadCounters reads packet/byte counters for all Kernloom rules by parsing
// `iptables -L <chain> -v -n -x` and matching comments back to rule IDs.
func (b *Backend) ReadCounters(ctx context.Context) ([]RuleCounter, error) {
	if b.probe.Path == "" {
		return nil, fmt.Errorf("iptables not available")
	}
	var all []RuleCounter
	for _, chain := range kernloomChains(b.cfg) {
		counters, err := b.readChainCounters(ctx, chain)
		if err != nil {
			return nil, err
		}
		all = append(all, counters...)
	}
	return all, nil
}

func (b *Backend) readChainCounters(ctx context.Context, chain string) ([]RuleCounter, error) {
	cmd := exec.CommandContext(ctx, b.probe.Path, "-L", chain, "-v", "-n", "-x")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Chain might not exist yet — treat as empty, not an error.
		if strings.Contains(string(out), "No chain") || strings.Contains(string(out), "does not exist") {
			return nil, nil
		}
		return nil, fmt.Errorf("iptables -L %s: %w", chain, err)
	}
	return parseChainCounters(chain, string(out), b.cfg.Ownership.CommentPrefix), nil
}

// parseChainCounters extracts RuleCounters from `iptables -L -v -n -x` output.
// Lines look like:  pkts bytes target prot opt in out source destination  [comment]
func parseChainCounters(chain, output, commentPrefix string) []RuleCounter {
	var counters []RuleCounter
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Skip header lines.
		if line == "" || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "pkts") {
			continue
		}
		// Extract rule ID from comment: "kernloom action=deny id=<id>"
		ruleID := extractRuleID(line, commentPrefix)
		if ruleID == "" {
			continue
		}
		pkts, bytes := parseCounterFields(line)
		counters = append(counters, RuleCounter{
			RuleID:  ruleID,
			Chain:   chain,
			Packets: pkts,
			Bytes:   bytes,
		})
	}
	return counters
}

// extractRuleID finds "id=<value>" in the comment part of an iptables -L line.
func extractRuleID(line, prefix string) string {
	idx := strings.Index(line, prefix+" ")
	if idx < 0 {
		return ""
	}
	rest := line[idx:]
	for _, field := range strings.Fields(rest) {
		if strings.HasPrefix(field, "id=") {
			return strings.TrimPrefix(field, "id=")
		}
	}
	return ""
}

// parseCounterFields extracts packet/byte counts from the first two numeric fields.
func parseCounterFields(line string) (pkts, bytes uint64) {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		pkts, _ = parseUint64(fields[0])
		bytes, _ = parseUint64(fields[1])
	}
	return
}

func parseUint64(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// Cleanup removes all Kernloom-owned chains and jump rules from the host.
// It never modifies non-Kernloom chains.
func (b *Backend) Cleanup(ctx context.Context) error {
	chains := kernloomChains(b.cfg)

	if b.dryRun {
		logger.Printf("[dry-run] would remove chains: %v", chains)
		return nil
	}

	for _, chain := range chains {
		hook := hookForChain(chain, b.cfg.Ownership.ChainPrefix)
		// Remove jump rule from parent hook.
		_ = b.run(ctx, b.probe.Path, "-D", hook, "-j", chain)
		// Flush then delete the chain.
		_ = b.run(ctx, b.probe.Path, "-F", chain)
		_ = b.run(ctx, b.probe.Path, "-X", chain)
	}
	return nil
}

// EnsureChains creates KERNLOOM_* chains and inserts jump rules if missing.
// Idempotent: uses -C to check existence before -N / -I.
func (b *Backend) EnsureChains(ctx context.Context) error {
	if b.dryRun {
		return nil
	}
	for _, chain := range kernloomChains(b.cfg) {
		// Create chain if it does not exist.
		if err := b.run(ctx, b.probe.Path, "-N", chain); err != nil {
			// -N returns 1 if chain already exists — that is fine.
			if !strings.Contains(err.Error(), "Chain already exists") &&
				!strings.Contains(err.Error(), "exit status 1") {
				return fmt.Errorf("create chain %s: %w", chain, err)
			}
		}
		// Insert jump rule at position 1 if not already present.
		hook := hookForChain(chain, b.cfg.Ownership.ChainPrefix)
		checkErr := b.run(ctx, b.probe.Path, "-C", hook, "-j", chain)
		if checkErr != nil {
			if err := b.run(ctx, b.probe.Path, "-I", hook, "1", "-j", chain); err != nil {
				return fmt.Errorf("insert jump %s->%s: %w", hook, chain, err)
			}
		}
	}
	return nil
}

/* ── internal helpers ──────────────────────────────────────────────────── */

func (b *Backend) restore(ctx context.Context, script string) error {
	if b.probe.RestorePath == "" {
		return fmt.Errorf("iptables-restore not found")
	}
	cmd := exec.CommandContext(ctx, b.probe.RestorePath, "--noflush", "--wait")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore: %w\noutput: %s", err, out)
	}
	return nil
}

func (b *Backend) applySets(ctx context.Context, sets []netfilter.SetPlan) error {
	if b.probe.IPSet.Path == "" {
		return nil // ipset unavailable — sets skipped
	}
	for _, cmd := range RenderSetOps(sets) {
		args := strings.Fields(cmd)
		if len(args) < 2 {
			continue
		}
		if b.dryRun {
			logger.Printf("[dry-run] ipset %s", strings.Join(args[1:], " "))
			continue
		}
		if err := b.run(ctx, b.probe.IPSet.Path, args[1:]...); err != nil {
			return fmt.Errorf("ipset %v: %w", args[1:], err)
		}
	}
	return nil
}

func (b *Backend) run(ctx context.Context, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// kernloomChains returns the list of KERNLOOM_* chains based on config.
func kernloomChains(cfg netfilter.Config) []string {
	var chains []string
	p := cfg.Ownership.ChainPrefix
	if cfg.Directions.Input {
		chains = append(chains, p+"_INPUT")
	}
	if cfg.Directions.Forward {
		chains = append(chains, p+"_FORWARD")
	}
	if cfg.Directions.Output {
		chains = append(chains, p+"_OUTPUT")
	}
	return chains
}

// hookForChain maps a KERNLOOM_* chain name back to its parent hook.
func hookForChain(chain, prefix string) string {
	suffix := strings.TrimPrefix(chain, prefix+"_")
	switch strings.ToUpper(suffix) {
	case "INPUT":
		return "INPUT"
	case "FORWARD":
		return "FORWARD"
	case "OUTPUT":
		return "OUTPUT"
	default:
		return "INPUT"
	}
}
