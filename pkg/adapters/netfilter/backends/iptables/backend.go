// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package iptables

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
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
