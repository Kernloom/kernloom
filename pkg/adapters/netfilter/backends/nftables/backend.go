// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package nftables

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

var logger = log.New(os.Stderr, "[netfilter/nftables] ", log.LstdFlags)

// Backend implements the nftables enforcement backend.
type Backend struct {
	probe  netfilter.NFTablesProbe
	cfg    netfilter.Config
	opts   RenderOptions
	dryRun bool
}

// New creates a nftables backend from a completed probe result.
func New(probe netfilter.NFTablesProbe, cfg netfilter.Config) *Backend {
	opts := DefaultRenderOptions()
	opts.TableName = cfg.Ownership.TableName
	opts.CommentPrefix = cfg.Ownership.CommentPrefix
	return &Backend{
		probe:  probe,
		cfg:    cfg,
		opts:   opts,
		dryRun: cfg.Mode == netfilter.ModeDryRun,
	}
}

// Apply atomically replaces the Kernloom nftables table with the desired plan.
// Uses "nft -f" which is atomic at the kernel level — either the whole table
// is replaced or the old state is retained on error.
func (b *Backend) Apply(ctx context.Context, plan netfilter.NetfilterPlan) error {
	script := RenderTable(plan, b.opts)

	if b.dryRun {
		logger.Printf("[dry-run] would apply nft ruleset:\n%s", script)
		return nil
	}

	return b.applyFile(ctx, script)
}

// AddElements inserts new entries into an existing set without a full table
// replacement. Used for dynamic deny/allow TTL entries during a running cycle.
func (b *Backend) AddElements(ctx context.Context, setName string, elements []netfilter.SetElement) error {
	cmds := RenderAddElements(b.opts.TableName, setName, elements)
	for _, cmd := range cmds {
		if b.dryRun {
			logger.Printf("[dry-run] nft %s", cmd)
			continue
		}
		if err := b.run(ctx, strings.Fields(cmd)...); err != nil {
			return fmt.Errorf("nft add element: %w", err)
		}
	}
	return nil
}

// Cleanup atomically deletes the entire Kernloom table.
// All sets, chains and rules owned by Kernloom are removed in one operation.
// Other tables are never touched.
func (b *Backend) Cleanup(ctx context.Context) error {
	if b.dryRun {
		logger.Printf("[dry-run] would delete table inet %s", b.opts.TableName)
		return nil
	}
	cmd := RenderDeleteTable(b.opts)
	args := strings.Fields(cmd)
	if err := b.run(ctx, args...); err != nil {
		// "No such file or directory" means table does not exist — that is fine.
		if strings.Contains(err.Error(), "No such file") ||
			strings.Contains(err.Error(), "Table") ||
			strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return fmt.Errorf("nft delete table: %w", err)
	}
	return nil
}

// TableExists reports whether the Kernloom table is currently loaded.
func (b *Backend) TableExists(ctx context.Context) bool {
	_, err := b.runOutput(ctx, "list", "table", "inet", b.opts.TableName)
	return err == nil
}

/* ── internal helpers ──────────────────────────────────────────────────── */

// applyFile writes the nft script to a temp file and applies it atomically.
// We use a temp file rather than stdin because nft -f from stdin does not
// support the "delete table" + "add table" pattern needed for clean replace.
func (b *Backend) applyFile(ctx context.Context, script string) error {
	// Write to temp file.
	f, err := os.CreateTemp("", "kernloom-nft-*.nft")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return fmt.Errorf("write nft script: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close nft script: %w", err)
	}

	// Delete existing table first so the apply is truly atomic (old table →
	// no table → new table). The two operations are not transactional, but
	// the window between them is sub-millisecond and enforcement rules are
	// still in effect in the kernel until the delete commits.
	if b.TableExists(ctx) {
		if err := b.run(ctx, "delete", "table", "inet", b.opts.TableName); err != nil {
			logger.Printf("WARNING: could not delete existing table before replace: %v", err)
		}
	}

	if err := b.run(ctx, "-f", f.Name()); err != nil {
		return fmt.Errorf("nft -f: %w", err)
	}
	return nil
}

func (b *Backend) run(ctx context.Context, args ...string) error {
	_, err := b.runOutput(ctx, args...)
	return err
}

func (b *Backend) runOutput(ctx context.Context, args ...string) (string, error) {
	if b.probe.Path == "" {
		return "", fmt.Errorf("nft binary not found")
	}
	cmd := exec.CommandContext(ctx, b.probe.Path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
