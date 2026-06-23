// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/core/decision"
)

type executionLeaseStore interface {
	ListActionLeasesByStatus(context.Context, decision.ActionLeaseStatus) ([]decision.ActionLease, error)
	UpdateActionLeaseStatus(context.Context, decision.ActionLease) error
}

func supersedeStaleDryRunExecutionLeases(ctx context.Context, store executionLeaseStore, currentDryRun bool, now time.Time) (int, error) {
	if store == nil || currentDryRun {
		return 0, nil
	}
	leases, err := store.ListActionLeasesByStatus(ctx, decision.ActionLeaseActive)
	if err != nil {
		return 0, err
	}
	now = now.UTC()
	count := 0
	for _, lease := range leases {
		if !leaseExecutionDryRun(lease) {
			continue
		}
		lease.Status = decision.ActionLeaseSuperseded
		lease.LastError = "superseded stale dry-run lease before real enforcement startup"
		lease.RevertedAt = &now
		if err := store.UpdateActionLeaseStatus(ctx, lease); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func leaseExecutionDryRun(lease decision.ActionLease) bool {
	if lease.Metadata == nil {
		return false
	}
	raw := strings.TrimSpace(lease.Metadata["param.execution_dry_run"])
	if raw == "" {
		return false
	}
	dryRun, err := strconv.ParseBool(raw)
	return err == nil && dryRun
}
