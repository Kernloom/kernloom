// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestBrokeredRelationshipApplyAndRevert(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	now := start
	relPEP := &testRelationshipPEP{available: true}
	brokerPEP := newBrokeredRelationshipPEP(relPEP)
	relBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new relationship broker: %v", err)
	}
	executor := newBrokeredActionExecutor(nil, nil, nil, relBroker, brokerPEP, store, "node-1")

	relTarget := adapterruntime.RelationshipTarget{
		RelationshipKey: adapterruntime.RelationshipKey{
			SubjectID: "source-1",
			TargetID:  "service-1",
			Dimension: map[string]string{"port": "443", "proto": "tcp"},
		},
	}
	actionTarget := actions.ActionTarget{
		Granularity: actions.TargetGranularityRelationship,
		Value:       relTarget.Canonical(),
		Attributes: map[string]string{
			actions.TargetAttrSubjectID:                 "source-1",
			actions.TargetAttrTargetID:                  "service-1",
			actions.TargetAttrDimensionPrefix + "port":  "443",
			actions.TargetAttrDimensionPrefix + "proto": "tcp",
		},
	}
	res := actions.ActionResolution{
		ProposalID:       "proposal-1",
		DecisionID:       "decision-1",
		Allowed:          true,
		RequestedAction:  "enforce.access.deny",
		RequestedLevel:   "block",
		ExecutableAction: "enforce.access.deny",
		ExecutableLevel:  "block",
		Target:           actionTarget,
		TTL:              time.Second,
	}

	result := executor.ApplyRelationship(relTarget, res, now)
	if result.Status != "applied" {
		t.Fatalf("relationship apply: %#v", result)
	}
	if relPEP.denyCalls != 1 {
		t.Fatalf("expected one deny call, got %d", relPEP.denyCalls)
	}

	now = start.Add(2 * time.Second)
	executor.RevertExpired(context.Background(), now)
	if relPEP.allowCalls != 1 {
		t.Fatalf("expected one allow revert call, got %d", relPEP.allowCalls)
	}

	receipts, err := store.ListPendingReceipts(context.Background(), 10)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("expected apply + revert receipts, got %d: %#v", len(receipts), receipts)
	}
}

func TestBrokeredSourceFencingPreventsOlderLeaseRevertingNewerLevel(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 6, 19, 10, 10, 0, 0, time.UTC)
	now := start
	pep := &recordingSourcePEP{}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return adapterruntime.EnforcementParams{
			SoftTTL:  time.Second,
			HardTTL:  5 * time.Second,
			BlockTTL: 5 * time.Second,
		}
	})
	sourceBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new source broker: %v", err)
	}
	executor := newBrokeredActionExecutor(sourceExecutor, sourceBroker, brokerPEP, nil, nil, store, "node-1")
	target := adapterruntime.SourceTarget{SourceID: "10.0.0.1"}

	state, result := executor.ApplySource(target, fsm.State{}, sourceResolution("decision-soft", "soft", time.Second), adapterruntime.EnforcementParams{SoftTTL: time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelSoft {
		t.Fatalf("soft apply: state=%s result=%#v", state.Level, result)
	}

	now = start.Add(500 * time.Millisecond)
	state, result = executor.ApplySource(target, state, sourceResolution("decision-hard", "hard", 5*time.Second), adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("hard apply: state=%s result=%#v", state.Level, result)
	}

	now = start.Add(2 * time.Second)
	executor.RevertExpired(context.Background(), now)
	if len(pep.levels) != 2 {
		t.Fatalf("old soft lease must not revert newer hard lease, transitions=%#v", pep.levels)
	}
	if pep.levels[0] != fsm.LevelSoft || pep.levels[1] != fsm.LevelHard {
		t.Fatalf("unexpected transitions: %#v", pep.levels)
	}
}

func TestBrokeredSourceRenewReturnsLeaseState(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	now := start
	pep := &recordingSourcePEP{}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}
	})
	sourceBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new source broker: %v", err)
	}
	executor := newBrokeredActionExecutor(sourceExecutor, sourceBroker, brokerPEP, nil, nil, store, "node-1")
	target := adapterruntime.SourceTarget{SourceID: "10.0.0.1"}

	state, result := executor.ApplySource(target, fsm.State{}, sourceResolution("decision-hard-1", "hard", 5*time.Second), adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("first apply: state=%s result=%#v", state.Level, result)
	}

	now = start.Add(time.Second)
	state, result = executor.ApplySource(target, fsm.State{Level: fsm.LevelObserve}, sourceResolution("decision-hard-2", "hard", 5*time.Second), adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("renew apply must return lease state hard, state=%s result=%#v", state.Level, result)
	}
	if result.Reason != "lease renewed" {
		t.Fatalf("renew result reason = %q", result.Reason)
	}
	if len(pep.levels) != 1 {
		t.Fatalf("renew must not call PEP transition again, transitions=%#v", pep.levels)
	}
}

func TestBrokeredSourceDryRunSwitchReapplies(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 6, 22, 22, 50, 0, 0, time.UTC)
	now := start
	pep := &recordingSourcePEP{}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}
	})
	sourceBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new source broker: %v", err)
	}
	executor := newBrokeredActionExecutor(sourceExecutor, sourceBroker, brokerPEP, nil, nil, store, "node-1")
	target := adapterruntime.SourceTarget{SourceID: "10.0.0.1"}

	state, result := executor.ApplySource(target, fsm.State{}, sourceResolution("decision-dry-run", "hard", 5*time.Second), adapterruntime.EnforcementParams{
		DryRun:  true,
		HardTTL: 5 * time.Second,
	}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("dry-run apply: state=%s result=%#v", state.Level, result)
	}

	now = start.Add(time.Second)
	state, result = executor.ApplySource(target, state, sourceResolution("decision-real", "hard", 5*time.Second), adapterruntime.EnforcementParams{
		DryRun:  false,
		HardTTL: 5 * time.Second,
	}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("real apply after dry-run: state=%s result=%#v", state.Level, result)
	}
	if result.Reason == "lease renewed" {
		t.Fatalf("dry-run switch must not renew stale dry-run lease: %#v", result)
	}
	if len(pep.levels) != 2 {
		t.Fatalf("dry-run switch must call PEP again, transitions=%#v", pep.levels)
	}
}

func TestSupersedeStaleDryRunExecutionLeasesBeforeRealRun(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 22, 23, 55, 0, 0, time.UTC)
	dryRunLease := decision.ActionLease{
		LeaseID:      "lease-dry-run",
		DecisionID:   "decision-dry-run",
		NodeID:       "node-1",
		AdapterID:    "kliq-source-pep",
		Target:       "source:10.0.0.1",
		Action:       "enforce.traffic.rate_limit",
		Level:        "hard",
		Status:       decision.ActionLeaseActive,
		FencingToken: "token-dry-run",
		AppliedAt:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Minute),
		Metadata:     map[string]string{"param.execution_dry_run": "true"},
	}
	realLease := dryRunLease
	realLease.LeaseID = "lease-real"
	realLease.DecisionID = "decision-real"
	realLease.Target = "source:10.0.0.2"
	realLease.FencingToken = "token-real"
	realLease.Metadata = map[string]string{"param.execution_dry_run": "false"}
	if err := store.UpsertActionLease(context.Background(), dryRunLease); err != nil {
		t.Fatalf("insert dry-run lease: %v", err)
	}
	if err := store.UpsertActionLease(context.Background(), realLease); err != nil {
		t.Fatalf("insert real lease: %v", err)
	}

	n, err := supersedeStaleDryRunExecutionLeases(context.Background(), store, false, now)
	if err != nil {
		t.Fatalf("supersede stale dry-run leases: %v", err)
	}
	if n != 1 {
		t.Fatalf("superseded leases = %d, want 1", n)
	}
	loadedDry, ok, err := store.GetActionLease(context.Background(), dryRunLease.LeaseID)
	if err != nil || !ok {
		t.Fatalf("load dry-run lease: ok=%v err=%v", ok, err)
	}
	if loadedDry.Status != decision.ActionLeaseSuperseded {
		t.Fatalf("dry-run lease status = %s, want superseded", loadedDry.Status)
	}
	if loadedDry.RevertedAt == nil {
		t.Fatal("dry-run lease should get reverted_at when superseded")
	}
	loadedReal, ok, err := store.GetActionLease(context.Background(), realLease.LeaseID)
	if err != nil || !ok {
		t.Fatalf("load real lease: ok=%v err=%v", ok, err)
	}
	if loadedReal.Status != decision.ActionLeaseActive {
		t.Fatalf("real lease status = %s, want active", loadedReal.Status)
	}

	n, err = supersedeStaleDryRunExecutionLeases(context.Background(), store, true, now)
	if err != nil {
		t.Fatalf("dry-run startup reconcile: %v", err)
	}
	if n != 0 {
		t.Fatalf("dry-run startup should not supersede real leases, got %d", n)
	}
}

func TestBrokeredSourceRenewsExpiredActiveLeaseBeforeRevert(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 6, 20, 9, 30, 0, 0, time.UTC)
	now := start
	pep := &recordingSourcePEP{}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}
	})
	sourceBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new source broker: %v", err)
	}
	executor := newBrokeredActionExecutor(sourceExecutor, sourceBroker, brokerPEP, nil, nil, store, "node-1")
	target := adapterruntime.SourceTarget{SourceID: "10.0.0.1"}

	state, result := executor.ApplySource(target, fsm.State{}, sourceResolution("decision-hard-1", "hard", time.Second), adapterruntime.EnforcementParams{HardTTL: time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("first apply: state=%s result=%#v", state.Level, result)
	}

	now = start.Add(2 * time.Second)
	state, result = executor.ApplySource(target, state, sourceResolution("decision-hard-2", "hard", 5*time.Second), adapterruntime.EnforcementParams{HardTTL: 5 * time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("expired active lease renewal: state=%s result=%#v", state.Level, result)
	}
	executor.RevertExpired(context.Background(), now)
	if len(pep.levels) != 1 {
		t.Fatalf("renew-before-revert should avoid observe bounce, transitions=%#v", pep.levels)
	}
}

func TestBrokeredSourceAppliesRuntimeDecisionRatePPS(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 23, 10, 30, 0, 0, time.UTC)
	pep := &recordingSourcePEP{}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return adapterruntime.EnforcementParams{HardRate: 20, HardBurst: 40, HardTTL: 10 * time.Second}
	})
	sourceBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new source broker: %v", err)
	}
	executor := newBrokeredActionExecutor(sourceExecutor, sourceBroker, brokerPEP, nil, nil, store, "node-1")
	target := adapterruntime.SourceTarget{SourceID: "10.0.0.1"}
	res := sourceResolution("decision-hard-rate", "hard", time.Minute)
	res.Parameters = map[string]any{"rate_pps": 100}

	state, result := executor.ApplySource(target, fsm.State{}, res, adapterruntime.EnforcementParams{HardRate: 20, HardBurst: 40, HardTTL: 10 * time.Second}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("apply: state=%s result=%#v", state.Level, result)
	}
	if len(pep.params) != 1 {
		t.Fatalf("PEP params calls = %d", len(pep.params))
	}
	if got := pep.params[0].HardRate; got != 100 {
		t.Fatalf("hard rate = %d, want 100", got)
	}
	if got := pep.params[0].HardBurst; got != 200 {
		t.Fatalf("hard burst = %d, want 200", got)
	}
	if !state.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("state expiry = %s, want %s", state.ExpiresAt, now.Add(time.Minute))
	}
	receipts, err := store.ListPendingReceipts(context.Background(), 10)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected one receipt, got %d: %#v", len(receipts), receipts)
	}
	if !strings.Contains(receipts[0].Message, "hard_rate_pps=100") {
		t.Fatalf("receipt message = %q", receipts[0].Message)
	}
}

func TestApplyResolvedSourceActionProjectsActiveLeaseState(t *testing.T) {
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	now := start
	pep := &recordingSourcePEP{}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return adapterruntime.EnforcementParams{
			HardTTL:  time.Minute,
			BlockTTL: time.Minute,
		}
	})
	sourceBroker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new source broker: %v", err)
	}
	executor := newBrokeredActionExecutor(sourceExecutor, sourceBroker, brokerPEP, nil, nil, store, "node-1")
	target := adapterruntime.SourceTarget{SourceID: "10.0.0.1"}

	state, result := executor.ApplySource(target, fsm.State{}, sourceResolution("decision-rate", "hard", time.Minute), adapterruntime.EnforcementParams{HardTTL: time.Minute}, now)
	if result.Status != "applied" || state.Level != fsm.LevelHard {
		t.Fatalf("rate-limit apply: state=%s result=%#v", state.Level, result)
	}

	now = start.Add(10 * time.Second)
	block := sourceResolution("decision-block", "block", time.Minute)
	block.RequestedAction = "enforce.traffic.drop"
	block.ExecutableAction = "enforce.traffic.drop"
	if !applyResolvedSourceAction(block, executor, adapterruntime.EnforcementParams{BlockTTL: time.Minute}, now) {
		t.Fatal("block action was not applied")
	}
	if len(pep.prev) < 2 || len(pep.levels) < 2 {
		t.Fatalf("PEP transitions missing: prev=%#v levels=%#v", pep.prev, pep.levels)
	}
	if pep.prev[1] != fsm.LevelHard || pep.levels[1] != fsm.LevelBlock {
		t.Fatalf("block transition = %v->%v, want hard->block (all prev=%#v levels=%#v)", pep.prev[1], pep.levels[1], pep.prev, pep.levels)
	}
}

func sourceResolution(decisionID, level string, ttl time.Duration) actions.ActionResolution {
	return actions.ActionResolution{
		ProposalID:       "proposal-" + decisionID,
		DecisionID:       decisionID,
		Allowed:          true,
		RequestedAction:  "enforce.traffic.rate_limit",
		RequestedLevel:   level,
		ExecutableAction: "enforce.traffic.rate_limit",
		ExecutableLevel:  level,
		Target:           actions.ActionTarget{Granularity: actions.TargetGranularitySource, Value: "10.0.0.1"},
		TTL:              ttl,
		PolicyID:         "policy-test",
	}
}
