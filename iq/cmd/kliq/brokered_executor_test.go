// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
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
