// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actionbroker_test

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/core/decision"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

type fakePEP struct {
	token        string
	applyCalls   int
	revertCalls  int
	currentToken string
}

func (p *fakePEP) AdapterID() string { return "fake-pep" }

func (p *fakePEP) Apply(_ context.Context, lease decision.ActionLease) (string, error) {
	p.applyCalls++
	if p.token == "" {
		p.token = lease.FencingToken
	}
	p.currentToken = p.token
	return p.token, nil
}

func (p *fakePEP) CurrentFencingToken(_ context.Context, _ decision.ActionLease) (string, error) {
	return p.currentToken, nil
}

func (p *fakePEP) Revert(_ context.Context, _ decision.ActionLease) error {
	p.revertCalls++
	p.currentToken = ""
	return nil
}

func newBroker(t *testing.T, pep *fakePEP, now func() time.Time) (*actionbroker.Broker, *sstore.Store) {
	t.Helper()
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	b, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-1",
		Store:  store,
		PEP:    pep,
		Now:    now,
	})
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b, store
}

func testResolution(ttl time.Duration) actions.ActionResolution {
	return actions.ActionResolution{
		ProposalID:       "proposal-1",
		DecisionID:       "decision-1",
		Allowed:          true,
		RequestedAction:  "enforce.traffic.rate_limit",
		RequestedLevel:   "soft",
		ExecutableAction: "enforce.traffic.rate_limit",
		ExecutableLevel:  "soft",
		Target:           actions.ActionTarget{Granularity: "ip", Value: "10.0.0.1"},
		TTL:              ttl,
		PolicyID:         "policy-1",
		Parameters:       map[string]any{"rate_pps": 100},
	}
}

func TestApplyCreatesLeaseAndReceipt(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	pep := &fakePEP{}
	b, store := newBroker(t, pep, func() time.Time { return now })
	defer store.Close()

	lease, receipt, err := b.Apply(context.Background(), testResolution(time.Minute))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if pep.applyCalls != 1 {
		t.Fatalf("expected one PEP apply, got %d", pep.applyCalls)
	}
	if lease.Status != decision.ActionLeaseActive {
		t.Fatalf("expected active lease, got %s", lease.Status)
	}
	if lease.FencingToken == "" {
		t.Fatal("expected broker-generated fencing token")
	}
	if receipt.Status != decision.StatusApplied || receipt.LeaseID != lease.LeaseID {
		t.Fatalf("bad receipt: %#v", receipt)
	}
	loaded, ok, err := store.GetActionLease(context.Background(), lease.LeaseID)
	if err != nil {
		t.Fatalf("load lease: %v", err)
	}
	if !ok || loaded.LeaseID != lease.LeaseID {
		t.Fatalf("lease not persisted: ok=%v lease=%#v", ok, loaded)
	}
}

func TestDeniedActionDoesNotCreateLease(t *testing.T) {
	pep := &fakePEP{}
	b, store := newBroker(t, pep, time.Now)
	defer store.Close()

	res := testResolution(time.Minute)
	res.Allowed = false
	res.DenyReason = "capability_not_allowed"
	lease, receipt, err := b.Apply(context.Background(), res)
	if err != nil {
		t.Fatalf("apply denied: %v", err)
	}
	if lease.LeaseID != "" {
		t.Fatalf("expected no lease, got %#v", lease)
	}
	if pep.applyCalls != 0 {
		t.Fatalf("PEP apply must not be called for denied action")
	}
	if receipt.Status != decision.StatusSkipped {
		t.Fatalf("expected skipped receipt, got %s", receipt.Status)
	}
}

func TestRevertExpiredRevertsMatchingLease(t *testing.T) {
	start := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	current := start
	pep := &fakePEP{}
	b, store := newBroker(t, pep, func() time.Time { return current })
	defer store.Close()

	lease, _, err := b.Apply(context.Background(), testResolution(time.Second))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	current = start.Add(2 * time.Second)
	receipts, err := b.RevertExpired(context.Background(), current)
	if err != nil {
		t.Fatalf("revert expired: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != decision.StatusReverted {
		t.Fatalf("expected reverted receipt, got %#v", receipts)
	}
	if pep.revertCalls != 1 {
		t.Fatalf("expected one revert call, got %d", pep.revertCalls)
	}
	loaded, ok, err := store.GetActionLease(context.Background(), lease.LeaseID)
	if err != nil || !ok {
		t.Fatalf("load lease after revert: ok=%v err=%v", ok, err)
	}
	if loaded.Status != decision.ActionLeaseReverted {
		t.Fatalf("expected reverted lease, got %s", loaded.Status)
	}
}

func TestApplyRenewsMatchingActiveLease(t *testing.T) {
	start := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	current := start
	pep := &fakePEP{}
	b, store := newBroker(t, pep, func() time.Time { return current })
	defer store.Close()

	lease1, _, err := b.Apply(context.Background(), testResolution(time.Second))
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}

	current = start.Add(500 * time.Millisecond)
	res := testResolution(5 * time.Second)
	res.DecisionID = "decision-renewed"
	res.ProposalID = "proposal-renewed"
	lease2, receipt, err := b.Apply(context.Background(), res)
	if err != nil {
		t.Fatalf("renew apply: %v", err)
	}
	if pep.applyCalls != 1 {
		t.Fatalf("renewal should not reapply an already-active lease, got %d apply calls", pep.applyCalls)
	}
	if lease2.LeaseID != lease1.LeaseID || lease2.FencingToken != lease1.FencingToken {
		t.Fatalf("expected same lease/token after renewal: first=%#v second=%#v", lease1, lease2)
	}
	if receipt.Status != decision.StatusApplied || receipt.Message == "" {
		t.Fatalf("expected applied renewal receipt with message, got %#v", receipt)
	}

	current = start.Add(2 * time.Second)
	receipts, err := b.RevertExpired(context.Background(), current)
	if err != nil {
		t.Fatalf("revert before renewed expiry: %v", err)
	}
	if len(receipts) != 0 || pep.revertCalls != 0 {
		t.Fatalf("renewed lease should not expire at old ttl: receipts=%#v revertCalls=%d", receipts, pep.revertCalls)
	}

	current = start.Add(6 * time.Second)
	receipts, err = b.RevertExpired(context.Background(), current)
	if err != nil {
		t.Fatalf("revert after renewed expiry: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != decision.StatusReverted {
		t.Fatalf("expected renewed lease to revert later, got %#v", receipts)
	}
}

func TestRevertExpiredMarksConflictOnFencingMismatch(t *testing.T) {
	start := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	current := start
	pep := &fakePEP{}
	b, store := newBroker(t, pep, func() time.Time { return current })
	defer store.Close()

	lease, _, err := b.Apply(context.Background(), testResolution(time.Second))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	pep.currentToken = "manual-admin-change"
	current = start.Add(2 * time.Second)
	receipts, err := b.RevertExpired(context.Background(), current)
	if err != nil {
		t.Fatalf("revert expired: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != decision.StatusConflict {
		t.Fatalf("expected conflict receipt, got %#v", receipts)
	}
	if pep.revertCalls != 0 {
		t.Fatalf("revert must not be called on fencing conflict")
	}
	loaded, ok, err := store.GetActionLease(context.Background(), lease.LeaseID)
	if err != nil || !ok {
		t.Fatalf("load lease after conflict: ok=%v err=%v", ok, err)
	}
	if loaded.Status != decision.ActionLeaseConflict {
		t.Fatalf("expected conflict lease, got %s", loaded.Status)
	}
}

func TestReconcilePendingMarksUnknownApplyFailed(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	pep := &fakePEP{}
	b, store := newBroker(t, pep, func() time.Time { return now })
	defer store.Close()

	lease := decision.ActionLease{
		LeaseID:      "lease-pending",
		DecisionID:   "decision-pending",
		NodeID:       "node-1",
		AdapterID:    pep.AdapterID(),
		Target:       "ip:10.0.0.1",
		Action:       "enforce.traffic.rate_limit",
		Level:        "soft",
		Status:       decision.ActionLeasePending,
		FencingToken: "token-pending",
		AppliedAt:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Minute),
	}
	if err := store.UpsertActionLease(context.Background(), lease); err != nil {
		t.Fatalf("seed pending lease: %v", err)
	}

	receipts, err := b.ReconcilePending(context.Background())
	if err != nil {
		t.Fatalf("reconcile pending: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != decision.StatusFailed {
		t.Fatalf("expected failed receipt, got %#v", receipts)
	}
	if pep.applyCalls != 0 || pep.revertCalls != 0 {
		t.Fatalf("reconcile pending must not touch PEP: apply=%d revert=%d", pep.applyCalls, pep.revertCalls)
	}
	loaded, ok, err := store.GetActionLease(context.Background(), lease.LeaseID)
	if err != nil || !ok {
		t.Fatalf("load reconciled lease: ok=%v err=%v", ok, err)
	}
	if loaded.Status != decision.ActionLeaseFailed {
		t.Fatalf("expected failed lease, got %s", loaded.Status)
	}
	if loaded.LastError == "" {
		t.Fatal("expected diagnostic last_error")
	}
}
