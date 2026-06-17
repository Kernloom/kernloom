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
