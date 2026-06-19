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
