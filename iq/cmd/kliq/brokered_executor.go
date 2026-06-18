// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

// receiptStore is the minimal interface the brokered executor needs for
// durable receipt persistence. Satisfied by *sqlite.Store.
type receiptStore interface {
	PersistReceipt(ctx context.Context, r decision.EnforcementReceipt) error
}

type brokeredActionExecutor struct {
	legacy *actions.SourceActionExecutor
	broker *actionbroker.Broker
	pep    *brokeredFSMPEP
	store  receiptStore // may be nil when running without a state store
	nodeID string
}

func newBrokeredActionExecutor(
	legacy *actions.SourceActionExecutor,
	broker *actionbroker.Broker,
	pep *brokeredFSMPEP,
	store *sqlite.Store,
	nodeID string,
) *brokeredActionExecutor {
	return &brokeredActionExecutor{legacy: legacy, broker: broker, pep: pep, store: store, nodeID: nodeID}
}

func (e *brokeredActionExecutor) AddSidecar(s actions.PEPSidecar) {
	e.legacy.AddSidecar(s)
}

func (e *brokeredActionExecutor) ApplySource(target adapterruntime.SourceTarget, st fsm.State, r actions.ActionResolution, params adapterruntime.EnforcementParams, now time.Time) (fsm.State, actions.ActionResult) {
	if !shouldBrokerLease(r) {
		return e.legacy.ApplySource(target, st, r, params, now)
	}
	return e.applyBrokered(applyContext{target: target, state: st, resolution: r, params: params, now: now})
}

func (e *brokeredActionExecutor) ApplyDeEnforceSource(target adapterruntime.SourceTarget, st fsm.State, params adapterruntime.EnforcementParams, now time.Time) fsm.State {
	return e.legacy.ApplyDeEnforceSource(target, st, params, now)
}

func (e *brokeredActionExecutor) ApplyRelationship(pep adapterruntime.RelationshipPEP, target adapterruntime.RelationshipTarget, r actions.ActionResolution, now time.Time) actions.ActionResult {
	return e.legacy.ApplyRelationship(pep, target, r, now)
}

func (e *brokeredActionExecutor) applyBrokered(ctx applyContext) (fsm.State, actions.ActionResult) {
	e.pep.begin(ctx)
	lease, receipt, err := e.broker.Apply(context.Background(), ctx.resolution)
	applied := e.pep.finish()
	if receipt != nil {
		logEnforcementReceipt(receipt)
		e.persistReceipt(receipt)
	}
	if err != nil {
		result := applied.result
		if result.Status == "" {
			result = actions.ActionResult{
				ProposalID: ctx.resolution.ProposalID,
				DecisionID: ctx.resolution.DecisionID,
				Action:     ctx.resolution.ExecutableAction,
				Status:     "failed",
				Reason:     err.Error(),
				AppliedAt:  ctx.now,
			}
		}
		return ctx.state, result
	}
	if lease.LeaseID == "" {
		return ctx.state, actions.ActionResult{
			ProposalID: ctx.resolution.ProposalID,
			DecisionID: ctx.resolution.DecisionID,
			Action:     ctx.resolution.ExecutableAction,
			Status:     "skipped",
			Reason:     "broker produced no lease",
			AppliedAt:  ctx.now,
		}
	}
	return applied.state, applied.result
}

func shouldBrokerLease(r actions.ActionResolution) bool {
	return r.Allowed && r.TTL > 0 && r.ExecutableLevel != "" && r.ExecutableLevel != "observe"
}

type applyContext struct {
	target     adapterruntime.SourceTarget
	state      fsm.State
	resolution actions.ActionResolution
	params     adapterruntime.EnforcementParams
	now        time.Time
}

type applyOutcome struct {
	state  fsm.State
	result actions.ActionResult
}

type brokeredFSMPEP struct {
	legacy *actions.SourceActionExecutor
	active *applyContext
	last   applyOutcome
}

func newBrokeredFSMPEP(legacy *actions.SourceActionExecutor) *brokeredFSMPEP {
	return &brokeredFSMPEP{legacy: legacy}
}

func (p *brokeredFSMPEP) AdapterID() string { return "kliq-fsm-pep" }

func (p *brokeredFSMPEP) begin(ctx applyContext) {
	p.active = &ctx
	p.last = applyOutcome{}
}

func (p *brokeredFSMPEP) finish() applyOutcome {
	out := p.last
	p.active = nil
	p.last = applyOutcome{}
	return out
}

func (p *brokeredFSMPEP) Apply(_ context.Context, lease decision.ActionLease) (string, error) {
	if p.active == nil {
		return "", fmt.Errorf("brokered fsm pep apply without active transition context")
	}
	st, result := p.legacy.ApplySource(p.active.target, p.active.state, p.active.resolution, p.active.params, p.active.now)
	p.last = applyOutcome{state: st, result: result}
	if p.last.result.Status == "failed" {
		return "", fmt.Errorf("%s", p.last.result.Reason)
	}
	return lease.FencingToken, nil
}

func (p *brokeredFSMPEP) CurrentFencingToken(_ context.Context, lease decision.ActionLease) (string, error) {
	return lease.FencingToken, nil
}

func (p *brokeredFSMPEP) Revert(_ context.Context, lease decision.ActionLease) error {
	return fmt.Errorf("brokered fsm pep revert is not wired to runtime state maps for target %s", lease.Target)
}

// persistReceipt durably stores a receipt so it can be uploaded to Forge later.
// Non-blocking: errors are logged but never propagate to the enforcement path.
func (e *brokeredActionExecutor) persistReceipt(r *decision.EnforcementReceipt) {
	if r == nil || e.store == nil {
		return
	}
	if r.NodeID == "" {
		r.NodeID = e.nodeID
	}
	if err := e.store.PersistReceipt(context.Background(), *r); err != nil {
		kliqLog.Printf("ACTION-RECEIPT persist error id=%s: %v", r.ID, err)
	}
}

func logEnforcementReceipt(receipt *decision.EnforcementReceipt) {
	parts := []string{
		"ACTION-RECEIPT",
		"status=" + string(receipt.Status),
		"adapter=" + receipt.AdapterID,
	}
	if receipt.LeaseID != "" {
		parts = append(parts, "lease="+receipt.LeaseID)
	}
	if receipt.Action != "" {
		parts = append(parts, "action="+receipt.Action)
	}
	if receipt.Target != "" {
		parts = append(parts, "target="+receipt.Target)
	}
	if receipt.Message != "" {
		parts = append(parts, "message="+fmt.Sprintf("%q", receipt.Message))
	}
	kliqLog.Print(strings.Join(parts, " "))
}
