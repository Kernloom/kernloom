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
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

// receiptStore is the minimal interface the brokered executor needs for
// durable receipt persistence. Satisfied by *sqlite.Store.
type receiptStore interface {
	PersistReceipt(ctx context.Context, r decision.EnforcementReceipt) error
}

type brokeredActionExecutor struct {
	sourceExecutor     *actions.SourceActionExecutor
	sourceBroker       *actionbroker.Broker
	sourcePEP          *brokeredSourcePEP
	relationshipBroker *actionbroker.Broker
	relationshipPEP    *brokeredRelationshipPEP
	store              receiptStore // may be nil when running without a state store
	nodeID             string
}

func newBrokeredActionExecutor(
	sourceExecutor *actions.SourceActionExecutor,
	sourceBroker *actionbroker.Broker,
	sourcePEP *brokeredSourcePEP,
	relationshipBroker *actionbroker.Broker,
	relationshipPEP *brokeredRelationshipPEP,
	store *sqlite.Store,
	nodeID string,
) *brokeredActionExecutor {
	return &brokeredActionExecutor{
		sourceExecutor:     sourceExecutor,
		sourceBroker:       sourceBroker,
		sourcePEP:          sourcePEP,
		relationshipBroker: relationshipBroker,
		relationshipPEP:    relationshipPEP,
		store:              store,
		nodeID:             nodeID,
	}
}

func (e *brokeredActionExecutor) AddSidecar(s actions.PEPSidecar) {
	e.sourceExecutor.AddSidecar(s)
}

func (e *brokeredActionExecutor) ApplySource(target adapterruntime.SourceTarget, st fsm.State, r actions.ActionResolution, params adapterruntime.EnforcementParams, now time.Time) (fsm.State, actions.ActionResult) {
	if !shouldBrokerLease(r) {
		return e.sourceExecutor.ApplySource(target, st, r, params, now)
	}
	return e.applyBrokered(applyContext{target: target, state: st, resolution: r, params: params, now: now})
}

func (e *brokeredActionExecutor) ApplyDeEnforceSource(target adapterruntime.SourceTarget, st fsm.State, params adapterruntime.EnforcementParams, now time.Time) fsm.State {
	return e.sourceExecutor.ApplyDeEnforceSource(target, st, params, now)
}

func (e *brokeredActionExecutor) ApplyRelationship(target adapterruntime.RelationshipTarget, r actions.ActionResolution, now time.Time) actions.ActionResult {
	if !r.Allowed {
		return actions.ActionResult{
			ProposalID: r.ProposalID,
			DecisionID: r.DecisionID,
			Action:     r.RequestedAction,
			Status:     "denied",
			Reason:     r.DenyReason,
			AppliedAt:  now,
		}
	}
	if r.ExecutableLevel != "block" {
		return relationshipSkippedResult(r, now, r.DenyReason)
	}
	if r.TTL <= 0 {
		return relationshipSkippedResult(r, now, "relationship action requires TTL")
	}
	if e.relationshipBroker == nil || e.relationshipPEP == nil {
		return relationshipSkippedResult(r, now, "relationship broker unavailable")
	}
	e.relationshipPEP.begin(target)
	lease, receipt, err := e.relationshipBroker.Apply(context.Background(), r)
	applied := e.relationshipPEP.finish()
	if receipt != nil {
		logEnforcementReceipt(receipt)
		e.persistReceipt(receipt)
	}
	if err != nil {
		result := applied
		if result.Status == "" {
			result = actions.ActionResult{
				ProposalID: r.ProposalID,
				DecisionID: r.DecisionID,
				Action:     r.ExecutableAction,
				Status:     "failed",
				Reason:     err.Error(),
				AppliedAt:  now,
			}
		}
		return result
	}
	if lease.LeaseID == "" {
		return relationshipSkippedResult(r, now, "broker produced no relationship lease")
	}
	if applied.Status == "" {
		applied = actions.ActionResult{
			ProposalID: r.ProposalID,
			DecisionID: r.DecisionID,
			Action:     r.ExecutableAction,
			Status:     "applied",
			AppliedAt:  now,
		}
	}
	return applied
}

func (e *brokeredActionExecutor) applyBrokered(ctx applyContext) (fsm.State, actions.ActionResult) {
	e.sourcePEP.begin(ctx)
	lease, receipt, err := e.sourceBroker.Apply(context.Background(), ctx.resolution)
	applied := e.sourcePEP.finish()
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

func (e *brokeredActionExecutor) RevertExpired(ctx context.Context, now time.Time) {
	brokers := []*actionbroker.Broker{e.sourceBroker, e.relationshipBroker}
	for _, broker := range brokers {
		if broker == nil {
			continue
		}
		receipts, err := broker.RevertExpired(ctx, now)
		for _, receipt := range receipts {
			logEnforcementReceipt(receipt)
			e.persistReceipt(receipt)
		}
		if err != nil {
			kliqLog.Printf("ACTION-RECEIPT revert expired error: %v", err)
		}
	}
}

func shouldBrokerLease(r actions.ActionResolution) bool {
	return r.Allowed && r.TTL > 0 && r.ExecutableLevel != "" && r.ExecutableLevel != "observe"
}

func relationshipSkippedResult(r actions.ActionResolution, now time.Time, reason string) actions.ActionResult {
	if reason == "" {
		reason = r.DenyReason
	}
	return actions.ActionResult{
		ProposalID: r.ProposalID,
		DecisionID: r.DecisionID,
		Action:     r.RequestedAction,
		Status:     "skipped",
		Reason:     reason,
		AppliedAt:  now,
	}
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

type brokeredSourcePEP struct {
	sourceExecutor *actions.SourceActionExecutor
	params         func() adapterruntime.EnforcementParams
	active         *applyContext
	last           applyOutcome
}

func newBrokeredSourcePEP(sourceExecutor *actions.SourceActionExecutor, params func() adapterruntime.EnforcementParams) *brokeredSourcePEP {
	return &brokeredSourcePEP{sourceExecutor: sourceExecutor, params: params}
}

func (p *brokeredSourcePEP) AdapterID() string { return "kliq-source-pep" }

func (p *brokeredSourcePEP) begin(ctx applyContext) {
	p.active = &ctx
	p.last = applyOutcome{}
}

func (p *brokeredSourcePEP) finish() applyOutcome {
	out := p.last
	p.active = nil
	p.last = applyOutcome{}
	return out
}

func (p *brokeredSourcePEP) Apply(_ context.Context, lease decision.ActionLease) (string, error) {
	if p.active == nil {
		return "", fmt.Errorf("brokered source pep apply without active transition context")
	}
	st, result := p.sourceExecutor.ApplySource(p.active.target, p.active.state, p.active.resolution, p.active.params, p.active.now)
	p.last = applyOutcome{state: st, result: result}
	if p.last.result.Status == "failed" {
		return "", fmt.Errorf("%s", p.last.result.Reason)
	}
	return lease.FencingToken, nil
}

func (p *brokeredSourcePEP) CurrentFencingToken(_ context.Context, lease decision.ActionLease) (string, error) {
	return lease.FencingToken, nil
}

func (p *brokeredSourcePEP) Revert(_ context.Context, lease decision.ActionLease) error {
	target := actionbroker.TargetFromLease(lease)
	if target.Value == "" {
		return fmt.Errorf("source revert target missing for lease %s", lease.LeaseID)
	}
	params := adapterruntime.EnforcementParams{}
	if p.params != nil {
		params = p.params()
	}
	p.sourceExecutor.ApplyDeEnforceSource(adapterruntime.SourceTarget{
		SourceID:   target.Value,
		Subject:    observation.EntityRef{ID: target.Value},
		Attributes: copyStringMap(target.Attributes),
	}, fsm.State{Level: actions.ParseFSMLevel(lease.Level)}, params, time.Now().UTC())
	return nil
}

type brokeredRelationshipPEP struct {
	pep    adapterruntime.RelationshipPEP
	active *adapterruntime.RelationshipTarget
	last   actions.ActionResult
}

func newBrokeredRelationshipPEP(pep adapterruntime.RelationshipPEP) *brokeredRelationshipPEP {
	return &brokeredRelationshipPEP{pep: pep}
}

func (p *brokeredRelationshipPEP) AdapterID() string { return "kliq-relationship-pep" }

func (p *brokeredRelationshipPEP) begin(target adapterruntime.RelationshipTarget) {
	p.active = &target
	p.last = actions.ActionResult{}
}

func (p *brokeredRelationshipPEP) finish() actions.ActionResult {
	out := p.last
	p.active = nil
	p.last = actions.ActionResult{}
	return out
}

func (p *brokeredRelationshipPEP) Apply(_ context.Context, lease decision.ActionLease) (string, error) {
	if p.pep == nil || !p.pep.RelationshipAvailable() {
		return "", fmt.Errorf("relationship pep unavailable")
	}
	if p.active == nil {
		return "", fmt.Errorf("relationship pep apply without active target context")
	}
	if err := p.pep.DenyRelationship(*p.active); err != nil {
		p.last = actions.ActionResult{
			ProposalID: lease.ProposalID,
			DecisionID: lease.DecisionID,
			Action:     lease.Action,
			Status:     "failed",
			Reason:     err.Error(),
			AppliedAt:  time.Now().UTC(),
		}
		return "", err
	}
	p.last = actions.ActionResult{
		ProposalID: lease.ProposalID,
		DecisionID: lease.DecisionID,
		Action:     lease.Action,
		Status:     "applied",
		AppliedAt:  time.Now().UTC(),
	}
	return lease.FencingToken, nil
}

func (p *brokeredRelationshipPEP) CurrentFencingToken(_ context.Context, lease decision.ActionLease) (string, error) {
	return lease.FencingToken, nil
}

func (p *brokeredRelationshipPEP) Revert(_ context.Context, lease decision.ActionLease) error {
	if p.pep == nil || !p.pep.RelationshipAvailable() {
		return fmt.Errorf("relationship pep unavailable")
	}
	target, ok := relationshipTargetFromActionTarget(actionbroker.TargetFromLease(lease))
	if !ok {
		return fmt.Errorf("relationship revert target invalid for lease %s", lease.LeaseID)
	}
	return p.pep.AllowRelationship(target)
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
