// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
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

type actionLeaseLookupStore interface {
	FindActiveActionLease(ctx context.Context, adapterID, target, action, level string) (decision.ActionLease, bool, error)
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
	params = enforcementParamsForResolution(params, r)
	if !shouldBrokerLease(r) {
		return e.sourceExecutor.ApplySource(target, st, r, params, now)
	}
	return e.applyBrokered(applyContext{target: target, state: st, resolution: r, params: params, now: now})
}

func (e *brokeredActionExecutor) ApplyDeEnforceSource(target adapterruntime.SourceTarget, st fsm.State, params adapterruntime.EnforcementParams, now time.Time) fsm.State {
	return e.sourceExecutor.ApplyDeEnforceSource(target, st, params, now)
}

func (e *brokeredActionExecutor) ApplySourceObserveOverride(target adapterruntime.SourceTarget, st fsm.State, params adapterruntime.EnforcementParams, now time.Time, reason string) (fsm.State, actions.ActionResult) {
	if target.SourceID == "" {
		target.SourceID = target.Subject.ID
	}
	resolution := actions.ActionResolution{
		ProposalID:       "operator-override",
		DecisionID:       "operator-" + now.UTC().Format(time.RFC3339Nano) + "-" + target.SourceID,
		Allowed:          true,
		RequestedAction:  "operator.observe",
		RequestedLevel:   "observe",
		ExecutableAction: "operator.observe",
		ExecutableLevel:  "observe",
		Target: actions.ActionTarget{
			Granularity: actions.TargetGranularitySource,
			Value:       target.SourceID,
			Attributes:  copyStringMap(target.Attributes),
		},
		DenyReason: reason,
		PolicyID:   "operator.override",
	}
	next, result := e.sourceExecutor.ApplySource(target, st, resolution, params, now)
	receipt := decision.NewEnforcementReceipt(resolution.DecisionID, e.nodeID, "kliq-source-pep", receiptStatusForActionResult(result))
	receipt.AppliedAt = now.UTC()
	receipt.Action = resolution.ExecutableAction
	receipt.Target = actions.TargetGranularitySource + ":" + target.SourceID
	if result.Reason != "" {
		receipt.SetMessage(result.Reason)
	} else if reason != "" {
		receipt.SetMessage(reason)
	}
	logEnforcementReceipt(receipt)
	e.persistReceipt(receipt)
	return next, result
}

func (e *brokeredActionExecutor) activeSourceState(sourceID string, now time.Time) fsm.State {
	if e == nil || e.sourcePEP == nil || sourceID == "" {
		return fsm.State{}
	}
	store, ok := e.store.(actionLeaseLookupStore)
	if !ok {
		return fsm.State{}
	}
	target := actions.TargetGranularitySource + ":" + sourceID
	adapterID := e.sourcePEP.AdapterID()
	var best decision.ActionLease
	bestWeight := 0
	for _, action := range brokeredSourceActionOrder {
		for _, level := range []string{"block", "hard", "soft"} {
			lease, ok, err := store.FindActiveActionLease(context.Background(), adapterID, target, action, level)
			if err != nil {
				kliqLog.Printf("WARN: lookup active lease for %s: %v", sourceID, err)
				continue
			}
			if !ok || (!lease.ExpiresAt.IsZero() && !lease.ExpiresAt.After(now.UTC())) {
				continue
			}
			weight := brokeredSourceLeaseStrength(lease.Action, lease.Level)
			if weight > bestWeight {
				best = lease
				bestWeight = weight
			}
		}
	}
	if bestWeight == 0 {
		return fsm.State{}
	}
	return fsm.State{
		Level:     actions.ParseFSMLevel(best.Level),
		ExpiresAt: best.ExpiresAt,
	}
}

var brokeredSourceActionOrder = []string{
	"enforce.traffic.drop",
	"enforce.access.deny",
	"enforce.network.quarantine",
	"enforce.identity.disable",
	"enforce.traffic.rate_limit",
}

func brokeredSourceLeaseStrength(action, level string) int {
	switch strings.TrimSpace(action) {
	case "enforce.traffic.drop", "enforce.access.deny", "enforce.network.quarantine", "enforce.identity.disable":
		return 300
	}
	switch strings.TrimSpace(level) {
	case "block":
		return 300
	case "hard":
		return 200
	case "soft":
		return 100
	default:
		return 0
	}
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
	e.relationshipPEP.applyMu.Lock()
	defer e.relationshipPEP.applyMu.Unlock()
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
	ctx.resolution = resolutionWithExecutionMetadata(ctx.resolution, ctx.params)
	e.sourcePEP.applyMu.Lock()
	defer e.sourcePEP.applyMu.Unlock()
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
	if applied.result.Status == "" {
		applied = sourceApplyOutcomeFromLease(ctx, lease)
	}
	return applied.state, applied.result
}

func sourceApplyOutcomeFromLease(ctx applyContext, lease decision.ActionLease) applyOutcome {
	state := ctx.state
	state.Level = actions.ParseFSMLevel(lease.Level)
	state.ExpiresAt = lease.ExpiresAt
	return applyOutcome{
		state: state,
		result: actions.ActionResult{
			ProposalID: ctx.resolution.ProposalID,
			DecisionID: ctx.resolution.DecisionID,
			Action:     lease.Action,
			Status:     "applied",
			Reason:     "lease renewed",
			AppliedAt:  ctx.now,
		},
	}
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

func resolutionWithExecutionMetadata(r actions.ActionResolution, params adapterruntime.EnforcementParams) actions.ActionResolution {
	metadata := copyAnyMap(r.Parameters)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["execution_dry_run"] = params.DryRun
	metadata["execution_soft_rate"] = params.SoftRate
	metadata["execution_soft_burst"] = params.SoftBurst
	metadata["execution_hard_rate"] = params.HardRate
	metadata["execution_hard_burst"] = params.HardBurst
	r.Parameters = metadata
	return r
}

func enforcementParamsForResolution(params adapterruntime.EnforcementParams, r actions.ActionResolution) adapterruntime.EnforcementParams {
	if r.TTL > 0 {
		switch actions.ParseFSMLevel(r.ExecutableLevel) {
		case fsm.LevelSoft:
			params.SoftTTL = r.TTL
		case fsm.LevelHard:
			params.HardTTL = r.TTL
		case fsm.LevelBlock:
			params.BlockTTL = r.TTL
		}
	}
	rate := uint64Param(r.Parameters, "rate_pps")
	if rate <= 0 {
		return params
	}
	burst := uint64Param(r.Parameters, "burst")
	if burst <= 0 {
		burst = rate * 2
	}
	switch actions.ParseFSMLevel(r.ExecutableLevel) {
	case fsm.LevelSoft:
		params.SoftRate = rate
		params.SoftBurst = burst
	case fsm.LevelHard:
		params.HardRate = rate
		params.HardBurst = burst
	}
	return params
}

func uint64Param(params map[string]any, key string) uint64 {
	if len(params) == 0 {
		return 0
	}
	switch value := params[key].(type) {
	case uint64:
		return value
	case uint:
		return uint64(value)
	case int:
		if value > 0 {
			return uint64(value)
		}
	case int64:
		if value > 0 {
			return uint64(value)
		}
	case float64:
		if value > 0 {
			return uint64(value)
		}
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err == nil {
			return parsed
		}
	}
	return 0
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

func receiptStatusForActionResult(result actions.ActionResult) decision.ReceiptStatus {
	switch result.Status {
	case "failed":
		return decision.StatusFailed
	case "denied", "skipped":
		return decision.StatusSkipped
	default:
		return decision.StatusApplied
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
	applyMu        sync.Mutex
	mu             sync.Mutex
	currentTokens  map[string]string
	active         *applyContext
	last           applyOutcome
}

func newBrokeredSourcePEP(sourceExecutor *actions.SourceActionExecutor, params func() adapterruntime.EnforcementParams) *brokeredSourcePEP {
	return &brokeredSourcePEP{
		sourceExecutor: sourceExecutor,
		params:         params,
		currentTokens:  map[string]string{},
	}
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
	p.setCurrentFencingToken(lease)
	return lease.FencingToken, nil
}

func (p *brokeredSourcePEP) CurrentFencingToken(_ context.Context, lease decision.ActionLease) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if token := p.currentTokens[leaseFencingKey(lease)]; token != "" {
		return token, nil
	}
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
	p.clearCurrentFencingToken(lease)
	return nil
}

func (p *brokeredSourcePEP) setCurrentFencingToken(lease decision.ActionLease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.currentTokens[leaseFencingKey(lease)] = lease.FencingToken
}

func (p *brokeredSourcePEP) clearCurrentFencingToken(lease decision.ActionLease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := leaseFencingKey(lease)
	if p.currentTokens[key] == lease.FencingToken {
		delete(p.currentTokens, key)
	}
}

type brokeredRelationshipPEP struct {
	pep     adapterruntime.RelationshipPEP
	applyMu sync.Mutex
	mu      sync.Mutex
	tokens  map[string]string
	active  *adapterruntime.RelationshipTarget
	last    actions.ActionResult
}

func newBrokeredRelationshipPEP(pep adapterruntime.RelationshipPEP) *brokeredRelationshipPEP {
	return &brokeredRelationshipPEP{pep: pep, tokens: map[string]string{}}
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
	p.setCurrentFencingToken(lease)
	return lease.FencingToken, nil
}

func (p *brokeredRelationshipPEP) CurrentFencingToken(_ context.Context, lease decision.ActionLease) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if token := p.tokens[leaseFencingKey(lease)]; token != "" {
		return token, nil
	}
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
	if err := p.pep.AllowRelationship(target); err != nil {
		return err
	}
	p.clearCurrentFencingToken(lease)
	return nil
}

func (p *brokeredRelationshipPEP) setCurrentFencingToken(lease decision.ActionLease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[leaseFencingKey(lease)] = lease.FencingToken
}

func (p *brokeredRelationshipPEP) clearCurrentFencingToken(lease decision.ActionLease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := leaseFencingKey(lease)
	if p.tokens[key] == lease.FencingToken {
		delete(p.tokens, key)
	}
}

func leaseFencingKey(lease decision.ActionLease) string {
	if lease.Target != "" {
		return lease.Target
	}
	target := actionbroker.TargetFromLease(lease)
	if target.Granularity != "" {
		return target.Granularity + ":" + target.Value
	}
	return target.Value
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
