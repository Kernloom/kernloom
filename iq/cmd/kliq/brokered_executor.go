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
	shieldclient "github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	shieldpep "github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

type brokeredActionExecutor struct {
	legacy *actions.ShieldActionExecutor
	broker *actionbroker.Broker
	pep    *brokeredFSMPEP
}

func newBrokeredActionExecutor(legacy *actions.ShieldActionExecutor, broker *actionbroker.Broker, pep *brokeredFSMPEP) *brokeredActionExecutor {
	return &brokeredActionExecutor{legacy: legacy, broker: broker, pep: pep}
}

func (e *brokeredActionExecutor) AddSidecar(s actions.PEPSidecar) {
	e.legacy.AddSidecar(s)
}

func (e *brokeredActionExecutor) Apply4(ip [4]byte, st fsm.State, r actions.ActionResolution, params shieldpep.EnforcementParams, now time.Time) (fsm.State, actions.ActionResult) {
	if !shouldBrokerLease(r) {
		return e.legacy.Apply4(ip, st, r, params, now)
	}
	return e.applyBrokered(applyContext{family: 4, ip4: ip, state: st, resolution: r, params: params, now: now})
}

func (e *brokeredActionExecutor) Apply6(ip [16]byte, st fsm.State, r actions.ActionResolution, params shieldpep.EnforcementParams, now time.Time) (fsm.State, actions.ActionResult) {
	if !shouldBrokerLease(r) {
		return e.legacy.Apply6(ip, st, r, params, now)
	}
	return e.applyBrokered(applyContext{family: 6, ip6: ip, state: st, resolution: r, params: params, now: now})
}

func (e *brokeredActionExecutor) ApplyDeEnforce4(ip [4]byte, st fsm.State, params shieldpep.EnforcementParams, now time.Time) fsm.State {
	return e.legacy.ApplyDeEnforce4(ip, st, params, now)
}

func (e *brokeredActionExecutor) ApplyDeEnforce6(ip [16]byte, st fsm.State, params shieldpep.EnforcementParams, now time.Time) fsm.State {
	return e.legacy.ApplyDeEnforce6(ip, st, params, now)
}

func (e *brokeredActionExecutor) ApplyTuple4(key shieldclient.Edge4Key, r actions.ActionResolution, now time.Time) actions.ActionResult {
	return e.legacy.ApplyTuple4(key, r, now)
}

func (e *brokeredActionExecutor) applyBrokered(ctx applyContext) (fsm.State, actions.ActionResult) {
	e.pep.begin(ctx)
	lease, receipt, err := e.broker.Apply(context.Background(), ctx.resolution)
	applied := e.pep.finish()
	if receipt != nil {
		logEnforcementReceipt(receipt)
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
	family     int
	ip4        [4]byte
	ip6        [16]byte
	state      fsm.State
	resolution actions.ActionResolution
	params     shieldpep.EnforcementParams
	now        time.Time
}

type applyOutcome struct {
	state  fsm.State
	result actions.ActionResult
}

type brokeredFSMPEP struct {
	legacy *actions.ShieldActionExecutor
	active *applyContext
	last   applyOutcome
}

func newBrokeredFSMPEP(legacy *actions.ShieldActionExecutor) *brokeredFSMPEP {
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
	switch p.active.family {
	case 4:
		st, result := p.legacy.Apply4(p.active.ip4, p.active.state, p.active.resolution, p.active.params, p.active.now)
		p.last = applyOutcome{state: st, result: result}
	case 6:
		st, result := p.legacy.Apply6(p.active.ip6, p.active.state, p.active.resolution, p.active.params, p.active.now)
		p.last = applyOutcome{state: st, result: result}
	default:
		return "", fmt.Errorf("unsupported IP family %d", p.active.family)
	}
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
