// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

// runtimePDPRunner manages the new contracts-based RuntimePDP path.
//
// Modes:
//   - shadow (default): evaluates and logs RuntimePDP decisions, no enforcement.
//   - active: RuntimePDP is authoritative; decisions become real ActionProposals
//     fed into the broker path.
//
// The FSM remains available as a signal/hysteresis fact producer. It does not
// own network enforcement decisions; it supplies proposed levels to RuntimePDP.
//
// Cutover sequence (Step 5):
//  1. Run in shadow mode to observe RuntimePDP decisions without PEP effects.
//  2. Validate policy coverage in staging.
//  3. Set --runtime-pdp-mode=active to let RuntimePDP emit broker actions.

import (
	"context"
	"log"
	"sync"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/localrisk"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// runtimePDPMode controls whether the RuntimePDP enforces or just observes.
type runtimePDPMode string

const (
	// PDPModeShadow — evaluate and log only; no enforcement action is emitted.
	PDPModeShadow runtimePDPMode = "shadow"
	// PDPModeActive — evaluate and emit ActionProposals; FSM supplies facts only.
	PDPModeActive runtimePDPMode = "active"
)

// shadowPDPRunner (renamed internally but kept as shadowPDPRunner for backward compat
// in kliq.go wiring) manages the RuntimePDP lifecycle and evaluation.
type shadowPDPRunner struct {
	mu        sync.RWMutex
	pdp       *runtimepdp.PDP
	nodeID    string
	mode      runtimePDPMode
	logger    *log.Logger
	proposals chan<- actions.ActionProposal // non-nil in active mode
}

func newShadowPDPRunner(nodeID string, logger *log.Logger) *shadowPDPRunner {
	return &shadowPDPRunner{
		nodeID: nodeID,
		mode:   PDPModeShadow,
		logger: logger,
	}
}

// SetMode switches between shadow and active enforcement.
// Safe to call at any time.
func (s *shadowPDPRunner) SetMode(mode runtimePDPMode, proposals chan<- actions.ActionProposal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.proposals = proposals
	s.logger.Printf("[runtime-pdp] mode set to %s", mode)
}

// UpdatePack (re)compiles the RuntimePDP from a new RuntimePolicyPack.
// Called from managed mode when a bundle is activated.
func (s *shadowPDPRunner) UpdatePack(pack contracts.RuntimePolicyPack) error {
	pdp, err := runtimepdp.Compile(pack)
	if err != nil {
		s.logger.Printf("[runtime-pdp] compile error: %v", err)
		return err
	}
	s.mu.Lock()
	s.pdp = pdp
	s.mu.Unlock()
	s.logger.Printf("[runtime-pdp] pack loaded: %d rules", len(pack.Spec.Rules))
	return nil
}

// current returns the active PDP or nil if none is loaded.
func (s *shadowPDPRunner) current() *runtimepdp.PDP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pdp
}

func (s *shadowPDPRunner) getMode() (runtimePDPMode, chan<- actions.ActionProposal) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode, s.proposals
}

// startShadowPDP launches the evaluation goroutine.
// It subscribes independently to the bus, accumulates signals in a 5-second
// window, builds a LocalRiskAssessment, and calls the RuntimePDP.
//
// In shadow mode: decisions are logged only.
// In active mode: decisions become ActionProposals fed to the broker path.
func startShadowPDP(ctx context.Context, bus adapterruntime.EventBus, runner *shadowPDPRunner) {
	sigCh := bus.SubscribeSignals(256)
	go func() {
		windowDur := 5 * time.Second
		ticker := time.NewTicker(windowDur)
		defer ticker.Stop()

		buf := make(map[string][]signal.Signal)

		flush := func() {
			if len(buf) == 0 {
				return
			}
			pdp := runner.current()
			mode, proposals := runner.getMode()
			now := time.Now().UTC()

			for subjectID, sigs := range buf {
				assessments := localrisk.FromSignals(sigs, now, localrisk.DefaultConfig())
				for _, a := range assessments {
					if a.SubjectID != subjectID {
						continue
					}
					entityRef := contracts.EntityRef{
						Kind: "ip",
						ID:   subjectID,
					}
					lra := a.ToContract(entityRef, runner.nodeID)

					if pdp == nil {
						if a.Score >= 30 && mode == PDPModeShadow {
							runner.logger.Printf("[runtime-pdp:shadow] ASSESS subject=%s level=%s score=%d (no pack)",
								subjectID, a.Level, a.Score)
						}
						continue
					}

					dec, matched, err := pdp.Decide(runtimepdp.Input{
						NodeID:  runner.nodeID,
						Subject: entityRef,
						Risk:    lra,
						Now:     now,
					})
					if err != nil {
						runner.logger.Printf("[runtime-pdp] decide error subject=%s: %v", subjectID, err)
						continue
					}
					if !matched {
						continue
					}

					switch mode {
					case PDPModeShadow:
						runner.logger.Printf("[runtime-pdp:shadow] DECISION subject=%s effect=%s risk=%s(%.2f) score=%d reasons=%v",
							subjectID, dec.Effect, lra.Level, lra.Confidence, lra.Score, dec.ReasonCodes)

					case PDPModeActive:
						runner.logger.Printf("[runtime-pdp:active] DECISION subject=%s effect=%s risk=%s(%.2f) score=%d",
							subjectID, dec.Effect, lra.Level, lra.Confidence, lra.Score)

						if proposals != nil {
							prop, ok, reason := runtimeDecisionToActionProposal(dec, subjectID, lra.Confidence, now)
							if !ok {
								runner.logger.Printf("[runtime-pdp:active] decision skipped subject=%s reason=%s", subjectID, reason)
								continue
							}
							select {
							case proposals <- prop:
							default:
								runner.logger.Printf("[runtime-pdp:active] proposal channel full, dropping for %s", subjectID)
							}
						}
					}
				}
			}
			buf = make(map[string][]signal.Signal)
		}

		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case <-ticker.C:
				flush()
			case sig, ok := <-sigCh:
				if !ok {
					flush()
					return
				}
				if sig.Subject.ID != "" {
					buf[sig.Subject.ID] = append(buf[sig.Subject.ID], sig)
				}
			}
		}
	}()
}
