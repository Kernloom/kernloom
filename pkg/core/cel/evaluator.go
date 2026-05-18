// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package cel compiles and evaluates CEL expressions from v1.2 LocalPolicyPack
// rules. Each rule's when.expression is compiled once at pack-load time into a
// cel.Program and evaluated per-source-IP on every KLIQ tick.
//
// CEL variable model:
//
//	vars — map(string, dyn) populated from the rule's named bindings.
//	        Signal bindings resolve to float64 (live metric for this tick).
//	        Baseline bindings resolve to float64 or string (for "phase").
//
// Example expression (from mitigate-connection-spike policy):
//
//	(vars.src_phase == "stable" && vars.src_confidence >= 0.7 && vars.current_cps > vars.src_upper * 1.5)
//	|| (vars.src_confidence < 0.7 && vars.current_cps > vars.global_upper * 1.5)
package cel

import (
	"fmt"

	"github.com/google/cel-go/cel"

	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
)

// SourceSignals holds the per-source signal values available for CEL binding
// resolution on a single KLIQ tick.
type SourceSignals struct {
	// Live signal values measured this tick.
	PPS      float64
	BPS      float64
	SynRate  float64
	ScanRate float64
	CPS      float64 // connections per second (0 if not tracked separately)

	// Anomaly scoring outputs.
	AnomalyScore      float64 // 0.0–1.0
	AnomalyConfidence float64 // 0.0–1.0

	// Per-source baseline profile (from sourcebaseline.Cache).
	HasBaseline bool
	EWMAPPS     float64 // expected PPS (EWMA)
	EWMABPS     float64 // expected BPS (EWMA)
	EWMASyn     float64 // expected SYN/s (EWMA)
	Confidence  float64 // 0.0–1.0
	Promoted    bool    // true once source has enough observations

	// Global trigger values (used as fallback when per-source baseline is not stable).
	GlobalTrigPPS float64
	GlobalTrigBPS float64
}

// Phase returns "stable" when the source has a promoted, confident baseline,
// "learning" otherwise. Matches the baseline.phase signal values.
func (s *SourceSignals) Phase() string {
	if s.HasBaseline && s.Promoted && s.Confidence >= 0.4 {
		return "stable"
	}
	return "learning"
}

// CompiledRule is a CEL-compiled pack rule ready for per-tick evaluation.
type CompiledRule struct {
	Name       string
	program    cel.Program
	bindings   map[string]corepolicy.Binding
	Capability string // then.capability (determines enforcement action)
	Level      string // "soft" | "hard" | "block" (derived from capability)
	TTL        string // then.ttl
	Params     map[string]string
}

// Evaluate resolves bindings from sigs and evaluates the CEL expression.
// Returns true when the rule's condition is met for this source this tick.
// buf is a caller-supplied map reused across calls to avoid per-source allocation.
func (r *CompiledRule) Evaluate(sigs *SourceSignals, buf map[string]any) bool {
	r.resolveVarsInto(sigs, buf)
	out, _, err := r.program.Eval(map[string]any{"vars": buf})
	if err != nil {
		return false
	}
	b, ok := out.Value().(bool)
	return ok && b
}

// resolveVarsInto populates buf from the rule's bindings and sigs, reusing the map.
func (r *CompiledRule) resolveVarsInto(s *SourceSignals, buf map[string]any) {
	for name, b := range r.bindings {
		buf[name] = resolveBinding(&b, s)
	}
}

// resolveBinding resolves a single binding to its current value.
// Numeric signals return float64; "phase" returns string.
func resolveBinding(b *corepolicy.Binding, s *SourceSignals) any {
	switch b.From {
	case "signal":
		switch b.ID {
		case "network.metric.packets_per_second":
			return s.PPS
		case "network.metric.bytes_per_second":
			return s.BPS
		case "network.metric.syn_per_second":
			return s.SynRate
		case "network.metric.connections_per_second":
			return s.CPS
		case "anomaly.score", "anomaly.score.combined":
			return s.AnomalyScore
		case "anomaly.confidence", "anomaly.state.confidence":
			return s.AnomalyConfidence
		}

	case "baseline":
		if b.Statistic == "phase" {
			return s.Phase()
		}
		sig := b.Signal
		scope := b.Scope
		switch b.Statistic {
		case "upper_bound", "expected":
			// For per-source scope: use the source's EWMA as the expected value.
			// The CEL expression applies its own multiplier (e.g. * 1.5) on top.
			// For global scope: use the global trigger as a proxy.
			if scope == "src_ip" {
				switch sig {
				case "network.metric.packets_per_second":
					return s.EWMAPPS
				case "network.metric.bytes_per_second":
					return s.EWMABPS
				case "network.metric.syn_per_second":
					return s.EWMASyn
				}
			}
			if scope == "global" {
				switch sig {
				case "network.metric.packets_per_second":
					return s.GlobalTrigPPS
				case "network.metric.bytes_per_second":
					return s.GlobalTrigBPS
				}
			}
		case "confidence":
			return s.Confidence
		case "deviation_ratio":
			switch sig {
			case "network.metric.packets_per_second":
				if s.EWMAPPS > 0 {
					return s.PPS / s.EWMAPPS
				}
			case "network.metric.bytes_per_second":
				if s.EWMABPS > 0 {
					return s.BPS / s.EWMABPS
				}
			}
		}
	}
	return 0.0
}

// shared CEL environment — one instance, vars is map(string, dyn).
var celEnv *cel.Env

func init() {
	var err error
	celEnv, err = cel.NewEnv(
		cel.Variable("vars", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		panic(fmt.Sprintf("cel: failed to create environment: %v", err))
	}
}

// Compile parses and compiles a CEL WhenSpec into a CompiledRule.
// Returns an error when the expression is syntactically invalid.
// Binding resolution is checked structurally but full type-checking is deferred
// (type-checking against registry types is planned for a later phase).
func Compile(name, capability, level, ttl string, params map[string]string, when corepolicy.WhenSpec) (*CompiledRule, error) {
	if when.Language != "cel" || when.Expression == "" {
		return nil, fmt.Errorf("cel: rule %q: not a CEL when block", name)
	}

	ast, iss := celEnv.Parse(when.Expression)
	if iss.Err() != nil {
		return nil, fmt.Errorf("cel: rule %q: parse expression: %w", name, iss.Err())
	}
	prog, err := celEnv.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("cel: rule %q: build program: %w", name, err)
	}

	return &CompiledRule{
		Name:       name,
		program:    prog,
		bindings:   when.Bindings,
		Capability: capability,
		Level:      level,
		TTL:        ttl,
		Params:     params,
	}, nil
}
