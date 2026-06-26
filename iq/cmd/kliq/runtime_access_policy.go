// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
)

type accessPolicyReconciler struct {
	pep      adapterruntime.AccessPolicyPEP
	get      func() []contracts.RuntimeAccessPolicy
	interval time.Duration
	dryRun   bool

	lastHash string
}

func startAccessPolicyReconciler(ctx context.Context, pep adapterruntime.AccessPolicyPEP, get func() []contracts.RuntimeAccessPolicy, interval time.Duration, dryRun bool) {
	if interval < 0 {
		interval = 0
	}
	r := &accessPolicyReconciler{
		pep:      pep,
		get:      get,
		interval: interval,
		dryRun:   dryRun,
	}
	r.reconcile(ctx, "startup")
	if interval == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.reconcile(ctx, "periodic")
			}
		}
	}()
}

func (r *accessPolicyReconciler) reconcile(ctx context.Context, reason string) {
	if r == nil || r.get == nil {
		return
	}
	policies := normalizeRuntimeAccessPolicies(r.get())
	if len(policies) == 0 {
		r.lastHash = ""
		return
	}
	if r.pep == nil {
		if r.lastHash == "" {
			kliqEventf(kliqLogInfo, "access", "policy sync degraded policies=%d reason=no_access_policy_pep", len(policies))
			r.lastHash = runtimeAccessPolicyHash(policies)
		}
		return
	}
	hash := runtimeAccessPolicyHash(policies)
	if hash != r.lastHash {
		kliqEventf(kliqLogInfo, "access", "policy sync reason=%s policies=%d hash=%s", reason, len(policies), shortHash(hash))
		for _, policy := range policies {
			r.apply(ctx, policy)
		}
		r.lastHash = hash
	}
	for _, policy := range policies {
		drift, err := r.pep.CheckAccessPolicyDrift(ctx, policy)
		if err != nil {
			kliqEventf(kliqLogInfo, "warn", "ACCESS drift policy=%s check_failed=%v", policy.ID, err)
			continue
		}
		if drift.InSync {
			continue
		}
		kliqEventf(kliqLogInfo, "drift", "ACCESS policy=%s reason=%s native=%v; reapplying",
			policy.ID, drift.Reason, drift.NativeEnforcement)
		r.apply(ctx, policy)
	}
}

func (r *accessPolicyReconciler) apply(ctx context.Context, policy contracts.RuntimeAccessPolicy) {
	if r == nil || r.pep == nil {
		return
	}
	result, err := r.pep.ApplyAccessPolicy(ctx, policy, adapterruntime.AccessPolicyApplyOptions{
		DryRun: r.dryRun,
		Now:    time.Now().UTC(),
	})
	if err != nil {
		kliqEventf(kliqLogInfo, "warn", "ACCESS apply policy=%s failed=%v", policy.ID, err)
		return
	}
	warn := ""
	if len(result.Warnings) > 0 {
		warn = " warnings=" + strings.Join(result.Warnings, ",")
	}
	kliqEventf(kliqLogInfo, "access", "apply policy=%s subject=%s:%s resource=%s:%s effect=%s status=%s native=%v%s",
		policy.ID, policy.Subject.Type, policy.Subject.Ref, policy.Resource.Type, policy.Resource.Ref,
		policy.Effect, result.Status, result.NativeEnforcement, warn)
}

func normalizeRuntimeAccessPolicies(in []contracts.RuntimeAccessPolicy) []contracts.RuntimeAccessPolicy {
	out := make([]contracts.RuntimeAccessPolicy, 0, len(in))
	for _, policy := range in {
		policy.ID = strings.TrimSpace(policy.ID)
		if policy.ID == "" {
			continue
		}
		out = append(out, policy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func runtimeAccessPolicyHash(policies []contracts.RuntimeAccessPolicy) string {
	raw, err := json.Marshal(policies)
	if err != nil {
		return fmt.Sprintf("marshal-error:%v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
