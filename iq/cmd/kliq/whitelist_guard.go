// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"

	"github.com/kernloom/kernloom/pkg/core/learning"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

// whitelistAwareGuard wraps a learning.Guard and short-circuits to AllowLearning
// for any entity whose IP string is on the whitelist.  Used when --whitelist-learn=true.
type whitelistAwareGuard struct {
	inner learning.Guard
	wl    *whitelist
}

func newWhitelistAwareGuard(inner learning.Guard, wl *whitelist) learning.Guard {
	return &whitelistAwareGuard{inner: inner, wl: wl}
}

func (g *whitelistAwareGuard) CheckMetric(ctx context.Context, m learning.MetricCheck) learning.CheckResult {
	if g.wl.matchIPString(m.SubjectEntityID) {
		return learning.CheckResult{Decision: learning.AllowLearning}
	}
	return g.inner.CheckMetric(ctx, m)
}

func (g *whitelistAwareGuard) CheckRelationship(ctx context.Context, r learning.RelationshipCheck) learning.CheckResult {
	if g.wl.matchIPString(r.Relationship.SubjectEntityID) {
		return learning.CheckResult{Decision: learning.AllowLearning}
	}
	return g.inner.CheckRelationship(ctx, r)
}

func (g *whitelistAwareGuard) AddExclusion(ctx context.Context, e learning.Exclusion) error {
	return g.inner.AddExclusion(ctx, e)
}

func (g *whitelistAwareGuard) RevokeExclusion(ctx context.Context, id string) error {
	return g.inner.RevokeExclusion(ctx, id)
}

func (g *whitelistAwareGuard) IsExcluded(ctx context.Context, entityID string, dim learning.AppliesTo) bool {
	if g.wl.matchIPString(entityID) {
		return false
	}
	return g.inner.IsExcluded(ctx, entityID, dim)
}

// storeAsGuard bridges *sqlite.Store to learning.Guard for the AddExclusion path
// (called from the decision engine when a block/RL action is taken).
// Implements only AddExclusion; the full guard logic lives in learningguard.Guard.
type storeAddExclusionBridge struct {
	learning.Guard
	store *sqlite.Store
}
