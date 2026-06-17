// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package relationshiplearner_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/relationship"
	rl "github.com/kernloom/kernloom/pkg/relationshiplearner"
)

func testCfg() rl.Config {
	cfg := rl.DefaultConfig("node-1")
	cfg.Promotion = rl.PromotionConfig{
		MinSeenCount:       3,
		MinDistinctWindows: 2,
		MinAge:             0, // no age gate for tests
	}
	return cfg
}

func candidate(subj, pred, obj string) relationship.Relationship {
	return relationship.Relationship{
		NodeID:          "node-1",
		SubjectEntityID: subj,
		Predicate:       pred,
		ObjectEntityID:  obj,
		SeenCount:       1,
		DistinctWindows: 1,
		FirstSeenAt:     time.Now(),
		LastSeenAt:      time.Now(),
	}
}

func TestLearner_PromotesAfterThreshold(t *testing.T) {
	l := rl.New(testCfg(), nil, nil, nil)
	ctx := context.Background()

	r := candidate("src-1", "network.connects_to", "dst-1")
	// Need MinSeenCount=3, MinDistinctWindows=2
	l.Learn(ctx, []relationship.Relationship{r})
	l.Learn(ctx, []relationship.Relationship{r})
	l.Learn(ctx, []relationship.Relationship{r})

	rels := l.List("network.connects_to", "")
	if len(rels) != 1 {
		t.Fatalf("want 1 relationship, got %d", len(rels))
	}
	if rels[0].State != relationship.StateLearned {
		t.Errorf("want learned, got %s", rels[0].State)
	}
}

func TestLearner_CandidateBeforeThreshold(t *testing.T) {
	l := rl.New(testCfg(), nil, nil, nil)
	ctx := context.Background()

	r := candidate("src-2", "network.connects_to", "dst-2")
	l.Learn(ctx, []relationship.Relationship{r}) // single observation

	rels := l.List("", "candidate")
	if len(rels) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(rels))
	}
}

func TestLearner_DeduplicatesKey(t *testing.T) {
	l := rl.New(testCfg(), nil, nil, nil)
	ctx := context.Background()

	r := candidate("src-3", "http.calls", "dst-3")
	for i := 0; i < 5; i++ {
		l.Learn(ctx, []relationship.Relationship{r})
	}
	if l.Len() != 1 {
		t.Errorf("expected 1 entry (deduplication), got %d", l.Len())
	}
}

func TestLearner_FreezeEmitsNoSignalWithoutPublisher(t *testing.T) {
	cfg := testCfg()
	cfg.Mode = rl.ModeFrozenObserve
	l := rl.New(cfg, nil, nil, nil) // no publisher — must not panic
	ctx := context.Background()

	r := candidate("src-4", "network.connects_to", "dst-4")
	// Should not panic even without a publisher.
	l.Learn(ctx, []relationship.Relationship{r})
}

func TestLearner_FlushDirty_NoStore(t *testing.T) {
	l := rl.New(testCfg(), nil, nil, nil)
	ctx := context.Background()
	l.Learn(ctx, []relationship.Relationship{candidate("src-5", "ziti.dials", "dst-5")})

	n, err := l.FlushDirty(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("no store: expected 0 flushed, got %d", n)
	}
}

func TestLearner_CardinalityGuard(t *testing.T) {
	cfg := testCfg()
	cfg.MaxCachedRelationships = 2
	l := rl.New(cfg, nil, nil, nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		r := candidate(fmt.Sprintf("src-%d", i), "network.connects_to", "dst")
		l.Learn(ctx, []relationship.Relationship{r})
	}
	if l.Len() > 2 {
		t.Errorf("cardinality guard: want ≤2, got %d", l.Len())
	}
}
