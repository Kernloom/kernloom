// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/relationship"
)

func TestSortRelationships(t *testing.T) {
	rels := []relationship.Relationship{
		{SubjectEntityID: "src-b", ObjectEntityID: "obj-b", Predicate: "ziti.dials", SeenCount: 2, LastSeenAt: time.Unix(20, 0)},
		{SubjectEntityID: "src-a", ObjectEntityID: "obj-a", Predicate: "http.calls", SeenCount: 9, LastSeenAt: time.Unix(10, 0)},
	}

	key, desc, err := parseRelationshipSortSpec("-seen")
	if err != nil {
		t.Fatalf("parse sort: %v", err)
	}
	sortRelationships(rels, key, desc)
	if rels[0].SubjectEntityID != "src-a" {
		t.Fatalf("expected src-a first by descending seen count, got %s", rels[0].SubjectEntityID)
	}

	key, desc, err = parseRelationshipSortSpec("last:desc")
	if err != nil {
		t.Fatalf("parse sort: %v", err)
	}
	sortRelationships(rels, key, desc)
	if rels[0].SubjectEntityID != "src-b" {
		t.Fatalf("expected src-b first by last seen desc, got %s", rels[0].SubjectEntityID)
	}
}
