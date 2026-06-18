// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"testing"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
)

func TestRelationshipActionTargetFromAttributesUsesGenericDimensions(t *testing.T) {
	target, ok := relationshipActionTargetFromAttributes("subject-1", map[string]string{
		actions.TargetAttrTargetID:                  "service-1",
		actions.TargetAttrDimensionPrefix + "port":  "443",
		actions.TargetAttrDimensionPrefix + "proto": "tcp",
	})
	if !ok {
		t.Fatal("expected relationship target")
	}

	if target.PEP.SubjectID != "subject-1" {
		t.Fatalf("subject id: got %q", target.PEP.SubjectID)
	}
	if target.PEP.TargetID != "service-1" {
		t.Fatalf("target id: got %q", target.PEP.TargetID)
	}
	if target.PEP.Dimension["port"] != "443" || target.PEP.Dimension["proto"] != "tcp" {
		t.Fatalf("dimension not propagated: %#v", target.PEP.Dimension)
	}
	if target.Proposal.Value == "" || target.Label == "" {
		t.Fatal("expected canonical label/proposal value")
	}
	if target.Proposal.Attributes[actions.TargetAttrDimensionPrefix+"port"] != "443" {
		t.Fatalf("proposal dimension missing: %#v", target.Proposal.Attributes)
	}
}

func TestRelationshipActionTargetFromAttributesRequiresTargetOrDimension(t *testing.T) {
	if _, ok := relationshipActionTargetFromAttributes("subject-1", map[string]string{"predicate": "ziti.dials"}); ok {
		t.Fatal("expected no target without target_id or dimensions")
	}
}

type testRelationshipPEP struct {
	available bool
	setErr    error
	denyErr   error
	allowErr  error

	setCalls   int
	denyCalls  int
	allowCalls int
}

func (p *testRelationshipPEP) RelationshipAvailable() bool { return p.available }
func (p *testRelationshipPEP) SetRelationshipEnforcement(bool) error {
	p.setCalls++
	return p.setErr
}
func (p *testRelationshipPEP) DenyRelationship(adapterruntime.RelationshipTarget) error {
	p.denyCalls++
	return p.denyErr
}
func (p *testRelationshipPEP) AllowRelationship(adapterruntime.RelationshipTarget) error {
	p.allowCalls++
	return p.allowErr
}

func TestRelationshipPEPGroupSucceedsWhenAnyPEPApplies(t *testing.T) {
	failPEP := &testRelationshipPEP{available: true, denyErr: fmt.Errorf("wrong domain")}
	okPEP := &testRelationshipPEP{available: true}
	group := &relationshipPEPGroup{}
	group.Add("fail", failPEP, nil)
	group.Add("ok", okPEP, nil)

	err := group.DenyRelationship(adapterruntime.RelationshipTarget{
		RelationshipKey: adapterruntime.RelationshipKey{
			SubjectID: "source-1",
			Dimension: map[string]string{"port": "443", "proto": "tcp"},
		},
	})
	if err != nil {
		t.Fatalf("DenyRelationship: %v", err)
	}
	if failPEP.denyCalls != 1 || okPEP.denyCalls != 1 {
		t.Fatalf("deny calls: fail=%d ok=%d", failPEP.denyCalls, okPEP.denyCalls)
	}
}

func TestRelationshipPEPGroupFailsWhenAllAvailablePEPsFail(t *testing.T) {
	group := &relationshipPEPGroup{}
	group.Add("fail", &testRelationshipPEP{available: true, denyErr: fmt.Errorf("boom")}, nil)

	err := group.DenyRelationship(adapterruntime.RelationshipTarget{
		RelationshipKey: adapterruntime.RelationshipKey{SubjectID: "source-1", TargetID: "target-1"},
	})
	if err == nil {
		t.Fatal("expected error when all available relationship PEPs fail")
	}
}

func TestRelationshipPEPGroupRefreshesUnavailablePEPs(t *testing.T) {
	called := false
	group := &relationshipPEPGroup{}
	group.Add("needs-refresh", &testRelationshipPEP{available: false}, func() { called = true })

	group.RefreshUnavailable()
	if !called {
		t.Fatal("expected refresh callback")
	}
}
