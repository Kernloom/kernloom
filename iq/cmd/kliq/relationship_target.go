// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"strings"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

type relationshipActionTarget struct {
	PEP      adapterruntime.RelationshipTarget
	Proposal actions.ActionTarget
	Label    string
}

type relationshipPEPEntry struct {
	id      string
	pep     adapterruntime.RelationshipPEP
	refresh func()
}

type relationshipPEPGroup struct {
	entries []relationshipPEPEntry
}

func (g *relationshipPEPGroup) Add(id string, pep adapterruntime.RelationshipPEP, refresh func()) {
	if pep == nil {
		return
	}
	if id == "" {
		id = "relationship-pep"
	}
	g.entries = append(g.entries, relationshipPEPEntry{id: id, pep: pep, refresh: refresh})
}

func (g *relationshipPEPGroup) Len() int {
	if g == nil {
		return 0
	}
	return len(g.entries)
}

func (g *relationshipPEPGroup) RefreshUnavailable() {
	if g == nil {
		return
	}
	for _, entry := range g.entries {
		if entry.pep == nil || entry.pep.RelationshipAvailable() || entry.refresh == nil {
			continue
		}
		entry.refresh()
	}
}

func (g *relationshipPEPGroup) RelationshipAvailable() bool {
	if g == nil {
		return false
	}
	for _, entry := range g.entries {
		if entry.pep != nil && entry.pep.RelationshipAvailable() {
			return true
		}
	}
	return false
}

func (g *relationshipPEPGroup) SetRelationshipEnforcement(on bool) error {
	if g == nil {
		return fmt.Errorf("relationship pep unavailable")
	}
	attempts, successes := 0, 0
	var failures []string
	for _, entry := range g.entries {
		if entry.pep == nil || !entry.pep.RelationshipAvailable() {
			continue
		}
		attempts++
		if err := entry.pep.SetRelationshipEnforcement(on); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", entry.id, err))
			continue
		}
		successes++
	}
	if successes > 0 {
		logRelationshipPEPFailures("set-enforcement", failures)
		return nil
	}
	if attempts == 0 && !on {
		return nil
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return fmt.Errorf("relationship pep unavailable")
}

func (g *relationshipPEPGroup) DenyRelationship(target adapterruntime.RelationshipTarget) error {
	return g.applyRelationship("deny", target, func(pep adapterruntime.RelationshipPEP) error {
		return pep.DenyRelationship(target)
	})
}

func (g *relationshipPEPGroup) AllowRelationship(target adapterruntime.RelationshipTarget) error {
	return g.applyRelationship("allow", target, func(pep adapterruntime.RelationshipPEP) error {
		return pep.AllowRelationship(target)
	})
}

func (g *relationshipPEPGroup) applyRelationship(op string, target adapterruntime.RelationshipTarget, apply func(adapterruntime.RelationshipPEP) error) error {
	if g == nil {
		return fmt.Errorf("relationship pep unavailable")
	}
	attempts, successes := 0, 0
	var failures []string
	for _, entry := range g.entries {
		if entry.pep == nil || !entry.pep.RelationshipAvailable() {
			continue
		}
		attempts++
		if err := apply(entry.pep); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", entry.id, err))
			continue
		}
		successes++
	}
	if successes > 0 {
		logRelationshipPEPFailures(op+" "+target.Canonical(), failures)
		return nil
	}
	if attempts == 0 {
		return fmt.Errorf("relationship pep unavailable")
	}
	return fmt.Errorf("%s", strings.Join(failures, "; "))
}

func logRelationshipPEPFailures(context string, failures []string) {
	if len(failures) == 0 {
		return
	}
	kliqLog.Printf("relationship PEP partial failure %s: %s", context, strings.Join(failures, "; "))
}

func relationshipActionTargetFromSignal(sig signal.Signal) (relationshipActionTarget, bool) {
	return relationshipActionTargetFromAttributes(sig.Subject.ID, sig.Attributes)
}

func relationshipActionTargetFromAttributes(sourceID string, attrs map[string]string) (relationshipActionTarget, bool) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return relationshipActionTarget{}, false
	}
	key := adapterruntime.RelationshipKey{
		SubjectID: sourceID,
		TargetID:  relationshipTargetID(attrs),
		Dimension: relationshipDimensions(attrs),
	}
	if key.TargetID == "" && len(key.Dimension) == 0 {
		return relationshipActionTarget{}, false
	}
	label := key.Canonical()
	return relationshipActionTarget{
		PEP: adapterruntime.RelationshipTarget{
			RelationshipKey: key,
			Attributes:      cloneRelationshipAttrs(attrs),
		},
		Proposal: actions.ActionTarget{
			Granularity: actions.TargetGranularityRelationship,
			Value:       label,
			Attributes:  relationshipProposalAttributes(key),
		},
		Label: label,
	}, true
}

func relationshipTargetID(attrs map[string]string) string {
	for _, key := range []string{
		actions.TargetAttrTargetID,
		"object_id",
		"object_entity_id",
		"target_id",
	} {
		if v := strings.TrimSpace(attrs[key]); v != "" {
			return v
		}
	}
	return ""
}

func relationshipDimensions(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range attrs {
		if !strings.HasPrefix(k, actions.TargetAttrDimensionPrefix) {
			continue
		}
		name := strings.TrimPrefix(k, actions.TargetAttrDimensionPrefix)
		if name == "" {
			continue
		}
		if value := strings.TrimSpace(v); value != "" {
			out[name] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func relationshipProposalAttributes(key adapterruntime.RelationshipKey) map[string]string {
	attrs := map[string]string{
		actions.TargetAttrSubjectID: key.SubjectID,
	}
	if key.TargetID != "" {
		attrs[actions.TargetAttrTargetID] = key.TargetID
	}
	for k, v := range key.Dimension {
		attrs[actions.TargetAttrDimensionPrefix+k] = v
	}
	return attrs
}

func cloneRelationshipAttrs(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	return out
}
