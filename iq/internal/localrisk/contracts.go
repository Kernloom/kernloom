// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package localrisk

import contracts "github.com/kernloom/kernloom-contracts"

func (a Assessment) ToContract(subject contracts.EntityRef, nodeID string) contracts.LocalRiskAssessment {
	contributions := make([]contracts.RiskContribution, 0, len(a.Contributions))
	for _, c := range a.Contributions {
		contributions = append(contributions, contracts.RiskContribution{
			SignalID:   c.SignalID,
			SignalType: c.SignalType,
			Domain:     c.Domain,
			Score:      c.Score,
			Confidence: c.Confidence,
			Weight:     c.Weight,
		})
	}
	return contracts.LocalRiskAssessment{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindLocalRiskAssessment,
		},
		Metadata: contracts.ObjectMeta{
			NodeID: nodeID,
		},
		Subject:       subject,
		Level:         contracts.RiskLevel(a.Level),
		Score:         a.Score,
		Confidence:    a.Confidence,
		Completeness:  a.Completeness,
		Domains:       append([]string(nil), a.Domains...),
		Contributions: contributions,
		MissingInputs: append([]string(nil), a.MissingInputs...),
		ValidUntil:    a.ValidUntil,
		Model:         a.Model,
	}
}
