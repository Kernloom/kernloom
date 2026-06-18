// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package reason

import (
	"testing"
)

func TestHeuristicReasonCodes(t *testing.T) {
	codes := []string{
		PPSHigh, PPSVeryHigh,
		SYNRateHigh, SYNRateVeryHigh,
		ScanRateHigh, PortScanSuspected,
		RateLimitDropsSustained, RateLimitDropsResume,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("heuristic reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestGraphReasonCodes(t *testing.T) {
	codes := []string{
		GraphNewEdgeAfterFreeze, GraphNewRelationshipDim, GraphNewPeer,
		GraphDirectionChange, GraphMetricDeviation, GraphTimeWindowDeviation,
		GraphEdgeCandidate, GraphEdgeLearned, GraphEdgeFrozen, GraphEdgeMetricPeakExceeds,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("graph reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestTrustReasonCodes(t *testing.T) {
	codes := []string{
		TrustAttestationOK, TrustAttestationFailed,
		TrustAssertionExpired, TrustAssertionFresh,
		TrustIMAViolation, TrustPCRMismatch,
		TrustTPMUnavailable, TrustMode,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("trust reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestPolicyReasonCodes(t *testing.T) {
	codes := []string{
		PolicyPackSignatureOK, PolicyPackSignatureBad,
		PolicyPackRollbackAttempt, PolicyPackExpired,
		PolicyPackCapabilityMissing, PolicyPackTargetMismatch,
		PolicyViolation,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("policy reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestCampaignReasonCodes(t *testing.T) {
	codes := []string{
		CampaignDistributedScan, CampaignWormlikeBehavior,
		CampaignDataExfil, GlobalRiskSignal,
		FleetAnomalyDetected, ServiceAnomalyDetected,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("campaign reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestAutonomyReasonCodes(t *testing.T) {
	codes := []string{
		LocalAutonomyAllowed, LocalAutonomyDenied,
		LocalAutonomyThrottled, SeverityBelowThreshold,
		TrustGateFailed,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("autonomy reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestExemptionReasonCodes(t *testing.T) {
	codes := []string{
		WhitelistMatch, FeedbackMatch, ExemptionMatch,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("exemption reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestEnforcementStateReasonCodes(t *testing.T) {
	codes := []string{
		EnforcementStateObserve, EnforcementStateSoftLimit,
		EnforcementStateHardLimit, EnforcementStateBlocked,
		EnforcementStateCooldown, EnforcementStateExpired,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("enforcement state reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestBootstrapReasonCodes(t *testing.T) {
	codes := []string{
		BootstrapPhase1, BootstrapPhase2, BootstrapPhase3,
		AutoTuneApplied, AutoTuneSkipped, LowConfidenceData,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("bootstrap reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestHealthReasonCodes(t *testing.T) {
	codes := []string{
		AdapterHealthy, AdapterDegraded, AdapterFailing,
		MapReadError, StateRestored, StateNotAvailable,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("health reason code is empty")
		}
		if !IsValidReasonCode(code) {
			t.Errorf("expected %s to be valid", code)
		}
	}
}

func TestReasonCodeNaming(t *testing.T) {
	// Reason codes should use snake_case
	codes := []string{
		PPSHigh, SYNRateHigh, GraphNewEdgeAfterFreeze,
		TrustAttestationOK, PolicyPackSignatureOK,
		CampaignDistributedScan, LocalAutonomyAllowed,
	}

	for _, code := range codes {
		if code == "" {
			t.Errorf("reason code is empty")
		}

		// Check for reasonable characters (letters, numbers, underscores)
		for _, ch := range code {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_') {
				t.Errorf("reason code %s contains invalid character: %c", code, ch)
			}
		}
	}
}

func TestIsValidReasonCode(t *testing.T) {
	if !IsValidReasonCode("some_valid_code") {
		t.Error("expected valid reason code")
	}

	if IsValidReasonCode("") {
		t.Error("expected empty string to be invalid")
	}
}

func TestReasonCodeUniqueness(t *testing.T) {
	// Collect all reason code constants
	allCodes := []string{
		PPSHigh, PPSVeryHigh,
		SYNRateHigh, SYNRateVeryHigh,
		ScanRateHigh, PortScanSuspected,
		RateLimitDropsSustained, RateLimitDropsResume,
		GraphNewEdgeAfterFreeze, GraphNewRelationshipDim, GraphNewPeer,
		GraphDirectionChange, GraphMetricDeviation, GraphTimeWindowDeviation,
		GraphEdgeCandidate, GraphEdgeLearned, GraphEdgeFrozen, GraphEdgeMetricPeakExceeds,
		TrustAttestationOK, TrustAttestationFailed,
		TrustAssertionExpired, TrustAssertionFresh,
		TrustIMAViolation, TrustPCRMismatch,
		TrustTPMUnavailable, TrustMode,
		PolicyPackSignatureOK, PolicyPackSignatureBad,
		PolicyPackRollbackAttempt, PolicyPackExpired,
		PolicyPackCapabilityMissing, PolicyPackTargetMismatch,
		PolicyViolation,
		CampaignDistributedScan, CampaignWormlikeBehavior,
		CampaignDataExfil, GlobalRiskSignal,
		FleetAnomalyDetected, ServiceAnomalyDetected,
		LocalAutonomyAllowed, LocalAutonomyDenied,
		LocalAutonomyThrottled, SeverityBelowThreshold,
		TrustGateFailed,
		WhitelistMatch, FeedbackMatch, ExemptionMatch,
		EnforcementStateObserve, EnforcementStateSoftLimit,
		EnforcementStateHardLimit, EnforcementStateBlocked,
		EnforcementStateCooldown, EnforcementStateExpired,
		BootstrapPhase1, BootstrapPhase2, BootstrapPhase3,
		AutoTuneApplied, AutoTuneSkipped, LowConfidenceData,
		AdapterHealthy, AdapterDegraded, AdapterFailing,
		MapReadError, StateRestored, StateNotAvailable,
	}

	seen := make(map[string]bool)
	for _, code := range allCodes {
		if seen[code] {
			t.Errorf("duplicate reason code: %s", code)
		}
		seen[code] = true
	}
}
