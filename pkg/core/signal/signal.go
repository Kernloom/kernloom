// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package signal

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/observation"
)

// SignalProducer describes which component produced the signal.
type SignalProducer string

const (
	ProducerKLIQ      SignalProducer = "kliq"      // Local IQ agent
	ProducerCorrelate SignalProducer = "correlate" // Global correlation service
	ProducerTrust     SignalProducer = "trust"     // Trust/integrity component
	ProducerForge     SignalProducer = "forge"     // Policy management
)

// SignalScope describes the scope of a signal's relevance.
type SignalScope string

const (
	ScopeLocal  SignalScope = "local"  // Relevant to single node
	ScopeSite   SignalScope = "site"   // Relevant to a site/region
	ScopeTenant SignalScope = "tenant" // Relevant to a tenant
	ScopeGlobal SignalScope = "global" // Relevant to entire fleet
)

// SignalType categorizes signals for routing and handling.
// Signal types follow the pattern "domain.severity_or_class".
type SignalType string

// Heuristic signals (local, from KLIQ)
const (
	SignalScanSuspected           SignalType = "source.scan_suspected"             // High port diversity
	SignalPPSHigh                 SignalType = "source.pps_high"                   // Packets per second spike
	SignalSYNRateHigh             SignalType = "source.syn_rate_high"              // SYN flood pattern
	SignalRateLimitDropsSustained SignalType = "source.rate_limit_drops_sustained" // RL drops continue
)

// Graph signals (local, from KLIQ graph learner)
const (
	SignalGraphNewEdgeAfterFreeze  SignalType = "graph.new_edge_after_freeze" // New edge detected post-freeze
	SignalGraphNewDestinationPort  SignalType = "graph.new_destination_port"  // Known peer, new port
	SignalGraphNewPeer             SignalType = "graph.new_peer"              // Never seen before
	SignalGraphDirectionChange     SignalType = "graph.direction_change"      // Inbound/egress flip
	SignalGraphVolumeDeviation     SignalType = "graph.volume_deviation"      // Unusual traffic volume
	SignalGraphTimeWindowDeviation SignalType = "graph.time_window_deviation" // Off-hours communication
)

// Trust signals
const (
	SignalNodeTrustDegraded  SignalType = "node.trust_degraded"  // Attestation stale or failed
	SignalNodeTrustUntrusted SignalType = "node.trust_untrusted" // Attestation violation
	SignalNodeTrustRecovered SignalType = "node.trust_recovered" // Attestation healed
)

// Campaign signals (global, from Correlate)
const (
	SignalCampaignDistributedScan  SignalType = "campaign.distributed_scan"  // Slow scan across fleet
	SignalCampaignWormlikeBehavior SignalType = "campaign.wormlike_behavior" // Lateral movement pattern
	SignalCampaignDataExfil        SignalType = "campaign.data_exfil"        // Unusual egress pattern
)

// Policy signals
const (
	SignalPolicyPackRollbackAttempt SignalType = "policy.pack_rollback_attempt" // Downgrade detected
	SignalPolicyViolation           SignalType = "policy.violation"             // Action disallowed by policy
)

// Service signals
const (
	SignalServiceUnusualClient SignalType = "service.unusual_client" // Client not in baseline
	SignalServiceUnusualPort   SignalType = "service.unusual_port"   // Service on unexpected port
	SignalServiceNewInstance   SignalType = "service.new_instance"   // Service replica appeared
)

// Identity/Auth signals
const (
	SignalIdentityRiskyAuthContext SignalType = "identity.risky_auth_context" // Auth from unusual context
	SignalIdentityNewUser          SignalType = "identity.new_user"           // First sighting
)

// Signal is a higher-level interpretation of observations.
// Observations are raw; signals are processed, scored, and actionable.
//
// Examples:
//
//   - Observation: "100 packets from 203.0.113.55 in 1 second"
//
//   - Signal: "source.pps_high" from 203.0.113.55 with score 75
//
//   - Observations: 12 different destination ports from 203.0.113.55 across fleet
//
//   - Signal: "campaign.distributed_scan" with score 92 across 12 nodes
type Signal struct {
	// ID is a unique identifier for this signal (UUIDv4 recommended).
	ID string `json:"id"`

	// Time is when the signal was generated (may differ from observation time).
	Time time.Time `json:"time"`

	// Producer is which component generated this signal.
	Producer SignalProducer `json:"producer"`

	// Scope is the applicability level (local, site, tenant, global).
	Scope SignalScope `json:"scope"`

	// Type is the signal category/classification.
	Type SignalType `json:"type"`

	// Subject is the primary entity involved (source IP, node, service, etc.)
	Subject observation.EntityRef `json:"subject"`

	// Object is the secondary entity (destination, policy, etc.) - optional.
	Object observation.EntityRef `json:"object,omitempty"`

	// Score is a risk score from 0 to 100.
	// 0-30: Low risk, informational
	// 31-60: Medium risk, monitor
	// 61-80: High risk, consider action
	// 81-100: Critical risk, immediate action likely
	Score int `json:"score"`

	// Confidence is the signal's reliability from 0 to 100.
	// Signals with low confidence should generate weaker actions or require more confirmation.
	Confidence int `json:"confidence"`

	// TTL is how long this signal remains active (advisory).
	// Example: 15m for a distributed scan, 1h for a graph freeze detection.
	TTL time.Duration `json:"ttl"`

	// ReasonCodes are machine-readable reasons for the signal (join with reason.*)
	// Examples: "pps_high", "syn_rate_high", "scan_rate_high", "global_risk_signal"
	ReasonCodes []string `json:"reason_codes"`

	// Attributes provide additional context.
	// Examples:
	//   "nodes_affected": "12"
	//   "sustained_for": "5m"
	//   "policy_scope": "public-api"
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewSignal creates a new signal with required fields.
func NewSignal(producer SignalProducer, scope SignalScope, sigType SignalType, subject observation.EntityRef) *Signal {
	return &Signal{
		ID:          generateID(),
		Time:        time.Now().UTC(),
		Producer:    producer,
		Scope:       scope,
		Type:        sigType,
		Subject:     subject,
		Score:       50, // Default middle score; caller should adjust
		Confidence:  50,
		TTL:         15 * time.Minute, // Default; caller should adjust
		ReasonCodes: []string{},
		Attributes:  make(map[string]string),
	}
}

// SetObject sets the object entity reference.
func (s *Signal) SetObject(obj observation.EntityRef) *Signal {
	s.Object = obj
	return s
}

// SetScore sets the risk score (clamped to 0-100).
func (s *Signal) SetScore(score int) *Signal {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	s.Score = score
	return s
}

// SetConfidence sets the confidence score (clamped to 0-100).
func (s *Signal) SetConfidence(confidence int) *Signal {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	s.Confidence = confidence
	return s
}

// SetTTL sets the time-to-live for this signal.
func (s *Signal) SetTTL(ttl time.Duration) *Signal {
	s.TTL = ttl
	return s
}

// AddReasonCode appends a reason code.
func (s *Signal) AddReasonCode(code string) *Signal {
	s.ReasonCodes = append(s.ReasonCodes, code)
	return s
}

// SetAttribute adds or updates an attribute.
func (s *Signal) SetAttribute(key, value string) *Signal {
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[key] = value
	return s
}

// IsExpired checks if the signal has expired based on its TTL.
func (s *Signal) IsExpired() bool {
	if s.TTL <= 0 {
		return false // No expiration
	}
	return time.Since(s.Time) > s.TTL
}

// ExpiresAt returns the time when this signal expires.
func (s *Signal) ExpiresAt() time.Time {
	if s.TTL <= 0 {
		return time.Time{} // No expiration
	}
	return s.Time.Add(s.TTL)
}

// generateID returns a random UUIDv4 string.
func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
