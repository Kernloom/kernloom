// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package decision

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/observation"
)

// Decider describes which component made the decision.
type Decider string

const (
	DeciderKLIQ      Decider = "kliq"      // Local KLIQ agent
	DeciderForge     Decider = "forge"     // Policy engine
	DeciderCorrelate Decider = "correlate" // Global risk engine
)

// ActionType describes what action to take.
type ActionType string

const (
	ActionObserve   ActionType = "observe"    // No enforcement; monitor only
	ActionSignal    ActionType = "signal"     // Emit a signal
	ActionRateLimit ActionType = "rate_limit" // Apply rate limiting
	ActionBlock     ActionType = "block"      // Drop traffic
	ActionAllow     ActionType = "allow"      // Explicitly allow
	ActionIsolate   ActionType = "isolate"    // Isolate entity (network/process)
	ActionTag       ActionType = "tag"        // Add tag/label for tracking
	ActionNotify    ActionType = "notify"     // Send alert/notification
)

// Action describes a specific enforcement action to be taken.
type Action struct {
	// Type is the action category (observe, signal, rate_limit, block, etc.)
	Type ActionType `json:"type"`

	// Capability is the capability needed to execute this action.
	// Examples: "network.block_source", "network.rate_limit_source", "signal.emit_local_risk"
	Capability string `json:"capability"`

	// Params are action-specific parameters.
	// Examples for rate_limit:
	//   "source": "203.0.113.55"
	//   "rate_pps": "100"
	//   "burst": "200"
	// Examples for block:
	//   "source": "203.0.113.55"
	//   "ttl": "10m"
	// Examples for signal:
	//   "signal_type": "source.pps_high"
	//   "score": "85"
	Params map[string]string `json:"params,omitempty"`
}

// Decision describes what a PDP (Policy Decision Point) has decided.
// A Decision is not yet a guarantee that a PEP (Policy Enforcement Point) will execute it;
// that is confirmed by an EnforcementReceipt.
type Decision struct {
	// ID is a unique identifier for this decision (UUIDv4 recommended).
	ID string `json:"id"`

	// Time is when the decision was made.
	Time time.Time `json:"time"`

	// Decider is the component that made this decision.
	Decider Decider `json:"decider"`

	// NodeID is the node where this decision applies (local context).
	NodeID string `json:"node_id"`

	// Subject is the primary entity being enforced against (IP, node, service, user, etc.)
	Subject observation.EntityRef `json:"subject"`

	// Action is what to do.
	Action Action `json:"action"`

	// Severity is how severe the situation is (0-100).
	// Directly influences whether local autonomy permits enforcement.
	Severity int `json:"severity"`

	// ReasonCodes are machine-readable reasons for the decision.
	// Examples: "pps_high", "scan_suspected", "graph_new_edge_after_freeze"
	ReasonCodes []string `json:"reason_codes"`

	// ExpiresAt is when this decision should no longer apply.
	// nil means no automatic expiration.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// DryRun indicates this is a simulation only; do not actually enforce.
	DryRun bool `json:"dry_run"`

	// Attributes provide additional context.
	// Examples:
	//   "policy_pack_id": "public-api-baseline-001"
	//   "confidence": "85"
	//   "local_autonomy": "allowed"
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewDecision creates a new decision with required fields.
func NewDecision(decider Decider, nodeID string, subject observation.EntityRef, action Action) *Decision {
	return &Decision{
		ID:          generateID(),
		Time:        time.Now().UTC(),
		Decider:     decider,
		NodeID:      nodeID,
		Subject:     subject,
		Action:      action,
		Severity:    50, // Default; caller should adjust
		ReasonCodes: []string{},
		DryRun:      true, // Default to dry-run for safety; caller decides
		Attributes:  make(map[string]string),
	}
}

// SetSeverity sets the severity (clamped to 0-100).
func (d *Decision) SetSeverity(sev int) *Decision {
	if sev < 0 {
		sev = 0
	}
	if sev > 100 {
		sev = 100
	}
	d.Severity = sev
	return d
}

// AddReasonCode appends a reason code.
func (d *Decision) AddReasonCode(code string) *Decision {
	d.ReasonCodes = append(d.ReasonCodes, code)
	return d
}

// SetExpiry sets when this decision expires.
func (d *Decision) SetExpiry(t time.Time) *Decision {
	d.ExpiresAt = &t
	return d
}

// SetExpiryDuration sets expiry relative to now.
func (d *Decision) SetExpiryDuration(dur time.Duration) *Decision {
	if dur > 0 {
		expiry := time.Now().Add(dur)
		d.ExpiresAt = &expiry
	}
	return d
}

// SetDryRun sets whether this is a simulation.
func (d *Decision) SetDryRun(dryRun bool) *Decision {
	d.DryRun = dryRun
	return d
}

// SetAttribute adds or updates an attribute.
func (d *Decision) SetAttribute(key, value string) *Decision {
	if d.Attributes == nil {
		d.Attributes = make(map[string]string)
	}
	d.Attributes[key] = value
	return d
}

// IsExpired checks if the decision has expired.
func (d *Decision) IsExpired() bool {
	if d.ExpiresAt == nil {
		return false // No expiration
	}
	return time.Now().After(*d.ExpiresAt)
}

// EnforcementReceipt documents whether a PEP (Policy Enforcement Point) successfully applied a Decision.
// A Decision without a Receipt is not confirmed as applied.
type EnforcementReceipt struct {
	// ID is a unique identifier for this receipt (UUIDv4 recommended).
	ID string `json:"id"`

	// DecisionID is the ID of the Decision this Receipt corresponds to.
	DecisionID string `json:"decision_id"`

	// NodeID is the node where enforcement was attempted.
	NodeID string `json:"node_id"`

	// AdapterID is the adapter/PEP that handled the enforcement.
	// Examples: "shield-pep", "nginx-pep", "ziti-adapter"
	AdapterID string `json:"adapter_id"`

	// Status describes the outcome.
	Status ReceiptStatus `json:"status"`

	// Message is a human-readable note about the status.
	Message string `json:"message,omitempty"`

	// AppliedAt is when the action was applied (or attempted).
	AppliedAt time.Time `json:"applied_at"`
}

// ReceiptStatus describes the result of an enforcement attempt.
type ReceiptStatus string

const (
	StatusApplied     ReceiptStatus = "applied"     // Decision successfully applied
	StatusFailed      ReceiptStatus = "failed"      // Application failed (error in Message)
	StatusSkipped     ReceiptStatus = "skipped"     // Decision skipped (policy/permission)
	StatusUnsupported ReceiptStatus = "unsupported" // Capability not available
	StatusDryRun      ReceiptStatus = "dry_run"     // Simulated; not actually applied
)

// NewEnforcementReceipt creates a new receipt.
func NewEnforcementReceipt(decisionID, nodeID, adapterID string, status ReceiptStatus) *EnforcementReceipt {
	return &EnforcementReceipt{
		ID:         generateID(),
		DecisionID: decisionID,
		NodeID:     nodeID,
		AdapterID:  adapterID,
		Status:     status,
		AppliedAt:  time.Now().UTC(),
	}
}

// SetMessage adds a message to the receipt.
func (r *EnforcementReceipt) SetMessage(msg string) *EnforcementReceipt {
	r.Message = msg
	return r
}

// generateID returns a random UUIDv4 string.
func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
