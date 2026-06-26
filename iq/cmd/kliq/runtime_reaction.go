// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const runtimeReactionStateAdapterID = "kliq-runtime-reaction"

type runtimeReactionEngine struct {
	mu               sync.Mutex
	windows          map[string][]reactionSample
	lastFire         map[string]time.Time
	lastResponse     map[string]time.Time
	activeDetections map[string]reactionActiveDetection
	activeActions    map[string]reactionActiveAction
	activeAlerts     map[string]reactionActiveAlert
	store            *sqlite.Store
	nodeID           string
	alertFile        string
	identityResolver adapterruntime.IdentityResolver
}

type reactionSample struct {
	At    time.Time `json:"at"`
	Count int       `json:"count"`
}

type reactionDetectionEvent struct {
	Rule         contracts.RuntimeDetectionRule
	Key          string
	SourceID     string
	Count        int
	Window       time.Duration
	ObservedAt   time.Time
	SourceAttrs  map[string]string
	SourceTarget adapterruntime.SourceTarget
}

type reactionActiveAction struct {
	ActionID        string    `json:"action_id"`
	Level           string    `json:"level,omitempty"`
	SourceID        string    `json:"source_id"`
	ResourceRef     string    `json:"resource_ref,omitempty"`
	ResponseRuleID  string    `json:"response_rule_id,omitempty"`
	DetectionRuleID string    `json:"detection_rule_id,omitempty"`
	AppliedAt       time.Time `json:"applied_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type reactionActiveDetection struct {
	DetectionRuleID string    `json:"detection_rule_id"`
	Key             string    `json:"key"`
	SourceID        string    `json:"source_id"`
	ResourceRef     string    `json:"resource_ref,omitempty"`
	Count           int       `json:"count"`
	WindowSeconds   int64     `json:"window_seconds,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type reactionActiveAlert struct {
	AlertID         string    `json:"alert_id"`
	RouteID         string    `json:"route_id,omitempty"`
	ResponseRuleID  string    `json:"response_rule_id,omitempty"`
	DetectionRuleID string    `json:"detection_rule_id,omitempty"`
	SourceID        string    `json:"source_id,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
	AckDeadline     time.Time `json:"ack_deadline,omitempty"`
	Escalated       bool      `json:"escalated,omitempty"`
}

type runtimeReactionSnapshot struct {
	Version          int                                `json:"version"`
	Windows          map[string][]reactionSample        `json:"windows,omitempty"`
	LastFire         map[string]time.Time               `json:"last_fire,omitempty"`
	LastResponse     map[string]time.Time               `json:"last_response,omitempty"`
	ActiveDetections map[string]reactionActiveDetection `json:"active_detections,omitempty"`
	ActiveActions    map[string]reactionActiveAction    `json:"active_actions,omitempty"`
	ActiveAlerts     map[string]reactionActiveAlert     `json:"active_alerts,omitempty"`
}

func newRuntimeReactionEngine() *runtimeReactionEngine {
	return &runtimeReactionEngine{
		windows:          map[string][]reactionSample{},
		lastFire:         map[string]time.Time{},
		lastResponse:     map[string]time.Time{},
		activeDetections: map[string]reactionActiveDetection{},
		activeActions:    map[string]reactionActiveAction{},
		activeAlerts:     map[string]reactionActiveAlert{},
	}
}

func (e *runtimeReactionEngine) SetAlertFile(path string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.alertFile = strings.TrimSpace(path)
	e.mu.Unlock()
	if strings.TrimSpace(path) != "" {
		kliqLog.Printf("ALERT file fallback path=%s (used only by file/jsonl alert routes)", path)
	}
}

func (e *runtimeReactionEngine) SetIdentityResolver(resolver adapterruntime.IdentityResolver) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.identityResolver = resolver
	e.mu.Unlock()
}

func (e *runtimeReactionEngine) Load(ctx context.Context, store *sqlite.Store, nodeID string) error {
	if e == nil || store == nil {
		return nil
	}
	e.mu.Lock()
	e.store = store
	e.nodeID = nodeID
	e.mu.Unlock()

	data, ok, err := store.GetAdapterState(ctx, runtimeReactionStateAdapterID)
	if err != nil {
		return err
	}
	if !ok || len(data) == 0 {
		return nil
	}
	var snap runtimeReactionSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("load runtime reaction state: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if snap.Windows != nil {
		e.windows = snap.Windows
	}
	if snap.LastFire != nil {
		e.lastFire = snap.LastFire
	}
	if snap.LastResponse != nil {
		e.lastResponse = snap.LastResponse
	}
	if snap.ActiveDetections != nil {
		e.activeDetections = snap.ActiveDetections
	}
	if snap.ActiveActions != nil {
		e.activeActions = snap.ActiveActions
	}
	if snap.ActiveAlerts != nil {
		e.activeAlerts = snap.ActiveAlerts
	}
	return nil
}

func (e *runtimeReactionEngine) CandidateFacts(_ context.Context, _ string, m metrics, now time.Time) (runtimePDPFactSnapshot, error) {
	if e == nil {
		return runtimePDPFactSnapshot{}, nil
	}
	return runtimePDPFactSnapshot{
		Detections: e.detectionFactsForSource(m.sourceID(), now),
	}, nil
}

func (e *runtimeReactionEngine) detectionFactsForSource(sourceID string, now time.Time) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]any{}
	activeCount := 0
	changed := false
	for key, active := range e.activeDetections {
		if !active.ExpiresAt.IsZero() && !now.Before(active.ExpiresAt) {
			delete(e.activeDetections, key)
			changed = true
			continue
		}
		if sourceID != "" && active.SourceID != sourceID {
			continue
		}
		factKey := runtimePDPFactKey(active.DetectionRuleID)
		if factKey == "" {
			continue
		}
		out[factKey] = map[string]any{
			"active":         true,
			"detection_id":   active.DetectionRuleID,
			"source_id":      active.SourceID,
			"resource_ref":   active.ResourceRef,
			"count":          active.Count,
			"window_seconds": active.WindowSeconds,
			"observed_at":    active.ObservedAt.UTC().Format(time.RFC3339Nano),
			"expires_at":     active.ExpiresAt.UTC().Format(time.RFC3339Nano),
		}
		activeCount++
	}
	out["active_count"] = activeCount
	if changed {
		snap := e.snapshotLocked()
		go e.persistSnapshot(snap)
	}
	return out
}

func (e *runtimeReactionEngine) EvaluateCandidate(
	m metrics,
	st fsm.State,
	now time.Time,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
) fsm.State {
	if e == nil {
		return st
	}
	e.sweepAlertEscalations(c, now)
	if len(c.RuntimeDetectionRules) == 0 || len(c.RuntimeResponseRules) == 0 {
		return st
	}
	var out = st
	for _, detection := range c.RuntimeDetectionRules {
		event, ok := e.observeDetection(detection, m, now)
		if !ok {
			continue
		}
		out = e.applyResponses(event, out, c, resolver, executor, nodeID, now)
	}
	return out
}

func (e *runtimeReactionEngine) EvaluateSignal(
	sig signal.Signal,
	now time.Time,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
) {
	if e == nil {
		return
	}
	e.sweepAlertEscalations(c, now)
	if len(c.RuntimeDetectionRules) == 0 || len(c.RuntimeResponseRules) == 0 {
		return
	}
	m := reactionMetricsFromSignal(sig)
	if m.sourceID() == "" {
		return
	}
	for _, detection := range c.RuntimeDetectionRules {
		event, ok := e.observeDetection(detection, m, now)
		if !ok {
			continue
		}
		_ = e.applyResponses(event, fsm.State{}, c, resolver, executor, nodeID, now)
	}
}

func (e *runtimeReactionEngine) observeDetection(rule contracts.RuntimeDetectionRule, m metrics, now time.Time) (reactionDetectionEvent, bool) {
	if strings.TrimSpace(rule.ID) == "" || !reactionSubjectMatches(rule.Subject, m.Target) || !reactionDetectionResourceMatches(rule, m) {
		return reactionDetectionEvent{}, false
	}
	count := reactionObservationCount(rule, m)
	if count <= 0 {
		return reactionDetectionEvent{}, false
	}
	window := rule.Window.Duration
	if window <= 0 {
		window = time.Minute
	}
	threshold := rule.Threshold
	if threshold <= 0 {
		threshold = 1
	}
	key := reactionDetectionKey(rule, m)
	e.mu.Lock()
	samples := append(e.windows[key], reactionSample{At: now, Count: count})
	fullWindow := !sustainedDetectionRequiresFullWindow(rule) || reactionSamplesCoverWindow(samples, window, now)
	cutoff := now.Add(-window)
	total := 0
	kept := samples[:0]
	for _, sample := range samples {
		if sample.At.Before(cutoff) {
			continue
		}
		total += sample.Count
		kept = append(kept, sample)
	}
	e.windows[key] = kept
	if total < threshold {
		snap := e.snapshotLocked()
		e.mu.Unlock()
		e.persistSnapshot(snap)
		return reactionDetectionEvent{}, false
	}
	if !fullWindow {
		snap := e.snapshotLocked()
		e.mu.Unlock()
		e.persistSnapshot(snap)
		return reactionDetectionEvent{}, false
	}
	if last := e.lastFire[key]; !last.IsZero() && now.Sub(last) < window {
		snap := e.snapshotLocked()
		e.mu.Unlock()
		e.persistSnapshot(snap)
		return reactionDetectionEvent{}, false
	}
	e.lastFire[key] = now
	if e.activeDetections == nil {
		e.activeDetections = map[string]reactionActiveDetection{}
	}
	e.activeDetections[key] = reactionActiveDetection{
		DetectionRuleID: rule.ID,
		Key:             key,
		SourceID:        m.sourceID(),
		ResourceRef:     rule.ResourceRef,
		Count:           total,
		WindowSeconds:   int64(window.Seconds()),
		ObservedAt:      now.UTC(),
		ExpiresAt:       now.Add(window).UTC(),
	}
	snap := e.snapshotLocked()
	e.mu.Unlock()
	e.persistSnapshot(snap)
	kliqLog.Printf("[reaction] detection=%s source=%s active count=%d window=%s", rule.ID, m.sourceID(), total, window)
	return reactionDetectionEvent{
		Rule:         rule,
		Key:          key,
		SourceID:     m.sourceID(),
		Count:        total,
		Window:       window,
		ObservedAt:   now,
		SourceAttrs:  copyStringMap(m.Target.Attributes),
		SourceTarget: m.Target,
	}, true
}

func (e *runtimeReactionEngine) applyResponses(
	event reactionDetectionEvent,
	st fsm.State,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
	now time.Time,
) fsm.State {
	out := st
	for _, rule := range c.RuntimeResponseRules {
		if !reactionResponseMatches(rule.When, event.Rule.ID) {
			continue
		}
		for _, action := range rule.Then {
			if action.ID == "notify.alert.emit" {
				e.emitAlert(rule, action, event, c, now)
				continue
			}
			next, applied := e.applyRuntimeAction(rule, action, event, out, c, resolver, executor, nodeID, now)
			if applied {
				out = next
			}
		}
	}
	return out
}

func (e *runtimeReactionEngine) emitAlert(rule contracts.RuntimeResponseRule, action contracts.RuntimeResponseAction, event reactionDetectionEvent, c cfg, now time.Time) {
	route := runtimeAlertRouteByID(c.RuntimeAlertRoutes, action.Route)
	dedupe := action.Dedupe.Duration
	if dedupe <= 0 && route != nil {
		dedupe = route.Deduplication.Window.Duration
	}
	if dedupe <= 0 {
		dedupe = time.Minute
	}
	severity := action.Severity
	if severity == "" && route != nil {
		severity = route.DefaultSeverity
	}
	if severity == "" {
		severity = "medium"
	}
	key := "alert|" + rule.ID + "|" + action.Route + "|" + event.Key
	alertID := reactionAlertID(key, now)
	e.mu.Lock()
	if last := e.lastResponse[key]; !last.IsZero() && now.Sub(last) < dedupe {
		e.mu.Unlock()
		return
	}
	e.lastResponse[key] = now
	if route != nil && route.Acknowledgement.Required {
		timeout := route.Acknowledgement.Timeout.Duration
		if timeout <= 0 {
			timeout = 15 * time.Minute
		}
		if e.activeAlerts == nil {
			e.activeAlerts = map[string]reactionActiveAlert{}
		}
		e.activeAlerts[alertID] = reactionActiveAlert{
			AlertID:         alertID,
			RouteID:         action.Route,
			ResponseRuleID:  rule.ID,
			DetectionRuleID: event.Rule.ID,
			SourceID:        event.SourceID,
			Severity:        severity,
			ObservedAt:      now.UTC(),
			AckDeadline:     now.Add(timeout).UTC(),
		}
	}
	snap := e.snapshotLocked()
	e.mu.Unlock()
	e.persistSnapshot(snap)
	alertPayload := map[string]any{
		"alert_id":          alertID,
		"route":             action.Route,
		"severity":          severity,
		"detection_rule_id": event.Rule.ID,
		"response_rule_id":  rule.ID,
		"source":            event.SourceID,
		"resource_ref":      event.Rule.ResourceRef,
		"count":             event.Count,
		"window":            event.Window.String(),
		"observed_at":       event.ObservedAt.UTC().Format(time.RFC3339Nano),
		"emitted_at":        now.UTC().Format(time.RFC3339Nano),
	}
	e.persistAlertSignal(rule, action, event, severity, now)
	e.dispatchAlertNotifications(route, rule, action, event, severity, now, alertPayload)
	kliqEventf(kliqLogInfo, "alert", "reaction detection=%s response=%s route=%s severity=%s source=%s count=%d window=%s",
		event.Rule.ID, rule.ID, action.Route, severity, event.SourceID, event.Count, event.Window)
}

func reactionAlertID(key string, now time.Time) string {
	clean := strings.NewReplacer("|", "-", " ", "-").Replace(key)
	return clean + "-" + now.UTC().Format("20060102T150405.000000000Z")
}

func (e *runtimeReactionEngine) dispatchAlertNotifications(
	route *contracts.RuntimeAlertRoute,
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	severity string,
	now time.Time,
	alertPayload map[string]any,
) {
	if route == nil || len(route.Channels) == 0 {
		logReactionNotification("log.default", rule, action, event, severity, now)
		return
	}
	for _, channel := range route.Channels {
		switch normalizeRuntimeBehavior(channel.Type) {
		case "log":
			logReactionNotification(channel.Ref, rule, action, event, severity, now)
		case "email":
			if err := sendReactionEmail(channel.Ref, route, rule, action, event, severity, now); err != nil {
				kliqEventf(kliqLogInfo, "warn", "reaction email notification route=%s ref=%s: %v", action.Route, channel.Ref, err)
			}
		case "file", "jsonl", "file_jsonl", "jsonl_file":
			path := e.alertFilePathForChannel(channel)
			if path == "" {
				kliqEventf(kliqLogInfo, "warn", "reaction file notification route=%s ref=%s has no path; set --alert-file or use file:///path", action.Route, channel.Ref)
				continue
			}
			e.appendAlertFile(path, "alert", alertPayload)
		default:
			kliqEventf(kliqLogInfo, "warn", "reaction notification channel %q is not supported locally", channel.Type)
		}
	}
}

func (e *runtimeReactionEngine) sweepAlertEscalations(c cfg, now time.Time) {
	if e == nil {
		return
	}
	var due []reactionActiveAlert
	e.mu.Lock()
	for id, alert := range e.activeAlerts {
		if alert.Escalated || alert.AckDeadline.IsZero() || now.Before(alert.AckDeadline) {
			continue
		}
		alert.Escalated = true
		e.activeAlerts[id] = alert
		due = append(due, alert)
	}
	snap := e.snapshotLocked()
	e.mu.Unlock()
	if len(due) == 0 {
		return
	}
	e.persistSnapshot(snap)
	for _, alert := range due {
		route := runtimeAlertRouteByID(c.RuntimeAlertRoutes, alert.RouteID)
		escalationPayload := map[string]any{
			"alert_id":          alert.AlertID,
			"route":             alert.RouteID,
			"severity":          alert.Severity,
			"detection_rule_id": alert.DetectionRuleID,
			"response_rule_id":  alert.ResponseRuleID,
			"source":            alert.SourceID,
			"ack_deadline":      alert.AckDeadline.UTC().Format(time.RFC3339Nano),
			"escalated_at":      now.UTC().Format(time.RFC3339Nano),
		}
		e.dispatchAlertEscalation(route, alert, now, escalationPayload)
	}
}

func (e *runtimeReactionEngine) dispatchAlertEscalation(route *contracts.RuntimeAlertRoute, alert reactionActiveAlert, now time.Time, escalationPayload map[string]any) {
	if route == nil || route.Acknowledgement.NoEscalation || len(route.Acknowledgement.Escalation) == 0 {
		kliqEventf(kliqLogInfo, "alert", "escalation alert=%s route=%s source=%s severity=%s reason=ack_timeout",
			alert.AlertID, alert.RouteID, alert.SourceID, alert.Severity)
		return
	}
	for _, escalation := range route.Acknowledgement.Escalation {
		via := strings.Join(escalation.Via, ",")
		if via == "" {
			via = "log"
		}
		kliqEventf(kliqLogInfo, "alert", "escalation alert=%s route=%s to=%s:%s via=%s source=%s severity=%s at=%s",
			alert.AlertID, alert.RouteID, escalation.To.Type, escalation.To.Ref, via,
			alert.SourceID, alert.Severity, now.UTC().Format(time.RFC3339))
		for _, channelType := range escalation.Via {
			switch normalizeRuntimeBehavior(channelType) {
			case "file", "jsonl", "file_jsonl", "jsonl_file":
				path := e.alertFilePathForEscalation(route)
				if path == "" {
					kliqEventf(kliqLogInfo, "warn", "reaction escalation file notification route=%s has no path; set --alert-file or use file:///path", alert.RouteID)
					continue
				}
				e.appendAlertFile(path, "alert_escalation", escalationPayload)
			}
		}
	}
}

func (e *runtimeReactionEngine) alertFilePathForChannel(channel contracts.RuntimeAlertChannel) string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	fallback := e.alertFile
	e.mu.Unlock()
	return runtimeAlertFilePathForChannel(channel, fallback)
}

func (e *runtimeReactionEngine) alertFilePathForEscalation(route *contracts.RuntimeAlertRoute) string {
	if e == nil {
		return ""
	}
	var channel contracts.RuntimeAlertChannel
	if route != nil {
		for _, candidate := range route.Channels {
			switch normalizeRuntimeBehavior(candidate.Type) {
			case "file", "jsonl", "file_jsonl", "jsonl_file":
				channel = candidate
				break
			}
			if channel.Type != "" {
				break
			}
		}
	}
	return e.alertFilePathForChannel(channel)
}

func runtimeAlertFilePathForChannel(channel contracts.RuntimeAlertChannel, fallback string) string {
	fallback = strings.TrimSpace(fallback)
	ref := strings.TrimSpace(channel.Ref)
	if ref == "" {
		return fallback
	}
	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "file://") {
		return strings.TrimSpace(ref[len("file://"):])
	}
	if strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") || strings.Contains(ref, string(os.PathSeparator)) {
		return ref
	}
	return fallback
}

func (e *runtimeReactionEngine) appendAlertFile(path, eventType string, payload map[string]any) {
	if e == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	e.mu.Lock()
	nodeID := e.nodeID
	e.mu.Unlock()
	entry := map[string]any{}
	if payload == nil {
		payload = map[string]any{}
	}
	for key, value := range payload {
		entry[key] = value
	}
	entry["type"] = eventType
	entry["node_id"] = nodeID
	if _, ok := entry["written_at"]; !ok {
		entry["written_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			kliqEventf(kliqLogInfo, "warn", "create alert file dir %s: %v", dir, err)
			return
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		kliqEventf(kliqLogInfo, "warn", "open alert file %s: %v", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(entry); err != nil {
		kliqEventf(kliqLogInfo, "warn", "append alert file %s: %v", path, err)
	}
}

func logReactionNotification(ref string, rule contracts.RuntimeResponseRule, action contracts.RuntimeResponseAction, event reactionDetectionEvent, severity string, now time.Time) {
	if strings.TrimSpace(ref) == "" {
		ref = "log.default"
	}
	kliqEventf(kliqLogInfo, "notify", "log ref=%s route=%s severity=%s detection=%s response=%s source=%s count=%d observed=%s",
		ref, action.Route, severity, event.Rule.ID, rule.ID, event.SourceID, event.Count, now.UTC().Format(time.RFC3339))
}

func sendReactionEmail(
	ref string,
	route *contracts.RuntimeAlertRoute,
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	severity string,
	now time.Time,
) error {
	addr := strings.TrimSpace(os.Getenv("KERNLOOM_SMTP_ADDR"))
	from := strings.TrimSpace(os.Getenv("KERNLOOM_SMTP_FROM"))
	if addr == "" || from == "" {
		return fmt.Errorf("KERNLOOM_SMTP_ADDR and KERNLOOM_SMTP_FROM are required")
	}
	to := emailRecipientFromRef(ref)
	if to == "" {
		return fmt.Errorf("channel ref %q is not an email address", ref)
	}
	subject := fmt.Sprintf("[kernloom:%s] %s", severity, event.Rule.ID)
	body := fmt.Sprintf("Kernloom runtime alert\n\nRoute: %s\nAudience: %s:%s\nSeverity: %s\nDetection: %s\nResponse: %s\nSource: %s\nCount: %d\nWindow: %s\nObserved: %s\n",
		action.Route, route.Audience.Type, route.Audience.Ref, severity, event.Rule.ID, rule.ID, event.SourceID, event.Count, event.Window, now.UTC().Format(time.RFC3339))
	msg := []byte("To: " + to + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" + body)
	var auth smtp.Auth
	if user := strings.TrimSpace(os.Getenv("KERNLOOM_SMTP_USERNAME")); user != "" {
		host := addr
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		auth = smtp.PlainAuth("", user, os.Getenv("KERNLOOM_SMTP_PASSWORD"), host)
	}
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}

func emailRecipientFromRef(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "email.")
	for _, prefix := range []string{"mailinglist.", "channel."} {
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		name := strings.TrimPrefix(ref, prefix)
		if domain := strings.TrimSpace(os.Getenv("KERNLOOM_EMAIL_DOMAIN")); domain != "" && name != "" {
			return name + "@" + domain
		}
	}
	if strings.Contains(ref, "@") {
		return ref
	}
	return ""
}

func (e *runtimeReactionEngine) persistAlertSignal(
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	severity string,
	now time.Time,
) {
	e.mu.Lock()
	store := e.store
	nodeID := e.nodeID
	e.mu.Unlock()
	if store == nil {
		return
	}
	subject := observation.EntityRef{Kind: "source", ID: event.SourceID}
	if kind := firstStringAttr(event.SourceAttrs, "subject.kind"); kind != "" {
		subject.Kind = observation.EntityKind(kind)
	}
	sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalReactionAlert, subject).
		SetScore(alertSeverityScore(severity)).
		SetConfidence(100).
		SetTTL(7*24*time.Hour).
		AddReasonCode("runtime_response_alert").
		SetAttribute("response_rule_id", rule.ID).
		SetAttribute("detection_rule_id", event.Rule.ID).
		SetAttribute("route", action.Route).
		SetAttribute("severity", severity).
		SetAttribute("source", event.SourceID).
		SetAttribute("count", strconv.Itoa(event.Count)).
		SetAttribute("window", event.Window.String()).
		SetAttribute("observed_at", event.ObservedAt.UTC().Format(time.RFC3339Nano))
	if event.Rule.ResourceRef != "" {
		sig.SetAttribute("resource.ref", event.Rule.ResourceRef)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := store.PersistSignal(ctx, *sig, nodeID); err != nil {
		kliqLog.Printf("WARN: persist reaction alert signal: %v", err)
	}
}

func (e *runtimeReactionEngine) snapshotLocked() runtimeReactionSnapshot {
	return runtimeReactionSnapshot{
		Version:          1,
		Windows:          copyReactionWindows(e.windows),
		LastFire:         copyTimeMap(e.lastFire),
		LastResponse:     copyTimeMap(e.lastResponse),
		ActiveDetections: copyReactionActiveDetections(e.activeDetections),
		ActiveActions:    copyReactionActiveActions(e.activeActions),
		ActiveAlerts:     copyReactionActiveAlerts(e.activeAlerts),
	}
}

func (e *runtimeReactionEngine) persistSnapshot(snap runtimeReactionSnapshot) {
	e.mu.Lock()
	store := e.store
	nodeID := e.nodeID
	e.mu.Unlock()
	if store == nil {
		return
	}
	data, err := json.Marshal(snap)
	if err != nil {
		kliqLog.Printf("WARN: marshal runtime reaction state: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := store.UpsertAdapterState(ctx, runtimeReactionStateAdapterID, nodeID, data); err != nil {
		kliqLog.Printf("WARN: persist runtime reaction state: %v", err)
	}
}

func runtimeAlertRouteByID(routes []contracts.RuntimeAlertRoute, id string) *contracts.RuntimeAlertRoute {
	for i := range routes {
		if routes[i].ID == id {
			return &routes[i]
		}
	}
	return nil
}

func alertSeverityScore(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 95
	case "high":
		return 80
	case "low":
		return 30
	default:
		return 60
	}
}

func (e *runtimeReactionEngine) applyRuntimeAction(
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	st fsm.State,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
	now time.Time,
) (fsm.State, bool) {
	mode := "shadow"
	if c.RuntimePDPMode == string(PDPModeActive) {
		mode = "active"
	}
	kliqEventf(kliqLogDebug, "action", "[reaction:%s] response=%s detection=%s action=%s source=%s deferred-to-runtime-pdp",
		mode, rule.ID, event.Rule.ID, action.ID, event.SourceID)
	return st, false
}

func (e *runtimeReactionEngine) responseRequirementDenyReason(
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	st fsm.State,
	now time.Time,
) string {
	if reason := e.responseBlastRadiusDenyReason(action, event); reason != "" {
		return reason
	}
	previousID := strings.TrimSpace(stringAnyParam(action.Params, "previous_action_id"))
	if previousID == "" {
		return ""
	}
	if !boolAnyParam(action.Params, "previous_action_active") {
		return "previous_action_requires_active_true"
	}
	previousID = normalizeCapabilityID(previousID)
	if e.previousActionActiveInRuntime(previousID, event, now) {
		return ""
	}
	if reactionEvidenceAllowsLocalRuntimeState(action.Params) && localRuntimeStateSatisfiesPreviousAction(previousID, st, now) {
		return ""
	}
	return "previous_action_not_active"
}

func (e *runtimeReactionEngine) responseBlastRadiusDenyReason(action contracts.RuntimeResponseAction, event reactionDetectionEvent) string {
	subjects, unknownBehavior := reactionBlastRadiusRequirement(action.Params)
	if len(subjects) == 0 {
		return ""
	}
	hardAction := reactionIsHardResponseAction(action)
	for _, subject := range subjects {
		if subject.Type != "group" || subject.Ref == "" {
			continue
		}
		known, contains := e.reactionSubjectGroupMembership(event, subject.Ref)
		if known && contains {
			return "blast_radius_protected_group"
		}
		if !known && hardAction && normalizeRuntimeBehavior(unknownBehavior) == "reject_hard_action" {
			return "blast_radius_unknown_target"
		}
	}
	return ""
}

func (e *runtimeReactionEngine) reactionSubjectGroupMembership(event reactionDetectionEvent, group string) (known bool, contains bool) {
	if e != nil {
		e.mu.Lock()
		resolver := e.identityResolver
		e.mu.Unlock()
		if resolver != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			membership, err := resolver.SubjectGroupMembership(ctx, event.SourceTarget, group)
			if err != nil {
				kliqLog.Printf("WARN: identity resolver group membership group=%s source=%s: %v", group, event.SourceID, err)
			} else if membership.Known {
				return true, membership.Member
			}
		}
	}
	return reactionSubjectGroupMembership(event.SourceAttrs, group)
}

type reactionProtectedSubject struct {
	Type string
	Ref  string
}

func reactionBlastRadiusRequirement(params map[string]any) ([]reactionProtectedSubject, string) {
	if len(params) == 0 {
		return nil, ""
	}
	var subjects []reactionProtectedSubject
	unknownBehavior := ""
	if raw, ok := params["blast_radius"]; ok {
		if m, ok := raw.(map[string]any); ok {
			unknownBehavior = strings.TrimSpace(fmt.Sprint(m["unknown_behavior"]))
			subjects = append(subjects, reactionProtectedSubjectsFromAny(m["excludes"])...)
		}
	}
	if group := strings.TrimSpace(stringAnyParam(params, "requires_target_excludes_group")); group != "" {
		subjects = append(subjects, reactionProtectedSubject{Type: "group", Ref: group})
		if unknownBehavior == "" {
			unknownBehavior = "reject_hard_action"
		}
	}
	return subjects, unknownBehavior
}

func reactionProtectedSubjectsFromAny(raw any) []reactionProtectedSubject {
	var out []reactionProtectedSubject
	switch values := raw.(type) {
	case []map[string]string:
		for _, item := range values {
			out = append(out, reactionProtectedSubject{Type: item["type"], Ref: item["ref"]})
		}
	case []map[string]any:
		for _, item := range values {
			out = append(out, reactionProtectedSubject{Type: fmt.Sprint(item["type"]), Ref: fmt.Sprint(item["ref"])})
		}
	case []any:
		for _, item := range values {
			switch typed := item.(type) {
			case map[string]any:
				out = append(out, reactionProtectedSubject{Type: fmt.Sprint(typed["type"]), Ref: fmt.Sprint(typed["ref"])})
			case map[string]string:
				out = append(out, reactionProtectedSubject{Type: typed["type"], Ref: typed["ref"]})
			}
		}
	}
	cleaned := out[:0]
	for _, subject := range out {
		subject.Type = strings.TrimSpace(subject.Type)
		subject.Ref = strings.TrimSpace(subject.Ref)
		if subject.Type != "" && subject.Ref != "" {
			cleaned = append(cleaned, subject)
		}
	}
	return cleaned
}

func reactionSubjectGroupMembership(attrs map[string]string, group string) (known bool, contains bool) {
	groups := firstStringAttr(attrs, "subject.groups", "subject_groups", "subjectGroups", "subject.group", "group")
	if groups == "" {
		return false, false
	}
	return true, reactionListContains(groups, group)
}

func reactionIsHardResponseAction(action contracts.RuntimeResponseAction) bool {
	capability := normalizeCapabilityID(action.ID)
	level := reactionActionLevel(action, capability)
	switch level {
	case "hard", "block":
		return true
	}
	switch capability {
	case "enforce.access.deny", "enforce.traffic.drop", "enforce.network.quarantine", "enforce.identity.disable":
		return true
	default:
		return false
	}
}

func normalizeRuntimeBehavior(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
}

func (e *runtimeReactionEngine) previousActionActiveInRuntime(actionID string, event reactionDetectionEvent, now time.Time) bool {
	if e == nil || actionID == "" || event.SourceID == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, active := range e.activeActions {
		if active.ActionID != actionID || active.SourceID != event.SourceID {
			continue
		}
		if !active.ExpiresAt.IsZero() && !now.Before(active.ExpiresAt) {
			delete(e.activeActions, key)
			continue
		}
		if !active.AppliedAt.IsZero() && !active.AppliedAt.Before(now) {
			continue
		}
		if event.Rule.ResourceRef == "" || active.ResourceRef == "" || active.ResourceRef == event.Rule.ResourceRef {
			return true
		}
	}
	return false
}

func localRuntimeStateSatisfiesPreviousAction(actionID string, st fsm.State, now time.Time) bool {
	if st.Level == fsm.LevelObserve {
		return false
	}
	if !st.ExpiresAt.IsZero() && !now.Before(st.ExpiresAt) {
		return false
	}
	switch normalizeCapabilityID(actionID) {
	case "enforce.traffic.rate_limit":
		return st.Level == fsm.LevelSoft || st.Level == fsm.LevelHard
	case "enforce.traffic.drop", "enforce.access.deny":
		return st.Level == fsm.LevelBlock
	default:
		switch capabilityToFsmLevel(actionID) {
		case "soft":
			return st.Level == fsm.LevelSoft
		case "hard":
			return st.Level == fsm.LevelHard
		case "block":
			return st.Level == fsm.LevelBlock
		default:
			return false
		}
	}
}

func reactionEvidenceAllowsLocalRuntimeState(params map[string]any) bool {
	for _, evidence := range reactionPreviousActionEvidence(params) {
		switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(evidence)), "-", "_") {
		case "local_runtime_state", "local_enforcement_state", "local_state":
			return true
		}
	}
	return false
}

func reactionPreviousActionEvidence(params map[string]any) []string {
	value, ok := anyParam(params, "previous_action_evidence")
	if !ok {
		return []string{"runtime_response_state"}
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		var out []string
		for _, part := range strings.Split(typed, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func (e *runtimeReactionEngine) recordActiveAction(
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	res actions.ActionResolution,
	now time.Time,
) {
	if e == nil || res.ExecutableAction == "" || res.ExecutableLevel == "" || res.ExecutableLevel == "observe" {
		return
	}
	ttl := res.TTL
	if ttl <= 0 {
		ttl = action.TTL.Duration
	}
	if ttl <= 0 {
		return
	}
	record := reactionActiveAction{
		ActionID:        normalizeCapabilityID(res.ExecutableAction),
		Level:           res.ExecutableLevel,
		SourceID:        event.SourceID,
		ResourceRef:     event.Rule.ResourceRef,
		ResponseRuleID:  rule.ID,
		DetectionRuleID: event.Rule.ID,
		AppliedAt:       now,
		ExpiresAt:       now.Add(ttl),
	}
	ids := []string{record.ActionID}
	if authoredID := normalizeCapabilityID(action.ID); authoredID != "" && authoredID != record.ActionID {
		ids = append(ids, authoredID)
	}
	e.mu.Lock()
	if e.activeActions == nil {
		e.activeActions = map[string]reactionActiveAction{}
	}
	for key, active := range e.activeActions {
		if !active.ExpiresAt.IsZero() && !now.Before(active.ExpiresAt) {
			delete(e.activeActions, key)
		}
	}
	for _, id := range ids {
		id = normalizeCapabilityID(id)
		if id == "" {
			continue
		}
		record.ActionID = id
		e.activeActions[reactionActiveActionKey(id, event.SourceID, event.Rule.ResourceRef)] = record
	}
	snap := e.snapshotLocked()
	e.mu.Unlock()
	e.persistSnapshot(snap)
}

func reactionActiveActionKey(actionID, sourceID, resourceRef string) string {
	return strings.Join([]string{normalizeCapabilityID(actionID), strings.TrimSpace(sourceID), strings.TrimSpace(resourceRef)}, "|")
}

func reactionActionProposal(
	nodeID string,
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	now time.Time,
) (actions.ActionProposal, bool) {
	capability := normalizeCapabilityID(action.ID)
	level := reactionActionLevel(action, capability)
	if capability == "" || level == "" || level == "observe" {
		return actions.ActionProposal{}, false
	}
	target := reactionActionTarget(action.Target, event)
	params := copyAnyMap(action.Params)
	if params == nil {
		params = map[string]any{}
	}
	params["node_id"] = nodeID
	params["response_rule_id"] = rule.ID
	params["detection_rule_id"] = event.Rule.ID
	params["detection_count"] = event.Count
	params["detection_window"] = event.Window.String()
	params["runtime_action_id"] = action.ID
	params["runtime_action_from"] = "response_policy"
	return actions.ActionProposal{
		ID:            fmt.Sprintf("reaction-%s-%s-%d", sanitizeReactionID(rule.ID), sanitizeReactionID(event.SourceID), now.UnixNano()),
		Source:        "reaction",
		Reason:        "reaction:" + event.Rule.ID,
		DesiredAction: capability,
		DesiredLevel:  level,
		Target:        target,
		Parameters:    params,
		TTL:           action.TTL.Duration,
		Confidence:    1,
		CreatedAt:     now,
	}, true
}

func reactionActionLevel(action contracts.RuntimeResponseAction, capability string) string {
	switch strings.TrimSpace(action.Severity) {
	case "soft", "hard", "block":
		return action.Severity
	}
	return capabilityToFsmLevel(capability)
}

func reactionActionTarget(target contracts.RuntimeResponseTarget, event reactionDetectionEvent) actions.ActionTarget {
	scope := strings.TrimSpace(target.Scope)
	value := strings.TrimSpace(target.Ref)
	if value == "" {
		value = event.SourceID
	}
	switch scope {
	case "", "source", "source.ip", "source.identity_or_ip":
		return actions.ActionTarget{
			Granularity: actions.TargetGranularitySource,
			Value:       value,
			Attributes:  copyStringMap(event.SourceAttrs),
		}
	default:
		return actions.ActionTarget{
			Granularity: scope,
			Value:       value,
			Attributes:  copyStringMap(event.SourceAttrs),
		}
	}
}

func reactionResponseMatches(trigger contracts.RuntimeResponseTrigger, detectionID string) bool {
	if trigger.Detection == "" {
		return false
	}
	if trigger.Detection == detectionID {
		return true
	}
	return strings.HasSuffix(trigger.Detection, "/"+detectionID)
}

func reactionMetricsFromSignal(sig signal.Signal) metrics {
	attrs := copyStringMap(sig.Attributes)
	if attrs == nil {
		attrs = map[string]string{}
	}
	sourceID := sig.Subject.ID
	if sourceID == "" {
		sourceID = firstStringAttr(attrs, "source.id", "source_id", "source.ip", "source_ip", "source")
	}
	if attrs["resource.ref"] == "" && sig.Object.ID != "" {
		attrs["resource.ref"] = sig.Object.ID
	}
	if attrs["object.kind"] == "" && sig.Object.Kind != "" {
		attrs["object.kind"] = string(sig.Object.Kind)
	}
	signals := map[string]float64{
		"signal.score":      float64(sig.Score),
		"signal.confidence": float64(sig.Confidence),
		string(sig.Type):    1,
	}
	for key, value := range attrs {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			signals[key] = parsed
		}
	}
	if isAccessDeniedSignal(sig) {
		signals["access.denied"] = signalCountAttr(attrs)
	}
	if sig.Type == signal.SignalRateLimitDropsSustained {
		dropRate := firstPositiveAttrFloat(attrs, "network.rate_limit_drop_rate", "rate_limit_drop_rate", "drop_rate", "drop_rl_rate")
		if dropRate <= 0 {
			dropRate = 1
		}
		signals[adapterruntime.MetricNetworkRateLimitDropRate] = dropRate
		signals[string(signal.SignalRateLimitDropsSustained)] = dropRate
	}
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID:   sourceID,
			Subject:    sig.Subject,
			Attributes: attrs,
		},
		Score:   float64(sig.Score),
		Signals: signals,
	}
}

func reactionObservationCount(rule contracts.RuntimeDetectionRule, m metrics) int {
	switch strings.TrimSpace(rule.Type) {
	case "access.denied_threshold", "access_denied":
		return firstPositiveSignalCount(m, "access.denied", "access.denied_count", "access_denied", "events.access_denied", "security.access_denied")
	case "network.rate_limit_drop_threshold", "source.rate_limit_drops_sustained":
		return int(math.Ceil(m.enforcementFeedbackRate()))
	case "signal.threshold", "signal.score_threshold":
		return signalThresholdCount(rule, m)
	case "metric.threshold":
		return metricThresholdCount(rule, m)
	default:
		return metricThresholdCount(rule, m)
	}
}

func firstPositiveSignalCount(m metrics, keys ...string) int {
	for _, key := range keys {
		value := m.signalValue(key)
		if value <= 0 {
			continue
		}
		if value < 1 {
			return 1
		}
		return int(math.Ceil(value))
	}
	return 0
}

func sustainedDetectionRequiresFullWindow(rule contracts.RuntimeDetectionRule) bool {
	switch strings.TrimSpace(rule.Type) {
	case "source.rate_limit_drops_sustained":
		return rule.Window.Duration > 0
	default:
		return false
	}
}

func reactionSamplesCoverWindow(samples []reactionSample, window time.Duration, now time.Time) bool {
	if window <= 0 {
		return true
	}
	cutoff := now.Add(-window)
	tolerance := reactionSustainedWindowTolerance(window)
	for _, sample := range samples {
		if sample.Count <= 0 {
			continue
		}
		if sample.At.After(cutoff) {
			continue
		}
		if sample.At.Before(cutoff.Add(-tolerance)) {
			continue
		}
		return true
	}
	return false
}

func reactionSustainedWindowTolerance(window time.Duration) time.Duration {
	tolerance := window / 4
	if tolerance < 2*time.Second {
		return 2 * time.Second
	}
	if tolerance > 5*time.Second {
		return 5 * time.Second
	}
	return tolerance
}

func signalThresholdCount(rule contracts.RuntimeDetectionRule, m metrics) int {
	signalType := stringAnyParam(rule.Params, "signal_type", "type")
	if signalType != "" && m.signalValue(signalType) <= 0 {
		return 0
	}
	minScore := floatAnyParam(rule.Params, "min_score", "score", "threshold")
	if minScore <= 0 {
		minScore = float64(rule.Threshold)
	}
	if minScore <= 0 {
		return 1
	}
	if m.signalValue("signal.score") >= minScore {
		return 1
	}
	return 0
}

func metricThresholdCount(rule contracts.RuntimeDetectionRule, m metrics) int {
	metricID := stringAnyParam(rule.Params, "metric", "signal", "key")
	if metricID == "" {
		return 0
	}
	op := stringAnyParam(rule.Params, "operator", "op")
	if op == "" {
		op = "gt"
	}
	if wanted, ok := anyParam(rule.Params, "value", "threshold"); ok && isStringComparisonValue(wanted, op) {
		if compareStringValue(metricStringValue(m, metricID), op, wanted) {
			return 1
		}
		return 0
	}
	value := m.signalValue(metricID)
	if normalizeRuntimeReactionMetricKey(metricID) == "runtime.risk.score" {
		value = float64(runtimeReactionRiskScore(m))
	}
	threshold := floatAnyParam(rule.Params, "value", "threshold")
	if compareFloat(value, op, threshold) {
		return 1
	}
	return 0
}

func metricStringValue(m metrics, metricID string) string {
	switch normalizeRuntimeReactionMetricKey(metricID) {
	case "runtime.risk.level":
		return string(riskLevelForScore(runtimeReactionRiskScore(m)))
	case "runtime.risk.score":
		return strconv.Itoa(runtimeReactionRiskScore(m))
	}
	if attrs := m.Target.Attributes; attrs != nil {
		if value := strings.TrimSpace(attrs[metricID]); value != "" {
			return value
		}
		if value := strings.TrimSpace(attrs[strings.ReplaceAll(metricID, ".", "_")]); value != "" {
			return value
		}
	}
	if value := m.signalValue(metricID); value != 0 {
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	return ""
}

func normalizeRuntimeReactionMetricKey(key string) string {
	key = strings.TrimSpace(key)
	switch key {
	case "risk", "risk.level", "runtime.risk.level":
		return "runtime.risk.level"
	case "risk.score", "runtime.risk.score":
		return "runtime.risk.score"
	default:
		return key
	}
}

func runtimeReactionRiskScore(m metrics) int {
	if value := m.signalValue("runtime.risk.score"); value > 0 {
		return clampInt(int(math.Round(value)), 0, 100)
	}
	if value := m.signalValue("risk.score"); value > 0 {
		return clampInt(int(math.Round(value)), 0, 100)
	}
	if value := m.signalValue("signal.score"); value > 0 {
		return clampInt(int(math.Round(value)), 0, 100)
	}
	return clampInt(int(math.Round(m.score())), 0, 100)
}

func isStringComparisonValue(value any, op string) bool {
	switch op {
	case "in", "not_in":
		return true
	}
	switch v := value.(type) {
	case []string:
		return true
	case []interface{}:
		return true
	case string:
		_, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return err != nil
	default:
		return false
	}
}

func compareStringValue(got, op string, wanted any) bool {
	got = strings.TrimSpace(got)
	matches := stringValueMatches(got, wanted)
	switch op {
	case "eq", "equals", "is":
		return matches
	case "neq", "not":
		return !matches
	case "in":
		return matches
	case "not_in":
		return !matches
	default:
		return false
	}
}

func stringValueMatches(got string, wanted any) bool {
	for _, value := range paramStringList(wanted) {
		if got == value {
			return true
		}
	}
	return false
}

func paramStringList(value any) []string {
	switch v := value.(type) {
	case []string:
		return cleanStringList(v)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
		return cleanStringList(out)
	case string:
		parts := strings.Split(strings.Trim(v, "[]"), ",")
		return cleanStringList(parts)
	default:
		return cleanStringList([]string{fmt.Sprint(v)})
	}
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.Trim(value, " \t\n\r\"'")
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func isAccessDeniedSignal(sig signal.Signal) bool {
	switch strings.TrimSpace(string(sig.Type)) {
	case "access.denied", "access_denied", "event.access_denied", "policy.access_denied", "security.access_denied":
		return true
	}
	eventType := firstStringAttr(sig.Attributes, "event.type", "event_type", "access.result", "access_result")
	return eventType == "denied" || eventType == "access_denied"
}

func signalCountAttr(attrs map[string]string) float64 {
	count := firstPositiveAttrFloat(attrs, "count", "events", "access.denied_count", "access_denied_count")
	if count <= 0 {
		return 1
	}
	return count
}

func firstPositiveAttrFloat(attrs map[string]string, keys ...string) float64 {
	for _, key := range keys {
		value := strings.TrimSpace(attrs[key])
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return 0
}

func compareFloat(left float64, op string, right float64) bool {
	switch op {
	case "eq":
		return left == right
	case "neq":
		return left != right
	case "gte":
		return left >= right
	case "lte":
		return left <= right
	case "lt":
		return left < right
	default:
		return left > right
	}
}

func reactionDetectionKey(rule contracts.RuntimeDetectionRule, m metrics) string {
	if raw, ok := anyParam(rule.Params, "group_by"); ok {
		if values := reactionGroupByValues(paramStringList(raw), m); len(values) > 0 {
			return rule.ID + "|group_by|" + strings.Join(values, "|")
		}
	}
	scope := strings.TrimSpace(rule.Scope)
	if scope == "" {
		scope = "source"
	}
	return rule.ID + "|" + scope + "|" + m.sourceID()
}

func reactionGroupByValues(keys []string, m metrics) []string {
	var out []string
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value := reactionGroupByValue(key, m)
		if value == "" {
			continue
		}
		out = append(out, key+"="+value)
	}
	return out
}

func reactionGroupByValue(key string, m metrics) string {
	switch key {
	case "source.identity_or_ip", "source.id", "source.ip":
		return m.sourceID()
	case "subject.id":
		if m.Target.Subject.ID != "" {
			return m.Target.Subject.ID
		}
		return firstStringAttr(m.Target.Attributes, "subject.id", "subject_id")
	case "resource.id", "resource.ref":
		return firstStringAttr(m.Target.Attributes, "resource.id", "resource_id", "resource.ref", "resource_ref", "resource")
	default:
		if value := firstStringAttr(m.Target.Attributes, key, strings.ReplaceAll(key, ".", "_")); value != "" {
			return value
		}
		return ""
	}
}

func reactionSubjectMatches(subject contracts.RuntimeDetectionSubject, target adapterruntime.SourceTarget) bool {
	if subject.Type == "" && subject.Ref == "" && subject.Selector == "" {
		return true
	}
	if subject.Selector == "unknown_source" {
		status := firstStringAttr(target.Attributes, "subject.resolution.status", "subject_resolution_status", "resolution.status")
		if status == "known" || status == "resolved" {
			return false
		}
		switch target.Subject.Kind {
		case "user", "group", "role", "service_account", "device":
			return false
		default:
			return true
		}
	}
	if subject.Selector == "known_subject" {
		return reactionKnownSubject(target)
	}
	if subject.Selector == "known_subject_excluding_group" {
		if !reactionKnownSubject(target) {
			return false
		}
		if subject.Type != "group" || subject.Ref == "" {
			return true
		}
		groups := firstStringAttr(target.Attributes, "subject.groups", "subject_groups", "subjectGroups", "group")
		if groups == "" {
			return false
		}
		return !reactionListContains(groups, subject.Ref)
	}
	if subject.Ref == "" {
		return true
	}
	if target.Subject.ID == subject.Ref || target.SourceID == subject.Ref {
		return true
	}
	if subject.Type == "group" {
		groups := firstStringAttr(target.Attributes, "subject.groups", "subject_groups", "subjectGroups", "group")
		return reactionListContains(groups, subject.Ref)
	}
	return false
}

func reactionKnownSubject(target adapterruntime.SourceTarget) bool {
	status := firstStringAttr(target.Attributes, "subject.resolution.status", "subject_resolution_status", "resolution.status")
	if status == "known" || status == "resolved" {
		return true
	}
	switch target.Subject.Kind {
	case "user", "group", "role", "service_account", "device", "workload":
		return target.Subject.ID != ""
	default:
		return false
	}
}

func reactionResourceMatches(resourceRef string, attrs map[string]string) bool {
	resourceRef = strings.TrimSpace(resourceRef)
	if resourceRef == "" {
		return true
	}
	resource := reactionResourceAttr(attrs)
	if resource == "" {
		return false
	}
	return resource == resourceRef
}

func reactionDetectionResourceMatches(rule contracts.RuntimeDetectionRule, m metrics) bool {
	if reactionResourceMatches(rule.ResourceRef, m.Target.Attributes) {
		return true
	}
	if strings.TrimSpace(rule.ResourceRef) == "" {
		return true
	}
	if strings.TrimSpace(rule.Type) != "source.rate_limit_drops_sustained" {
		return false
	}
	if reactionResourceAttr(m.Target.Attributes) != "" {
		return false
	}
	return m.enforcementFeedbackRate() > 0
}

func reactionResourceAttr(attrs map[string]string) string {
	return firstStringAttr(attrs, "resource.ref", "resource_ref", "resource", "service", "service_id", "target", "target_id")
}

func firstStringAttr(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if attrs[key] != "" {
			return attrs[key]
		}
	}
	return ""
}

func reactionListContains(values, want string) bool {
	if values == "" || want == "" {
		return false
	}
	for _, part := range strings.Split(values, ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}

func stringAnyParam(params map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func anyParam(params map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		value, ok := params[key]
		if ok {
			return value, true
		}
	}
	return nil, false
}

func boolAnyParam(params map[string]any, keys ...string) bool {
	for _, key := range keys {
		value, ok := params[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			typed = strings.ToLower(strings.TrimSpace(typed))
			return typed == "true" || typed == "yes" || typed == "1"
		case int:
			return typed != 0
		case int64:
			return typed != 0
		case float64:
			return typed != 0
		default:
			return strings.EqualFold(fmt.Sprint(typed), "true")
		}
	}
	return false
}

func floatAnyParam(params map[string]any, keys ...string) float64 {
	for _, key := range keys {
		value, ok := params[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case uint64:
			return float64(v)
		case string:
			parsed, _ := strconv.ParseFloat(v, 64)
			return parsed
		default:
			parsed, _ := strconv.ParseFloat(fmt.Sprint(v), 64)
			return parsed
		}
	}
	return 0
}

func sanitizeReactionID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "-")
}

func copyReactionWindows(in map[string][]reactionSample) map[string][]reactionSample {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]reactionSample, len(in))
	for key, samples := range in {
		out[key] = append([]reactionSample(nil), samples...)
	}
	return out
}

func copyTimeMap(in map[string]time.Time) map[string]time.Time {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]time.Time, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyReactionActiveDetections(in map[string]reactionActiveDetection) map[string]reactionActiveDetection {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]reactionActiveDetection, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyReactionActiveActions(in map[string]reactionActiveAction) map[string]reactionActiveAction {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]reactionActiveAction, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyReactionActiveAlerts(in map[string]reactionActiveAlert) map[string]reactionActiveAlert {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]reactionActiveAlert, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
