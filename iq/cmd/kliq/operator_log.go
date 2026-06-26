// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kernloom/kernloom/pkg/core/signal"
)

type kliqRuntimeLogLevel int

const (
	kliqLogQuiet kliqRuntimeLogLevel = iota
	kliqLogInfo
	kliqLogDebug
)

var (
	kliqCurrentLogLevel = kliqLogInfo
	kliqColorEnabled    bool

	signalLogMu   sync.Mutex
	signalLastLog = map[string]time.Time{}
)

func configureKLIQLogging(c cfg) {
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "quiet", "warn", "warning", "error":
		kliqCurrentLogLevel = kliqLogQuiet
	case "debug", "verbose", "trace":
		kliqCurrentLogLevel = kliqLogDebug
	default:
		kliqCurrentLogLevel = kliqLogInfo
	}
	switch strings.ToLower(strings.TrimSpace(c.LogColor)) {
	case "always", "true", "yes", "on":
		kliqColorEnabled = true
	case "never", "false", "no", "off":
		kliqColorEnabled = false
	default:
		kliqColorEnabled = stderrLooksInteractive()
	}
}

func kliqDebugf(format string, args ...any) {
	if kliqCurrentLogLevel < kliqLogDebug {
		return
	}
	kliqLog.Printf("%s", decorateOperatorMessage(fmt.Sprintf(format, args...)))
}

func kliqEventf(level kliqRuntimeLogLevel, tag string, format string, args ...any) {
	if kliqCurrentLogLevel < level {
		return
	}
	kliqLog.Printf("%s %s", colorLogTag(tag), decorateOperatorMessage(fmt.Sprintf(format, args...)))
}

func colorLogTag(tag string) string {
	clean := strings.ToUpper(strings.TrimSpace(tag))
	if clean == "" {
		clean = "INFO"
	}
	if !kliqColorEnabled {
		return clean
	}
	label := clean
	if icon := logTagIcon(clean); icon != "" {
		label = icon + " " + clean
	}
	switch clean {
	case "WARN", "DRIFT":
		return "\x1b[33m" + label + "\x1b[0m"
	case "ACTION", "STATE", "ACCESS":
		return "\x1b[36m" + label + "\x1b[0m"
	case "ALERT", "NOTIFY":
		return "\x1b[35m" + label + "\x1b[0m"
	case "DECISION", "RISK", "SIGNAL":
		return "\x1b[32m" + label + "\x1b[0m"
	default:
		return "\x1b[2m" + label + "\x1b[0m"
	}
}

func logTagIcon(tag string) string {
	switch tag {
	case "WARN":
		return "⚠️"
	case "DRIFT":
		return "🧭"
	case "ACTION":
		return "⚙️"
	case "STATE":
		return "🚦"
	case "ACCESS":
		return "🔐"
	case "ALERT":
		return "🚨"
	case "NOTIFY":
		return "📣"
	case "DECISION":
		return "🧠"
	case "RISK":
		return "📈"
	case "SIGNAL":
		return "📡"
	default:
		return ""
	}
}

func decorateOperatorMessage(message string) string {
	if !kliqColorEnabled {
		return message
	}
	return decorateRuntimeLevels(message)
}

func decorateRuntimeLevels(message string) string {
	var out strings.Builder
	for i := 0; i < len(message); {
		if runtimeLevelBoundaryBefore(message, i) {
			if level, n := runtimeLevelTokenAt(message[i:]); n > 0 && runtimeLevelBoundaryAfter(message, i+n) {
				out.WriteString(colorRuntimeLevel(level))
				i += n
				continue
			}
		}
		out.WriteByte(message[i])
		i++
	}
	return out.String()
}

func runtimeLevelTokenAt(value string) (string, int) {
	for _, level := range []string{"observe", "soft", "hard", "block"} {
		if len(value) >= len(level) && strings.EqualFold(value[:len(level)], level) {
			return value[:len(level)], len(level)
		}
	}
	return "", 0
}

func runtimeLevelBoundaryBefore(value string, index int) bool {
	if index <= 0 {
		return true
	}
	return runtimeLevelBoundaryByte(value[index-1])
}

func runtimeLevelBoundaryAfter(value string, index int) bool {
	if index >= len(value) {
		return true
	}
	return runtimeLevelBoundaryByte(value[index])
}

func runtimeLevelBoundaryByte(c byte) bool {
	return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.')
}

func colorRuntimeLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "observe":
		return "\x1b[90m👁 OBSERVE\x1b[0m"
	case "soft":
		return "\x1b[36m🟦 SOFT\x1b[0m"
	case "hard":
		return "\x1b[33m🟨 HARD\x1b[0m"
	case "block":
		return "\x1b[31;1m🟥 BLOCK\x1b[0m"
	default:
		return level
	}
}

func stderrLooksInteractive() bool {
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func shouldLogRuntimeSignal(sig signal.Signal, now time.Time) bool {
	if kliqCurrentLogLevel >= kliqLogDebug {
		return true
	}
	if kliqCurrentLogLevel < kliqLogInfo {
		return false
	}
	if sig.Score < 40 && !importantRuntimeSignal(sig) {
		return false
	}
	interval := 30 * time.Second
	if sig.Score >= 80 || importantRuntimeSignal(sig) {
		interval = 10 * time.Second
	}
	key := string(sig.Type) + "|" + sig.Subject.ID
	signalLogMu.Lock()
	defer signalLogMu.Unlock()
	if last := signalLastLog[key]; !last.IsZero() && now.Sub(last) < interval {
		return false
	}
	signalLastLog[key] = now
	return true
}

func importantRuntimeSignal(sig signal.Signal) bool {
	switch sig.Type {
	case signal.SignalReactionAlert, signal.SignalGraphNewEdgeAfterFreeze:
		return true
	default:
		return strings.Contains(string(sig.Type), "deny") || strings.Contains(string(sig.Type), "drop")
	}
}
