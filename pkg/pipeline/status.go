// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package pipeline

import "time"

// Status holds the current pipeline metrics for logging and Forge status reporting.
type Status struct {
	// Mode is the current pipeline mode.
	Mode Mode

	// StartedAt is when the pipeline was started.
	StartedAt time.Time

	// Ticks is the number of evaluation windows processed.
	Ticks uint64

	// MetricsExtracted is the total number of metric values extracted.
	MetricsExtracted uint64

	// UnknownMetricsDropped is the count of metrics dropped due to unknown metric ID.
	UnknownMetricsDropped uint64

	// LearnedWindows is the number of windows where baselines were updated.
	LearnedWindows uint64

	// SuspiciousWindows is the number of windows skipped due to learning guards.
	SuspiciousWindows uint64

	// SignalsEmitted is the total number of shadow signals produced.
	SignalsEmitted uint64

	// DryRunProposals is the number of dry-run action proposals generated (audit mode).
	DryRunProposals uint64

	// DroppedObs is the number of observations dropped due to channel backpressure.
	DroppedObs uint64

	// BaselineProfiles is the current number of active baseline profiles.
	BaselineProfiles int
}
