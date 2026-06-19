// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

type fsmActionExecutor interface {
	ApplySource(adapterruntime.SourceTarget, fsm.State, actions.ActionResolution, adapterruntime.EnforcementParams, time.Time) (fsm.State, actions.ActionResult)
	ApplyDeEnforceSource(adapterruntime.SourceTarget, fsm.State, adapterruntime.EnforcementParams, time.Time) fsm.State
}

type sourceMatcher interface {
	MatchSource(string) bool
}

func recordTuningSample(tuner adapterruntime.Tuner, m metrics, accepted bool) {
	if tuner == nil {
		return
	}
	tuner.RecordSample(adapterruntime.TuningSample{
		PacketsPerSecond:       m.signalValue(adapterruntime.MetricNetworkPacketsPerSecond),
		SynRate:                m.signalValue(adapterruntime.MetricNetworkSynRate),
		DestinationPortChanges: m.signalValue(adapterruntime.MetricNetworkDestinationPortChanges),
		BytesPerSecond:         m.signalValue(adapterruntime.MetricNetworkBytesPerSecond),
		SourceID:               m.sourceID(),
		Accepted:               accepted,
	})
}

// toFSMMetrics converts a kliq metrics struct to fsm.Metrics. The metric IDs
// are canonical; adapters decide which concrete observations populate them.
func (m metrics) toFSMMetrics() fsm.Metrics {
	return fsm.Metrics{
		PPS:        m.signalValue(adapterruntime.MetricNetworkPacketsPerSecond),
		Bps:        m.signalValue(adapterruntime.MetricNetworkBytesPerSecond),
		SynRate:    m.signalValue(adapterruntime.MetricNetworkSynRate),
		ScanRate:   m.signalValue(adapterruntime.MetricNetworkDestinationPortChanges),
		DropRLRate: m.enforcementFeedbackRate(),
		Severity:   m.score(),
	}
}
