// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package adapterruntime

import (
	"context"
	"sync"

	"github.com/adrianenderlin/kernloom/pkg/core/decision"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	"github.com/adrianenderlin/kernloom/pkg/core/signal"
)

// EventBus is the internal message bus connecting adapters to the KLIQ pipeline.
//
// Backpressure rules:
//   - Observations may be dropped under load (counter: dropped_observations_total).
//   - Signals should not be dropped; deduplication is acceptable.
//   - Decisions and Receipts must never be silently dropped.
type EventBus interface {
	PublishObservation(ctx context.Context, obs observation.Observation) error
	PublishSignal(ctx context.Context, sig signal.Signal) error
	PublishDecision(ctx context.Context, dec decision.Decision) error

	Observations() <-chan observation.Observation
	Signals() <-chan signal.Signal
	Decisions() <-chan decision.Decision
}

// Bus is a bounded, in-process implementation of EventBus.
type Bus struct {
	observations chan observation.Observation
	signals      chan signal.Signal
	decisions    chan decision.Decision
	mu           sync.RWMutex

	droppedObservations uint64
}

// NewBus creates a Bus with the given channel buffer size.
func NewBus(buffer int) *Bus {
	return &Bus{
		observations: make(chan observation.Observation, buffer),
		signals:      make(chan signal.Signal, buffer),
		decisions:    make(chan decision.Decision, buffer),
	}
}

// PublishObservation sends an observation; drops without blocking when buffer is full.
func (b *Bus) PublishObservation(_ context.Context, obs observation.Observation) error {
	select {
	case b.observations <- obs:
	default:
		b.mu.Lock()
		b.droppedObservations++
		b.mu.Unlock()
	}
	return nil
}

// PublishSignal sends a signal; blocks briefly but does not drop.
func (b *Bus) PublishSignal(ctx context.Context, sig signal.Signal) error {
	select {
	case b.signals <- sig:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// PublishDecision sends a decision; blocks until delivered or context expires.
func (b *Bus) PublishDecision(ctx context.Context, dec decision.Decision) error {
	select {
	case b.decisions <- dec:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (b *Bus) Observations() <-chan observation.Observation { return b.observations }
func (b *Bus) Signals() <-chan signal.Signal                { return b.signals }
func (b *Bus) Decisions() <-chan decision.Decision          { return b.decisions }

// DroppedObservations returns the total number of observations dropped due to backpressure.
func (b *Bus) DroppedObservations() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.droppedObservations
}
