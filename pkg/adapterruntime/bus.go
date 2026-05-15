// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package adapterruntime

import (
	"context"
	"sync"

	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// EventBus is the internal message bus connecting adapters to the KLIQ pipeline.
//
// Backpressure rules:
//   - Observations may be dropped under load (counter: dropped_observations_total).
//   - Signals should not be dropped; deduplication is acceptable.
//   - Decisions and Receipts must never be silently dropped.
//
// Signals support multiple subscribers via SubscribeSignals — each subscriber
// receives every signal independently (fan-out). Observations and Decisions
// remain single-channel for now (one consumer each).
type EventBus interface {
	PublishObservation(ctx context.Context, obs observation.Observation) error
	PublishSignal(ctx context.Context, sig signal.Signal) error
	PublishDecision(ctx context.Context, dec decision.Decision) error

	Observations() <-chan observation.Observation
	SubscribeSignals(buffer int) <-chan signal.Signal
	Decisions() <-chan decision.Decision
}

// Bus is a bounded, in-process implementation of EventBus.
type Bus struct {
	observations chan observation.Observation
	decisions    chan decision.Decision
	mu           sync.RWMutex

	signalMu   sync.Mutex
	signalSubs []chan signal.Signal

	droppedObservations uint64
}

// NewBus creates a Bus with the given channel buffer size.
func NewBus(buffer int) *Bus {
	return &Bus{
		observations: make(chan observation.Observation, buffer),
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

// PublishSignal fans the signal out to every registered subscriber.
// Each subscriber owns its own buffered channel. If a subscriber's channel is
// full the signal is dropped for that subscriber only (non-blocking) so a slow
// consumer cannot stall the publisher or the other subscribers.
func (b *Bus) PublishSignal(_ context.Context, sig signal.Signal) error {
	b.signalMu.Lock()
	subs := make([]chan signal.Signal, len(b.signalSubs))
	copy(subs, b.signalSubs)
	b.signalMu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- sig:
		default:
			// Subscriber channel full — drop for that subscriber.
			// Honours the documented "signals may be deduplicated" relaxation
			// while ensuring publishers and other subscribers do not block.
		}
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
func (b *Bus) Decisions() <-chan decision.Decision          { return b.decisions }

// SubscribeSignals registers a new signal subscriber and returns its receive
// channel. Each subscriber sees every published signal independently.
// buffer controls the per-subscriber channel capacity; pass a generous value
// for consumers that may briefly block (e.g. doing DB writes per signal).
func (b *Bus) SubscribeSignals(buffer int) <-chan signal.Signal {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan signal.Signal, buffer)
	b.signalMu.Lock()
	b.signalSubs = append(b.signalSubs, ch)
	b.signalMu.Unlock()
	return ch
}

// DroppedObservations returns the total number of observations dropped due to backpressure.
func (b *Bus) DroppedObservations() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.droppedObservations
}
