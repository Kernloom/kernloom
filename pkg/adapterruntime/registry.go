// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package adapterruntime

import (
	"fmt"
	"sync"

	"github.com/kernloom/kernloom/pkg/core/capability"
)

// Registry tracks which capabilities are available at runtime.
// Each adapter registers its capabilities on startup; the registry is queried
// by KLIQ when reporting to Forge or evaluating policy pack requirements.
//
// The registry is thread-safe and designed for single-writer / many-reader use.
type Registry struct {
	mu        sync.RWMutex
	byAdapter map[string][]*capability.Capability // adapterID -> capabilities
	index     map[string]*capability.Capability   // capabilityID -> first registered Capability
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byAdapter: make(map[string][]*capability.Capability),
		index:     make(map[string]*capability.Capability),
	}
}

// Register records the capabilities an adapter provides.
// If the adapter was previously registered, its capabilities are replaced.
// Returns an error if any capability has an empty ID.
func (r *Registry) Register(adapterID string, caps []*capability.Capability) error {
	for _, c := range caps {
		if c.ID == "" {
			return fmt.Errorf("adapter %q: capability with empty ID", adapterID)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove old entries from the index.
	for _, old := range r.byAdapter[adapterID] {
		delete(r.index, old.ID)
	}

	tagged := make([]*capability.Capability, len(caps))
	for i, c := range caps {
		cp := *c
		cp.Adapter = adapterID
		tagged[i] = &cp
		r.index[cp.ID] = &cp
	}

	r.byAdapter[adapterID] = tagged
	return nil
}

// Unregister removes all capabilities reported by the given adapter.
func (r *Registry) Unregister(adapterID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, c := range r.byAdapter[adapterID] {
		delete(r.index, c.ID)
	}
	delete(r.byAdapter, adapterID)
}

// Has reports whether a capability with the given ID is registered.
func (r *Registry) Has(capabilityID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.index[capabilityID]
	return ok
}

// Lookup returns the capability for the given ID, or false if not registered.
func (r *Registry) Lookup(capabilityID string) (*capability.Capability, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.index[capabilityID]
	return c, ok
}

// All returns all registered capabilities across all adapters.
func (r *Registry) All() []*capability.Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*capability.Capability, 0, len(r.index))
	for _, c := range r.index {
		out = append(out, c)
	}
	return out
}

// ByAdapter returns the capabilities registered by a specific adapter.
func (r *Registry) ByAdapter(adapterID string) []*capability.Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byAdapter[adapterID]
}

// HasAll reports whether all listed capability IDs are registered.
// Used by KLIQ to validate that a policy pack's required capabilities are met.
func (r *Registry) HasAll(ids []string) (missing []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, id := range ids {
		if _, ok := r.index[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}
