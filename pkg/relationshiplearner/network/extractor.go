// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package network provides the L3/L4 network relationship extractor.
// It derives "network.connects_to" relationships from TypeFlow observations,
// replicating the filtering logic that was previously embedded in graphlearner.
package network

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

// Predicate is the relationship predicate produced by this extractor.
const Predicate = "network.connects_to"

// Config controls extractor filtering behaviour.
type Config struct {
	NodeID            string
	ExcludeLoopback   bool
	ExcludeBroadcast  bool
	ExcludeSourceCIDRs []net.IPNet
	MinPackets        uint64
	MinBytes          uint64
	// CollapseEphemeralPorts collapses destination ports >= 32768 to 0.
	CollapseEphemeralPorts bool
}

// DefaultConfig returns safe production defaults.
func DefaultConfig(nodeID string) Config {
	return Config{
		NodeID:                 nodeID,
		ExcludeLoopback:        true,
		ExcludeBroadcast:       true,
		CollapseEphemeralPorts: true,
	}
}

// Extractor derives network.connects_to relationships from TypeFlow observations.
type Extractor struct {
	cfg Config
}

// New creates a network Extractor.
func New(cfg Config) *Extractor {
	return &Extractor{cfg: cfg}
}

func (e *Extractor) Name() string { return "network" }

// Extract returns network.connects_to candidates from flow observations.
func (e *Extractor) Extract(_ context.Context, obs []observation.Observation) ([]relationship.Relationship, error) {
	now := time.Now().UTC()
	var result []relationship.Relationship

	for _, o := range obs {
		if o.Type != observation.TypeFlow {
			continue
		}
		if o.Subject.ID == "" {
			continue
		}
		// Require destination_port for L4 relationships.
		if o.Attributes["destination_port"] == "" {
			continue
		}

		// Fill missing object with local node.
		objID := o.Object.ID
		if objID == "" {
			objID = o.NodeID
			if objID == "" {
				objID = e.cfg.NodeID
			}
		}

		// Relevance filters.
		if e.cfg.ExcludeLoopback && (isLoopback(o.Subject.ID) || isLoopback(objID)) {
			continue
		}
		if e.cfg.ExcludeBroadcast && isBroadcastOrMulticast(objID) {
			continue
		}
		if len(e.cfg.ExcludeSourceCIDRs) > 0 && isInCIDRs(o.Subject.ID, e.cfg.ExcludeSourceCIDRs) {
			continue
		}
		if e.cfg.MinPackets > 0 && uint64(o.Metrics["packets"]) < e.cfg.MinPackets {
			continue
		}
		if e.cfg.MinBytes > 0 && uint64(o.Metrics["bytes"]) < e.cfg.MinBytes {
			continue
		}

		proto := o.Attributes["protocol"]
		if proto == "" {
			proto = "unknown"
		}
		dstPort := uint16(0)
		if p, err := strconv.ParseUint(o.Attributes["destination_port"], 10, 16); err == nil {
			dstPort = uint16(p)
		}
		if e.cfg.CollapseEphemeralPorts && dstPort >= 32768 {
			dstPort = 0
		}

		dir := "ingress"
		if ip := net.ParseIP(o.Subject.ID); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
			dir = "egress"
		}

		dims := map[string]string{
			"protocol":         proto,
			"destination_port": strconv.Itoa(int(dstPort)),
			"direction":        dir,
		}

		subjectID := sqlite.StableEntityID("ip", o.Subject.ID, "")
		objectID := sqlite.StableEntityID("ip", objID, "")

		result = append(result, relationship.Relationship{
			NodeID:          e.cfg.NodeID,
			SubjectEntityID: subjectID,
			Predicate:       Predicate,
			ObjectEntityID:  objectID,
			Dimensions:      dims,
			DimensionsHash:  sqlite.DimensionsHash(dims),
			State:           relationship.StateCandidate,
			SeenCount:       1,
			DistinctWindows: 1,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			LearnedBy:       relationship.LearnedByLocal,
			SourceAdapter:   string(o.Source),
			SubjectLabel: o.Subject.ID,
			SubjectKind:  string(entity.KindIP),
			ObjectLabel:  objID,
			ObjectKind:   string(entity.KindIP),
		})
	}
	return result, nil
}

func isLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

func isBroadcastOrMulticast(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && (ip.IsMulticast() || ip.Equal(net.IPv4bcast))
}

func isInCIDRs(addr string, cidrs []net.IPNet) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for i := range cidrs {
		if cidrs[i].Contains(ip) {
			return true
		}
	}
	return false
}
