// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package network_test

import (
	"context"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/relationshiplearner/network"
)

func flowObs(srcIP, dstIP, proto, dstPort string) observation.Observation {
	return observation.Observation{
		Type:   observation.TypeFlow,
		Source: observation.SourceShield,
		NodeID: "node-1",
		Subject: observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
		Object:  observation.EntityRef{Kind: observation.KindIP, ID: dstIP},
		Attributes: map[string]string{
			"protocol":         proto,
			"destination_port": dstPort,
		},
		Metrics: map[string]float64{"packets": 10, "bytes": 1024},
	}
}

func TestExtract_BasicFlow(t *testing.T) {
	e := network.New(network.DefaultConfig("node-1"))
	obs := []observation.Observation{flowObs("203.0.113.1", "10.0.0.1", "tcp", "443")}
	rels, err := e.Extract(context.Background(), obs)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("want 1 relationship, got %d", len(rels))
	}
	if rels[0].Predicate != network.Predicate {
		t.Errorf("predicate: want %q, got %q", network.Predicate, rels[0].Predicate)
	}
	if rels[0].State != relationship.StateCandidate {
		t.Errorf("state: want candidate, got %s", rels[0].State)
	}
	if rels[0].Dimensions["protocol"] != "tcp" {
		t.Errorf("dimension protocol: want tcp, got %q", rels[0].Dimensions["protocol"])
	}
}

func TestExtract_SkipsNonFlow(t *testing.T) {
	e := network.New(network.DefaultConfig("node-1"))
	obs := []observation.Observation{{Type: observation.TypeHTTP, Subject: observation.EntityRef{ID: "x"}}}
	rels, _ := e.Extract(context.Background(), obs)
	if len(rels) != 0 {
		t.Errorf("non-flow should be ignored, got %d relationships", len(rels))
	}
}

func TestExtract_SkipsLoopback(t *testing.T) {
	e := network.New(network.DefaultConfig("node-1"))
	obs := []observation.Observation{flowObs("127.0.0.1", "127.0.0.1", "tcp", "80")}
	rels, _ := e.Extract(context.Background(), obs)
	if len(rels) != 0 {
		t.Errorf("loopback should be excluded, got %d", len(rels))
	}
}

func TestExtract_SkipsNoDstPort(t *testing.T) {
	e := network.New(network.DefaultConfig("node-1"))
	o := flowObs("1.2.3.4", "10.0.0.1", "tcp", "")
	o.Attributes["destination_port"] = ""
	rels, _ := e.Extract(context.Background(), []observation.Observation{o})
	if len(rels) != 0 {
		t.Errorf("missing destination_port should be skipped, got %d", len(rels))
	}
}

func TestExtract_CollapseEphemeralPort(t *testing.T) {
	e := network.New(network.DefaultConfig("node-1"))
	obs := []observation.Observation{flowObs("1.2.3.4", "10.0.0.1", "tcp", "54321")}
	rels, _ := e.Extract(context.Background(), obs)
	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
	if rels[0].Dimensions["destination_port"] != "0" {
		t.Errorf("ephemeral port not collapsed: %q", rels[0].Dimensions["destination_port"])
	}
}

func TestExtract_DimensionsHashDeterministic(t *testing.T) {
	e := network.New(network.DefaultConfig("node-1"))
	obs := []observation.Observation{flowObs("1.2.3.4", "10.0.0.2", "tcp", "22")}
	r1, _ := e.Extract(context.Background(), obs)
	r2, _ := e.Extract(context.Background(), obs)
	if r1[0].DimensionsHash != r2[0].DimensionsHash {
		t.Errorf("dimensions hash not deterministic: %q vs %q", r1[0].DimensionsHash, r2[0].DimensionsHash)
	}
}
