// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package conntrack

import (
	"testing"
	"time"
)

func TestParseLine_TCPEstablished(t *testing.T) {
	line := `tcp  6  431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.1 sport=54321 dport=8080 packets=34 bytes=8192 src=10.0.0.1 dst=10.0.0.2 sport=8080 dport=54321 packets=20 bytes=4096 [ASSURED] mark=0 use=1`
	f, ok := parseLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if f.Proto != "tcp" {
		t.Errorf("proto: want tcp, got %q", f.Proto)
	}
	if f.SrcIP != "10.0.0.2" {
		t.Errorf("src: want 10.0.0.2, got %q", f.SrcIP)
	}
	if f.DstIP != "10.0.0.1" {
		t.Errorf("dst: want 10.0.0.1, got %q", f.DstIP)
	}
	if f.SrcPort != 54321 {
		t.Errorf("sport: want 54321, got %d", f.SrcPort)
	}
	if f.DstPort != 8080 {
		t.Errorf("dport: want 8080, got %d", f.DstPort)
	}
	if f.State != "ESTABLISHED" {
		t.Errorf("state: want ESTABLISHED, got %q", f.State)
	}
	if f.Packets != 34 {
		t.Errorf("packets: want 34, got %d", f.Packets)
	}
	if f.Bytes != 8192 {
		t.Errorf("bytes: want 8192, got %d", f.Bytes)
	}
}

func TestParseLine_UDP(t *testing.T) {
	line := `udp  17  30 src=10.0.0.2 dst=8.8.8.8 sport=12345 dport=53 packets=2 bytes=120 src=8.8.8.8 dst=10.0.0.2 sport=53 dport=12345 packets=2 bytes=220 mark=0 use=1`
	f, ok := parseLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if f.Proto != "udp" {
		t.Errorf("proto: want udp, got %q", f.Proto)
	}
	if f.DstPort != 53 {
		t.Errorf("dport: want 53, got %d", f.DstPort)
	}
	if f.State != "" {
		t.Errorf("UDP should have no state, got %q", f.State)
	}
}

func TestParseLine_NoPortsICMP(t *testing.T) {
	line := `icmp  1  25 src=192.168.1.5 dst=192.168.1.1 type=8 code=0 id=1234 src=192.168.1.1 dst=192.168.1.5 type=0 code=0 id=1234 mark=0 use=1`
	f, ok := parseLine(line)
	if !ok {
		t.Fatal("expected ICMP parse to succeed")
	}
	if f.Proto != "icmp" {
		t.Errorf("proto: want icmp, got %q", f.Proto)
	}
	if f.SrcPort != 0 || f.DstPort != 0 {
		t.Errorf("ICMP should have no ports, got sport=%d dport=%d", f.SrcPort, f.DstPort)
	}
}

func TestParseLine_EmptyLine(t *testing.T) {
	_, ok := parseLine("")
	if ok {
		t.Error("empty line should not parse")
	}
}

func TestParseLine_CommentLine(t *testing.T) {
	_, ok := parseLine("# conntrack v1.4.7 (conntrack-tools): 42 flow entries have been shown.")
	if ok {
		t.Error("comment/summary line should not parse")
	}
}

func TestParseLine_UnknownProto(t *testing.T) {
	line := `unknown  255  30 src=10.0.0.1 dst=10.0.0.2`
	_, ok := parseLine(line)
	if ok {
		t.Error("unknown protocol should not parse")
	}
}

func TestParseLine_MissingSrcDst(t *testing.T) {
	line := `tcp  6  431999 ESTABLISHED sport=54321 dport=8080`
	_, ok := parseLine(line)
	if ok {
		t.Error("line without src/dst should not parse")
	}
}

func TestParseLine_FirstOccurrenceUsed(t *testing.T) {
	// conntrack -L shows both directions; we must use the FIRST src/dst (original direction).
	line := `tcp  6  60 TIME_WAIT src=1.2.3.4 dst=5.6.7.8 sport=1111 dport=80 src=5.6.7.8 dst=1.2.3.4 sport=80 dport=1111`
	f, ok := parseLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if f.SrcIP != "1.2.3.4" {
		t.Errorf("want src=1.2.3.4 (original direction), got %q", f.SrcIP)
	}
	if f.DstPort != 80 {
		t.Errorf("want dport=80 (original direction), got %d", f.DstPort)
	}
}

func TestFlowToObservation(t *testing.T) {
	f := Flow{
		Proto:   "tcp",
		SrcIP:   "10.0.0.2",
		DstIP:   "10.0.0.1",
		DstPort: 8080,
		State:   "ESTABLISHED",
		Packets: 10,
		Bytes:   1024,
	}
	obs := flowToObservation(f, "test-node")
	if obs.Subject.ID != "10.0.0.2" {
		t.Errorf("subject: want 10.0.0.2, got %q", obs.Subject.ID)
	}
	if obs.Object.ID != "10.0.0.1:8080" {
		t.Errorf("object: want 10.0.0.1:8080, got %q", obs.Object.ID)
	}
	if obs.Attributes["proto"] != "tcp" {
		t.Errorf("attr proto: want tcp, got %q", obs.Attributes["proto"])
	}
	if obs.NodeID != "test-node" {
		t.Errorf("nodeID: want test-node, got %q", obs.NodeID)
	}
}

func TestIsConnState(t *testing.T) {
	for _, s := range []string{"ESTABLISHED", "TIME_WAIT", "NEW", "CLOSE_WAIT"} {
		if !isConnState(s) {
			t.Errorf("expected %q to be a valid conn state", s)
		}
	}
	if isConnState("RANDOM") || isConnState("src=1.2.3.4") {
		t.Error("non-states should not be recognised as conn states")
	}
}

func TestNewObserver_NoBinary(t *testing.T) {
	cfg := Config{ConntrackPath: "/nonexistent/conntrack"}
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("default poll interval: want 5s, got %v", cfg.PollInterval)
	}
	if cfg.MaxFlows != 10000 {
		t.Errorf("default max flows: want 10000, got %d", cfg.MaxFlows)
	}
}
