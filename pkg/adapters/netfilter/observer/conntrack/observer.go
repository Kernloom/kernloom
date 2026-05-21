// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package conntrack provides a Conntrack-based flow observer for the Kernloom
// Netfilter adapter. It periodically snapshots active connections from
// conntrack(8) and publishes them as flow observations on the KLIQ event bus.
//
// Primary consumers:
//   - GraphLearner: receives flow edges (src→dst:port/proto) for learning.
//
// This observer does NOT replace klshield PPS/SYN telemetry — conntrack is
// connection-oriented and cannot provide per-packet rates. It is designed
// for systems where klshield is unavailable.
package conntrack

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

var logger = log.New(os.Stderr, "[conntrack] ", log.LstdFlags)

// Config controls the conntrack observer.
type Config struct {
	// ConntrackPath is the path to the conntrack binary.
	// Empty = auto-detected via PATH.
	ConntrackPath string

	// PollInterval controls how often conntrack -L is run.
	// Default: 5s.
	PollInterval time.Duration

	// MaxFlows caps the number of flows emitted per poll cycle.
	// Default: 10000.
	MaxFlows int

	// NodeID is attached to every observation for correlation.
	NodeID string
}

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{
		PollInterval: 5 * time.Second,
		MaxFlows:     10000,
	}
}

// Observer polls conntrack and publishes flow observations on the event bus.
type Observer struct {
	cfg  Config
	path string // resolved conntrack binary path
}

// New creates a new Observer. Returns an error if conntrack is not available.
func New(cfg Config) (*Observer, error) {
	path := cfg.ConntrackPath
	if path == "" {
		var err error
		path, err = exec.LookPath("conntrack")
		if err != nil {
			return nil, err
		}
	} else {
		// Verify explicit path is executable.
		if _, err := exec.LookPath(path); err != nil {
			return nil, fmt.Errorf("conntrack binary not found at %q: %w", path, err)
		}
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = DefaultConfig().PollInterval
	}
	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = DefaultConfig().MaxFlows
	}
	return &Observer{cfg: cfg, path: path}, nil
}

// Start runs the poll loop until ctx is cancelled.
// Observations are published on bus. Errors are logged and retried next cycle.
func (o *Observer) Start(ctx context.Context, bus adapterruntime.EventBus) {
	ticker := time.NewTicker(o.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.poll(ctx, bus)
		}
	}
}

func (o *Observer) poll(ctx context.Context, bus adapterruntime.EventBus) {
	flows, err := o.snapshot(ctx)
	if err != nil {
		logger.Printf("snapshot error: %v", err)
		return
	}

	emitted := 0
	for _, f := range flows {
		if emitted >= o.cfg.MaxFlows {
			break
		}
		obs := flowToObservation(f, o.cfg.NodeID)
		if err := bus.PublishObservation(ctx, obs); err != nil {
			return // bus full or shutting down
		}
		emitted++
	}
}

// snapshot runs "conntrack -L" and returns parsed flows.
func (o *Observer) snapshot(ctx context.Context) ([]Flow, error) {
	cmd := exec.CommandContext(ctx, o.path, "-L")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var flows []Flow
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if f, ok := parseLine(line); ok {
			flows = append(flows, f)
		}
	}
	_ = cmd.Wait()
	return flows, scanner.Err()
}

// Flow is a parsed conntrack entry.
type Flow struct {
	Proto   string
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	State   string // "ESTABLISHED", "TIME_WAIT", etc. (TCP only)
	Packets uint64
	Bytes   uint64
}

// flowToObservation converts a conntrack Flow into an observation.Observation
// that the GraphLearner can process.
func flowToObservation(f Flow, nodeID string) observation.Observation {
	src := observation.EntityRef{Kind: observation.KindIP, ID: f.SrcIP}
	obs := *observation.NewObservation(
		"netfilter-conntrack",
		observation.TypeFlow,
		nodeID,
		src,
	)

	dstID := f.DstIP
	if f.DstPort > 0 {
		dstID = f.DstIP + ":" + strconv.Itoa(int(f.DstPort))
	}
	obs.SetObject(observation.EntityRef{
		Kind: observation.KindService,
		ID:   dstID,
	})

	obs.SetAttribute("proto", f.Proto)
	obs.SetAttribute("dst_port", strconv.Itoa(int(f.DstPort)))
	obs.SetAttribute("src_port", strconv.Itoa(int(f.SrcPort)))
	obs.SetAttribute("state", f.State)
	if f.Packets > 0 {
		obs.SetAttribute("packets", strconv.FormatUint(f.Packets, 10))
	}
	if f.Bytes > 0 {
		obs.SetAttribute("bytes", strconv.FormatUint(f.Bytes, 10))
	}
	return obs
}

// parseLine parses one line of "conntrack -L" output.
//
// Example conntrack -L lines:
//
//	tcp  6  431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.1 sport=54321 dport=8080 ...
//	udp  17  30 src=10.0.0.2 dst=8.8.8.8 sport=12345 dport=53 ...
func parseLine(line string) (Flow, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Flow{}, false
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Flow{}, false
	}

	f := Flow{Proto: strings.ToLower(fields[0])}
	if f.Proto != "tcp" && f.Proto != "udp" && f.Proto != "icmp" {
		return Flow{}, false
	}

	// Parse key=value fields (conntrack -L format).
	// We pick the FIRST occurrence of src/dst/sport/dport (original direction).
	srcSeen, dstSeen := false, false
	for _, field := range fields[3:] {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			// State word (e.g. "ESTABLISHED") — no "=" sign.
			if f.State == "" && isConnState(field) {
				f.State = field
			}
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "src":
			if !srcSeen {
				f.SrcIP = val
				srcSeen = true
			}
		case "dst":
			if !dstSeen {
				f.DstIP = val
				dstSeen = true
			}
		case "sport":
			if f.SrcPort == 0 {
				if p, err := strconv.ParseUint(val, 10, 16); err == nil {
					f.SrcPort = uint16(p)
				}
			}
		case "dport":
			if f.DstPort == 0 {
				if p, err := strconv.ParseUint(val, 10, 16); err == nil {
					f.DstPort = uint16(p)
				}
			}
		case "packets":
			if f.Packets == 0 {
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					f.Packets = n
				}
			}
		case "bytes":
			if f.Bytes == 0 {
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					f.Bytes = n
				}
			}
		}
	}

	if f.SrcIP == "" || f.DstIP == "" {
		return Flow{}, false
	}
	return f, true
}

func isConnState(s string) bool {
	switch s {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT",
		"CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN",
		"NEW", "RELATED", "UNREPLIED":
		return true
	}
	return false
}
