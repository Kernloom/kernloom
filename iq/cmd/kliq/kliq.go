// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

/*
Kernloom IQ (kliq) — controller for Kernloom Shield (XDP) with:
- Progressive enforcement: OBSERVE -> SOFT -> HARD -> BLOCK
- Anti-flap: up/down streaks + minimum hold
- Non-compliance: if DropRL/s stays > 0 while in HARD -> go BLOCK faster
- Autotune: learn trig-pps/trig-syn/trig-scan using Median+MAD (robust)
- Anti-poisoning: learn only during "clean ticks" (incl optional total drop-ratio gating)
- Persistence: versioned state.json with atomic writes; load on startup
- Whitelist: exclude specific IPs/CIDRs from enforcement (and optionally from learning)
- Feedback: temporary exemptions (forgive/whitelist) + optional CIDR de-enforcement scan

Pinned maps (defaults, from Kernloom Shield):
  Telemetry:
    /sys/fs/bpf/kernloom_src4_stats     (key=[4]byte  => IPv4)
    /sys/fs/bpf/kernloom_src6_stats     (key=src6Key  => IPv6)
    /sys/fs/bpf/kernloom_totals         (per-cpu array, optional for learn gating)
  Enforcement:
    /sys/fs/bpf/kernloom_deny4_hash     (key=[4]byte, value=u8)
    /sys/fs/bpf/kernloom_deny6_hash     (key=key6Bytes, value=u8)
    /sys/fs/bpf/kernloom_rl_policy4     (key=[4]byte, value={u64 rate_pps, u64 burst})
    /sys/fs/bpf/kernloom_rl_policy6     (key=src6Key, value={u64 rate_pps, u64 burst})

NOTE:
  The upstream documentation may state "IPv4 only". This build wires IPv6 into the same flow:
  - reads src6 telemetry
  - applies per-IP RL and deny entries for IPv6
  - supports IPv6 in whitelist + feedback inputs
*/

package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	ossignal "os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/adapterruntime"
	"github.com/adrianenderlin/kernloom/pkg/adapters/graphlearner"
	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldpep"
	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldtelemetry"
	"github.com/adrianenderlin/kernloom/pkg/core/decision"
	"github.com/adrianenderlin/kernloom/pkg/core/fsm"
	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	corepolicy "github.com/adrianenderlin/kernloom/pkg/core/policy"
	"github.com/adrianenderlin/kernloom/pkg/core/signal"
	"github.com/adrianenderlin/kernloom/pkg/decisionengine"
	gstore "github.com/adrianenderlin/kernloom/pkg/graphstore/sqlite"
	"github.com/adrianenderlin/kernloom/pkg/shieldclient"
	"github.com/adrianenderlin/kernloom/pkg/signalengine/shieldheuristic"
)

var kliqLog = log.New(os.Stderr, "[kliq] ", log.LstdFlags)

// graphStrikeMsg carries FSM strike credits from a graph.new_edge_after_freeze signal
// to the main tick loop where state4/state6 are owned.
// forceBlock=true overrides n and sets strikes to BlockAt+1 so the FSM
// transitions directly to BLOCK in the next tick (frozen-enforce mode).
type graphStrikeMsg struct {
	ip4        [4]byte
	ip6        [16]byte
	isV6       bool
	n          int  // strike credits to add
	forceBlock bool // frozen-enforce: skip FSM accumulation, go straight to BLOCK
}

// prevV4 stores the previous tick's counters for an IPv4 source.
type prevV4 struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

// prevV6 stores the previous tick's counters for an IPv6 source.
type prevV6 struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

func main() {
	// Handle graph subcommands before flag parsing so they work standalone.
	// e.g.: kliq graph status, kliq graph export, kliq graph freeze
	if handleGraphSubcommand(
		"/var/lib/kernloom/iq/graph.db",                // default store path
		"/opt/kernloom/attested/etc/frozen-graph.yaml", // default frozen output
		"", // nodeID resolved inside
	) {
		return
	}

	c := parseFlags()

	// Mode handling.
	switch c.Mode {
	case string(corepolicy.ModeStandalone):
		// normal local-policy path
	case string(corepolicy.ModeManaged):
		kliqLog.Printf("INFO: mode=managed — Forge integration pending, running as standalone")
	default:
		log.Fatalf("unknown --mode %q: must be standalone or managed", c.Mode)
	}

	// Policy resolution: --policy-file takes precedence over --profile.
	var p profile
	if c.PolicyFile != "" {
		pp, err := corepolicy.LoadFromFile(c.PolicyFile)
		if err != nil {
			log.Fatalf("load policy file: %v", err)
		}
		kliqLog.Printf("Policy loaded: file=%s name=%s", c.PolicyFile, pp.Metadata.Name)
		p = policyPackToProfile(pp)
		applyPolicyPackToCfg(pp, &c)
	} else {
		p = profileByName(c.ProfileName)
	}
	applyProfileDefaults(&c, p)

	// Load persisted state (may override trig-*)
	var stFile *stateFile
	if c.StatePath != "" {
		if st, err := loadState(c.StatePath, c.MaxStateAge); err == nil {
			stFile = st
			if st.Active.Trig.TrigPPS > 0 {
				c.TrigPPS = st.Active.Trig.TrigPPS
			}
			if st.Active.Trig.TrigSyn > 0 {
				c.TrigSyn = st.Active.Trig.TrigSyn
			}
			if st.Active.Trig.TrigScan > 0 {
				c.TrigScan = st.Active.Trig.TrigScan
			}
			kliqLog.Printf("Loaded state: profile=%s rev=%d updated=%s trig{pps=%.1f syn=%.1f scan=%.1f}",
				st.Active.Profile, st.Active.Revision, st.Active.UpdatedAt.Format(time.RFC3339),
				c.TrigPPS, c.TrigSyn, c.TrigScan)
		} else {
			kliqLog.Printf("No usable state loaded (%s): %v", c.StatePath, err)
		}
	}

	// Bootstrap start time (persisted so schedule survives reboot)
	var bs bootstrapInfo
	if c.Bootstrap {
		if stFile != nil {
			bs = stFile.Active.Bootstrap
		}
		bs.Enabled = true
		if bs.StartedAt.IsZero() {
			bs.StartedAt = time.Now()
			bs.Window = c.BootstrapWindow.String()
			bs.Phase = "bootstrap-1"

			if c.StatePath != "" {
				if stFile == nil {
					stFile = &stateFile{Version: 2}
					stFile.Active = stateActive{
						Profile:     p.Name,
						Revision:    0,
						UpdatedAt:   time.Time{},
						Trig:        trigState{TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan},
						Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: c.AutoK, SigmaFactor: 1.4826},
						Bootstrap:   bs,
						SampleCount: 0,
						CleanRatio:  1.0,
						Notes:       "bootstrap initialized",
					}
					stFile.History = []stateHistory{}
				} else {
					stFile.Active.Bootstrap = bs
				}
				_ = writeStateAtomic(c.StatePath, stFile)
			}
		}
	}

	// Whitelist + Feedback
	wl := newWhitelist(c.WhitelistPath)
	fb := newFeedbackManager(c.FeedbackPath)

	if c.WhitelistPath != "" {
		if err := wl.load(); err == nil {
			if fi, err := os.Stat(c.WhitelistPath); err == nil {
				wl.modTime = fi.ModTime()
			}
			kliqLog.Printf("Whitelist loaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d",
				c.WhitelistPath, len(wl.exact4), len(wl.cidrs4), len(wl.exact6), len(wl.cidrs6))
		} else {
			kliqLog.Printf("Whitelist not loaded (%s): %v", c.WhitelistPath, err)
		}
	}

	if c.FeedbackPath != "" {
		if err := fb.load(time.Now()); err == nil {
			if fi, err := os.Stat(c.FeedbackPath); err == nil {
				fb.modTime = fi.ModTime()
			}
			kliqLog.Printf("Feedback loaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d",
				c.FeedbackPath, len(fb.exact4), len(fb.cidrs4), len(fb.exact6), len(fb.cidrs6))
		} else {
			kliqLog.Printf("Feedback not loaded (%s): %v", c.FeedbackPath, err)
		}
	}

	// Open Shield eBPF maps via shieldclient.
	maps, err := shieldclient.Open(c.BPFfsRoot, c.DryRun)
	if err != nil {
		log.Fatalf("open BPF maps: %v", err)
	}
	defer maps.Close()

	// Resolve node ID (shared by heuristic engine and graph learner).
	nodeID := c.GraphNodeID
	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "local"
		}
	}

	// Create the Shield PEP adapter (synchronous enforcement).
	pep := shieldpep.New(maps, c.DryRun)
	if err := pep.Init(context.Background(), nil); err != nil {
		log.Fatalf("init shield pep: %v", err)
	}

	// Decision engine: adds audit trail for FSM transitions and enforces graph-freeze signals.
	decPolicy := decisionengine.LocalPolicy{
		NodeID:              nodeID,
		DryRun:              c.DryRun,
		MaxAction:           decision.ActionType(c.GraphFreezeMaxAction),
		AllowLocalBlock:     c.GraphFreezeAllowBlock,
		GraphFreezeAction:   decision.ActionType(c.GraphFreezeAction),
		GraphFreezeTTL:      c.GraphFreezeTTL,
		LevelSoft:           decision.ActionRateLimit,
		LevelHard:           decision.ActionRateLimit,
		LevelBlock:          decision.ActionBlock,
		SoftTTL:             c.SoftTTL,
		HardTTL:             c.HardTTL,
		BlockTTL:            c.BlockTTL,
		MinSeverityForBlock: c.GraphFreezeMinSeverity,
	}
	shieldBridge := decisionengine.NewShieldBridge(maps, c.DryRun, nodeID, c.toPEPParams())
	decisionEng := decisionengine.New(decPolicy, shieldBridge)

	// Heuristic signal engine: converts per-source metrics → Signals + fsm.Metrics.
	// Replaces inline fsm.CalcSeverity calls throughout the main loop.
	engine := shieldheuristic.New(shieldheuristic.Config{
		NodeID:    nodeID,
		TrigPPS:   c.TrigPPS,
		TrigSyn:   c.TrigSyn,
		TrigScan:  c.TrigScan,
		WPPS:      c.WPPS,
		WSyn:      c.WSyn,
		WScan:     c.WScan,
		SevCap:    c.SevCap,
		SignalTTL: 2 * time.Minute,
	})

	// Main signal bus — shared by heuristic engine, graph learner and future adapters.
	mainBus := adapterruntime.NewBus(512)

	// graphStrikeCh bridges graph.new_edge_after_freeze signals to the main tick loop.
	// The signal consumer goroutine writes credits; the tick loop drains and applies them
	// to state4/state6 so the FSM is the single enforcement authority.
	graphStrikeCh := make(chan graphStrikeMsg, 512)

	// Signal consumer: logs signals, injects graph strikes into FSM state.
	sigCtx, sigCancel := context.WithCancel(context.Background())
	defer sigCancel()
	go func() {
		for {
			select {
			case <-sigCtx.Done():
				return
			case sig, ok := <-mainBus.Signals():
				if !ok {
					return
				}
				kliqLog.Printf("SIGNAL type=%s subject=%s score=%d confidence=%d ttl=%s reasons=%v",
					sig.Type, sig.Subject.ID, sig.Score, sig.Confidence, sig.TTL, sig.ReasonCodes)

				if _, _, err := decisionEng.EvaluateSignal(sigCtx, sig); err != nil {
					kliqLog.Printf("SIGNAL decision error: %v", err)
				}

				// Graph freeze violation: translate score → FSM strike credits.
				// score >= 90 (frozen-enforce): forceBlock=true forces the FSM
				// directly to BLOCK level in the next tick, bypassing accumulation.
				// score < 90 (frozen-observe): normal strike accumulation.
				// The FSM is the single enforcement authority for both paths.
				if sig.Type == signal.SignalGraphNewEdgeAfterFreeze && sig.Subject.ID != "" {
					n := graphStrikesFromScore(sig.Score)
					forceBlock := sig.Score >= 90
					ip := net.ParseIP(sig.Subject.ID)
					if ip != nil {
						var msg graphStrikeMsg
						msg.n = n
						msg.forceBlock = forceBlock
						if ip4 := ip.To4(); ip4 != nil {
							copy(msg.ip4[:], ip4)
						} else {
							msg.isV6 = true
							copy(msg.ip6[:], ip.To16())
						}
						select {
						case graphStrikeCh <- msg:
						default:
							kliqLog.Printf("GRAPH-STRIKE dropped (channel full) subject=%s", sig.Subject.ID)
						}
					}
				}
			}
		}
	}()

	// Graph learner (optional).
	var graphStore *gstore.Store
	var graphCtxCancel context.CancelFunc

	if c.GraphEnabled {
		gs, err := gstore.Open(c.GraphStorePath)
		if err != nil {
			log.Fatalf("open graph store %s: %v", c.GraphStorePath, err)
		}
		defer gs.Close()
		graphStore = gs

		// Shield telemetry adapter publishes flow observations onto the shared mainBus.
		telAdapter := shieldtelemetry.NewFromMaps(shieldtelemetry.Config{
			Interval: c.Interval,
			NodeID:   nodeID,
			PrevTTL:  c.PrevTTL,
		}, maps)

		mode := graphlearner.ModeLearn
		switch c.GraphMode {
		case "frozen-observe":
			mode = graphlearner.ModeFrozenObserve
		case "frozen-enforce":
			mode = graphlearner.ModeFrozenEnforce
			// frozen-enforce: override decision engine policy so graph signals
			// trigger immediate PEP enforcement (score=95 meets this threshold).
			decPolicy.GraphFreezeAction = decision.ActionBlock
			decPolicy.AllowLocalBlock = true
			decPolicy.MaxAction = decision.ActionBlock
			decPolicy.MinSeverityForBlock = 90
			decisionEng.UpdatePolicy(decPolicy)
			kliqLog.Printf("Graph: frozen-enforce active — unknown edges will be blocked via PEP directly")
		}

		excludeCIDRs := parseGraphExcludeCIDRs(c.GraphExcludeSourceCIDR)
		if len(excludeCIDRs) > 0 {
			kliqLog.Printf("Graph: excluding source CIDRs from learning: %s", c.GraphExcludeSourceCIDR)
		}

		learner := graphlearner.New(graphlearner.Config{
			NodeID: nodeID,
			Mode:   mode,
			Promotion: graph.PromotionConfig{
				MinSeenCount:       c.GraphMinSeenCount,
				MinDistinctWindows: c.GraphMinWindows,
				MinFirstSeenAge:    c.GraphMinAge,
			},
			PromoteInterval:    c.GraphPromoteInterval,
			ExpireTTL:          c.GraphExpireTTL,
			MinPacketsPerTick:  c.GraphMinPackets,
			MinBytesPerTick:    c.GraphMinBytes,
			ExcludeBroadcast:   c.GraphExcludeBcast,
			ExcludeLoopback:    c.GraphExcludeLoopback,
			ExcludeSourceCIDRs: excludeCIDRs,
		}, graphStore)

		gctx, cancel := context.WithCancel(context.Background())
		graphCtxCancel = cancel
		if err := telAdapter.Start(gctx, mainBus); err != nil {
			cancel()
			log.Fatalf("start graph telemetry adapter: %v", err)
		}
		if err := learner.Start(gctx, mainBus); err != nil {
			cancel()
			log.Fatalf("start graph learner: %v", err)
		}
		defer func() {
			telAdapter.Stop(context.Background())
			learner.Stop(context.Background())
			cancel()
		}()

		kliqLog.Printf("Graph learning started: mode=%s store=%s node=%s", c.GraphMode, c.GraphStorePath, nodeID)
	}
	_ = graphCtxCancel // may be nil when graph is disabled

	// Per-tick previous-snapshot maps (live here in kliq; not in the adapter).
	prev4 := make(map[[4]byte]prevV4, 64_000)
	prev6 := make(map[[16]byte]prevV6, 64_000)

	// FSM state maps.
	state4 := make(map[[4]byte]fsm.State, 64_000)
	state6 := make(map[[16]byte]fsm.State, 64_000)

	resPPS := newReservoir(50_000)
	resSyn := newReservoir(50_000)
	resScan := newReservoir(50_000)

	lastTune := time.Now()
	if stFile != nil && !stFile.Active.UpdatedAt.IsZero() {
		lastTune = stFile.Active.UpdatedAt
	}
	totalLearnTicks := 0
	cleanLearnTicks := 0

	// Baseline totals for drop-ratio gating.
	var prevTotals shieldclient.Totals
	var prevTotalsWall time.Time
	if maps.Totals != nil {
		if t, err := shieldclient.ReadTotalsSum(maps.Totals); err == nil {
			prevTotals = t
			prevTotalsWall = time.Now()
		}
	}

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	var tickN uint64

	// SIGUSR1: de-escalate all enforced IPs to OBSERVE so kliq state stays in
	// sync after an external map reset (e.g. klshield reset).
	resetCh := make(chan os.Signal, 1)
	ossignal.Notify(resetCh, syscall.SIGUSR1)
	defer ossignal.Stop(resetCh)

	kliqLog.Printf("Kernloom IQ started profile=%s interval=%s dry_run=%v top=%d trig{pps=%.1f syn=%.1f scan=%.1f} weights{pps=%.2f syn=%.2f scan=%.2f} cap=%.1f (ipv6=%v)",
		p.Name, c.Interval.String(), c.DryRun, c.TopN, c.TrigPPS, c.TrigSyn, c.TrigScan, c.WPPS, c.WSyn, c.WScan, c.SevCap, maps.Src6 != nil)

	for range ticker.C {
		nowWall := time.Now()

		// Handle SIGUSR1: clear FSM state to sync with an external map reset.
		select {
		case <-resetCh:
			n := 0
			pepParams := c.toPEPParams()
			for ip, st := range state4 {
				if st.Level != fsm.LevelObserve {
					pep.TransitionV4(ip, st, fsm.LevelObserve, nowWall, pepParams)
					st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks = 0, 0, 0, 0
					st.Level = fsm.LevelObserve
					state4[ip] = st
					n++
				}
			}
			for ip, st := range state6 {
				if st.Level != fsm.LevelObserve {
					pep.TransitionV6(ip, st, fsm.LevelObserve, nowWall, pepParams)
					st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks = 0, 0, 0, 0
					st.Level = fsm.LevelObserve
					state6[ip] = st
					n++
				}
			}
			kliqLog.Printf("RESET via SIGUSR1: de-escalated %d enforced IPs to OBSERVE", n)
		default:
		}

		wl.maybeReload(c.WhitelistReload)
		fb.maybeReload(c.FeedbackReload)

		fb.applyV4(nowWall, maps.Deny4, maps.RL4, state4, c.DryRun)
		fb.applyV6(nowWall, maps.Deny6, maps.RL6, state6, c.DryRun)

		if c.FeedbackCIDRDeenforce {
			fb.applyCIDRsIfDue(nowWall, maps.Deny4, maps.RL4, state4, maps.Deny6, maps.RL6, state6, c.DryRun, c.FeedbackCIDREvery, c.FeedbackCIDRMax)
		}

		// Compute drop ratio for learn gating.
		dropRatio := 0.0
		if maps.Totals != nil && !prevTotalsWall.IsZero() {
			if t, err := shieldclient.ReadTotalsSum(maps.Totals); err == nil {
				sec := nowWall.Sub(prevTotalsWall).Seconds()
				if sec > 0 {
					dPass := float64(t.Pass - prevTotals.Pass)
					dDrop := float64((t.DropAllow + t.DropDeny + t.DropRL) - (prevTotals.DropAllow + prevTotals.DropDeny + prevTotals.DropRL))
					if den := dPass + dDrop; den > 0 {
						dropRatio = dDrop / den
					}
				}
				prevTotals = t
				prevTotalsWall = nowWall
			}
		}

		cands := make([]metrics, 0, 4096)
		seenForLearn := 0
		highSevCount := 0

		// ----- Iterate v4 sources -----
		it4 := maps.Src4.Iterate()
		var k4 [4]byte
		var v4 shieldclient.SrcStatsV4

		for it4.Next(&k4, &v4) {
			pv, ok := prev4[k4]
			if !ok {
				prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}
				continue
			}

			sec := nowWall.Sub(pv.LastWall).Seconds()
			if sec <= 0 {
				sec = c.Interval.Seconds()
				if sec <= 0 {
					sec = 1
				}
			}

			dPkts := v4.Pkts - pv.Pkts
			dBytes := v4.Bytes - pv.Bytes
			dSyn := v4.Syn - pv.Syn
			dScan := v4.DportChanges - pv.Scan
			dDropRL := v4.DropRL - pv.DropRL

			pps := float64(dPkts) / sec
			bps := float64(dBytes) / sec
			synRate := float64(dSyn) / sec
			scanRate := float64(dScan) / sec
			dropRLRate := float64(dDropRL) / sec

			subject4 := observation.EntityRef{Kind: observation.KindIP, ID: ip4String(k4)}
			fsmM4, sigs4 := engine.Evaluate(subject4, pps, bps, synRate, scanRate, dropRLRate)
			for _, sig := range sigs4 {
				_ = mainBus.PublishSignal(context.Background(), sig)
			}

			if dPkts > 0 || dSyn > 0 || dScan > 0 {
				seenForLearn++
				if fsmM4.Severity >= c.LearnSevGT {
					highSevCount++
				}
			}

			prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}

			if pps < c.MinPPS && fsmM4.Severity < c.MinSev && dropRLRate == 0 {
				continue
			}

			cands = append(cands, metrics{
				IPVer: 4, IP4: k4,
				PPS: fsmM4.PPS, Bps: fsmM4.Bps, SynRate: fsmM4.SynRate, ScanRate: fsmM4.ScanRate, DropRLRate: fsmM4.DropRLRate, Severity: fsmM4.Severity,
			})
		}
		if err := it4.Err(); err != nil {
			kliqLog.Printf("iterate src4 map err: %v", err)
			continue
		}

		// ----- Iterate v6 sources -----
		if maps.Src6 != nil {
			it6 := maps.Src6.Iterate()
			var k6 shieldclient.Src6Key
			var v6 shieldclient.SrcStatsV6

			for it6.Next(&k6, &v6) {
				ip6 := k6.IP
				pv, ok := prev6[ip6]
				if !ok {
					prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}
					continue
				}

				sec := nowWall.Sub(pv.LastWall).Seconds()
				if sec <= 0 {
					sec = c.Interval.Seconds()
					if sec <= 0 {
						sec = 1
					}
				}

				dPkts := v6.Pkts - pv.Pkts
				dBytes := v6.Bytes - pv.Bytes
				dSyn := v6.Syn - pv.Syn
				dScan := v6.DportChanges - pv.Scan
				dDropRL := v6.DropRL - pv.DropRL

				pps := float64(dPkts) / sec
				bps := float64(dBytes) / sec
				synRate := float64(dSyn) / sec
				scanRate := float64(dScan) / sec
				dropRLRate := float64(dDropRL) / sec

				subject6 := observation.EntityRef{Kind: observation.KindIP, ID: ip6String(ip6)}
				fsmM6, sigs6 := engine.Evaluate(subject6, pps, bps, synRate, scanRate, dropRLRate)
				for _, sig := range sigs6 {
					_ = mainBus.PublishSignal(context.Background(), sig)
				}

				if dPkts > 0 || dSyn > 0 || dScan > 0 {
					seenForLearn++
					if fsmM6.Severity >= c.LearnSevGT {
						highSevCount++
					}
				}

				prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}

				if pps < c.MinPPS && fsmM6.Severity < c.MinSev && dropRLRate == 0 {
					continue
				}

				cands = append(cands, metrics{
					IPVer: 6, IP6: ip6,
					PPS: fsmM6.PPS, Bps: fsmM6.Bps, SynRate: fsmM6.SynRate, ScanRate: fsmM6.ScanRate, DropRLRate: fsmM6.DropRLRate, Severity: fsmM6.Severity,
				})
			}
			if err := it6.Err(); err != nil {
				kliqLog.Printf("iterate src6 map err: %v", err)
			}
		}

		sort.Slice(cands, func(i, j int) bool {
			if cands[i].Severity == cands[j].Severity {
				return cands[i].PPS > cands[j].PPS
			}
			return cands[i].Severity > cands[j].Severity
		})
		if c.TopN < len(cands) {
			cands = cands[:c.TopN]
		}

		// Drain graph strike credits from frozen-observe/enforce signals.
		// Applied after TopN cap so graph-violated IPs are always evaluated.
		// UpStreak is set to UpNeed to bypass the anti-flap guard — a behavioral
		// violation is deliberate, not metric noise.
		// forceBlock=true (frozen-enforce): set strikes to BlockAt+1 so the FSM
		// transitions to BLOCK immediately. The FSM then owns the deny-map entry
		// and its TTL, preventing conflicts with FSM-level downgrades.
	drainGraphStrikes:
		for {
			select {
			case gs := <-graphStrikeCh:
				if gs.isV6 {
					st := state6[gs.ip6]
					if gs.forceBlock {
						st.Strikes = c.BlockAt + 1
						st.ForceBlock = true
					} else {
						st.Strikes += gs.n
					}
					if st.UpStreak < c.UpNeed {
						st.UpStreak = c.UpNeed
					}
					if st.HighSevSince.IsZero() {
						st.HighSevSince = nowWall
					}
					st.LastTrigger = nowWall
					state6[gs.ip6] = st
					alreadyIn := false
					for _, m := range cands {
						if m.IPVer == 6 && m.IP6 == gs.ip6 {
							alreadyIn = true
							break
						}
					}
					if !alreadyIn {
						cands = append(cands, metrics{IPVer: 6, IP6: gs.ip6})
					}
				} else {
					st := state4[gs.ip4]
					if gs.forceBlock {
						st.Strikes = c.BlockAt + 1
						st.ForceBlock = true
					} else {
						st.Strikes += gs.n
					}
					if st.UpStreak < c.UpNeed {
						st.UpStreak = c.UpNeed
					}
					if st.HighSevSince.IsZero() {
						st.HighSevSince = nowWall
					}
					st.LastTrigger = nowWall
					state4[gs.ip4] = st
					alreadyIn := false
					for _, m := range cands {
						if m.IPVer == 4 && m.IP4 == gs.ip4 {
							alreadyIn = true
							break
						}
					}
					if !alreadyIn {
						cands = append(cands, metrics{IPVer: 4, IP4: gs.ip4})
					}
				}
			default:
				break drainGraphStrikes
			}
		}

		// Count active blocks for clean-tick decision.
		blocksActive := 0
		for _, st := range state4 {
			if st.Level == fsm.LevelBlock {
				blocksActive++
			}
		}
		for _, st := range state6 {
			if st.Level == fsm.LevelBlock {
				blocksActive++
			}
		}

		totalLearnTicks++
		clean := true
		if c.LearnSkipIfBlocks && blocksActive > 0 {
			clean = false
		}
		if seenForLearn > 0 && float64(highSevCount)/float64(seenForLearn) > c.LearnFracGT {
			clean = false
		}
		if c.LearnMaxDropRatio > 0 && dropRatio > c.LearnMaxDropRatio {
			clean = false
		}
		if clean {
			cleanLearnTicks++
		}

		for _, m := range cands {
			if m.IPVer == 4 {
				state4[m.IP4] = processCandidate4(m, state4[m.IP4], nowWall, c, wl, fb, pep, resPPS, resSyn, resScan, clean)
			} else {
				state6[m.IP6] = processCandidate6(m, state6[m.IP6], nowWall, c, wl, fb, pep, resPPS, resSyn, resScan, clean)
			}
		}

		tickN++
		if tickN%30 == 1 {
			softN, hardN, blockN := 0, 0, 0
			for _, st := range state4 {
				switch st.Level {
				case fsm.LevelSoft:
					softN++
				case fsm.LevelHard:
					hardN++
				case fsm.LevelBlock:
					blockN++
				}
			}
			for _, st := range state6 {
				switch st.Level {
				case fsm.LevelSoft:
					softN++
				case fsm.LevelHard:
					hardN++
				case fsm.LevelBlock:
					blockN++
				}
			}
			topSummary := "none"
			if len(cands) > 0 {
				top := cands[0]
				topSummary = fmt.Sprintf("%s sev=%.2f pps=%.0f syn=%.0f scan=%.0f", top.ipString(), top.Severity, top.PPS, top.SynRate, top.ScanRate)
			}
			kliqLog.Printf("TICK#%d sources=%d cands=%d clean=%v fsm{soft=%d hard=%d block=%d} trig{pps=%.0f syn=%.0f scan=%.0f} top: %s",
				tickN, seenForLearn, len(cands), clean, softN, hardN, blockN, c.TrigPPS, c.TrigSyn, c.TrigScan, topSummary)
		}

		// Housekeeping: bound memory.
		for ip, pv := range prev4 {
			if nowWall.Sub(pv.LastWall) > c.PrevTTL {
				delete(prev4, ip)
			}
		}
		for ip, pv := range prev6 {
			if nowWall.Sub(pv.LastWall) > c.PrevTTL {
				delete(prev6, ip)
			}
		}
		for ip, st := range state4 {
			if st.Level == fsm.LevelObserve && st.Strikes == 0 && !st.LastSeenWallTime.IsZero() && nowWall.Sub(st.LastSeenWallTime) > c.StateTTL {
				delete(state4, ip)
			}
		}
		for ip, st := range state6 {
			if st.Level == fsm.LevelObserve && st.Strikes == 0 && !st.LastSeenWallTime.IsZero() && nowWall.Sub(st.LastSeenWallTime) > c.StateTTL {
				delete(state6, ip)
			}
		}

		// Autotune schedule.
		steadyEveryEff := c.AutoEvery
		if c.Bootstrap {
			steadyEveryEff = c.SteadyEvery
		}
		steadyUp, steadyDown := c.AutoMaxChange, c.AutoMaxChange
		if c.AutoMaxUp > 0 {
			steadyUp = c.AutoMaxUp
		}
		if c.AutoMaxDown > 0 {
			steadyDown = c.AutoMaxDown
		}

		pol := bootstrapEffective(nowWall, bs, c.BootstrapWindow, c.BootstrapP1End, c.BootstrapP2End,
			c.BootstrapEvery1, c.BootstrapEvery2, c.BootstrapEvery3,
			c.BootstrapKStart, c.BootstrapKFinal,
			c.BootstrapMaxUp1, c.BootstrapMaxDown1, c.BootstrapMaxUp2, c.BootstrapMaxDown2, c.BootstrapMaxUp3, c.BootstrapMaxDown3,
			c.BootstrapAlpha1, c.BootstrapAlpha2, c.BootstrapAlpha3,
			steadyEveryEff, c.AutoK, steadyUp, steadyDown, c.AutoAlpha)

		if c.AutoTune && pol.Every > 0 && time.Since(lastTune) >= pol.Every {
			n := minInt(len(resPPS.data), len(resSyn.data), len(resScan.data))
			cleanRatio := 0.0
			if totalLearnTicks > 0 {
				cleanRatio = float64(cleanLearnTicks) / float64(totalLearnTicks)
			}

			if n < c.AutoMinSamples {
				kliqLog.Printf("AUTOTUNE skipped: not enough samples (have=%d need=%d) cleanRatio=%.4f", n, c.AutoMinSamples, cleanRatio)
				lastTune = time.Now()
				continue
			}

			mPPS := median(resPPS.data)
			mdPPS := mad(resPPS.data, mPPS)
			mSyn := median(resSyn.data)
			mdSyn := mad(resSyn.data, mSyn)
			mScan := median(resScan.data)
			mdScan := mad(resScan.data, mScan)

			targetPPS := math.Max(c.AutoFloorPPS, mPPS+pol.K*mdPPS)
			targetSyn := math.Max(c.AutoFloorSyn, mSyn+pol.K*mdSyn)
			targetScan := math.Max(c.AutoFloorScan, mScan+pol.K*mdScan)

			targetPPS = capChangeDir(c.TrigPPS, targetPPS, pol.MaxUp, pol.MaxDown)
			targetSyn = capChangeDir(c.TrigSyn, targetSyn, pol.MaxUp, pol.MaxDown)
			targetScan = capChangeDir(c.TrigScan, targetScan, pol.MaxUp, pol.MaxDown)

			if pol.Alpha > 0 && pol.Alpha < 1 {
				targetPPS = c.TrigPPS*(1-pol.Alpha) + targetPPS*pol.Alpha
				targetSyn = c.TrigSyn*(1-pol.Alpha) + targetSyn*pol.Alpha
				targetScan = c.TrigScan*(1-pol.Alpha) + targetScan*pol.Alpha
			}

			oldPPS, oldSyn, oldScan := c.TrigPPS, c.TrigSyn, c.TrigScan
			c.TrigPPS, c.TrigSyn, c.TrigScan = targetPPS, targetSyn, targetScan
			lastTune = time.Now()

			engine.UpdateConfig(shieldheuristic.Config{
				NodeID: nodeID, TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan,
				WPPS: c.WPPS, WSyn: c.WSyn, WScan: c.WScan, SevCap: c.SevCap,
			})

			kliqLog.Printf("AUTOTUNE applied: trig_pps %.1f->%.1f trig_syn %.1f->%.1f trig_scan %.1f->%.1f (median+MAD k=%.2f) samples=%d cleanRatio=%.4f clean=%v dropRatio=%.4f phase=%s",
				oldPPS, c.TrigPPS, oldSyn, c.TrigSyn, oldScan, c.TrigScan, pol.K, n, cleanRatio, clean, dropRatio, pol.Phase)

			if c.StatePath != "" {
				st := stFile
				if st == nil {
					st = &stateFile{Version: 1}
				}
				rev := st.Active.Revision + 1
				st.History = append(st.History, stateHistory{
					Revision:  rev,
					At:        time.Now(),
					Trig:      trigState{TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan},
					MedianPPS: mPPS, MadPPS: mdPPS,
					MedianSyn: mSyn, MadSyn: mdSyn,
					MedianScan: mScan, MadScan: mdScan,
					SampleCount: n,
					CleanRatio:  cleanRatio,
					Notes:       fmt.Sprintf("autotune median+mad dropRatio=%.4f phase=%s", dropRatio, pol.Phase),
				})
				if len(st.History) > c.HistoryKeep && c.HistoryKeep > 0 {
					st.History = st.History[len(st.History)-c.HistoryKeep:]
				}
				st.Active = stateActive{
					Profile:     p.Name,
					Revision:    rev,
					UpdatedAt:   time.Now(),
					Trig:        trigState{TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan},
					Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: pol.K, SigmaFactor: 1.4826},
					Bootstrap:   bs,
					SampleCount: n,
					CleanRatio:  cleanRatio,
					Notes:       "autotune",
				}
				if err := writeStateAtomic(c.StatePath, st); err != nil {
					kliqLog.Printf("AUTOTUNE state write failed: %v", err)
				} else {
					stFile = st
					kliqLog.Printf("AUTOTUNE state saved: %s (rev=%d)", c.StatePath, rev)
				}
			}
		}

		if len(cands) > 0 {
			top := cands[0]
			topWL := false
			if top.IPVer == 4 {
				topWL = wl.matchV4(top.IP4)
			} else {
				topWL = wl.matchV6(top.IP6)
			}
			fmt.Printf("TOP %-39s ipver=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f trig{pps=%.0f syn=%.0f scan=%.0f} clean=%v dropRatio=%.4f wl=%v phase=%s\n",
				top.ipString(), top.IPVer, top.Severity, top.PPS, top.SynRate, top.ScanRate, top.DropRLRate,
				c.TrigPPS, c.TrigSyn, c.TrigScan, clean, dropRatio, topWL, pol.Phase)
		}
	}
}
