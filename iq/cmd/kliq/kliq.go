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
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	ossignal "os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/graphlearner"
	"github.com/kernloom/kernloom/pkg/adapters/shieldpep"
	"github.com/kernloom/kernloom/pkg/adapters/shieldtelemetry"
	"github.com/kernloom/kernloom/pkg/adapters/sourcebaseline"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/featureset"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/graph"
	kliqconfig "github.com/kernloom/kernloom/pkg/core/kliqconfig"
	"github.com/kernloom/kernloom/pkg/core/observation"
	corepdp "github.com/kernloom/kernloom/pkg/core/pdp"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/decisionengine"
	gstore "github.com/kernloom/kernloom/pkg/graphstore/sqlite"
	"github.com/kernloom/kernloom/pkg/shieldclient"
	"github.com/kernloom/kernloom/pkg/signalengine/shieldheuristic"

	// Ensure enforcement package is available for future tuple target use.
	_ "github.com/kernloom/kernloom/pkg/core/enforcement"
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
	// addToCands: when true the IP is added to cands so it gets FSM-processed
	// this tick even without Shield telemetry. Set for freeze violations (source
	// is active). False for baseline deviations — strikes accumulate and are
	// applied the next time the source naturally appears in telemetry with real
	// metrics, avoiding UpStreak reset from zero-metric processing.
	addToCands bool
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
	// Handle subcommands before flag parsing so they work standalone.
	const defaultDB = "/var/lib/kernloom/iq/kliq.db"
	const defaultStateFile = "/var/lib/kernloom/iq/state.json"
	if handleGraphSubcommand(
		defaultDB,
		"/opt/kernloom/attested/etc/frozen-graph.yaml",
		"",
	) {
		return
	}
	if handleStatusSubcommand(defaultStateFile, defaultDB) {
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

	// PDP config: signal engine + progressive enforcement + graph + adapter params.
	// --pdp-config file takes precedence over --profile.
	var p profile
	if c.PDPConfig != "" {
		pdpc, err := corepdp.LoadFromFile(c.PDPConfig)
		if err != nil {
			log.Fatalf("load pdp config: %v", err)
		}
		kliqLog.Printf("PDP config loaded: file=%s name=%s", c.PDPConfig, pdpc.Metadata.Name)
		p = pdpConfigToProfile(pdpc)
		applyPDPGraphToCfg(pdpc, &c)
		applyPDPBaselineToCfg(pdpc, &c)
		applyPDPAutotuneToCfg(pdpc, &c)
		c.adapterParams = adapterParamsFromPDPConfig(pdpc)
		applyPDPAdaptiveRatesToCfg(pdpc, &c)
	} else {
		p = profileByName(c.ProfileName)
		c.adapterParams = shieldpep.DefaultCapabilityParams()
	}

	// Policy: abstract enforcement rules (autonomy, when/then, exports).
	// Optional — without a policy file, profile defaults + CLI flags apply.
	if c.PolicyFile != "" {
		var pp *corepolicy.PolicyPack
		var err error

		if c.Mode == string(corepolicy.ModeManaged) {
			// Managed mode: signature verification is mandatory (CLAUDE.md rule #8).
			if c.PolicyVerifyKeyPath == "" {
				log.Fatalf("managed mode requires --policy-verify-key to verify pack signature")
			}
			pubKey, kerr := corepolicy.LoadPublicKey(c.PolicyVerifyKeyPath)
			if kerr != nil {
				log.Fatalf("load policy verify key: %v", kerr)
			}
			pp, err = corepolicy.LoadAndVerify(c.PolicyFile, pubKey)
		} else {
			// Standalone mode: signature verification is optional.
			if c.PolicyVerifyKeyPath != "" {
				pubKey, kerr := corepolicy.LoadPublicKey(c.PolicyVerifyKeyPath)
				if kerr != nil {
					log.Fatalf("load policy verify key: %v", kerr)
				}
				pp, err = corepolicy.LoadAndVerify(c.PolicyFile, pubKey)
			} else {
				pp, err = corepolicy.LoadFromFile(c.PolicyFile)
			}
		}
		if err != nil {
			log.Fatalf("load policy file: %v", err)
		}
		kliqLog.Printf("Policy loaded: file=%s name=%s", c.PolicyFile, pp.Metadata.Name)
		applyPolicyPackToCfg(pp, &c)
		rulesFromPolicyPack(pp, &c)
	}

	applyProfileDefaults(&c, p)
	c.Cooldown = c.adapterParams.Cooldown

	// Resolve runtime feature profile.
	// --feature-profile takes precedence; otherwise derive from --graph flag.
	if c.FeatureProfile == "" {
		if c.GraphEnabled {
			c.FeatureProfile = string(featureset.ProfileGraphLearning)
		} else {
			c.FeatureProfile = string(featureset.ProfileDOSLight)
		}
	}
	features := featureset.FeaturesFor(featureset.RuntimeProfile(c.FeatureProfile))
	kliqLog.Printf("Feature profile: %s  src_baseline=%v graph=%v sqlite=%v",
		c.FeatureProfile, features.SourceBaseline, features.GraphLearning, features.SQLite)

	// Source baseline cache (iq-learning and higher).
	// Nil when disabled — the main loop checks before calling Update/Resolve.
	var srcBL *sourcebaseline.Cache
	if features.SourceBaseline {
		srcBL = sourcebaseline.New(sourcebaseline.Config{
			Alpha:          c.SrcBaselineAlpha,
			AlphaPromoted:  c.SrcBaselineAlphaStable,
			MinUpdatePPS:   c.SrcBaselineMinPPS,
			MinObs:         c.SrcBaselineMinObs,
			MaxSources:     c.SrcBaselineMaxSources,
			PeakMultiplier: c.SrcBaselinePeakMul,
			MinConfidence:  c.SrcBaselineMinConf,
		})
		kliqLog.Printf("Source baseline cache started: min_pps=%.1f min_obs=%d max_sources=%d peak_mul=%.2f",
			c.SrcBaselineMinPPS, c.SrcBaselineMinObs, c.SrcBaselineMaxSources, c.SrcBaselinePeakMul)
	}

	// Collect flags the user explicitly set on the command line.
	// flag.Visit only visits flags that were actually provided, not those
	// left at their default values. State (autotune) must not override these.
	explicitFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })

	// Deployment config: overrides flag defaults for operational fields
	// (mode, dry_run, paths, Forge URL). Explicit CLI flags always win.
	if c.DeploymentConfigPath != "" {
		dc, err := kliqconfig.LoadDeploymentConfig(c.DeploymentConfigPath)
		if err != nil {
			log.Fatalf("load deployment config: %v", err)
		}
		kliqLog.Printf("Deployment config loaded: file=%s name=%s", c.DeploymentConfigPath, dc.Metadata.Name)
		applyDeploymentConfig(dc, &c, explicitFlags)
	}

	// Compute the config hash used to detect autotune-relevant config changes.
	// A mismatch between this hash and the one stored in state.json invalidates
	// the bootstrap session (BPFfsRoot change = different interface, floor
	// change = different learning target).
	cfgHash := bootstrapConfigHash(&c)

	// Load persisted autotune state.
	// Priority: explicit CLI flag > state (learned) > PDPConfig/profile default.
	var stFile *stateFile
	if c.StatePath != "" {
		if st, err := loadState(c.StatePath, c.MaxStateAge); err == nil {
			// Invalidate bootstrap state when autotune-relevant config has changed.
			if st.Active.ConfigHash != "" && st.Active.ConfigHash != cfgHash {
				kliqLog.Printf("Bootstrap state invalidated: config changed (stored=%s current=%s) — starting fresh",
					st.Active.ConfigHash, cfgHash)
				st.Active.Bootstrap = bootstrapInfo{}
			}
			stFile = st
			if st.Active.Trig.TrigPPS > 0 && !explicitFlags["trig-pps"] {
				c.TrigPPS = st.Active.Trig.TrigPPS
			}
			if st.Active.Trig.TrigSyn > 0 && !explicitFlags["trig-syn"] {
				c.TrigSyn = st.Active.Trig.TrigSyn
			}
			if st.Active.Trig.TrigScan > 0 && !explicitFlags["trig-scan"] {
				c.TrigScan = st.Active.Trig.TrigScan
			}
			if st.Active.Trig.TrigBPS > 0 && !explicitFlags["trig-bps"] {
				c.TrigBPS = st.Active.Trig.TrigBPS
			}
			kliqLog.Printf("Loaded state: profile=%s rev=%d updated=%s trig{pps=%.1f syn=%.1f scan=%.1f bps=%.0f}",
				st.Active.Profile, st.Active.Revision, st.Active.UpdatedAt.Format(time.RFC3339),
				c.TrigPPS, c.TrigSyn, c.TrigScan, c.TrigBPS)
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
						Trig:        trigState{TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan, TrigBPS: c.TrigBPS},
						Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: c.AutoK, SigmaFactor: 1.4826},
						Bootstrap:   bs,
						ConfigHash:  cfgHash,
						SampleCount: 0,
						CleanRatio:  1.0,
						Notes:       "bootstrap initialized",
					}
					stFile.History = []stateHistory{}
				} else {
					stFile.Active.Bootstrap = bs
					stFile.Active.ConfigHash = cfgHash
				}
				_ = writeStateAtomic(c.StatePath, stFile)
			}
		} else {
			// Resuming an existing bootstrap session.
			kliqLog.Printf("Bootstrap resumed: observed=%s required=%s phase=%s",
				(time.Duration(bs.ObservedSeconds) * time.Second).String(),
				c.BootstrapWindow.String(),
				bs.Phase)
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

	// Central enforcement pipeline: resolver is the policy gate; executor is the
	// only component authorized to call TransitionV4/V6.
	resolver := c.buildPolicyResolver()
	executor := buildExecutor(pep)

	// Runtime inventory and config-asset report — built once after all config
	// sources are applied and maps are open. Logged and saved alongside state.
	inv := pep.BuildInventory(nodeID)
	report := buildConfigAssetReport(c, nodeID, features)
	logInventoryAndReport(inv, report, c.StatePath)

	// Tuple enforcement: activate XDP edge maps when the feature is enabled.
	if features.TupleEnforcement {
		if pep.TupleAvailable() {
			if err := pep.SetTupleEnforce(true); err != nil {
				kliqLog.Printf("WARNING: tuple enforce activate failed: %v", err)
			} else {
				kliqLog.Printf("Tuple enforcement: XDP edge maps active (deny-mode)")
			}
		} else {
			kliqLog.Printf("WARNING: feature-profile=graph-enforce but edge maps not available. Reload klshield with new .bpf.o")
		}
	}

	// Decision engine: adds audit trail for FSM transitions and enforces graph-freeze signals.
	// LocalPolicy MaxAction is resolved via the Action Resolver so that
	// managed-no-pack and PolicyMaxAction rules apply to the decision engine path too.
	decPolicy := decisionengine.LocalPolicy{
		NodeID:              nodeID,
		DryRun:              c.DryRun,
		MaxAction:           c.resolveDecisionAction(decision.ActionType(c.GraphFreezeMaxAction)),
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
	decisionEng := decisionengine.New(decPolicy)

	// Heuristic signal engine: converts per-source metrics → Signals + fsm.Metrics.
	// Replaces inline fsm.CalcSeverity calls throughout the main loop.
	engine := shieldheuristic.New(shieldheuristic.Config{
		NodeID:    nodeID,
		TrigPPS:   c.TrigPPS,
		TrigSyn:   c.TrigSyn,
		TrigScan:  c.TrigScan,
		TrigBPS:   c.TrigBPS,
		WPPS:      c.WPPS,
		WSyn:      c.WSyn,
		WScan:     c.WScan,
		WBps:      c.WBps,
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
	// Use a dedicated subscriber channel — the bus fans signals out to every
	// subscriber, so both this loop and the graphlearner see every signal.
	sigCtx, sigCancel := context.WithCancel(context.Background())
	defer sigCancel()
	kliqSigCh := mainBus.SubscribeSignals(256)
	go func() {
		for {
			select {
			case <-sigCtx.Done():
				return
			case sig, ok := <-kliqSigCh:
				if !ok {
					return
				}
				logLine := fmt.Sprintf("SIGNAL type=%s subject=%s score=%d confidence=%d ttl=%s reasons=%v",
					sig.Type, sig.Subject.ID, sig.Score, sig.Confidence, sig.TTL, sig.ReasonCodes)
				if len(sig.Attributes) > 0 {
					keys := make([]string, 0, len(sig.Attributes))
					for k := range sig.Attributes {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						logLine += fmt.Sprintf(" %s=%s", k, sig.Attributes[k])
					}
				}
				kliqLog.Print(logLine)

				if _, _, err := decisionEng.EvaluateSignal(sigCtx, sig); err != nil {
					kliqLog.Printf("SIGNAL decision error: %v", err)
				}

				// Graph freeze violation → FSM strike credits.
				// score >= 90 (frozen-enforce): forceBlock skips accumulation.
				// score < 90 (frozen-observe): normal strike accumulation.
				// Graph freeze violation: source is actively sending → add to cands
				// so the FSM is processed this tick with real metrics.
				if sig.Type == signal.SignalGraphNewEdgeAfterFreeze && sig.Subject.ID != "" {
					sendStrike(graphStrikeCh, sig.Subject.ID, graphStrikesFromScore(sig.Score), sig.Score >= 90, true)

					// Tuple enforcement (graph-enforce profile): deny the specific
					// (src, dst_port, proto) tuple via the ActionResolver instead of
					// calling pep.DenyEdge4 directly.
					if features.TupleEnforcement && sig.Score >= 90 && pep.TupleAvailable() {
						portStr := sig.Attributes["destination_port"]
						proto := sig.Attributes["protocol"]
						var port uint64
						if portStr != "" {
							fmt.Sscanf(portStr, "%d", &port)
						}
						if port > 0 && proto != "" {
							if ekey, ok := shieldclient.NewEdge4Key(sig.Subject.ID, uint16(port), proto); ok {
								proposal := actions.ActionProposal{
									Source:        "graph",
									Reason:        "graph_new_edge_after_freeze",
									DesiredAction: "enforce.access.deny",
									DesiredLevel:  "block",
									Target: actions.ActionTarget{
										Granularity: "tuple_src_dst_port",
										Value:       sig.Subject.ID,
										Attributes: map[string]string{
											"src_ip":   sig.Subject.ID,
											"dst_port": portStr,
											"protocol": proto,
										},
									},
									Confidence: float64(sig.Confidence) / 100.0,
									CreatedAt:  time.Now(),
								}
								res := resolver.Resolve(proposal)
								if res.DenyReason != "" {
									kliqLog.Printf("ACTION-RESOLVER tuple %s:%s/%s %s→%s reason=%q",
										sig.Subject.ID, portStr, proto,
										proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
								}
								result := executor.ApplyTuple4(ekey, res, time.Now())
								switch result.Status {
								case "applied":
									kliqLog.Printf("TUPLE deny edge: %s port=%s proto=%s (freeze violation)", sig.Subject.ID, portStr, proto)
								case "failed":
									kliqLog.Printf("TUPLE deny edge %s:%s/%s failed: %s", sig.Subject.ID, portStr, proto, result.Reason)
								}
							}
						}
					}
				}

				// Edge baseline deviation (EWMA) and peak-exceeded signals:
				// strikes accumulate but IP is NOT added to cands, so the FSM
				// processes it with real metrics on the next natural telemetry tick.
				if (sig.Type == signal.SignalGraphEdgeBaselinePPSDeviation ||
					sig.Type == signal.SignalGraphEdgeBaselineBytesDeviation ||
					sig.Type == signal.SignalGraphEdgeBaselinePPSPeakExceeded ||
					sig.Type == signal.SignalGraphEdgeBaselineBPSPeakExceeded) &&
					sig.Subject.ID != "" {
					sendStrike(graphStrikeCh, sig.Subject.ID, graphStrikesFromScore(sig.Score), false, false)
				}
			}
		}
	}()

	// Graph learner (optional).
	var graphStore *gstore.Store
	var graphCtxCancel context.CancelFunc
	var learner *graphlearner.Adapter

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
		case "learn", "":
			mode = graphlearner.ModeLearn
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
		default:
			log.Fatalf("unknown --graph-mode %q (valid: learn, frozen-observe, frozen-enforce)", c.GraphMode)
		}

		excludeCIDRs := parseGraphExcludeCIDRs(c.GraphExcludeSourceCIDR)
		if len(excludeCIDRs) > 0 {
			kliqLog.Printf("Graph: excluding source CIDRs from learning: %s", c.GraphExcludeSourceCIDR)
		}

		learner = graphlearner.New(graphlearner.Config{
			NodeID: nodeID,
			Mode:   mode,
			Promotion: graph.PromotionConfig{
				MinSeenCount:       c.GraphMinSeenCount,
				MinDistinctWindows: c.GraphMinWindows,
				MinFirstSeenAge:    c.GraphMinAge,
			},
			PromoteInterval:            c.GraphPromoteInterval,
			ExpireTTL:                  c.GraphExpireTTL,
			MinPacketsPerTick:          c.GraphMinPackets,
			MinBytesPerTick:            c.GraphMinBytes,
			ExcludeBroadcast:           c.GraphExcludeBcast,
			ExcludeLoopback:            c.GraphExcludeLoopback,
			ExcludeSourceCIDRs:         excludeCIDRs,
			BaselineAlpha:              c.BaselineAlpha,
			BaselineAlphaBootstrap:     c.BaselineAlphaBootstrap,
			BaselineMinObservations:    c.BaselineMinObservations,
			BaselineMinObsTimeBased:    c.BaselineMinObsTimeBased,
			BaselineMinAge:             c.BaselineMinAge,
			BaselineDeviationThreshold: c.BaselineDeviationThreshold,
			BaselineMinUpdatePPS:       c.BaselineMinUpdatePPS,
			BaselineMinUpdateBPS:       c.BaselineMinUpdateBPS,
			BaselinePeakTolerance:      c.BaselinePeakTolerance,
			BaselineTrigPPS:            c.TrigPPS,
			BaselineTrigBPS:            c.TrigBPS,
			BaselinePeakDecayHalfLife:  c.BaselinePeakDecayHalfLife,
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

		kliqLog.Printf("Graph learning started: mode=%s store=%s node=%s", mode, c.GraphStorePath, nodeID)
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
	resBps := newReservoir(50_000)

	lastTune := time.Now()
	if stFile != nil && !stFile.Active.UpdatedAt.IsZero() {
		lastTune = stFile.Active.UpdatedAt
	}
	totalLearnTicks := 0
	cleanLearnTicks := 0

	// Autotune quiet-node fix: consecutive skip counter.
	// After 2 skips (2× interval) we proceed with available samples so quiet
	// nodes are not permanently locked out of autotune.
	autotuneSkipCount := 0

	// Bootstrap downscale guards.
	bootstrapCompletedWindows := 0
	bootstrapDistinctSources := make(map[string]bool, 256)

	// Baseline totals for drop-ratio gating.
	var prevTotals shieldclient.Totals
	var prevTotalsWall time.Time
	if maps.Totals != nil {
		if t, err := shieldclient.ReadTotalsSum(maps.Totals); err == nil {
			prevTotals = t
			prevTotalsWall = time.Now()
		}
	}

	// syncEdge4Allow writes all frozen/approved graph edges into edge4_allow so
	// the XDP allowlist reflects the current frozen graph. Must be called before
	// activating allow-mode (tuple-enforce allow). Also run periodically so newly
	// approved edges are picked up without restarting KLIQ.
	syncEdge4Allow := func() {
		if graphStore == nil || !pep.TupleAvailable() {
			return
		}
		edges, err := graphStore.ListByNode(nodeID, "")
		if err != nil {
			kliqLog.Printf("syncEdge4Allow: list edges: %v", err)
			return
		}
		n := 0
		for _, e := range edges {
			if e.State != graph.EdgeFrozen && e.State != graph.EdgeApproved {
				continue
			}
			ekey, ok := shieldclient.NewEdge4Key(e.Source.ID, e.DestinationPort, e.Protocol)
			if !ok {
				continue
			}
			if err := pep.AllowEdge4(ekey); err != nil {
				kliqLog.Printf("syncEdge4Allow: %s:%d/%s: %v", e.Source.ID, e.DestinationPort, e.Protocol, err)
			} else {
				n++
			}
		}
		if n > 0 {
			kliqLog.Printf("syncEdge4Allow: synced %d frozen/approved edges to XDP allowlist", n)
		}
	}

	// Populate allowlist on startup (idempotent: LRU map, duplicate writes are fine).
	if features.TupleEnforcement {
		syncEdge4Allow()
	}

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	var tickN uint64
	lastExpiredCleanup := time.Now()

	// SIGUSR1: de-escalate all enforced IPs to OBSERVE so kliq state stays in
	// sync after an external map reset (e.g. klshield reset).
	resetCh := make(chan os.Signal, 1)
	ossignal.Notify(resetCh, syscall.SIGUSR1)
	defer ossignal.Stop(resetCh)

	// SIGTERM/SIGINT: terminate the main loop cleanly so deferred cleanups run
	// (graph store close, telemetry/learner Stop, pending baseline commits).
	stopCh := make(chan os.Signal, 1)
	ossignal.Notify(stopCh, syscall.SIGTERM, syscall.SIGINT)
	defer ossignal.Stop(stopCh)

	bootstrapPhase := "steady"
	if bs.Enabled && bs.Phase != "" {
		bootstrapPhase = bs.Phase
	}
	kliqLog.Printf("Kernloom IQ started profile=%s bootstrap=%s interval=%s dry_run=%v top=%d trig{pps=%.1f bps=%s syn=%.1f scan=%.1f} weights{pps=%.2f bps=%.2f syn=%.2f scan=%.2f} cap=%.1f (ipv6=%v)",
		p.Name, bootstrapPhase, c.Interval.String(), c.DryRun, c.TopN, c.TrigPPS, fmtBPS(c.TrigBPS), c.TrigSyn, c.TrigScan, c.WPPS, c.WBps, c.WSyn, c.WScan, c.SevCap, maps.Src6 != nil)

	for {
		select {
		case <-stopCh:
			kliqLog.Println("shutting down")
			return
		case <-ticker.C:
		}
		nowWall := time.Now()

		// Handle SIGUSR1: clear FSM state to sync with an external map reset.
		select {
		case <-resetCh:
			n := 0
			pepParams := c.toPEPParams()
			for ip, st := range state4 {
				if st.Level != fsm.LevelObserve {
					st = executor.ApplyDeEnforce4(ip, st, pepParams, nowWall)
					st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks = 0, 0, 0, 0
					state4[ip] = st
					n++
				}
			}
			for ip, st := range state6 {
				if st.Level != fsm.LevelObserve {
					st = executor.ApplyDeEnforce6(ip, st, pepParams, nowWall)
					st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks = 0, 0, 0, 0
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

			// Counter-reset guard: if any of the eBPF counters appears to have
			// shrunk (e.g. after `klshield reset`), reseed prev and skip the tick.
			// Without this, uint64 wraparound produces deltas ≈ 2^64 → instant BLOCK.
			if v4.Pkts < pv.Pkts || v4.Bytes < pv.Bytes || v4.Syn < pv.Syn ||
				v4.DportChanges < pv.Scan || v4.DropRL < pv.DropRL {
				prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}
				continue
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

			// Source baseline update + per-source effective thresholds.
			var fsmM4 fsm.Metrics
			var sigs4 []signal.Signal
			if srcBL != nil {
				srcBL.Update(subject4.ID, pps, bps, synRate, scanRate, false, nowWall)
				effPPS := srcBL.EffectiveTrigPPS(subject4.ID, c.TrigPPS)
				effBPS := srcBL.EffectiveTrigBPS(subject4.ID, c.TrigBPS)
				fsmM4, sigs4 = engine.EvaluateAt(subject4, pps, bps, synRate, scanRate, dropRLRate,
					effPPS, c.TrigSyn, c.TrigScan, effBPS)
			} else {
				fsmM4, sigs4 = engine.Evaluate(subject4, pps, bps, synRate, scanRate, dropRLRate)
			}
			for _, sig := range sigs4 {
				_ = mainBus.PublishSignal(context.Background(), sig)
			}

			// Baseline update and deviation check happen in the cands loop below,
			// after `clean` is computed — same timing as the global autotune.

			if dPkts > 0 || dSyn > 0 || dScan > 0 {
				seenForLearn++
				bootstrapDistinctSources[subject4.ID] = true
				if fsmM4.Severity >= c.LearnSevGT {
					highSevCount++
				}
			}

			prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}

			// MinSev=0 means "no severity override" — only PPS decides.
			// MinSev>0 lets a high-severity source bypass the PPS floor.
			sevOverride := c.MinSev > 0 && fsmM4.Severity >= c.MinSev
			if pps < c.MinPPS && !sevOverride && dropRLRate == 0 {
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

				// Counter-reset guard (see IPv4 path above).
				if v6.Pkts < pv.Pkts || v6.Bytes < pv.Bytes || v6.Syn < pv.Syn ||
					v6.DportChanges < pv.Scan || v6.DropRL < pv.DropRL {
					prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}
					continue
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

				var fsmM6 fsm.Metrics
				var sigs6 []signal.Signal
				if srcBL != nil {
					srcBL.Update(subject6.ID, pps, bps, synRate, scanRate, false, nowWall)
					effPPS := srcBL.EffectiveTrigPPS(subject6.ID, c.TrigPPS)
					effBPS := srcBL.EffectiveTrigBPS(subject6.ID, c.TrigBPS)
					fsmM6, sigs6 = engine.EvaluateAt(subject6, pps, bps, synRate, scanRate, dropRLRate,
						effPPS, c.TrigSyn, c.TrigScan, effBPS)
				} else {
					fsmM6, sigs6 = engine.Evaluate(subject6, pps, bps, synRate, scanRate, dropRLRate)
				}
				for _, sig := range sigs6 {
					_ = mainBus.PublishSignal(context.Background(), sig)
				}

				if dPkts > 0 || dSyn > 0 || dScan > 0 {
					seenForLearn++
					bootstrapDistinctSources[subject6.ID] = true
					if fsmM6.Severity >= c.LearnSevGT {
						highSevCount++
					}
				}

				prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}

				sevOverride6 := c.MinSev > 0 && fsmM6.Severity >= c.MinSev
				if pps < c.MinPPS && !sevOverride6 && dropRLRate == 0 {
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
						if needed := c.BlockAt + 1; st.Strikes < needed {
							st.Strikes = needed
						}
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
					if gs.addToCands {
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
					}
				} else {
					st := state4[gs.ip4]
					if gs.forceBlock {
						if needed := c.BlockAt + 1; st.Strikes < needed {
							st.Strikes = needed
						}
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
					if gs.addToCands {
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
			// Increment observed_seconds: only real, clean runtime counts toward
			// the bootstrap window. Offline time between restarts does not count.
			// Accumulate real elapsed seconds per tick rather than ticks themselves,
			// so non-1s intervals (e.g. 500ms, 2s) still measure wall time correctly.
			if c.Bootstrap && bs.Enabled {
				sec := uint64(math.Round(c.Interval.Seconds()))
				if sec == 0 {
					sec = 1
				}
				bs.ObservedSeconds += sec
			}
		}

		// Track which IPs were processed this tick so the sweep below can skip them.
		inCands4 := make(map[[4]byte]bool, len(cands))
		inCands6 := make(map[[16]byte]bool)
		for _, m := range cands {
			if m.IPVer == 4 {
				state4[m.IP4] = processCandidate4(m, state4[m.IP4], nowWall, c, wl, fb, resolver, executor, resPPS, resSyn, resScan, resBps, clean)
				inCands4[m.IP4] = true
			} else {
				state6[m.IP6] = processCandidate6(m, state6[m.IP6], nowWall, c, wl, fb, resolver, executor, resPPS, resSyn, resScan, resBps, clean)
				inCands6[m.IP6] = true
			}
		}

		// Maintenance sweep: advance FSM for non-OBSERVE sources that had no traffic
		// this tick (fell below MinPPS or disappeared from the Shield map entirely).
		// Without this, a source that goes quiet after being rate-limited stays in
		// RATE_HARD/BLOCK forever because fsm.Advance() is never called for it and
		// TTL-based de-escalation never fires.
		pepParams := c.toPEPParams()
		zeroM := fsm.Metrics{}
		for ip4, st := range state4 {
			if st.Level == fsm.LevelObserve || inCands4[ip4] {
				continue
			}
			ip := ip4 // capture
			doT := func(s fsm.State, target fsm.Level) fsm.State {
				proposal := actions.ActionProposal{
					Source:        "housekeeping",
					Reason:        "fsm_downscale",
					DesiredAction: actions.FsmLevelToCapability(target),
					DesiredLevel:  actions.FsmLevelName(target),
					Target:        actions.ActionTarget{Granularity: "src_ip", Value: ip4String(ip)},
					CreatedAt:     nowWall,
				}
				res := resolver.Resolve(proposal)
				if res.DenyReason != "" {
					kliqLog.Printf("ACTION-RESOLVER housekeeping %s %s→%s reason=%q",
						ip4String(ip), proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
				}
				newSt, _ := executor.Apply4(ip, s, res, pepParams, nowWall)
				return newSt
			}
			state4[ip4], _ = fsm.Advance(zeroM, st, nowWall, c.toFSMConfig(), doT)
		}
		for ip6, st := range state6 {
			if st.Level == fsm.LevelObserve || inCands6[ip6] {
				continue
			}
			ip := ip6 // capture
			doT := func(s fsm.State, target fsm.Level) fsm.State {
				proposal := actions.ActionProposal{
					Source:        "housekeeping",
					Reason:        "fsm_downscale",
					DesiredAction: actions.FsmLevelToCapability(target),
					DesiredLevel:  actions.FsmLevelName(target),
					Target:        actions.ActionTarget{Granularity: "src_ip", Value: ip6String(ip)},
					CreatedAt:     nowWall,
				}
				res := resolver.Resolve(proposal)
				if res.DenyReason != "" {
					kliqLog.Printf("ACTION-RESOLVER housekeeping %s %s→%s reason=%q",
						ip6String(ip), proposal.DesiredLevel, res.ExecutableLevel, res.DenyReason)
				}
				newSt, _ := executor.Apply6(ip, s, res, pepParams, nowWall)
				return newSt
			}
			state6[ip6], _ = fsm.Advance(zeroM, st, nowWall, c.toFSMConfig(), doT)
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
				topSummary = fmt.Sprintf("%s sev=%.2f pps=%.0f bps=%s syn=%.0f scan=%.0f", top.ipString(), top.Severity, top.PPS, fmtBPS(top.Bps), top.SynRate, top.ScanRate)
			}
			kliqLog.Printf("TICK#%d sources=%d cands=%d reservoir=%d clean=%v fsm{soft=%d hard=%d block=%d} trig{pps=%.0f bps=%s syn=%.0f scan=%.0f} top: %s",
				tickN, seenForLearn, len(cands), resPPS.Len(), clean, softN, hardN, blockN, c.TrigPPS, fmtBPS(c.TrigBPS), c.TrigSyn, c.TrigScan, topSummary)
		}

		// Housekeeping: bound memory.
		if srcBL != nil && tickN%300 == 1 { // evict every ~5 min at 1s interval
			srcBL.Evict(nowWall.Add(-24 * time.Hour))
		}
		// Re-sync XDP allowlist every 5 min so newly approved/frozen edges
		// are picked up without a restart.
		if features.TupleEnforcement && tickN%300 == 1 {
			syncEdge4Allow()
		}
		// DB housekeeping: every 24 h delete edges that have been in 'expired'
		// state long enough so the SQLite file does not grow without bound.
		if graphStore != nil && nowWall.Sub(lastExpiredCleanup) >= 24*time.Hour {
			cutoff := nowWall.Add(-c.GraphExpireTTL)
			if n, err := graphStore.DeleteExpired(nodeID, cutoff); err != nil {
				kliqLog.Printf("delete expired edges: %v", err)
			} else if n > 0 {
				kliqLog.Printf("deleted %d expired edges older than %s", n, c.GraphExpireTTL)
			}
			lastExpiredCleanup = nowWall
		}
		// Bootstrap checkpoint every 30s: persist observed_seconds so a restart
		// can resume from where it left off (max ~30s of progress lost on crash).
		if c.Bootstrap && bs.Enabled && c.StatePath != "" && stFile != nil && tickN%30 == 0 {
			stFile.Active.Bootstrap = bs
			stFile.Active.ConfigHash = cfgHash
			if err := writeStateAtomic(c.StatePath, stFile); err != nil {
				kliqLog.Printf("bootstrap checkpoint failed: %v", err)
			}
		}
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

		// Keep BootstrapActive in sync so the FSM block cap is applied correctly.
		c.BootstrapActive = pol.Active

		if c.AutoTune && pol.Every > 0 && time.Since(lastTune) >= pol.Every {
			n := minInt(len(resPPS.data), len(resSyn.data), len(resScan.data))
			cleanRatio := 0.0
			if totalLearnTicks > 0 {
				cleanRatio = float64(cleanLearnTicks) / float64(totalLearnTicks)
			}

			if n < c.AutoMinSamples {
				autotuneSkipCount++
				// 2× failsafe: after 2 consecutive skips proceed with whatever
				// samples exist so quiet nodes are not permanently locked out.
				// Require ≥50 samples to avoid running on empty data.
				if n < 50 || autotuneSkipCount < 2 {
					kliqLog.Printf("AUTOTUNE skipped: not enough samples (have=%d need=%d skip=%d) cleanRatio=%.4f",
						n, c.AutoMinSamples, autotuneSkipCount, cleanRatio)
					lastTune = time.Now()
					continue
				}
				kliqLog.Printf("AUTOTUNE proceeding with limited samples after %d skips (have=%d need=%d) cleanRatio=%.4f",
					autotuneSkipCount, n, c.AutoMinSamples, cleanRatio)
			}
			autotuneSkipCount = 0 // reset on successful run

			// Bootstrap downscale guard (optional, default disabled).
			// Only active when bootstrap-min-windows > 0. The floor
			// (autotune-floor-pps) is the primary protection against collapse.
			distinctSourceCount := len(bootstrapDistinctSources)
			guardEnabled := pol.Active && c.BootstrapMinWindowsBeforeDownscale > 0
			canDownscale := !guardEnabled ||
				(bootstrapCompletedWindows >= c.BootstrapMinWindowsBeforeDownscale &&
					(c.BootstrapMinSourcesBeforeDownscale == 0 ||
						distinctSourceCount >= c.BootstrapMinSourcesBeforeDownscale))

			mPPS := median(resPPS.data)
			mdPPS := mad(resPPS.data, mPPS)
			mSyn := median(resSyn.data)
			mdSyn := mad(resSyn.data, mSyn)
			mScan := median(resScan.data)
			mdScan := mad(resScan.data, mScan)

			targetPPS := math.Max(c.AutoFloorPPS, mPPS+pol.K*mdPPS)
			targetSyn := math.Max(c.AutoFloorSyn, mSyn+pol.K*mdSyn)
			targetScan := math.Max(c.AutoFloorScan, mScan+pol.K*mdScan)

			// Apply downscale guard when active: clamp targets to current values
			// from below so triggers can only rise, not fall, this cycle.
			if !canDownscale {
				if targetPPS < c.TrigPPS {
					kliqLog.Printf("AUTOTUNE guard: downscale blocked (windows=%d need=%d sources=%d need=%d) — pps target %.1f clamped to %.1f",
						bootstrapCompletedWindows, c.BootstrapMinWindowsBeforeDownscale,
						distinctSourceCount, c.BootstrapMinSourcesBeforeDownscale,
						targetPPS, c.TrigPPS)
					targetPPS = c.TrigPPS
				}
				if targetSyn < c.TrigSyn {
					targetSyn = c.TrigSyn
				}
				if targetScan < c.TrigScan {
					targetScan = c.TrigScan
				}
			}

			targetPPS = capChangeDir(c.TrigPPS, targetPPS, pol.MaxUp, pol.MaxDown)
			targetSyn = capChangeDir(c.TrigSyn, targetSyn, pol.MaxUp, pol.MaxDown)
			targetScan = capChangeDir(c.TrigScan, targetScan, pol.MaxUp, pol.MaxDown)

			// EWMA smoothing is applied only in steady-state (pol.Active == false).
			// During bootstrap the cap (maxDown) alone is the intended brake —
			// stacking Alpha on top reduces the effective per-cycle drop from 10%
			// to ~1%, preventing the fast convergence bootstrap is designed for.
			if !pol.Active && pol.Alpha > 0 && pol.Alpha < 1 {
				targetPPS = c.TrigPPS*(1-pol.Alpha) + targetPPS*pol.Alpha
				targetSyn = c.TrigSyn*(1-pol.Alpha) + targetSyn*pol.Alpha
				targetScan = c.TrigScan*(1-pol.Alpha) + targetScan*pol.Alpha
			}

			oldPPS, oldSyn, oldScan := c.TrigPPS, c.TrigSyn, c.TrigScan
			c.TrigPPS, c.TrigSyn, c.TrigScan = targetPPS, targetSyn, targetScan

			// BPS autotune: only when AutoFloorBPS > 0 (opt-in).
			oldBPS := c.TrigBPS
			if c.AutoFloorBPS > 0 && len(resBps.data) >= c.AutoMinSamples {
				mBps := median(resBps.data)
				mdBps := mad(resBps.data, mBps)
				targetBPS := math.Max(c.AutoFloorBPS, mBps+pol.K*mdBps)
				targetBPS = capChangeDir(c.TrigBPS, targetBPS, pol.MaxUp, pol.MaxDown)
				if !pol.Active && pol.Alpha > 0 && pol.Alpha < 1 {
					targetBPS = c.TrigBPS*(1-pol.Alpha) + targetBPS*pol.Alpha
				}
				c.TrigBPS = targetBPS
			}

			lastTune = time.Now()
			bootstrapCompletedWindows++
			// Reset distinct-source window for the next autotune cycle.
			bootstrapDistinctSources = make(map[string]bool, 256)

			engine.UpdateConfig(shieldheuristic.Config{
				NodeID:  nodeID,
				TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan, TrigBPS: c.TrigBPS,
				WPPS: c.WPPS, WSyn: c.WSyn, WScan: c.WScan, WBps: c.WBps,
				SevCap: c.SevCap,
			})

			// Keep the graph learner's anti-poisoning cap in sync with the
			// just-learned host triggers. Without this it stays on the cold-start
			// bootstrap values and either over-rejects (cap too low) or fails to
			// reject attack-level traffic (cap too high) once autotune diverges.
			if learner != nil {
				learner.UpdateTriggers(c.TrigPPS, c.TrigBPS)
			}

			kliqLog.Printf("AUTOTUNE applied: trig_pps %.1f->%.1f trig_syn %.1f->%.1f trig_scan %.1f->%.1f trig_bps %.0f->%.0f (median+MAD k=%.2f) samples=%d cleanRatio=%.4f clean=%v dropRatio=%.4f phase=%s",
				oldPPS, c.TrigPPS, oldSyn, c.TrigSyn, oldScan, c.TrigScan, oldBPS, c.TrigBPS, pol.K, n, cleanRatio, clean, dropRatio, pol.Phase)

			if c.StatePath != "" {
				st := stFile
				if st == nil {
					st = &stateFile{Version: 1}
				}
				rev := st.Active.Revision + 1
				mBpsHist := median(resBps.data)
				mdBpsHist := mad(resBps.data, mBpsHist)
				st.History = append(st.History, stateHistory{
					Revision:  rev,
					At:        time.Now(),
					Trig:      trigState{TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan, TrigBPS: c.TrigBPS},
					MedianPPS: mPPS, MadPPS: mdPPS,
					MedianSyn: mSyn, MadSyn: mdSyn,
					MedianScan: mScan, MadScan: mdScan,
					MedianBPS: mBpsHist, MadBPS: mdBpsHist,
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
					Trig:        trigState{TrigPPS: c.TrigPPS, TrigSyn: c.TrigSyn, TrigScan: c.TrigScan, TrigBPS: c.TrigBPS},
					Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: pol.K, SigmaFactor: 1.4826},
					Bootstrap:   bs,
					ConfigHash:  cfgHash,
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

	}
}
