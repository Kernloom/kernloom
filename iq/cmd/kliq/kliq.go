// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

/*
Kernloom IQ (kliq) is the local runtime orchestrator. It hosts Forge bundle
handling, adapter lifecycle, local evidence/risk/decision flow, temporary
action brokering, state persistence and feedback upload. Product-specific
telemetry and enforcement mechanics belong in pkg/adapters/<vendor>/.
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
	"path/filepath"
	"sort"
	"syscall"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/forgeagent"
	"github.com/kernloom/kernloom/iq/internal/lifecycle/bootstrapautotune"
	lgraph "github.com/kernloom/kernloom/iq/internal/lifecycle/graph"
	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/catalog"
	netfilterruntime "github.com/kernloom/kernloom/pkg/adapters/netfilter/runtime"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/featureset"
	kliqconfig "github.com/kernloom/kernloom/pkg/core/kliqconfig"
	"github.com/kernloom/kernloom/pkg/core/learning"
	corepdp "github.com/kernloom/kernloom/pkg/core/pdp"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/decisionengine"
	"github.com/kernloom/kernloom/pkg/learningguard"
	"github.com/kernloom/kernloom/pkg/pipeline"
	"github.com/kernloom/kernloom/pkg/pipeline/graphpipeline"
	"github.com/kernloom/kernloom/pkg/relationshiplearner"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"

	// Ensure enforcement package is available for future tuple target use.
	_ "github.com/kernloom/kernloom/pkg/core/enforcement"
)

var kliqLog = log.New(os.Stderr, "[kliq] ", log.LstdFlags)

const kliqUsage = `Kernloom IQ — local intelligence and enforcement agent

Usage:
  kliq run [flags...]         Start the KLIQ runtime (DoS prevention / microsegmentation)
  kliq graph <subcommand>     Communication graph: edges, baselines, freeze, approve-source, ...
  kliq status                 Show current runtime status (autotune, FSM, bootstrap)
  kliq entities               Entity store browser
  kliq relationships          Relationship store browser
  kliq baselines              Metric baseline store browser
  kliq learning               Learning guard / exclusion store
  kliq storage                SQLite state store info

  kliq run --help             Show all runtime flags

Examples:
  kliq run --pdp-config=/etc/kernloom/pdp/node.yaml --dry-run=true
  kliq graph edges --sort=state
  kliq status`

// graphStrikeMsg carries graph-derived severity hints into the generic
// source-candidate fact path.
// forceBlock=true overrides n and sets strikes to BlockAt+1 so the FSM intent
// facts propose BLOCK on the next tick.
type graphStrikeMsg struct {
	sourceID    string
	n           int // strike credits to add before FSM processing
	signalScore int // graph signal score, mapped to FSM severity when addToCands is true
	forceBlock  bool
	// addToCands: when true the source is added to cands so RuntimePDP receives
	// source-level graph/FSM facts this tick.
	addToCands bool
}

// main is organised into the following phases:
//
//	§1 Subcommand dispatch  (before flag parse; early return on match)
//	§2 Config + PDP setup   (flags, profiles, PDPConfig, bootstrap)
//	§3 State store + graph  (SQLite, lifecycle controllers)
//	§4 Adapter init         (catalog adapters, netfilter, PIPs)
//	§5 Decision pipeline    (bus, signal engine, decision engine)
//	§6 Forge agent          (enrollment, heartbeat, bundle delivery)
//	§7 Tick-loop prep       (ticker, signals, runtime PDP, shadow pipeline)
//	§8 Main tick loop       (fact evaluation, autotune — core of KLIQ)
func main() {
	// ── §1 Subcommand dispatch ───────────────────────────────────────────────
	// kliq requires an explicit first argument:
	//   kliq run [flags...]   — start the KLIQ runtime
	//   kliq graph <sub>      — graph subcommands
	//   kliq status           — show runtime status
	//   kliq entities         — entity store
	//   kliq relationships    — relationship store
	//   kliq baselines        — baseline engine
	//   kliq learning         — learning guard
	//   kliq storage          — SQLite store
	//
	// An unknown or missing first argument is an error — this prevents
	// accidentally starting the KLIQ runtime when mistyping a subcommand.
	const defaultStateDB = "/var/lib/kernloom/iq/kliq-state.db"
	const defaultStateFile = "/var/lib/kernloom/iq/state.json"

	// Extract first arg before --db parsing so we can dispatch early.
	firstArg := ""
	if len(os.Args) >= 2 {
		firstArg = os.Args[1]
	}

	// Allow --db <path> to override the state store path for subcommands.
	subCmdDB := defaultStateDB
	for i, a := range os.Args[1:] {
		if a == "--db" && i+2 < len(os.Args) {
			subCmdDB = os.Args[i+2]
		} else if len(a) > 5 && a[:5] == "--db=" {
			subCmdDB = a[5:]
		}
	}

	switch firstArg {
	case "run":
		// Remove "run" from os.Args so flag.Parse() sees the actual flags.
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	case "graph":
		if !handleGraphSubcommand(subCmdDB, "/opt/kernloom/attested/etc/frozen-graph.yaml", "") {
			fmt.Fprintln(os.Stderr, "usage: kliq graph <edges|baselines|freeze|approve-source|deny-source|export|reset>")
			os.Exit(1)
		}
		return
	case "status":
		if !handleStatusSubcommand(defaultStateFile, subCmdDB) {
			fmt.Fprintln(os.Stderr, "usage: kliq status [--state-file <path>]")
			os.Exit(1)
		}
		return
	case "entities":
		if !handleEntitiesSubcommand(subCmdDB) {
			fmt.Fprintln(os.Stderr, "usage: kliq entities [--db <path>]")
			os.Exit(1)
		}
		return
	case "relationships":
		if !handleRelationshipsSubcommand(subCmdDB, "") {
			fmt.Fprintln(os.Stderr, "usage: kliq relationships [--db <path>]")
			os.Exit(1)
		}
		return
	case "baselines":
		if !handleBaselinesGenericSubcommand(subCmdDB) {
			fmt.Fprintln(os.Stderr, "usage: kliq baselines [--db <path>]")
			os.Exit(1)
		}
		return
	case "learning":
		if !handleLearningSubcommand(subCmdDB) {
			fmt.Fprintln(os.Stderr, "usage: kliq learning [--db <path>]")
			os.Exit(1)
		}
		return
	case "storage":
		if !handleStorageSubcommand(subCmdDB) {
			fmt.Fprintln(os.Stderr, "usage: kliq storage [--db <path>]")
			os.Exit(1)
		}
		return
	case "", "--help", "-h":
		fmt.Fprintln(os.Stderr, kliqUsage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "kliq: unknown command %q\n\n%s\n", firstArg, kliqUsage)
		os.Exit(1)
	}

	// ── §2 Config + PDP setup ───────────────────────────────────────────────
	c := parseFlags()

	// Mode handling.
	switch c.Mode {
	case string(corepolicy.ModeStandalone):
		// normal local-policy path
	case string(corepolicy.ModeManaged):
		kliqLog.Printf("INFO: mode=managed")
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
		adapterParams, err := catalog.CapabilityParamsFromPDP(catalog.DefaultAdapterID, pdpc)
		if err != nil {
			log.Fatalf("load PDP adapter config: %v", err)
		}
		c.adapterParams = adapterParams
		softFactor, hardFactor, err := catalog.AdaptiveRateFactorsFromPDP(catalog.DefaultAdapterID, pdpc)
		if err != nil {
			log.Fatalf("load PDP adaptive adapter config: %v", err)
		}
		if softFactor > 0 {
			c.SoftRateFactor = softFactor
		}
		if hardFactor > 0 {
			c.HardRateFactor = hardFactor
		}
	} else {
		// In managed mode: LKG bundle may override pdp_profile and adapters.
		if c.Mode == string(corepolicy.ModeManaged) {
			if lkgBytes := loadLastKnownGoodBundle(c.StatePath); lkgBytes != nil {
				if b, err := parseTrustedRuntimeBundle(lkgBytes, &c); err == nil {
					if b.Spec.PDPProfile != "" {
						kliqLog.Printf("PDP profile from bundle: %s (was: %s)", b.Spec.PDPProfile, c.ProfileName)
						c.ProfileName = b.Spec.PDPProfile
					}
					if b.Spec.Adapters != "" {
						kliqLog.Printf("Adapters from bundle: %s (was: %s)", b.Spec.Adapters, c.Adapters)
						c.Adapters = b.Spec.Adapters
					}
				} else {
					kliqLog.Printf("MANAGED: ignoring untrusted last-known-good bundle for profile/adapters: %v", err)
				}
			}
		}
		p = profileByName(c.ProfileName)
		c.adapterParams = catalog.DefaultCapabilityParams(catalog.DefaultAdapterID)
	}

	var startupPolicy loadedPolicyFile

	// Policy: abstract enforcement rules (autonomy, when/then, exports).
	// Optional — without a policy file, profile defaults + CLI flags apply.
	// --policy-file accepts both LocalPolicyPack and contracts-based
	// RuntimePolicyPack files; the top-level kind selects the loader path.
	if c.PolicyFile != "" {
		var loaded loadedPolicyFile
		if c.Mode == string(corepolicy.ModeManaged) {
			// Managed mode: signature verification is mandatory (CLAUDE.md rule #8).
			if c.PolicyVerifyKeyPath == "" {
				log.Fatalf("managed mode requires --policy-verify-key to verify pack signature")
			}
			pubKey, kerr := corepolicy.LoadPublicKey(c.PolicyVerifyKeyPath)
			if kerr != nil {
				log.Fatalf("load policy verify key: %v", kerr)
			}
			var err error
			loaded, err = loadPolicyFile(c.PolicyFile, pubKey)
			if err != nil {
				log.Fatalf("load policy file: %v", err)
			}
		} else {
			// Standalone mode: signature verification is optional.
			if c.PolicyVerifyKeyPath != "" {
				pubKey, kerr := corepolicy.LoadPublicKey(c.PolicyVerifyKeyPath)
				if kerr != nil {
					log.Fatalf("load policy verify key: %v", kerr)
				}
				var err error
				loaded, err = loadPolicyFile(c.PolicyFile, pubKey)
				if err != nil {
					log.Fatalf("load policy file: %v", err)
				}
			} else {
				var err error
				loaded, err = loadPolicyFile(c.PolicyFile, nil)
				if err != nil {
					log.Fatalf("load policy file: %v", err)
				}
			}
		}
		kliqLog.Printf("Policy loaded: file=%s kind=%s name=%s", c.PolicyFile, loaded.Kind, loaded.Name())
		applyLoadedPolicyToCfg(loaded, &c)
		startupPolicy = loaded
	}

	applyProfileDefaults(&c, p)
	c.Cooldown = c.adapterParams.Cooldown

	// Resolve runtime feature profile.
	// Priority: --feature-profile flag > LKG bundle > --graph flag > dos-light default.
	// The LKG bundle is read here (before adapters start) so its feature_profile takes
	// effect on startup rather than being applied too late after adapters are already
	// initialized with the wrong profile.
	if c.FeatureProfile == "" {
		if lkgBytes := loadLastKnownGoodBundle(c.StatePath); lkgBytes != nil {
			if b, err := parseTrustedRuntimeBundle(lkgBytes, &c); err == nil && b.Spec.FeatureProfile != "" {
				c.FeatureProfile = b.Spec.FeatureProfile
				kliqLog.Printf("Feature profile from bundle: %s", c.FeatureProfile)
			} else if err != nil {
				kliqLog.Printf("MANAGED: ignoring untrusted last-known-good bundle for feature profile: %v", err)
			}
		}
	}
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

	// Sync GraphEnabled from the resolved feature profile so that bundles setting
	// feature_profile=graph-* activate graph learning without requiring --graph flag.
	if features.GraphLearning {
		c.GraphEnabled = true
	}

	sourceBaseline, sourceBaselineSummary, err := runtimeSourceBaseline(catalog.DefaultAdapterID, features.SourceBaseline, c)
	if err != nil {
		log.Fatalf("source baseline setup: %v", err)
	}
	if sourceBaseline != nil {
		kliqLog.Printf("Source baseline cache started: %s", sourceBaselineSummary)
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
			tuningApplied, tuningReason := c.applyPersistedTuningThresholds(st, explicitFlags, p.Name)
			updatedStr := "never"
			if !st.Active.UpdatedAt.IsZero() {
				updatedStr = st.Active.UpdatedAt.Format(time.RFC3339)
			}
			if tuningApplied {
				kliqLog.Printf("Loaded tuning state: profile=%s rev=%d updated=%s %s %s",
					st.Active.Profile, st.Active.Revision, updatedStr, tuningReason, c.tuningThresholds().Summary())
			} else {
				kliqLog.Printf("Loaded state metadata: profile=%s rev=%d updated=%s tuning=skipped reason=%q",
					st.Active.Profile, st.Active.Revision, updatedStr, tuningReason)
			}
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
					stFile.Active = newBootstrapStateActive(p.Name, c, bs, cfgHash)
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
	wl := sourcefilters.NewWhitelist(c.WhitelistPath)
	fb := sourcefilters.NewFeedback(c.FeedbackPath)

	if c.WhitelistPath != "" {
		if err := wl.Load(); err == nil {
			wl.MarkLoaded()
			stats := wl.Stats()
			kliqLog.Printf("Whitelist loaded: %s subjects=%d entries=%d ranges=%d",
				c.WhitelistPath, stats.Subjects, stats.Entries(), stats.Ranges())
		} else {
			kliqLog.Printf("Whitelist not loaded (%s): %v", c.WhitelistPath, err)
		}
	}

	if c.FeedbackPath != "" {
		if err := fb.Load(time.Now()); err == nil {
			fb.MarkLoaded()
			stats := fb.Stats()
			kliqLog.Printf("Feedback loaded: %s subjects=%d entries=%d ranges=%d",
				c.FeedbackPath, stats.Subjects, stats.Entries(), stats.Ranges())
		} else {
			kliqLog.Printf("Feedback not loaded (%s): %v", c.FeedbackPath, err)
		}
	}

	// ── §4 Adapter init ─────────────────────────────────────────────────────
	// Resolve node ID (shared by heuristic engine and graph learner).
	nodeID := c.GraphNodeID
	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "local"
		}
	}

	type adapterBinding struct {
		id      string
		binding *catalog.Binding
	}
	var adapterBindings []adapterBinding
	type sourcePEPBinding struct {
		id  string
		pep adapterruntime.SourcePEP
	}
	var sourcePEPSidecars []sourcePEPBinding
	var sourcePEP adapterruntime.SourcePEP
	var relationshipPEP adapterruntime.RelationshipPEP
	relationshipPEPs := &relationshipPEPGroup{}
	bindingAdapterNames := c.bindingAdapterNames()
	if len(bindingAdapterNames) > 0 {
		kliqLog.Printf("Adapter bindings requested: %v", bindingAdapterNames)
	}
	for _, adapterID := range bindingAdapterNames {
		binding, berr := catalog.OpenBinding(context.Background(), catalog.BindingConfig{
			AdapterID: adapterID,
			NodeID:    nodeID,
			BPFfsRoot: c.BPFfsRoot,
			Interval:  c.Interval,
			PrevTTL:   c.PrevTTL,
			DryRun:    c.DryRun,
		})
		if berr != nil {
			kliqLog.Printf("WARNING: adapter %s unavailable (%v) — enforcement/telemetry may be inactive", adapterID, berr)
		}
		if binding == nil {
			continue
		}
		bindingID := adapterID
		if catalog.IsBindingAdapter(bindingID) {
			bindingID = catalog.CanonicalAdapterID(bindingID)
		}
		adapterBindings = append(adapterBindings, adapterBinding{id: bindingID, binding: binding})
		if binding.Close != nil {
			defer binding.Close()
		}
		if binding.SourcePEP != nil {
			if sourcePEP == nil {
				sourcePEP = binding.SourcePEP
			} else {
				sourcePEPSidecars = append(sourcePEPSidecars, sourcePEPBinding{
					id:  bindingID,
					pep: binding.SourcePEP,
				})
			}
		}
		if binding.RelationshipPEP != nil {
			binding := binding
			relationshipPEPs.Add(bindingID, binding.RelationshipPEP, func() {
				if binding.TryOpenRelations != nil {
					binding.TryOpenRelations(c.BPFfsRoot)
				}
			})
		}
	}
	if relationshipPEPs.Len() > 0 {
		relationshipPEP = relationshipPEPs
	}
	if len(bindingAdapterNames) == 0 {
		kliqLog.Printf("no catalog runtime adapter in --adapter list — skipping catalog adapter binding")
	}

	// ── §3 State store + graph ──────────────────────────────────────────────
	if c.StateStorePath != "" && c.StateStorePath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(c.StateStorePath), 0o755); err != nil {
			log.Fatalf("create state store dir for %s: %v", c.StateStorePath, err)
		}
	}
	stateStore, ssErr := sstore.Open(sstore.DefaultConfig(c.StateStorePath))
	if ssErr != nil {
		log.Fatalf("open state store %s: %v", c.StateStorePath, ssErr)
	}
	defer stateStore.Close()

	// Central enforcement pipeline: resolver is the policy gate; executor is the
	// only component authorized to call the source PEP, through the action broker
	// for TTL-bounded actions.
	resolver := c.buildPolicyResolver()
	sourceExecutor := buildExecutor(sourcePEP)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return c.toPEPParams()
	})
	actionBroker, abErr := actionbroker.New(actionbroker.Config{
		NodeID: nodeID,
		Store:  stateStore,
		PEP:    brokerPEP,
		Now:    func() time.Time { return time.Now().UTC() },
	})
	if abErr != nil {
		log.Fatalf("action broker init: %v", abErr)
	}
	var relationshipBroker *actionbroker.Broker
	var relationshipBrokerPEP *brokeredRelationshipPEP
	if relationshipPEP != nil {
		relationshipBrokerPEP = newBrokeredRelationshipPEP(relationshipPEP)
		var rbErr error
		relationshipBroker, rbErr = actionbroker.New(actionbroker.Config{
			NodeID: nodeID,
			Store:  stateStore,
			PEP:    relationshipBrokerPEP,
			Now:    func() time.Time { return time.Now().UTC() },
		})
		if rbErr != nil {
			log.Fatalf("relationship action broker init: %v", rbErr)
		}
	}
	executor := newBrokeredActionExecutor(sourceExecutor, actionBroker, brokerPEP, relationshipBroker, relationshipBrokerPEP, stateStore, nodeID)
	runtimeFacts := newRuntimePDPFactStore(stateStore)
	for _, sidecar := range sourcePEPSidecars {
		sidecar := sidecar
		executor.AddSidecar(sourcePEPSidecar{
			id:  sidecar.id,
			pep: sidecar.pep,
			params: func() adapterruntime.EnforcementParams {
				return c.toPEPParams()
			},
		})
		kliqLog.Printf("Source PEP sidecar active: adapter=%s", sidecar.id)
	}
	if receipts, err := actionBroker.ReconcilePending(context.Background()); err != nil {
		kliqLog.Printf("WARNING: action broker pending lease reconciliation failed: %v", err)
	} else if len(receipts) > 0 {
		kliqLog.Printf("Action broker reconciled %d pending leases", len(receipts))
		for _, receipt := range receipts {
			logEnforcementReceipt(receipt)
		}
	}
	if relationshipBroker != nil {
		if receipts, err := relationshipBroker.ReconcilePending(context.Background()); err != nil {
			kliqLog.Printf("WARNING: relationship action broker pending lease reconciliation failed: %v", err)
		} else if len(receipts) > 0 {
			kliqLog.Printf("Relationship action broker reconciled %d pending leases", len(receipts))
			for _, receipt := range receipts {
				logEnforcementReceipt(receipt)
			}
		}
	}

	// Netfilter adapter — active when "netfilter" is in --adapter list.
	// Registered as a sidecar so every enforcement decision is also mirrored
	// into iptables/nftables rules. Works with or without catalog adapters.
	var nfAdapter *netfilterruntime.Adapter
	if c.WantsNetfilter() {
		nfAdapter = netfilterruntime.InitAdapter(context.Background(), netfilterruntime.SetupConfig{
			DryRun:    c.DryRun,
			PDPConfig: c.PDPConfig,
		}, kliqLog)
		if nfAdapter != nil {
			executor.AddSidecar(nfAdapter)
			kliqLog.Printf("Netfilter adapter active: backend=%s dry_run=%v", nfAdapter.SelectedBackend(), c.DryRun)
		} else {
			kliqLog.Printf("WARNING: --adapter includes netfilter but no backend found (nft/iptables missing)")
		}
	}

	// Runtime inventory and config-asset report is logged after the LKG bundle
	// apply (below) so that HasPolicyPack and ProfileName reflect the restored state.

	// ── Managed lifecycle controllers ─────────────────────────────────────────
	// Both controllers are initialised from defaults; if a RuntimeBundle is
	// present (persisted or pulled at startup) applyBundleUpdate will rebuild
	// them with the bundle-provided config.

	// Bootstrap/autotune lifecycle controller.
	bsCfg := bootstrapautotune.DefaultConfig()
	bsCfg.Enabled = c.Bootstrap
	var bsInitState *bootstrapautotune.State
	if stFile != nil && stFile.Active.Bootstrap.Enabled {
		bsInitState = &bootstrapautotune.State{
			Enabled:         stFile.Active.Bootstrap.Enabled,
			StartedAt:       stFile.Active.Bootstrap.StartedAt,
			Phase:           stFile.Active.Bootstrap.Phase,
			ObservedSeconds: stFile.Active.Bootstrap.ObservedSeconds,
		}
	}
	bsCtl := bootstrapautotune.New(bsCfg, bsInitState)

	// Graph lifecycle controller (managed mode only; stays at learn by default).
	graphCfg := lgraph.DefaultConfig()
	graphCfg.Enabled = c.Mode == "managed"
	graphPhase := ""
	graphLifecycleStart := time.Time{}
	if stFile != nil {
		graphPhase = stFile.Active.GraphLifecyclePhase
		graphLifecycleStart = stFile.Active.GraphLifecycleStartedAt
	}
	graphCtl := lgraph.New(graphCfg, graphPhase, graphLifecycleStart)

	// managedState tracks bundle-level persistence (generation, hash).
	ms := managedState{}
	if stFile != nil {
		ms.BundleGeneration = stFile.Active.ForgeBundleGeneration
		ms.BundleHash = stFile.Active.ForgeBundleHash
	}

	// bundleUpdateCh receives raw bundle YAML from the forgeagent heartbeat.
	// Declared as receive-only so it can be set from forgeAgent.BundleUpdates()
	// or from a local channel when running without Forge.
	var bundleUpdateCh <-chan []byte = make(chan []byte, 1)
	runtimePolicyUpdateCh := make(chan contracts.RuntimePolicyPack, 8)

	// ── Shadow metric pipeline ──────────────────────────────────────────────────
	// Disabled by default (metric_pipeline.enabled=false). Adapter-specific
	// metric conversion belongs in runtime adapters; the orchestrator only owns
	// the lifecycle of the generic pipeline.
	shadowPipelineCfg := pipeline.DefaultConfig()
	// TODO: read from KliqComponentConfig.Analyzers.MetricPipeline when available
	// For now: check environment variable for easy testing
	if os.Getenv("KLIQ_METRIC_PIPELINE") == "shadow" {
		shadowPipelineCfg.Enabled = true
		shadowPipelineCfg.Mode = pipeline.ModeShadow
	}
	shadowPipeline := pipeline.New(pipeline.Options{
		Config: shadowPipelineCfg,
	})

	// Apply last-known-good bundle on startup (fail_static).
	if lkg := loadLastKnownGoodBundle(c.StatePath); lkg != nil {
		kliqLog.Printf("MANAGED: applying last-known-good bundle from disk")
		applyBundleUpdate(lkg, &c, &bsCtl, &graphCtl, &ms, stFile)
	}

	// Pre-set HasPolicyPack from persisted state so the startup INVENTORY log
	// reflects a previously applied pack rather than always showing false.
	if !c.HasPolicyPack && stFile != nil && stFile.Active.ForgePackName != "" {
		c.HasPolicyPack = true
	}

	// Runtime inventory and config-asset report — built after LKG bundle apply
	// so that HasPolicyPack and ProfileName reflect the restored state.
	activeAdapters := make(map[string]bool)
	primaryActive := false
	for _, adapterBinding := range adapterBindings {
		binding := adapterBinding.binding
		if binding == nil {
			continue
		}
		id := adapterBinding.id
		if binding.Active {
			activeAdapters[id] = true
			primaryActive = true
		} else if _, ok := activeAdapters[id]; !ok {
			activeAdapters[id] = false
		}
	}
	if nfAdapter != nil {
		activeAdapters["netfilter"] = true
	} else if c.WantsNetfilter() {
		activeAdapters["netfilter"] = false
	}
	report := buildConfigAssetReport(c, nodeID, features, activeAdapters)
	inv := buildEmptyInventory(nodeID)
	for _, adapterBinding := range adapterBindings {
		binding := adapterBinding.binding
		if binding != nil && binding.Inventory.Metadata.ID != "" {
			inv = binding.Inventory
			break
		}
	}
	logInventoryAndReport(inv, report, c.StatePath)

	// tupleActive is set after edge-map probe and read by the heartbeat goroutine.
	tupleActive := false

	// ── §6 Forge agent ──────────────────────────────────────────────────────
	// Receipt upload queue — runs whenever a Forge client is available.
	// Picks up persisted receipts and uploads them to Forge asynchronously.
	// Initialized below after forgeC is created; nil-safe if Forge is not configured.
	receiptUploaderCtx, receiptUploaderCancel := context.WithCancel(context.Background())
	defer receiptUploaderCancel()

	// Forge enrollment + heartbeat — driven by internal/forgeagent.
	var forgeC *forgeClient
	var activePackIssuedAt time.Time // set by applyForgePack; used for rollback protection
	var forgeAgent *forgeagent.Agent
	if c.ForgeURL != "" {
		var fcErr error
		forgeC, fcErr = newForgeClient(c.ForgeURL, c.ForgeEnrollToken, nodeID, c.ForgeCAPath)
		if fcErr != nil {
			kliqLog.Fatalf("forge client init: %v", fcErr)
		}

		// Start receipt upload queue now that we have a Forge client.
		startReceiptUploader(receiptUploaderCtx, stateStore, forgeC,
			log.New(os.Stderr, "[receipt-uploader] ", log.LstdFlags))

		// Restore persisted session from state file (avoids re-enrollment on restart).
		initPackName, initPackHash := "", ""
		if stFile != nil && stFile.Active.ForgeSessionToken != "" {
			forgeC.RestoreSession(stFile.Active.ForgeSessionToken)
			initPackName = stFile.Active.ForgePackName
			initPackHash = stFile.Active.ForgePackHash
			activePackIssuedAt = stFile.Active.ForgePackIssuedAt
			kliqLog.Printf("FORGE session restored from state: pack=%s", initPackName)
		}

		forgeAgent = forgeagent.New(
			forgeagent.Config{
				NodeID:          nodeID,
				Heartbeat:       c.ForgeHeartbeat,
				InitialPackName: initPackName,
				InitialPackHash: initPackHash,
			},
			forgeagent.Callbacks{
				Enroll: func(ctx context.Context) (string, string, error) {
					er, err := forgeC.Enroll(ctx, c.Mode, inv, report)
					if err != nil {
						return "", "", err
					}
					if stFile != nil && forgeC.SessionToken() != "" {
						stFile.Active.ForgeSessionToken = forgeC.SessionToken()
						_ = writeStateAtomic(c.StatePath, stFile)
					}
					return er.NodeID, er.Status, nil
				},
				Heartbeat: func(ctx context.Context, packName string) (bool, string, error) {
					return forgeC.Heartbeat(ctx, packName, false)
				},
				PullPack: func(ctx context.Context) ([]byte, string, error) {
					return forgeC.PullPack(ctx)
				},
				PullBundle: func(ctx context.Context) ([]byte, error) {
					b, _, err := forgeC.PullBundle(ctx)
					return b, err
				},
				ReportPackStatus: func(ctx context.Context, name string, ok bool, msg string) error {
					return forgeC.ReportPackStatus(ctx, name, ok, msg)
				},
				ReportStatus: func(ctx context.Context) error {
					status := buildRuntimeStatus(nodeID, ms, bsCtl, graphCtl, lgraph.GraphStats{}, &c, tupleActive)
					reportBundleStatus(ctx, forgeC, status)
					return nil
				},
			},
			func(packBytes []byte, packName string) error {
				// Apply the pack and update rollback state.
				loaded, err := applyForgePack(packBytes, packName, c.PolicyVerifyKeyPath, &c, &activePackIssuedAt)
				if err != nil {
					return err
				}
				if loaded.Runtime != nil {
					select {
					case runtimePolicyUpdateCh <- *loaded.Runtime:
					default:
						kliqLog.Printf("runtime policy update channel full; dropping pack %s", packName)
					}
				}
				hash := PackHash(packBytes)
				forgeAgent.SetPackHash(hash)
				updateSidecarPack(c.StatePath, packName, c.PolicyMaxAction)
				return nil
			},
			func(packName, packHash string) {
				if stFile != nil {
					stFile.Active.ForgePackName = packName
					stFile.Active.ForgePackIssuedAt = activePackIssuedAt
					stFile.Active.ForgePackHash = packHash
					_ = writeStateAtomic(c.StatePath, stFile)
				}
			},
			log.New(os.Stderr, "[forge-agent] ", log.LstdFlags),
		)
		agentCtx, agentCancel := context.WithCancel(context.Background())
		defer agentCancel()
		if err := forgeAgent.Start(agentCtx); err != nil {
			kliqLog.Printf("WARNING: forge agent start: %v", err)
		}
		// Wire the agent's bundle channel to the main loop.
		bundleUpdateCh = forgeAgent.BundleUpdates()
	}

	// Tuple enforcement: activate relationship enforcement when the feature is enabled.
	// Try to refresh relationship enforcement handles first in case an adapter
	// was reloaded after kliq started (or tuple support was activated
	// post-startup). If unavailable, degrade gracefully to graph-learning behavior.
	if features.TupleEnforcement && relationshipPEP != nil {
		if !relationshipPEP.RelationshipAvailable() {
			relationshipPEPs.RefreshUnavailable()
		}
		if relationshipPEP.RelationshipAvailable() {
			if err := relationshipPEP.SetRelationshipEnforcement(true); err != nil {
				kliqLog.Printf("WARNING: tuple enforce activate failed: %v", err)
			} else {
				tupleActive = true
				kliqLog.Printf("Tuple enforcement: relationship PEP active (deny-mode)")
			}
		} else {
			features.TupleEnforcement = false
			kliqLog.Printf("DEGRADED: feature-profile=graph-enforce but relationship enforcement is not available — " +
				"running as graph-learning until a configured adapter exposes relationship enforcement. " +
				"Graph learning and baselines are active.")
		}
	} else if features.TupleEnforcement {
		features.TupleEnforcement = false
		kliqLog.Printf("DEGRADED: feature-profile=graph-enforce but no relationship PEP is configured — " +
			"running as graph-learning. Graph learning and baselines are active.")
	}

	// ── §5 Decision pipeline ────────────────────────────────────────────────
	// Decision engine: classifies local signals for audit/risk context.
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

	// Main signal bus — shared by runtime adapters, graph learner and future adapters.
	mainBus := adapterruntime.NewBus(512)

	var runtimeAdapters []adapterruntime.ObservingAdapter
	for _, adapterBinding := range adapterBindings {
		binding := adapterBinding.binding
		if binding == nil || binding.TelemetryHandle == nil || binding.RuntimeFactory == nil {
			continue
		}
		runtimeAdapter, err := startRuntimeAdapter(
			context.Background(),
			binding.RuntimeFactory,
			runtimeAdapterSpec(binding.RuntimeAdapterID, nodeID, c, binding.TelemetryHandle, sourceBaseline),
			mainBus,
		)
		if err != nil {
			log.Fatalf("start runtime adapter %s: %v", binding.RuntimeAdapterID, err)
		}
		runtimeAdapters = append(runtimeAdapters, runtimeAdapter)
		defer runtimeAdapter.Stop(context.Background())
	}

	// Start the netfilter adapter on the bus (launches the TTL GC goroutine).
	if nfAdapter != nil {
		nfCtx, nfCancel := context.WithCancel(context.Background())
		defer nfCancel()
		if err := nfAdapter.Start(nfCtx, mainBus); err != nil {
			kliqLog.Printf("WARNING: netfilter adapter Start failed: %v", err)
		}
	}

	netfilterruntime.StartTopologyFallbackObserver(context.Background(), mainBus, nodeID, c.GraphEnabled, primaryActive, nfAdapter, kliqLog)

	// graphStrikeCh bridges graph.new_edge_after_freeze signals to the generic
	// RuntimePDP candidate path. The graph contributes facts; it does not own
	// enforcement.
	graphStrikeCh := make(chan graphStrikeMsg, 512)

	runtimeCtx, runtimeCancel := context.WithCancel(context.Background())
	defer runtimeCancel()
	shadowRunner, err := startRuntimePDPService(runtimeCtx, runtimePDPServiceConfig{
		NodeID:      nodeID,
		Mode:        c.RuntimePDPMode,
		PolicyFile:  c.PolicyFile,
		StartupPack: startupPolicy.Runtime,
		PackUpdates: runtimePolicyUpdateCh,
		Bus:         mainBus,
		Resolver:    resolver,
		Executor:    executor,
		Params: func() adapterruntime.EnforcementParams {
			return c.toPEPParams()
		},
		Facts: runtimeFacts,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	startKLIQSignalConsumer(runtimeCtx, runtimeSignalConsumerConfig{
		NodeID:           nodeID,
		Bus:              mainBus,
		DecisionEngine:   decisionEng,
		GraphStrikeCh:    graphStrikeCh,
		TupleEnforcement: features.TupleEnforcement,
		RelationshipPEP:  relationshipPEP,
		RuntimeRunner:    shadowRunner,
		RuntimeFacts:     runtimeFacts,
		Resolver:         resolver,
		Executor:         executor,
	})

	// Graph pipeline (optional) — uses generic relationship learner + state store.
	var gpAdapter *graphpipeline.Adapter
	var gpStateStore *sstore.Store

	if c.GraphEnabled {
		ss := stateStore
		gpStateStore = stateStore

		gpMode := graphpipeline.ModeLearn
		switch c.GraphMode {
		case "learn", "":
			gpMode = graphpipeline.ModeLearn
		case "frozen-observe":
			gpMode = graphpipeline.ModeFrozenObserve
		case "frozen-enforce":
			gpMode = graphpipeline.ModeFrozenEnforce
			decPolicy.GraphFreezeAction = decision.ActionBlock
			decPolicy.AllowLocalBlock = true
			decPolicy.MaxAction = decision.ActionBlock
			decPolicy.MinSeverityForBlock = 90
			decisionEng.UpdatePolicy(decPolicy)
			kliqLog.Printf("Graph: frozen-enforce active — unknown edges produce RuntimePDP block-intent facts")
		default:
			log.Fatalf("unknown --graph-mode %q (valid: learn, frozen-observe, frozen-enforce)", c.GraphMode)
		}

		excludeCIDRs := graphpipeline.ParseExcludeSourceCIDRs(c.GraphExcludeSourceCIDR)
		if len(excludeCIDRs) > 0 {
			kliqLog.Printf("Graph: excluding source CIDRs from learning: %s", c.GraphExcludeSourceCIDR)
		}

		var guard learning.Guard = learningguard.New(learningguard.DefaultConfig(), ss, nil)
		if c.WhitelistLearn {
			guard = newWhitelistAwareGuard(guard, wl)
			kliqLog.Printf("Graph: whitelist-aware guard active (whitelisted IPs bypass learning exclusions)")
		}

		rlCfg := relationshiplearner.DefaultConfig(nodeID)
		rlCfg.Mode = relationshiplearner.Mode(gpMode)
		rlCfg.Promotion = relationshiplearner.PromotionConfig{
			MinSeenCount:       c.GraphMinSeenCount,
			MinDistinctWindows: c.GraphMinWindows,
			MinAge:             c.GraphMinAge,
		}
		rlLearner := relationshiplearner.New(rlCfg, guard, ss, mainBus)
		if loadErr := rlLearner.LoadFromStore(context.Background()); loadErr != nil {
			kliqLog.Printf("WARN: load relationships from store: %v", loadErr)
		}

		gpConfig := graphpipeline.Config{
			NodeID:                     nodeID,
			Mode:                       gpMode,
			Promotion:                  rlCfg.Promotion,
			BaselineAlpha:              c.BaselineAlpha,
			BaselineAlphaBootstrap:     c.BaselineAlphaBootstrap,
			BaselineMinObservations:    c.BaselineMinObservations,
			BaselineDeviationThreshold: c.BaselineDeviationThreshold,
			BaselineMinUpdates:         graphBaselineMinUpdates(c),
			BaselinePeakTolerance:      c.BaselinePeakTolerance,
			ObservationMinValues:       graphObservationMinValues(c),
			ExcludeBroadcast:           c.GraphExcludeBcast,
			ExcludeLoopback:            c.GraphExcludeLoopback,
			ExcludeSourceCIDRs:         excludeCIDRs,
		}
		applyGraphRuntimeValuesFromAdapters(&gpConfig, runtimeAdapters)
		gpAdapter = graphpipeline.New(gpConfig, rlLearner, guard)

		// Periodic flush of dirty relationships + state store GC.
		go func() {
			flushT := time.NewTicker(30 * time.Second)
			gcT := time.NewTicker(5 * time.Minute)
			defer flushT.Stop()
			defer gcT.Stop()
			for {
				select {
				case <-runtimeCtx.Done():
					_, _ = rlLearner.FlushDirty(context.Background())
					_, _ = gpAdapter.BaselineEngine().FlushDirty(context.Background(), ss)
					return
				case <-flushT.C:
					if _, err := rlLearner.FlushDirty(context.Background()); err != nil {
						kliqLog.Printf("WARN: flush relationships: %v", err)
					}
					if _, err := gpAdapter.BaselineEngine().FlushDirty(context.Background(), ss); err != nil {
						kliqLog.Printf("WARN: flush baselines: %v", err)
					}
				case <-gcT.C:
					_ = ss.GC(context.Background())
				}
			}
		}()

		defer func() {
			if n, err := rlLearner.FlushDirty(context.Background()); err != nil {
				kliqLog.Printf("WARN: shutdown flush relationships: %v", err)
			} else if n > 0 {
				kliqLog.Printf("Graph shutdown flush: relationships=%d", n)
			}
			if n, err := gpAdapter.BaselineEngine().FlushDirty(context.Background(), ss); err != nil {
				kliqLog.Printf("WARN: shutdown flush baselines: %v", err)
			} else if n > 0 {
				kliqLog.Printf("Graph shutdown flush: baselines=%d", n)
			}
		}()

		gctx, gcancel := context.WithCancel(context.Background())

		startedFlowTelemetry := 0
		for _, adapterBinding := range adapterBindings {
			binding := adapterBinding.binding
			if binding == nil || binding.FlowTelemetry == nil {
				continue
			}
			telAdapter := binding.FlowTelemetry
			if err := telAdapter.Start(gctx, mainBus); err != nil {
				gcancel()
				log.Fatalf("start graph telemetry adapter %s: %v", telAdapter.ID(), err)
			}
			defer telAdapter.Stop(context.Background())
			startedFlowTelemetry++
		}
		if startedFlowTelemetry == 0 {
			kliqLog.Printf("Graph: adapter flow telemetry unavailable — using topology fallback observations")
		}

		if err := gpAdapter.Start(gctx, mainBus); err != nil {
			gcancel()
			log.Fatalf("start graph pipeline adapter: %v", err)
		}
		defer func() {
			gpAdapter.Stop(context.Background())
			gcancel()
		}()

		kliqLog.Printf("Graph pipeline started: mode=%s state-db=%s node=%s", gpMode, c.StateStorePath, nodeID)
	}

	sources := newSourceStates()

	tuner, tunerErr := catalog.NewTuner(catalog.DefaultAdapterID, c.tuningThresholds(), c.tuningConfig(), 50_000)
	if tunerErr != nil {
		log.Fatalf("tuner init: %v", tunerErr)
	}

	totalLearnTicks := 0
	cleanLearnTicks := 0

	// syncRelationshipAllowlist writes all frozen/approved network.connects_to
	// relationships into the active adapter relationship PEP. Must be called
	// before activating allow-mode and periodically after graph changes.
	syncRelationshipAllowlist := func() {
		if gpStateStore == nil || relationshipPEP == nil || !relationshipPEP.RelationshipAvailable() {
			return
		}
		rels, err := gpStateStore.ListRelationships(context.Background(), nodeID, "network.connects_to", "")
		if err != nil {
			kliqLog.Printf("relationship allowlist sync: list relationships: %v", err)
			return
		}
		n := 0
		for _, r := range rels {
			if r.State != relationship.StateFrozen && r.State != relationship.StateApproved {
				continue
			}
			// SubjectEntityID is the stable entity ID hash, not a raw IP.
			// For relationship enforcement we need the adapter-facing source ID.
			srcEntity, eErr := gpStateStore.GetEntityByStableID(context.Background(), r.SubjectEntityID)
			if eErr != nil || srcEntity == nil {
				continue
			}
			target, ok := relationshipActionTargetFromAttributes(srcEntity.ID, r.Dimensions)
			if !ok {
				continue
			}
			if err := relationshipPEP.AllowRelationship(target.PEP); err != nil {
				kliqLog.Printf("relationship allowlist sync: %s: %v", target.Label, err)
			} else {
				n++
			}
		}
		if n > 0 {
			kliqLog.Printf("relationship allowlist sync: synced %d frozen/approved edges", n)
		}
	}

	// Populate allowlist on startup (idempotent: LRU map, duplicate writes are fine).
	if features.TupleEnforcement {
		syncRelationshipAllowlist()
	}

	// Start shadow pipeline (no-op when disabled).
	pipelineCtx, pipelineCancel := context.WithCancel(context.Background())
	defer pipelineCancel()
	shadowPipeline.Start(pipelineCtx)

	// ── §7 Tick-loop prep ───────────────────────────────────────────────────
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	var tickN uint64
	lastBrokerRevert := time.Time{}
	lastExpiredCleanup := time.Now()

	// SIGUSR1: de-escalate all enforced IPs to OBSERVE so kliq state stays in
	// sync after an external enforcement reset.
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
	tuningSummary := "adapter-tuning=unavailable"
	if len(runtimeAdapters) > 0 {
		tuningSummary = runtimeAdaptersSummary(runtimeAdapters)
	}
	ipv6Active := false
	for _, adapterBinding := range adapterBindings {
		binding := adapterBinding.binding
		if binding != nil && binding.IPv6Active {
			ipv6Active = true
			break
		}
	}
	adapterSummary := fmt.Sprintf("adapter_active=%v", primaryActive)
	if len(adapterBindings) > 0 {
		ipv6Status := "inactive"
		if ipv6Active {
			ipv6Status = "active"
		}
		adapterSummary = fmt.Sprintf("%s adapter_ipv6=%s", adapterSummary, ipv6Status)
	}
	kliqLog.Printf("Kernloom IQ started profile=%s bootstrap=%s interval=%s dry_run=%v top=%d %s (%s)",
		p.Name, bootstrapPhase, c.Interval.String(), c.DryRun, c.TopN, tuningSummary, adapterSummary)

	// ── §8 Main tick loop ───────────────────────────────────────────────────
	// This loop is the core of KLIQ. Each tick:
	//   a) drains pending bundle/signal updates
	//   b) reads eBPF map telemetry (v4+v6)
	//   c) evaluates source facts/intent per opaque source
	//   d) runs autotune when due
	// The loop runs on a single goroutine — no locking needed for shared state.
	for {
		select {
		case <-stopCh:
			kliqLog.Println("shutting down")
			return
		case <-ticker.C:
		}
		nowWall := time.Now()
		if lastBrokerRevert.IsZero() || nowWall.Sub(lastBrokerRevert) >= c.Interval {
			lastBrokerRevert = nowWall
			executor.RevertExpired(context.Background(), nowWall)
		}

		// Process pending bundle update (non-blocking; delivered by heartbeat goroutine).
		select {
		case rawBundle := <-bundleUpdateCh:
			applyBundleUpdate(rawBundle, &c, &bsCtl, &graphCtl, &ms, stFile)
			// Persist updated managed state immediately.
			if stFile != nil {
				stFile.Active.ForgeBundleGeneration = ms.BundleGeneration
				stFile.Active.ForgeBundleHash = ms.BundleHash
				_ = writeStateAtomic(c.StatePath, stFile)
			}
		default:
		}

		// Handle SIGUSR1: clear FSM state to sync with an external map reset.
		select {
		case <-resetCh:
			pepParams := c.toPEPParams()
			n := sources.reset(nowWall, executor, pepParams)
			kliqLog.Printf("RESET via SIGUSR1: de-escalated %d enforced sources to OBSERVE", n)
		default:
		}

		wl.MaybeReload(c.WhitelistReload)
		fb.MaybeReload(c.FeedbackReload)

		pepParams := c.toPEPParams()
		sources.applyFeedback(nowWall, fb, executor, pepParams, c.FeedbackCIDRDeenforce, c.FeedbackCIDREvery, c.FeedbackCIDRMax)

		// Compute drop ratio for learn gating.
		dropRatio := 0.0

		cands := make([]metrics, 0, 4096)
		seenForLearn := 0
		highSevCount := 0

		observedAny := false
		observeFailed := false
		for _, runtimeAdapter := range runtimeAdapters {
			observed, stats, err := runtimeAdapter.Observe(context.Background(), adapterruntime.RuntimeTick{
				Now:      nowWall,
				Interval: c.Interval,
			})
			if err != nil {
				observeFailed = true
				kliqLog.Printf("observe adapter=%s err: %v", stats.AdapterID, err)
				continue
			}
			observedAny = true
			for _, obs := range observed {
				m, ok := metricsFromObservation(obs)
				if !ok {
					continue
				}
				if m.hasLearningSignal() {
					seenForLearn++
					if m.score() >= c.LearnSevGT {
						highSevCount++
					}
				}
				cands = append(cands, m)
			}
		}
		if observeFailed && !observedAny {
			continue
		}

		sort.Slice(cands, func(i, j int) bool {
			if cands[i].score() == cands[j].score() {
				return cands[i].primarySortValue() > cands[j].primarySortValue()
			}
			return cands[i].score() > cands[j].score()
		})
		if c.TopN < len(cands) {
			cands = cands[:c.TopN]
		}

		// Drain graph strike credits from frozen-observe/enforce signals.
		// Applied after TopN cap so graph-violated IPs are always evaluated.
		// UpStreak is set to UpNeed to bypass the anti-flap guard — a behavioral
		// violation is deliberate, not metric noise.
		// forceBlock=true (frozen-enforce): set strikes to BlockAt+1 so FSM intent
		// proposes BLOCK immediately. RuntimePDP still decides whether an action
		// is emitted.
	drainGraphStrikes:
		for {
			select {
			case gs := <-graphStrikeCh:
				sources.applyGraphStrike(&cands, gs, nowWall, c)
			default:
				break drainGraphStrikes
			}
		}

		// Count active blocks for clean-tick decision.
		blocksActive := sources.activeBlocks()

		totalLearnTicks++
		clean := !observeFailed
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
			// Mirror into lifecycle controller (managed-mode status reporting).
			{
				sec := uint64(math.Round(c.Interval.Seconds()))
				if sec == 0 {
					sec = 1
				}
				bsCtl.RecordTick(clean, sec, nil)
			}
		}

		processed := sources.processCandidates(cands, nowWall, c, wl, fb, resolver, executor, tuner, clean, shadowRunner, nodeID, runtimeFacts)

		// Maintenance sweep: advance source intent for non-OBSERVE sources that
		// had no qualifying observation this tick. RuntimePDP decides whether the
		// resulting downscale/observe intent becomes an action.
		sources.sweepInactive(processed, nowWall, c, resolver, executor, pepParams, shadowRunner, nodeID, runtimeFacts)

		tickN++
		if tickN%30 == 1 {
			softN, hardN, blockN := sources.levelCounts()
			topSummary := "none"
			if len(cands) > 0 {
				top := cands[0]
				topSummary = fmt.Sprintf("%s score=%.2f", top.sourceID(), top.score())
			}
			kliqLog.Printf("TICK#%d sources=%d cands=%d samples=%d clean=%v fsm{soft=%d hard=%d block=%d} %s top: %s",
				tickN, seenForLearn, len(cands), tuner.SampleCount(), clean, softN, hardN, blockN,
				tuner.CurrentThresholds().Summary(), topSummary)
		}

		// Housekeeping: bound memory.
		if tickN%300 == 1 { // evict every ~5 min at 1s interval
			evictRuntimeSourceBaseline(sourceBaseline, nowWall.Add(-24*time.Hour))
		}
		// Re-sync relationship allowlist every 5 min so newly approved/frozen
		// edges are picked up without a restart.
		if features.TupleEnforcement && tickN%300 == 1 {
			syncRelationshipAllowlist()
		}
		// State store GC runs via the dedicated goroutine (every 5 min);
		// reset the cleanup timestamp so the old guard doesn't fire.
		if gpStateStore != nil && nowWall.Sub(lastExpiredCleanup) >= 24*time.Hour {
			lastExpiredCleanup = nowWall
		}
		// Bootstrap checkpoint every 30s: persist observed_seconds so a restart
		// can resume from where it left off (max ~30s of progress lost on crash).
		if c.Bootstrap && bs.Enabled && c.StatePath != "" && stFile != nil && tickN%30 == 0 {
			stFile.Active.Bootstrap = bs
			stFile.Active.ConfigHash = cfgHash
			// Also persist managed lifecycle state.
			stFile.Active.GraphLifecyclePhase = graphCtl.Phase()
			stFile.Active.GraphLifecycleStartedAt = graphCtl.StartedAt()
			if err := writeStateAtomic(c.StatePath, stFile); err != nil {
				kliqLog.Printf("bootstrap checkpoint failed: %v", err)
			}
		}

		// Managed graph lifecycle tick (advance phase state machine).
		if c.Mode == "managed" {
			gStats := lgraph.GraphStats{
				BootstrapPhase:   bsCtl.Effective().Phase,
				CleanLearningSec: bsCtl.ObservedSeconds(),
			}
			if changed := graphCtl.Tick(gStats, nowWall); changed {
				kliqLog.Printf("MANAGED: graph lifecycle phase → %s", graphCtl.Phase())
				if stFile != nil {
					stFile.Active.GraphLifecyclePhase = graphCtl.Phase()
					stFile.Active.GraphLifecycleStartedAt = graphCtl.StartedAt()
					_ = writeStateAtomic(c.StatePath, stFile)
				}
				// Upload proposal when reaching freeze_ready.
				if graphCtl.Phase() == lgraph.PhaseFreezeReady && forgeC != nil && graphCfg.ProposalUpload {
					go func() {
						id := uploadBaselineProposal(context.Background(), forgeC, nodeID,
							graphCtl, bsCtl, gStats, &c)
						if id != "" {
							graphCtl.MarkProposalSent(time.Now())
						}
					}()
				}
			}
		}
		sources.evictIdle(nowWall, c.StateTTL)

		// Autotune — policy is computed here; threshold math lives in the active adapter.
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

		// Keep BootstrapActive in sync so RuntimePDP receives current bootstrap facts.
		c.BootstrapActive = pol.Active

		if c.AutoTune {
			cleanRatio := 0.0
			if totalLearnTicks > 0 {
				cleanRatio = float64(cleanLearnTicks) / float64(totalLearnTicks)
			}
			atPol := adapterruntime.TuningPolicy{
				Active:  pol.Active,
				Every:   pol.Every,
				K:       pol.K,
				MaxUp:   pol.MaxUp,
				MaxDown: pol.MaxDown,
				Alpha:   pol.Alpha,
				Phase:   pol.Phase,
			}

			if r, ok := tuner.Tick(nowWall, atPol, cleanRatio); ok {
				c.applyTuningThresholds(r.NewThresholds)
				applyAutotuneRuntimeUpdateToAdapters(context.Background(), runtimeAdapters, r)
				if gpAdapter != nil {
					if values, ok := graphRuntimeValuesFromAdapters(runtimeAdapters); ok {
						gpAdapter.UpdateBaselineTriggers(values)
					}
				}

				tuner.LogResult(kliqLog, r, pol.K, dropRatio, clean)

				if c.StatePath != "" {
					tuningScope, _ := c.tuningScopeRef()
					st := applyAutotuneStateUpdate(stFile, p.Name, tuningScope, bs, cfgHash, c.HistoryKeep, r, pol.K, dropRatio)
					if err := writeStateAtomic(c.StatePath, st); err != nil {
						kliqLog.Printf("AUTOTUNE state write failed: %v", err)
					} else {
						stFile = st
						kliqLog.Printf("AUTOTUNE state saved: %s (rev=%d)", c.StatePath, st.Active.Revision)
					}
				}
			} else if r.Skipped {
				kliqLog.Printf("AUTOTUNE skipped: %s (have=%d need=%d) cleanRatio=%.4f",
					r.SkipReason, r.SampleCount, c.AutoMinSamples, r.CleanRatio)
				continue
			}
		}

	}
}
