# Kernloom

[![CI](https://github.com/Kernloom/kernloom/actions/workflows/ci.yml/badge.svg)](https://github.com/Kernloom/kernloom/actions/workflows/ci.yml)

Kernloom is a modular, open Zero Trust and anomaly detection platform for Linux workloads. The local runtime consists of two tightly integrated components:

- **`klshield`** — XDP/eBPF data plane. Enforces deny/rate-limit decisions in the kernel packet path at line rate.
- **`kliq`** — userspace intelligence agent. Learns traffic baselines and communication graphs, evaluates enterprise policy via a contracts-based Runtime PDP, brokers TTL-bounded enforcement actions, and integrates with Forge for managed-mode operation.

Official docs: https://kernloom.com/

---

## Architecture

```
Git / Enterprise PAP
    │
    ↓
Forge (policy compiler)          kernloom-forge repo
    │ signed RuntimeBundle        kernloom-contracts + core bundle schemas
    │
    ↓
┌──────────────────────────────────────────────────────────────┐
│                       KLIQ (kliq)                            │
│                                                              │
│  PIP adapters          Pipeline                  PDP         │
│  ──────────────        ─────────────────       ──────────    │
│  KLShield telemetry    graph learning          CEL rules      │
│  netfilter conntrack   metric baseline         local risk     │
│  OpenZiti events ①     signal engines          decisions     │
│                              │                               │
│                        Action Broker                         │
│                    (lease store, fencing,                    │
│                     receipts, upload queue)                  │
│                              │                               │
│  PEP adapters ───────────────┘                               │
│  KLShield PEP (eBPF maps)                                    │
│  netfilter PEP (nftables)                                    │
│  OpenZiti action adapter (planned) ①                         │
│                                                              │
│  Shadow/Active RuntimePDP                                    │
│  shadow: logs decisions alongside FSM                        │
│  active: becomes primary enforcement (--runtime-pdp-mode)    │
└──────────────────────────────────────────────────────────────┘
    │ writes eBPF maps
┌─────────────────────────────────────────┐
│  KLShield (XDP/eBPF)                    │
│  allowlist → denylist → rate-limit      │
│  → PASS / DROP                          │
└─────────────────────────────────────────┘

① OpenZiti: eventsource, decoder, mapping and relationship learning are
  present; enforcement actions are planned.
```

---

## Two use cases

### Scenario A — DoS Prevention (public-facing nodes)

**When:** Internet-facing nodes — Ziti controller, Ziti router, public web server, reverse proxy.

**What:** KLIQ learns your node's normal PPS/SYN/scan rates and rate-limits or blocks sources that deviate. No graph learning, no SQLite, minimal overhead.

### Scenario B — Microsegmentation (internal nodes)

**When:** Internal nodes communicating with a small, known set of services — database, IdP, internal API, NAS.

**What:** KLIQ learns the full communication graph. After freeze, unexpected connections are detected and can be rate-limited or blocked at the exact `(src_ip, port, proto)` tuple in XDP.

---

## Runtime profiles

| Profile | Active subsystems |
|---|---|
| `dos-light` | Source heuristics + autotune. No graph, no SQLite. |
| `iq-learning` | dos-light + per-source EWMA baseline + state store. |
| `graph-learning` | iq-learning + flow telemetry + graph learning + edge baselines + SQLite. |
| `graph-enforce` | graph-learning + XDP tuple enforcement. |
| `full-learning-experimental` | graph-learning + generic relationship/baseline paths for lab use. |

---

## Build

```bash
# Prerequisites: Linux + bpffs, clang ≥ 15, Go matching go.mod
export PATH=$PATH:/usr/local/go/bin
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# BPF object + binaries in ./bin
make build

# Tests
go test ./...
```

---

## Quick start — DoS Prevention

```bash
sudo ./bin/klshield attach-xdp --iface eth0 \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o
sudo ./bin/kliq run \
  --adapter=klshield \
  --feature-profile=dos-light \
  --pdp-config=configs/pdp/ziti-controller-bootstrap.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --whitelist-learn=true
./bin/kliq status
```

See `configs/pdp/` for all PDPConfig profiles.

---

## Quick start — Microsegmentation

```bash
# Phase 1 — learn (14 days dry-run)
sudo ./bin/kliq run \
  --adapter=klshield \
  --feature-profile=graph-learning \
  --pdp-config=configs/pdp/idp-bootstrap.yaml \
  --graph --graph-mode=learn \
  --dry-run=true --whitelist-learn=true

./bin/kliq graph edges --sort=state
./bin/kliq graph freeze --dry-run
sudo ./bin/kliq graph freeze

# Phase 2 — enforce
sudo ./bin/kliq run \
  --adapter=klshield \
  --feature-profile=graph-enforce \
  --pdp-config=configs/pdp/idp.yaml \
  --graph --graph-mode=frozen-enforce \
  --graph-freeze-action=rate_limit \
  --graph-freeze-max-action=rate_limit \
  --dry-run=false
```

---

## Managed mode (with Forge)

When a Forge control plane is available, KLIQ operates in managed mode:

```bash
# Start the Forge API server (in kernloom-forge repo)
forge serve --addr :8443

# Connect KLIQ to Forge
./bin/kliq run \
  --mode=managed \
  --forge-url=https://forge.example.com:8443 \
  --forge-enroll-token=<token> \
  --policy-verify-key=/etc/kernloom/forge.pub \
  --runtime-pdp-mode=shadow   # or: active
```

**`--runtime-pdp-mode`:**
- `shadow` (default) — the new Runtime PDP evaluates alongside the legacy FSM and logs decisions for parity comparison. No enforcement change.
- `active` — Runtime PDP decisions become enforcement actions via the action broker. The FSM remains active for network-layer defence.

In managed mode KLIQ:
1. Enrolls the node and heartbeats runtime status to Forge
2. Downloads a signed `RuntimeBundle` from Forge
3. Verifies Ed25519 signature, generation monotonicity, and expiry
4. Applies bootstrap autotune, graph lifecycle and enforcement bounds
5. Loads local or Forge-delivered `LocalPolicyPack` or `RuntimePolicyPack` files through the same policy gate
6. Persists enforcement leases/receipts locally and uploads pending receipts to Forge

Standalone nodes can also load a contracts-based RuntimePolicyPack directly:

```bash
./bin/kliq run \
  --adapter=klshield \
  --policy-file=/etc/kernloom/policies/runtime-policy.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true
```

`--policy-file` accepts:
- `kind: LocalPolicyPack` — legacy/local KLIQ policy and threshold tuning.
- `kind: RuntimePolicyPack` with `apiVersion: kernloom.io/runtime/v1alpha1` — contracts-based Runtime PDP rules. In `shadow` mode decisions are logged; in `active` mode matched Runtime PDP decisions are mapped to `ActionProposal`s and enforced through the action broker.

---

## Forge compatibility contract

Shared Runtime PDP wire schemas are imported from `github.com/kernloom/kernloom-contracts` (v0.1.0). During the migration, managed bundle ingestion still uses the local `pkg/core/bundle` model.

```
RuntimeBundle          kernloom.io/runtime/v1alpha1
RuntimePolicyPack      kernloom.io/runtime/v1alpha1
LocalRiskAssessment    kernloom.io/runtime/v1alpha1
RuntimeDecision        kernloom.io/runtime/v1alpha1
EnforcementReceipt     kernloom.io/runtime/v1alpha1
RuntimeFinding         kernloom.io/runtime/v1alpha1
BundleAck              kernloom.io/runtime/v1alpha1
```

KLIQ keeps conformance fixtures for signed runtime bundles, unsupported schema/capability/action/mode combinations, and offline last-known-good (`fail_static`) validation in `iq/internal/conformance/`.

---

## Action leases and receipts

Every TTL-bounded enforcement action is recorded as an `ActionLease` before the PEP is called. Leases carry:
- a fencing token (prevents blind revert if the target was manually changed)
- expiry time and previous state reference
- revert status: `pending` → `reverted` | `conflict` | `failed`

Receipts are emitted for every apply/revert and persisted in SQLite (`action_receipts` table). A background goroutine uploads pending receipts to Forge every 30 seconds.
KLIQ also reverts expired source and relationship leases from the main runtime tick, so tuple/relationship actions have the same expiry and receipt path as source actions.

---

## OpenZiti adapter

The OpenZiti adapter currently lives in `pkg/adapters/openziti/`:

| Package | Status | Description |
|---|---|---|
| `eventsource/` | ✅ implemented | `EventSource` interface, `RawVendorEvent`, version discovery, file replay |
| `decoder/` | ✅ implemented | Tolerant decoder for P0 namespaces (authentication, apiSession, session, usage, sdk) |
| `mapping/` | ✅ implemented | VendorFact → canonical Observation (no vendor field names in output) |
| `relationshiplearner/` | ✅ implemented | `ziti.dials` identity → service relationships from canonical observations |
| `signalengine/` | planned | OpenZiti-specific signal engine |
| `learningguard/` | planned | adapterruntime.LearningGuard |
| `actions/` | planned | remove access attribute, disable identity and related OpenZiti PEP actions |

Key invariants:
- `decoder/` is the only package that references OpenZiti field names.
- `service.dial.fail` is NOT mapped to identity risk (spec §7.4 — aggregated metric, not identity-attributed).
- Unknown event namespaces produce `SemanticStatus=unknown_namespace`, never a silent wrong signal.

---

## Repository layout

```
kernloom/
├── iq/
│   ├── cmd/kliq/                 KLIQ agent — main loop, CLI, wiring
│   │   ├── kliq.go               main loop and CLI runtime composition
│   │   ├── shadow_pdp.go         RuntimePDP shadow/active mode runner
│   │   ├── policy_file.go        LocalPolicyPack/RuntimePolicyPack loader
│   │   ├── runtime_pdp_action_mapper.go  RuntimeDecision → ActionProposal
│   │   ├── brokered_executor.go  Action broker wiring + receipt persistence
│   │   ├── receipt_uploader.go   Background Forge receipt upload queue
│   │   └── forge_client.go       Forge HTTP client (enroll, bundle pull, upload)
│   └── internal/
│       ├── actionbroker/         Lease journal, fencing, receipt/revert handling
│       ├── actions/              ActionProposal → PolicyResolver → ActionResolution
│       ├── conformance/          RuntimeBundle compatibility fixtures
│       ├── forgeagent/           Forge agent helpers and tests
│       ├── localrisk/            LocalRiskAssessment (level, confidence, completeness)
│       ├── runtimepdp/           CEL-based Runtime PDP (contracts.RuntimePolicyPack)
│       ├── sourcefilters/        Whitelist/feedback loaders
│       └── lifecycle/            Bootstrap autotune and graph lifecycle helpers
├── shield/
│   ├── bpf/                      XDP/eBPF program (C)
│   └── cmd/klshield/             klshield CLI
├── pkg/
│   ├── core/
│   │   ├── capability/           Generic capability IDs
│   │   ├── observation/          Canonical observation model
│   │   ├── signal/               Signal type catalog
│   │   ├── decision/             Decision, ActionLease, EnforcementReceipt
│   │   ├── enforcement/          Generic enforcement targets
│   │   ├── entity/               Entity model (Kind, Ref)
│   │   ├── graph/                Graph edge model + lifecycle
│   │   ├── relationship/         Generic relationship model
│   │   ├── evidence/             Evidence records
│   │   ├── learning/             Learning guard contracts + exclusions
│   │   ├── baseline/             Baseline key + profile types
│   │   ├── featureset/           Runtime feature profiles
│   │   ├── kliqconfig/           Deployment/component config schemas
│   │   ├── metric/               Metric model
│   │   ├── fsm/                  FSM levels, State, Advance()
│   │   ├── policy/               LocalPolicyPack schema + loader
│   │   ├── pdp/                  PDPConfig schema + loader
│   │   └── cel/                  CEL evaluator for KLShield policy rules
│   ├── adapters/                 Vendor/product integrations ONLY
│   │   ├── catalog/              Runtime adapter catalog, tuning and source baseline hooks
│   │   ├── klshield/
│   │   │   ├── client/           eBPF map client
│   │   │   ├── guard/            KLShield learning guard
│   │   │   ├── pep/              PEP (writes eBPF deny/rl/allow maps)
│   │   │   ├── runtime/          Runtime adapter factory, telemetry/tuning wiring
│   │   │   ├── shadow/           Shadow/dry-run wrapper
│   │   │   ├── signalengine/     KLShield heuristic signal engine
│   │   │   └── telemetry/        eBPF telemetry → observations
│   │   ├── netfilter/            netfilter PEP (nftables + iptables)
│   │   │   └── runtime/          netfilter runtime setup/status hooks
│   │   └── openziti/             OpenZiti adapter (Phase 1)
│   │       ├── eventsource/      EventSource interface + FileReplaySource
│   │       ├── decoder/          Tolerant decoder for P0 namespaces
│   │       ├── mapping/          VendorFact → canonical Observation
│   │       └── relationshiplearner/  ziti.dials relationship extractor
│   ├── pipeline/
│   │   ├── runner.go             Generic pipeline runner
│   │   └── graphpipeline/        Graph learning pipeline component
│   ├── sourcebaseline/           Per-source EWMA baseline cache
│   ├── metricbaseline/           Generic metric baseline engine (EWMA)
│   ├── learningguard/            Learning guard (anti-poisoning)
│   ├── featureextractor/         Feature extractor interface
│   ├── signalengine/             Signal engine interface
│   ├── relationshiplearner/      Generic relationship extractor interface
│   │   ├── network/              L3/L4 network relationships
│   │   └── http/                 HTTP relationships
│   ├── riskaggregator/           Signal risk aggregation
│   ├── decisionengine/           Decision engine (FSM + signals → decisions)
│   ├── adapterruntime/           Adapter lifecycle interface + EventBus
│   └── statestore/sqlite/        SQLite state store, baselines, leases, receipts
└── configs/
    └── pdp/                      PDPConfig profiles for supported node roles
```

---

## Adapter boundary rule

`pkg/adapters/` is reserved for vendor/product integrations only. Generic pipeline components live in `pkg/pipeline/` or sibling packages.

A complete vendor adapter contains all product-specific code in one directory:
`eventsource`, `decoder`, `mapping`, `extractor`, `signalengine`, `learningguard`, `relationshiplearner`, `pep`, `actions`.

Core packages (`pkg/core/`, `pkg/pipeline/`, etc.) must never contain vendor names as Go identifiers.

---

## Known technical debt

See `TECHNICAL_DEBT.md` for the full prioritised list. Key items:

| Issue | Priority |
|---|---|
| Shared `kernloom-contracts` module is not yet fully adopted by managed bundle ingestion | P1 |
| `iq/cmd/kliq` still owns too much runtime orchestration and should keep shrinking into internal services | P1 |
| Historical names such as `LocalPolicyPack` and `PDPConfig` remain visible during the migration | P2 |

---

## License

MPL-2.0 — see `LICENSE`.
