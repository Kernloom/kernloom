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
    │ signed RuntimeBundle        pkg/contracts/ schemas
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
│  OpenZiti action adapter ①                                   │
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

① OpenZiti: eventsource, decoder, mapping Phase 1 complete;
  action adapter planned in Phase 3
```

---

## Two use cases

### Scenario A — DoS Prevention (public-facing nodes)

**When:** Internet-facing nodes — Ziti controller, Ziti router, public web server, reverse proxy.

**What:** KLIQ learns your node's normal PPS/SYN/scan rates and rate-limits or blocks sources that deviate. No graph learning, no SQLite, minimal overhead.

### Scenario B — Microsegmentation (internal nodes)

**When:** Internal nodes communicating with a small, known set of services — database, IdP, internal API, NAS.

**What:** KLIQ learns the full communication graph. After freeze, any unexpected connection is detected and blocked to the exact `(src_ip, port, proto)` tuple in XDP with zero race window.

---

## Runtime profiles

| Profile | Active subsystems |
|---|---|
| `dos-light` | Source heuristics + autotune. No graph, no SQLite. |
| `iq-learning` | dos-light + per-source EWMA baseline. |
| `graph-learning` | iq-learning + flow telemetry + graph learning + edge baselines + SQLite. |
| `graph-enforce` | graph-learning + XDP tuple enforcement. |

---

## Build

```bash
# Prerequisites: Linux + bpffs, clang ≥ 15, Go matching go.mod
export PATH=$PATH:/usr/local/go/bin
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# BPF object
make -C shield/bpf

# Binaries
go build -o klshield ./shield/cmd/klshield
go build -o kliq     ./iq/cmd/kliq

# Tests
go test ./...
```

---

## Quick start — DoS Prevention

```bash
sudo ./klshield attach-xdp --iface eth0 \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o
sudo cp configs/pdp/ziti-controller-bootstrap.yaml \
        /opt/kernloom/attested/etc/pdp/node.yaml
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --dry-run=true --whitelist-learn=true
./kliq status
```

See `configs/pdp/` for all PDPConfig profiles.

---

## Quick start — Microsegmentation

```bash
# Phase 1 — learn (14 days dry-run)
sudo ./kliq --pdp-config=configs/pdp/idp-bootstrap.yaml \
  --graph --graph-mode=learn --dry-run=true --whitelist-learn=true

./kliq graph edges --sort=state
./kliq graph freeze --dry-run
sudo ./kliq graph freeze

# Phase 2 — enforce
sudo ./kliq --pdp-config=configs/pdp/idp-bootstrap.yaml \
  --graph --graph-mode=frozen-enforce --dry-run=false
```

---

## Managed mode (with Forge)

When a Forge control plane is available, KLIQ operates in managed mode:

```bash
# Start the Forge API server (in kernloom-forge repo)
forge serve --addr :8443

# Connect KLIQ to Forge
./kliq \
  --forge-url=https://forge.example.com:8443 \
  --forge-enroll-token=<token> \
  --runtime-pdp-mode=shadow   # or: active
```

**`--runtime-pdp-mode`:**
- `shadow` (default) — the new Runtime PDP evaluates alongside the legacy FSM and logs decisions for parity comparison. No enforcement change.
- `active` — Runtime PDP decisions become enforcement actions via the action broker. The FSM remains active for network-layer defence.

In managed mode KLIQ:
1. Downloads a signed `RuntimeBundle` from Forge
2. Verifies Ed25519 signature, generation monotonicity, and expiry
3. Activates the embedded `RuntimePolicyPack` in the Runtime PDP
4. Persists enforcement receipts locally and uploads them to Forge every 30 s
5. Sends `LocalRiskAssessment` and `RuntimeFinding` to Forge

---

## Forge compatibility contract

Shared wire schemas live in `github.com/kernloom/kernloom-contracts` (v0.1.0):

```
RuntimeBundle          kernloom.io/runtime/v1alpha1
RuntimePolicyPack      kernloom.io/policy/runtime/v1alpha1
LocalRiskAssessment    kernloom.io/risk/v1alpha1
EnforcementReceipt     kernloom.io/runtime/v1alpha1
RuntimeFinding         kernloom.io/runtime/v1alpha1
BundleAck              kernloom.io/runtime/v1alpha1
```

---

## Action leases and receipts

Every TTL-bounded enforcement action is recorded as an `ActionLease` before the PEP is called. Leases carry:
- a fencing token (prevents blind revert if the target was manually changed)
- expiry time and previous state reference
- revert status: `pending` → `reverted` | `conflict` | `failed`

Receipts are emitted for every apply/revert and persisted in SQLite (`action_receipts` table). A background goroutine uploads pending receipts to Forge every 30 seconds.

---

## OpenZiti adapter

Phase 1 of the OpenZiti adapter is implemented in `pkg/adapters/openziti/`:

| Package | Status | Description |
|---|---|---|
| `eventsource/` | ✅ Phase 1 | `EventSource` interface, `RawVendorEvent`, version discovery, file replay |
| `decoder/` | ✅ Phase 1 | Tolerant decoder for P0 namespaces (authentication, apiSession, session, usage, sdk) |
| `mapping/` | ✅ Phase 1 | VendorFact → canonical Observation (no vendor field names in output) |
| `relationshiplearner/` | ✅ stub | `identity_dials_service` relationships |
| `extractor/` | planned | featureextractor.Extractor |
| `signalengine/` | planned | signalengine.Engine |
| `learningguard/` | planned | adapterruntime.LearningGuard |
| `actions/` | planned Phase 3 | remove_kernloom_access_attribute, identity.disable |

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
│   │   ├── kliq.go               main loop (1950 lines; split planned TD-P1-004)
│   │   ├── shadow_pdp.go         RuntimePDP shadow/active mode runner
│   │   ├── brokered_executor.go  Action broker wiring + receipt persistence
│   │   ├── receipt_uploader.go   Background Forge receipt upload queue
│   │   └── forge_client.go       Forge HTTP client (enroll, bundle pull, upload)
│   └── internal/
│       ├── actionbroker/         Lease journal, fencing, receipt/revert handling
│       ├── actions/              ActionProposal → PolicyResolver → ActionResolution
│       ├── localrisk/            LocalRiskAssessment (level, confidence, completeness)
│       ├── runtimepdp/           CEL-based Runtime PDP (contracts.RuntimePolicyPack)
│       └── lifecycle/            Bootstrap autotune and graph lifecycle helpers
├── shield/
│   ├── bpf/                      XDP/eBPF program (C)
│   └── cmd/klshield/             klshield CLI
├── pkg/
│   ├── contracts/                Forge↔KLIQ wire schemas (local; v0.1.0 in contracts repo)
│   ├── core/
│   │   ├── observation/          Canonical observation model
│   │   ├── signal/               Signal type catalog
│   │   ├── decision/             Decision, ActionLease, EnforcementReceipt
│   │   ├── entity/               Entity model (Kind, Ref)
│   │   ├── graph/                Graph edge model + lifecycle
│   │   ├── evidence/             Evidence records
│   │   ├── learning/             Learning guard contracts + exclusions
│   │   ├── baseline/             Baseline key + profile types
│   │   ├── metric/               Metric model
│   │   ├── fsm/                  FSM levels, State, Advance()
│   │   ├── policy/               LocalPolicyPack schema + loader
│   │   ├── pdp/                  PDPConfig schema + loader
│   │   └── cel/                  CEL evaluator for KLShield policy rules
│   ├── adapters/                 Vendor/product integrations ONLY
│   │   ├── klshield/
│   │   │   ├── client/           eBPF map client
│   │   │   ├── guard/            KLShield learning guard
│   │   │   ├── pep/              PEP (writes eBPF deny/rl/allow maps)
│   │   │   ├── shadow/           Shadow/dry-run wrapper
│   │   │   ├── signalengine/     KLShield heuristic signal engine
│   │   │   └── telemetry/        eBPF telemetry → observations
│   │   ├── netfilter/            netfilter PEP (nftables + iptables)
│   │   └── openziti/             OpenZiti adapter (Phase 1)
│   │       ├── eventsource/      EventSource interface + FileReplaySource
│   │       ├── decoder/          Tolerant decoder for P0 namespaces
│   │       ├── mapping/          VendorFact → canonical Observation
│   │       └── relationshiplearner/  identity_dials_service extractor (stub)
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
    ├── pdp/                      PDPConfig profiles (16 profiles, all node roles)
    └── policies/                 LocalPolicyPack examples
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

| ID | Issue | Priority |
|---|---|---|
| TD-P0-001 | Two RuntimeBundle schemas (old `pkg/core/bundle/` + new `contracts`) need consolidation | P0 |
| TD-P1-003 | Action broker not yet fully live for tuple/de-enforce paths | P1 |
| TD-P1-004 | `kliq.go` is 1950 lines — split into `internal/forgeagent/`, `internal/runtimepdp/` etc. | P1 |
| TD-P1-005 | `pkg/contracts/` not yet committed to git (in `kernloom-contracts` repo with replace directive) | P1 |

---

## License

MPL-2.0 — see `LICENSE`.
