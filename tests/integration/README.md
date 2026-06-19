# Kernloom Integration Tests

These tests check how KLIQ, KLShield/XDP, Netfilter, and Forge work together at the process, network, and control-plane level. They are not unit tests on purpose. They start real binaries, create Linux network namespaces, attach XDP programs to veth interfaces, send real traffic, and check logs, eBPF maps, CLI output, and HTTP APIs.

## Quick Start

Full XDP/netns run:

```bash
make integration
```

Control-plane run without XDP/root network setup:

```bash
make integration-forge
```

Run single scenarios:

```bash
KLT_SCENARIOS="00 09 10" make integration
KLT_SCENARIOS="09" bash tests/integration/run-forge.sh
KLT_SCENARIOS="12" bash tests/integration/run-forge.sh
KLT_SCENARIOS="tests/integration/scenarios/04_graph_learn_freeze.sh" sudo -E tests/integration/run.sh
```

`KLT_SCENARIOS` accepts full paths, file names, or prefixes such as `04`, `09`, or `11`.

## Requirements

The full run needs a Linux host with:

- `sudo`
- `ip netns`, `iproute2`
- `bpffs` mounted at `/sys/fs/bpf`
- eBPF/XDP support for veth interfaces
- `clang`, `llvm`, `make`, `libbpf-dev`, kernel headers
- `curl`, `python3`, `jq`
- optional for scenario 11: `nft` or `iptables`, `nc`/`ncat`/`netcat`

Forge scenarios 09 and 10 do not need XDP. They need:

- `curl`
- `jq`
- a built Forge binary or a sibling checkout at `../kernloom-forge`

Scenario 12 also runs without XDP. It needs:

- a Go toolchain (`KLT_GO`, `go`, or `/usr/local/go/bin/go`)

## Artifacts

Runtime artifacts are stored outside the repository by default:

```text
/tmp/kernloom-integration-artifacts-<uid>/<run-id>/
```

Important files in this folder:

- `kliq.log`: KLIQ tick, signal, FSM, and action logs
- `klshield.log`: XDP attach/detach output
- `server.log`: HTTP test server output
- `state/`: KLIQ state, SQLite DB, feedback/whitelist copies
- `09/`, `10/`, `11/`, `12/`: scenario-specific Forge, Netfilter, or RuntimePolicyPack output

You can override the path:

```bash
KLT_ARTIFACT_DIR=/tmp/my-kernloom-it sudo -E tests/integration/run.sh
```

`tests/integration/artifacts/` remains only as an empty guard directory in the repository. Everything in it is protected by `.gitignore`; only `.gitignore` and `.gitkeep` stay tracked. CI also fails if generated artifacts are accidentally tracked anyway.

## Test Topology

The XDP scenarios build this local topology:

```text
                 host namespace

      veth-good-h      veth-bad-h       veth-api-h
          |                |                |
          +----------------+----------------+
                           |
                         br-klt
                           |
        XDP attach on veth-good-h and veth-bad-h

  klt-good namespace   klt-bad namespace    klt-api namespace
  10.42.0.11           10.42.0.66           10.42.0.20:8080
  good client          bad client           Python HTTP server
```

KLShield/XDP is attached to the host-side client veth interfaces. This lets KLIQ see the correct source IP address of the clients, while both client sides share the same eBPF maps.

## Runners

### `run.sh`

`tests/integration/run.sh` is the full runner. It:

- loads `env.sh`
- creates the artifact directory
- runs `cleanup_all` first
- mounts bpffs if needed
- resolves `KLT_SCENARIOS`
- builds Forge for 09/10 if these scenarios are active
- continues with all scenarios even if individual scenarios fail
- collects debug information on failures
- runs cleanup at the end
- fixes artifact ownership after sudo runs

### `run-forge.sh`

`tests/integration/run-forge.sh` is the small runner for CI and local control-plane checks without XDP. By default it starts scenarios 09, 10, and 12. It builds Forge only when scenarios 09 or 10 are active, and builds `bin/kliq` when scenario 12 is active. Running only scenario 12 does not need Forge, `curl`, or `jq`.

## Important Environment Variables

| Variable | Meaning | Default |
| --- | --- | --- |
| `KLT_ARTIFACT_DIR` | Target directory for logs, DBs, and temporary data | `/tmp/kernloom-integration-artifacts-<uid>/<run-id>` |
| `KLT_SCENARIOS` | Scenario selection | empty = default list |
| `KLT_KLIQ` | KLIQ binary | `bin/kliq` |
| `KLT_KLSHIELD` | KLShield binary | `bin/klshield` |
| `KLT_BPF_OBJ` | BPF object | `shield/bpf/out/xdp_kernloom_shield.bpf.o` |
| `KLT_FORGE_ROOT` | Forge repository | `../kernloom-forge` |
| `KLT_FORGE` | Forge binary | `bin/forge` |
| `KLT_FORGE_SKIP_BUILD` | Do not rebuild Forge | `0` |
| `KLT_GO` | Go binary | `go` or `/usr/local/go/bin/go` |

## Scenario Overview

| ID | Script | Scope | What is checked |
| --- | --- | --- | --- |
| 00 | `00_smoke_build.sh` | Build/CLI | Binaries, BPF object, and important KLIQ CLI flags |
| 01 | `01_attach_stats.sh` | XDP/Traffic | Netns topology, HTTP reachability, XDP attach, packet counters |
| 02 | `02_dryrun_detection.sh` | Detection | Bad traffic is detected, but not enforced |
| 03 | `03_enforce_rate_limit_or_block.sh` | Enforcement | RuntimePDP active mode escalates a bad source and creates XDP drops |
| 04 | `04_graph_learn_freeze.sh` | Graph | Learn good edge, freeze graph, signal new bad edge |
| 05 | `05_restart_recovery.sh` | Recovery | KLIQ restart and XDP detach/attach without traffic loss |
| 06 | `06_autotune_bootstrap.sh` | Autotune | Bootstrap tuning uses max-down without EWMA regression |
| 07 | `07_good_bad_isolation.sh` | Isolation | Good source stays reachable while bad source is enforced |
| 08 | `08_runtime_pdp_stepdown.sh` | RuntimePDP Recovery | Enforced source returns to OBSERVE after the attack stops |
| 09 | `09_managed_enrollment.sh` | Forge API | Managed enrollment, bundle pull, ACKs, receipts, findings, proposals |
| 10 | `10_adapter_definition.sh` | Forge Compiler | Adapter manifests, AccessPolicy validation, profile compilation |
| 11 | `11_netfilter_adapter.sh` | Netfilter | KLIQ without XDP, deny/restore, idempotent rules, safe cleanup |
| 12 | `12_runtime_policy_pack.sh` | RuntimePDP | `--policy-file` RuntimePolicyPack loading, compile, mapper/broker/conformance fixtures |

## Scenario Details

### 00 Smoke Build

Goal: make sure the local build artifacts exist and the most important CLI contracts are visible.

The test checks that:

- `bin/klshield` exists
- `bin/kliq` exists
- the BPF object exists
- `kliq --help` shows `kliq run`
- `kliq run --help` contains `--feature-profile` and `--runtime-pdp-mode`
- `kliq graph --help` contains graph subcommands such as `freeze`

This test also runs in normal CI without root network setup.

### 01 Attach Stats

Goal: start the real XDP data plane and prove that KLShield sees traffic.

Flow:

1. Network namespaces and a bridge are created.
2. A Python HTTP server starts in `klt-api`.
3. KLShield attaches XDP to `veth-good-h` and `veth-bad-h`.
4. `klt-good` calls the API.
5. `klshield stats` is checked.

Expected result:

- HTTP from the good client to the API works.
- `pkts` and `pass` in the XDP totals are greater than 0.
- The API remains reachable after XDP is attached.

This scenario validates the base setup for all following XDP tests.

### 02 Dry-Run Detection

Goal: KLIQ should detect aggressive traffic, but should not write any real enforcement action.

KLIQ starts with:

- `--adapter=klshield`
- `--feature-profile=dos-light`
- `--runtime-pdp-mode=shadow`
- `--dry-run=true`
- low thresholds (`trig-pps=5`, `trig-syn=5`, `trig-scan=3`)

Flow:

1. Good traffic creates a clean baseline/ticks.
2. Bad traffic bursts 200 requests.
3. KLIQ processes several ticks.
4. Good and bad source must still be able to reach HTTP.
5. The KLIQ log must contain the bad source.
6. The log must not contain any real action with `dry_run=false`.

Important: `runtime-pdp-mode=shadow` is observe-only: RuntimePDP decisions may be logged, but no action is emitted to a PEP. `--dry-run=true` is still used by this scenario to guard adapter effects while testing, but KLIQ's decision authority is the same model in both modes: analyzers/FSM produce facts and RuntimePDP owns enforcement in `active`.

### 03 Enforce Rate-Limit Or Block

Goal: prove that real local enforcement through KLShield works.

KLIQ starts in active RuntimePDP mode with a local `RuntimePolicyPack` that maps
generic `fsm.proposed_level` facts to source actions:

- `--runtime-pdp-mode=active`
- `--dry-run=false`
- low FSM thresholds (`soft-at=2`, `hard-at=4`, `block-at=6`)

Flow:

1. Good traffic stays clean.
2. Bad source bursts 300 requests.
3. KLIQ should log RuntimePDP/broker actions such as `RATE_SOFT`, `RATE_HARD`, or `BLOCK`.
4. Good source must stay reachable.
5. `klshield stats` must show `drop_rl` or `drop_deny` greater than 0.

Important: `shadow` is observe-only. Real enforcement in this scenario requires `--runtime-pdp-mode=active`.

### 04 Graph Learn Freeze

Goal: test the trust-graph lifecycle: learn, freeze, report a new edge.

KLIQ starts in the `graph-learning` profile:

- `--graph`
- `--graph-mode=learn`
- fast promotion (`graph-min-seen=3`, `graph-min-age=3s`)

Flow:

1. Good source creates several API requests.
2. KLIQ learns a relationship/edge from this.
3. KLIQ is stopped so that the in-memory graph is flushed to SQLite.
4. `kliq graph edges --all` must show the good source.
5. `kliq graph freeze` freezes the learned relationships.
6. KLIQ starts with `graph-enforce` and `--graph-mode=frozen-observe`.
7. Bad source creates a new edge that was not frozen before.
8. KLIQ must log `SIGNAL type=graph.new_edge_after_freeze` for the bad source.

This scenario also validates the shutdown flush of the graph data, so the CLI and runtime see the same persisted state.

### 05 Restart Recovery

Goal: test restart and reattach behavior.

Flow:

1. Good source must reach HTTP before the restart.
2. KLIQ is stopped and restarted in dry-run mode.
3. The KLIQ log must contain ticks again.
4. XDP is detached and attached again.
5. Good source must still reach HTTP afterwards.
6. `klshield stats` must show packets again.

This scenario covers common operator actions: restarting KLIQ and reattaching KLShield/XDP without breaking the test service.

### 06 Autotune Bootstrap

Goal: protect against an autotune regression.

Historical bug: During bootstrap, EWMA smoothing was applied to the bootstrap downscale limit. Because of this, `trig_pps` did not drop by about 10 percent per cycle, but only by about 1 percent.

KLIQ starts with:

- `--bootstrap=true`
- `--autotune=true`
- `--trig-pps=100`
- `--bootstrap-every1=8s`
- `--bootstrap-max-down1=0.10`
- `--autotune-alpha=0.10`

Flow:

1. Low-PPS good traffic fills the autotune reservoir.
2. At least one bootstrap cycle runs.
3. KLIQ is stopped.
4. `state.json` and the autotune log are checked.

Expected result:

- The first `AUTOTUNE applied` step should be around `100 -> 90`.
- A final value of `81` is okay if a second 8-second cycle also ran.
- Values near `99` would indicate the old EWMA regression.
- The scenario reads the final PPS threshold from the generic state path
  `active.tuning_scopes[*].metrics["network.packets_per_second"].threshold`
  and falls back to legacy `active.trig.trig_pps` for old state files.

### 07 Good/Bad Isolation

Goal: check the most important safety property: enforcement against a bad source must not affect a good source.

Flow:

1. XDP enforcement maps are reset.
2. KLIQ starts with active enforcement.
3. Good traffic warms up the environment.
4. Bad source creates sustained traffic in the background.
5. The test waits until KLIQ reaches `RATE_SOFT`, `RATE_HARD`, or `BLOCK` for the bad source.
6. While the bad source is enforced, the good source sends 10 HTTP requests.

Expected result:

- The KLIQ log contains a bad-source RuntimePDP action or action receipt.
- The good source has 10/10 successful HTTP checks.

This scenario protects against map keys that are too broad, global drops, or enforcement actions sent to the wrong target.

### 08 RuntimePDP Stepdown

Goal: check that a source leaves enforcement again after the attack stops.

KLIQ starts in active RuntimePDP mode with short TTLs:

- `soft-ttl=5s`
- `hard-ttl=5s`
- `block-ttl=5s`
- `down-need=2`
- `min-hold-hard=0s`

Flow:

1. Bad source creates traffic until KLIQ logs enforcement.
2. Bad traffic is stopped cleanly.
3. The test waits long enough for TTLs and clean ticks.
4. Bad source tries HTTP requests again.

Expected result:

- At least 4 out of 5 requests from the bad source work after recovery.
- The KLIQ log contains a transition to `OBSERVE`.

This scenario mainly protects the maintenance-sweep logic: even quiet sources must continue to produce downscale/observe intent facts, so RuntimePDP can release `RATE_HARD` or `BLOCK`.

### 09 Forge Managed Enrollment

Goal: test the current Forge managed-mode API contract. No XDP is needed.

Flow:

1. Forge starts with adapter and profile examples.
2. `/healthz` must return `ok`.
3. A node named `it-node-09` enrolls itself.
4. The enrollment response must contain `node_id` and `session_token`.
5. The runtime bundle for the node can be fetched.
6. Bundle ACK is accepted.
7. Receipt upload is accepted.
8. Findings upload is accepted.
9. Baseline proposal upload is accepted.

This scenario validates the HTTP endpoints that KLIQ needs in managed mode.

### 10 Forge Adapter Definition

Goal: test Forge adapter/profile/policy compilation. No XDP is needed.

Flow:

1. Adapter capability manifests for `klshield`, `netfilter`, and `openziti` are validated.
2. The example policy `investor-apps-access` is validated.
3. The policy is compiled against the example profiles.
4. The summary output must contain profiles such as `idp-production`, `klshield-local`, and `openziti-production`.
5. The summary must show deployment qualities such as `deployable`, `unsupported`, `downgraded`, `delegated`, or `compensating`.
6. The YAML plan output must not be empty and must contain policy metadata.

This scenario checks the policy-intent split across several PEP/adapter profiles: one intent can be partly directly deployable, partly delegated, or partly compensated.

### 11 Netfilter Adapter

Goal: validate Netfilter as a fallback or alternative without KLShield/XDP.

The scenario skips cleanly if requirements are missing:

- no `CAP_NET_ADMIN`
- no `nft` or `iptables`
- no `nc`/`ncat`/`netcat`

Flow:

1. Two separate namespaces are created: server and client.
2. Baseline connectivity is checked with ping.
3. `kliq run --adapter=netfilter` starts briefly without KLShield/XDP maps.
4. The test checks that there is no BPF-map-open fatal error in the log.
5. A TCP listener starts in the server namespace.
6. Client connectivity works before deny.
7. A deny rule is applied for the specific backend.
8. Client connectivity must be blocked.
9. Reapplying the rule must not create duplicates.
10. De-enforce/flush must restore connectivity.
11. Cleanup must only remove Kernloom-owned Netfilter objects.
12. A pre-existing user rule must be preserved.

This scenario is intentionally defensive: it checks not only the effect, but also idempotency and cleanup boundaries.

### 12 RuntimePolicyPack Contract

Goal: validate the contracts-based Runtime PDP path without XDP or root network setup.

Flow:

1. The scenario writes a temporary `kind: RuntimePolicyPack` YAML file into the artifact directory.
2. `kliq run --adapter=none --policy-file=<runtime-policy.yaml> --runtime-pdp-mode=shadow` starts for a few seconds.
3. The log must show that the policy file was loaded as `RuntimePolicyPack`.
4. The Runtime PDP must compile the pack and log `pack loaded: 2 rules`.
5. The run must not log unsupported-kind, parse, compile, or panic errors.
6. Targeted Go contract tests then run for:
   - RuntimePolicyPack loader and signature verification
   - RuntimeDecision to ActionProposal mapping
   - broker lease renewal and source fencing
   - brokered relationship apply/revert receipts
   - signed RuntimeBundle conformance and offline last-known-good validation

Expected result:

- Standalone `--policy-file` accepts the contracts `RuntimePolicyPack` schema.
- RuntimePolicyPack rules can include an enforcement-feedback hold rule using `signals.enforcement_feedback_rate`.
- Runtime PDP shadow mode can load the policy without changing enforcement.
- The active-mode plumbing remains covered at the mapper/broker/conformance boundary.

## Cleanup

The runner automatically calls `cleanup_all` at the beginning and at the end. Manual cleanup:

```bash
make integration-clean
```

Cleanup removes:

- started KLIQ/Forge/test-server processes
- XDP links on the test veths
- `klt-*` network namespaces
- `br-klt` and test veths
- Kernloom BPF pins under `/sys/fs/bpf`
- runtime `state/` and `etc/` below the artifact directory

The cleanup logic only removes paths under the artifact directory or under `/tmp/kernloom-*`. Foreign state paths are rejected.

## CI

`ci.yml` runs quick checks:

- guard against tracked integration-test artifacts
- Go fmt
- `go test ./...`
- CLI builds
- BPF build
- smoke scenario 00

`integration.yml` is intended for self-hosted runners with XDP/netns and uploads artifacts from `/tmp/kernloom-integration-artifacts-<run-id>`.

`integration-forge.yml` runs on normal GitHub-hosted Ubuntu and checks scenarios 09, 10, and 12.

## Troubleshooting

`sudo: a terminal is required`

The full runner needs sudo. Locally, start `make integration` from a normal terminal so sudo can ask for a password. In CI, the runner must allow passwordless sudo for the required network operations.

`no nft/iptables found`

Scenario 11 skips if no Netfilter backend is installed. This is not an error for XDP scenarios.

`Graph edges (0 total)`

Graph relationships are learned in memory by KLIQ and are flushed to SQLite periodically or during shutdown. Scenario 04 stops KLIQ on purpose before the CLI read, so `kliq graph edges` sees the persisted state.

`trig_pps=81` in scenario 06

This is allowed if two bootstrap cycles ran: `100 -> 90 -> 81`. The test therefore checks the first `AUTOTUNE applied` step.

`trig_pps=0` in scenario 06

The test could not read a PPS threshold from `state.json`. Check whether the state file contains `active.tuning_scopes` with `network.packets_per_second`; current KLIQ no longer writes the old top-level `active.trig` mirror for new state files.

Artifacts in the repository

New artifacts should no longer be created in the repository by default. If they are, check the path:

```bash
source tests/integration/env.sh
echo "$KLT_ARTIFACT_DIR"
```

Generated files under `tests/integration/artifacts/` are ignored and must not be committed.
