# KLIQ Manual Test Guide

This guide shows a simple manual test path after the KLIQ move to a generic
runtime orchestrator.

This is a live test runbook, not the Natural Intent language reference. For
authoring vocabulary use
`../../../kernloom-forge/docs/natural-intent-vocabulary-cheat-sheet.md`; for
Forge-side example flows use `../../../kernloom-forge/docs/policy-intent-examples.md`.

Goal:

- Start `kliq run` without privileged adapters.
- Load a `RuntimePolicyPack` locally.
- Test KLShield and netfilter paths in dry-run first.
- Test Forge standalone packs and managed mode.
- Inspect source baselines, graph data, leases and receipts.

Current `v0.4.0` focus:

- Natural Intent is converted by Forge before KLIQ sees it.
- RuntimePDP can run in `shadow` or `active` mode.
- Active RuntimePDP emits brokered runtime actions.
- Runtime actions are TTL leased, fenced, receipted and auto-reverted.
- RuntimePolicyPack can carry hold rules, previous-action gates, confidence and
  freshness requirements, max-duration bounds and audit requirements.
- KLShield source rate limiting interprets `rate_pps` as an approximate pass
  budget. Drop counters show packets above that budget.
- Source baselines persist in SQLite when `iq-learning` or higher is enabled.
- Baseline output shows global and effective triggers.

**Requirements:**
- Go >= 1.23
- Linux
- Optional: root privileges for netfilter/KLShield
- Optional: `sqlite3`, `jq`, `curl`, `timeout`

---

## 1. Build And Test Baseline

```bash
cd /path/to/kernloom
mkdir -p bin

go build -o bin/kliq ./iq/cmd/kliq
go build -o bin/klshield ./shield/cmd/klshield

go test ./...
```

Expected: build succeeds and all tests pass.

If the Go cache is not writable in this environment:

```bash
GOCACHE=/tmp/kernloom-go-cache go test ./...
```

---

## 2. Start KLIQ Without An Adapter

This is the main smoke test for the generic orchestrator. It needs no eBPF, no
netfilter, and no root privileges.

```bash
cd /path/to/kernloom
mkdir -p /tmp/kernloom-manual

cat > /tmp/kernloom-manual/whitelist.txt <<'EOF'
# Generic subject ID
ziti.identity:alice

# IP/CIDR is still allowed as one match form for source filters.
127.0.0.1
10.0.0.0/24
EOF

cat > /tmp/kernloom-manual/feedback.json <<'EOF'
[
  {"target":"ziti.identity:alice","action":"forgive","ttl":"1h"},
  {"target":"127.0.0.1","action":"whitelist","ttl":"15m"}
]
EOF

timeout 12s ./bin/kliq run \
  --adapter=none \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state.json \
  --db=/tmp/kernloom-manual/kliq-state.db \
  --interval=2s
```

Expected:
- `kliq run` starts and runs until `timeout` stops it.
- Exit code `124` is normal when `timeout` stops the process.
- The log says that catalog adapter binding is skipped, RuntimePDP is in shadow
  mode, and KLIQ starts with `adapter_active=false`.
- Whitelist and feedback load generic subjects and IP/CIDR entries.

Important: `run` is required. `./bin/kliq --dry-run=true` is intentionally not
a valid start command anymore.

`--runtime-pdp-mode=shadow` and `--dry-run=true` are different:
- `shadow` means RuntimePDP evaluates and logs decisions, but does not emit an
  enforcement action to a PEP.
- `dry-run=true` means local enforcement effects are not written to PEPs such as
  KLShield or netfilter.

---

## 2.1 Load A RuntimePolicyPack With --policy-file

This test checks the new local contracts-based policy path. It needs no root
privileges and no adapter.

```bash
cd /path/to/kernloom
mkdir -p /tmp/kernloom-manual

cat > /tmp/kernloom-manual/runtime-policy.yaml <<'EOF'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: manual-runtime-policy
  issued_at: "2026-06-19T10:00:00Z"
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
  rules:
    - id: hold-enforcement-while-drops
      when: "fsm.current_level in ['soft', 'hard', 'block'] && signals.enforcement.active"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - rate_limit_drops_sustained
        - enforcement_hold
    - id: high-risk-rate-limit
      when: "risk.level in ['high', 'critical']"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - manual_runtime_policy
EOF

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file=/tmp/kernloom-manual/runtime-policy.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-runtime-policy.json \
  --db=/tmp/kernloom-manual/kliq-runtime-policy.db \
  --interval=2s
```

Expected:
- The log contains `Policy loaded: ... kind=RuntimePolicyPack`.
- The log contains `[runtime-pdp] pack loaded: 2 rules`.
- The log contains `RuntimePDP mode: SHADOW`.
- No messages like `unsupported kind`, `parse runtime pack`, or
  `compile error`.

Note: without adapter signals, there are usually no RuntimePDP decisions. This
test only checks load, validation, and compilation of the pack. Use
`--runtime-pdp-mode=active` only after the policy pack is correct and
`--dry-run=false` is really wanted.

`signals.enforcement.*` are generic RuntimePDP facts for active PEP feedback:
- `signals.enforcement.feedback_rate`: generic feedback rate.
- `signals.enforcement.drop_rate`: drop rate; for KLShield this is currently
  `network.rate_limit_drop_rate`.
- `signals.enforcement.deny_rate`: deny/reject rate, currently `0` until an
  adapter provides it.
- `signals.enforcement.throttle_rate`: throttle/backpressure rate, currently
  `0` until an adapter provides it.
- `signals.enforcement.active`: `true` when one of these rates is greater than
  `0`.

`signals.enforcement_feedback_rate` remains usable as an old alias for
`signals.enforcement.feedback_rate`.

---

## 3. Check The State Store

```bash
cd /path/to/kernloom

./bin/kliq storage status --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq relationships stats --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq relationships list --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq baselines list --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq status \
  --state-file=/tmp/kernloom-manual/state.json \
  --db=/tmp/kernloom-manual/kliq-state.db
```

Expected:
- `storage status` opens the SQLite DB and shows tables such as `entities`,
  `relationships`, `metric_baselines`, `signals`, `decisions`.
- Without adapter telemetry, relationships and baselines will probably be empty.
  That is correct for this smoke test.

---

## 4. Netfilter Dry-Run

Netfilter is an enforcement adapter. It does not provide primary telemetry.

```bash
cd /path/to/kernloom

timeout 15s sudo ./bin/kliq run \
  --adapter=netfilter \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-netfilter.json \
  --db=/tmp/kernloom-manual/kliq-netfilter.db \
  --interval=2s
```

Expected:
- If `nft` or `iptables` is available, the log says `Netfilter adapter active`.
- If no backend is available, KLIQ logs a warning but does not crash.
- Do not expect graph telemetry from netfilter; conntrack is only an optional
  topology fallback.

---

## 5. KLShield Runtime-Smoke

This test uses the default adapter, `klshield`. It only makes sense when the
KLShield/eBPF maps exist, or when you intentionally test the environment in
dry-run mode.

```bash
cd /path/to/kernloom

timeout 20s sudo ./bin/kliq run \
  --adapter=klshield \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-klshield.json \
  --db=/tmp/kernloom-manual/kliq-klshield.db \
  --interval=2s
```

Expected:
- With available maps, the KLShield runtime adapter starts.
- Without maps, an adapter warning is acceptable; the process must not panic.
- KLShield-specific metrics stay in `pkg/adapters/klshield/...`; KLIQ only
  processes generic `SourceObservation` values.

### 5.1 KLShield + Netfilter On The Same KLIQ/PDP

Multiple adapters are passed as a comma-separated list. The first available
source PEP owns the local FSM state. Other source PEPs mirror authorized
transitions as sidecars. Relationship PEPs are collected, so tuple or
relationship enforcement can use all available matching adapters.

```bash
cd /path/to/kernloom

timeout 20s sudo ./bin/kliq run \
  --adapter=klshield,netfilter \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-multi-adapter.json \
  --db=/tmp/kernloom-manual/kliq-multi-adapter.db \
  --interval=2s
```

Expected:
- KLIQ logs the requested adapters and the active inventory/PEP bindings.
- If Netfilter is available, the log says `Netfilter adapter active`.
- RuntimePDP remains one local PDP; adapters do not make their own policy
  decisions.
- If KLShield maps are missing, Netfilter may still start as a sidecar.

### 5.2 Remote k6: Stepwise Escalation And De-Escalation

This test uses two machines:
- Target host: the service, KLShield, and KLIQ run here.
- Load generator: another machine in the same network running `k6`.

Goal: prove that KLIQ sees the remote source, then escalates step by step from
`OBSERVE -> RATE_SOFT -> RATE_HARD -> BLOCK`, and de-escalates back to
`OBSERVE` after the load stops.

Important:
- Run this only in a lab network.
- If NAT, VPN, WSL, a load balancer, or a gateway is in the path, KLIQ may see
  the gateway/NAT IP instead of the real k6 IP.
- For a BLOCK test, set `--bootstrap=false`. Active bootstrap intentionally caps
  BLOCK at `RATE_HARD`.
- Do not use a policy pack with `max_action=rate_limit` for this test, because
  that intentionally forbids BLOCK.

Prepare the target host:

```bash
cd /path/to/kernloom
mkdir -p /tmp/kernloom-manual

# Choose the interface that receives packets from the k6 machine.
ip -br addr
export IFACE=eth0

# Start a test service if you do not use your own service.
python3 -m http.server 8000 --bind 0.0.0.0
```

In a second terminal on the target host:

```bash
cd /path/to/kernloom

sudo ./bin/klshield attach-xdp \
  --iface "$IFACE" \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o

# Optional: remove old test entries from the KLShield maps.
sudo ./bin/klshield reset || true

cat > /tmp/kernloom-manual/whitelist-empty.txt <<'EOF'
# Keep this empty. The k6 source must NOT be whitelisted for this test.
EOF

printf '[]\n' > /tmp/kernloom-manual/feedback-empty.json

cat > /tmp/kernloom-manual/k6-runtime-policy.yaml <<'EOF'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: manual-k6-runtime-policy
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
    - enforce.access.deny
  rules:
    - id: fsm-intent-block
      when: "fsm.proposed_level == 'block'"
      then:
        capability: enforce.access.deny
        level: block
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_block
    - id: hold-enforcement-while-drops
      when: "fsm.current_level in ['soft', 'hard', 'block'] && signals.enforcement.active"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
      reason_codes:
        - rate_limit_drops_sustained
        - enforcement_hold
    - id: fsm-intent-hard
      when: "fsm.proposed_level == 'hard'"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_hard
    - id: fsm-intent-soft
      when: "fsm.proposed_level == 'soft'"
      then:
        capability: enforce.traffic.rate_limit
        level: soft
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_soft
    - id: fsm-intent-observe
      when: "fsm.proposed_level == 'observe' && fsm.current_level != 'observe'"
      then:
        level: observe
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_observe
EOF
```

Start KLIQ in dry-run first:

```bash
cd /path/to/kernloom

sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-manual/k6-runtime-policy.yaml \
  --feature-profile=dos-light \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --bootstrap=false \
  --autotune=false \
  --min-pps=1 \
  --trig-pps=20 \
  --trig-syn=20 \
  --trig-scan=5 \
  --trig-bps=0 \
  --sev-delta1=1 \
  --sev-delta2=1 \
  --sev-delta3=1 \
  --soft-at=2 \
  --hard-at=7 \
  --block-at=12 \
  --up-need=1 \
  --down-need=2 \
  --soft-ttl=10s \
  --hard-ttl=10s \
  --block-ttl=10s \
  --min-hold-soft=0s \
  --min-hold-hard=0s \
  --block-min-sev=0 \
  --block-min-dur=0s \
  --soft-rate-factor=0.5 \
  --hard-rate-factor=0.1 \
  --whitelist=/tmp/kernloom-manual/whitelist-empty.txt \
  --feedback-file=/tmp/kernloom-manual/feedback-empty.json \
  --state-file=/tmp/kernloom-manual/state-k6-dryrun.json \
  --db=/tmp/kernloom-manual/kliq-k6-dryrun.db \
  --interval=1s \
  2>&1 | tee /tmp/kernloom-manual/kliq-k6-dryrun.log
```

On the k6 machine:

```bash
cat > stresstest-k6.js <<'EOF'
import http from 'k6/http';

export const options = {
  stages: [
    { duration: '10s', target: 50 },
    { duration: '25s', target: 200 },
    { duration: '20s', target: 200 },
    { duration: '15s', target: 0 },
  ],
};

export default function () {
  http.get(__ENV.TARGET, { timeout: '2s' });
}
EOF

TARGET=http://TARGET_HOST_IP:8000 k6 run stresstest-k6.js
```

Dry-run check on the target host:

```bash
grep -E 'STATE|ACTION-RECEIPT|TICK#|top:' /tmp/kernloom-manual/kliq-k6-dryrun.log
```

Expected:
- The source in `top:` or `STATE` is the IP of the k6 machine. If it is the
  gateway IP, NAT is in the path.
- The log shows at least these transitions:
  - `STATE <k6-ip> OBSERVE->RATE_SOFT`
  - `STATE <k6-ip> RATE_SOFT->RATE_HARD`
  - optional `STATE <k6-ip> RATE_HARD->BLOCK`
- In dry-run there are no real drops. `runtime-pdp-mode=active` plus
  `dry_run=true` checks detection, RuntimePolicyPack, broker/receipt flow, and
  logging without PEP effects.

Real enforcement variant:

1. Stop KLIQ with `Ctrl-C`.
2. Reset the KLShield maps.
3. Start KLIQ with the same flags, but with `--dry-run=false`.
4. Run k6 again.

```bash
sudo ./bin/klshield reset || true

sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-manual/k6-runtime-policy.yaml \
  --feature-profile=dos-light \
  --runtime-pdp-mode=active \
  --dry-run=false \
  --bootstrap=false \
  --autotune=false \
  --min-pps=1 \
  --trig-pps=20 \
  --trig-syn=20 \
  --trig-scan=5 \
  --trig-bps=0 \
  --sev-delta1=1 \
  --sev-delta2=1 \
  --sev-delta3=1 \
  --soft-at=2 \
  --hard-at=7 \
  --block-at=12 \
  --up-need=1 \
  --down-need=2 \
  --soft-ttl=10s \
  --hard-ttl=10s \
  --block-ttl=10s \
  --min-hold-soft=0s \
  --min-hold-hard=0s \
  --block-min-sev=0 \
  --block-min-dur=0s \
  --soft-rate-factor=0.5 \
  --hard-rate-factor=0.1 \
  --whitelist=/tmp/kernloom-manual/whitelist-empty.txt \
  --feedback-file=/tmp/kernloom-manual/feedback-empty.json \
  --state-file=/tmp/kernloom-manual/state-k6-enforce.json \
  --db=/tmp/kernloom-manual/kliq-k6-enforce.db \
  --interval=1s \
  2>&1 | tee /tmp/kernloom-manual/kliq-k6-enforce.log
```

While k6 is running:

```bash
grep -E 'STATE|ACTION-RECEIPT|TICK#|top:' /tmp/kernloom-manual/kliq-k6-enforce.log
sudo ./bin/klshield stats
sudo ./bin/klshield list-rl
sudo ./bin/klshield top-src -n 5 -by droprl
```

Expected:
- `STATE <k6-ip> OBSERVE->RATE_SOFT`
- `STATE <k6-ip> RATE_SOFT->RATE_HARD`
- `STATE <k6-ip> RATE_HARD->BLOCK`, or at least `RATE_HARD` if the test is too
  short or the load is too low.
- `ACTION-RECEIPT` for apply actions.
- `klshield stats` shows increasing `drop_rl` or `drop_deny`.

Rate-limit interpretation:
- `rate=100` or `rate_pps=100` means roughly 100 packets per second are allowed
  for that source, with a configured burst. It does not mean 100 packets per
  second are dropped.
- `drop_rl_rate` is the current packet drop rate above the pass budget. If the
  incoming source rate is near 180 pps, a low drop rate such as 70-90 pps is
  normal. If the incoming source rate is near 2,000 pps, the drop rate should be
  roughly 1,900 pps once the limiter is active.
- In SYN-heavy k6 tests, `syn_rate - drop_rl_rate` is a useful quick estimate of
  effective pass-through. It should sit near the configured hard budget once the
  source rate is clearly above that budget.
- A low `drop_rl_rate` is only suspicious when `list-rl` shows the override is
  active and KLIQ or adapter telemetry also shows sustained pass-through far
  above the configured budget.

Test de-escalation:

1. Let k6 finish or stop it with `Ctrl-C`.
2. Keep KLIQ running.
3. Wait 45-60 seconds. With `soft/hard/block-ttl=10s`, `down-need=2`, and the
   KLShield 5s cooldown, the reverse chain is stepwise, not instant.

```bash
grep -E 'STATE .*->(RATE_HARD|RATE_SOFT|OBSERVE)|TICK#' \
  /tmp/kernloom-manual/kliq-k6-enforce.log
```

Expected:
- After the load ends, reverse transitions appear, for example:
  - `STATE <k6-ip> BLOCK->RATE_HARD`
  - `STATE <k6-ip> RATE_HARD->RATE_SOFT`
  - `STATE <k6-ip> RATE_SOFT->OBSERVE`
- Later ticks show `fsm{soft=0 hard=0 block=0}`.
- A normal request from the k6 machine works again:

```bash
curl -fsS http://TARGET_HOST_IP:8000 >/dev/null && echo recovered
```

If no escalation is visible:
- Check whether `klshield stats` counts any `pkts`/`pass`.
- Check whether KLIQ sees the k6 IP or only a NAT/gateway IP.
- Lower `--trig-pps`, for example to `5`.
- Make sure the k6 IP is not in the whitelist or feedback file.
- Make sure `--bootstrap=false` is set if BLOCK is expected.
- If BLOCK happens too fast to see the intermediate states, increase
  `--hard-at` and `--block-at`, or reduce the k6 load.

---

## 6. Graph And Baselines

Graph learning needs a telemetry source. With `--adapter=none`, stores stay
empty, but the CLI paths must still work.

```bash
cd /path/to/kernloom

timeout 20s sudo ./bin/kliq run \
  --adapter=klshield \
  --dry-run=true \
  --feature-profile=graph-learning \
  --graph=true \
  --runtime-pdp-mode=shadow \
  --state-file=/tmp/kernloom-manual/state-graph.json \
  --db=/tmp/kernloom-manual/kliq-graph.db \
  --interval=2s

./bin/kliq relationships stats --db=/tmp/kernloom-manual/kliq-graph.db
./bin/kliq relationships list --db=/tmp/kernloom-manual/kliq-graph.db
./bin/kliq baselines list \
  --db=/tmp/kernloom-manual/kliq-graph.db \
  --scope=relationship
```

Expected:
- `storage status --db=/tmp/kernloom-manual/kliq-graph.db` shows rows in
  `entities`, `relationships`, and `metric_baselines`.
- `baselines list` shows one row per learned metric and subject.
- `BASELINE` is the EWMA normal value.
- `PEAK` is the learned peak. `-` means not set yet.
- `GTRIG` is the global trigger. `-` means disabled or not set.
- `ETRIG` is the effective trigger after source-baseline adjustment. `-` means
  disabled or not set.
- `CONF` is baseline confidence from `0` to `1`.
- `OBS` is the observation count.
- `ETRIG` is never lower than `GTRIG`. Source baselines only raise triggers
  for learned high-traffic sources; they do not weaken global guardrails.
- `--scope=relationship` filters baselines bound to a learned relationship, for
  example a network edge such as "source IP connects_to target tuple". Other
  scopes can be entity- or subject-based baselines.

New generic graph signals that may appear in logs or stores:
- `graph.new_relationship_dim`
- `graph.edge_metric_deviation`
- `graph.edge_metric_peak_exceeds`

Old signal names such as `graph.edge_baseline_pps_deviation` should not appear
in new code or new data.

---

## 7. Forge -> KLIQ: Standalone-Pack und Managed Mode

This section is the new end-to-end path:

1. An operator writes Natural Intent.
2. Forge converts it into canonical documents plus a thin `PolicyIntent`
   manifest.
3. Forge builds a `RuntimePolicyPack` from that generated `PolicyIntent`.
4. KLIQ loads that pack in standalone mode with `--policy-file`.
5. Forge signs the same intent as a `RuntimeBundle`.
6. KLIQ pulls the bundle in managed mode from `forge serve`.

KLIQ does not load natural intent text directly. It only sees the converted
runtime artifact: `RuntimePolicyPack` in standalone mode or signed
`RuntimeBundle` in managed mode.

The longer Forge-side guide is in
`kernloom-forge/docs/policy-intent-examples.md`.

### 7.1 Binaries And Work Directory

```bash
mkdir -p /tmp/kernloom-manual/forge/policies /tmp/kernloom-manual/forge/out

cd /path/to/kernloom
mkdir -p bin
go build -o bin/kliq ./iq/cmd/kliq

cd /path/to/kernloom-forge
mkdir -p bin
go build -o bin/forge ./cmd/forge
```

### 7.2 Write A Simple Policy Intent

Rich Natural Intent smoke test with detection, response and guardrail output:

```bash
cd /path/to/kernloom-forge

cat > /tmp/kernloom-manual/forge/policies/protect-ziti-controller.intent <<'EOF'
intent "protect-ziti-controller-admin-access"

protect "ziti-controller" in "production" as "critical admin interface"

compose:
  access "ziti-controller-admin-access"
  requirements "low-risk-strong-auth"
  detection "ziti-controller-denied-access"
  response "ziti-controller-deny-escalation"
  alert_route "security-ops"
  guardrail "never-autoblock-kernloom-admins"
  capabilities "ziti-controller-admin-protection"

access "ziti-controller-admin-access":
  default deny access to "ziti-controller"
  allow group "kernloom-admins" to access "ziti-controller"

requirements "low-risk-strong-auth":
  require "subject.risk.level" eq "low"
  require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]

detection "ziti-controller-denied-access":
  detect "admin-deny":
    when denied access to "ziti-controller" by group "kernloom-admins" exceeds 3 within 15m

  detect "unknown-source-heavy-deny":
    when denied access to "ziti-controller" by unknown source exceeds 20 within 15m

response "ziti-controller-deny-escalation":
  on "admin-deny" then alert route "security-ops" severity "medium" dedupe 15m
  on "unknown-source-heavy-deny" then rate_limit source for 15m

alert_route "security-ops":
  notify group "kernloom-security-ops"
  via ["log", "email"]
  dedupe by ["tenant.id", "resource.id", "detection.id", "source.identity_or_ip"]
  create case false

guardrail "never-autoblock-kernloom-admins":
  never auto_block group "kernloom-admins"
  never quarantine group "kernloom-admins"
  never disable identity group "kernloom-admins"

capabilities "ziti-controller-admin-protection":
  require context "subject.risk.level"
  require context "session.authentication.strength"
  require windowed_detection
  require traffic_rate_limit

gap_handling:
  fail on missing_context
  require_approval on identity_to_ip downgrade
EOF

./bin/forge intent convert \
  --input /tmp/kernloom-manual/forge/policies/protect-ziti-controller.intent \
  --output-dir /tmp/kernloom-manual/forge/policies/protect-ziti-controller \
  --emit-policy-intent \
  --owner security \
  --compile-target klshield-local

./bin/forge validate \
  --policy /tmp/kernloom-manual/forge/policies/protect-ziti-controller/access.yaml

./bin/forge intent validate \
  --input /tmp/kernloom-manual/forge/policies/protect-ziti-controller/policy-intent.yaml
```

Expected:
- `forge intent convert` writes `access.yaml`, `guardrails.yaml`,
  `requirements.yaml`, `detections.yaml`, `responses.yaml`,
  `security-ops-alert-route.yaml`, `capabilities.yaml`, and
  `policy-intent.yaml`.
- `policy-intent.yaml` is a small manifest with file refs and `sha256:` digests.
- `requirements ...` writes a `RequirementPolicy` YAML file referenced by the
  generated `PolicyIntent`.
- `never ...` writes a `GuardrailPolicy` YAML file.
- `detect ... when ...` writes a `DetectionPolicy` YAML file.
- `on ... then alert route ...` writes a `ResponsePolicy` and generated `AlertRoute`.
  The response references the detection ID and the alert route ID.
- `capabilities ...` and `gap_handling ...` write a `CapabilityRequirement`
  document and add it to the generated `PolicyIntent`.
- Warnings for `default deny` are normal for now. It will later map to target
  defaults or runtime default behavior.
- `alert` is a routed notification action, not a signal alias. Runtime
  enforcement aliases such as `rate_limit`,
  `deny`, `drop`, and `quarantine` are defined by the registries and must obey
  the target's allowed action level.
- `forge validate` prints
  `OK: AccessPolicy "protect-ziti-controller-admin-access" is valid`.
- The command prints `OK: PolicyIntent ... is valid`.
- Forge checks that response rules reference existing detection IDs.
- Forge checks that alert actions reference existing alert routes.
- Forge checks that enforcing response actions are registry-known and TTL-bound.

The next small intent says: for a local KLShield node, risk must be `low` and device
posture must be `healthy`. Both are canonical registry keys.

```bash
cd /path/to/kernloom-forge

cat > /tmp/kernloom-manual/forge/policies/manual-edge-access.intent <<'EOF'
intent "manual-edge-access"

protect service "public-edge" in "production" as "public edge service"

compose:
  access "manual-edge-access"
  requirements "manual-edge-context"
  detection "manual-edge-runtime-detections"
  response "manual-edge-runtime-responses"
  alert_route "security-ops"
  guardrail "never-autoblock-kernloom-admins"
  capabilities "manual-edge-runtime-capabilities"

access "manual-edge-access":
  allow all

requirements "manual-edge-context":
  require "subject.risk.level" eq "low"
  require "device.posture.status" eq "healthy"

detection "manual-edge-runtime-detections":
  detect "risk-elevated":
    when risk at least medium

  detect "risk-high":
    when risk at least high

  detect "unknown-source-deny":
    when denied access to "public-edge" by unknown source exceeds 5 within 15m

  detect "sustained-pressure":
    when rate_limit drops to "public-edge" by unknown source sustained for 5m

response "manual-edge-runtime-responses":
  on "risk-elevated" then rate_limit source for 15m
  on "risk-high" then alert route "security-ops" severity "high" dedupe 1m
  on "sustained-pressure" then temporary_block source for 10m
    require previous action "enforce.traffic.rate_limit" active
    allow local enforcement state evidence
    require enforcement target excludes group "kernloom-admins"

alert_route "security-ops":
  notify group "kernloom-security-ops"
  via ["log", "email"]
  dedupe by ["tenant.id", "resource.id", "detection.id", "source.identity_or_ip"]
  create case false

guardrail "never-autoblock-kernloom-admins":
  never auto_block group "kernloom-admins"
  never quarantine group "kernloom-admins"
  never disable identity group "kernloom-admins"

capabilities "manual-edge-runtime-capabilities":
  require context "subject.risk.level"
  require context "device.posture.status"
  require windowed_detection
  require traffic_rate_limit
  require temporary_traffic_block

gap_handling:
  fail on missing_context
  require_approval on identity_to_ip downgrade
EOF

./bin/forge intent convert \
  --input /tmp/kernloom-manual/forge/policies/manual-edge-access.intent \
  --output-dir /tmp/kernloom-manual/forge/policies/manual-edge-access \
  --emit-policy-intent \
  --name manual-edge-access \
  --owner lab-operator
```

### 7.3 Check With Forge And Export A RuntimePolicyPack

The normal Forge input is the generated `PolicyIntent`. The older `--policy`,
`--guardrail`, `--detection`, `--response`, and `--alert-route` flags are useful
for fixture-level debugging, but should not be the first manual workflow.
For source-only adapters, a group guardrail can reject hard actions when the
subject is unknown. That is safe, but it can also prevent source blocks until
identity context is available.

```bash
./bin/forge validate \
  --policy /tmp/kernloom-manual/forge/policies/manual-edge-access/access.yaml

./bin/forge intent validate \
  --input /tmp/kernloom-manual/forge/policies/manual-edge-access/policy-intent.yaml

./bin/forge intent support \
  --input /tmp/kernloom-manual/forge/policies/manual-edge-access.intent \
  --target klshield-local \
  --output /tmp/kernloom-manual/forge/out/manual-edge-support.yaml

./bin/forge compile \
  --intent /tmp/kernloom-manual/forge/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output summary

./bin/forge report \
  --intent /tmp/kernloom-manual/forge/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output /tmp/kernloom-manual/forge/out/manual-edge-report.yaml

./bin/forge export-runtime-policy \
  --intent /tmp/kernloom-manual/forge/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --ttl 30s \
  --output /tmp/kernloom-manual/forge/out/manual-edge-runtime-pack.yaml
```

Optional guarded and routed response pack from the generated natural intent:

```bash
./bin/forge export-runtime-policy \
  --intent /tmp/kernloom-manual/forge/policies/protect-ziti-controller/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --ttl 30s \
  --output /tmp/kernloom-manual/forge/out/protect-ziti-controller-runtime-pack.yaml
```

Expected:
- `compile --output summary` shows `manual-edge-access -> klshield-local`.
- The report shows `risk_level` and `device_posture` as
  `compensating_control`.
- The report includes `runtimeNotes` for context-sensitive controls, so missing
  or unknown evidence is visible before you load the pack.
- The exported pack is `kind: RuntimePolicyPack`.
- If the generated `PolicyIntent` references guardrails, detections, responses
  or alert routes, the exported pack contains `spec.guardrails`,
  `spec.detection_rules`, `spec.response_rules` and `spec.alert_routes`.
- The generated `PolicyIntent` references the `CapabilityRequirement`
  document. Forge validation sees the required context, reaction capabilities
  and gap handling policy before deployment.
- `manual-edge-support.yaml` is a `NaturalIntentSupportReport` with
  `enforced`, `carried`, and `warnings` counters for policy writers.
- KLIQ evaluates `spec.detection_rules` with local window counters when matching
  source facts are present.
- KLIQ evaluates `spec.response_rules` after a detection fires.
- Technical response actions such as `enforce.traffic.rate_limit` only mutate a
  PEP in `--runtime-pdp-mode=active`.
- `notify.alert.emit` logs a routed reaction event and stores a
  `reaction.alert` signal in the state DB. Real log and SMTP-backed email delivery
  belongs behind the AlertRoute notification backend.

Quick check:

```bash
grep -E 'kind: RuntimePolicyPack|capabilities_required:|guardrails:|detection_rules:|response_rules:|alert_routes:|when:|capability:|level:' \
  /tmp/kernloom-manual/forge/out/manual-edge-runtime-pack.yaml
```

Expected in the pack:
- `capability: enforce.traffic.rate_limit`
- `capability: enforce.traffic.drop`
- a rule for `risk.level in ['medium', 'high', 'critical']`
- a rule for `device.posture.status in ['degraded', 'unhealthy']`
- response rules for `risk-elevated`, `risk-high`, and `sustained-pressure`
- previous-action params such as `previous_action_id`

Missing or unknown context should be visible in the Forge report, not silently
compiled into a hard block. For example, a KLShield-only test target that cannot
prove device posture must not keep renewing a block just because posture is
`unknown`.

Important: `forge compile --output yaml` creates an `EnforcementPlan`. That is
a report. KLIQ standalone loads the file from `export-runtime-policy`.

### 7.4 Standalone KLIQ With The Forge Pack

This test needs no adapter, no eBPF, and no root privileges. It checks loading,
validation, and RuntimePDP compilation of the pack created by Forge.

```bash
cd /path/to/kernloom

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file=/tmp/kernloom-manual/forge/out/manual-edge-runtime-pack.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-manual/state-forge-standalone.json \
  --db=/tmp/kernloom-manual/kliq-forge-standalone.db \
  --interval=2s
```

Expected:
- `Policy loaded: ... kind=RuntimePolicyPack`
- `[runtime-pdp] pack loaded: 3 rules`
- `RuntimePDP mode: SHADOW`
- no `unsupported kind`, parse, or compile errors.

### 7.4.1 Replay The Scenario-12 Productive Intent

This is the exact manual path for
`tests/integration/fixtures/policies/klshield-edge-autonomy-hold.intent`.
It starts from Natural Intent, writes a support report, exports a KLShield
`RuntimePolicyPack`, and loads that pack in standalone KLIQ.

```bash
export KL_ROOT=/path/to/kernloom
export FORGE_ROOT=/path/to/kernloom-forge
export WORK=/tmp/kernloom-manual/edge-autonomy-hold

mkdir -p "$WORK/policies" "$WORK/out"

cd "$KL_ROOT"
GOCACHE=/tmp/kernloom-go-build go build -o bin/kliq ./iq/cmd/kliq
GOCACHE=/tmp/kernloom-go-build go build -o bin/klshield ./shield/cmd/klshield

cd "$FORGE_ROOT"
GOCACHE=/tmp/kernloom-forge-go-build go build -o "$KL_ROOT/bin/forge" ./cmd/forge

cd "$KL_ROOT"
./bin/forge intent convert \
  --input "$KL_ROOT/tests/integration/fixtures/policies/klshield-edge-autonomy-hold.intent" \
  --output-dir "$WORK/policies" \
  --emit-policy-intent \
  --compile-target klshield-local \
  --show-notes \
  2>&1 | tee "$WORK/out/convert.log"

./bin/forge intent support \
  --input "$KL_ROOT/tests/integration/fixtures/policies/klshield-edge-autonomy-hold.intent" \
  --target klshield-local \
  --output "$WORK/out/intent-support.yaml"

./bin/forge export-runtime-policy \
  --intent "$WORK/policies/policy-intent.yaml" \
  --adapters "$FORGE_ROOT/examples/adapters" \
  --profiles "$FORGE_ROOT/examples/profiles" \
  --target klshield-local \
  --ttl 1m \
  --output "$WORK/out/klshield-edge-runtime-policy.yaml" \
  2>&1 | tee "$WORK/out/export.log"

grep -E 'kind: RuntimePolicyPack|autonomy_lifecycle:|capability:|previous_action_id|risk\.confidence|risk\.age_seconds|risk\.independent_signal_count|requires_audit|rate_pps' \
  "$WORK/out/klshield-edge-runtime-policy.yaml"

: > "$WORK/out/whitelist.txt"
printf '[]\n' > "$WORK/out/feedback.json"

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file="$WORK/out/klshield-edge-runtime-policy.yaml" \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --whitelist="$WORK/out/whitelist.txt" \
  --feedback-file="$WORK/out/feedback.json" \
  --state-file="$WORK/out/state-shadow.json" \
  --db="$WORK/out/kliq-shadow.db" \
  --interval=1s \
  2>&1 | tee "$WORK/out/kliq-shadow.log"
```

Expected:
- `intent-support.yaml` has `kind: NaturalIntentSupportReport`.
- The support report has enforced autonomy hold, max duration, audit receipt,
  previous-action, risk-confidence, risk-freshness, and independent-signal
  diagnostics.
- The support report should show `warnings: 0` for this fixture.
- `klshield-edge-runtime-policy.yaml` has `kind: RuntimePolicyPack` and
  `name: klshield-edge-autonomy-hold-intent-klshield-local`.
- KLIQ logs `Policy loaded: ... kind=RuntimePolicyPack`.
- KLIQ logs `[runtime-pdp] pack loaded: 4 rules`.
- KLIQ logs `RuntimePDP mode: SHADOW`.

For live KLShield observation, attach XDP and run active mode in dry-run first:

```bash
export IFACE=<your-test-interface>

sudo "$KL_ROOT/bin/klshield" attach-xdp \
  --iface "$IFACE" \
  --obj "$KL_ROOT/shield/bpf/out/xdp_kernloom_shield.bpf.o" \
  --force

sudo "$KL_ROOT/bin/kliq" run \
  --adapter=klshield \
  --policy-file="$WORK/out/klshield-edge-runtime-policy.yaml" \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --whitelist="$WORK/out/whitelist.txt" \
  --feedback-file="$WORK/out/feedback.json" \
  --state-file="$WORK/out/state-klshield-dryrun.json" \
  --db="$WORK/out/kliq-klshield-dryrun.db" \
  --interval=1s \
  --min-pps=1 \
  --trig-pps=5 \
  --trig-syn=5 \
  --trig-scan=3 \
  2>&1 | tee "$WORK/out/kliq-klshield-dryrun.log"
```

Expected while traffic crosses `$IFACE`:
- `RuntimePDP mode: ACTIVE`
- `[runtime-pdp:active] DECISION ...`
- `ACTION-RESOLVER runtime-pdp ...`
- `ACTION-RECEIPT ...`

Set `--dry-run=false` only after the dry-run shows the expected source and
action. Then inspect the PEP side with:

```bash
sudo "$KL_ROOT/bin/klshield" status
sudo "$KL_ROOT/bin/klshield" list-rl
sudo "$KL_ROOT/bin/klshield" list-deny
```

Optional KLShield dry-run:

```bash
sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-manual/forge/out/manual-edge-runtime-pack.yaml \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --feature-profile=iq-learning \
  --bootstrap=false \
  --autotune=false \
  --whitelist-learn=true \
  --state-file=/tmp/kernloom-manual/state-forge-klshield.json \
  --db=/tmp/kernloom-manual/kliq-forge-klshield.db \
  --interval=1s
```

Expected: RuntimePDP is active, but `--dry-run=true` prevents real PEP writes.
Use `--dry-run=false` only after a successful dry-run.

To test persisted source baselines, let KLIQ observe traffic for at least one
flush window or stop it cleanly, then inspect the source scope:

```bash
./bin/kliq storage status --db=/tmp/kernloom-manual/kliq-forge-klshield.db
./bin/kliq baselines list \
  --db=/tmp/kernloom-manual/kliq-forge-klshield.db \
  --scope=source
```

Expected: `metric_baselines` contains source-scoped rows for observed KLShield
metrics such as `network.packets_per_second`, `network.bytes_per_second`,
`network.syn_rate`, and `network.scan_rate`. `GTRIG` and `ETRIG` show the
global and effective trigger. `-` means disabled or unset, not "trigger at
zero".

### 7.5 Managed Mode With A Signed RuntimeBundle

Managed mode is more than "KLIQ can reach Forge". The important test is: KLIQ
gets a signed `RuntimeBundle`, verifies it with `--policy-verify-key`, and
activates the embedded registry snapshot plus `RuntimePolicyPack`.

Build keys and a bundle:

Use `--intent .../policy-intent.yaml` on `build-runtime-bundle` and `serve`.
The manifest carries the generated canonical documents and their digests.

```bash
cd /path/to/kernloom-forge

./bin/forge keygen \
  --private /tmp/kernloom-manual/forge/out/forge-runtime.key \
  --public /tmp/kernloom-manual/forge/out/forge-runtime.pub

./bin/forge build-runtime-bundle \
  --intent /tmp/kernloom-manual/forge/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --node-id node-manual-1 \
  --generation 1 \
  --runtime-pdp-mode shadow \
  --failover fail_static \
  --signing-key /tmp/kernloom-manual/forge/out/forge-runtime.key \
  --output /tmp/kernloom-manual/forge/out/manual-edge-runtime-bundle.yaml
```

Check the bundle:

```bash
grep -E 'kind: RuntimeBundle|registry_snapshot:|runtime_policy_pack:|signature:' \
  /tmp/kernloom-manual/forge/out/manual-edge-runtime-bundle.yaml
```

Pre-register the KLIQ node and copy the printed `enroll_token`:

```bash
./bin/forge enroll-token create \
  --store /tmp/kernloom-manual/forge/out/enroll-tokens.yaml \
  --node-id node-manual-1 \
  --ttl 24h
```

In a second terminal, start Forge as the control plane:

```bash
cd /path/to/kernloom-forge

./bin/forge serve \
  --addr :18443 \
  --intent /tmp/kernloom-manual/forge/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --signing-key /tmp/kernloom-manual/forge/out/forge-runtime.key \
  --enroll-token-store /tmp/kernloom-manual/forge/out/enroll-tokens.yaml \
  --generation 1 \
  --runtime-pdp-mode shadow \
  --failover fail_static
```

Because this `PolicyIntent` has no fixed compile target and `forge serve` has no
`--target`, Forge auto-places the bundle from the enrolled node's reported
adapter and effective capabilities. Use `--target` only for a forced single
target, or `--assignments` when you want explicit node selectors. Assignment
selectors can also match inventory labels reported by KLIQ with
`--node-labels`.

Health check:

```bash
curl -fsS http://localhost:18443/healthz
```

Start KLIQ in managed mode. Replace `PASTE_ENROLL_TOKEN_HERE` with the token
printed by `forge enroll-token create`:

```bash
cd /path/to/kernloom

timeout 30s ./bin/kliq run \
  --adapter=none \
  --graph-node-id=node-manual-1 \
  --mode=managed \
  --forge-url=http://localhost:18443 \
  --forge-enroll-token=PASTE_ENROLL_TOKEN_HERE \
  --node-labels=role=edge-gateway,env=production,service=public-edge \
  --policy-verify-key=/tmp/kernloom-manual/forge/out/forge-runtime.pub \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-manual/state-managed.json \
  --db=/tmp/kernloom-manual/kliq-managed.db \
  --interval=2s
```

Expected:
- Forge logs enrollment, heartbeat, and bundle requests.
- KLIQ logs that it applied a RuntimeBundle.
- KLIQ rejects bundles without a valid signature or without a registry snapshot.
- `managed/current-bundle.yaml` is written next to the state file.

Note: the Forge API server is still an MVP. Enrollment tokens and session tokens
are stored in memory while the server runs, but the enrollment token store keeps
used/unused token state on disk.

---

## 8. Integration Test Scripts

The integration scripts can check the manual steps above.

No-XDP/no-root path for RuntimePolicyPack:

```bash
cd /path/to/kernloom
KLT_SCENARIOS=12 bash tests/integration/run-forge.sh
```

Expected:
- `bin/kliq` is built when needed.
- Scenario `12_runtime_policy_pack.sh` starts `kliq run --adapter=none` with
  `kind: RuntimePolicyPack`.
- Then focused contract tests run for loader, signature checks,
  `RuntimeDecision -> ActionProposal`, broker revert, and RuntimeBundle
  conformance.

No-XDP control-plane group:

```bash
make integration-forge
```

By default this runs scenarios 09, 10, and 12. Forge is built when one of those
scenarios needs it. Scenario 12 needs the Forge CLI, but not a Forge server,
`curl`, or `jq`.

Full XDP/netns run:

```bash
make integration
```

Note: the full run needs sudo, a Linux environment with XDP/netns support, and
optional netfilter tools for scenario 11. Artifacts are written under
`/tmp/kernloom-integration-artifacts-<uid>/<run-id>/`, not into the repository.

---

## 9. OpenZiti Decoder/Mapping Tests

These tests do not need a controller:

```bash
cd /path/to/kernloom

go test -v ./pkg/adapters/openziti/decoder/...
go test -v ./pkg/adapters/openziti/mapping/...
go test -v ./pkg/adapters/openziti/relationshiplearner/...
```

Optional with a real controller:

```bash
cat > /tmp/openziti-test.go <<'EOF'
package main

import (
	"context"
	"fmt"

	"github.com/kernloom/kernloom/pkg/adapters/openziti/eventsource"
)

func main() {
	cv, err := eventsource.DiscoverVersion(context.Background(),
		eventsource.Config{BaseURL: "https://YOUR-CONTROLLER:1280", APIToken: "YOUR-TOKEN"},
		nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Version: %s\nCompatible: %v\nWarnings: %v\n",
		cv.Version, cv.Compatible, cv.Warnings)
}
EOF

go run /tmp/openziti-test.go
```

---

## 10. What Is Intentionally Different Now

- KLIQ starts with `kliq run [flags]`; subcommands are explicit.
- The state store flag is `--db`; `--state-store-path` is old.
- `--policy-file` accepts `kind: LocalPolicyPack` and
  `kind: RuntimePolicyPack` with `apiVersion: kernloom.io/runtime/v1alpha1`.
- Whitelist and feedback match generic subject IDs. IP/CIDR is only one
  supported subject form for network-based adapters.
- Adapter-specific telemetry, tuning details, and enforcement keys belong in
  `pkg/adapters/<adapter>/...`, not in `iq/cmd/kliq`.
- Graph/baseline data is metric-based and subject-/relationship-based. New
  adapters should provide their own metric IDs and dimensions instead of
  coupling KLIQ to IP, port, or PPS.
- In `active` mode, RuntimePDP decisions are mapped to `ActionProposal`s and go
  through the action broker with lease, receipt, and revert flow. The old direct
  relationship path is no longer the target path.

---

## 11. Common Problems

| Problem | Fix |
|---|---|
| `unknown command` or KLIQ does not start | `run` is missing: use `./bin/kliq run ...` |
| `flag provided but not defined: -state-store-path` | Use the new flag: `--db=/tmp/kernloom-manual/kliq-state.db` |
| `timeout` returns exit code `124` | Expected when the smoke test stops the running agent |
| `go: command not found` | `export PATH=$PATH:/usr/local/go/bin` |
| `kliq: no such file` | `go build -o bin/kliq ./iq/cmd/kliq` |
| `unsupported kind` with `--policy-file` | Check top-level `kind`: currently `LocalPolicyPack` or `RuntimePolicyPack` |
| `compile runtime policy file` | Check CEL expression, capability, level, or TTL in the RuntimePolicyPack |
| `Netfilter adapter ... no backend found` | `nft`/`iptables` is missing or root rights are missing; use `--adapter=none` for orchestrator smoke tests |
| KLShield maps are missing | Start KLShield/eBPF setup first, or use the unprivileged smoke test |
| KLShield `drop_rl_rate` is lower than expected | Check `klshield list-rl`; remember `rate_pps` is an allowed pass budget, while `drop_rl_rate` is only traffic above that budget |
| Relationships/Baselines are empty | Normal without a telemetry source; graph learning needs adapter observations |
| Forge server is not reachable | Check the port: `lsof -i :18443` |
| `forge compile --output yaml` does not load via `--policy-file` | That is an `EnforcementPlan`. For standalone KLIQ, create a `RuntimePolicyPack` with `apiVersion: kernloom.io/runtime/v1alpha1` |
