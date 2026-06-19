#!/usr/bin/env bash
# Process lifecycle helpers (start / stop klshield, kliq, forge, HTTP server).

set -euo pipefail

record_pid() {
  local name="$1"
  local pid="$2"
  echo "$pid" > "$KLT_ARTIFACT_DIR/$name.pid"
}

stop_by_pidfile() {
  local pidfile="$1"
  [[ -f "$pidfile" ]] || return 0
  local pid
  pid="$(cat "$pidfile")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    # Kill children first (e.g. actual kliq binary under sudo wrapper),
    # before killing the parent — after parent dies children are reparented
    # to init and pkill -P can no longer find them.
    sudo pkill -TERM -P "$pid" 2>/dev/null || true
    sudo kill -TERM "$pid" 2>/dev/null || true
    local i=0
    while kill -0 "$pid" 2>/dev/null && [[ $i -lt 6 ]]; do
      sleep 0.5
      i=$((i + 1))
    done
    sudo pkill -KILL -P "$pid" 2>/dev/null || true
    sudo kill -KILL "$pid" 2>/dev/null || true
    sleep 0.2
  fi
  rm -f "$pidfile"
}

stop_kliq() {
  stop_by_pidfile "$KLT_ARTIFACT_DIR/kliq.pid"
}

stop_server() {
  stop_by_pidfile "$KLT_ARTIFACT_DIR/server.pid"
}

start_http_server() {
  echo "[proc] starting HTTP server in $KLT_NS_API ($KLT_IP_API:$KLT_API_PORT)"
  sudo ip netns exec "$KLT_NS_API" \
    python3 -m http.server "$KLT_API_PORT" --bind "$KLT_IP_API" \
    > "$KLT_LOG_SERVER" 2>&1 &
  record_pid server "$!"
  sleep 1
}

attach_xdp() {
  # Attach to both client-side veths in the HOST namespace.
  # veth-good-h sees ingress from klt-good; veth-bad-h sees klt-bad.
  # Shared maps → kliq sees both client IPs with correct SRC addresses.
  for iface in "$KLT_XDP_IFACE1" "$KLT_XDP_IFACE2"; do
    echo "[proc] attaching XDP to $iface"
    sudo "$KLT_KLSHIELD" attach-xdp \
      --iface "$iface" \
      --obj   "$KLT_BPF_OBJ" \
      --force \
      >> "$KLT_LOG_SHIELD" 2>&1 \
      || { echo "[ERROR] XDP attach failed on $iface:"; cat "$KLT_LOG_SHIELD" >&2; return 1; }
  done
  echo "[proc] XDP attached to $KLT_XDP_IFACE1 and $KLT_XDP_IFACE2"
}

detach_xdp() {
  echo "[proc] detaching XDP"
  sudo "$KLT_KLSHIELD" detach-xdp --iface "$KLT_XDP_IFACE1" 2>/dev/null || true
  sudo "$KLT_KLSHIELD" detach-xdp --iface "$KLT_XDP_IFACE2" 2>/dev/null || true
}

prepare_kliq_runtime() {
  sudo mkdir -p "$KLT_STATE_DIR" "$KLT_ETC_DIR"
  sudo cp "$KLT_ROOT/tests/integration/testdata/whitelist.txt" "$KLT_ETC_DIR/whitelist.txt"
  sudo cp "$KLT_ROOT/tests/integration/testdata/feedback.json" "$KLT_STATE_DIR/feedback.json"
}

write_runtime_network_policy() {
  local policy="${1:-$KLT_STATE_DIR/runtime-network-policy.yaml}"
  sudo mkdir -p "$(dirname "$policy")"
  sudo tee "$policy" >/dev/null <<'YAML'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: integration-network-runtime-policy
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
        - integration_fsm_intent_block
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
        - integration_fsm_intent_hard
    - id: fsm-intent-soft
      when: "fsm.proposed_level == 'soft'"
      then:
        capability: enforce.traffic.rate_limit
        level: soft
        ttl: "30s"
      reason_codes:
        - integration_fsm_intent_soft
    - id: fsm-intent-observe
      when: "fsm.proposed_level == 'observe' && fsm.current_level != 'observe'"
      then:
        level: observe
        ttl: "30s"
      reason_codes:
        - integration_fsm_intent_observe
YAML
  echo "$policy"
}

kliq_base_args() {
  KLIQ_BASE_ARGS=(
    "--state-file=$KLT_STATE_DIR/state.json"
    "--feedback-file=$KLT_STATE_DIR/feedback.json"
    "--whitelist=$KLT_ETC_DIR/whitelist.txt"
    "--db=$KLT_STATE_DIR/kliq.db"
    "--bpffs-root=/sys/fs/bpf"
    "--interval=1s"
  )
}

start_kliq_with_args() {
  local logfile="$1"
  shift
  prepare_kliq_runtime
  kliq_base_args
  sudo "$KLT_KLIQ" run \
    "${KLIQ_BASE_ARGS[@]}" \
    "$@" \
    > "$logfile" 2>&1 &
  record_pid kliq "$!"
  sleep 2
  local pid
  pid="$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[ERROR] kliq exited during startup; log follows:" >&2
    tail -80 "$logfile" >&2 || true
    return 1
  fi
}

start_kliq_dryrun() {
  local logfile="${1:-$KLT_LOG_KLIQ}"
  echo "[proc] starting kliq (dry-run, low thresholds) → $logfile"

  start_kliq_with_args "$logfile" \
    --adapter=klshield \
    --feature-profile=dos-light \
    --runtime-pdp-mode=shadow \
    --dry-run=true \
    --bootstrap=false \
    --autotune=false \
    --min-pps=1 \
    --trig-pps=5 \
    --trig-syn=5 \
    --trig-scan=3
  echo "[proc] kliq running (dry-run) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}

start_kliq_enforce() {
  local logfile="${1:-$KLT_LOG_KLIQ}"
  local policy
  policy="$(write_runtime_network_policy "$KLT_STATE_DIR/runtime-network-policy.yaml")"
  echo "[proc] starting kliq (RuntimePDP active, fast thresholds) → $logfile"

  start_kliq_with_args "$logfile" \
    --adapter=klshield \
    --policy-file="$policy" \
    --feature-profile=dos-light \
    --runtime-pdp-mode=active \
    --dry-run=false \
    --bootstrap=false \
    --autotune=false \
    --min-pps=1 \
    --trig-pps=5 \
    --trig-syn=5 \
    --trig-scan=3 \
    --soft-at=2 \
    --hard-at=4 \
    --block-at=6 \
    --up-need=1 \
    --down-need=5 \
    --soft-ttl=30s \
    --hard-ttl=30s \
    --block-ttl=30s
  echo "[proc] kliq running (RuntimePDP active) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}

start_kliq_graph() {
  local logfile="${1:-$KLT_LOG_KLIQ}"
  echo "[proc] starting kliq (graph-learning, fast promotion) → $logfile"

  start_kliq_with_args "$logfile" \
    --adapter=klshield \
    --feature-profile=graph-learning \
    --runtime-pdp-mode=shadow \
    --dry-run=false \
    --bootstrap=false \
    --autotune=false \
    --min-pps=1 \
    --trig-pps=100 \
    --trig-syn=100 \
    --trig-scan=100 \
    --graph \
    --graph-mode=learn \
    --graph-min-seen=3 \
    --graph-min-windows=1 \
    --graph-min-age=3s \
    --graph-promote-interval=5s
  echo "[proc] kliq running (graph) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}

start_kliq_frozen() {
  local logfile="${1:-$KLT_LOG_KLIQ}"
  echo "[proc] starting kliq (frozen-observe)"

  start_kliq_with_args "$logfile" \
    --adapter=klshield \
    --feature-profile=graph-enforce \
    --runtime-pdp-mode=shadow \
    --dry-run=false \
    --bootstrap=false \
    --autotune=false \
    --min-pps=1 \
    --trig-pps=100 \
    --trig-syn=100 \
    --trig-scan=100 \
    --graph \
    --graph-mode=frozen-observe \
    --graph-freeze-action=signal \
    --graph-freeze-min-severity=0
  echo "[proc] kliq running (frozen-observe) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}


# ── Forge ─────────────────────────────────────────────────────────────────────

start_forge() {
  echo "[proc] starting forge serve on $KLT_FORGE_ADDR"
  "$KLT_FORGE" serve \
    --addr "$KLT_FORGE_ADDR" \
    --adapters "${KLT_FORGE_ADAPTERS:-}" \
    --profiles "${KLT_FORGE_PROFILES:-}" \
    > "$KLT_FORGE_LOG" 2>&1 &
  record_pid forge "$!"
  # Wait for forge to be ready.
  local i=0
  while ! curl -sf "$KLT_FORGE_URL/healthz" >/dev/null 2>&1; do
    sleep 0.3
    i=$((i + 1))
    [[ $i -lt 20 ]] || { echo "[ERROR] forge did not start"; cat "$KLT_FORGE_LOG" >&2; exit 1; }
  done
  echo "[proc] forge running pid=$(cat "$KLT_ARTIFACT_DIR/forge.pid")"
}

stop_forge() {
  stop_by_pidfile "$KLT_ARTIFACT_DIR/forge.pid"
}

forge_admin() {
  curl -sf \
    -H "Content-Type: application/json" \
    "$@"
}

# Simulate KLIQ enrollment via curl (no BPF required).
# $1 = node_id
forge_simulate_enroll() {
  local node_id="$1"

  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/enroll" \
    -H "Content-Type: application/json" \
    -d "{
      \"node_id\": \"$node_id\",
      \"mode\": \"managed\",
      \"enroll_key\": \"it-test\"
    }"
}

# Pull the runtime bundle via curl.
# $1 = node_id
forge_pull_bundle() {
  local node_id="$1"
  curl -sf "$KLT_FORGE_URL/api/v1/nodes/$node_id/runtime-bundle"
}

# $1 = node_id
forge_post_bundle_ack() {
  local node_id="$1"
  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/$node_id/bundle-acks" \
    -H "Content-Type: application/json" \
    -d '{"status":"activated","generation":1}'
}

# $1 = node_id
forge_post_receipts() {
  local node_id="$1"
  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/$node_id/receipts" \
    -H "Content-Type: application/json" \
    -d '{"receipts":[{"id":"receipt-it-1","status":"applied"}]}'
}

# $1 = node_id
forge_post_findings() {
  local node_id="$1"
  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/$node_id/findings" \
    -H "Content-Type: application/json" \
    -d '[{"id":"finding-it-1","severity":"info"}]'
}

# $1 = node_id
forge_post_baseline_proposal() {
  local node_id="$1"
  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/$node_id/baseline-proposals" \
    -H "Content-Type: application/json" \
    -d '{"proposal":"it"}'
}
