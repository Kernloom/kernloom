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
    sudo kill "$pid" 2>/dev/null || true
    # Wait up to 3s for graceful exit, then force-kill.
    local i=0
    while kill -0 "$pid" 2>/dev/null && [[ $i -lt 6 ]]; do
      sleep 0.5
      i=$((i + 1))
    done
    sudo kill -9 "$pid" 2>/dev/null || true
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

_kliq_common_flags() {
  echo \
    --state-file="$KLT_STATE_DIR/state.json" \
    --feedback-file="$KLT_STATE_DIR/feedback.json" \
    --whitelist="$KLT_ETC_DIR/whitelist.txt" \
    --db="$KLT_STATE_DIR/kliq.db" \
    --bpffs-root=/sys/fs/bpf \
    --interval=1s
}

start_kliq_dryrun() {
  echo "[proc] starting kliq (dry-run, low thresholds)"
  sudo mkdir -p "$KLT_STATE_DIR" "$KLT_ETC_DIR"
  sudo cp "$KLT_ROOT/tests/integration/testdata/whitelist.txt" "$KLT_ETC_DIR/whitelist.txt"
  sudo cp "$KLT_ROOT/tests/integration/testdata/feedback.json" "$KLT_STATE_DIR/feedback.json"

  # shellcheck disable=SC2046
  sudo "$KLT_KLIQ" \
    $(_kliq_common_flags) \
    --dry-run=true \
    --bootstrap=false \
    --autotune=false \
    --min-pps=1 \
    --trig-pps=5 \
    --trig-syn=5 \
    --trig-scan=3 \
    > "$KLT_LOG_KLIQ" 2>&1 &
  record_pid kliq "$!"
  sleep 2
  echo "[proc] kliq running (dry-run) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}

start_kliq_enforce() {
  echo "[proc] starting kliq (enforce mode, fast thresholds)"
  sudo mkdir -p "$KLT_STATE_DIR" "$KLT_ETC_DIR"
  sudo cp "$KLT_ROOT/tests/integration/testdata/whitelist.txt" "$KLT_ETC_DIR/whitelist.txt"
  sudo cp "$KLT_ROOT/tests/integration/testdata/feedback.json" "$KLT_STATE_DIR/feedback.json"

  # shellcheck disable=SC2046
  sudo "$KLT_KLIQ" \
    $(_kliq_common_flags) \
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
    --block-ttl=30s \
    > "$KLT_LOG_KLIQ" 2>&1 &
  record_pid kliq "$!"
  sleep 2
  echo "[proc] kliq running (enforce) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}

start_kliq_graph() {
  echo "[proc] starting kliq (graph-learning, fast promotion)"
  sudo mkdir -p "$KLT_STATE_DIR" "$KLT_ETC_DIR"
  sudo cp "$KLT_ROOT/tests/integration/testdata/whitelist.txt" "$KLT_ETC_DIR/whitelist.txt"
  sudo cp "$KLT_ROOT/tests/integration/testdata/feedback.json" "$KLT_STATE_DIR/feedback.json"

  # shellcheck disable=SC2046
  sudo "$KLT_KLIQ" \
    $(_kliq_common_flags) \
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
    --graph-promote-interval=5s \
    > "$KLT_LOG_KLIQ" 2>&1 &
  record_pid kliq "$!"
  sleep 2
  echo "[proc] kliq running (graph) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}

start_kliq_frozen() {
  local logfile="${1:-$KLT_LOG_KLIQ}"
  echo "[proc] starting kliq (frozen-observe)"
  # shellcheck disable=SC2046
  sudo "$KLT_KLIQ" \
    $(_kliq_common_flags) \
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
    --graph-freeze-min-severity=0 \
    > "$logfile" 2>&1 &
  record_pid kliq "$!"
  sleep 2
  echo "[proc] kliq running (frozen-observe) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}


# ── Forge ─────────────────────────────────────────────────────────────────────

start_forge() {
  echo "[proc] starting forge serve on $KLT_FORGE_ADDR"
  mkdir -p "$(dirname "$KLT_FORGE_DB")"
  "$KLT_FORGE" serve \
    --addr    "$KLT_FORGE_ADDR" \
    --db      "$KLT_FORGE_DB" \
    --admin-key "$KLT_FORGE_ADMIN_KEY" \
    --adapters "${KLT_FORGE_ADAPTERS:-}" \
    > "$KLT_FORGE_LOG" 2>&1 &
  record_pid forge "$!"
  # Wait for forge to be ready.
  local i=0
  while ! curl -sf "$KLT_FORGE_URL/api/v1/nodes" \
      -H "Authorization: Bearer $KLT_FORGE_ADMIN_KEY" >/dev/null 2>&1; do
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
    -H "Authorization: Bearer $KLT_FORGE_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    "$@"
}

forge_create_token() {
  local node_id="${1:-}"
  local args=()
  [[ -n "$node_id" ]] && args+=(--node "$node_id")
  "$KLT_FORGE" token create \
    --db "$KLT_FORGE_DB" \
    "${args[@]}" \
    --expires 1h \
    2>/dev/null | grep '^TOKEN=' | cut -d= -f2-
}

# Simulate KLIQ enrollment via curl (no BPF required).
# $1 = node_id, $2 = token, $3 = plugin_adapter (default: builtin-klshield)
forge_simulate_enroll() {
  local node_id="$1"
  local token="$2"
  local plugin="${3:-builtin-klshield}"

  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/enroll" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{
      \"node_id\": \"$node_id\",
      \"mode\": \"managed\",
      \"kliq_version\": \"it-test\",
      \"inventory\": {
        \"apiVersion\": \"kernloom.io/v1alpha1\",
        \"kind\": \"ComponentRuntimeInventory\",
        \"metadata\": {\"id\": \"$plugin-$node_id\"},
        \"controlled_by\": {
          \"node_id\": \"$node_id\",
          \"plugin_adapter\": \"$plugin\"
        },
        \"component\": {\"product\": \"kernloom-shield\"},
        \"roles\": [\"pep\", \"sensor\"],
        \"profiles\": [\"network.l3_l4_filter\"]
      }
    }"
}

# Simulate a KLIQ heartbeat via curl.
# $1 = node_id, $2 = session_token
forge_simulate_heartbeat() {
  local node_id="$1"
  local session_token="$2"
  curl -sf -X POST "$KLT_FORGE_URL/api/v1/nodes/$node_id/heartbeat" \
    -H "Authorization: Bearer $session_token" \
    -H "Content-Type: application/json" \
    -d "{\"node_id\": \"$node_id\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
}

# Pull the runtime bundle via curl.
# $1 = node_id, $2 = session_token
forge_pull_bundle() {
  local node_id="$1"
  local session_token="$2"
  curl -sf "$KLT_FORGE_URL/api/v1/nodes/$node_id/runtime-bundle" \
    -H "Authorization: Bearer $session_token"
}
