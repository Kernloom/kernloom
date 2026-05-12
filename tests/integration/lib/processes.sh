#!/usr/bin/env bash
# Process lifecycle helpers (start / stop klshield, kliq, HTTP server).

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
    --graph-node-id=it-node \
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
    --graph-node-id=it-node \
    --graph-freeze-action=signal \
    --graph-freeze-min-severity=0 \
    > "$logfile" 2>&1 &
  record_pid kliq "$!"
  sleep 2
  echo "[proc] kliq running (frozen-observe) pid=$(cat "$KLT_ARTIFACT_DIR/kliq.pid")"
}
