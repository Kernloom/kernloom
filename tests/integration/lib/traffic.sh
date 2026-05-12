#!/usr/bin/env bash
# Traffic generation helpers.

set -euo pipefail

api_url() {
  echo "http://$KLT_IP_API:$KLT_API_PORT/"
}

good_http_once() {
  sudo ip netns exec "$KLT_NS_GOOD" \
    curl -fsS --max-time 5 "$(api_url)" >/dev/null
}

good_http_many() {
  local n="${1:-10}"
  echo "[traffic] good: $n HTTP requests"
  for _ in $(seq 1 "$n"); do
    good_http_once || true
    sleep 0.1
  done
}

# Rapid-fire requests to trigger PPS/SYN detection.
bad_http_burst() {
  local n="${1:-150}"
  echo "[traffic] bad: $n rapid requests"
  sudo ip netns exec "$KLT_NS_BAD" bash -c "
    for i in \$(seq 1 $n); do
      curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    done
  "
}

# Scan many destination ports to trigger scan detection.
bad_port_scan() {
  local start="${1:-7000}"
  local end="${2:-7150}"
  echo "[traffic] bad: port scan $start-$end"
  sudo ip netns exec "$KLT_NS_BAD" bash -c "
    for p in \$(seq $start $end); do
      (echo '' | nc -w1 $KLT_IP_API \$p) >/dev/null 2>&1 || true
    done
  " || true
}
