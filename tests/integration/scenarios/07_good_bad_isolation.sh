#!/usr/bin/env bash
# Scenario 07: Good/Bad source isolation under active enforcement.
#
# The strongest safety property: while a bad source is being rate-limited
# or blocked, a good source must NEVER be affected.
# We measure good-source success rate during sustained bad traffic.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

stop_kliq
start_kliq_enforce

echo "[07] warming up — good traffic to establish clean baseline"
good_http_many 5
sleep 3

echo "[07] starting sustained bad traffic in background"
# Rate: ~10 req/s (sleep 0.1) — enough to trigger enforcement without
# overwhelming the single-threaded python HTTP server.
sudo ip netns exec "$KLT_NS_BAD" bash -c "
  while true; do
    curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    sleep 0.1
  done
" &
BAD_PID=$!

# Wait for kliq to escalate bad source to at least RATE_HARD/BLOCK.
# With --soft-at=2 --hard-at=4 --block-at=6 and 1s tick, needs ~8s.
sleep 10

# Verify the HTTP server is still alive before measuring good source.
# If the server died from overload the test result would be a false negative.
sudo ip netns exec "$KLT_NS_GOOD" \
  curl -fsS --max-time 3 "$(api_url)" >/dev/null 2>&1 \
  || fail "07: HTTP server unreachable before measurement phase (server may have crashed)"

echo "[07] measuring good source reachability during enforcement (20 checks)"
GOOD_OK=0
GOOD_FAIL=0

for i in $(seq 1 20); do
  if sudo ip netns exec "$KLT_NS_GOOD" \
       curl -fsS --max-time 3 "$(api_url)" >/dev/null 2>&1; then
    GOOD_OK=$((GOOD_OK + 1))
  else
    GOOD_FAIL=$((GOOD_FAIL + 1))
    echo "[07] check $i: good source FAILED (unexpected)"
  fi
  sleep 0.5
done

sudo kill "$BAD_PID" 2>/dev/null || true
wait "$BAD_PID" 2>/dev/null || true

echo "[07] good source: $GOOD_OK ok / $GOOD_FAIL failed out of 20 checks"

# Verify kliq escalated the bad source.
assert_contains "$KLT_LOG_KLIQ" "${KLT_IP_BAD}"
assert_contains "$KLT_LOG_KLIQ" "ACTION ip=${KLT_IP_BAD}"

# Good source must have succeeded on every single check.
[[ "$GOOD_FAIL" -eq 0 ]] \
  || fail "07: good source failed $GOOD_FAIL/20 times during enforcement of bad source"

pass "07: good source 20/20 reachable while bad source was enforced"
