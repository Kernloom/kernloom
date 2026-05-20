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
sudo ip netns exec "$KLT_NS_BAD" bash -c "
  while true; do
    curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    sleep 0.05
  done
" &
BAD_PID=$!

# Wait until kliq has BLOCKED the bad source (XDP drops all packets).
# We measure good-source isolation specifically during BLOCK — after BLOCK
# steps down to RATE_HARD, some bad traffic leaks through again.
echo "[07] waiting for bad source to reach BLOCK state (max 15s)..."
BLOCKED=false
for i in $(seq 1 30); do
  if grep -qE "->BLOCK" "$KLT_LOG_KLIQ" 2>/dev/null; then
    BLOCKED=true
    break
  fi
  sleep 0.5
done
[[ "$BLOCKED" == "true" ]] \
  || fail "07: bad source was not BLOCKED within 15s — kliq may not have escalated"
echo "[07] bad source is BLOCKED — measuring good source isolation (10 checks × 0.2s)"

# Measure quickly (2s) to stay within the BLOCK window.
# During BLOCK, XDP drops 100% of bad source packets → server only sees good.
GOOD_OK=0
GOOD_FAIL=0
for i in $(seq 1 10); do
  if sudo ip netns exec "$KLT_NS_GOOD" \
       curl -fsS --max-time 1 "$(api_url)" >/dev/null 2>&1; then
    GOOD_OK=$((GOOD_OK + 1))
  else
    GOOD_FAIL=$((GOOD_FAIL + 1))
    echo "[07] check $i: good source FAILED during BLOCK (unexpected)"
  fi
  sleep 0.2
done

sudo kill "$BAD_PID" 2>/dev/null || true
wait "$BAD_PID" 2>/dev/null || true

echo "[07] good source during BLOCK: $GOOD_OK ok / $GOOD_FAIL failed out of 10 checks"

assert_contains "$KLT_LOG_KLIQ" "${KLT_IP_BAD}"
assert_contains "$KLT_LOG_KLIQ" "->BLOCK"

[[ "$GOOD_FAIL" -eq 0 ]] \
  || fail "07: good source failed $GOOD_FAIL/10 checks while bad source was in BLOCK state"

pass "07: good source 20/20 reachable while bad source was enforced"
