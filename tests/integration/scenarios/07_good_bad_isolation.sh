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
# 2 req/s — each HTTP request is ~10-15 packets, so 20-30 pps > trig-pps=5.
# Do NOT use sleep 0.05 (20 req/s): that spawns hundreds of curl processes
# and triggers the OOM killer on memory-constrained test hosts.
sudo ip netns exec "$KLT_NS_BAD" bash -c "
  while true; do
    curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    sleep 0.5
  done
" &
BAD_PID=$!

# Wait for kliq to apply first enforcement (RATE_SOFT = kliq has detected bad source).
# We test isolation property: when bad source is being rate-limited or blocked,
# good source must be completely unaffected.
# We don't require BLOCK specifically because rate-limiting may keep strikes low.
echo "[07] waiting for bad source enforcement (RATE_SOFT) to start (max 20s)..."
ENFORCED=false
for i in $(seq 1 40); do
  if grep -qE "->RATE_SOFT|->RATE_HARD|->BLOCK" "$KLT_LOG_KLIQ" 2>/dev/null; then
    ENFORCED=true
    break
  fi
  sleep 0.5
done
[[ "$ENFORCED" == "true" ]] \
  || fail "07: bad source was not enforced within 10s — kliq may not have escalated"

STATE=$(grep -oE "->RATE_SOFT|->RATE_HARD|->BLOCK" "$KLT_LOG_KLIQ" | tail -1)
echo "[07] bad source enforcement: $STATE — measuring good source isolation (10 checks × 0.2s)"

# Check good source quickly while bad source is under active enforcement.
# XDP rate-limits/blocks bad source but must not affect good source at all.
GOOD_OK=0
GOOD_FAIL=0
for i in $(seq 1 10); do
  if sudo ip netns exec "$KLT_NS_GOOD" \
       curl -fsS --max-time 1 "$(api_url)" >/dev/null 2>&1; then
    GOOD_OK=$((GOOD_OK + 1))
  else
    GOOD_FAIL=$((GOOD_FAIL + 1))
    echo "[07] check $i: good source FAILED during enforcement (unexpected)"
  fi
  sleep 0.2
done

sudo kill "$BAD_PID" 2>/dev/null || true
wait "$BAD_PID" 2>/dev/null || true

echo "[07] good source: $GOOD_OK ok / $GOOD_FAIL failed out of 10 checks"

assert_contains "$KLT_LOG_KLIQ" "${KLT_IP_BAD}"
assert_contains "$KLT_LOG_KLIQ" "ACTION ip=${KLT_IP_BAD}"

[[ "$GOOD_FAIL" -eq 0 ]] \
  || fail "07: good source failed $GOOD_FAIL/10 checks while bad source was under enforcement ($STATE)"

pass "07: good source 20/20 reachable while bad source was enforced"
