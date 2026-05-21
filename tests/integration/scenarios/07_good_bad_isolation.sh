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

# Reset XDP enforcement state from previous scenarios.
# Previous scenarios (03, 04) may leave bad source in deny4/RL maps.
# Without reset, bad source SYNs are dropped by XDP → kliq sees <5 pps
# → never escalates to RATE_SOFT → test times out.
sudo "$KLT_KLSHIELD" reset 2>/dev/null || true

# Use a dedicated log so concurrent writes from a dying previous kliq
# (whose fd is still open on $KLT_LOG_KLIQ) cannot produce NUL bytes here.
LOG07="$KLT_ARTIFACT_DIR/kliq-07.log"

start_kliq_enforce "$LOG07"

echo "[07] warming up — good traffic to establish clean baseline"
good_http_many 5
sleep 3

echo "[07] starting sustained bad traffic in background"
# Stop-file mechanism avoids pkill which kills the test runner.
# pkill -9 bash would kill ALL visible bash processes (shared PID namespace).
BAD_STOP="/tmp/klt-bad-stop-07-$$"
rm -f "$BAD_STOP"
sudo ip netns exec "$KLT_NS_BAD" bash -c "
  while [[ ! -f '$BAD_STOP' ]]; do
    curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    sleep 0.3
  done
" &
BAD_PID=$!

# Wait for kliq to apply first enforcement (RATE_SOFT = kliq detected bad source).
# With clean XDP state and 3 req/s, bad source generates ~24-30 pps > trig-pps=5.
echo "[07] waiting for bad source enforcement (RATE_SOFT) to start (max 20s)..."
ENFORCED=false
for i in $(seq 1 40); do
  # -- prevents grep from treating the pattern as an option (pattern starts with -).
  if grep -q -- "->RATE_SOFT" "$LOG07" 2>/dev/null \
     || grep -q -- "->RATE_HARD" "$LOG07" 2>/dev/null \
     || grep -q -- "->BLOCK"     "$LOG07" 2>/dev/null; then
    ENFORCED=true
    break
  fi
  # Diagnostic every 5s (i is iteration count; each iteration = 0.5s).
  if (( i % 10 == 0 )); then
    echo "[07] i=${i} ($(( i / 2 ))s) — kliq log tail:"
    tail -3 "$LOG07" 2>/dev/null | sed 's/^/  /' || echo "  (empty)"
  fi
  sleep 0.5
done

if [[ "$ENFORCED" != "true" ]]; then
  echo "[07] kliq log at timeout (last 15 lines):"
  tail -15 "$LOG07" 2>/dev/null | sed 's/^/  /' || echo "  (empty)"
  touch "$BAD_STOP"; wait "$BAD_PID" 2>/dev/null || true; rm -f "$BAD_STOP"
  fail "07: bad source was not enforced within 20s — see diagnostics above"
fi

# Determine which enforcement state was reached (highest wins).
# The || true prevents set -e from aborting when grep finds no match (exit 1).
STATE="->RATE_SOFT"
{ grep -q -- "->RATE_HARD" "$LOG07" 2>/dev/null && STATE="->RATE_HARD"; } || true
{ grep -q -- "->BLOCK"     "$LOG07" 2>/dev/null && STATE="->BLOCK"; } || true
echo "[07] bad source enforcement: $STATE — measuring good source isolation (10 checks × 0.2s)"

# Check good source during active enforcement.
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

touch "$BAD_STOP"; wait "$BAD_PID" 2>/dev/null || true; rm -f "$BAD_STOP"

echo "[07] good source: $GOOD_OK ok / $GOOD_FAIL failed out of 10 checks"

assert_contains "$LOG07" "${KLT_IP_BAD}"
assert_contains "$LOG07" "ACTION ip=${KLT_IP_BAD}"

stop_kliq

[[ "$GOOD_FAIL" -eq 0 ]] \
  || fail "07: good source failed $GOOD_FAIL/10 checks while bad source was under enforcement ($STATE)"

pass "07: good source 10/10 reachable while bad source was enforced ($STATE)"
