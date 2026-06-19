#!/usr/bin/env bash
# Scenario 08: RuntimePDP stepdown after attack stops.
#
# Verifies that a blocked/rate-limited source recovers to OBSERVE after
# the enforcement TTL expires and enough clean ticks pass. The FSM supplies
# recovery intent facts; RuntimePDP owns the observe/downscale action.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

stop_kliq

# Clear any deny/rate-limit entries left by previous scenarios so the bad
# source is not already blocked when this scenario starts.
sudo "$KLT_KLSHIELD" reset 2>/dev/null || true

sudo rm -f "$KLT_STATE_DIR/state.json"

STEPDOWN_LOG="$KLT_ARTIFACT_DIR/kliq-08.log"
POLICY="$(write_runtime_network_policy "$KLT_STATE_DIR/runtime-network-policy-08.yaml")"

# Start kliq with very short TTLs so stepdown happens within the test window.
#   soft-ttl=5s hard-ttl=5s block-ttl=5s down-need=2 min-hold-hard=0
start_kliq_with_args "$STEPDOWN_LOG" \
  --adapter=klshield \
  --policy-file="$POLICY" \
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
  --down-need=2 \
  --soft-ttl=5s \
  --hard-ttl=5s \
  --block-ttl=5s \
  --min-hold-hard=0s

echo "[08] phase 1: generating bad traffic for 15s to trigger enforcement"
# Use a stop-file so the loop exits cleanly without pkill.
# pkill -9 bash is dangerous: it kills ALL visible bash processes (shared PID
# namespace), including the test runner itself, crashing the shell.
BAD_STOP="/tmp/klt-bad-stop-08-$$"
rm -f "$BAD_STOP"
sudo ip netns exec "$KLT_NS_BAD" bash -c "
  while [[ ! -f '$BAD_STOP' ]]; do
    curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    sleep 0.3
  done
" &
BAD_PID=$!

# Give kliq time to escalate (TTL=5s, soft-at=2 → ~3 ticks).
sleep 8

# Verify enforcement was applied while traffic is still running.
assert_contains "$STEPDOWN_LOG" "${KLT_IP_BAD}"
assert_contains "$STEPDOWN_LOG" "STATE ${KLT_IP_BAD} .*->(RATE_SOFT|RATE_HARD|BLOCK)|ACTION-RECEIPT.*${KLT_IP_BAD}"

echo "[08] phase 2: stopping bad traffic — waiting for recovery (TTL=5s + 2 clean ticks)"
# Signal the loop to exit via stop file, then wait for the process to finish.
touch "$BAD_STOP"
wait "$BAD_PID" 2>/dev/null || true
rm -f "$BAD_STOP"
# TTL=5s + down-need=2 ticks + margin = ~10s
# Full stepdown chain: BLOCK(up to 9s) → RATE_HARD(5s) → RATE_SOFT(5s) → OBSERVE.
# Observed total: ~22s. Sleep 25s to have margin.
sleep 25

echo "[08] phase 3: verifying bad source can reach API again"
RECOVER_OK=0
for _ in $(seq 1 5); do
  if sudo ip netns exec "$KLT_NS_BAD" \
       curl -fsS --max-time 3 "$(api_url)" >/dev/null 2>&1; then
    RECOVER_OK=$((RECOVER_OK + 1))
  fi
  sleep 0.5
done

echo "[08] recovery checks: $RECOVER_OK/5 succeeded"
grep -E -- "STATE|OBSERVE|stepdown|decay|fsm|runtime-pdp" "$STEPDOWN_LOG" | tail -10 || true

# At least 4/5 requests must succeed after recovery.
[[ "$RECOVER_OK" -ge 4 ]] \
  || fail "08: bad source did not recover after attack stopped ($RECOVER_OK/5 requests succeeded)"

# Log must show RuntimePDP/broker recovery to OBSERVE.
assert_contains "$STEPDOWN_LOG" "->OBSERVE"

stop_kliq

pass "08: RuntimePDP stepped down after attack stopped — source recovered in ~$(( 5 + 2 ))s"
