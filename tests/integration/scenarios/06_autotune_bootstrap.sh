#!/usr/bin/env bash
# Scenario 06: Autotune bootstrap regression.
#
# Verifies that during bootstrap the EWMA smoothing is NOT applied, so the
# trigger drops by ~maxDown% per cycle (10%), not by alpha*maxDown% (~1%).
#
# Bug: before the fix, effective drop was 1% per cycle instead of 10%.
# Reference commit: fix(autotune): skip EWMA smoothing during bootstrap
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

sudo mkdir -p "$KLT_STATE_DIR" "$KLT_ETC_DIR"
sudo cp "$KLT_ROOT/tests/integration/testdata/whitelist.txt" "$KLT_ETC_DIR/whitelist.txt"
sudo cp "$KLT_ROOT/tests/integration/testdata/feedback.json" "$KLT_STATE_DIR/feedback.json"
sudo rm -f "$KLT_STATE_DIR/state.json"

# Start kliq with:
#   - known starting trigger (trig-pps=100)
#   - low floor (autotune-floor-pps=5) so target falls below the cap floor
#   - fast cycle (bootstrap-every1=8s) and few required samples (5)
#   - maxDown=0.10 explicit so cap allows 10% drop per cycle
#   - alpha=0.10 (default) — must NOT apply during bootstrap
sudo "$KLT_KLIQ" \
  --state-file="$KLT_STATE_DIR/state.json" \
  --feedback-file="$KLT_STATE_DIR/feedback.json" \
  --whitelist="$KLT_ETC_DIR/whitelist.txt" \
  --db="$KLT_STATE_DIR/kliq.db" \
  --bpffs-root=/sys/fs/bpf \
  --interval=1s \
  --dry-run=true \
  --bootstrap=true \
  --autotune=true \
  --trig-pps=100 \
  --autotune-floor-pps=5 \
  --autotune-min-samples=2 \
  --autotune-k=3.5 \
  --autotune-alpha=0.10 \
  --bootstrap-every1=8s \
  --bootstrap-max-down1=0.10 \
  --bootstrap-max-up1=0.10 \
  --min-pps=1 \
  > "$KLT_ARTIFACT_DIR/kliq-06.log" 2>&1 &
KLIQ_PID=$!
echo "$KLIQ_PID" > "$KLT_ARTIFACT_DIR/kliq.pid"

echo "[06] kliq started, generating traffic via good namespace for reservoir"

# Generate low-PPS traffic so reservoir accumulates samples.
# The good namespace HTTP server is still running from earlier scenarios.
for _ in $(seq 1 12); do
  sudo ip netns exec "$KLT_NS_GOOD" \
    curl -fsS --max-time 3 "http://$KLT_IP_API:$KLT_API_PORT/" >/dev/null 2>&1 || true
  sleep 0.3
done

# Wait for the 8s cycle to fire (plus a few ticks margin).
sleep 12

sudo kill "$KLIQ_PID" 2>/dev/null || true
wait "$KLIQ_PID" 2>/dev/null || true

# Read the result.
STATE="$KLT_STATE_DIR/state.json"
if [[ ! -f "$STATE" ]]; then
  cat "$KLT_ARTIFACT_DIR/kliq-06.log" >&2
  fail "06: state.json not written — autotune cycle did not fire"
fi

NEW_PPS=$(python3 -c "
import json, sys
st = json.load(open('$STATE'))
sc = st['active']['sample_count']
trig = st['active']['trig']['trig_pps']
print(f'{trig:.2f}')
" 2>/dev/null || echo "0")

echo "[06] new trig_pps=$NEW_PPS (started at 100, maxDown=10% → expect ~90)"
cat "$KLT_ARTIFACT_DIR/kliq-06.log" | grep -E "AUTOTUNE|trig_pps" | tail -5 || true

# Correct (no EWMA in bootstrap): ~90  (100 * 0.90)
# Buggy  (EWMA applied):          ~99  (100 * 0.90 + 100*0.90*0.10)
# We check: new_pps < 95 (clearly below the buggy threshold of ~99)
python3 -c "
v = float('$NEW_PPS')
if v <= 0:
    print('[FAIL] trig_pps is 0 — cycle did not fire or state unreadable', flush=True)
    exit(1)
if v >= 95:
    print(f'[FAIL] trig_pps={v:.2f} >= 95: EWMA smoothing was applied during bootstrap (bug regression)', flush=True)
    exit(1)
if v < 85:
    print(f'[FAIL] trig_pps={v:.2f} < 85: dropped more than expected (check maxDown flag)', flush=True)
    exit(1)
print(f'[OK] trig_pps={v:.2f} — 10% cap applied correctly without EWMA', flush=True)
"

pass "06: autotune bootstrap drops ~10% per cycle (no EWMA regression)"
