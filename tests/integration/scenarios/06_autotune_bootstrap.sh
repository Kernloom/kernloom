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
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

stop_kliq
sudo rm -f "$KLT_STATE_DIR/state.json"

# Start kliq with:
#   - known starting trigger (trig-pps=100)
#   - low floor (autotune-floor-pps=5) so target falls below the cap floor
#   - fast cycle (bootstrap-every1=8s) and few required samples (5)
#   - maxDown=0.10 explicit so cap allows 10% drop per cycle
#   - alpha=0.10 (default) — must NOT apply during bootstrap
AUTOTUNE_LOG="$KLT_ARTIFACT_DIR/kliq-06.log"
start_kliq_with_args "$AUTOTUNE_LOG" \
  --adapter=klshield \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
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
  --min-pps=1

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

stop_kliq

# Read the result.
STATE="$KLT_STATE_DIR/state.json"
if [[ ! -f "$STATE" ]]; then
  cat "$AUTOTUNE_LOG" >&2
  fail "06: state.json not written — autotune cycle did not fire"
fi

NEW_PPS=$(python3 -c "
import json, sys
st = json.load(open('$STATE'))
active = st.get('active', {})

def metric_pps_from_scope(scope):
    metrics = scope.get('metrics') or {}
    metric = metrics.get('network.packets_per_second') or {}
    return metric.get('threshold')

# New generic state writes adapter-scoped metric thresholds. Keep the legacy
# active.trig fallback so the scenario can still validate old state files.
trig = None
scopes = active.get('tuning_scopes') or {}
if 'klshield:network' in scopes:
    trig = metric_pps_from_scope(scopes['klshield:network'])
if trig is None:
    for scope in scopes.values():
        trig = metric_pps_from_scope(scope)
        if trig is not None:
            break
if trig is None:
    trig = ((active.get('trig') or {}).get('trig_pps'))
if trig is None and st.get('history'):
    metrics = (st['history'][-1].get('metric_thresholds') or {})
    trig = metrics.get('network.packets_per_second')
if trig is None:
    raise KeyError('network.packets_per_second threshold not found in state')
print(f'{float(trig):.2f}')
" 2>/dev/null || echo "0")

echo "[06] final trig_pps=$NEW_PPS (started at 100, maxDown=10% per bootstrap cycle)"
grep -E "AUTOTUNE|trig_pps" "$AUTOTUNE_LOG" | tail -5 || true

# Correct (no EWMA in bootstrap): ~90  (100 * 0.90)
# Buggy  (EWMA applied):          ~99  (100 * 0.90 + 100*0.90*0.10)
# We check the first applied cycle. The final state may be 81 when the second
# 8s bootstrap cycle also fires before the test stops KLIQ.
python3 -c "
import re
from pathlib import Path

final_v = float('$NEW_PPS')
if final_v <= 0:
    print('[FAIL] trig_pps is 0 — cycle did not fire or state unreadable', flush=True)
    exit(1)
log = Path('$AUTOTUNE_LOG').read_text(errors='replace')
m = re.search(r'AUTOTUNE applied: trig_pps ([0-9.]+)->([0-9.]+)', log)
if not m:
    print('[FAIL] no AUTOTUNE applied line found', flush=True)
    exit(1)
old_v = float(m.group(1))
first_v = float(m.group(2))
if first_v >= 95:
    print(f'[FAIL] first trig_pps step {old_v:.2f}->{first_v:.2f}: EWMA smoothing was applied during bootstrap (bug regression)', flush=True)
    exit(1)
if first_v < 85:
    print(f'[FAIL] first trig_pps step {old_v:.2f}->{first_v:.2f}: dropped more than expected (check maxDown flag)', flush=True)
    exit(1)
print(f'[OK] first trig_pps step {old_v:.2f}->{first_v:.2f}; final={final_v:.2f} — 10% cap applied correctly without EWMA', flush=True)
"

pass "06: autotune bootstrap drops ~10% per cycle (no EWMA regression)"
