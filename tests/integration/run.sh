#!/usr/bin/env bash
# Kernloom integration test runner.
# Must be run as root (or via sudo):  sudo tests/integration/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=env.sh
source tests/integration/env.sh
# shellcheck source=lib/cleanup.sh
source tests/integration/lib/cleanup.sh

mkdir -p "$KLT_ARTIFACT_DIR"

# Collect debug info on failure.
dump_debug() {
  echo ""
  echo "=== DEBUG INFO ==="
  ip netns list 2>/dev/null || true
  ip link show 2>/dev/null | grep -E "klt|veth|br-" || true
  ls -la /sys/fs/bpf/ 2>/dev/null | grep kernloom || true
  dmesg 2>/dev/null | tail -20 || true
  echo ""
  for log in "$KLT_ARTIFACT_DIR"/*.log "$KLT_ARTIFACT_DIR"/*.txt; do
    [[ -f "$log" ]] || continue
    echo "--- $log ---"
    tail -30 "$log" || true
  done
}

on_exit() {
  local code=$?
  if [[ $code -ne 0 ]]; then
    dump_debug
  fi
  echo ""
  echo "[runner] cleanup"
  cleanup_all
  if [[ $code -eq 0 ]]; then
    echo "[runner] artifacts: $KLT_ARTIFACT_DIR"
  fi
}
trap on_exit EXIT

# Pre-clean from any previous run.
cleanup_all

# Make sure bpffs is mounted.
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

SCENARIOS=(
  tests/integration/scenarios/00_smoke_build.sh
  tests/integration/scenarios/01_attach_stats.sh
  tests/integration/scenarios/02_dryrun_detection.sh
  tests/integration/scenarios/03_enforce_rate_limit_or_block.sh
  tests/integration/scenarios/04_graph_learn_freeze.sh
  tests/integration/scenarios/05_restart_recovery.sh
  tests/integration/scenarios/06_autotune_bootstrap.sh
  tests/integration/scenarios/07_good_bad_isolation.sh
  tests/integration/scenarios/08_fsm_stepdown.sh
  # Forge control-plane scenarios — no XDP required.
  tests/integration/scenarios/09_managed_enrollment.sh
  tests/integration/scenarios/10_adapter_definition.sh
)

PASS=0
FAIL=0

for scenario in "${SCENARIOS[@]}"; do
  echo ""
  echo "=============================="
  echo "RUN $(basename "$scenario")"
  echo "=============================="
  if bash "$scenario"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "[FAIL] $scenario" >&2
    # Continue remaining scenarios even after a failure.
  fi
done

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

[[ $FAIL -eq 0 ]] || exit 1
echo "[PASS] all integration scenarios passed"
