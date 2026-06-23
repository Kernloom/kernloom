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

restore_artifact_ownership() {
  [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]] || return 0
  [[ -d "${KLT_ARTIFACT_DIR:-}" ]] || return 0
  case "$KLT_ARTIFACT_DIR" in
    /tmp/kernloom-*|"$KLT_ROOT"/tests/integration/artifacts/*)
      chown -R "$SUDO_UID:$SUDO_GID" "$KLT_ARTIFACT_DIR" 2>/dev/null || true
      ;;
  esac
  case "$(dirname "$KLT_ARTIFACT_DIR")" in
    /tmp/kernloom-integration-artifacts-*)
      chown "$SUDO_UID:$SUDO_GID" "$(dirname "$KLT_ARTIFACT_DIR")" 2>/dev/null || true
      ;;
  esac
}

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
  restore_artifact_ownership
  if [[ $code -eq 0 ]]; then
    echo "[runner] artifacts: $KLT_ARTIFACT_DIR"
  fi
}
trap on_exit EXIT

# Pre-clean from any previous run.
cleanup_all

# Make sure bpffs is mounted.
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

DEFAULT_SCENARIOS=(
  tests/integration/scenarios/00_smoke_build.sh
  tests/integration/scenarios/01_attach_stats.sh
  tests/integration/scenarios/02_dryrun_detection.sh
  tests/integration/scenarios/03_enforce_rate_limit_or_block.sh
  tests/integration/scenarios/04_graph_learn_freeze.sh
  tests/integration/scenarios/05_restart_recovery.sh
  tests/integration/scenarios/06_autotune_bootstrap.sh
  tests/integration/scenarios/07_good_bad_isolation.sh
  tests/integration/scenarios/08_runtime_pdp_stepdown.sh
  # Forge control-plane scenarios — no XDP required.
  tests/integration/scenarios/09_managed_enrollment.sh
  tests/integration/scenarios/10_adapter_definition.sh
  tests/integration/scenarios/11_netfilter_adapter.sh
  tests/integration/scenarios/12_runtime_policy_pack.sh
)

resolve_scenarios() {
  local items=()
  if [[ "$#" -gt 0 ]]; then
    items=("$@")
  elif [[ -n "${KLT_SCENARIOS:-}" ]]; then
    local item
    for item in $KLT_SCENARIOS; do
      items+=("$item")
    done
  else
    printf '%s\n' "${DEFAULT_SCENARIOS[@]}"
    return
  fi

  local item
  for item in "${items[@]}"; do
    if [[ -f "$item" ]]; then
      printf '%s\n' "$item"
    elif [[ -f "tests/integration/scenarios/$item" ]]; then
      printf '%s\n' "tests/integration/scenarios/$item"
    else
      printf '%s\n' "tests/integration/scenarios/${item}"*.sh
    fi
  done
}

mapfile -t SCENARIOS < <(resolve_scenarios "$@")
for scenario in "${SCENARIOS[@]}"; do
  [[ -f "$scenario" ]] || {
    echo "[runner] ERROR: scenario not found: $scenario" >&2
    exit 1
  }
done

needs_forge=false
for scenario in "${SCENARIOS[@]}"; do
  case "$(basename "$scenario")" in
    09_*|10_*|12_*) needs_forge=true ;;
  esac
done

# Build forge binary for scenarios 09, 10 and 12 (no XDP required).
# Skips silently if the kernloom-forge repo is not found — scenarios will
# then fail with a clear "forge not found" message rather than silently skip.
if [[ "$needs_forge" == "true" && "${KLT_FORGE_SKIP_BUILD:-0}" != "1" ]]; then
  FORGE_REPO="${KLT_FORGE_ROOT:-}"
  if [[ -z "$FORGE_REPO" ]] && [[ -d "$ROOT/../kernloom-forge" ]]; then
    FORGE_REPO="$(cd "$ROOT/../kernloom-forge" && pwd)"
  fi
  if [[ -n "$FORGE_REPO" && -d "$FORGE_REPO" ]]; then
    echo "[runner] building forge from $FORGE_REPO"
    mkdir -p "$(dirname "$KLT_FORGE")"
    (cd "$FORGE_REPO" && "$KLT_GO" build -o "$KLT_FORGE" ./cmd/forge/) \
      && echo "[runner] forge built: $KLT_FORGE" \
      || echo "[runner] WARNING: forge build failed — scenarios 09+10 will fail"
  else
    echo "[runner] WARNING: kernloom-forge repo not found — scenarios 09+10 will fail"
    echo "         Set KLT_FORGE_ROOT or place kernloom-forge next to kernloom"
  fi
elif [[ "$needs_forge" == "true" && ! -x "$KLT_FORGE" ]]; then
  echo "[runner] WARNING: forge binary not found at $KLT_FORGE"
fi

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
