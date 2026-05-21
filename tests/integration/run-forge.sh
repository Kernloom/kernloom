#!/usr/bin/env bash
# Kernloom Forge integration test runner (no XDP required).
# Runs only scenarios 09–10 which test the Forge control-plane via HTTP.
# Can run on any standard Linux host without BPF/XDP/netns capabilities.
#
# Requirements:
#   - forge binary at $KLT_FORGE (default: bin/forge, built from ../kernloom-forge)
#   - curl, jq
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source tests/integration/env.sh
source tests/integration/lib/cleanup.sh

mkdir -p "$KLT_ARTIFACT_DIR"

check_deps() {
  local missing=()
  for cmd in curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "[runner] ERROR: missing dependencies: ${missing[*]}" >&2
    exit 1
  fi
}

build_forge() {
  if [[ ! -x "$KLT_FORGE" ]]; then
    echo "[runner] forge binary not found at $KLT_FORGE — building..."
    local forge_root="${KLT_FORGE_ROOT:-}"
    if [[ -z "$forge_root" || ! -d "$forge_root" ]]; then
      echo "[runner] ERROR: KLT_FORGE_ROOT not set or not found" >&2
      echo "         Expected kernloom-forge repo at: $(cd "$ROOT/../kernloom-forge" 2>/dev/null && pwd || echo '<not found>')" >&2
      exit 1
    fi
    mkdir -p "$ROOT/bin"
    (cd "$forge_root" && go build -o "$KLT_FORGE" ./cmd/forge/)
    echo "[runner] forge built: $KLT_FORGE"
  fi
}

dump_debug() {
  echo ""
  echo "=== DEBUG INFO ==="
  for log in "$KLT_ARTIFACT_DIR"/*.log; do
    [[ -f "$log" ]] || continue
    echo "--- $log ---"
    tail -30 "$log" || true
  done
}

forge_cleanup() {
  # Stop forge if still running.
  local pidfile="$KLT_ARTIFACT_DIR/forge.pid"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid=$(cat "$pidfile")
    kill "$pid" 2>/dev/null || true
    rm -f "$pidfile"
  fi
  rm -f "$KLT_FORGE_DB" 2>/dev/null || true
}

on_exit() {
  local code=$?
  if [[ $code -ne 0 ]]; then
    dump_debug
  fi
  forge_cleanup
}
trap on_exit EXIT

check_deps
build_forge

SCENARIOS=(
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
  fi
done

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

[[ $FAIL -eq 0 ]] || exit 1
echo "[PASS] all Forge integration scenarios passed"
