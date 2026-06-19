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
  if [[ "${KLT_FORGE_SKIP_BUILD:-0}" != "1" ]]; then
    echo "[runner] building forge binary at $KLT_FORGE"
    local forge_root="${KLT_FORGE_ROOT:-}"
    if [[ -z "$forge_root" || ! -d "$forge_root" ]]; then
      echo "[runner] ERROR: KLT_FORGE_ROOT not set or not found" >&2
      echo "         Expected kernloom-forge repo at: $(cd "$ROOT/../kernloom-forge" 2>/dev/null && pwd || echo '<not found>')" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$KLT_FORGE")"
    (cd "$forge_root" && "$KLT_GO" build -o "$KLT_FORGE" ./cmd/forge/)
    echo "[runner] forge built: $KLT_FORGE"
  elif [[ ! -x "$KLT_FORGE" ]]; then
    echo "[runner] ERROR: forge binary not found at $KLT_FORGE" >&2
    exit 1
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
  restore_artifact_ownership
}
trap on_exit EXIT

check_deps
build_forge

DEFAULT_SCENARIOS=(
  tests/integration/scenarios/09_managed_enrollment.sh
  tests/integration/scenarios/10_adapter_definition.sh
)

resolve_scenarios() {
  if [[ -z "${KLT_SCENARIOS:-}" ]]; then
    printf '%s\n' "${DEFAULT_SCENARIOS[@]}"
    return
  fi
  local item
  for item in $KLT_SCENARIOS; do
    if [[ -f "$item" ]]; then
      printf '%s\n' "$item"
    elif [[ -f "tests/integration/scenarios/$item" ]]; then
      printf '%s\n' "tests/integration/scenarios/$item"
    else
      printf '%s\n' "tests/integration/scenarios/${item}"*.sh
    fi
  done
}

mapfile -t SCENARIOS < <(resolve_scenarios)
for scenario in "${SCENARIOS[@]}"; do
  [[ -f "$scenario" ]] || {
    echo "[runner] ERROR: scenario not found: $scenario" >&2
    exit 1
  }
done

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
