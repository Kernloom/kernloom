#!/usr/bin/env bash
# Kernloom no-XDP integration test runner.
# Runs Forge control-plane scenarios plus RuntimePolicyPack contract checks.
# Can run on any standard Linux host without BPF/XDP/netns capabilities.
#
# Requirements:
#   - scenario 09: Forge repo/binary, curl, jq
#   - scenario 10: Forge repo/binary
#   - scenario 12: Forge repo, Go toolchain; bin/forge and bin/kliq are built by this runner
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

DEFAULT_SCENARIOS=(
  tests/integration/scenarios/09_managed_enrollment.sh
  tests/integration/scenarios/10_adapter_definition.sh
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

check_deps() {
  local needs_forge_api_deps="$1"
  local needs_forge_binary="$2"
  local needs_kliq="$3"
  local missing=()
  if [[ "$needs_forge_api_deps" == "true" ]]; then
    for cmd in curl jq; do
      command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
  fi
  if [[ "$needs_forge_binary" == "true" || "$needs_kliq" == "true" ]]; then
    command -v "$KLT_GO" >/dev/null 2>&1 || missing+=("$KLT_GO")
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "[runner] ERROR: missing dependencies: ${missing[*]}" >&2
    exit 1
  fi
}

build_kliq() {
  if [[ "${KLT_KLIQ_SKIP_BUILD:-0}" != "1" ]]; then
    echo "[runner] building kliq binary at $KLT_KLIQ"
    mkdir -p "$(dirname "$KLT_KLIQ")"
    GOCACHE="${KLT_GO_BUILD_CACHE:-$KLT_ARTIFACT_DIR/go-build-runner}" \
      "$KLT_GO" build -o "$KLT_KLIQ" ./iq/cmd/kliq
    echo "[runner] kliq built: $KLT_KLIQ"
  elif [[ ! -x "$KLT_KLIQ" ]]; then
    echo "[runner] ERROR: kliq binary not found at $KLT_KLIQ" >&2
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
    (cd "$forge_root" && GOCACHE="${KLT_GO_BUILD_CACHE:-$KLT_ARTIFACT_DIR/go-build-runner}" \
      "$KLT_GO" build -o "$KLT_FORGE" ./cmd/forge/)
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

mapfile -t SCENARIOS < <(resolve_scenarios "$@")
for scenario in "${SCENARIOS[@]}"; do
  [[ -f "$scenario" ]] || {
    echo "[runner] ERROR: scenario not found: $scenario" >&2
    exit 1
  }
done

NEEDS_FORGE_BINARY=false
NEEDS_FORGE_API_DEPS=false
NEEDS_KLIQ=false
for scenario in "${SCENARIOS[@]}"; do
  case "$(basename "$scenario")" in
    09_*) NEEDS_FORGE_BINARY=true; NEEDS_FORGE_API_DEPS=true ;;
    10_*) NEEDS_FORGE_BINARY=true ;;
    12_*) NEEDS_FORGE_BINARY=true; NEEDS_KLIQ=true ;;
  esac
done

check_deps "$NEEDS_FORGE_API_DEPS" "$NEEDS_FORGE_BINARY" "$NEEDS_KLIQ"
if [[ "$NEEDS_KLIQ" == "true" ]]; then
  build_kliq
fi
if [[ "$NEEDS_FORGE_BINARY" == "true" ]]; then
  build_forge
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
  fi
done

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

[[ $FAIL -eq 0 ]] || exit 1
echo "[PASS] all no-XDP integration scenarios passed"
