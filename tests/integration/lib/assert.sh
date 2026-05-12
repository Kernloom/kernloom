#!/usr/bin/env bash
# Assertion helpers for integration tests.

set -euo pipefail

_KLT_PASS=0
_KLT_FAIL=0

pass() {
  _KLT_PASS=$((_KLT_PASS + 1))
  echo "[PASS] $*"
}

fail() {
  _KLT_FAIL=$((_KLT_FAIL + 1))
  echo "[FAIL] $*" >&2
  exit 1
}

assert_file_exists() {
  [[ -e "$1" ]] || fail "expected file to exist: $1"
}

assert_file_not_empty() {
  [[ -s "$1" ]] || fail "expected non-empty file: $1"
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  grep -qE -- "$pattern" "$file" || {
    echo "--- $file ---" >&2
    tail -50 "$file" >&2 || true
    fail "pattern '$pattern' not found in $file"
  }
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  if grep -qE -- "$pattern" "$file" 2>/dev/null; then
    fail "unexpected pattern '$pattern' found in $file"
  fi
}

assert_cmd_success() {
  "$@" || fail "command failed: $*"
}

assert_http_ok() {
  local ns="$1"
  local url="$2"
  sudo ip netns exec "$ns" curl -fsS --max-time 5 "$url" >/dev/null \
    || fail "expected HTTP OK from $ns → $url"
}

assert_http_fails() {
  local ns="$1"
  local url="$2"
  if sudo ip netns exec "$ns" curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
    fail "expected HTTP failure from $ns → $url, but it succeeded"
  fi
}

assert_int_gt() {
  local val="$1"
  local min="$2"
  local label="${3:-value}"
  [[ "$val" -gt "$min" ]] || fail "$label: expected >$min, got $val"
}

assert_stats_field_gt() {
  local statsfile="$1"
  local field="$2"
  local min="$3"
  local val
  val=$(grep -oE "${field}=[0-9]+" "$statsfile" | head -1 | cut -d= -f2 || echo 0)
  assert_int_gt "$val" "$min" "$field"
}
