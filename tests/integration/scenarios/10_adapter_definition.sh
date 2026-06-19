#!/usr/bin/env bash
# Scenario 10: Forge adapter/profile compiler contract.
#
# Does NOT require XDP/eBPF. Verifies the current Forge model:
# adapter capability manifests live under examples/adapters, profiles under
# examples/profiles, and an AccessPolicy compiles into per-profile plans.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

RESULTS_DIR="$KLT_ARTIFACT_DIR/10"
mkdir -p "$RESULTS_DIR"

[[ -x "$KLT_FORGE" ]] || fail "forge binary not found: $KLT_FORGE"
[[ -d "$KLT_FORGE_ADAPTERS" ]] || fail "adapter examples not found: $KLT_FORGE_ADAPTERS"
[[ -d "$KLT_FORGE_PROFILES" ]] || fail "profile examples not found: $KLT_FORGE_PROFILES"

POLICY_FILE="$KLT_FORGE_ROOT/examples/policies/investor-apps-access.yaml"
[[ -f "$POLICY_FILE" ]] || fail "policy example not found: $POLICY_FILE"

validate_adapter() {
  local name="$1"
  local out="$RESULTS_DIR/validate-adapter-$name.txt"
  "$KLT_FORGE" validate-adapter \
    --adapter "$KLT_FORGE_ADAPTERS/$name/capability.yaml" \
    > "$out"
  cat "$out"
  assert_contains "$out" "OK: AdapterCapabilityManifest"
  assert_contains "$out" "$name"
}

validate_adapter klshield
validate_adapter netfilter
validate_adapter openziti
pass "10.1: core adapter capability manifests validate"

POLICY_OUT="$RESULTS_DIR/validate-policy.txt"
"$KLT_FORGE" validate --policy "$POLICY_FILE" > "$POLICY_OUT"
cat "$POLICY_OUT"
assert_contains "$POLICY_OUT" "OK: AccessPolicy"
assert_contains "$POLICY_OUT" "investor-apps-access"
pass "10.2: AccessPolicy example validates"

SUMMARY_OUT="$RESULTS_DIR/compile-summary.txt"
"$KLT_FORGE" compile \
  --policy "$POLICY_FILE" \
  --adapters "$KLT_FORGE_ADAPTERS" \
  --profiles "$KLT_FORGE_PROFILES" \
  --output summary \
  > "$SUMMARY_OUT"
cat "$SUMMARY_OUT"
assert_contains "$SUMMARY_OUT" "idp-production"
assert_contains "$SUMMARY_OUT" "klshield-local"
assert_contains "$SUMMARY_OUT" "openziti-production"
assert_contains "$SUMMARY_OUT" "deployable"
assert_contains "$SUMMARY_OUT" "unsupported|downgraded|delegated|compensating"
pass "10.3: policy compiles to per-profile summaries"

YAML_OUT="$RESULTS_DIR/compile-plans.yaml"
"$KLT_FORGE" compile \
  --policy "$POLICY_FILE" \
  --adapters "$KLT_FORGE_ADAPTERS" \
  --profiles "$KLT_FORGE_PROFILES" \
  --output yaml \
  > "$YAML_OUT"
assert_file_not_empty "$YAML_OUT"
assert_contains "$YAML_OUT" "apiVersion:"
assert_contains "$YAML_OUT" "kind:"
assert_contains "$YAML_OUT" "investor-apps-access"
pass "10.4: policy compile emits YAML plans"

pass "10: Forge adapter/profile compiler contract complete"
