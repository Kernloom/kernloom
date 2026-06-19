#!/usr/bin/env bash
# Cleanup all integration test resources.
# Safe to call multiple times (idempotent).

set -euo pipefail

# Source env only if not already loaded.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../env.sh
source "$SCRIPT_DIR/../env.sh" 2>/dev/null || true

cleanup_all() {
  set +e
  echo "[cleanup] stopping processes"

  # Kill any kliq / HTTP server started by this test run.
  if [[ -d "${KLT_ARTIFACT_DIR:-}" ]]; then
    for pidfile in "$KLT_ARTIFACT_DIR"/*.pid; do
      [[ -f "$pidfile" ]] || continue
      local pid
      pid="$(cat "$pidfile")"
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        sudo kill "$pid" 2>/dev/null || true
        sleep 0.5
        sudo kill -9 "$pid" 2>/dev/null || true
      fi
      rm -f "$pidfile"
    done
  fi

  # Safety net: kill any remaining kliq/forge processes by exact binary name.
  # Uses -x (exact name match) not -f (full cmdline) to avoid pkill matching
  # its own command line and killing itself.
  sudo pkill -9 -x kliq  2>/dev/null || true
  sudo pkill -9 -x forge 2>/dev/null || true

  echo "[cleanup] detaching XDP"
  sudo "$KLT_KLSHIELD" detach-xdp --iface "${KLT_XDP_IFACE1:-veth-good-h}" 2>/dev/null || true
  sudo "$KLT_KLSHIELD" detach-xdp --iface "${KLT_XDP_IFACE2:-veth-bad-h}"  2>/dev/null || true

  echo "[cleanup] removing network namespaces and bridge"
  sudo ip netns del "${KLT_NS_GOOD:-klt-good}" 2>/dev/null || true
  sudo ip netns del "${KLT_NS_BAD:-klt-bad}"  2>/dev/null || true
  sudo ip netns del "${KLT_NS_API:-klt-api}"  2>/dev/null || true

  sudo ip link del "${KLT_VETH_GOOD_HOST:-veth-good-h}" 2>/dev/null || true
  sudo ip link del "${KLT_VETH_BAD_HOST:-veth-bad-h}"  2>/dev/null || true
  sudo ip link del "${KLT_VETH_API_HOST:-veth-api-h}"  2>/dev/null || true
  sudo ip link del "${KLT_BR:-br-klt}"                 2>/dev/null || true

  echo "[cleanup] removing kernloom BPF pins"
  sudo rm -f /sys/fs/bpf/kernloom_* 2>/dev/null || true
  sudo rm -f /sys/fs/bpf/kernloom_shield_xdp_link_* 2>/dev/null || true

  echo "[cleanup] removing test runtime dirs"
  # State and etc are now inside KLT_ARTIFACT_DIR — removing the artifact dir
  # covers them. Remove explicitly in case KLT_ARTIFACT_DIR is overridden.
  for dir in "${KLT_STATE_DIR:-}" "${KLT_ETC_DIR:-}"; do
    [[ -n "$dir" ]] || continue
    case "$dir" in
      "$KLT_ARTIFACT_DIR"/*|/tmp/kernloom-*)
        sudo rm -rf "$dir" 2>/dev/null || true
        ;;
      *)
        echo "[cleanup] refusing to remove non-artifact runtime dir: $dir"
        ;;
    esac
  done

  set -e
  echo "[cleanup] done"
}
