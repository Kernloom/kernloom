#!/usr/bin/env bash
# Network namespace / veth topology helpers.

set -euo pipefail

create_bridge() {
  sudo ip link add "$KLT_BR" type bridge 2>/dev/null || true
  sudo ip link set "$KLT_BR" up
}

add_ns() {
  local ns="$1"
  local ip="$2"
  local host_if="$3"
  local ns_if="$4"

  sudo ip netns add "$ns" 2>/dev/null || true
  sudo ip link del "$host_if" 2>/dev/null || true
  sudo ip link add "$host_if" type veth peer name "$ns_if"
  sudo ip link set "$host_if" master "$KLT_BR"
  sudo ip link set "$host_if" up
  sudo ip link set "$ns_if" netns "$ns"
  sudo ip netns exec "$ns" ip link set lo up
  sudo ip netns exec "$ns" ip addr flush dev "$ns_if" 2>/dev/null || true
  sudo ip netns exec "$ns" ip addr add "$ip/24" dev "$ns_if"
  sudo ip netns exec "$ns" ip link set "$ns_if" up
  # Default route so namespaces can reach the API via the bridge.
  sudo ip netns exec "$ns" ip route add default via "$KLT_IP_API" dev "$ns_if" 2>/dev/null || true
}

# Add an IP on the bridge so the host (and XDP) can route to namespaces.
setup_bridge_ip() {
  sudo ip addr flush dev "$KLT_BR" 2>/dev/null || true
  sudo ip addr add "10.42.0.1/24" dev "$KLT_BR" 2>/dev/null || true
}

setup_topology() {
  echo "[netns] creating bridge and namespaces"
  create_bridge
  add_ns "$KLT_NS_GOOD" "$KLT_IP_GOOD" "$KLT_VETH_GOOD_HOST" "$KLT_IF_GOOD"
  add_ns "$KLT_NS_BAD"  "$KLT_IP_BAD"  "$KLT_VETH_BAD_HOST"  "$KLT_IF_BAD"
  add_ns "$KLT_NS_API"  "$KLT_IP_API"  "$KLT_VETH_API_HOST"  "$KLT_IF_API"
  setup_bridge_ip
  # Enable forwarding so bridge passes traffic between veth pairs.
  sudo sysctl -q -w net.ipv4.ip_forward=1
  echo "[netns] topology ready"
}
