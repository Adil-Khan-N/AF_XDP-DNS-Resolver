#!/usr/bin/env bash
#
# testbed.sh — Set up / tear down a veth test network for benchmarking
#
# Creates:
#   - A veth pair: veth-dns <-> veth-client
#   - A network namespace "dnstest" for the client side
#   - Assigns 10.0.0.1/24 to veth-dns (host) and 10.0.0.2/24 to veth-client (ns)
#   - Pins the host-side veth to 1 RX/TX queue (required for AF_XDP)
#   - Disables checksum offload on both ends
#
# Usage:
#   sudo ./testbed.sh setup     # create the test network
#   sudo ./testbed.sh teardown  # destroy it
#   sudo ./testbed.sh status    # show current state
#
# Running the resolver (from the host):
#   sudo ./socket_resolver --local
#   — or —
#   sudo ./afxdp_resolver --local veth-dns
#
# Running dnsperf (from the client namespace):
#   sudo ip netns exec dnstest dnsperf -s 10.0.0.1 -p 53 -d payload.txt -l 10
#
# Running dig (from the client namespace):
#   sudo ip netns exec dnstest dig @10.0.0.1 -p 53 google.com A

set -euo pipefail

NS="dnstest"
VETH_HOST="veth-dns"
VETH_CLIENT="veth-client"
HOST_IP="10.0.0.1/24"
CLIENT_IP="10.0.0.2/24"

setup() {
    echo "=== Creating test network ==="

    # Create namespace
    ip netns add "$NS" 2>/dev/null || true

    # Create veth pair
    ip link add "$VETH_HOST" type veth peer name "$VETH_CLIENT"

    # Move client end into the namespace
    ip link set "$VETH_CLIENT" netns "$NS"

    # Configure host side
    ip addr add "$HOST_IP" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    # Configure client side (inside namespace)
    ip netns exec "$NS" ip addr add "$CLIENT_IP" dev "$VETH_CLIENT"
    ip netns exec "$NS" ip link set "$VETH_CLIENT" up
    ip netns exec "$NS" ip link set lo up

    # Pin to 1 queue (required for AF_XDP)
    ethtool -L "$VETH_HOST" combined 1 2>/dev/null || \
        echo "Note: ethtool -L failed (veth may only support 1 queue already)"

    # Disable checksum offload (important for AF_XDP — raw packets
    # won't have hardware-computed checksums)
    ethtool -K "$VETH_HOST" tx off rx off 2>/dev/null || true
    ip netns exec "$NS" ethtool -K "$VETH_CLIENT" tx off rx off 2>/dev/null || true

    echo ""
    echo "Host side:   $VETH_HOST  ${HOST_IP}"
    echo "Client side: $VETH_CLIENT (in namespace '$NS')  ${CLIENT_IP}"
    echo ""
    echo "To run the resolver:"
    echo "  sudo ./socket_resolver --local"
    echo ""
    echo "To send queries from the client namespace:"
    echo "  sudo ip netns exec $NS dig @10.0.0.1 -p 53 google.com A"
    echo "  sudo ip netns exec $NS dnsperf -s 10.0.0.1 -d payload.txt -l 10"
    echo ""
    echo "=== Done ==="
}

teardown() {
    echo "=== Tearing down test network ==="

    # Delete the veth pair (also removes the peer)
    ip link del "$VETH_HOST" 2>/dev/null || true

    # Delete the namespace
    ip netns del "$NS" 2>/dev/null || true

    echo "=== Done ==="
}

status() {
    echo "=== Host interfaces ==="
    ip -br addr show "$VETH_HOST" 2>/dev/null || echo "$VETH_HOST not found"

    echo ""
    echo "=== Namespace '$NS' ==="
    if ip netns list | grep -q "^${NS}"; then
        ip netns exec "$NS" ip -br addr show "$VETH_CLIENT" 2>/dev/null || \
            echo "$VETH_CLIENT not found in namespace"
    else
        echo "Namespace $NS does not exist"
    fi
}

case "${1:-}" in
    setup)    setup ;;
    teardown) teardown ;;
    status)   status ;;
    *)
        echo "Usage: $0 {setup|teardown|status}"
        exit 1
        ;;
esac
