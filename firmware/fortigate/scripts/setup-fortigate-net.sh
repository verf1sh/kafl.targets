#!/usr/bin/env bash
# setup-fortigate-net.sh
#
# Creates a bridge (br-fgt) + tap (tap-fgt0) for FortiGate VM networking.
# The VM's port1 sits at 10.0.1.1/24 by default; the host gets 10.0.1.254
# as its gateway onto the bridge.
#
# Overridable defaults:
#   FGT_BR=br-fgt       bridge name
#   FGT_TAP=tap-fgt0    tap device name
#   FGT_HOST_IP=10.0.1.254/24   host address on bridge
#   FGT_NET=10.0.1.0/24         network (used for iptables rules)
#
set -e

: ${FGT_BR:=br-fgt}
: ${FGT_TAP:=tap-fgt0}
: ${FGT_HOST_IP:=10.0.1.254/24}
: ${FGT_NET:=10.0.1.0/24}

# 1. Create bridge (reuse if exists)
ip link show "$FGT_BR" &>/dev/null && { echo "[*] $FGT_BR already exists, skipping create"; } || \
  { sudo ip link add "$FGT_BR" type bridge; sudo ip link set "$FGT_BR" up; }

# 2. Create tap and attach to bridge
ip link show "$FGT_TAP" &>/dev/null && { echo "[*] $FGT_TAP already exists, skipping create"; } || \
  { sudo ip tuntap add "$FGT_TAP" mode tap user "$(whoami)"; sudo ip link set "$FGT_TAP" master "$FGT_BR"; sudo ip link set "$FGT_TAP" up; }

# 3. Assign host address on the bridge (won't flush existing addresses)
sudo ip addr add "$FGT_HOST_IP" dev "$FGT_BR" 2>/dev/null || true

# 4. Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

# 5. Add NAT + forwarding rules (idempotent via -C probes)
sudo iptables -t nat -C POSTROUTING -s "$FGT_NET" ! -d "$FGT_NET" -j MASQUERADE 2>/dev/null || \
  sudo iptables -t nat -A POSTROUTING -s "$FGT_NET" ! -d "$FGT_NET" -j MASQUERADE

sudo iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

sudo iptables -C FORWARD -s "$FGT_NET" -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -s "$FGT_NET" -j ACCEPT

echo "[+] FortiGate network environment ready (bridge=$FGT_BR, tap=$FGT_TAP, host=$FGT_HOST_IP)"
