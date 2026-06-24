#!/usr/bin/env bash
# cleanup-fortigate-net.sh
#
# Tears down the bridge/tap and iptables rules created by
# setup-fortigate-net.sh.
#
# Overridable defaults (must match setup):
#   FGT_BR=br-fgt       bridge name
#   FGT_TAP=tap-fgt0    tap device name
#   FGT_NET=10.0.1.0/24 network
#
set -e

: ${FGT_BR:=br-fgt}
: ${FGT_TAP:=tap-fgt0}
: ${FGT_NET:=10.0.1.0/24}

# 1. Remove tap from bridge and delete it
sudo ip link set "$FGT_TAP" nomaster 2>/dev/null || true
sudo ip link del "$FGT_TAP" 2>/dev/null || true

# 2. Delete bridge (releases the host IP on it)
sudo ip link set "$FGT_BR" down 2>/dev/null || true
sudo ip link del "$FGT_BR" 2>/dev/null || true

# 3. Remove iptables rules (exact match)
sudo iptables -t nat -D POSTROUTING -s "$FGT_NET" ! -d "$FGT_NET" -j MASQUERADE 2>/dev/null || true
sudo iptables -D FORWARD -s "$FGT_NET" -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

echo "[+] FortiGate network environment cleaned up (bridge=$FGT_BR, tap=$FGT_TAP)"
