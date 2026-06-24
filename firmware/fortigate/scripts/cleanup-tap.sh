#!/usr/bin/env bash
# cleanup-tap.sh - Remove tap-fgt from virbr0 and delete it
#
set -e

FGT_TAP="${FGT_TAP:-tap-fgt}"

if ! ip link show "$FGT_TAP" &>/dev/null; then
    echo "[*] $FGT_TAP does not exist, nothing to clean"
    exit 0
fi

sudo ip link set "$FGT_TAP" nomaster 2>/dev/null || true
sudo ip link del "$FGT_TAP" 2>/dev/null || true
echo "[+] Removed $FGT_TAP"
