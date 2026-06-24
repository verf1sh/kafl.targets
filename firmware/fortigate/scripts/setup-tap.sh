#!/usr/bin/env bash
# setup-tap.sh - Create tap-fgt and attach to virbr0 (virt-manager bridge)
#
set -e

FGT_TAP="${FGT_TAP:-tap-fgt}"

if ip link show "$FGT_TAP" &>/dev/null; then
    echo "[*] $FGT_TAP already exists"
else
    sudo ip tuntap add "$FGT_TAP" mode tap user "$(whoami)"
    sudo ip link set "$FGT_TAP" master virbr0
    sudo ip link set "$FGT_TAP" up
    echo "[+] Created $FGT_TAP and attached to virbr0"
fi
