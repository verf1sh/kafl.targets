#!/bin/bash
#
# start_vm.sh - Host script to manually start FortiGate VM for debugging
#
# Usage:
#   ./start_vm.sh          # Start VM with serial console
#
# Note: For actual fuzzing, kAFL manages VM automatically. This script
# is only for manual debugging and verification.
#

set -e

FGT_QCOW2="/home/verf1sh/fuzzing/kAFL/kafl/examples/firmware/fortigate/fortios_7.4.3.qcow2"
FGT_TAP="${FGT_TAP:-tap-fgt}"
QEMU_BIN="${QEMU_BIN:-/home/verf1sh/fuzzing/kAFL/kafl/qemu/x86_64-softmmu/qemu-system-x86_64}"
FGT_MACHINE="${FGT_MACHINE:-q35,accel=kvm}"
FGT_CPU="${FGT_CPU:-host}"

# Check image exists
if [ ! -f "$FGT_QCOW2" ]; then
    echo "[!] Error: FortiOS qcow2 not found at $FGT_QCOW2"
    exit 1
fi

# Check tap exists
if ! ip link show "$FGT_TAP" &>/dev/null; then
    echo "[!] Tap $FGT_TAP not found. Run setup first:"
    echo "    sudo ip tuntap add $FGT_TAP mode tap user $(whoami)"
    echo "    sudo ip link set $FGT_TAP master virbr0"
    echo "    sudo ip link set $FGT_TAP up"
    exit 1
fi

echo "[*] Starting FortiGate VM for debugging..."
echo "[*] Image: $FGT_QCOW2"
echo "[*] Tap: $FGT_TAP -> virbr0"
echo "[*] QEMU: $QEMU_BIN"
echo "[*] Machine: $FGT_MACHINE CPU: $FGT_CPU"
echo "[*] Press Ctrl+A then X to quit QEMU"
echo ""

"$QEMU_BIN" \
    -enable-kvm \
    -machine "$FGT_MACHINE" \
    -cpu "$FGT_CPU" \
    -m 4096 \
    -drive file="$FGT_QCOW2",format=qcow2,if=none,id=disk0 \
    -device ahci,id=ahci0 \
    -device ide-hd,drive=disk0,bus=ahci0.0 \
    -netdev tap,id=net0,ifname="$FGT_TAP",script=no,downscript=no -device e1000,netdev=net0 \
    -display none \
    -nographic \
    -serial mon:stdio
