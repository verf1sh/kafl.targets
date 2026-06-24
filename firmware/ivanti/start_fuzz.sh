#!/bin/sh
#
# start_fuzz.sh - Ivanti VM startup script for kAFL fuzzing (CVE-2025-22457)
#
# Place this file at /data/start_fuzz.sh inside the Ivanti qcow2 image.
# It starts the web daemon with LD_PRELOAD hook and then runs the trigger.
#
# Usage (inside Ivanti VM):
#   /data/start_fuzz.sh
#

echo "[*] Starting Ivanti kAFL fuzzing environment..."

# Ensure /dev/shm exists for shm_open() used by hook + agent
echo "[*] Setting up /dev/shm..."
mkdir -p /dev/shm
mount -t tmpfs -o size=10M tmpfs /dev/shm 2>/dev/null || true

# Kill any existing web process first
echo "[*] Stopping existing web process..."
killall web 2>/dev/null || true
killall web 2>/dev/null || true
killall web 2>/dev/null || true

# Start web daemon with hook library
echo "[*] Starting web daemon with hook_SSL_read.so..."

PWD=/home DSINSTALL=/home LD_LIBRARY_PATH=/home/lib PATH=/bin:/usr/bin:/sbin:/usr/sbin LD_PRELOAD=/data/hook_SSL_read.so /home/bin/web -s /home/runtime/webserver/conf &

# Wait for web daemon to initialize and start listening
echo "[*] Waiting for web daemon to start..."
sleep 3

WEB_PID=$(/data/busybox_x86 pidof web | /data/busybox_x86 awk '{print $1}')
if [ -n "$WEB_PID" ] && [ -r "/proc/$WEB_PID/maps" ]; then
    echo "[*] web pid: $WEB_PID"
    echo "[*] Relevant executable mappings:"
    /data/busybox_x86 awk '$2 ~ /x/ && ($0 ~ /\/home\/bin\/web/ || $0 ~ /\/home\/lib\/libdsagentd\.so/ || $0 ~ /hook_SSL_read\.so/) { print "    " $0 }' "/proc/$WEB_PID/maps"

    echo "[*] Suggested kAFL IP filters:"
    /data/busybox_x86 awk '
        $2 ~ /x/ && ($0 ~ /\/home\/bin\/web/ || $0 ~ /\/home\/lib\/libdsagentd\.so/) {
            split($1, a, "-");
            printf " -ip%d 0x%s-0x%s", n, a[1], a[2];
            n++;
            if (n == 4) exit;
        }
        END { print "" }
    ' "/proc/$WEB_PID/maps"

    if grep -q 'hook_SSL_read\.so' "/proc/$WEB_PID/maps"; then
        echo "[+] hook_SSL_read.so is loaded"
    else
        echo "[!] hook_SSL_read.so is NOT visible in web maps"
    fi
else
    echo "[!] Could not read web maps"
fi

# Verify web daemon is listening on 443
if netstat -tlnp 2>/dev/null | grep -q ':443'; then
    echo "[+] Web daemon listening on 443"
elif ss -tlnp 2>/dev/null | grep -q ':443'; then
    echo "[+] Web daemon listening on 443"
else
    echo "[!] Warning: web daemon may not be listening on 443"
    echo "[*] Checking process status..."
    ps | grep web || true
fi

# Run the kAFL agent (receives bootstrap config via hypercall payload)
echo "[*] Starting kAFL agent..."

CONFIG=/data/strategy.txt
if [ ! -f "$CONFIG" ]; then
    echo "[!] $CONFIG not found, agent will use default single-packet mode"
fi

exec /data/agent "$CONFIG"
