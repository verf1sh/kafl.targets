#!/bin/sh
#
# start_fuzz.sh — FortiGate kAFL fuzz launcher (runs inside VM)
# Required files in / : agent, inject, hook.so, strategy.txt
#

echo "[*] FortiGate kAFL fuzz start"

wait_httpsd()
{
    i=0
    while [ "$i" -lt 30 ]; do
        if busybox ps aux | busybox grep '/bin/httpsd' >/dev/null 2>&1; then
            return 0
        fi
        busybox sleep 1
        i=$((i + 1))
    done
    return 1
}

httpsd_count()
{
    busybox ps aux | busybox awk '$0 ~ /\/bin\/httpsd/ {n++} END {print n + 0}'
}

httpsd_pids()
{
    busybox ps aux | busybox awk '$0 ~ /\/bin\/httpsd/ {print $1}'
}

wait_httpsd_stable()
{
    last=-1
    stable=0
    i=0
    while [ "$i" -lt 20 ]; do
        cur=$(httpsd_count)
        if [ "$cur" -gt 0 ] && [ "$cur" = "$last" ]; then
            stable=$((stable + 1))
            if [ "$stable" -ge 3 ]; then
                return 0
            fi
        else
            stable=0
            last="$cur"
        fi
        busybox sleep 1
        i=$((i + 1))
    done
    return 1
}

check_httpsd_sane()
{
    cur=$(httpsd_count)
    echo "[*] /bin/httpsd process count: $cur"
    return 0
}

inject_httpsd_rounds()
{
    hook_path=${HOOK_PATH:-/hook.so}
    round=1
    while [ "$round" -le 3 ]; do
        echo "[*] httpsd processes before injection round $round:"
        busybox ps aux | busybox awk '$0 ~ /\/bin\/httpsd/'
        echo "[*] injecting $hook_path round $round ..."
        /inject httpsd "$hook_path"
        inject_rc=$?
        busybox sleep 1

        if verify_hook_mapped; then
            return 0
        fi

        if [ "$inject_rc" -ne 0 ]; then
            echo "[!] hook injection failed in round $round"
            return 1
        fi

        round=$((round + 1))
    done

    echo "[!] hook is not mapped into every /bin/httpsd process"
    return 1
}

start_ptrace_tracer()
{
    echo "[*] starting ptrace syscall tracer for httpsd ..."
    busybox killall inject >/dev/null 2>&1
    trace_log=${TRACE_LOG:-/dev/console}
    if [ "$trace_log" = "/dev/shm/kafl_trace.log" ]; then
        busybox rm -f "$trace_log"
    fi
    /inject --trace httpsd >"$trace_log" 2>&1 &
    TRACE_PID=$!
    busybox sleep 1

    if ! kill -0 "$TRACE_PID" 2>/dev/null; then
        echo "[!] ptrace tracer exited early"
        if [ -f "$trace_log" ]; then
            busybox cat "$trace_log" 2>/dev/null
        fi
        return 1
    fi

    echo "[+] ptrace tracer pid=$TRACE_PID"
    echo "[*] ptrace tracer log: $trace_log"
    return 0
}

start_learn_tracer()
{
    echo "[*] starting ptrace input-point learner for httpsd ..."
    busybox killall inject >/dev/null 2>&1
    /inject --learn httpsd &
    LEARN_PID=$!
    busybox sleep 1

    if ! kill -0 "$LEARN_PID" 2>/dev/null; then
        echo "[!] ptrace learner exited early"
        return 1
    fi

    echo "[+] ptrace learner pid=$LEARN_PID"
    return 0
}

verify_hook_mapped()
{
    hook_path=${HOOK_PATH:-/hook.so}
    total=0
    missing=0

    for pid in $(httpsd_pids); do
        total=$((total + 1))
        if busybox grep -q "$hook_path" "/proc/$pid/maps" 2>/dev/null; then
            echo "[+] hook mapped pid=$pid"
        else
            echo "[!] hook missing pid=$pid"
            missing=$((missing + 1))
        fi
    done

    echo "[*] hook mapping summary: mapped=$((total - missing)) total=$total"

    if [ "$total" -eq 0 ]; then
        return 1
    fi
    if [ "$missing" -ne 0 ]; then
        return 1
    fi
    return 0
}

# 1. /dev/shm for hook<->agent communication
#    FortiOS already provides /dev/shm; mounting fails with "wrong flags".
#    Just verify writability — if broken, shm_open() will fail anyway.
busybox ls -la /dev/ | busybox grep shm || echo "[!] /dev/shm missing"
busybox rm -f /dev/shm/kafl_hook_shm
busybox rm -f /dev/shm/kafl_hook_enable

# 2. Inject hook.so into every matching worker.  By default do not restart
#    httpsd: FortiOS supervision can respawn a fresh prefork pool before old
#    workers exit, temporarily creating many /bin/httpsd processes.
if [ "$RESTART_HTTPSD" = "1" ]; then
    echo "[*] restarting httpsd workers..."
    busybox killall httpsd >/dev/null 2>&1
else
    echo "[*] using existing httpsd workers (set RESTART_HTTPSD=1 to restart)"
fi

if ! wait_httpsd; then
    echo "[!] httpsd is not running"
    exit 1
fi
if ! wait_httpsd_stable; then
    echo "[!] httpsd process set did not stabilize"
    busybox ps aux | busybox grep '[h]ttpsd'
    exit 1
fi
if ! check_httpsd_sane; then
    exit 1
fi

# Default to ptrace-dlopen hook injection.  The syscall tracer remains
# available for diagnostics via FUZZ_INJECT_MODE=ptrace or learn mode.
FUZZ_INJECT_MODE=${FUZZ_INJECT_MODE:-hook}
if [ "$FUZZ_INJECT_MODE" = "hook" ]; then
    if [ "$RUN_AGENT" != "0" ]; then
        busybox touch /dev/shm/kafl_hook_enable
        echo "[*] kAFL hook execution enabled"
    else
        echo "[*] RUN_AGENT=0: hook is passthrough; kAFL hypercalls disabled"
    fi
    if ! inject_httpsd_rounds; then
        exit 1
    fi
    export AGENT_MODE=${AGENT_MODE:-hook}
elif [ "$FUZZ_INJECT_MODE" = "learn" ]; then
    if ! start_learn_tracer; then
        exit 1
    fi
    echo "[*] learn mode ready; trigger HTTP manually from outside, or inside the VM, e.g.:"
    echo "    printf 'GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n' | nc 127.0.0.1 9980"
    if [ "$RUN_AGENT" != "1" ]; then
        if [ "$LEARN_BACKGROUND" = "1" ]; then
            echo "[*] LEARN_BACKGROUND=1, leaving learner in background"
            exit 0
        fi
        echo "[*] RUN_AGENT is not 1, waiting for learner in foreground"
        echo "[*] open another shell/serial session to trigger HTTP requests"
        wait "$LEARN_PID"
        exit $?
    fi
    export AGENT_MODE=${AGENT_MODE:-hook}
else
    if ! start_ptrace_tracer; then
        exit 1
    fi
    export AGENT_MODE=${AGENT_MODE:-ptrace}
fi

# 3. Launch agent
echo "[*] launching agent..."
if [ "$RUN_AGENT" = "0" ]; then
    echo "[*] RUN_AGENT=0, injection-only test complete"
    exit 0
fi
exec /agent /strategy.txt
