/*
 * hook_common.h — shared definitions for agent and LD_PRELOAD hook
 * edit by verf1sh: add crash classification + taint marker for cmd-inj detection
 *
 * Keep this file in sync between agent.c and hook_SSL_read.c.
 */

#ifndef HOOK_COMMON_H
#define HOOK_COMMON_H

#define SHM_NAME            "/kafl_hook_shm"
#define MAX_PAYLOAD         (1 * 1024 * 1024)
#define TAINT_MARKER_LEN    48
#define SHM_MAGIC           0x4B41464C

/* ---- kAFL hypercall numbers (must match both sides) ----------------
 * Guarded with #ifndef because nyx_api.h (included by agent.c) may
 * already define the same constants.  */
#ifndef HYPERCALL_KAFL_RAX_ID
#define HYPERCALL_KAFL_RAX_ID       0x01f
#endif
#ifndef HYPERCALL_KAFL_RELEASE
#define HYPERCALL_KAFL_RELEASE      0x04
#endif
#ifndef HYPERCALL_KAFL_SUBMIT_CR3
#define HYPERCALL_KAFL_SUBMIT_CR3   0x05
#endif
#ifndef HYPERCALL_KAFL_PANIC
#define HYPERCALL_KAFL_PANIC        0x08
#endif

/* ---- Crash reason classification ------------------------------------ */
#define CRASH_NONE          0
#define CRASH_CMD_INJECT    1
#define CRASH_REAL          2

/* ---- Shared memory state (mmap'd by both agent and hook) ----------- */
struct hook_state {
    int ready;
    int consumed;
    int size;
    int prefix_phase;
    int suppress_release;
    int crash_reason;                   /* CRASH_NONE / CRASH_CMD_INJECT / CRASH_REAL */
    char taint_marker[TAINT_MARKER_LEN]; /* current round marker (e.g. KAFL_CMDINJ_xxx) */
    char data[MAX_PAYLOAD];
};

/* ---- Multi-packet header (embedded in data[], v3 SHM format) ------- */
#define MAX_PACKETS 5

struct shm_header {
    uint32_t magic;
    uint32_t packet_count;
    uint32_t reserved;
    uint32_t packet_sizes[MAX_PACKETS];
};

#endif
