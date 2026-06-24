/*
 * hook_common.h — shared definitions for agent and LD_PRELOAD hook
 * edit by verf1sh: crash classification + taint marker for cmd-inj detection
 *
 * Agent and hook use this shared-memory layout to coordinate:
 *   - RELEASE suppression/trigger
 *   - SHM data injection mode
 *   - Crash reason classification
 *
 * Keep this file in sync between agent.c and hook.c.
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
    int generation;
    int read_hits;
    int last_read_fd;
    int last_read_size;
    int last_copy_size;
    int last_payload_size;
    int last_api;                       /* 1=read, 2=recv, 3=recvfrom */
    int cr3_submits;
    int iter_count;                     /* in-target: iterations entered (pre-snapshot only) */
    int release_hits;                   /* in-target: RELEASE calls observed */
    int snapshot_taken;                 /* in-target: set once NEXT_PAYLOAD snapshot created */
    int hook_read_calls;                /* diag: read() hook entered (httpsd) */
    int hook_recv_calls;                /* diag: recv()/recvfrom() hook entered */
    int hook_readv_calls;               /* diag: readv() hook entered */
    int hook_recvmsg_calls;             /* diag: recvmsg() hook entered */
    int accept_calls;                   /* diag: accept()/accept4() hook entered */
    int sock_read_calls;                /* diag: read-family hook entered on a SOCKET fd */
    int hook_ctor_hits;
    int hook_ctor_pid;
    int patch_objects;
    int patch_slots;
    int patch_failed;
    int patch_last_errno;
    int accept_hits;
    int last_accept_fd;
    int last_accept_pid;
    int syscall_hits;
    int last_syscall_nr;
    int entry_patch_slots;
    int entry_patch_failed;
    int entry_patch_last_errno;
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