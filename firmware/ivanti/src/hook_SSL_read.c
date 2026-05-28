/*
 * hook_SSL_read.c — LD_PRELOAD hook for kAFL fuzzing
 * edit by verf1sh: network-injection mode (SSL_write) with SHM fallback for multi-packet
 *
 * Two modes (auto-selected by agent via g_state->ready):
 *   1. Network injection (ready=0): agent sends fuzz data via SSL_write.
 *      Hook only tracks RELEASE via SSL_write/close interception.
 *   2. SHM injection (ready=1): agent packs data into /kafl_hook_shm.
 *      Hook intercepts SSL_read to inject SHM data, RELEASE on last packet.
 *
 * Network injection is the default — avoids deadlock when web daemon
 * is stuck in orig_SSL_read blocking on the real socket.
 *
 * data[] 布局 (v3, SHM mode only):
 *   [0..3]   magic:  0x4B41464C
 *   [4..7]   packet_count (1-5)
 *   [8..11]  reserved
 *   [12..31] packet_sizes[0..4]
 *   [32..]   concatenated packet data
 *
 * 编译: make hook
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

#define SHM_NAME "/kafl_hook_shm"
#define MAX_PAYLOAD         (1 * 1024 * 1024)
#define SHM_MAGIC           0x4B41464C

/* ---- kAFL hypercall ------------------------------------------------- */
#define HYPERCALL_KAFL_RAX_ID       0x01f
#define HYPERCALL_KAFL_RELEASE      0x04
#define HYPERCALL_KAFL_SUBMIT_CR3   0x05
#define HYPERCALL_KAFL_PANIC        0x08

#define MAX_PACKETS 5

static inline void kAFL_vmcall(unsigned long id, unsigned long arg)
{
    unsigned long nr = HYPERCALL_KAFL_RAX_ID;
    asm volatile (
        "vmcall"
        : "=a"(nr)
        : "a"(nr), "b"(id), "c"(arg)
        : "memory"
    );
}

/* ---- 共享内存 (与 agent 保持一致) -------------------------------------- */
struct hook_state {
    int ready;
    int consumed;
    int size;
    int prefix_phase;
    char data[MAX_PAYLOAD];
};

/* ---- 内嵌在 data[] 中的头部 (v3 SHM 格式) ----------------------------- */
struct shm_header {
    uint32_t magic;
    uint32_t packet_count;
    uint32_t reserved;
    uint32_t packet_sizes[MAX_PACKETS];
};

/* ---- SSL 句柄 -------------------------------------------------------- */
struct ssl_st;
typedef struct ssl_st SSL;

static int (*orig_SSL_read)(SSL *, void *, int) = NULL;
static int (*orig_SSL_write)(SSL *, const void *, int) = NULL;
static int (*orig_close)(int) = NULL;
static struct hook_state *g_state = NULL;

static volatile int cr3_submitted = 0;
static volatile int need_release  = 0;

/* ---- 初始化 ----------------------------------------------------------- */
static void init_shm(void)
{
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd < 0) return;
    if (ftruncate(fd, sizeof(struct hook_state)) < 0) { close(fd); return; }
    g_state = mmap(NULL, sizeof(struct hook_state),
                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (g_state == MAP_FAILED) { g_state = NULL; return; }

    static int done = 0;
    if (!done) { memset(g_state, 0, sizeof(struct hook_state)); done = 1; }
}

static void submit_cr3(void)
{
    if (!cr3_submitted) {
        kAFL_vmcall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
        cr3_submitted = 1;
    }
}

static void do_release(void)
{
    /* During prefix phase, suppress RELEASE.
     * The web daemon's responses to prefix packets would otherwise
     * cause premature RELEASEs that confuse the fuzzer's import
     * processing — making it harvest coverage before the real fuzz
     * payload is sent, leading to "No inputs in queue". */
    if (g_state && g_state->prefix_phase) {
        need_release = 0;
        return;
    }
    need_release = 0;
    kAFL_vmcall(HYPERCALL_KAFL_RELEASE, 0);
    if (g_state) g_state->consumed = 1;
}

static void crash_handler(int sig)
{
    kAFL_vmcall(HYPERCALL_KAFL_PANIC, 0);
    _exit(128 + sig);
}

static void init_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
}

static void reinstall_signals(void)
{
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, NULL, &old);
    if (old.sa_handler != crash_handler) {
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGILL,  &sa, NULL);
        sigaction(SIGBUS,  &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);
        sigaction(SIGFPE,  &sa, NULL);
    }
}

/* ---- SHM 多包注入逻辑 (仅在 ready=1 时激活) -------------------------- */
static int parse_header(struct shm_header *hdr)
{
    if (!g_state || g_state->size < (int)sizeof(struct shm_header))
        return -1;

    const struct shm_header *h = (const struct shm_header *)g_state->data;
    if (h->magic != SHM_MAGIC)
        return -1;
    if (h->packet_count == 0 || h->packet_count > MAX_PACKETS)
        return -1;

    memcpy(hdr, h, sizeof(*hdr));
    return (int)hdr->packet_count;
}

/* ---- Hook 入口 -------------------------------------------------------- */
int SSL_read(SSL *ssl, void *buf, int num)
{
    if (!orig_SSL_read) {
        orig_SSL_read = (int (*)(SSL *, void *, int))
            dlsym(RTLD_NEXT, "SSL_read");
        if (!orig_SSL_read) return -1;
    }

    reinstall_signals();
    submit_cr3();

    /* Network-injection mode: always set need_release so that the next
     * SSL_write or close on the web daemon side triggers RELEASE. */
    need_release = 1;

    /* SHM injection mode (ready=1): intercept and inject from shared memory.
     * Network injection mode (ready=0): pass through to real SSL_read. */
    if (!g_state || !g_state->ready || g_state->consumed || g_state->size <= 0)
        return orig_SSL_read(ssl, buf, num);

    /* ---- SHM injection path (multi-packet, ready=1) ---- */
    struct shm_header hdr;
    int n_packets = parse_header(&hdr);

    if (n_packets > 0) {
        /* v3 multi-packet: consumed field doubles as byte cursor */
        int base = (int)sizeof(struct shm_header);
        int cursor = g_state->consumed - base;
        if (cursor < 0) cursor = 0;

        int pkt_idx = 0, acc = 0, copy_sz = 0;
        for (; pkt_idx < n_packets; pkt_idx++) {
            int pkt_sz = (int)hdr.packet_sizes[pkt_idx];
            if (cursor < acc + pkt_sz) {
                int pkt_off = base + acc;
                copy_sz = pkt_sz < num ? pkt_sz : num;
                memcpy(buf, g_state->data + pkt_off, copy_sz);
                g_state->consumed = pkt_off + pkt_sz;
                break;
            }
            acc += pkt_sz;
        }

        if (pkt_idx >= n_packets || pkt_idx + 1 >= n_packets)
            g_state->consumed = 1;  /* last packet: signal agent */
        return copy_sz > 0 ? copy_sz : 0;
    } else {
        /* v1/v2 single-packet (backward compat) */
        int copy_sz = g_state->size < num ? g_state->size : num;
        memcpy(buf, g_state->data, copy_sz);
        g_state->consumed = 1;
        return copy_sz;
    }
}

/* ---- SSL_write / close ------------------------------------------------- */
int SSL_write(SSL *ssl, const void *buf, int num)
{
    if (!orig_SSL_write) {
        orig_SSL_write = (int (*)(SSL *, const void *, int))
            dlsym(RTLD_NEXT, "SSL_write");
        if (!orig_SSL_write) return -1;
    }
    int ret = orig_SSL_write(ssl, buf, num);
    do_release();
    return ret;
}

int close(int fd)
{
    if (!orig_close) {
        orig_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
        if (!orig_close) orig_close = close;
    }
    int ret = orig_close(fd);
    do_release();
    return ret;
}

__attribute__((constructor)) void init_hook(void)
{
    init_shm();
    init_signals();
    submit_cr3();
}
