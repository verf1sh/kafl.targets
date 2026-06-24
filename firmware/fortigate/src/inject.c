/*
 * inject.c - small x86_64 ptrace dlopen injector.
 *
 * Demo usage:
 *   make
 *   ./test
 *
 * Direct usage:
 *   ./inject <pid|process-name> <path-to-so>
 *
 * When a process name is provided, every matching process is injected.
 * This matters for FortiGate's httpsd prefork model: the agent may connect
 * to any worker, so a single-worker injection is not reliable enough.
 *
 * The implementation intentionally keeps the moving parts visible:
 *   1. find target libc/libdl mapping from /proc/<pid>/maps
 *   2. resolve dlopen/__libc_dlopen_mode from that exact ELF file
 *   3. attach, place the .so path on the target stack
 *   4. call the function with an INT3 return trampoline
 *   5. restore registers and stack bytes before detaching
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hook_common.h"

#define RTLD_LAZY_FLAG          0x1UL
#define GLIBC_RTLD_DLOPEN_FLAG  0x80000000UL
#define TRACE_HTTP_READ_SIZE    0x1f40UL

#define die(fmt, ...) \
    do { fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__); return 1; } while (0)

struct module_info {
    unsigned long base;
    char path[PATH_MAX];
};

struct remote_call_result {
    unsigned long rax;
    int signal;
};

static int pt_attach(pid_t pid);
static void pt_detach(pid_t pid);
static int pt_getregs(pid_t pid, struct user_regs_struct *regs);
static int pt_setregs(pid_t pid, const struct user_regs_struct *regs);
static int pt_read(pid_t pid, unsigned long addr, void *buf, size_t len);
static int pt_write(pid_t pid, unsigned long addr, const void *buf, size_t len);

static int is_stopped_by(int status, int sig)
{
    return WIFSTOPPED(status) && WSTOPSIG(status) == sig;
}

static int find_module(pid_t pid, const char *needle, struct module_info *out)
{
    char maps_path[64];
    char line[1024];

    memset(out, 0, sizeof(*out));
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp) {
        fprintf(stderr, "[-] fopen(%s): %s\n", maps_path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, off = 0, inode = 0;
        char perms[8] = {0};
        char dev[32] = {0};
        char path[PATH_MAX] = {0};

        int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %4095s",
                       &start, &end, perms, &off, dev, &inode, path);
        (void)end;
        (void)dev;
        (void)inode;

        if (n < 7) continue;
        if (!strstr(path, needle)) continue;

        out->base = start - off;
        snprintf(out->path, sizeof(out->path), "%s", path);
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

#ifndef INJECT_NO_MAIN
#define MAX_TARGET_PIDS 256
#define MAX_TRACE_PROCS 512

struct trace_proc {
    pid_t pid;
    int in_syscall;
    long syscall_nr;
    int client_fd;
    int cr3_submitted;
    int pending_read;
    int skip_read;
    unsigned long read_buf;
    unsigned long read_size;
    unsigned long forced_read_len;
    unsigned long forced_payload_len;
    unsigned long forced_http_len;
    int learn_budget;
};

struct trace_ctx {
    struct trace_proc procs[MAX_TRACE_PROCS];
    int count;
    struct hook_state *state;
    int learn_only;
};

static int is_pid_dir_name(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
    }
    return 1;
}

static int proc_matches_name(const char *pid_name, const char *name)
{
    char path[PATH_MAX];
    char comm[256] = {0};

    snprintf(path, sizeof(path), "/proc/%s/comm", pid_name);

    FILE *fp = fopen(path, "r");
    if (fp) {
        if (fgets(comm, sizeof(comm), fp)) {
            comm[strcspn(comm, "\r\n")] = '\0';
            if (strcmp(comm, name) == 0) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_name);
    fp = fopen(path, "r");
    if (fp) {
        char argv0[512] = {0};
        size_t n = fread(argv0, 1, sizeof(argv0) - 1, fp);
        fclose(fp);
        if (n > 0) {
            const char *base = strrchr(argv0, '/');
            base = base ? base + 1 : argv0;
            if (strcmp(base, name) == 0)
                return 1;
        }
    }

    return 0;
}

static int collect_pids_by_name(const char *name, pid_t *out, int max_out)
{
    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (!is_pid_dir_name(ent->d_name)) continue;
        if (!proc_matches_name(ent->d_name, name)) continue;

        struct module_info libc;
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (find_module(pid, "libc.so", &libc) < 0 &&
            find_module(pid, "libc-", &libc) < 0) {
            printf("[*] skipping pid=%d (%s): no libc mapping\n", pid, name);
            continue;
        }

        if (count >= max_out) break;
        out[count++] = pid;
    }

    closedir(proc);
    return count;
}

static int looks_like_number(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
    }
    return 1;
}

static struct trace_proc *trace_find_proc(struct trace_ctx *ctx, pid_t pid)
{
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->procs[i].pid == pid)
            return &ctx->procs[i];
    }
    return NULL;
}

static struct trace_proc *trace_add_proc(struct trace_ctx *ctx, pid_t pid)
{
    struct trace_proc *p = trace_find_proc(ctx, pid);
    if (p)
        return p;
    if (ctx->count >= MAX_TRACE_PROCS) {
        fprintf(stderr, "[-] trace process table full, pid=%d\n", pid);
        return NULL;
    }

    p = &ctx->procs[ctx->count++];
    memset(p, 0, sizeof(*p));
    p->pid = pid;
    p->client_fd = -1;
    return p;
}

static void trace_remove_proc(struct trace_ctx *ctx, pid_t pid)
{
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->procs[i].pid != pid)
            continue;
        ctx->procs[i] = ctx->procs[ctx->count - 1];
        ctx->count--;
        return;
    }
}

static struct hook_state *trace_map_state(void)
{
    char shm_path[sizeof("/dev/shm") + sizeof(SHM_NAME)];
    snprintf(shm_path, sizeof(shm_path), "/dev/shm%s", SHM_NAME);

    int fd = open(shm_path, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        fprintf(stderr, "[-] open(%s): %s\n", shm_path, strerror(errno));
        return NULL;
    }
    if (ftruncate(fd, sizeof(struct hook_state)) < 0) {
        fprintf(stderr, "[-] ftruncate(%s): %s\n", shm_path, strerror(errno));
        close(fd);
        return NULL;
    }

    struct hook_state *state = mmap(NULL, sizeof(struct hook_state),
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (state == MAP_FAILED) {
        fprintf(stderr, "[-] mmap(%s): %s\n", shm_path, strerror(errno));
        return NULL;
    }
    return state;
}

static void trace_format_addr(pid_t pid, unsigned long addr,
                              char *out, size_t out_len)
{
    char maps_path[64];
    char line[1024];
    snprintf(out, out_len, "0x%lx", addr);
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, off = 0, inode = 0;
        char perms[8] = {0};
        char dev[32] = {0};
        char path[PATH_MAX] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %4095s",
                       &start, &end, perms, &off, dev, &inode, path);
        (void)perms;
        (void)dev;
        (void)inode;
        if (n < 6)
            continue;
        if (addr < start || addr >= end)
            continue;
        if (n >= 7)
            snprintf(out, out_len, "0x%lx %s+0x%lx",
                     addr, path, addr - start + off);
        else
            snprintf(out, out_len, "0x%lx [anon]+0x%lx",
                     addr, addr - start + off);
        fclose(fp);
        return;
    }

    fclose(fp);
}

static unsigned long trace_peek_word(pid_t pid, unsigned long addr)
{
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (word == -1 && errno)
        return 0;
    return (unsigned long)word;
}

static const char *trace_syscall_name(long nr)
{
    switch (nr) {
    case SYS_read: return "read";
    case SYS_write: return "write";
    case SYS_close: return "close";
    case SYS_accept: return "accept";
    case SYS_accept4: return "accept4";
    case SYS_recvfrom: return "recvfrom";
    case SYS_sendto: return "sendto";
    case SYS_readv: return "readv";
    case SYS_recvmsg: return "recvmsg";
    case SYS_poll: return "poll";
#ifdef SYS_ppoll
    case SYS_ppoll: return "ppoll";
#endif
#ifdef SYS_epoll_wait
    case SYS_epoll_wait: return "epoll_wait";
#endif
#ifdef SYS_epoll_pwait
    case SYS_epoll_pwait: return "epoll_pwait";
#endif
    case SYS_select: return "select";
    default: return "other";
    }
}

static int is_input_syscall(long nr)
{
    return nr == SYS_read || nr == SYS_recvfrom ||
           nr == SYS_readv || nr == SYS_recvmsg;
}

static int is_trace_injection_read(long nr, unsigned long size)
{
    /*
     * Learned FortiGate httpsd input point:
     *   accept() -> apr_socket_accept() -> ap_unixd_accept()
     *   -> read(client_fd, buf, 0x1f40)
     *
     * Later reads on the same fd with size 0x200 are cleanup/keepalive reads
     * and should not consume a fuzz input.
     */
    return nr == SYS_read && size == TRACE_HTTP_READ_SIZE;
}

static size_t build_logincheck_request(const unsigned char *payload,
                                       size_t payload_len,
                                       unsigned char *out,
                                       size_t out_cap)
{
    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "POST /logincheck HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        payload_len);

    if (header_len <= 0)
        return 0;

    size_t written = 0;
    size_t hlen = (size_t)header_len;
    if (hlen > out_cap)
        hlen = out_cap;
    memcpy(out, header, hlen);
    written += hlen;

    if (written < out_cap) {
        size_t body_len = payload_len;
        if (body_len > out_cap - written)
            body_len = out_cap - written;
        memcpy(out + written, payload, body_len);
        written += body_len;
    }

    return written;
}

static int trace_write_logincheck(pid_t pid, struct trace_proc *proc,
                                  struct user_regs_struct *regs,
                                  struct hook_state *state)
{
    if (!state || !state->ready || state->consumed || state->size <= 0)
        return 0;
    if (!proc->pending_read || proc->read_size == 0)
        return 0;

    size_t payload_len = (size_t)state->size;
    if (payload_len > MAX_PAYLOAD)
        payload_len = MAX_PAYLOAD;

    size_t max_http = payload_len + 256;
    unsigned char *http = malloc(max_http);
    if (!http) {
        fprintf(stderr, "[-] malloc http request failed\n");
        return -1;
    }

    size_t full_len = build_logincheck_request(
        (const unsigned char *)state->data, payload_len, http, max_http);
    size_t write_len = full_len;
    if (write_len > proc->read_size)
        write_len = proc->read_size;

    int rc = 0;
    if (write_len == 0 || pt_write(pid, proc->read_buf, http, write_len) < 0) {
        rc = -1;
        goto out;
    }

    regs->rax = write_len;
    if (pt_setregs(pid, regs) < 0) {
        rc = -1;
        goto out;
    }

    state->read_hits++;
    state->last_api = 20; /* ptrace read syscall injection */
    state->last_read_fd = proc->client_fd;
    state->last_read_size = (int)proc->read_size;
    state->last_copy_size = (int)write_len;
    state->last_payload_size = (int)payload_len;
    state->consumed = 1;
    state->ready = 0;

    printf("[TRACE] pid=%d client_fd=%d read_buf=0x%lx read_size=%lu "
           "payload_len=%zu http_len=%zu wrote=%zu\n",
           pid, proc->client_fd, proc->read_buf, proc->read_size,
           payload_len, full_len, write_len);

out:
    free(http);
    return rc;
}

static int trace_stage_logincheck(pid_t pid, struct trace_proc *proc,
                                  struct hook_state *state)
{
    if (!state || !state->ready || state->consumed || state->size <= 0)
        return 0;
    if (!proc->pending_read || proc->read_size == 0)
        return 0;

    size_t payload_len = (size_t)state->size;
    if (payload_len > MAX_PAYLOAD)
        payload_len = MAX_PAYLOAD;

    size_t max_http = payload_len + 256;
    unsigned char *http = malloc(max_http);
    if (!http) {
        fprintf(stderr, "[-] malloc staged http request failed\n");
        return -1;
    }

    size_t full_len = build_logincheck_request(
        (const unsigned char *)state->data, payload_len, http, max_http);
    size_t write_len = full_len;
    if (write_len > proc->read_size)
        write_len = proc->read_size;

    int rc = 0;
    if (write_len == 0 || pt_write(pid, proc->read_buf, http, write_len) < 0) {
        rc = -1;
        goto out;
    }

    proc->skip_read = 1;
    proc->forced_read_len = (unsigned long)write_len;
    proc->forced_payload_len = (unsigned long)payload_len;
    proc->forced_http_len = (unsigned long)full_len;

    printf("[TRACE] pid=%d staged client_fd=%d read_buf=0x%lx read_size=%lu "
           "payload_len=%zu http_len=%zu wrote=%zu\n",
           pid, proc->client_fd, proc->read_buf, proc->read_size,
           payload_len, full_len, write_len);
    rc = 1;

out:
    free(http);
    return rc;
}

static int trace_finish_skipped_read(pid_t pid, struct trace_proc *proc,
                                     struct user_regs_struct *regs,
                                     struct hook_state *state)
{
    regs->rax = proc->forced_read_len;
    if (pt_setregs(pid, regs) < 0)
        return -1;

    if (state) {
        state->read_hits++;
        state->last_api = 21; /* ptrace read syscall-entry skip injection */
        state->last_read_fd = proc->client_fd;
        state->last_read_size = (int)proc->read_size;
        state->last_copy_size = (int)proc->forced_read_len;
        state->last_payload_size = (int)proc->forced_payload_len;
        state->consumed = 1;
        state->ready = 0;
    }

    printf("[TRACE] pid=%d forced read return client_fd=%d wrote=%lu "
           "http_len=%lu\n",
           pid, proc->client_fd, proc->forced_read_len,
           proc->forced_http_len);

    proc->skip_read = 0;
    proc->forced_read_len = 0;
    proc->forced_payload_len = 0;
    proc->forced_http_len = 0;
    return 0;
}

static int wait_for_int3(pid_t pid, int *status)
{
    int sig = 0;

    for (int i = 0; i < 16; i++) {
        if (ptrace(PTRACE_CONT, pid, 0, (void *)(long)sig) == -1) {
            fprintf(stderr, "[-] PTRACE_CONT(%d): %s\n",
                    pid, strerror(errno));
            return -1;
        }
        if (waitpid(pid, status, __WALL) != pid) {
            fprintf(stderr, "[-] waitpid vmcall(%d): %s\n",
                    pid, strerror(errno));
            return -1;
        }

        if (is_stopped_by(*status, SIGTRAP))
            return 0;
        if (!WIFSTOPPED(*status))
            return -1;

        sig = WSTOPSIG(*status);
        if (sig == SIGCHLD || sig == SIGURG || sig == SIGALRM)
            continue;
        return -1;
    }

    fprintf(stderr, "[-] vmcall stub did not trap back for pid=%d\n", pid);
    return -1;
}

static int remote_submit_cr3(pid_t pid, struct hook_state *state)
{
    struct user_regs_struct saved;
    struct user_regs_struct regs;
    unsigned long code_addr = 0;
    unsigned char saved_code[32];
    int status = 0;
    int rc = -1;

    unsigned char stub[32];
    size_t off = 0;

    /* movabs rax, HYPERCALL_KAFL_RAX_ID */
    stub[off++] = 0x48; stub[off++] = 0xb8;
    *(uint64_t *)(stub + off) = HYPERCALL_KAFL_RAX_ID;
    off += 8;
    /* movabs rbx, HYPERCALL_KAFL_SUBMIT_CR3 */
    stub[off++] = 0x48; stub[off++] = 0xbb;
    *(uint64_t *)(stub + off) = HYPERCALL_KAFL_SUBMIT_CR3;
    off += 8;
    /* rcx = ~0ULL: update decoder CR3 from this worker, but do not
     * enable PT CR3 filtering.  FortiGate has multiple httpsd workers,
     * so a single CR3 filter would randomly hide coverage. */
    stub[off++] = 0x31; stub[off++] = 0xc9;
    stub[off++] = 0x48; stub[off++] = 0xff; stub[off++] = 0xc9;
    /* vmcall; int3 */
    stub[off++] = 0x0f; stub[off++] = 0x01; stub[off++] = 0xc1;
    stub[off++] = 0xcc;

    if (pt_getregs(pid, &saved) < 0)
        return -1;

    regs = saved;
    code_addr = saved.rip;
    if (pt_read(pid, code_addr, saved_code, off) < 0)
        return -1;
    if (pt_write(pid, code_addr, stub, off) < 0)
        goto out_restore;

    regs.rip = code_addr;
    if (pt_setregs(pid, &regs) < 0)
        goto out_restore;

    if (wait_for_int3(pid, &status) < 0)
        goto out_restore;
    if (!is_stopped_by(status, SIGTRAP)) {
        fprintf(stderr, "[-] submit CR3 stopped unexpectedly pid=%d status=0x%x\n",
                pid, status);
        goto out_restore;
    }

    if (state)
        state->cr3_submits++;
    printf("[TRACE] submitted CR3 from pid=%d\n", pid);
    rc = 0;

out_restore:
    (void)pt_write(pid, code_addr, saved_code, off);
    (void)pt_setregs(pid, &saved);
    return rc;
}

static int trace_attach_one(struct trace_ctx *ctx, pid_t pid)
{
    if (trace_find_proc(ctx, pid))
        return 0;

    if (pt_attach(pid) < 0)
        return -1;

    long opts = PTRACE_O_TRACESYSGOOD |
                PTRACE_O_TRACEFORK |
                PTRACE_O_TRACEVFORK |
                PTRACE_O_TRACECLONE;
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)opts) == -1) {
        fprintf(stderr, "[-] PTRACE_SETOPTIONS(%d): %s\n",
                pid, strerror(errno));
        pt_detach(pid);
        return -1;
    }

    struct trace_proc *p = trace_add_proc(ctx, pid);
    if (!p) {
        pt_detach(pid);
        return -1;
    }

    struct user_regs_struct regs;
    if (pt_getregs(pid, &regs) == 0 &&
        (regs.orig_rax == SYS_accept || regs.orig_rax == SYS_accept4)) {
        p->in_syscall = 1;
        p->syscall_nr = (long)regs.orig_rax;
        printf("[TRACE] pid=%d attached while in accept syscall\n", pid);
    }

    printf("[TRACE] attached pid=%d\n", pid);
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        fprintf(stderr, "[-] PTRACE_SYSCALL(%d): %s\n",
                pid, strerror(errno));
        return -1;
    }
    return 0;
}

static void trace_handle_syscall(struct trace_ctx *ctx, pid_t pid)
{
    struct trace_proc *proc = trace_find_proc(ctx, pid);
    if (!proc)
        proc = trace_add_proc(ctx, pid);
    if (!proc)
        return;

    struct user_regs_struct regs;
    if (pt_getregs(pid, &regs) < 0)
        return;

    /*
     * On x86_64, syscall-enter stops normally expose rax=-ENOSYS while
     * orig_rax holds the syscall number.  This is more robust than toggling a
     * boolean when we attach to a process that may already be blocked inside a
     * syscall (accept/poll/read).
     */
    int is_enter = ((long)regs.rax == -ENOSYS);
    if (proc->skip_read && proc->in_syscall)
        is_enter = 0;

    if (is_enter) {
        proc->in_syscall = 1;
        proc->syscall_nr = (long)regs.orig_rax;
        proc->pending_read = 0;

        if (ctx->learn_only && proc->learn_budget > 0) {
            char rip_desc[PATH_MAX + 128];
            trace_format_addr(pid, regs.rip, rip_desc, sizeof(rip_desc));
            printf("[LEARN] pid=%d syscall enter nr=%ld(%s) "
                   "rdi=0x%llx rsi=0x%llx rdx=0x%llx rip=%s\n",
                   pid, (long)regs.orig_rax,
                   trace_syscall_name((long)regs.orig_rax),
                   (unsigned long long)regs.rdi,
                   (unsigned long long)regs.rsi,
                   (unsigned long long)regs.rdx,
                   rip_desc);
            proc->learn_budget--;
        }

        int is_client_input = is_input_syscall((long)regs.orig_rax) &&
                              proc->client_fd >= 0 &&
                              (int)regs.rdi == proc->client_fd;
        int should_inject = is_trace_injection_read((long)regs.orig_rax,
                                                    (unsigned long)regs.rdx);

        if (is_client_input && (ctx->learn_only || should_inject)) {
            proc->pending_read = 1;
            proc->read_buf = regs.rsi;
            proc->read_size = regs.rdx;
            if (ctx->learn_only) {
                unsigned long ret_addr = trace_peek_word(pid, regs.rsp);
                char rip_desc[PATH_MAX + 128];
                char ret_desc[PATH_MAX + 128];
                trace_format_addr(pid, regs.rip, rip_desc, sizeof(rip_desc));
                trace_format_addr(pid, ret_addr, ret_desc, sizeof(ret_desc));
                printf("[LEARN] pid=%d %s enter fd=%d buf=0x%lx size=0x%lx "
                       "rip=%s rsp=0x%llx ret=%s\n",
                       pid, trace_syscall_name((long)regs.orig_rax),
                       proc->client_fd, proc->read_buf, proc->read_size,
                       rip_desc, (unsigned long long)regs.rsp, ret_desc);
            } else {
                printf("[TRACE] pid=%d %s enter client_fd=%d buf=0x%lx size=%lu\n",
                       pid, trace_syscall_name((long)regs.orig_rax),
                       proc->client_fd, proc->read_buf, proc->read_size);
                if (trace_stage_logincheck(pid, proc, ctx->state) > 0) {
                    regs.orig_rax = -1UL; /* skip the blocking kernel read */
                    regs.rax = 0;
                    if (pt_setregs(pid, &regs) < 0)
                        fprintf(stderr, "[!] failed to skip read syscall pid=%d\n", pid);
                }
            }
        }
        return;
    }

    proc->in_syscall = 0;
    if ((proc->syscall_nr == SYS_accept || proc->syscall_nr == SYS_accept4) &&
        (long)regs.rax >= 0) {
        proc->client_fd = (int)regs.rax;
        if (ctx->learn_only)
            proc->learn_budget = 32;
        if (ctx->learn_only) {
            char rip_desc[PATH_MAX + 128];
            trace_format_addr(pid, regs.rip, rip_desc, sizeof(rip_desc));
            printf("[LEARN] pid=%d accept exit client_fd=%d rip=%s\n",
                   pid, proc->client_fd, rip_desc);
        } else {
            printf("[TRACE] pid=%d accept exit client_fd=%d\n",
                   pid, proc->client_fd);
        }
        if (!ctx->learn_only && !proc->cr3_submitted) {
            if (remote_submit_cr3(pid, ctx->state) == 0)
                proc->cr3_submitted = 1;
            else
                fprintf(stderr, "[!] failed to submit CR3 from pid=%d\n", pid);
        }
    } else if (is_input_syscall(proc->syscall_nr) && proc->pending_read) {
        if (ctx->learn_only) {
            printf("[LEARN] pid=%d %s exit fd=%d ret=%lld expected_size=0x%lx\n",
                   pid, trace_syscall_name(proc->syscall_nr), proc->client_fd,
                   (long long)regs.rax, proc->read_size);
        } else if (proc->skip_read) {
            (void)trace_finish_skipped_read(pid, proc, &regs, ctx->state);
        } else if (proc->syscall_nr == SYS_read && (long)regs.rax >= 0) {
            (void)trace_write_logincheck(pid, proc, &regs, ctx->state);
        }
        proc->pending_read = 0;
    }
}

static int run_trace_loop(struct trace_ctx *ctx)
{
    while (ctx->count > 0) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[-] waitpid trace: %s\n", strerror(errno));
            return 1;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("[TRACE] pid=%d exited\n", pid);
            trace_remove_proc(ctx, pid);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
                trace_remove_proc(ctx, pid);
            continue;
        }

        int sig = WSTOPSIG(status);
        unsigned event = (unsigned)status >> 16;

        if (event == PTRACE_EVENT_FORK ||
            event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long child = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child) == 0 &&
                child > 0) {
                (void)trace_add_proc(ctx, (pid_t)child);
                printf("[TRACE] pid=%d spawned child=%lu\n", pid, child);
                (void)ptrace(PTRACE_SETOPTIONS, (pid_t)child, 0,
                              (void *)(PTRACE_O_TRACESYSGOOD |
                                        PTRACE_O_TRACEFORK |
                                        PTRACE_O_TRACEVFORK |
                                        PTRACE_O_TRACECLONE));
                (void)ptrace(PTRACE_SYSCALL, (pid_t)child, 0, 0);
            }
            sig = 0;
        } else if (sig == (SIGTRAP | 0x80)) {
            trace_handle_syscall(ctx, pid);
            sig = 0;
        } else if (sig == SIGTRAP || sig == SIGSTOP) {
            sig = 0;
        }

        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(long)sig) == -1) {
            if (errno != ESRCH)
                fprintf(stderr, "[-] PTRACE_SYSCALL(%d): %s\n",
                        pid, strerror(errno));
            trace_remove_proc(ctx, pid);
        }
    }
    return 0;
}

static int do_trace(pid_t *pids, int count, int learn_only)
{
    struct trace_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.learn_only = learn_only;
    if (!learn_only)
        ctx.state = trace_map_state();
    if (!learn_only && !ctx.state)
        return 1;

    int ok = 0;
    int fail = 0;
    for (int i = 0; i < count; i++) {
        if (trace_attach_one(&ctx, pids[i]) == 0)
            ok++;
        else
            fail++;
    }
    if (ok == 0) {
        fprintf(stderr, "[-] no trace targets attached\n");
        return 1;
    }
    if (fail > 0) {
        fprintf(stderr, "[-] only attached %d/%d targets; aborting to avoid "
                "untraced httpsd workers stealing requests\n", ok, count);
        for (int i = 0; i < ctx.count; i++)
            pt_detach(ctx.procs[i].pid);
        return 1;
    }

    printf("[%s] tracing %d process(es)\n",
           learn_only ? "LEARN" : "TRACE", ok);
    return run_trace_loop(&ctx);
}
#endif

static unsigned long elf_dynsym(const char *path, const char *name)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return 0;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0;

    unsigned long value = 0;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_shoff == 0 || eh->e_shnum == 0 ||
        eh->e_shstrndx == SHN_UNDEF) {
        munmap(map, st.st_size);
        return 0;
    }

    Elf64_Shdr *sh = (Elf64_Shdr *)((char *)map + eh->e_shoff);
    if ((char *)&sh[eh->e_shnum] > (char *)map + st.st_size) {
        munmap(map, st.st_size);
        return 0;
    }

    const char *shstr = (const char *)map + sh[eh->e_shstrndx].sh_offset;
    Elf64_Shdr *dynsym = NULL;
    Elf64_Shdr *dynstr = NULL;

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *sec = shstr + sh[i].sh_name;
        if (strcmp(sec, ".dynsym") == 0) dynsym = &sh[i];
        if (strcmp(sec, ".dynstr") == 0) dynstr = &sh[i];
    }

    if (dynsym && dynstr) {
        Elf64_Sym *sym = (Elf64_Sym *)((char *)map + dynsym->sh_offset);
        const char *strtab = (const char *)map + dynstr->sh_offset;
        int count = dynsym->sh_size / sizeof(Elf64_Sym);

        for (int i = 0; i < count; i++) {
            const char *sym_name = strtab + sym[i].st_name;
            if (strcmp(sym_name, name) == 0) {
                value = sym[i].st_value;
                break;
            }
        }
    }

    munmap(map, st.st_size);
    return value;
}

static int pt_attach(pid_t pid)
{
    int status = 0;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        fprintf(stderr, "[-] PTRACE_ATTACH(%d): %s\n", pid, strerror(errno));
        return -1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        fprintf(stderr, "[-] waitpid attach: %s\n", strerror(errno));
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] target did not stop after attach, status=0x%x\n", status);
        return -1;
    }
    return 0;
}

static void pt_detach(pid_t pid)
{
    ptrace(PTRACE_DETACH, pid, 0, 0);
}

static int pt_getregs(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        fprintf(stderr, "[-] PTRACE_GETREGS: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int pt_setregs(pid_t pid, const struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        fprintf(stderr, "[-] PTRACE_SETREGS: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int pt_read(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    for (size_t i = 0; i < len; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, 0);
        if (word == -1 && errno) {
            fprintf(stderr, "[-] PEEKDATA 0x%lx: %s\n", addr + i, strerror(errno));
            return -1;
        }
        size_t n = len - i < sizeof(long) ? len - i : sizeof(long);
        memcpy((char *)buf + i, &word, n);
    }
    return 0;
}

static int pt_write(pid_t pid, unsigned long addr, const void *buf, size_t len)
{
    for (size_t i = 0; i < len; i += sizeof(long)) {
        unsigned long word = 0;
        size_t n = len - i < sizeof(long) ? len - i : sizeof(long);

        if (n != sizeof(long) && pt_read(pid, addr + i, &word, sizeof(word)) < 0)
            return -1;
        memcpy(&word, (const char *)buf + i, n);

        if (ptrace(PTRACE_POKEDATA, pid, addr + i, (void *)word) == -1) {
            fprintf(stderr, "[-] POKEDATA 0x%lx: %s\n", addr + i, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int wait_after_continue(pid_t pid, int *status)
{
    int sig = 0;

    for (int i = 0; i < 16; i++) {
        if (ptrace(PTRACE_CONT, pid, 0, (void *)(long)sig) == -1) {
            fprintf(stderr, "[-] PTRACE_CONT: %s\n", strerror(errno));
            return -1;
        }
        if (waitpid(pid, status, 0) != pid) {
            fprintf(stderr, "[-] waitpid continue: %s\n", strerror(errno));
            return -1;
        }

        if (is_stopped_by(*status, SIGTRAP))
            return 0;

        if (!WIFSTOPPED(*status))
            return 0;

        sig = WSTOPSIG(*status);
        if (sig == SIGCHLD || sig == SIGURG || sig == SIGALRM) {
            fprintf(stderr, "[*] remote call interrupted by signal %d, continuing\n", sig);
            continue;
        }

        return 0;
    }

    fprintf(stderr, "[-] remote call did not reach trampoline after signal storm\n");
    return -1;
}

static int remote_call2(pid_t pid, unsigned long fn,
                        unsigned long arg1, unsigned long arg2,
                        struct remote_call_result *out)
{
    struct user_regs_struct saved;
    struct user_regs_struct regs;
    unsigned long code_addr = 0;
    unsigned long saved_code_word = 0;
    int status = 0;
    int rc = -1;
    const unsigned char stub[] = {
        0xff, 0xd0, /* call *%rax */
        0xcc        /* int3 */
    };

    memset(out, 0, sizeof(*out));

    if (pt_getregs(pid, &saved) < 0) return -1;
    regs = saved;

    /*
     * Patch a tiny call stub at the stopped RIP instead of faking a return
     * address.  On CET/shadow-stack systems, a real CALL is important:
     * writing a synthetic return address on the normal stack can make the
     * callee's RET fault even though the function body already succeeded.
     */
    code_addr = saved.rip;
    if (pt_read(pid, code_addr, &saved_code_word, sizeof(saved_code_word)) < 0)
        return -1;

    if (pt_write(pid, code_addr, stub, sizeof(stub)) < 0)
        goto out_restore;

    regs.rip = code_addr;
    regs.rsp = saved.rsp & ~0xfUL;
    regs.rax = fn;
    regs.rdi = arg1;
    regs.rsi = arg2;

    if (pt_setregs(pid, &regs) < 0)
        goto out_restore;

    if (wait_after_continue(pid, &status) < 0)
        goto out_restore;

    if (!is_stopped_by(status, SIGTRAP)) {
        out->signal = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
        fprintf(stderr, "[-] remote call stopped unexpectedly, status=0x%x sig=%d\n",
                status, out->signal);
        goto out_restore;
    }

    if (pt_getregs(pid, &regs) < 0)
        goto out_restore;

    out->rax = regs.rax;
    out->signal = SIGTRAP;
    rc = 0;

out_restore:
    (void)pt_write(pid, code_addr, &saved_code_word, sizeof(saved_code_word));
    (void)pt_setregs(pid, &saved);
    return rc;
}

static int resolve_dlopen(pid_t pid, unsigned long *addr, unsigned long *flags,
                          char *where, size_t where_len)
{
    struct module_info libc;
    struct module_info libdl;
    unsigned long off = 0;

    if (find_module(pid, "libc.so", &libc) < 0 &&
        find_module(pid, "libc-", &libc) < 0) {
        fprintf(stderr, "[-] target libc mapping not found\n");
        return -1;
    }

    off = elf_dynsym(libc.path, "dlopen");
    if (off) {
        *addr = libc.base + off;
        *flags = RTLD_LAZY_FLAG;
        snprintf(where, where_len, "%s:dlopen base=0x%lx off=0x%lx",
                 libc.path, libc.base, off);
        return 0;
    }

    off = elf_dynsym(libc.path, "__libc_dlopen_mode");
    if (off) {
        *addr = libc.base + off;
        *flags = RTLD_LAZY_FLAG | GLIBC_RTLD_DLOPEN_FLAG;
        snprintf(where, where_len, "%s:__libc_dlopen_mode base=0x%lx off=0x%lx",
                 libc.path, libc.base, off);
        return 0;
    }

    if (find_module(pid, "libdl.so", &libdl) == 0) {
        off = elf_dynsym(libdl.path, "dlopen");
        if (off) {
            *addr = libdl.base + off;
            *flags = RTLD_LAZY_FLAG;
            snprintf(where, where_len, "%s:dlopen base=0x%lx off=0x%lx",
                     libdl.path, libdl.base, off);
            return 0;
        }
    }

    fprintf(stderr, "[-] neither dlopen nor __libc_dlopen_mode was found\n");
    return -1;
}

static int target_has_mapping(pid_t pid, const char *needle)
{
    char maps_path[64];
    char line[1024];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, needle)) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int do_inject(pid_t pid, const char *so_path)
{
    char abs_so[PATH_MAX];
    char resolved[PATH_MAX];
    char dlopen_where[PATH_MAX + 128];
    unsigned long dlopen_addr = 0;
    unsigned long dlopen_flags = 0;
    struct user_regs_struct regs;
    unsigned long path_addr = 0;
    size_t path_len = 0;
    unsigned char saved_path[PATH_MAX];
    struct remote_call_result call;
    int attached = 0;
    int ret = 1;

    if (!so_path || !*so_path) {
        fprintf(stderr, "[-] empty .so path\n");
        return 1;
    }

    if (!realpath(so_path, resolved)) {
        fprintf(stderr, "[-] realpath(%s): %s\n", so_path, strerror(errno));
        return 1;
    }
    snprintf(abs_so, sizeof(abs_so), "%s", resolved);
    path_len = strlen(abs_so) + 1;
    if (path_len > sizeof(saved_path)) {
        fprintf(stderr, "[-] .so path too long\n");
        return 1;
    }

    if (target_has_mapping(pid, abs_so)) {
        printf("[+] target pid:   %d\n", pid);
        printf("[+] target .so:   %s\n", abs_so);
        printf("[+] already mapped, skipping\n");
        return 0;
    }

    if (resolve_dlopen(pid, &dlopen_addr, &dlopen_flags,
                       dlopen_where, sizeof(dlopen_where)) < 0)
        return 1;

    printf("[+] target pid:   %d\n", pid);
    printf("[+] target .so:   %s\n", abs_so);
    printf("[+] resolver:     %s\n", dlopen_where);
    printf("[+] dlopen addr:  0x%lx flags=0x%lx\n", dlopen_addr, dlopen_flags);

    if (pt_attach(pid) < 0)
        return 1;
    attached = 1;

    if (pt_getregs(pid, &regs) < 0)
        goto out;

    path_addr = (regs.rsp - 0x4000) & ~0xFUL;
    if (pt_read(pid, path_addr, saved_path, path_len) < 0)
        goto out;
    if (pt_write(pid, path_addr, abs_so, path_len) < 0)
        goto out;

    printf("[*] path written: 0x%lx\n", path_addr);
    if (remote_call2(pid, dlopen_addr, path_addr, dlopen_flags, &call) < 0)
        goto out_restore_path;

    printf("[*] return rax:   0x%lx\n", call.rax);
    if (call.rax == 0) {
        fprintf(stderr, "[-] dlopen returned NULL\n");
        goto out_restore_path;
    }

    if (!target_has_mapping(pid, abs_so)) {
        fprintf(stderr, "[-] dlopen returned non-NULL, but mapping was not found\n");
        goto out_restore_path;
    }

    printf("[+] mapped:       %s\n", abs_so);
    ret = 0;

out_restore_path:
    (void)pt_write(pid, path_addr, saved_path, path_len);
out:
    if (attached)
        pt_detach(pid);
    return ret;
}

#ifndef INJECT_NO_MAIN
int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc == 3 && (strcmp(argv[1], "--trace") == 0 ||
                      strcmp(argv[1], "--learn") == 0)) {
        pid_t pids[MAX_TARGET_PIDS];
        int count = 0;
        int learn_only = (strcmp(argv[1], "--learn") == 0);

        if (looks_like_number(argv[2])) {
            pids[0] = (pid_t)atoi(argv[2]);
            count = 1;
        } else {
            count = collect_pids_by_name(argv[2], pids, MAX_TARGET_PIDS);
        }

        if (count <= 0)
            die("%s target not found: %s",
                learn_only ? "learn" : "trace", argv[2]);

        printf("[%s] matched %d process(es) for '%s'\n",
               learn_only ? "LEARN" : "TRACE", count, argv[2]);
        return do_trace(pids, count, learn_only);
    }

    if (argc != 3)
        die("usage: %s <pid|process-name> <path-to-so>\n"
            "       %s --trace <pid|process-name>\n"
            "       %s --learn <pid|process-name>",
            argv[0], argv[0], argv[0]);

    if (looks_like_number(argv[1])) {
        return do_inject((pid_t)atoi(argv[1]), argv[2]);
    }

    pid_t pids[MAX_TARGET_PIDS];
    int count = collect_pids_by_name(argv[1], pids, MAX_TARGET_PIDS);
    if (count <= 0)
        die("process not found: %s", argv[1]);

    printf("[*] matched %d process(es) for '%s'\n", count, argv[1]);
    int ok = 0;
    int fail = 0;
    for (int i = 0; i < count; i++) {
        printf("\n[*] injecting target %d/%d pid=%d\n", i + 1, count, pids[i]);
        if (do_inject(pids[i], argv[2]) == 0)
            ok++;
        else
            fail++;
    }

    printf("\n[*] injection summary: ok=%d fail=%d\n", ok, fail);
    return ok > 0 ? 0 : 1;
}
#endif
