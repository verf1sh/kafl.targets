/*
 * hook.c - minimal FortiGate httpsd hook.
 *
 * Keep only the path we have confirmed dynamically:
 *
 *   accept()/accept4() -> remember client fd
 *   read(client_fd)    -> kAFL in-target payload injection
 *
 * No recv/readv/write/send/close/syscall hooks, no command-injection helpers.
 * This is intentionally narrow so manual debugging can answer one question:
 * does the accepted httpsd client fd reach our read() hook?
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#if defined(__has_include)
# if __has_include(<nyx_api.h>)
#  include <nyx_api.h>
# endif
#endif

#include "hook_common.h"

#define HOOK_ENABLE_PATH "/dev/shm/kafl_hook_enable"

/*
 * kafl.yaml already provides the stable httpsd text range as ip0.  Submitting
 * the same executable mapping again from the hook creates overlapping PT
 * ranges and makes libxdc abort during NEXT_PAYLOAD initialization.
 */
#ifndef HOOK_SUBMIT_TEXT_RANGES
#define HOOK_SUBMIT_TEXT_RANGES 0
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef HYPERCALL_KAFL_ACQUIRE
#define HYPERCALL_KAFL_ACQUIRE          0
#endif
#ifndef HYPERCALL_KAFL_GET_PAYLOAD
#define HYPERCALL_KAFL_GET_PAYLOAD      1
#endif
#ifndef HYPERCALL_KAFL_USER_SUBMIT_MODE
#define HYPERCALL_KAFL_USER_SUBMIT_MODE 17
#endif
#ifndef HYPERCALL_KAFL_GET_HOST_CONFIG
#define HYPERCALL_KAFL_GET_HOST_CONFIG  35
#endif
#ifndef HYPERCALL_KAFL_SET_AGENT_CONFIG
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36
#endif
#ifndef HYPERCALL_KAFL_NEXT_PAYLOAD
#define HYPERCALL_KAFL_NEXT_PAYLOAD     12
#endif
#ifndef HYPERCALL_KAFL_RANGE_SUBMIT
#define HYPERCALL_KAFL_RANGE_SUBMIT     29
#endif
#ifndef HYPERCALL_KAFL_PRINTF
#define HYPERCALL_KAFL_PRINTF           13
#endif
#ifndef KAFL_MODE_64
#define KAFL_MODE_64                    0
#endif
#ifndef NYX_AGENT_MAGIC
#define NYX_AGENT_MAGIC                 0x4178794e
#endif
#ifndef NYX_AGENT_VERSION
#define NYX_AGENT_VERSION               1
#endif
#ifndef HPRINTF_MAX_SIZE
#define HPRINTF_MAX_SIZE                0x1000
#endif

#ifndef NYX_API_H
typedef struct {
    int32_t size;
    uint8_t data[];
} kAFL_payload;

typedef struct {
    uint32_t host_magic;
    uint32_t host_version;
    uint32_t bitmap_size;
    uint32_t ijon_bitmap_size;
    uint32_t payload_buffer_size;
    uint32_t worker_id;
} __attribute__((packed)) host_config_t;

typedef struct {
    uint32_t agent_magic;
    uint32_t agent_version;
    uint8_t agent_timeout_detection;
    uint8_t agent_tracing;
    uint8_t agent_ijon_tracing;
    uint8_t agent_non_reload_mode;
    uint64_t trace_buffer_vaddr;
    uint64_t ijon_trace_buffer_vaddr;
    uint32_t coverage_bitmap_size;
    uint32_t input_buffer_size;
    uint8_t dump_payloads;
} __attribute__((packed)) agent_config_t;

static inline uint64_t kAFL_hypercall(uint64_t id, uint64_t arg)
{
    uint64_t nr = HYPERCALL_KAFL_RAX_ID;
    asm volatile ("vmcall"
                  : "=a"(nr)
                  : "a"(nr), "b"(id), "c"(arg)
                  : "memory");
    return nr;
}

static void hprintf(const char *fmt, ...) __attribute__((unused));
static void hprintf(const char *fmt, ...)
{
    static char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(hprintf_buffer, sizeof(hprintf_buffer), fmt, ap);
    va_end(ap);
    kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
}
#endif

ssize_t read(int fd, void *buf, size_t count);
ssize_t __read(int fd, void *buf, size_t count);
ssize_t __libc_read(int fd, void *buf, size_t count);
int accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags);

static ssize_t hook_read_impl(int fd, void *buf, size_t count);
static int hook_accept_impl(int fd, struct sockaddr *addr, socklen_t *addrlen);
static int hook_accept4_impl(int fd, struct sockaddr *addr,
                             socklen_t *addrlen, int flags);

static struct hook_state *g_state;
static int g_is_httpsd;
static int g_client_fd = -1;
static int g_setup_done;
static int g_iter_active;
static int g_cursor;
static int g_first_read_logged;
static volatile int g_cr3_submitted;
static kAFL_payload *g_payload;
static uint32_t g_payload_cap;

static long raw_syscall6(long nr, unsigned long a1, unsigned long a2,
                         unsigned long a3, unsigned long a4,
                         unsigned long a5, unsigned long a6)
{
    long ret;
    register unsigned long r10 asm("r10") = a4;
    register unsigned long r8  asm("r8")  = a5;
    register unsigned long r9  asm("r9")  = a6;

    asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    if (ret < 0 && ret >= -4095) {
        errno = (int)-ret;
        return -1;
    }
    return ret;
}

static long raw_syscall3(long nr, unsigned long a1,
                         unsigned long a2, unsigned long a3)
{
    return raw_syscall6(nr, a1, a2, a3, 0, 0, 0);
}

static int buffer_contains(const char *buf, ssize_t n, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (n <= 0 || needle_len == 0 || (size_t)n < needle_len)
        return 0;
    for (ssize_t i = 0; i <= n - (ssize_t)needle_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0)
            return 1;
    }
    return 0;
}

static int is_httpsd_process(void)
{
    int f = open("/proc/self/comm", O_RDONLY);
    if (f >= 0) {
        char comm[64];
        ssize_t n = raw_syscall3(SYS_read, (unsigned long)f,
                                 (unsigned long)comm, sizeof(comm));
        raw_syscall3(SYS_close, (unsigned long)f, 0, 0);
        if (buffer_contains(comm, n, "httpsd"))
            return 1;
    }

    f = open("/proc/self/cmdline", O_RDONLY);
    if (f < 0)
        return 0;
    char cmdline[256];
    ssize_t n = raw_syscall3(SYS_read, (unsigned long)f,
                             (unsigned long)cmdline, sizeof(cmdline));
    raw_syscall3(SYS_close, (unsigned long)f, 0, 0);
    return buffer_contains(cmdline, n, "httpsd");
}

static int is_socket_fd(int fd)
{
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0)
        return 0;
    return S_ISSOCK(st.st_mode) ? 1 : 0;
}

static int kafl_enabled(void)
{
    return raw_syscall3(SYS_access, (unsigned long)HOOK_ENABLE_PATH, F_OK, 0) == 0;
}

static void init_shm(void)
{
    char shm_path[sizeof("/dev/shm") + sizeof(SHM_NAME)];
    snprintf(shm_path, sizeof(shm_path), "/dev/shm%s", SHM_NAME);

    int fd = open(shm_path, O_CREAT | O_RDWR, 0666);
    if (fd < 0)
        return;
    if (ftruncate(fd, sizeof(struct hook_state)) < 0) {
        raw_syscall3(SYS_close, (unsigned long)fd, 0, 0);
        return;
    }
    g_state = mmap(NULL, sizeof(struct hook_state),
                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    raw_syscall3(SYS_close, (unsigned long)fd, 0, 0);
    if (g_state == MAP_FAILED)
        g_state = NULL;
}

static void *alloc_resident(size_t pages)
{
    size_t sz = pages * PAGE_SIZE;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    memset(p, 0x42, sz);
    mlock(p, sz);
    return p;
}

#if HOOK_SUBMIT_TEXT_RANGES
static unsigned long parse_hex(const char *s)
{
    unsigned long v = 0;
    for (; *s; s++) {
        char c = *s;
        unsigned d;
        if (c >= '0' && c <= '9')
            d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            d = (unsigned)(c - 'A' + 10);
        else
            break;
        v = (v << 4) | d;
    }
    return v;
}

static void hrange_submit_local(unsigned id, uintptr_t start, uintptr_t end)
{
    uint64_t nr = HYPERCALL_KAFL_RAX_ID;
    asm volatile (
        "vmcall"
        : "=a"(nr)
        : "a"(nr),
          "b"((uint64_t)HYPERCALL_KAFL_RANGE_SUBMIT),
          "c"((uint64_t)id),
          "d"((uint64_t)start),
          "S"((uint64_t)end)
        : "memory"
    );
}

static void submit_self_text_ranges(void)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        hprintf("[HOOK] cannot open /proc/self/maps\n");
        return;
    }

    char line[512];
    unsigned id = 1;
    while (id <= 3 && fgets(line, sizeof(line), maps)) {
        char *dash = strchr(line, '-');
        if (!dash)
            continue;
        char *sp = strchr(dash, ' ');
        if (!sp)
            continue;
        const char *perms = sp + 1;
        if (perms[2] != 'x')
            continue;
        if (!strstr(line, "/httpsd") && !strstr(line, "/bin/init"))
            continue;

        unsigned long start = parse_hex(line);
        unsigned long end = parse_hex(dash + 1);
        if (start == 0 || end <= start)
            continue;
        hprintf("[HOOK] PT ip%u=0x%lx-0x%lx\n", id, start, end);
        hrange_submit_local(id, (uintptr_t)start, (uintptr_t)end);
        id++;
    }
    fclose(maps);
}
#endif

static void submit_cr3_once(void)
{
    if (!g_cr3_submitted) {
        kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
        g_cr3_submitted = 1;
        if (g_state)
            g_state->cr3_submits++;
    }
}

static void kafl_setup(void)
{
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    host_config_t host_config;
    memset(&host_config, 0, sizeof(host_config));
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

    agent_config_t agent_config;
    memset(&agent_config, 0, sizeof(agent_config));
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;
    agent_config.coverage_bitmap_size = host_config.bitmap_size;
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    g_payload_cap = host_config.payload_buffer_size;
    size_t pages = (g_payload_cap + PAGE_SIZE - 1) / PAGE_SIZE;
    g_payload = alloc_resident(pages);
    if (!g_payload) {
        hprintf("[HOOK] payload alloc failed cap=%u\n", g_payload_cap);
        return;
    }
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)g_payload);

#if HOOK_SUBMIT_TEXT_RANGES
    submit_self_text_ranges();
#else
    hprintf("[HOOK] PT range submit skipped; using kafl.yaml ip0\n");
#endif
    submit_cr3_once();

    if (g_state)
        g_state->last_payload_size = (int)g_payload_cap;
    hprintf("[HOOK] setup done pid=%d fd=%d payload_cap=%u bitmap=%u\n",
            (int)getpid(), g_client_fd, g_payload_cap, host_config.bitmap_size);
}

static void crash_handler(int sig)
{
    if (g_state && g_state->crash_reason == CRASH_NONE)
        g_state->crash_reason = CRASH_REAL;
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
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

static ssize_t fuzz_read(int fd, void *buf, size_t count, int *handled)
{
    *handled = 0;
    if (!g_is_httpsd)
        return 0;

    if (!g_iter_active) {
        int is_sock = is_socket_fd(fd);
        if (is_sock && g_state)
            g_state->sock_read_calls++;

        if (g_client_fd >= 0) {
            if (fd != g_client_fd)
                return 0;
        } else {
            if (!is_sock)
                return 0;
            g_client_fd = fd;
        }

        if (!g_first_read_logged)
            g_first_read_logged = 1;

        if (!kafl_enabled())
            return 0;

        if (!g_setup_done) {
            kafl_setup();
            g_setup_done = 1;
        }

        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        g_iter_active = 1;
        g_cursor = 0;
        if (g_state) {
            g_state->snapshot_taken = 1;
            g_state->crash_reason = CRASH_NONE;
        }
    } else if (fd != g_client_fd) {
        return 0;
    }

    *handled = 1;

    int sz = g_payload ? g_payload->size : 0;
    if (sz < 0)
        sz = 0;
    int max_in = (int)g_payload_cap - (int)sizeof(int32_t);
    if (max_in < 0)
        max_in = 0;
    if (sz > max_in)
        sz = max_in;

    int remain = sz - g_cursor;
    if (remain <= 0) {
        if (g_state) {
            g_state->consumed = 1;
            g_state->release_hits++;
        }
        g_iter_active = 0;
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
        return 0;
    }

    int n = remain < (int)count ? remain : (int)count;
    memcpy(buf, g_payload->data + g_cursor, (size_t)n);
    g_cursor += n;

    if (g_state) {
        g_state->read_hits++;
        g_state->last_read_fd = fd;
        g_state->last_read_size = (int)count;
        g_state->last_copy_size = n;
        g_state->last_payload_size = sz;
        g_state->last_api = 1;
    }
    return n;
}

static ssize_t hook_read_impl(int fd, void *buf, size_t count)
{
    if (g_state)
        g_state->hook_read_calls++;

    int handled = 0;
    ssize_t ret = fuzz_read(fd, buf, count, &handled);
    if (handled)
        return ret;

    return (ssize_t)raw_syscall3(SYS_read, (unsigned long)fd,
                                 (unsigned long)buf, (unsigned long)count);
}

ssize_t read(int fd, void *buf, size_t count)
{
    return hook_read_impl(fd, buf, count);
}

ssize_t __read(int fd, void *buf, size_t count)
{
    return hook_read_impl(fd, buf, count);
}

ssize_t __libc_read(int fd, void *buf, size_t count)
{
    return hook_read_impl(fd, buf, count);
}

static int hook_accept_impl(int fd, struct sockaddr *addr,
                            socklen_t *addrlen)
{
    if (g_state)
        g_state->accept_calls++;

    int ret = (int)raw_syscall3(SYS_accept, (unsigned long)fd,
                                (unsigned long)addr, (unsigned long)addrlen);
    if (g_is_httpsd && ret >= 0) {
        g_client_fd = ret;
        if (g_state) {
            g_state->accept_hits++;
            g_state->last_accept_fd = ret;
            g_state->last_accept_pid = (int)getpid();
        }
    }
    return ret;
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return hook_accept_impl(fd, addr, addrlen);
}

static int hook_accept4_impl(int fd, struct sockaddr *addr,
                             socklen_t *addrlen, int flags)
{
    if (g_state)
        g_state->accept_calls++;

    int ret = (int)raw_syscall6(SYS_accept4, (unsigned long)fd,
                                (unsigned long)addr,
                                (unsigned long)addrlen,
                                (unsigned long)flags, 0, 0);
    if (g_is_httpsd && ret >= 0) {
        g_client_fd = ret;
        if (g_state) {
            g_state->accept_hits++;
            g_state->last_accept_fd = ret;
            g_state->last_accept_pid = (int)getpid();
        }
    }
    return ret;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return hook_accept4_impl(fd, addr, addrlen, flags);
}

static void *replacement_for_symbol(const char *name)
{
    if (!name)
        return NULL;
    if (strcmp(name, "read") == 0)
        return (void *)hook_read_impl;
    if (strcmp(name, "__read") == 0)
        return (void *)hook_read_impl;
    if (strcmp(name, "__libc_read") == 0)
        return (void *)hook_read_impl;
    if (strcmp(name, "accept") == 0)
        return (void *)hook_accept_impl;
    if (strcmp(name, "accept4") == 0)
        return (void *)hook_accept4_impl;
    return NULL;
}

static int should_skip_object(const char *name)
{
    if (!name || !*name)
        return 0;
    if (strstr(name, "/hook.so") || strstr(name, "hook.so"))
        return 1;
    if (strstr(name, "libc.so") || strstr(name, "ld-linux") ||
        strstr(name, "/ld-") || strstr(name, "linux-vdso"))
        return 1;
    return 0;
}

static uintptr_t dyn_ptr(uintptr_t base, uintptr_t min_vaddr,
                         uintptr_t max_vaddr, uintptr_t value)
{
    if (value >= base + min_vaddr && value < base + max_vaddr)
        return value;
    return base + value;
}

static int patch_got_slot(void **slot, void *replacement)
{
    if (!slot || !replacement || *slot == replacement)
        return 0;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        page_size = 4096;

    uintptr_t page = (uintptr_t)slot & ~((uintptr_t)page_size - 1);
    if (mprotect((void *)page, (size_t)page_size,
                 PROT_READ | PROT_WRITE) < 0) {
        if (g_state) {
            g_state->patch_failed++;
            g_state->patch_last_errno = errno;
        }
        return -1;
    }

    *slot = replacement;
    __sync_synchronize();
    if (g_state)
        g_state->patch_slots++;
    return 1;
}

static void patch_rela_table(const struct dl_phdr_info *info,
                             Elf64_Rela *rela, size_t relasz,
                             Elf64_Sym *symtab, const char *strtab)
{
    if (!rela || !relasz || !symtab || !strtab)
        return;

    size_t count = relasz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < count; i++) {
        unsigned type = ELF64_R_TYPE(rela[i].r_info);
        if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT)
            continue;

        unsigned sym_idx = ELF64_R_SYM(rela[i].r_info);
        const char *name = strtab + symtab[sym_idx].st_name;
        void *replacement = replacement_for_symbol(name);
        if (!replacement)
            continue;

        void **slot = (void **)(info->dlpi_addr + rela[i].r_offset);
        patch_got_slot(slot, replacement);
    }
}

static int patch_object_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;

    if (should_skip_object(info->dlpi_name))
        return 0;
    if (g_state)
        g_state->patch_objects++;

    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    Elf64_Dyn *dynamic = NULL;

    for (Elf64_Half i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr *ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_LOAD) {
            if (ph->p_vaddr < min_vaddr)
                min_vaddr = ph->p_vaddr;
            if (ph->p_vaddr + ph->p_memsz > max_vaddr)
                max_vaddr = ph->p_vaddr + ph->p_memsz;
        } else if (ph->p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)(info->dlpi_addr + ph->p_vaddr);
        }
    }
    if (!dynamic || min_vaddr == UINTPTR_MAX || max_vaddr == 0)
        return 0;

    Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    Elf64_Rela *jmprel = NULL;
    Elf64_Rela *rela = NULL;
    size_t pltrelsz = 0;
    size_t relasz = 0;

    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            symtab = (Elf64_Sym *)dyn_ptr(info->dlpi_addr, min_vaddr,
                                          max_vaddr, dyn->d_un.d_ptr);
            break;
        case DT_STRTAB:
            strtab = (const char *)dyn_ptr(info->dlpi_addr, min_vaddr,
                                           max_vaddr, dyn->d_un.d_ptr);
            break;
        case DT_JMPREL:
            jmprel = (Elf64_Rela *)dyn_ptr(info->dlpi_addr, min_vaddr,
                                           max_vaddr, dyn->d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            pltrelsz = (size_t)dyn->d_un.d_val;
            break;
        case DT_RELA:
            rela = (Elf64_Rela *)dyn_ptr(info->dlpi_addr, min_vaddr,
                                         max_vaddr, dyn->d_un.d_ptr);
            break;
        case DT_RELASZ:
            relasz = (size_t)dyn->d_un.d_val;
            break;
        default:
            break;
        }
    }

    patch_rela_table(info, jmprel, pltrelsz, symtab, strtab);
    patch_rela_table(info, rela, relasz, symtab, strtab);
    return 0;
}

static void patch_process_imports(void)
{
    dl_iterate_phdr(patch_object_cb, NULL);
}

static void patch_function_entry(const char *name, void *replacement)
{
    if (!name || !replacement)
        return;

    void *target = dlsym(RTLD_NEXT, name);
    if (!target || target == replacement)
        return;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        page_size = 4096;

    unsigned char *p = (unsigned char *)target;
    if (p[0] == 0x48 && p[1] == 0xb8 &&
        *(uintptr_t *)(p + 2) == (uintptr_t)replacement &&
        p[10] == 0xff && p[11] == 0xe0)
        return;

    uintptr_t page = (uintptr_t)target & ~((uintptr_t)page_size - 1);
    if (mprotect((void *)page, (size_t)page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        if (g_state) {
            g_state->entry_patch_failed++;
            g_state->entry_patch_last_errno = errno;
        }
        return;
    }

    unsigned char patch[12];
    patch[0] = 0x48;
    patch[1] = 0xb8;
    *(uintptr_t *)(patch + 2) = (uintptr_t)replacement;
    patch[10] = 0xff;
    patch[11] = 0xe0;
    memcpy(p, patch, sizeof(patch));
    __builtin___clear_cache((char *)p, (char *)p + sizeof(patch));
    __sync_synchronize();

    if (g_state)
        g_state->entry_patch_slots++;
}

static void patch_libc_entries(void)
{
    patch_function_entry("read", (void *)hook_read_impl);
    patch_function_entry("__read", (void *)hook_read_impl);
    patch_function_entry("__libc_read", (void *)hook_read_impl);
    patch_function_entry("accept", (void *)hook_accept_impl);
    patch_function_entry("__accept", (void *)hook_accept_impl);
    patch_function_entry("__libc_accept", (void *)hook_accept_impl);
    patch_function_entry("accept4", (void *)hook_accept4_impl);
    patch_function_entry("__accept4", (void *)hook_accept4_impl);
    patch_function_entry("__libc_accept4", (void *)hook_accept4_impl);
}

__attribute__((constructor)) void init_hook(void)
{
    if (!is_httpsd_process())
        return;

    g_is_httpsd = 1;
    init_shm();
    if (g_state) {
        g_state->hook_ctor_hits++;
        g_state->hook_ctor_pid = (int)getpid();
    }

    patch_libc_entries();
    patch_process_imports();
    init_signals();
}
