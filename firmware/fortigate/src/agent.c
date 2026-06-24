/*
 * agent.c - FortiGate httpsd kAFL agent.
 *
 * Default mode: hook kicker
 *   hook.so is ptrace-dlopen'd into httpsd workers.  The hook owns the kAFL
 *   loop inside the selected worker; this agent only opens a local connection
 *   until a worker reaches the hooked read() and takes the in-target snapshot.
 *
 * Optional mode: AGENT_MODE=ptrace
 *   /inject --trace tracks accept/read syscalls in httpsd workers.  This agent
 *   owns the kAFL loop, copies each payload into /dev/shm/kafl_hook_shm, then
 *   opens one localhost:9980 connection so the tracer can replace the worker's
 *   read() buffer with a POST /logincheck request.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <nyx_api.h>

#include "hook_common.h"

#define HTTPSD_ADDR "127.0.0.1"
#define HTTPSD_PORT 9980
#define PAGE_SIZE_LOCAL 4096
#define DEFAULT_WAIT_US 100000
#define DEFAULT_GRACE_US 20000
#define DEFAULT_PAYLOAD_CAP MAX_PAYLOAD
#define DEFAULT_DIAG_ROUNDS 16

static int g_conn_ok;
static int g_conn_fail;
static int g_last_errno;

static void *alloc_resident_pages(size_t pages)
{
    size_t sz = pages * PAGE_SIZE_LOCAL;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    memset(p, 0, sz);
    mlock(p, sz);
    return p;
}

static int env_int(const char *name, int fallback)
{
    const char *s = getenv(name);
    if (!s || !*s)
        return fallback;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v < 0 || v > 10000000)
        return fallback;
    return (int)v;
}

static size_t payload_alloc_size(const host_config_t *host_config)
{
    size_t cap = host_config->payload_buffer_size;

    if (cap == 0 || cap > MAX_PAYLOAD) {
        hprintf("[AGENT] suspicious payload_buffer_size=%u, using %u\n",
                host_config->payload_buffer_size, DEFAULT_PAYLOAD_CAP);
        cap = DEFAULT_PAYLOAD_CAP;
    }

    return sizeof(kAFL_payload) + cap;
}

static int kick_open(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTPSD_PORT);
    addr.sin_addr.s_addr = inet_addr(HTTPSD_ADDR);

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        g_last_errno = errno;
        g_conn_fail++;
        close(sock);
        return -1;
    }

    g_conn_ok++;
    static const char req[] =
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(sock, req, sizeof(req) - 1, MSG_NOSIGNAL);
    return sock;
}

static int kick_once(int hold_us)
{
    int sock = kick_open();
    if (sock < 0)
        return -1;
    if (hold_us > 0)
        usleep((useconds_t)hold_us);
    close(sock);
    return 0;
}

static struct hook_state *map_state(void)
{
    char path[64];
    snprintf(path, sizeof(path), "/dev/shm%s", SHM_NAME);

    int fd = open(path, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        hprintf("[AGENT] open %s failed errno=%d\n", path, errno);
        return NULL;
    }
    if (ftruncate(fd, sizeof(struct hook_state)) < 0) {
        hprintf("[AGENT] ftruncate shm failed errno=%d\n", errno);
        close(fd);
        return NULL;
    }

    struct hook_state *st = mmap(NULL, sizeof(*st),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (st == MAP_FAILED) {
        hprintf("[AGENT] mmap shm failed errno=%d\n", errno);
        return NULL;
    }
    memset(st, 0, sizeof(*st));
    return st;
}

static unsigned long parse_hex(const char *s)
{
    unsigned long v = 0;
    for (; *s; s++) {
        unsigned d;
        if (*s >= '0' && *s <= '9')
            d = (unsigned)(*s - '0');
        else if (*s >= 'a' && *s <= 'f')
            d = (unsigned)(*s - 'a' + 10);
        else if (*s >= 'A' && *s <= 'F')
            d = (unsigned)(*s - 'A' + 10);
        else
            break;
        v = (v << 4) | d;
    }
    return v;
}

static void submit_range(unsigned id, uintptr_t start, uintptr_t end)
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

static int pid_is_httpsd(const char *pid_name)
{
    char path[512];
    char comm[64] = {0};

    snprintf(path, sizeof(path), "/proc/%s/comm", pid_name);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;
    if (!fgets(comm, sizeof(comm), fp)) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    comm[strcspn(comm, "\r\n")] = '\0';
    return strcmp(comm, "httpsd") == 0;
}

static int first_httpsd_pid(void)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;

    int found = -1;
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        const char *s = ent->d_name;
        int numeric = 1;
        for (const char *p = s; *p; p++) {
            if (*p < '0' || *p > '9') {
                numeric = 0;
                break;
            }
        }
        if (!numeric || !pid_is_httpsd(s))
            continue;
        found = atoi(s);
        break;
    }
    closedir(proc);
    return found;
}

static void submit_httpsd_text_ranges(void)
{
    int do_submit = env_int("AGENT_SUBMIT_RANGES", 1);
    int pid = first_httpsd_pid();
    if (pid < 0) {
        hprintf("[AGENT] no httpsd pid for PT ranges\n");
        return;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) {
        hprintf("[AGENT] open %s failed errno=%d\n", path, errno);
        return;
    }

    hprintf("[AGENT] collecting PT ranges from httpsd pid=%d%s\n", pid,
            do_submit ? "" : " (diagnostic only; set AGENT_SUBMIT_RANGES=1 to submit)");
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
        if (perms[0] == '\0' || perms[1] == '\0' || perms[2] != 'x')
            continue;
        /* ip0 is supplied on the kafl command line for /bin/init.  Use the
         * remaining hardware ranges for FortiGate's Apache/APR HTTP stack,
         * but keep libc/ld out to avoid noisy generic coverage. */
        if (!strstr(line, "libapr") &&
            !strstr(line, "libaprutil") &&
            !strstr(line, "libpcre") &&
            !strstr(line, "libexpat") &&
            !strstr(line, "libssl") &&
            !strstr(line, "libcrypto") &&
            !strstr(line, "/httpsd"))
            continue;

        unsigned long start = parse_hex(line);
        unsigned long end = parse_hex(dash + 1);
        if (start == 0 || end <= start)
            continue;
        hprintf("[AGENT] PT candidate ip%u=0x%lx-0x%lx %s",
                id, start, end, line);
        if (do_submit)
            submit_range(id, (uintptr_t)start, (uintptr_t)end);
        id++;
    }
    fclose(maps);

    if (id == 1)
        hprintf("[AGENT] WARNING: no httpsd executable range submitted\n");
}

static void dump_hook_state(void)
{
    char path[64];
    snprintf(path, sizeof(path), "/dev/shm%s", SHM_NAME);
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        hprintf("[AGENT] no shm at %s\n", path);
        return;
    }
    struct hook_state *st = mmap(NULL, sizeof(*st),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (st == MAP_FAILED) {
        hprintf("[AGENT] shm mmap failed\n");
        return;
    }
    hprintf("[AGENT] HOOK DIAG: ctor=%d patch_slots=%d entry_slots=%d | "
            "read_calls=%d recv_calls=%d readv=%d recvmsg=%d sock_reads=%d | "
            "accept_calls=%d accept_ok=%d afd=%d apid=%d | "
            "read_hits=%d snapshot=%d cr3=%d\n",
            st->hook_ctor_hits, st->patch_slots, st->entry_patch_slots,
            st->hook_read_calls, st->hook_recv_calls, st->hook_readv_calls,
            st->hook_recvmsg_calls, st->sock_read_calls,
            st->accept_calls, st->accept_hits, st->last_accept_fd,
            st->last_accept_pid,
            st->read_hits, st->snapshot_taken, st->cr3_submits);
    munmap(st, sizeof(*st));
}

static int run_hook_kicker(void)
{
    hprintf("[AGENT] kicker start (in-target snapshot model)\n");
    for (int i = 0; ; i++) {
        kick_once(50000);
        usleep(200000);
        if (i == 50 || i == 150) {
            hprintf("[AGENT] still kicking after %ds: connect ok=%d fail=%d "
                    "last_errno=%d\n", (i + 1) / 5, g_conn_ok, g_conn_fail,
                    g_last_errno);
            dump_hook_state();
        }
    }
    return 0;
}

static int run_ptrace_agent(void)
{
    hprintf("[AGENT] ptrace-shm agent start\n");

    submit_httpsd_text_ranges();

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

    size_t payload_bytes = payload_alloc_size(&host_config);
    kAFL_payload *payload = alloc_resident_pages(
        (payload_bytes + PAGE_SIZE_LOCAL - 1) / PAGE_SIZE_LOCAL);
    if (!payload) {
        hprintf("[AGENT] payload alloc failed bytes=%lu cap=%u bitmap=%u\n",
                (unsigned long)payload_bytes,
                host_config.payload_buffer_size,
                host_config.bitmap_size);
        return 1;
    }
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload);

    struct hook_state *state = map_state();
    if (!state)
        return 1;

    /* Warmup connection lets the tracer observe accept() and submit the
     * target worker CR3 before real fuzz iterations begin. */
    kick_once(50000);
    usleep(100000);

    int wait_us = env_int("AGENT_WAIT_US", DEFAULT_WAIT_US);
    int grace_us = env_int("AGENT_GRACE_US", DEFAULT_GRACE_US);
    int diag_rounds = env_int("AGENT_DIAG_ROUNDS", DEFAULT_DIAG_ROUNDS);
    int generation = 0;

    hprintf("[AGENT] payload_cap=%u bitmap=%u wait_us=%d grace_us=%d diag_rounds=%d\n",
            host_config.payload_buffer_size, host_config.bitmap_size,
            wait_us, grace_us, diag_rounds);

    while (1) {
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        int sz = payload->size;
        if (sz <= 0 || sz > MAX_PAYLOAD) {
            hprintf("[AGENT] bad payload size=%d\n", sz);
            state->ready = 0;
            state->consumed = 0;
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
            continue;
        }

        state->ready = 0;
        state->consumed = 0;
        state->size = sz;
        state->generation = ++generation;
        state->crash_reason = CRASH_NONE;
        int hits_before = state->read_hits;
        int cr3_before = state->cr3_submits;
        memcpy(state->data, payload->data, (size_t)sz);
        __sync_synchronize();
        state->ready = 1;

        int sock = kick_open();
        if (sock < 0) {
            hprintf("[AGENT] connect failed ok=%d fail=%d errno=%d\n",
                    g_conn_ok, g_conn_fail, g_last_errno);
        }

        int waited = 0;
        while (!state->consumed && waited < wait_us) {
            usleep(1000);
            waited += 1000;
        }
        if (grace_us > 0)
            usleep((useconds_t)grace_us);

        if (!state->consumed) {
            hprintf("[AGENT] payload not consumed gen=%d size=%d hits=%d "
                    "copy=%d read_sz=%d afd=%d cr3=%d ok=%d fail=%d\n",
                    generation, sz, state->read_hits, state->last_copy_size,
                    state->last_read_size, state->last_accept_fd,
                    state->cr3_submits, g_conn_ok, g_conn_fail);
        } else if (generation <= diag_rounds) {
            hprintf("[AGENT] consumed gen=%d size=%d hits=%d(+%d) copy=%d "
                    "read_sz=%d fd=%d cr3=%d(+%d) ok=%d fail=%d api=%d\n",
                    generation, sz, state->read_hits,
                    state->read_hits - hits_before, state->last_copy_size,
                    state->last_read_size, state->last_read_fd,
                    state->cr3_submits, state->cr3_submits - cr3_before,
                    g_conn_ok, g_conn_fail, state->last_api);
        }

        state->ready = 0;
        state->consumed = 0;
        if (sock >= 0)
            close(sock);

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}

int main(void)
{
    const char *mode = getenv("AGENT_MODE");
    if (mode && strcmp(mode, "ptrace") == 0)
        return run_ptrace_agent();
    return run_hook_kicker();
}
