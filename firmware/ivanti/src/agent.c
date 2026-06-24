/*
 * agent.c — strategy-driven agent for IFT-TLS multi-packet fuzzing
 * edit by verf1sh: root snapshot relocation + network injection + smart RELEASE
 *                    + cmd-inj taint marker support via hook_common.h
 *
 * VM 内只需: agent, hook_SSL_read.so, start_fuzz.sh, strategy.txt
 * 用法: ./agent [strategy.txt]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <nyx_api.h>
#include <nyx_agent.h>

#include "hook_common.h"

#define SSL_READ_BUF_MAX    0x4000
#define STRATEGY_PATH       "./strategy.txt"
#define MAX_PT_RANGES       4
#define DYNAMIC_PT_FIRST_ID 1
#define AGENT_VERBOSE       0

#if AGENT_VERBOSE
#define vlog(...) hprintf(__VA_ARGS__)
#else
#define vlog(...) do { } while (0)
#endif

/* IFT packet types that web daemon processes silently (no SSL_write/close) */
#define IFT_TYPE_CLIENT_INFO  0x00000A4C

struct fuzz_strategy {
    int       prefix_count;
    int       fuzz_count;
    char     *prefix_data[MAX_PACKETS];
    int       prefix_sizes[MAX_PACKETS];
};

struct pt_range {
    uintptr_t start;
    uintptr_t end;
    char      object[128];
};

struct fuzz_packet_view {
    int   count;
    uint8_t *data[MAX_PACKETS];
    int   sizes[MAX_PACKETS];
};

static int range_already_added(const struct pt_range *ranges, int count,
                               uintptr_t start, uintptr_t end)
{
    for (int i = 0; i < count; i++) {
        if (ranges[i].start == start && ranges[i].end == end)
            return 1;
    }
    return 0;
}

static int wanted_text_mapping(const char *path)
{
    return strcmp(path, "/home/bin/web") == 0 ||
           strcmp(path, "/home/lib/libdsagentd.so") == 0;
}

static int is_pid_dir(const char *name)
{
    if (!name || !name[0])
        return 0;
    for (const char *p = name; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}

static int find_web_pid(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        hprintf("[AGENT] can't open /proc\n");
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (!is_pid_dir(ent->d_name))
            continue;

        char exe_link[128];
        char exe_path[256];
        if (strlen(ent->d_name) > 32)
            continue;
        snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", ent->d_name);

        ssize_t n = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (n <= 0)
            continue;
        exe_path[n] = '\0';

        if (strcmp(exe_path, "/home/bin/web") == 0) {
            int pid = atoi(ent->d_name);
            closedir(proc);
            return pid;
        }
    }

    closedir(proc);
    hprintf("[AGENT] web pid not found\n");
    return -1;
}

static int collect_web_text_ranges(struct pt_range *ranges, int max_ranges)
{
    int pid = find_web_pid();
    if (pid <= 0)
        return 0;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        hprintf("[AGENT] can't open %s\n", maps_path);
        return 0;
    }

    int count = 0;
    char line[512];
    while (count < max_ranges && fgets(line, sizeof(line), maps)) {
        unsigned long start = 0, end = 0, offset = 0;
        char perms[5] = {0};
        char dev[32] = {0};
        unsigned long inode = 0;
        char path[256] = {0};

        int n = sscanf(line, "%lx-%lx %4s %lx %31s %lu %255s",
                       &start, &end, perms, &offset, dev, &inode, path);
        if (n < 7)
            continue;
        if (strchr(perms, 'x') == NULL)
            continue;
        if (!wanted_text_mapping(path))
            continue;
        if (range_already_added(ranges, count, (uintptr_t)start, (uintptr_t)end))
            continue;

        ranges[count].start = (uintptr_t)start;
        ranges[count].end = (uintptr_t)end;
        snprintf(ranges[count].object, sizeof(ranges[count].object), "%s", path);
        count++;
    }

    fclose(maps);
    return count;
}

static void submit_web_text_ranges(void)
{
    struct pt_range ranges[MAX_PT_RANGES] = {0};
    int count = collect_web_text_ranges(ranges, MAX_PT_RANGES - DYNAMIC_PT_FIRST_ID);

    if (count == 0) {
        hprintf("[AGENT] no web/libdsagentd text ranges found; keeping frontend -ipN\n");
        return;
    }

    for (int i = 0; i < count; i++) {
        unsigned id = (unsigned)(i + DYNAMIC_PT_FIRST_ID);
        vlog("[AGENT] PT ip%d=%p-%p %s\n",
             id, (void *)ranges[i].start, (void *)ranges[i].end,
             ranges[i].object);
        hrange_submit(id, ranges[i].start, ranges[i].end);
    }
}

static int read_strategy(const char *path, struct fuzz_strategy *s)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        hprintf("[STRATEGY] No config, using default single-packet\n");
        memset(s, 0, sizeof(*s));
        s->prefix_count = 0;
        s->fuzz_count   = 1;
        return 0;
    }

    memset(s, 0, sizeof(*s));
    char line[512];
    int line_no = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        nl = strchr(line, '\r');       if (nl) *nl = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        char key[64] = {0}, val[480] = {0};
        if (sscanf(line, "%63s %479[^\n]", key, val) < 2) {
            hprintf("[STRATEGY] parse error line %d: %s\n", line_no, line);
            continue;
        }

        if (strcmp(key, "PREFIX_FILE") == 0 && s->prefix_count < MAX_PACKETS) {
            FILE *pf = fopen(val, "rb");
            if (!pf) {
                hprintf("[STRATEGY] can't open prefix: %s\n", val);
                fclose(fp); return -1;
            }
            fseek(pf, 0, SEEK_END);
            long sz = ftell(pf);
            fseek(pf, 0, SEEK_SET);
            if (sz <= 0 || sz > SSL_READ_BUF_MAX) {
                hprintf("[STRATEGY] bad prefix size: %ld\n", sz);
                fclose(pf); fclose(fp); return -1;
            }
            int idx = s->prefix_count;
            s->prefix_data[idx] = malloc(sz);
            if (!s->prefix_data[idx]) { fclose(pf); fclose(fp); return -1; }
            if (fread(s->prefix_data[idx], 1, sz, pf) != (size_t)sz) {
                hprintf("[STRATEGY] short read on prefix\n");
                fclose(pf); fclose(fp); return -1;
            }
            s->prefix_sizes[idx] = (int)sz;
            s->prefix_count++;
            fclose(pf);
            vlog("[STRATEGY] PREFIX[%d] file=%s size=%d\n", idx, val, (int)sz);
        }
        else if (strcmp(key, "PREFIX_HEX") == 0 && s->prefix_count < MAX_PACKETS) {
            size_t hex_len = strlen(val);
            if (hex_len == 0 || hex_len % 2 != 0 || hex_len / 2 > SSL_READ_BUF_MAX) {
                hprintf("[STRATEGY] bad hex prefix length\n");
                fclose(fp); return -1;
            }
            int sz = (int)(hex_len / 2);
            int idx = s->prefix_count;
            s->prefix_data[idx] = malloc(sz);
            if (!s->prefix_data[idx]) { fclose(fp); return -1; }
            for (int i = 0; i < sz; i++) {
                unsigned int byte;
                sscanf(val + i*2, "%2x", &byte);
                s->prefix_data[idx][i] = (char)byte;
            }
            s->prefix_sizes[idx] = sz;
            s->prefix_count++;
            vlog("[STRATEGY] PREFIX[%d] hex_size=%d\n", idx, sz);
        }
        else if (strcmp(key, "FUZZ_COUNT") == 0) {
            s->fuzz_count = atoi(val);
            if (s->fuzz_count < 1) s->fuzz_count = 1;
            if (s->fuzz_count > MAX_PACKETS) s->fuzz_count = MAX_PACKETS;
        }
        else {
            hprintf("[STRATEGY] unknown key: %s\n", key);
        }
    }
    fclose(fp);

    if (s->prefix_count + s->fuzz_count > MAX_PACKETS) {
        hprintf("[STRATEGY] too many packets (max %d)\n", MAX_PACKETS);
        return -1;
    }
    if (s->fuzz_count == 0) s->fuzz_count = 1;

    vlog("[STRATEGY] prefix=%d fuzz=%d\n", s->prefix_count, s->fuzz_count);
    return 0;
}

static SSL *tls_connect(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        hprintf("[AGENT] socket failed errno=%d\n", errno);
        return NULL;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(443),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        hprintf("[AGENT] connect 127.0.0.1:443 failed errno=%d\n", errno);
        close(sock); return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(sock); return NULL; }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_min_proto_version(ctx, 0);
    SSL_CTX_set_security_level(ctx, 0);
#endif
    if (!SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0")) {
        ERR_clear_error();
        SSL_CTX_set_cipher_list(ctx, "ALL");
    }

    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (!ssl) { close(sock); return NULL; }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, "127.0.0.1");

    for (int tries = 0; tries < 200; tries++) {
        int ret = SSL_connect(ssl);
        if (ret == 1)
            return ssl;

        int ssl_err = SSL_get_error(ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            usleep(20000);
            continue;
        }

        unsigned long err;
        hprintf("[AGENT] SSL_connect failed ssl_err=%d\n", ssl_err);
        while ((err = ERR_get_error()) != 0) {
            char ebuf[256];
            ERR_error_string_n(err, ebuf, sizeof(ebuf));
            hprintf("[AGENT] OpenSSL: %s\n", ebuf);
        }
        SSL_free(ssl); close(sock); return NULL;
    }

    hprintf("[AGENT] SSL_connect timed out waiting for handshake\n");
    SSL_free(ssl); close(sock); return NULL;
}

static int send_prefix(SSL *ssl, const char *data, int size)
{
    if (SSL_write(ssl, data, size) <= 0) {
        hprintf("[AGENT] prefix send failed\n");
        return -1;
    }
    usleep(50000);
    return 0;
}

static int unpack_fuzz_packets(kAFL_payload *payload, int expected_count,
                               struct fuzz_packet_view *out)
{
    memset(out, 0, sizeof(*out));

    if (expected_count <= 1) {
        out->count = 1;
        out->data[0] = payload->data;
        out->sizes[0] = (int)payload->size;
        return 0;
    }

    if (payload->size < (int)sizeof(struct shm_header)) {
        vlog("[AGENT] packed fuzz payload too small: %u\n", payload->size);
        return -1;
    }

    struct shm_header hdr;
    memcpy(&hdr, payload->data, sizeof(hdr));
    if (hdr.magic != SHM_MAGIC ||
        hdr.packet_count == 0 ||
        hdr.packet_count > MAX_PACKETS ||
        hdr.packet_count != (uint32_t)expected_count) {
        vlog("[AGENT] bad packed fuzz header magic=0x%x count=%u expected=%d\n",
             hdr.magic, hdr.packet_count, expected_count);
        return -1;
    }

    int off = (int)sizeof(struct shm_header);
    out->count = (int)hdr.packet_count;
    for (int i = 0; i < out->count; i++) {
        uint32_t sz = hdr.packet_sizes[i];
        if (sz == 0 || sz > SSL_READ_BUF_MAX || off + (int)sz > (int)payload->size) {
            vlog("[AGENT] bad fuzz packet[%d] size=%u payload=%u\n",
                 i, sz, payload->size);
            return -1;
        }
        out->data[i] = payload->data + off;
        out->sizes[i] = (int)sz;
        off += (int)sz;
    }
    return 0;
}

static int send_fuzz_packets(SSL *ssl, const struct fuzz_packet_view *packets)
{
    for (int i = 0; i < packets->count; i++) {
        if (SSL_write(ssl, packets->data[i], packets->sizes[i]) <= 0) {
            hprintf("[AGENT] fuzz[%d] send failed\n", i);
            return -1;
        }
        usleep(1000);
    }
    return 0;
}

int main(int argc, char **argv)
{
    nyx_cpu_type = get_nyx_cpu_type();

    const char *cfg_path = (argc > 1) ? argv[1] : STRATEGY_PATH;
    struct fuzz_strategy strategy;
    if (read_strategy(cfg_path, &strategy) < 0) return 1;

    hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    hypercall(HYPERCALL_KAFL_RELEASE, 0);
    hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    host_config_t host_config = {0};
    hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    vlog("[AGENT] payload_size=%u bitmap=%u\n",
         host_config.payload_buffer_size, host_config.bitmap_size);

    agent_config_t agent_config = {0};
    agent_config.agent_magic   = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;
    agent_config.coverage_bitmap_size = host_config.bitmap_size;
    hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    kAFL_payload *payload = malloc_resident_pages(
        (host_config.payload_buffer_size + 4095) / 4096);
    if (!payload) { hprintf("[AGENT] payload alloc failed\n"); return 1; }
    hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload);

    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { hprintf("[AGENT] shm_open failed\n"); return 1; }
    if (ftruncate(fd, sizeof(struct hook_state)) < 0) {
        hprintf("[AGENT] ftruncate failed\n"); return 1;
    }
    struct hook_state *state = mmap(NULL, sizeof(struct hook_state),
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (state == MAP_FAILED) { hprintf("[AGENT] mmap failed\n"); return 1; }
    memset(state, 0, sizeof(struct hook_state));

    state->prefix_phase = 1;
    state->suppress_release = 0;
    state->crash_reason = CRASH_NONE;
    state->taint_marker[0] = '\0';

    submit_web_text_ranges();

    SSL *ssl = tls_connect();
    if (!ssl) { hprintf("[AGENT] TLS connect failed\n"); return 1; }

    for (int i = 0; i < strategy.prefix_count; i++) {
        vlog("[AGENT] sending prefix[%d] size=%d\n",
             i, strategy.prefix_sizes[i]);
        if (send_prefix(ssl, strategy.prefix_data[i],
                        strategy.prefix_sizes[i]) < 0)
            return 1;
    }

    vlog("[AGENT] %d prefixes sent, entering fuzz loop\n",
         strategy.prefix_count);

    state->prefix_phase = 0;

    /*
     * Root snapshot relocation: NEXT_PAYLOAD inside loop captures
     * post-prefix VM state on first call, restores + fetches on later calls.
     * Network injection avoids kernel deadlock in orig_SSL_read.
     * Smart RELEASE: IFT type 0x0A4C processed silently by daemon
     * → force RELEASE immediately.  Other types → short poll then force.
     */
    while (1) {
        hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        /* Reset per-round crash classification before processing payload. */
        state->crash_reason = CRASH_NONE;
        state->taint_marker[0] = '\0';

        /* Root snapshot creation pass: first NEXT_PAYLOAD yields poison */
        if (payload->size <= 0 || payload->size > SSL_READ_BUF_MAX) {
            hypercall(HYPERCALL_KAFL_RELEASE, 0);
            state->consumed = 0;
            continue;
        }

        struct fuzz_packet_view packets;
        if (unpack_fuzz_packets(payload, strategy.fuzz_count, &packets) < 0) {
            hypercall(HYPERCALL_KAFL_RELEASE, 0);
            state->consumed = 0;
            continue;
        }

        state->suppress_release = 1;
        if (send_fuzz_packets(ssl, &packets) < 0) {
            state->suppress_release = 0;
            hypercall(HYPERCALL_KAFL_RELEASE, 0);
            state->consumed = 0;
            continue;
        }
        /*
         * Poll for hook to deliver data to web's SSL_read (sets consumed).
         * Then wait extra for web to FINISH processing (dispatchMessage etc)
         * before RELEASE captures the PT trace.  Total ~3ms.
         */
        int retries = 50;
        while (!state->consumed && retries-- > 0)
            usleep(100);
        usleep(3000);  /* 3ms grace for web to process the frame */
        state->suppress_release = 0;
        hypercall(HYPERCALL_KAFL_RELEASE, 0);
        state->consumed = 0;
    }

    return 0;
}
