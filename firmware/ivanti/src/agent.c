/*
 * agent.c — strategy-driven agent for IFT-TLS multi-packet fuzzing
 * edit by verf1sh: root snapshot relocation + network injection + smart RELEASE
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <nyx_api.h>
#include <nyx_agent.h>

#define SHM_NAME            "/kafl_hook_shm"
#define MAX_PAYLOAD         (1 * 1024 * 1024)
#define MAX_PACKETS         5
#define SSL_READ_BUF_MAX    0x4000
#define STRATEGY_PATH       "./strategy.txt"

/* IFT packet types that web daemon processes silently (no SSL_write/close) */
#define IFT_TYPE_CLIENT_INFO  0x00000A4C

struct hook_state {
    int ready;
    int consumed;
    int size;
    int prefix_phase;
    char data[MAX_PAYLOAD];
};

struct fuzz_strategy {
    int       prefix_count;
    int       fuzz_count;
    char     *prefix_data[MAX_PACKETS];
    int       prefix_sizes[MAX_PACKETS];
};

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
            hprintf("[STRATEGY] PREFIX[%d] file=%s size=%d\n", idx, val, (int)sz);
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
            hprintf("[STRATEGY] PREFIX[%d] hex_size=%d\n", idx, sz);
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

    hprintf("[STRATEGY] prefix=%d fuzz=%d\n", s->prefix_count, s->fuzz_count);
    return 0;
}

static SSL *tls_connect(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(443),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(sock); return NULL; }

    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (!ssl) { close(sock); return NULL; }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, "127.0.0.1");

    if (SSL_connect(ssl) <= 0) { SSL_free(ssl); close(sock); return NULL; }
    return ssl;
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
    hprintf("[AGENT] payload_size=%u bitmap=%u\n",
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

    SSL *ssl = tls_connect();
    if (!ssl) { hprintf("[AGENT] TLS connect failed\n"); return 1; }

    for (int i = 0; i < strategy.prefix_count; i++) {
        hprintf("[AGENT] sending prefix[%d] size=%d\n",
                i, strategy.prefix_sizes[i]);
        if (send_prefix(ssl, strategy.prefix_data[i],
                        strategy.prefix_sizes[i]) < 0)
            return 1;
    }

    hprintf("[AGENT] %d prefixes sent, entering fuzz loop\n",
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

        /* Root snapshot creation pass: first NEXT_PAYLOAD yields poison */
        if (payload->size <= 0 || payload->size > SSL_READ_BUF_MAX) {
            hypercall(HYPERCALL_KAFL_RELEASE, 0);
            state->consumed = 0;
            continue;
        }

        SSL_write(ssl, payload->data, payload->size);

        /* Decode IFT type to decide wait strategy.
         * Type 0x0A4C (client-info): daemon never responds, force RELEASE.
         * Others: poll briefly — daemon responds in <5ms if at all. */
        uint32_t ift_type = 0;
        if (payload->size >= 4) {
            memcpy(&ift_type, payload->data, 4);
            ift_type = ntohl(ift_type);
        }

        if (ift_type == IFT_TYPE_CLIENT_INFO) {
            hypercall(HYPERCALL_KAFL_RELEASE, 0);
        } else {
            int retries = 50;  /* 50 * 100us = 5ms */
            while (!state->consumed && retries-- > 0)
                usleep(100);
            if (!state->consumed)
                hypercall(HYPERCALL_KAFL_RELEASE, 0);
        }
        state->consumed = 0;
    }

    return 0;
}
