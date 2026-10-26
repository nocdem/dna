/**
 * Nodus — Client SDK server-key pin, chain id and monotonic timeout tests
 *
 * DHT v2 3b-2 rewrite (the old file pinned the AUTH_OK / Kyber / round-3
 * paths, which no longer exist). Governing records: docs/plans/decisions/
 * 2026-10-23-kurultay-43-summary.md (pins and chain id mandatory, no
 * fallback), 2026-10-23-dht-v2-session-bytes.md.
 *
 * What it proves — nodus_client_config_t.pinned_server_fps / expected_chain_id:
 *   P1  init refuses a broken or missing pin: count > 0 with a NULL list,
 *       count < 0, NO pin at all (a zeroed config).
 *   P1b init refuses a config with no chain id (has_expected_chain_id false,
 *       or an all-zero id).
 *   P2  real nodus_server_t, pin = its node id, same chain id → connects,
 *       the session is READY and client->server_dil_pk is that server's key.
 *   P2b the matching fingerprint is not the first list entry → connects
 *       (the pin is a SET).
 *   P3  pin list holding only OTHER fingerprints → refused, never ready.
 *   P4  right pin, a different chain id → refused.
 *   P5  a request on the session answers (ping → pong): the sealed stream
 *       carries the token and a T2 request end to end.
 *   Monotonic clock:
 *   T1  nodus_time_mono_ms() never goes back and advances at least as far as
 *       a sleep.
 *   T2  a TRULY silent server (a raw listener: the kernel takes the TCP
 *       handshake, nothing reads or closes): the connect fails and at least
 *       connect_timeout_ms of MONOTONIC time passed. Lower bound only — no
 *       upper bound is asserted (a timing assertion that fails under load;
 *       CLAUDE.md DETERMINISM).
 *   T3  a server that accepts and closes: the client fails fast — before a
 *       long (5 s) timeout, which only a disconnect-blind wait would use up.
 *       (Round 4: T2's old server was not silent; since round 1 the client
 *       correctly returns at once on a disconnect.)
 *
 * What it requires: default build, nothing else. No environment. Ports: real
 * server 15400-15404 (test-unique, see the parallel-safety note in
 * nodus/CMakeLists.txt); the silent server listens on 127.0.0.1:0. Data dir
 * /tmp/nodus_client_pin_test_<pid>, removed at the end.
 *
 * What it leaves behind: nothing (server thread joined, data dir removed).
 *
 * How it can lie:
 *   - P3 / P4 prove the refusal happens, not WHICH check refused; the reason
 *     is in the client's and the server's log lines.
 *   - T2 cannot step the wall clock (needs root); it proves the wait lasted
 *     its full limit on the monotonic clock.
 *   - Native build only: the __EMSCRIPTEN__ branches are not run.
 */

#include "nodus/nodus.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "test_server_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define REAL_BASE_PORT 15400
#define CHAIN_BYTE     0x77

/* ── Real server (test_client.c pattern) ─────────────────────────────── */

static nodus_server_t g_server;           /* large — static */
static nodus_server_config_t g_server_cfg;
static pthread_t g_server_tid;
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_init_cond = PTHREAD_COND_INITIALIZER;
static bool g_server_ready = false;
static bool g_server_init_done = false;

static void server_init_outcome(bool ready) {
    pthread_mutex_lock(&g_init_lock);
    g_server_ready = ready;
    g_server_init_done = true;
    pthread_cond_broadcast(&g_init_cond);
    pthread_mutex_unlock(&g_init_lock);
}

static void *real_server_thread(void *arg) {
    (void)arg;
    char cmd[320];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", g_server_cfg.data_path);
    if (system(cmd) != 0) { server_init_outcome(false); return NULL; }
    if (nodus_server_init(&g_server, &g_server_cfg) != 0) {
        fprintf(stderr, "test_client_pin: server init failed\n");
        server_init_outcome(false);
        return NULL;
    }
    ts_server_chain(&g_server, CHAIN_BYTE);   /* no witness here */
    server_init_outcome(true);
    nodus_server_run(&g_server);
    nodus_server_close(&g_server);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_server_cfg.data_path);
    if (system(cmd) != 0) fprintf(stderr, "test_client_pin: cleanup failed\n");
    return NULL;
}

static int start_real_server(void) {
    memset(&g_server_cfg, 0, sizeof(g_server_cfg));
    snprintf(g_server_cfg.bind_ip, sizeof(g_server_cfg.bind_ip), "127.0.0.1");
    g_server_cfg.udp_port     = REAL_BASE_PORT;
    g_server_cfg.tcp_port     = REAL_BASE_PORT + 1;
    g_server_cfg.peer_port    = REAL_BASE_PORT + 2;
    g_server_cfg.ch_port      = REAL_BASE_PORT + 3;
    g_server_cfg.witness_port = REAL_BASE_PORT + 4;
    snprintf(g_server_cfg.data_path, sizeof(g_server_cfg.data_path),
             "/tmp/nodus_client_pin_test_%d", getpid());
    if (pthread_create(&g_server_tid, NULL, real_server_thread, NULL) != 0)
        return -1;
    pthread_mutex_lock(&g_init_lock);
    while (!g_server_init_done)
        pthread_cond_wait(&g_init_cond, &g_init_lock);
    bool ready = g_server_ready;
    pthread_mutex_unlock(&g_init_lock);
    return ready ? 0 : -1;
}

static void stop_real_server(void) {
    nodus_server_stop(&g_server);
    pthread_join(g_server_tid, NULL);
}

/* ── A silent server: accepts TCP, never answers ─────────────────────── */

/* A raw POSIX listener: the kernel completes the TCP handshake into the
 * backlog and nothing in this process ever reads or answers — truly silent
 * (the earlier nodus_tcp-based "silent" server read the client's HELLO bytes
 * and dropped the connection, so it was not silent). */
static int g_silent_fd = -1;
static uint16_t g_silent_port;
/* A second listener that accepts and closes at once. */
static int g_closing_fd = -1;
static uint16_t g_closing_port;
static pthread_t g_closing_tid;
static _Atomic bool g_closing_stop;

static int raw_listen(uint16_t *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(fd, 8) != 0 || getsockname(fd, (struct sockaddr *)&a, &al) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *port_out = ntohs(a.sin_port);
    return fd;
}

static void *closing_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_closing_stop)) {
        struct pollfd p = { .fd = g_closing_fd, .events = POLLIN };
        if (poll(&p, 1, 20) > 0) {
            int c = accept(g_closing_fd, NULL, NULL);
            if (c >= 0) close(c);
        }
    }
    return NULL;
}

/* ── One connect attempt ─────────────────────────────────────────────── */

static nodus_identity_t *g_client_id;

/* 0 connected (client left ready, caller closes it), -1 refused / failed. */
static int connect_once(uint16_t port, const nodus_key_t *pins, int npins,
                        uint8_t chain_byte, int timeout_ms,
                        nodus_client_t **out) {
    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = port;
    cfg.server_count = 1;
    cfg.connect_timeout_ms = timeout_ms;
    cfg.pinned_server_fps = pins;
    cfg.pinned_server_fp_count = npins;
    memset(cfg.expected_chain_id, chain_byte, sizeof(cfg.expected_chain_id));
    cfg.has_expected_chain_id = true;
    if (nodus_client_init(c, &cfg, g_client_id) != 0) { free(c); return -1; }
    int rc = nodus_client_connect(c);
    if (rc != 0 || !nodus_client_is_ready(c)) {
        nodus_client_close(c);
        free(c);
        return -1;
    }
    if (out) { *out = c; return 0; }
    nodus_client_close(c);
    free(c);
    return 0;
}

/* ── P1 ──────────────────────────────────────────────────────────────── */

static void test_init_rejects(void) {
    nodus_client_t *c = calloc(1, sizeof(*c));
    nodus_key_t pin;
    memset(&pin, 0x11, sizeof(pin));
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = 1;
    cfg.server_count = 1;
    memset(cfg.expected_chain_id, CHAIN_BYTE, sizeof(cfg.expected_chain_id));
    cfg.has_expected_chain_id = true;

    TEST("P1 init refuses: count > 0 with a NULL list");
    cfg.pinned_server_fp_count = 1; cfg.pinned_server_fps = NULL;
    if (nodus_client_init(c, &cfg, g_client_id) != 0) PASS(); else FAIL("accepted");

    TEST("P1 init refuses: negative count");
    cfg.pinned_server_fp_count = -1; cfg.pinned_server_fps = &pin;
    if (nodus_client_init(c, &cfg, g_client_id) != 0) PASS(); else FAIL("accepted");

    TEST("P1 init refuses: NO pin at all (zeroed pin fields)");
    cfg.pinned_server_fp_count = 0; cfg.pinned_server_fps = NULL;
    if (nodus_client_init(c, &cfg, g_client_id) != 0) PASS(); else FAIL("accepted");

    cfg.pinned_server_fp_count = 1; cfg.pinned_server_fps = &pin;
    TEST("P1b init refuses: has_expected_chain_id false");
    cfg.has_expected_chain_id = false;
    if (nodus_client_init(c, &cfg, g_client_id) != 0) PASS(); else FAIL("accepted");

    TEST("P1b init refuses: all-zero chain id");
    cfg.has_expected_chain_id = true;
    memset(cfg.expected_chain_id, 0, sizeof(cfg.expected_chain_id));
    if (nodus_client_init(c, &cfg, g_client_id) != 0) PASS(); else FAIL("accepted");

    TEST("P1c init refuses: an all-zero pin entry (central zero-pin refusal)");
    memset(cfg.expected_chain_id, CHAIN_BYTE, sizeof(cfg.expected_chain_id));
    {
        nodus_key_t pins2[2];
        memset(&pins2[0], 0x11, sizeof(pins2[0]));
        memset(&pins2[1], 0, sizeof(pins2[1]));
        cfg.pinned_server_fp_count = 2; cfg.pinned_server_fps = pins2;
        if (nodus_client_init(c, &cfg, g_client_id) != 0) PASS(); else FAIL("accepted");
        cfg.pinned_server_fp_count = 1; cfg.pinned_server_fps = &pin;
    }

    TEST("P1 control: a complete config is accepted");
    if (nodus_client_init(c, &cfg, g_client_id) == 0) {
        nodus_client_close(c);
        PASS();
    } else {
        FAIL("a complete config was refused");
    }
    free(c);
}

/* ── P2-P5 ───────────────────────────────────────────────────────────── */

static void test_real_server(void) {
    uint16_t port = REAL_BASE_PORT + 1;
    nodus_key_t srv_fp = g_server.identity.node_id;
    nodus_key_t other[2];
    memset(&other[0], 0x01, sizeof(other[0]));
    memset(&other[1], 0x02, sizeof(other[1]));

    TEST("P2 pinned to the server's key + same chain id: connects, key recorded");
    {
        nodus_client_t *c = NULL;
        int rc = connect_once(port, &srv_fp, 1, CHAIN_BYTE, 5000, &c);
        bool ok = rc == 0 && c && c->has_server_dil_pk &&
                  memcmp(c->server_dil_pk.bytes, g_server.identity.pk.bytes,
                         NODUS_PK_BYTES) == 0;
        if (ok) PASS(); else FAIL("did not connect, or the server key was not recorded");

        TEST("P5 a request on the session answers (get_servers, token accepted)");
        bool answered = false;
        if (c) {
            nodus_server_endpoint_t eps[8];
            int n = 0;
            answered = nodus_client_get_servers(c, eps, 8, &n) == 0 && n >= 0;
        }
        if (answered) PASS(); else FAIL("the session did not answer a request");
        if (c) { nodus_client_close(c); free(c); }
    }

    TEST("P2b the matching fingerprint is the 3rd list entry: connects");
    {
        nodus_key_t list[3] = { other[0], other[1], srv_fp };
        if (connect_once(port, list, 3, CHAIN_BYTE, 5000, NULL) == 0) PASS();
        else FAIL("a pin SET containing the server's key was refused");
    }

    TEST("P3 pin list with only OTHER fingerprints: refused");
    if (connect_once(port, other, 2, CHAIN_BYTE, 3000, NULL) == -1) PASS();
    else FAIL("connected to a server that is not pinned");

    TEST("P4 right pin, different chain id: refused");
    if (connect_once(port, &srv_fp, 1, (uint8_t)(CHAIN_BYTE ^ 0xff), 3000, NULL) == -1) PASS();
    else FAIL("connected across chains");
}

/* ── T1-T2: monotonic clock ──────────────────────────────────────────── */

static void test_mono_clock(void) {
    TEST("T1 nodus_time_mono_ms never goes back, advances >= a sleep");
    uint64_t prev = nodus_time_mono_ms();
    bool monotone = true;
    for (int i = 0; i < 10000; i++) {
        uint64_t now = nodus_time_mono_ms();
        if (now < prev) { monotone = false; break; }
        prev = now;
    }
    uint64_t a = nodus_time_mono_ms();
    usleep(120 * 1000);
    uint64_t b = nodus_time_mono_ms();
    if (monotone && b >= a + 120) PASS();
    else FAIL("monotonic clock went back or did not advance");
}

static void test_timeout_on_mono_clock(void) {
    TEST("T2 silent server: the session wait fails after >= connect_timeout_ms");
    nodus_key_t pin;
    memset(&pin, 0x33, sizeof(pin));
    const int limit_ms = 400;
    uint64_t t0 = nodus_time_mono_ms();
    int rc = connect_once(g_silent_port, &pin, 1, CHAIN_BYTE, limit_ms, NULL);
    uint64_t spent = nodus_time_mono_ms() - t0;
    if (rc == -1 && spent >= (uint64_t)limit_ms) PASS();
    else FAIL("timed out early, or connected to a silent server");
}

static void test_server_closes_fails_fast(void) {
    TEST("T3 a server that closes: the client fails at once, not after the timeout");
    nodus_key_t pin;
    memset(&pin, 0x33, sizeof(pin));
    const int limit_ms = 5000;
    uint64_t t0 = nodus_time_mono_ms();
    int rc = connect_once(g_closing_port, &pin, 1, CHAIN_BYTE, limit_ms, NULL);
    uint64_t spent = nodus_time_mono_ms() - t0;
    /* Not a timing assertion on a short bound: the failure must come well
     * before the (long) limit, which a disconnect-blind wait would use up. */
    if (rc == -1 && spent < (uint64_t)limit_ms) PASS();
    else FAIL("the client waited out its whole timeout on a closed connection");
}

int main(void) {
    printf("=== Nodus client server-key pin, chain id + monotonic timeout tests ===\n");

    g_client_id = calloc(1, sizeof(*g_client_id));
    if (!g_client_id || nodus_identity_generate(g_client_id) != 0) {
        printf("FATAL: client identity\n");
        return 1;
    }

    test_mono_clock();
    test_init_rejects();

    g_silent_fd = raw_listen(&g_silent_port);
    g_closing_fd = raw_listen(&g_closing_port);
    if (g_silent_fd < 0 || g_closing_fd < 0 ||
        pthread_create(&g_closing_tid, NULL, closing_thread, NULL) != 0) {
        printf("FATAL: raw servers\n");
        return 1;
    }
    test_timeout_on_mono_clock();
    test_server_closes_fails_fast();
    atomic_store(&g_closing_stop, true);
    pthread_join(g_closing_tid, NULL);
    close(g_closing_fd);
    close(g_silent_fd);

    if (start_real_server() != 0) {
        printf("FATAL: real server did not start (ports %d-%d)\n",
               REAL_BASE_PORT, REAL_BASE_PORT + 4);
        return 1;
    }
    test_real_server();
    stop_real_server();

    nodus_identity_clear(g_client_id);
    free(g_client_id);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
