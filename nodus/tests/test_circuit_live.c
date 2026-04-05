/**
 * Nodus — Live Integration Test: Same-Nodus Circuit Bridge (VPN Mesh Faz 1)
 *
 * Starts one server, connects two clients to it, opens a circuit between them
 * via fingerprint-based routing, and verifies bidirectional data flow.
 */

#include "server/nodus_server.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-45s ", tests_run, name); \
    fflush(stdout); \
} while (0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

/* ── Server thread ──────────────────────────────────────────────── */

static nodus_server_t server;
static volatile bool server_ready = false;

static void *server_thread(void *arg) {
    (void)arg;
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port = 15000;
    config.tcp_port = 15001;
    config.ch_port  = 15003;
    snprintf(config.data_path, sizeof(config.data_path), "/tmp/nodus_circuit_test_%d", getpid());

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", config.data_path);
    system(cmd);

    if (nodus_server_init(&server, &config) != 0) {
        fprintf(stderr, "server init failed\n");
        return NULL;
    }
    server_ready = true;
    nodus_server_run(&server);
    nodus_server_close(&server);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", config.data_path);
    system(cmd);
    return NULL;
}

/* ── Client callback state ─────────────────────────────────────── */

typedef struct {
    uint8_t  received_data[65536];
    size_t   received_len;
    volatile bool got_data;
    volatile bool got_close;
    nodus_circuit_handle_t *inbound_handle;
    nodus_key_t inbound_peer_fp;
    volatile bool got_inbound;
} circuit_test_ctx_t;

static void on_data_cb(nodus_circuit_handle_t *h, const uint8_t *data, size_t len, void *user) {
    (void)h;
    circuit_test_ctx_t *ctx = (circuit_test_ctx_t *)user;
    if (len <= sizeof(ctx->received_data)) {
        memcpy(ctx->received_data, data, len);
        ctx->received_len = len;
        ctx->got_data = true;
    }
}

static void on_close_cb(nodus_circuit_handle_t *h, int reason, void *user) {
    (void)h; (void)reason;
    circuit_test_ctx_t *ctx = (circuit_test_ctx_t *)user;
    ctx->got_close = true;
}

static void on_inbound_cb(struct nodus_client *client, const nodus_key_t *peer_fp,
                           nodus_circuit_handle_t *h, void *user) {
    (void)client;
    circuit_test_ctx_t *ctx = (circuit_test_ctx_t *)user;
    ctx->inbound_peer_fp = *peer_fp;
    ctx->inbound_handle = h;
    ctx->got_inbound = true;
    nodus_circuit_attach(h, on_data_cb, on_close_cb, user);
}

/* Wait helper: busy-wait up to timeout_ms for *flag to become true */
static bool wait_for(volatile bool *flag, int timeout_ms) {
    int elapsed = 0;
    while (!*flag && elapsed < timeout_ms) {
        struct timespec ts = {0, 10 * 1000 * 1000};  /* 10ms */
        nanosleep(&ts, NULL);
        elapsed += 10;
    }
    return *flag;
}

/* ── Main test ─────────────────────────────────────────────────── */

int main(void) {
    printf("=== Circuit Live Integration Test (Same-Nodus) ===\n");

    pthread_t srv_tid;
    pthread_create(&srv_tid, NULL, server_thread, NULL);

    /* Wait for server ready */
    int waited = 0;
    while (!server_ready && waited < 5000) {
        struct timespec ts = {0, 10 * 1000 * 1000}; nanosleep(&ts, NULL);
        waited += 10;
    }
    if (!server_ready) { fprintf(stderr, "FATAL: server didn't start\n"); return 1; }
    /* Give it a moment to start accepting */
    struct timespec ts_init = {0, 200 * 1000 * 1000}; nanosleep(&ts_init, NULL);

    /* ── Two identities ────────────────────────────────────────── */
    nodus_identity_t id_u1, id_u2;
    uint8_t seed1[32], seed2[32];
    memset(seed1, 0x11, sizeof(seed1));
    memset(seed2, 0x22, sizeof(seed2));
    nodus_identity_from_seed(seed1, &id_u1);
    nodus_identity_from_seed(seed2, &id_u2);

    /* ── Two clients connecting to same server ─────────────────── */
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.servers[0].ip, "127.0.0.1", 63);
    cfg.servers[0].port = 15001;
    cfg.server_count = 1;
    cfg.request_timeout_ms = 5000;

    nodus_client_t client_u1, client_u2;
    memset(&client_u1, 0, sizeof(client_u1));
    memset(&client_u2, 0, sizeof(client_u2));

    int final_rc = 1;

    TEST("user1 init+connect");
    if (nodus_client_init(&client_u1, &cfg, &id_u1) != 0) { FAIL("u1 init"); goto cleanup; }
    if (nodus_client_connect(&client_u1) != 0) { FAIL("u1 connect"); goto cleanup; }
    PASS();

    TEST("user2 init+connect");
    if (nodus_client_init(&client_u2, &cfg, &id_u2) != 0) { FAIL("u2 init"); goto cleanup; }
    if (nodus_client_connect(&client_u2) != 0) { FAIL("u2 connect"); goto cleanup; }
    PASS();

    /* Allow presence to settle */
    { struct timespec ts = {0, 200 * 1000 * 1000}; nanosleep(&ts, NULL); }

    /* ── Setup User2 inbound callback ──────────────────────────── */
    circuit_test_ctx_t ctx_u2;
    memset(&ctx_u2, 0, sizeof(ctx_u2));
    nodus_circuit_set_inbound_cb(&client_u2, on_inbound_cb, &ctx_u2);

    /* ── User1 opens circuit to User2 ──────────────────────────── */
    TEST("user1 opens circuit to user2");
    circuit_test_ctx_t ctx_u1;
    memset(&ctx_u1, 0, sizeof(ctx_u1));
    nodus_circuit_handle_t *h_u1 = NULL;
    int rc = nodus_circuit_open(&client_u1, &id_u2.node_id,
                                  on_data_cb, on_close_cb, &ctx_u1, &h_u1);
    if (rc != 0 || !h_u1) { FAIL("open"); goto cleanup; }
    PASS();

    /* User2 should have received circ_inbound */
    TEST("user2 receives inbound notification");
    if (!wait_for(&ctx_u2.got_inbound, 2000)) { FAIL("no inbound"); goto cleanup; }
    if (nodus_key_cmp(&ctx_u2.inbound_peer_fp, &id_u1.node_id) != 0) { FAIL("wrong peer fp"); goto cleanup; }
    PASS();

    /* ── User1 → User2: send 1KB ────────────────────────────────── */
    TEST("u1->u2 send 1KB");
    uint8_t payload1[1024];
    for (size_t i = 0; i < sizeof(payload1); i++) payload1[i] = (uint8_t)(i & 0xFF);
    ctx_u2.got_data = false; ctx_u2.received_len = 0;
    if (nodus_circuit_send(h_u1, payload1, sizeof(payload1)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u2.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u2.received_len != sizeof(payload1) ||
        memcmp(ctx_u2.received_data, payload1, sizeof(payload1)) != 0) { FAIL("mismatch"); goto cleanup; }
    PASS();

    /* ── User2 → User1: send 2KB ────────────────────────────────── */
    TEST("u2->u1 send 2KB");
    uint8_t payload2[2048];
    for (size_t i = 0; i < sizeof(payload2); i++) payload2[i] = (uint8_t)((i * 31) & 0xFF);
    ctx_u1.got_data = false; ctx_u1.received_len = 0;
    if (nodus_circuit_send(ctx_u2.inbound_handle, payload2, sizeof(payload2)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u1.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u1.received_len != sizeof(payload2) ||
        memcmp(ctx_u1.received_data, payload2, sizeof(payload2)) != 0) { FAIL("mismatch"); goto cleanup; }
    PASS();

    /* ── User1 closes circuit ───────────────────────────────────── */
    TEST("user1 closes circuit, user2 notified");
    ctx_u2.got_close = false;
    nodus_circuit_close(h_u1);
    if (!wait_for(&ctx_u2.got_close, 2000)) { FAIL("no close"); goto cleanup; }
    PASS();

    final_rc = 0;

cleanup:
    nodus_client_close(&client_u1);
    nodus_client_close(&client_u2);
    nodus_server_stop(&server);
    pthread_join(srv_tid, NULL);
    nodus_identity_clear(&id_u1);
    nodus_identity_clear(&id_u2);

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    (void)final_rc;
    return (tests_passed == tests_run) ? 0 : 1;
}
