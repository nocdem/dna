/**
 * Nodus — Live Integration Test: Cross-Nodus Circuit (VPN Mesh Faz 1)
 *
 * Two in-process servers clustered together. User1 on server A opens
 * circuit to User2 on server B via fingerprint routing.
 */

#include "server/nodus_server.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include "consensus/nodus_cluster.h"
#include "core/nodus_routing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

static int tests_run = 0;
static int tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %-48s ", tests_run, name); fflush(stdout); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

/* ── Server threads ─────────────────────────────────────────────── */

static nodus_server_t srv_a, srv_b;
static volatile bool srv_a_ready = false, srv_b_ready = false;

static void *srv_a_thread(void *arg) {
    (void)arg;
    nodus_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.udp_port = 16000;
    cfg.tcp_port = 16001;
    cfg.peer_port = 16002;
    cfg.ch_port = 16003;
    cfg.witness_port = 16004;
    cfg.require_peer_auth = false;
    snprintf(cfg.data_path, sizeof(cfg.data_path), "/tmp/nodus_cross_a_%d", getpid());
    char cmd[256]; snprintf(cmd, sizeof(cmd), "mkdir -p %s", cfg.data_path); system(cmd);
    if (nodus_server_init(&srv_a, &cfg) != 0) { fprintf(stderr, "srv_a init failed\n"); return NULL; }
    srv_a_ready = true;
    nodus_server_run(&srv_a);
    nodus_server_close(&srv_a);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.data_path); system(cmd);
    return NULL;
}

static void *srv_b_thread(void *arg) {
    (void)arg;
    nodus_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.udp_port = 17000;
    cfg.tcp_port = 17001;
    cfg.peer_port = 17002;
    cfg.ch_port = 17003;
    cfg.witness_port = 17004;
    cfg.require_peer_auth = false;
    snprintf(cfg.data_path, sizeof(cfg.data_path), "/tmp/nodus_cross_b_%d", getpid());
    char cmd[256]; snprintf(cmd, sizeof(cmd), "mkdir -p %s", cfg.data_path); system(cmd);
    if (nodus_server_init(&srv_b, &cfg) != 0) { fprintf(stderr, "srv_b init failed\n"); return NULL; }
    srv_b_ready = true;
    nodus_server_run(&srv_b);
    nodus_server_close(&srv_b);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.data_path); system(cmd);
    return NULL;
}

/* ── Callbacks ─────────────────────────────────────────────────── */

typedef struct {
    uint8_t  received_data[65536];
    size_t   received_len;
    volatile bool got_data;
    volatile bool got_close;
    nodus_circuit_handle_t *inbound_handle;
    nodus_key_t inbound_peer_fp;
    volatile bool got_inbound;
} ctx_t;

static void on_data_cb(nodus_circuit_handle_t *h, const uint8_t *d, size_t n, void *u) {
    (void)h;
    ctx_t *c = (ctx_t *)u;
    if (n <= sizeof(c->received_data)) { memcpy(c->received_data, d, n); c->received_len = n; c->got_data = true; }
}
static void on_close_cb(nodus_circuit_handle_t *h, int r, void *u) { (void)h; (void)r; ((ctx_t *)u)->got_close = true; }
static void on_inbound_cb(struct nodus_client *cl, const nodus_key_t *peer_fp,
                           nodus_circuit_handle_t *h, void *u) {
    (void)cl;
    ctx_t *c = (ctx_t *)u;
    c->inbound_peer_fp = *peer_fp;
    c->inbound_handle = h;
    c->got_inbound = true;
    nodus_circuit_attach(h, on_data_cb, on_close_cb, u);
}
static bool wait_for(volatile bool *flag, int timeout_ms) {
    int e = 0; while (!*flag && e < timeout_ms) { struct timespec t = {0, 10*1000*1000}; nanosleep(&t, NULL); e += 10; }
    return *flag;
}

/* ── Main test ─────────────────────────────────────────────────── */

int main(void) {
    printf("=== Cross-Nodus Circuit Integration Test ===\n");

    pthread_t tid_a, tid_b;
    pthread_create(&tid_a, NULL, srv_a_thread, NULL);
    pthread_create(&tid_b, NULL, srv_b_thread, NULL);

    /* Wait for both servers */
    int waited = 0;
    while ((!srv_a_ready || !srv_b_ready) && waited < 5000) {
        struct timespec t = {0, 10*1000*1000}; nanosleep(&t, NULL); waited += 10;
    }
    if (!srv_a_ready || !srv_b_ready) { FAIL("servers not ready"); return 1; }
    struct timespec settle = {0, 200*1000*1000}; nanosleep(&settle, NULL);

    /* Manually cluster-peer the two servers (ALIVE state, no heartbeat wait) */
    nodus_cluster_add_peer(&srv_a.cluster, &srv_b.identity.node_id,
                            "127.0.0.1", 17000, 17002);
    srv_a.cluster.peers[0].state = NODUS_NODE_ALIVE;
    srv_a.cluster.peers[0].last_seen = (uint64_t)time(NULL);

    nodus_cluster_add_peer(&srv_b.cluster, &srv_a.identity.node_id,
                            "127.0.0.1", 16000, 16002);
    srv_b.cluster.peers[0].state = NODUS_NODE_ALIVE;
    srv_b.cluster.peers[0].last_seen = (uint64_t)time(NULL);

    /* Also add to routing tables — presence p_sync broadcasts to routing peers,
     * not cluster peers. tcp_port here is the inter-node port (UDP+2). */
    nodus_peer_t rp_b = {0};
    rp_b.node_id = srv_b.identity.node_id;
    snprintf(rp_b.ip, sizeof(rp_b.ip), "127.0.0.1");
    rp_b.udp_port = 17000;
    rp_b.tcp_port = 17002;
    rp_b.last_seen = (uint64_t)time(NULL);
    nodus_routing_insert(&srv_a.routing, &rp_b);

    nodus_peer_t rp_a = {0};
    rp_a.node_id = srv_a.identity.node_id;
    snprintf(rp_a.ip, sizeof(rp_a.ip), "127.0.0.1");
    rp_a.udp_port = 16000;
    rp_a.tcp_port = 16002;
    rp_a.last_seen = (uint64_t)time(NULL);
    nodus_routing_insert(&srv_b.routing, &rp_a);

    /* Two user identities */
    nodus_identity_t id_u1, id_u2;
    uint8_t s1[32], s2[32];
    memset(s1, 0x33, sizeof(s1)); memset(s2, 0x44, sizeof(s2));
    nodus_identity_from_seed(s1, &id_u1);
    nodus_identity_from_seed(s2, &id_u2);

    /* User1 → server A (16001), User2 → server B (17001) */
    nodus_client_config_t cfg_a, cfg_b;
    memset(&cfg_a, 0, sizeof(cfg_a));
    strncpy(cfg_a.servers[0].ip, "127.0.0.1", 63);
    cfg_a.servers[0].port = 16001; cfg_a.server_count = 1; cfg_a.request_timeout_ms = 8000;
    memcpy(&cfg_b, &cfg_a, sizeof(cfg_a));
    cfg_b.servers[0].port = 17001;

    nodus_client_t cl_u1, cl_u2;
    memset(&cl_u1, 0, sizeof(cl_u1)); memset(&cl_u2, 0, sizeof(cl_u2));

    TEST("user1 connect to server A");
    if (nodus_client_init(&cl_u1, &cfg_a, &id_u1) != 0) { FAIL("init"); goto cleanup; }
    if (nodus_client_connect(&cl_u1) != 0) { FAIL("connect"); goto cleanup; }
    PASS();

    TEST("user2 connect to server B");
    if (nodus_client_init(&cl_u2, &cfg_b, &id_u2) != 0) { FAIL("init"); goto cleanup; }
    if (nodus_client_connect(&cl_u2) != 0) { FAIL("connect"); goto cleanup; }
    PASS();

    /* Force immediate presence_sync broadcast from both servers by resetting last_sync.
     * The server main loop calls nodus_presence_tick() every iteration. */
    srv_a.presence.last_sync = 0;
    srv_b.presence.last_sync = 0;

    /* Wait for p_sync to propagate (several ticks, ~500ms should be plenty). */
    struct timespec sync_wait = {0, 500 * 1000 * 1000}; nanosleep(&sync_wait, NULL);

    /* ── User2 registers inbound callback ───────────────────────── */
    ctx_t ctx_u2; memset(&ctx_u2, 0, sizeof(ctx_u2));
    nodus_circuit_set_inbound_cb(&cl_u2, on_inbound_cb, &ctx_u2);

    /* ── User1 opens circuit to User2 (cross-nodus) ────────────── */
    TEST("user1 opens cross-nodus circuit to user2");
    ctx_t ctx_u1; memset(&ctx_u1, 0, sizeof(ctx_u1));
    nodus_circuit_handle_t *h_u1 = NULL;
    int rc = nodus_circuit_open(&cl_u1, &id_u2.node_id, on_data_cb, on_close_cb, &ctx_u1, &h_u1);
    if (rc != 0 || !h_u1) {
        char m[64]; snprintf(m, sizeof(m), "rc=%d", rc);
        FAIL(m); goto cleanup;
    }
    PASS();

    TEST("user2 receives inbound notification");
    if (!wait_for(&ctx_u2.got_inbound, 2000)) { FAIL("no inbound"); goto cleanup; }
    if (nodus_key_cmp(&ctx_u2.inbound_peer_fp, &id_u1.node_id) != 0) { FAIL("wrong fp"); goto cleanup; }
    PASS();

    /* ── Data exchange 1 KB u1→u2 ───────────────────────────────── */
    TEST("u1->u2 1KB through cross-nodus");
    uint8_t payload[1024];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i & 0xFF);
    ctx_u2.got_data = false; ctx_u2.received_len = 0;
    if (nodus_circuit_send(h_u1, payload, sizeof(payload)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u2.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u2.received_len != sizeof(payload) || memcmp(ctx_u2.received_data, payload, sizeof(payload)) != 0) {
        FAIL("mismatch"); goto cleanup;
    }
    PASS();

    /* ── Data exchange u2→u1 ───────────────────────────────────── */
    TEST("u2->u1 1KB reverse cross-nodus");
    uint8_t payload2[1024];
    for (size_t i = 0; i < sizeof(payload2); i++) payload2[i] = (uint8_t)((i * 13) & 0xFF);
    ctx_u1.got_data = false; ctx_u1.received_len = 0;
    if (nodus_circuit_send(ctx_u2.inbound_handle, payload2, sizeof(payload2)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u1.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u1.received_len != sizeof(payload2) || memcmp(ctx_u1.received_data, payload2, sizeof(payload2)) != 0) {
        FAIL("mismatch"); goto cleanup;
    }
    PASS();

    /* ── Close propagation ────────────────────────────────────── */
    TEST("circuit close propagates cross-nodus");
    ctx_u2.got_close = false;
    nodus_circuit_close(h_u1);
    if (!wait_for(&ctx_u2.got_close, 2000)) { FAIL("no close"); goto cleanup; }
    PASS();

cleanup:
    nodus_client_close(&cl_u1);
    nodus_client_close(&cl_u2);
    nodus_server_stop(&srv_a);
    nodus_server_stop(&srv_b);
    pthread_join(tid_a, NULL);
    pthread_join(tid_b, NULL);

    printf("\n=== Cross-Nodus Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
