/**
 * Nodus — DHT v2 3b-2 round-4 hardening: re-entrant disconnect (D-24 a),
 * central zero-pin refusal in the session layer, force_disconnect state,
 * and the batch-forward session config resolving through the DHT's host.
 *
 * PROVES:
 *   R1  an on_disconnect that disconnects its own connection runs ONCE, and
 *       a nodus_tcp_disconnect issued afterwards on the closed connection's
 *       pointer inside the same call does not free it twice (the callback
 *       counter is 1; the transport count returns to 0).
 *   R2  nodus_tcp_sc_enable refuses an INITIATOR whose expected_peer is all
 *       zero, and one whose pin set holds an all-zero entry; a non-zero pin
 *       on a fresh connection is accepted (control).
 *   R3  nodus_client_force_disconnect clears session_ready and
 *       has_server_dil_pk (it bypasses client_on_disconnect).
 *   R4  after nodus_dht_init, replacing dht->host under the live DHT (the
 *       pattern of test_dht_ipc case 12) makes the batch-forward session
 *       config call the NEW host's chain_id with the NEW ctx — a copy taken
 *       at init would call the old one (a use-after-free in production).
 *
 * REQUIRES: default build, loopback only; the listener binds port 0.
 * LEAVES: nothing (transports closed, DHT stopped).
 *
 * HOW IT CAN LIE:
 *   - R1 counts callbacks; a double free shows only under a sanitiser or as
 *     a crash, not in the counter alone.
 *   - R2's refusals are asserted by return value; the log line says which
 *     check refused. The control (non-zero pin accepted) rules out "enable
 *     always refuses this connection".
 *   - R3 sets the fields by hand (no live session): it proves the clearing,
 *     not that a real session ever sets them.
 *   - R4 calls the config hook directly; it does not run a batch forward
 *     (that needs two live nodes — test_node_session covers the session).
 */

#include "nodus/nodus.h"
#include "dht/nodus_dht.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── R1 ──────────────────────────────────────────────────────────────── */

static int g_disc_calls;

static void reentrant_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_tcp_t *tcp = (nodus_tcp_t *)ctx;
    g_disc_calls++;
    nodus_tcp_disconnect(tcp, conn);     /* the same connection, re-entrantly */
}

static void test_reentrant_disconnect(void) {
    TEST("R1 an on_disconnect that disconnects its own conn runs once");
    nodus_tcp_t tcp;
    if (nodus_tcp_init(&tcp, -1) != 0 ||
        nodus_tcp_listen(&tcp, "127.0.0.1", 0) != 0) { FAIL("setup"); return; }
    tcp.on_disconnect = reentrant_on_disconnect;
    tcp.cb_ctx = &tcp;
    g_disc_calls = 0;
    nodus_tcp_conn_t *c = nodus_tcp_connect(&tcp, "127.0.0.1", tcp.port);
    if (!c) { nodus_tcp_close(&tcp); FAIL("connect"); return; }
    nodus_tcp_disconnect(&tcp, c);
    bool ok = g_disc_calls == 1;
    nodus_tcp_close(&tcp);
    if (ok) PASS(); else FAIL("on_disconnect ran more than once");
}

/* ── R2 ──────────────────────────────────────────────────────────────── */

static void test_zero_pin_refused(void) {
    TEST("R2 sc_enable refuses an all-zero expected peer / set entry");
    nodus_tcp_t tcp;
    nodus_identity_t id;
    if (nodus_tcp_init(&tcp, -1) != 0 ||
        nodus_tcp_listen(&tcp, "127.0.0.1", 0) != 0 ||
        nodus_identity_generate(&id) != 0) { FAIL("setup"); return; }

    nodus_tcp_sc_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = CMT_P2P_SC_ROLE_INITIATOR;
    cfg.profile = &CMT_P2P_SC_PROFILE_NODE;
    cfg.id = &id;
    cfg.proto_ver = NODUS_NSESS_PROTO_VERSION;
    memset(cfg.chain_id, 0x42, sizeof(cfg.chain_id));

    nodus_key_t zero, good[2];
    memset(&zero, 0, sizeof(zero));
    memset(&good[0], 0x11, sizeof(good[0]));
    memset(&good[1], 0, sizeof(good[1]));

    bool ok = true;
    nodus_tcp_conn_t *c1 = nodus_tcp_connect(&tcp, "127.0.0.1", tcp.port);
    nodus_tcp_conn_t *c2 = nodus_tcp_connect(&tcp, "127.0.0.1", tcp.port);
    nodus_tcp_conn_t *c3 = nodus_tcp_connect(&tcp, "127.0.0.1", tcp.port);
    if (!c1 || !c2 || !c3) { nodus_tcp_close(&tcp); FAIL("connect"); return; }

    cfg.expected_peer = &zero;
    if (nodus_tcp_sc_enable(&tcp, c1, &cfg) == 0) ok = false;
    cfg.expected_peer = NULL;
    cfg.expected_set = good; cfg.expected_set_n = 2;        /* [non-zero, ZERO] */
    if (nodus_tcp_sc_enable(&tcp, c2, &cfg) == 0) ok = false;
    cfg.expected_set_n = 1;                                  /* [non-zero] only */
    if (nodus_tcp_sc_enable(&tcp, c3, &cfg) != 0) ok = false; /* control */

    nodus_tcp_close(&tcp);
    nodus_identity_clear(&id);
    if (ok) PASS(); else FAIL("a zero pin was accepted, or the control refused");
}

/* ── R3 ──────────────────────────────────────────────────────────────── */

static void test_force_disconnect_state(void) {
    TEST("R3 force_disconnect clears session_ready and has_server_dil_pk");
    nodus_identity_t id;
    nodus_key_t pin;
    nodus_client_t *c = calloc(1, sizeof(*c));
    nodus_client_config_t cfg;
    memset(&pin, 0x11, sizeof(pin));
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = 1;
    cfg.server_count = 1;
    cfg.pinned_server_fps = &pin;
    cfg.pinned_server_fp_count = 1;
    memset(cfg.expected_chain_id, 0x42, sizeof(cfg.expected_chain_id));
    cfg.has_expected_chain_id = true;
    if (!c || nodus_identity_generate(&id) != 0 ||
        nodus_client_init(c, &cfg, &id) != 0) { free(c); FAIL("setup"); return; }

    atomic_store(&c->session_ready, true);
    c->has_server_dil_pk = true;
    nodus_client_force_disconnect(c);
    bool ok = !atomic_load(&c->session_ready) && !c->has_server_dil_pk;
    nodus_client_close(c);
    free(c);
    nodus_identity_clear(&id);
    if (ok) PASS(); else FAIL("state survived force_disconnect");
}

/* ── R4 ──────────────────────────────────────────────────────────────── */

static int g_chain_calls_a, g_chain_calls_b;

static bool chain_a(void *ctx, uint8_t out[32]) {
    (void)ctx; g_chain_calls_a++; memset(out, 0xA1, 32); return true;
}
static bool chain_b(void *ctx, uint8_t out[32]) {
    (void)ctx; g_chain_calls_b++; memset(out, 0xB2, 32); return ctx != NULL;
}

static void test_bf_cfg_follows_host(void) {
    TEST("R4 the batch-forward session config resolves through the CURRENT host");
    nodus_dht_t *dht = calloc(1, sizeof(*dht));
    nodus_identity_t id;
    nodus_dht_host_t h;
    int tag_a = 1, tag_b = 2;
    if (!dht || nodus_identity_generate(&id) != 0) { free(dht); FAIL("setup"); return; }
    memset(&h, 0, sizeof(h));
    h.identity = &id;
    h.ctx = &tag_a;
    h.chain_id = chain_a;
    if (nodus_dht_init(dht, &h) != 0) { free(dht); FAIL("dht init"); return; }

    /* the host replaced under the live DHT (the old ctx is now dead) */
    dht->host.ctx = &tag_b;
    dht->host.chain_id = chain_b;

    uint8_t out[32];
    memset(out, 0, sizeof(out));
    g_chain_calls_a = g_chain_calls_b = 0;
    bool got = dht->bf_state.cfg.chain_id &&
               dht->bf_state.cfg.chain_id(dht->bf_state.cfg.ctx, out);
    bool ok = got && out[0] == 0xB2 && g_chain_calls_b == 1 && g_chain_calls_a == 0;
    nodus_dht_stop(dht);
    nodus_dht_close(dht);
    free(dht);
    nodus_identity_clear(&id);
    if (ok) PASS(); else FAIL("the config still resolves through the old host");
}

int main(void) {
    printf("=== Nodus 3b-2 round-4 hardening tests ===\n");
    test_reentrant_disconnect();
    test_zero_pin_refused();
    test_force_disconnect_state();
    test_bf_cfg_follows_host();
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
