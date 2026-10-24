/**
 * Nodus — a REAL forwarded read over the 4002 node session (batch forward),
 * DHT v2 3b-2 fix round
 *
 * PROVES (nodus/src/dht/nodus_dht_server.c bf_start_forward / bf_on_session /
 * bf_on_frame, driven end to end through nodus_dht_client_request ->
 * handle_t2_get_batch -> nodus_dht_tick -> the batch-forward transport):
 *   B1  a get_batch whose key is not stored locally is FORWARDED to the
 *       routing peer over a pinned node session: the responder (a real
 *       nodus_tcp acceptor running the node session, as core's 4002 accept)
 *       receives exactly ONE get_batch frame, sealed, after the session is
 *       authenticated — i.e. bf_on_session opened the send gate
 *       (nodus_inter_dial_conn_open) before it sent. With the gate shut the
 *       frame went to the dial queue and was never replayed: the responder
 *       saw nothing and the client's read ended in the 5 s timeout.
 *   B2  the responder's token message (auth_ok, txn 0) is consumed by
 *       bf_on_frame and is NOT taken for the reply; the reply to the
 *       get_batch is absorbed (bf_on_frame -> nodus_dht_bf_absorb_reply) and
 *       the client origin gets its result (type 'r', its own txn) from
 *       nodus_dht_bf_send_result — an answered key, not UNAVAILABLE.
 *
 * REQUIRES: a default build (libnodus compiled with NODUS_TCP_SC); loopback;
 * /tmp writable. LEAVES: nothing (temp dir removed; the acceptor pool and the
 * DHT's forward transport closed).
 * HOW IT CAN LIE: the responder's counter proves the frame arrived and the
 * capture proves a reply was routed back, but the reply content is an EMPTY
 * answer built by this test, so it does not exercise merge logic (that is
 * test_bf_forward_frames). The loop is bounded (~8 s of ticks): exhaustion
 * FAILs. The forward is pinned to the responder's node id from the routing
 * entry, so a wrong-pin case is test_node_session's N2, not repeated here.
 */

#include "dht/nodus_dht.h"
#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;

static nodus_identity_t g_id_a, g_id_b;      /* DHT node / responder */
static uint8_t g_chain[32];
static nodus_tcp_t g_acc;
static nodus_inter_session_cfg_t g_cfg_b;

static int g_get_batch;                      /* get_batch frames the responder saw */
static int g_other;                          /* any other frame */
static int g_captures;                       /* replies the DHT sent to the origin */
static uint8_t g_cap[8192];
static size_t g_cap_len;

static bool chain_fn(void *ctx, uint8_t out[32]) {
    (void)ctx;
    memcpy(out, g_chain, 32);
    return true;
}

/* ── the responder: core's on_inter_accept / on_inter_session / frames ── */

static void acc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    conn->is_nodus = true;
    if (nodus_inter_session_enable(&g_acc, conn, false) != 0)
        nodus_tcp_disconnect(&g_acc, conn);
}

static void acc_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (nodus_inter_session_proven(conn) != 0) {
        nodus_tcp_disconnect(&g_acc, conn);
        return;
    }
    /* the token message first, then the gate (core's on_inter_session) */
    uint8_t token[NODUS_SESSION_TOKEN_LEN], buf[256];
    size_t len = 0;
    memset(token, 0x42, sizeof(token));
    if (nodus_t2_auth_ok(0, token, buf, sizeof(buf), &len) != 0 ||
        nodus_tcp_send_raw(conn, buf, len) != 0) {
        nodus_tcp_disconnect(&g_acc, conn);
        return;
    }
    nodus_inter_dial_conn_open(conn);
}

static void acc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    (void)ctx;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    if (nodus_t2_decode(payload, len, &m) == 0 &&
        strcmp(m.method, "get_batch") == 0 && m.batch_key_count == 1) {
        g_get_batch++;
        /* an EMPTY answer for the one key */
        nodus_value_t **v0 = NULL;
        nodus_value_t ***vals = &v0;
        size_t counts[1] = { 0 };
        uint8_t buf[1024];
        size_t blen = 0;
        if (nodus_t2_result_get_batch_ex(m.txn_id, m.batch_keys, 1, vals, counts,
                                         NULL, NULL, buf, sizeof(buf), &blen) == 0)
            nodus_tcp_send(conn, buf, blen);
    } else {
        g_other++;
    }
    nodus_t2_msg_free(&m);
}

/* ── the DHT's host ─────────────────────────────────────────────────── */

static int cap_send(void *ctx, nodus_dht_origin_t origin, const uint8_t *f, size_t l) {
    (void)ctx; (void)origin;
    g_captures++;
    g_cap_len = l < sizeof(g_cap) ? l : sizeof(g_cap);
    memcpy(g_cap, f, g_cap_len);
    return 0;
}

static int stub_udp(void *ctx, const uint8_t *p, size_t l, const char *ip, uint16_t port) {
    (void)ctx; (void)p; (void)l; (void)ip; (void)port;
    return 0;
}

static int stub_inter(void *ctx, const char *ip, uint16_t port, const nodus_key_t *id,
                      const uint8_t *f, size_t l) {
    (void)ctx; (void)ip; (void)port; (void)id; (void)f; (void)l;
    return NODUS_INTER_SEND_REFUSED;
}

static bool stub_hint(void *ctx, const nodus_key_t *id) {
    (void)ctx; (void)id;
    return false;
}

static void check(bool ok, const char *name, const char *why) {
    printf("  %-66s", name);
    if (ok) { printf("PASS\n"); passed++; }
    else { printf("FAIL: %s\n", why); failed++; }
}

int main(void) {
    printf("=== a real forwarded read over the node session (batch forward) ===\n");
    memset(g_chain, 0x5c, sizeof(g_chain));
    if (nodus_identity_generate(&g_id_a) != 0 || nodus_identity_generate(&g_id_b) != 0) {
        printf("FATAL: identities\n");
        return 1;
    }
    if (nodus_tcp_init(&g_acc, -1) != 0) { printf("FATAL: transport\n"); return 1; }
    g_cfg_b.identity = &g_id_b;
    g_cfg_b.chain_id = chain_fn;
    g_acc.auth_ctx = &g_cfg_b;
    g_acc.on_accept = acc_on_accept;
    g_acc.on_session = acc_on_session;
    g_acc.on_frame = acc_on_frame;
    if (nodus_tcp_listen(&g_acc, "127.0.0.1", 0) != 0) { printf("FATAL: listen\n"); return 1; }

    char dir[] = "/tmp/nodus_bf_session_XXXXXX";
    if (!mkdtemp(dir)) { printf("FATAL: mkdtemp\n"); return 1; }

    static nodus_dht_t dht;
    nodus_dht_host_t host;
    memset(&host, 0, sizeof(host));
    host.identity       = &g_id_a;
    host.send_to_origin = cap_send;
    host.udp_send       = stub_udp;
    host.inter_send     = stub_inter;
    host.chain_id       = chain_fn;
    host.hint_wanted    = stub_hint;
    if (nodus_dht_init(&dht, &host) != 0 ||
        nodus_dht_open(&dht, dir, "127.0.0.1", 4002) != 0) {
        printf("FATAL: dht\n");
        return 1;
    }

    /* the responder is the routing peer to ask (its inter port = udp + 2) */
    nodus_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.node_id  = g_id_b.node_id;
    snprintf(peer.ip, sizeof(peer.ip), "%s", "127.0.0.1");
    peer.udp_port = (uint16_t)(g_acc.port - 2);
    peer.tcp_port = g_acc.port;
    nodus_routing_insert(&dht.routing, &peer);

    nodus_dht_origin_t origin = { NODUS_DHT_ORIGIN_CLIENT, 3, 1 };
    nodus_dht_session_opened(&dht, origin);

    nodus_key_t key;
    memset(&key, 0x21, sizeof(key));          /* not stored: a local miss */
    uint8_t token[NODUS_SESSION_TOKEN_LEN] = { 0 };
    nodus_t2_read_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    uint8_t req[1024];
    size_t rlen = 0;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    if (nodus_t2_get_batch_ex(5, token, &key, 1, &opts, req, sizeof(req), &rlen) != 0 ||
        nodus_t2_decode(req, rlen, &m) != 0) {
        printf("FATAL: request\n");
        return 1;
    }
    nodus_dht_client_request(&dht, 3, &g_id_a.node_id, &g_id_a.pk, &m);
    nodus_t2_msg_free(&m);

    for (int i = 0; i < 1600 && g_captures == 0; i++) {
        nodus_dht_tick(&dht);
        nodus_tcp_poll(&g_acc, 5);
    }

    check(g_get_batch == 1 && g_other == 0, "B1 the responder received exactly one sealed get_batch",
          "no get_batch reached the responder (send gate shut?) or extra frames arrived");

    nodus_tier2_msg_t out;
    memset(&out, 0, sizeof(out));
    bool answered = g_captures == 1 && nodus_t2_decode(g_cap, g_cap_len, &out) == 0 &&
                    out.type != 'e' && out.txn_id == 5;
    check(answered, "B2 the reply is absorbed and the origin gets its result",
          "no result for the client's txn (timeout / UNAVAILABLE / wrong txn)");
    nodus_t2_msg_free(&out);

    nodus_dht_stop(&dht);
    nodus_dht_close(&dht);
    nodus_tcp_close(&g_acc);
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* temp dir stays; nothing else depends on it */ }

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
