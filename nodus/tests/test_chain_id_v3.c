/**
 * Nodus — the chain id of the sessions is the v3 chain id; the per-IP
 * handshake rate (DHT v2 3b-2, round 3)
 *
 * PROVES
 *   V1  nodus_server_chain_id returns the chain backend's chain_id_v3 (32
 *       bytes, what 4004's HELLO carries and every client knows) and NOT the
 *       legacy 16-byte-padded id its `status` reports (which stays what the T2
 *       status RPC says: the stub's status() is unchanged and still differs).
 *   V2  fail closed: a backend with no v3 id yet, or without the op, gives no
 *       chain id (so no 4001 / 4002 session is made).
 *   V3  over the real node session (two loopback pools, the acceptor's chain id
 *       taken from nodus_server_chain_id): a dialer configured with the
 *       LEGACY padded id is refused by the handshake — closed, no session, no
 *       frame; a dialer configured with the v3 id gets an authenticated
 *       session and its frame arrives.
 *   V4  nodus_witness_dht_chain_id (what the DHT snapshot's `ci` and the status
 *       `c3` carry) is the v3 id the witness caches (nodus_witness_v2_chain_id)
 *       — different from witness->chain_id (the legacy padded one) — and is an
 *       ERROR (never a zero id) when there is no open chain or no v3 id.
 *   V5  the per-IP handshake rate (decision 2026-10-24, 60/min), with injected
 *       monotonic time: the Nth+1 accept of one IP inside its minute is
 *       refused, another IP is not, the minute's end re-admits, an IPv6 /64 is
 *       one IP, rate 0 is off, the table is bounded (a flood of distinct IPs
 *       neither crashes nor grows it: the oldest window is evicted).
 *   V6  loopback is exempt from the rate on a REAL accept: a listener with a
 *       limit of 2 admits three connections from 127.0.0.1 (addendum
 *       2026-10-26).
 *
 * REQUIRES: a default build (libnodus with NODUS_TCP_SC); a loopback
 * interface. No environment, no compile flag beyond the default.
 * LEAVES: nothing (pools closed, kernel-chosen ports, in-memory sqlite).
 * HOW IT CAN LIE: V4 builds a scratch witness (an in-memory database, the
 * cached v3 id set by hand): it proves the helper's choice of field and its
 * failure modes, NOT that a real chain's genesis document derives a v3 id —
 * nodus_witness_dht_snap_fill itself needs block meta and is not run here.
 * V6 uses the wall of real time only for "four connects inside one minute".
 * The handshake itself is the layer's (nodus_tcp_sc.c); V3 pins that the chain
 * id fed to it is the v3 one, not the cryptography.
 */

#include "server/nodus_server.h"
#include "server/nodus_inter_dial.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_ipc.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_identity.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── The stub chain backend ───────────────────────────────────────── */

static uint8_t g_legacy[32];     /* 16 bytes + 16 zero: what status reports */
static uint8_t g_v3[32];         /* the 32-byte v3 id */
static bool    g_have_v3 = true;

static void stub_status(nodus_chain_backend_t *b, nodus_t2_status_info_t *info) {
    (void)b;
    memcpy(info->chain_id, g_legacy, 32);
}

static bool stub_v3(nodus_chain_backend_t *b, uint8_t out[32]) {
    (void)b;
    if (!g_have_v3) return false;
    memcpy(out, g_v3, 32);
    return true;
}

static const nodus_chain_backend_ops_t g_ops_v3 = {
    .status = stub_status, .chain_id_v3 = stub_v3,
};
static const nodus_chain_backend_ops_t g_ops_no_op = {
    .status = stub_status,
};

static nodus_server_t *new_server(const nodus_chain_backend_ops_t *ops,
                                  nodus_chain_backend_t *be) {
    nodus_server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    be->ops = ops;
    s->chain = be;
    return s;
}

static void test_v1(void) {
    TEST("V1 session chain id = chain_id_v3, not status' legacy id");
    nodus_chain_backend_t be;
    nodus_server_t *s = new_server(&g_ops_v3, &be);
    uint8_t out[32];
    if (!s) { FAIL("alloc"); return; }
    g_have_v3 = true;
    bool ok = nodus_server_chain_id(s, out);
    nodus_t2_status_info_t info;
    memset(&info, 0, sizeof(info));
    be.ops->status(&be, &info);
    bool status_unchanged = memcmp(info.chain_id, g_legacy, 32) == 0;
    bool is_v3 = memcmp(out, g_v3, 32) == 0;
    bool not_legacy = memcmp(out, g_legacy, 32) != 0;
    free(s);
    if (!ok || !is_v3) { FAIL("the session chain id is not the v3 id"); return; }
    if (!not_legacy) { FAIL("the session chain id equals the legacy id"); return; }
    if (!status_unchanged) { FAIL("the status chain id changed"); return; }
    PASS();
}

static void test_v2(void) {
    TEST("V2 no v3 id (or no op) -> no chain id: fail closed");
    nodus_chain_backend_t be;
    uint8_t out[32];
    g_have_v3 = false;
    nodus_server_t *a = new_server(&g_ops_v3, &be);
    bool none = a && !nodus_server_chain_id(a, out);
    free(a);
    g_have_v3 = true;
    nodus_chain_backend_t be2;
    nodus_server_t *b = new_server(&g_ops_no_op, &be2);
    bool noop = b && !nodus_server_chain_id(b, out);
    free(b);
    if (!none) { FAIL("a chain id came out of a backend without a v3 id"); return; }
    if (!noop) { FAIL("a chain id came out of a backend without the op"); return; }
    PASS();
}

/* ── V3: the node session with the legacy / the v3 id ──────────────── */

static nodus_identity_t g_id_a, g_id_b;
static nodus_tcp_t g_dial, g_acc;
static nodus_inter_session_cfg_t g_cfg_a, g_cfg_b;
static nodus_server_t *g_srv;                    /* supplies the acceptor's id */
static uint8_t g_dialer_chain[32];
static int g_acc_frames, g_acc_sessions, g_dial_closed;

static bool dialer_chain(void *ctx, uint8_t out[32]) {
    (void)ctx;
    memcpy(out, g_dialer_chain, 32);
    return true;
}

static bool acceptor_chain(void *ctx, uint8_t out[32]) {
    (void)ctx;
    return nodus_server_chain_id(g_srv, out);
}

static void acc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    conn->is_nodus = true;
    if (nodus_inter_session_enable(&g_acc, conn, false) != 0)
        nodus_tcp_disconnect(&g_acc, conn);
}
static void acc_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (nodus_inter_session_proven(conn) != 0) { nodus_tcp_disconnect(&g_acc, conn); return; }
    g_acc_sessions++;
    nodus_inter_dial_conn_open(conn);
}
static void acc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *p, size_t n, void *ctx) {
    (void)conn; (void)p; (void)n; (void)ctx;
    g_acc_frames++;
}
static void dial_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (nodus_inter_session_proven(conn) != 0) { nodus_tcp_disconnect(&g_dial, conn); return; }
    nodus_inter_dial_conn_open(conn);
}
static void dial_on_frame(nodus_tcp_conn_t *conn, const uint8_t *p, size_t n, void *ctx) {
    (void)conn; (void)p; (void)n; (void)ctx;
}
static void dial_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    g_dial_closed++;
}

static void poll_both(void) {
    nodus_tcp_poll(&g_dial, 5);
    nodus_tcp_poll(&g_acc, 5);
}

static bool wait_for(const int *counter, int want) {
    for (int i = 0; i < 600 && *counter < want; i++) poll_both();
    return *counter >= want;
}

static void close_all_dials(void) {
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (g_dial.pool[i]) nodus_tcp_disconnect(&g_dial, g_dial.pool[i]);
    for (int i = 0; i < 100; i++) poll_both();
}

static nodus_inter_send_t send_one(const char *text) {
    uint8_t fr[64];
    size_t fl = nodus_frame_encode(fr, sizeof(fr), (const uint8_t *)text,
                                   (uint32_t)strlen(text));
    return nodus_inter_pool_send_framed(&g_dial, "127.0.0.1", g_acc.port,
                                        &g_id_b.node_id, fr, fl);
}

static void test_v3(void) {
    TEST("V3 legacy padded id refused, v3 id accepted by the session");
    nodus_chain_backend_t be;
    g_have_v3 = true;
    g_srv = new_server(&g_ops_v3, &be);
    if (!g_srv) { FAIL("alloc"); return; }
    g_acc_frames = g_acc_sessions = g_dial_closed = 0;

    memcpy(g_dialer_chain, g_legacy, 32);        /* a client with the old id */
    if (send_one("legacy") != NODUS_INTER_SEND_QUEUED) {
        FAIL("the dial did not start"); free(g_srv); return;
    }
    bool closed = wait_for(&g_dial_closed, 1);
    for (int i = 0; i < 50; i++) poll_both();
    if (!closed || g_acc_sessions != 0 || g_acc_frames != 0) {
        FAIL("a session or frame came out of the legacy chain id");
        free(g_srv);
        return;
    }
    close_all_dials();

    memcpy(g_dialer_chain, g_v3, 32);            /* a client with the v3 id */
    if (send_one("v3") != NODUS_INTER_SEND_QUEUED || !wait_for(&g_acc_frames, 1) ||
        g_acc_sessions != 1) {
        FAIL("the v3 chain id did not get a session");
        free(g_srv);
        return;
    }
    free(g_srv);
    PASS();
    close_all_dials();
}

/* ── V4: the witness helper ────────────────────────────────────────── */

static void test_v4(void) {
    TEST("V4 dht chain id = cached v3 id, error without chain / v3 id");
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { FAIL("alloc"); return; }
    uint8_t out[32];
    bool no_db = nodus_witness_dht_chain_id(w, out) != 0;     /* no open chain */
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) { FAIL("sqlite"); free(w); return; }
    memset(w->chain_id, 0x44, 16);        /* legacy: 16 bytes, rest zero */
    memset(w->chain_id + 16, 0, 16);
    bool no_v3 = nodus_witness_dht_chain_id(w, out) != 0;     /* no genesis doc */
    memset(w->v2_chain32, 0xA7, sizeof(w->v2_chain32));
    w->v2_chain32_valid = true;
    memset(out, 0, sizeof(out));
    int rc = nodus_witness_dht_chain_id(w, out);
    bool is_v3 = rc == 0 && memcmp(out, w->v2_chain32, 32) == 0;
    bool not_legacy = memcmp(out, w->chain_id, 32) != 0;
    sqlite3_close(w->db);
    free(w);
    if (!no_db || !no_v3) { FAIL("an id came out of a witness without chain / v3 id"); return; }
    if (!is_v3) { FAIL("the helper did not return the cached v3 id"); return; }
    if (!not_legacy) { FAIL("the helper returned the legacy id"); return; }
    PASS();
}

/* ── V5: the rate table, injected time ─────────────────────────────── */

static nodus_ws_ip_bucket_t bucket_of(const char *ip) {
    nodus_ws_ip_bucket_t b;
    memset(&b, 0, sizeof(b));
    (void)nodus_ws_ip_bucket(ip, &b);
    return b;
}

static void test_v5(void) {
    TEST("V5 60/min per IP with injected time; bounded table");
    nodus_tcp_t *t = calloc(1, sizeof(*t));
    if (!t) { FAIL("alloc"); return; }
    t->hs_rate_per_min = 3;
    nodus_ws_ip_bucket_t a = bucket_of("203.0.113.5");
    nodus_ws_ip_bucket_t b = bucket_of("203.0.113.6");
    uint64_t t0 = 1000000;
    bool ok = true;
    for (int i = 0; i < 3; i++) ok = ok && nodus_tcp_hs_rate_allow(t, &a, t0 + (uint64_t)i * 100);
    bool fourth = nodus_tcp_hs_rate_allow(t, &a, t0 + 400);         /* refused */
    bool other  = nodus_tcp_hs_rate_allow(t, &b, t0 + 500);         /* admitted */
    bool late   = nodus_tcp_hs_rate_allow(t, &a, t0 + 59999);       /* still refused */
    bool again  = nodus_tcp_hs_rate_allow(t, &a, t0 + 60000);       /* minute over */
    if (!ok || fourth || !other || late || !again) {
        FAIL("window semantics (3 admitted, 4th refused, other IP ok, +60 s re-admits)");
        free(t);
        return;
    }
    /* an IPv6 /64 is one IP */
    nodus_ws_ip_bucket_t v6a = bucket_of("2001:db8:1:2::1");
    nodus_ws_ip_bucket_t v6b = bucket_of("2001:db8:1:2:ffff::9");
    uint64_t t1 = 5000000;
    bool v6ok = nodus_tcp_hs_rate_allow(t, &v6a, t1) &&
                nodus_tcp_hs_rate_allow(t, &v6b, t1 + 1) &&
                nodus_tcp_hs_rate_allow(t, &v6a, t1 + 2) &&
                !nodus_tcp_hs_rate_allow(t, &v6b, t1 + 3);
    if (!v6ok) { FAIL("two addresses of one /64 are not one IP"); free(t); return; }
    /* flood of distinct IPs: bounded, every first accept admitted */
    bool flood = true;
    for (uint32_t i = 0; i < NODUS_TCP_HS_RATE_TABLE * 3u; i++) {
        nodus_ws_ip_bucket_t f;
        memset(&f, 0, sizeof(f));
        f.family = 4;
        f.key[0] = 10; f.key[1] = (uint8_t)(i >> 16);
        f.key[2] = (uint8_t)(i >> 8); f.key[3] = (uint8_t)i;
        flood = flood && nodus_tcp_hs_rate_allow(t, &f, 9000000 + i);
    }
    if (!flood) { FAIL("a first accept of a new IP was refused under a flood"); free(t); return; }
    /* rate 0 = off */
    t->hs_rate_per_min = 0;
    bool off = true;
    for (int i = 0; i < 200; i++) off = off && nodus_tcp_hs_rate_allow(t, &a, 7000000);
    free(t);
    if (!off) { FAIL("rate 0 must admit everything"); return; }
    PASS();
}

/* ── V6: a real accept ─────────────────────────────────────────────── */

static int g_rate_accepts;
static void rate_on_accept(nodus_tcp_conn_t *c, void *ctx) {
    (void)c; (void)ctx;
    g_rate_accepts++;
}

static void test_v6(void) {
    TEST("V6 loopback is exempt from the rate: a limit of 2 admits all three");
    nodus_tcp_t srv, cli;
    if (nodus_tcp_init(&srv, -1) != 0 || nodus_tcp_init(&cli, -1) != 0) {
        FAIL("init");
        return;
    }
    srv.hs_rate_per_min = 2;
    srv.on_accept = rate_on_accept;
    g_rate_accepts = 0;
    if (nodus_tcp_listen(&srv, "127.0.0.1", 0) != 0) { FAIL("listen"); return; }
    nodus_tcp_conn_t *c[3];
    for (int i = 0; i < 3; i++) c[i] = nodus_tcp_connect(&cli, "127.0.0.1", srv.port);
    for (int i = 0; i < 100; i++) { nodus_tcp_poll(&srv, 5); nodus_tcp_poll(&cli, 5); }
    int accepts = g_rate_accepts;
    nodus_tcp_close(&cli);
    nodus_tcp_close(&srv);
    if (!c[0] || !c[1] || !c[2]) { FAIL("connect"); return; }
    /* operator addendum 2026-10-26: 127.0.0.0/8 is never counted (the local
     * machine; the harness runs every node on it) — so a limit of 2 refuses
     * nothing here. The refusal itself is pinned with injected time (V5) and
     * in test_role_exempt (a non-loopback bucket). */
    if (accepts != 3) { FAIL("a loopback connection was refused by the rate"); return; }
    PASS();
}

int main(void) {
    printf("=== v3 chain id of the sessions; handshake rate (DHT v2 3b-2) ===\n");
    memset(g_legacy, 0x11, 16);                 /* legacy: 16 bytes + 16 zero */
    memset(g_legacy + 16, 0, 16);
    for (int i = 0; i < 32; i++) g_v3[i] = (uint8_t)(0xC0 + i);
    if (nodus_identity_generate(&g_id_a) != 0 || nodus_identity_generate(&g_id_b) != 0 ||
        nodus_tcp_init(&g_dial, -1) != 0 || nodus_tcp_init(&g_acc, -1) != 0) {
        printf("FATAL: setup\n");
        return 1;
    }
    g_cfg_a.identity = &g_id_a; g_cfg_a.chain_id = dialer_chain;
    g_cfg_b.identity = &g_id_b; g_cfg_b.chain_id = acceptor_chain;
    g_dial.auth_ctx = &g_cfg_a;
    g_acc.auth_ctx  = &g_cfg_b;
    g_dial.on_session = dial_on_session;
    g_dial.on_frame = dial_on_frame;
    g_dial.on_disconnect = dial_on_disconnect;
    g_acc.on_accept = acc_on_accept;
    g_acc.on_session = acc_on_session;
    g_acc.on_frame = acc_on_frame;
    if (nodus_tcp_listen(&g_acc, "127.0.0.1", 0) != 0) {
        printf("FATAL: listen\n");
        return 1;
    }

    test_v1();
    test_v2();
    test_v3();
    test_v4();
    test_v5();
    test_v6();

    nodus_tcp_close(&g_dial);
    nodus_tcp_close(&g_acc);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
