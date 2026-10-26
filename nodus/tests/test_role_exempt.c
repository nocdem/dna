/**
 * Nodus — nodes with an active on-chain role are exempt from the per-IP
 * limits of 4001 / WS / 4002 accept (DHT v2 3b-2, operator addendum
 * 2026-10-26, decisions/2026-10-24-dht-v2-handshake-rate.md)
 *
 * PROVES
 *   E1  rate credit: a proven peer with an active role is credited back
 *       (nodus_tcp_role_exempt) — 150 attempts from one non-loopback IP inside
 *       one minute, each credited, are never refused; the same IP WITHOUT the
 *       credit (an unbonded peer) is admitted 60 times and refused at the 61st.
 *   E2  a credit lands only in the window the attempt was counted in: after
 *       the minute rolled over, crediting an old attempt does not reduce the
 *       new window's count.
 *   E3  loopback (127.0.0.0/8, ::1, ::ffff:127.x) is classified exempt by
 *       nodus_tcp_ip_is_loopback and is never refused on a REAL accept (a
 *       limit of 1 admits five connections from 127.0.0.1); a non-loopback
 *       text is not loopback.
 *   E4  the concurrent per-IP cap: on a real listener, an unmarked set of
 *       connections from one IP is capped at NODUS_MAX_CONNS_PER_IP (20); once
 *       those 20 are role_exempt, further connections from the same IP are
 *       admitted (the exempt ones no longer count) — more than 20 in total.
 *   E5  fail safe: nodus_role_set_has is false for an unknown set, for a set
 *       older than NODUS_ROLE_SET_STALE_MS, for a NULL set and for an identity
 *       not in the set; true only for a member of a known, fresh set.
 *   E6  nothing credited without the call: with the credit never made (the
 *       "set unknown" path of the server, which then never calls
 *       nodus_tcp_role_exempt), the limit applies exactly as before (61st
 *       refused) — the same as E1's unbonded half.
 *
 * REQUIRES: a default build (libnodus); a loopback interface. No environment
 * and no compile flag beyond the default.
 * LEAVES: nothing (transports closed, kernel-chosen ports).
 * HOW IT CAN LIE: E1/E2 fabricate connections (calloc'd structs with the
 * counted-attempt fields set by hand, as the accept path sets them) and drive
 * nodus_tcp_hs_rate_allow with injected time: they prove the credit arithmetic
 * and the window rule, NOT that the server calls the credit for the right
 * identity — the choice of key (conn->peer_id, the layer's proven key) and the
 * backend predicate (has_role: the witness' roles_fill; tests/
 * test_witness_ipc covers the answer, not the chain contents) are not run here.
 * E3/E4 use real sockets and the wall clock only for "a few polls". E4 marks
 * the accepted connections by hand (what on_session does): it proves the cap
 * loop skips role_exempt connections, not that on_session marks them.
 */

#include "transport/nodus_tcp.h"
#include "server/nodus_chain_backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;
#define TEST(name) do { printf("  %-72s", name); } while (0)
#define PASS() do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); failed++; } while (0)

static nodus_ws_ip_bucket_t bucket_of(const char *ip) {
    nodus_ws_ip_bucket_t b;
    memset(&b, 0, sizeof(b));
    (void)nodus_ws_ip_bucket(ip, &b);
    return b;
}

static void test_e1_e6(void) {
    TEST("E1 credited attempts never refused; uncredited refused at 61");
    nodus_tcp_t *t = calloc(1, sizeof(*t));
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!t || !c) { FAIL("alloc"); free(t); free(c); return; }
    t->hs_rate_per_min = 60;
    nodus_ws_ip_bucket_t a = bucket_of("203.0.113.9");
    nodus_ws_ip_bucket_t u = bucket_of("203.0.113.77");
    const uint64_t t0 = 5000000;
    bool bonded_ok = true;
    for (int i = 0; i < 150; i++) {
        /* the accept counts the attempt ... */
        bonded_ok = bonded_ok && nodus_tcp_hs_rate_allow(t, &a, t0 + (uint64_t)i);
        /* ... and the proven bonded key credits it back */
        memset(c, 0, sizeof(*c));
        c->hs_bucket = a;
        c->hs_window_ms = t0;       /* the window the first attempt opened */
        c->hs_counted = true;
        nodus_tcp_role_exempt(t, c);
        if (!c->role_exempt || c->hs_counted) bonded_ok = false;
    }
    int ok_unbonded = 0;
    bool refused_61 = false;
    for (int i = 0; i < 61; i++) {
        if (nodus_tcp_hs_rate_allow(t, &u, t0 + 1000 + (uint64_t)i)) ok_unbonded++;
        else refused_61 = true;
    }
    free(t);
    free(c);
    if (!bonded_ok) { FAIL("a credited (bonded) attempt was refused"); return; }
    if (ok_unbonded != 60 || !refused_61) { FAIL("the unbonded IP is not refused at the 61st"); return; }
    PASS();

    TEST("E6 no credit made (set unknown): the limit applies as before");
    t = calloc(1, sizeof(*t));
    if (!t) { FAIL("alloc"); return; }
    t->hs_rate_per_min = 60;
    int ok = 0;
    for (int i = 0; i < 61; i++)
        if (nodus_tcp_hs_rate_allow(t, &a, t0 + (uint64_t)i)) ok++;
    free(t);
    if (ok != 60) { FAIL("not exactly 60 admitted"); return; }
    PASS();
}

static void test_e2(void) {
    TEST("E2 a credit never lands in a later minute");
    nodus_tcp_t *t = calloc(1, sizeof(*t));
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!t || !c) { FAIL("alloc"); free(t); free(c); return; }
    t->hs_rate_per_min = 5;
    nodus_ws_ip_bucket_t a = bucket_of("198.51.100.4");
    const uint64_t t0 = 9000000;
    (void)nodus_tcp_hs_rate_allow(t, &a, t0);            /* window opens at t0 */
    c->hs_bucket = a;
    c->hs_window_ms = t0;
    c->hs_counted = true;
    /* a new minute: 3 attempts in the new window */
    for (int i = 0; i < 3; i++)
        (void)nodus_tcp_hs_rate_allow(t, &a, t0 + 70000 + (uint64_t)i);
    nodus_tcp_role_exempt(t, c);                          /* credit of the OLD attempt */
    /* the new window must still hold 3: two more admitted, the sixth refused */
    bool two = nodus_tcp_hs_rate_allow(t, &a, t0 + 70010) &&
               nodus_tcp_hs_rate_allow(t, &a, t0 + 70011);
    bool sixth = nodus_tcp_hs_rate_allow(t, &a, t0 + 70012);
    free(t);
    free(c);
    if (!two || sixth) { FAIL("the old attempt's credit reduced the new window"); return; }
    PASS();
}

static int g_acc;
static void on_acc(nodus_tcp_conn_t *conn, void *ctx) { (void)conn; (void)ctx; g_acc++; }

static int open_clients(nodus_tcp_t *cli, uint16_t port, int n) {
    int ok = 0;
    for (int i = 0; i < n; i++)
        if (nodus_tcp_connect(cli, "127.0.0.1", port)) ok++;
    return ok;
}

static int pool_count(const nodus_tcp_t *t) {
    int n = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (t->pool[i] && !t->pool[i]->close_pending) n++;
    return n;
}

static void pump(nodus_tcp_t *a, nodus_tcp_t *b) {
    for (int i = 0; i < 80; i++) { nodus_tcp_poll(a, 5); nodus_tcp_poll(b, 5); }
}

static void test_e3(void) {
    TEST("E3 loopback is exempt (classification + a real accept)");
    bool cls = nodus_tcp_ip_is_loopback("127.0.0.1") && nodus_tcp_ip_is_loopback("127.9.9.9") &&
               nodus_tcp_ip_is_loopback("::1") && nodus_tcp_ip_is_loopback("::ffff:127.0.0.1") &&
               !nodus_tcp_ip_is_loopback("128.0.0.1") && !nodus_tcp_ip_is_loopback("203.0.113.1") &&
               !nodus_tcp_ip_is_loopback(NULL);
    nodus_tcp_t srv, cli;
    if (nodus_tcp_init(&srv, -1) != 0 || nodus_tcp_init(&cli, -1) != 0) { FAIL("init"); return; }
    srv.hs_rate_per_min = 1;
    srv.on_accept = on_acc;
    g_acc = 0;
    if (nodus_tcp_listen(&srv, "127.0.0.1", 0) != 0) { FAIL("listen"); return; }
    int made = open_clients(&cli, srv.port, 5);
    pump(&srv, &cli);
    int acc = g_acc;
    nodus_tcp_close(&cli);
    nodus_tcp_close(&srv);
    if (!cls) { FAIL("loopback classification"); return; }
    if (made != 5 || acc != 5) { FAIL("a loopback connection was refused by the rate"); return; }
    PASS();
}

static void test_e4(void) {
    TEST("E4 the per-IP cap: 20 unmarked; role_exempt ones do not count");
    nodus_tcp_t srv, cli;
    if (nodus_tcp_init(&srv, -1) != 0 || nodus_tcp_init(&cli, -1) != 0) { FAIL("init"); return; }
    srv.hs_rate_per_min = 0;
    if (nodus_tcp_listen(&srv, "127.0.0.1", 0) != 0) { FAIL("listen"); return; }
    (void)open_clients(&cli, srv.port, 25);
    pump(&srv, &cli);
    int capped = pool_count(&srv);                    /* the cap: 20 */
    /* the proven keys have an active role (what on_session does) */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (srv.pool[i]) nodus_tcp_role_exempt(&srv, srv.pool[i]);
    (void)open_clients(&cli, srv.port, 10);
    pump(&srv, &cli);
    int after = pool_count(&srv);
    nodus_tcp_close(&cli);
    nodus_tcp_close(&srv);
    if (capped != NODUS_MAX_CONNS_PER_IP) { FAIL("unmarked connections are not capped at 20"); return; }
    if (after <= NODUS_MAX_CONNS_PER_IP) { FAIL("role_exempt connections still count toward the cap"); return; }
    PASS();
}

static void test_e5(void) {
    TEST("E5 nodus_role_set_has: fail safe");
    static uint8_t fps[2][64];
    memset(fps[0], 0xA1, 64);
    memset(fps[1], 0xB2, 64);
    nodus_role_set_t s;
    memset(&s, 0, sizeof(s));
    s.fps = fps;
    s.n = 2;
    s.known = true;
    s.at_ms = 1000;
    nodus_key_t in, out;
    memset(in.bytes, 0xB2, 64);
    memset(out.bytes, 0xC3, 64);
    bool member = nodus_role_set_has(&s, &in, 2000);
    bool stranger = nodus_role_set_has(&s, &out, 2000);
    bool stale = nodus_role_set_has(&s, &in, 1000 + NODUS_ROLE_SET_STALE_MS + 1);
    s.known = false;
    bool unknown = nodus_role_set_has(&s, &in, 2000);
    bool null_set = nodus_role_set_has(NULL, &in, 2000);
    if (!member) { FAIL("a member of a fresh known set is not found"); return; }
    if (stranger || stale || unknown || null_set) { FAIL("an identity was exempted without a known fresh set"); return; }
    PASS();
}

int main(void) {
    printf("=== per-IP limits: nodes with an active role are exempt ===\n");
    test_e1_e6();
    test_e2();
    test_e3();
    test_e4();
    test_e5();
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
