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
 *   E7  generation: a credit recorded against an evicted bucket incarnation
 *       does not reduce the count of the recreated bucket, even when both
 *       windows start at the same millisecond.
 *   E8  revalidation (nodus_server_role_revalidate): with a KNOWN set that no
 *       longer holds the proven key, role_exempt is cleared on live
 *       connections of both transports; with an UNKNOWN set nothing changes;
 *       a still-member keeps the flag; a never-exempt connection is untouched.
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
 * loop skips role_exempt connections, not that on_session marks them. E8 uses
 * a fake backend (two function pointers) and hand-placed pool entries: it
 * proves the walk and the fail-safe rule, not that the real backends' sets
 * refresh or that the run loop calls the walk on time.
 */

#include "transport/nodus_tcp.h"
#include "server/nodus_chain_backend.h"
#include "server/nodus_server.h"

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

/* The generation of the live window of `who` (what the accept path records in
 * conn->hs_gen). */
static uint64_t gen_of(const nodus_tcp_t *t, const nodus_ws_ip_bucket_t *who) {
    for (int i = 0; i < NODUS_TCP_HS_RATE_TABLE; i++)
        if (t->hs_rate[i].used && memcmp(&t->hs_rate[i].who, who, sizeof(*who)) == 0)
            return t->hs_rate[i].gen;
    return 0;
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
        c->hs_gen = gen_of(t, &a);  /* the window generation the attempt was counted in */
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
    c->hs_gen = gen_of(t, &a);
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

static void test_e7(void) {
    TEST("E7 a credit never lands in a recreated bucket (same start time)");
    nodus_tcp_t *t = calloc(1, sizeof(*t));
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!t || !c) { FAIL("alloc"); free(t); free(c); return; }
    t->hs_rate_per_min = 5;
    nodus_ws_ip_bucket_t a = bucket_of("198.51.100.4");
    const uint64_t t0 = 4000000;
    (void)nodus_tcp_hs_rate_allow(t, &a, t0);
    c->hs_bucket = a;
    c->hs_gen = gen_of(t, &a);
    c->hs_counted = true;
    /* fill the table with other IPs (later windows): a, the oldest, is evicted */
    for (int i = 0; i < NODUS_TCP_HS_RATE_TABLE; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.%d.%d.1", i / 250, i % 250);
        nodus_ws_ip_bucket_t o = bucket_of(ip);
        (void)nodus_tcp_hs_rate_allow(t, &o, t0 + 1 + (uint64_t)i);
    }
    /* a comes back at the SAME start time: a new incarnation, count 1 */
    (void)nodus_tcp_hs_rate_allow(t, &a, t0);
    nodus_tcp_role_exempt(t, c);                 /* the OLD attempt's credit */
    int more = 0;
    for (int i = 0; i < 6; i++)
        if (nodus_tcp_hs_rate_allow(t, &a, t0 + 5)) more++;
    free(t);
    free(c);
    /* count was 1 (the new incarnation): 4 more are admitted; a wrongly landed
     * credit would have left room for 5 */
    if (more != 4) { FAIL("the old attempt's credit reduced the recreated bucket"); return; }
    PASS();
}

/* ── E8: revalidation of live exemptions against a refreshed role set ── */
static bool g_known, g_member;
static bool fake_known(nodus_chain_backend_t *b) { (void)b; return g_known; }
static bool fake_has_role(nodus_chain_backend_t *b, const nodus_key_t *id) {
    (void)b; (void)id; return g_known && g_member;
}

static void test_e8(void) {
    TEST("E8 revalidation: a role that ended clears the flag; unknown keeps it");
    static nodus_server_t srv;           /* big: static, zero-initialised */
    nodus_chain_backend_ops_t ops;
    memset(&srv, 0, sizeof(srv));
    memset(&ops, 0, sizeof(ops));
    ops.has_role = fake_has_role;
    ops.roles_known = fake_known;
    nodus_chain_backend_t be = { &ops };
    srv.chain = &be;
    nodus_tcp_conn_t *c1 = calloc(1, sizeof(*c1));   /* on the client transport */
    nodus_tcp_conn_t *c2 = calloc(1, sizeof(*c2));   /* on 4002 */
    nodus_tcp_conn_t *c3 = calloc(1, sizeof(*c3));   /* never exempt */
    if (!c1 || !c2 || !c3) { FAIL("alloc"); free(c1); free(c2); free(c3); return; }
    c1->role_exempt = c2->role_exempt = true;
    c1->peer_id_set = c2->peer_id_set = c3->peer_id_set = true;
    srv.tcp.pool[0] = c1;
    srv.inter_tcp.pool[0] = c2;
    srv.tcp.pool[1] = c3;

    g_known = false; g_member = false;           /* UNKNOWN set: nothing changes */
    int n_unknown = nodus_server_role_revalidate(&srv);
    bool kept = c1->role_exempt && c2->role_exempt;
    g_known = true; g_member = true;             /* still a member: kept */
    int n_member = nodus_server_role_revalidate(&srv);
    bool still = c1->role_exempt && c2->role_exempt;
    g_member = false;                            /* the role ended */
    int n_gone = nodus_server_role_revalidate(&srv);
    bool cleared = !c1->role_exempt && !c2->role_exempt && !c3->role_exempt;
    free(c1); free(c2); free(c3);
    if (n_unknown != 0 || !kept) { FAIL("an unknown set changed the flags"); return; }
    if (n_member != 0 || !still) { FAIL("a member lost the flag"); return; }
    if (n_gone != 2 || !cleared) { FAIL("the flag survived the end of the role"); return; }
    PASS();
}

int main(void) {
    printf("=== per-IP limits: nodes with an active role are exempt ===\n");
    test_e1_e6();
    test_e2();
    test_e3();
    test_e4();
    test_e5();
    test_e7();
    test_e8();
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
