/**
 * Nodus — the 4002 node session (SecretConnection, NODE profile), DHT v2 3b-2
 *
 * PROVES (nodus/src/server/nodus_inter_dial.c, the module core and
 * nodus-storage share, over two real loopback nodus_tcp pools):
 *   N1  a dial pinned to the right node id reaches an AUTHENTICATED session:
 *       the first send returns QUEUED (nodus_inter_pool_send_framed — not yet
 *       authenticated), the queued frame is replayed SEALED when the gate
 *       opens and arrives exactly once, then a second send returns WRITTEN;
 *       both ends then carry the other's proven identity (peer_id / peer_pk).
 *   N2  a dial pinned to a WRONG node id never authenticates: the dialer's
 *       connection is closed by the pin check before the ENCAPS step, no
 *       frame reaches the acceptor — a QUEUED frame is lost with the
 *       handshake (which is why a hint row must stay on QUEUED).
 *   N3  different chain ids on the two ends: the handshake fails, no frame
 *       arrives.
 *   N4  the dialer does not know its chain id: the dial is refused LOCALLY —
 *       NODUS_INTER_SEND_REFUSED, nothing queued, and the chain id is checked
 *       BEFORE the TCP connect (the acceptor sees no connection at all, no
 *       session, no frame); a dial with NO pin is refused the same way.
 *   N4b a NULL pin is refused first even when a pooled connection exists (no
 *       unpinned reuse through the find).
 *   N7  the connect + handshake bound of a dialed session (10 s) is measured
 *       on the monotonic clock from the dial stamp: a young dial whose
 *       connected_at is still 0 is NOT closed by nodus_inter_pool_sweep, one
 *       past the bound is.
 *   N5  the acceptor does not know its chain id: it closes the accepted
 *       connection; no session, no frame.
 *   N6  an OLD plaintext hello (a T2 `hello` frame, what a pre-3b-2 dialer
 *       sends) to the acceptor: the connection is closed, nothing is
 *       dispatched — there is no plaintext path left on 4002 accept.
 *
 * REQUIRES: a default build (libnodus compiled with NODUS_TCP_SC); a
 * loopback interface. No environment, no compile flag beyond the default.
 * LEAVES: nothing (two pools closed; ports are kernel-chosen).
 * HOW IT CAN LIE: every wait is a bounded poll loop whose exhaustion FAILs
 * the case. "No frame arrives" is checked after the wrong-pin connection was
 * seen closed — a handshake still in flight when the loop ends would show as
 * the close not happening, which FAILs. The chain-id and pin checks are the
 * layer's (nodus_tcp_sc.c, cmt_p2p_secret.c); this test pins that they are
 * wired to the node session, not their cryptography. The acceptor's token
 * message (auth_ok, txn 0) is not exercised here (core's on_inter_session).
 */

#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t g_id_a, g_id_b;           /* dialer / acceptor */
static nodus_tcp_t g_dial, g_acc;
static nodus_inter_session_cfg_t g_cfg_a, g_cfg_b;
static uint8_t g_chain_a[32], g_chain_b[32];
static bool g_known_a = true, g_known_b = true;

static int  g_acc_frames;                         /* frames the acceptor dispatched */
static char g_acc_last[32];
static int  g_dial_closed, g_acc_closed;
static int  g_dial_sessions, g_acc_sessions;
static nodus_tcp_conn_t *g_acc_session_conn;

static bool chain_a(void *ctx, uint8_t out[32]) {
    (void)ctx;
    if (!g_known_a) return false;
    memcpy(out, g_chain_a, 32);
    return true;
}

static bool chain_b(void *ctx, uint8_t out[32]) {
    (void)ctx;
    if (!g_known_b) return false;
    memcpy(out, g_chain_b, 32);
    return true;
}

/* The acceptor: what core's on_inter_accept / on_inter_session do. */
static int g_acc_accepts;                         /* connections the acceptor saw */

static void acc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    g_acc_accepts++;
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
    g_acc_sessions++;
    g_acc_session_conn = conn;
    nodus_inter_dial_conn_open(conn);
}

static void acc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    (void)conn; (void)ctx;
    size_t n = len < sizeof(g_acc_last) - 1 ? len : sizeof(g_acc_last) - 1;
    memcpy(g_acc_last, payload, n);
    g_acc_last[n] = '\0';
    g_acc_frames++;
}

static void acc_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    g_acc_closed++;
}

/* The dialer: what core's on_inter_session / the storage's do. */
static void dial_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (nodus_inter_session_proven(conn) != 0) {
        nodus_tcp_disconnect(&g_dial, conn);
        return;
    }
    g_dial_sessions++;
    nodus_inter_dial_conn_open(conn);
}

static void dial_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                          size_t len, void *ctx) {
    (void)conn; (void)payload; (void)len; (void)ctx;
}

static void dial_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    g_dial_closed++;
}

static void poll_both(void) {
    nodus_tcp_poll(&g_dial, 5);
    nodus_tcp_poll(&g_acc, 5);
}

/* Poll until `*counter` reaches `want`, at most ~6 s of polls. */
static bool wait_for(const int *counter, int want) {
    for (int i = 0; i < 600 && *counter < want; i++) poll_both();
    return *counter >= want;
}

static void reset_counters(void) {
    g_acc_frames = 0;
    g_acc_accepts = 0;
    g_acc_last[0] = '\0';
    g_dial_closed = g_acc_closed = 0;
    g_dial_sessions = g_acc_sessions = 0;
    g_acc_session_conn = NULL;
}

static nodus_inter_send_t send_one(const nodus_key_t *pin, const char *text) {
    uint8_t fr[64];
    size_t fl = nodus_frame_encode(fr, sizeof(fr), (const uint8_t *)text,
                                   (uint32_t)strlen(text));
    if (fl == 0) return NODUS_INTER_SEND_FAILED;
    return nodus_inter_pool_send_framed(&g_dial, "127.0.0.1", g_acc.port, pin, fr, fl);
}

static void close_all_dials(void) {
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (g_dial.pool[i]) nodus_tcp_disconnect(&g_dial, g_dial.pool[i]);
    for (int i = 0; i < 100; i++) poll_both();
}

static void test_right_pin(void) {
    TEST("N1 right pin: QUEUED, replayed sealed once, then WRITTEN");
    reset_counters();
    if (send_one(&g_id_b.node_id, "first") != NODUS_INTER_SEND_QUEUED) {
        FAIL("the first send on a fresh dial is not QUEUED");
        return;
    }
    if (!wait_for(&g_acc_frames, 1) || strcmp(g_acc_last, "first") != 0) {
        FAIL("the queued frame did not arrive after the handshake");
        return;
    }
    if (g_dial_sessions != 1 || g_acc_sessions != 1) {
        FAIL("each end must see exactly one authenticated session");
        return;
    }
    nodus_inter_send_t rc = send_one(&g_id_b.node_id, "second");
    if (rc != NODUS_INTER_SEND_WRITTEN) {
        FAIL("a send on an authenticated session is not WRITTEN");
        return;
    }
    if (!wait_for(&g_acc_frames, 2) || strcmp(g_acc_last, "second") != 0) {
        FAIL("the second frame did not arrive");
        return;
    }
    if (g_acc_frames != 2) { FAIL("a frame arrived twice"); return; }
    /* both ends carry the other's proven identity */
    nodus_tcp_conn_t *d = nodus_inter_pool_find(&g_dial, "127.0.0.1", g_acc.port,
                                                &g_id_b.node_id);
    nodus_key_t fa;
    nodus_fingerprint(&g_id_a.pk, &fa);
    if (!d || !d->authenticated || !d->peer_id_set ||
        nodus_key_cmp(&d->peer_id, &g_id_b.node_id) != 0 ||
        !g_acc_session_conn || !g_acc_session_conn->peer_id_set ||
        nodus_key_cmp(&g_acc_session_conn->peer_id, &fa) != 0) {
        FAIL("proven peer identity not recorded on both ends");
        return;
    }
    PASS();
    close_all_dials();
}

static void test_wrong_pin(void) {
    TEST("N2 wrong pin: closed before ENCAPS, the queued frame is lost");
    reset_counters();
    nodus_key_t wrong;
    memset(&wrong, 0x77, sizeof(wrong));
    if (send_one(&wrong, "lost") != NODUS_INTER_SEND_QUEUED) {
        FAIL("a dial pinned to another id must still start (QUEUED)");
        return;
    }
    if (!wait_for(&g_dial_closed, 1)) { FAIL("the pin mismatch did not close the dial"); return; }
    for (int i = 0; i < 50; i++) poll_both();
    if (g_acc_frames != 0 || g_dial_sessions != 0 || g_acc_sessions != 0) {
        FAIL("a session or a frame came out of a pin mismatch");
        return;
    }
    PASS();
}

static void test_wrong_chain(void) {
    TEST("N3 different chain ids: the handshake fails, no frame");
    reset_counters();
    g_chain_a[0] ^= 0xff;
    nodus_inter_send_t rc = send_one(&g_id_b.node_id, "wrong-chain");
    bool started = rc == NODUS_INTER_SEND_QUEUED;
    bool closed = started && wait_for(&g_dial_closed, 1);
    for (int i = 0; i < 50; i++) poll_both();
    g_chain_a[0] ^= 0xff;
    if (!started || !closed) { FAIL("the chain mismatch did not close the dial"); return; }
    if (g_acc_frames != 0 || g_acc_sessions != 0) { FAIL("a session came out of a chain mismatch"); return; }
    PASS();
}

static void test_dialer_chain_unknown(void) {
    TEST("N4 dialer without a chain id / without a pin: REFUSED, no connect");
    reset_counters();
    g_known_a = false;
    nodus_inter_send_t rc = send_one(&g_id_b.node_id, "no-chain");
    g_known_a = true;
    nodus_inter_send_t rc2 = send_one(NULL, "no-pin");
    if (rc != NODUS_INTER_SEND_REFUSED) { FAIL("a dial with an unknown chain id was not refused"); return; }
    if (rc2 != NODUS_INTER_SEND_REFUSED) { FAIL("an unpinned dial was not refused"); return; }
    for (int i = 0; i < 30; i++) poll_both();
    /* what matters: the chain id is checked BEFORE the TCP connect — the
     * acceptor never saw a connection — and no session or frame was served */
    if (g_acc_accepts != 0 || g_acc_closed != 0 || g_acc_frames != 0 ||
        g_acc_sessions != 0 || g_dial_sessions != 0) {
        FAIL("a connection, session or frame came out of a refused dial");
        return;
    }
    PASS();
}

static void test_null_pin_with_pooled_conn(void) {
    TEST("N4b a NULL pin is refused even when a pooled conn exists");
    reset_counters();
    if (send_one(&g_id_b.node_id, "pooled") != NODUS_INTER_SEND_QUEUED ||
        !wait_for(&g_acc_frames, 1)) {
        FAIL("could not establish the pooled connection");
        return;
    }
    /* find with a NULL pin would hand back the pooled conn: the refusal
     * must come first (no unpinned dial, no unpinned reuse) */
    nodus_inter_send_t rc = send_one(NULL, "unpinned");
    for (int i = 0; i < 30; i++) poll_both();
    if (rc != NODUS_INTER_SEND_REFUSED) { FAIL("a NULL-pin send reused or dialed"); return; }
    if (g_acc_frames != 1) { FAIL("the unpinned frame was delivered"); return; }
    PASS();
    close_all_dials();
}

static void test_dial_bound(void) {
    TEST("N7 handshake bound is monotonic from the dial; a young dial stays");
    reset_counters();
    if (send_one(&g_id_b.node_id, "slow") != NODUS_INTER_SEND_QUEUED) {
        FAIL("dial not started");
        return;
    }
    nodus_tcp_conn_t *d = nodus_inter_pool_find(&g_dial, "127.0.0.1", g_acc.port,
                                                &g_id_b.node_id);
    if (!d || d->auth_state != NODUS_CONN_AUTH_HELLO_SENT) {
        FAIL("the dialed conn is not in HELLO_SENT");
        return;
    }
    /* a conn whose connect has not completed has connected_at == 0: the old
     * sweep (connected_at based) would have closed it at once */
    d->connected_at = 0;
    d->dial_mono_ms = nodus_time_mono_ms();
    nodus_inter_pool_sweep(&g_dial, nodus_time_now());
    if (g_dial.pool[d->slot] != d) { FAIL("a young dial was closed by the sweep"); return; }
    d->dial_mono_ms = nodus_time_mono_ms() - 11000;   /* older than the 10 s bound */
    nodus_inter_pool_sweep(&g_dial, nodus_time_now());
    if (g_dial.pool[d->slot] == d) { FAIL("a dial past the bound was kept"); return; }
    PASS();
    close_all_dials();
}

static void test_acceptor_chain_unknown(void) {
    TEST("N5 acceptor without a chain id closes the accepted connection");
    reset_counters();
    g_known_b = false;
    nodus_inter_send_t rc = send_one(&g_id_b.node_id, "late");
    bool closed = rc == NODUS_INTER_SEND_QUEUED && wait_for(&g_dial_closed, 1);
    for (int i = 0; i < 30; i++) poll_both();
    g_known_b = true;
    if (!closed) { FAIL("the dial was not closed"); return; }
    if (g_acc_frames != 0 || g_acc_sessions != 0) { FAIL("a session was served"); return; }
    PASS();
}

static void test_plaintext_hello(void) {
    TEST("N6 an old plaintext T2 hello is refused and never dispatched");
    reset_counters();
    nodus_tcp_conn_t *raw = nodus_tcp_connect(&g_dial, "127.0.0.1", g_acc.port);
    if (!raw) { FAIL("connect"); return; }
    for (int i = 0; i < 400 && raw->state != NODUS_CONN_CONNECTED; i++) poll_both();
    uint8_t buf[8192];
    size_t len = 0;
    if (raw->state != NODUS_CONN_CONNECTED ||
        nodus_t2_hello(0, &g_id_a.pk, &g_id_a.node_id, buf, sizeof(buf), &len) != 0 ||
        nodus_tcp_send(raw, buf, len) != 0) {
        FAIL("could not send the old hello");
        return;
    }
    if (!wait_for(&g_dial_closed, 1)) { FAIL("the acceptor kept a plaintext connection"); return; }
    if (g_acc_frames != 0 || g_acc_sessions != 0) { FAIL("the hello was dispatched"); return; }
    PASS();
}

int main(void) {
    printf("=== 4002 node session (DHT v2 3b-2) ===\n");
    memset(g_chain_a, 0x5c, sizeof(g_chain_a));
    memcpy(g_chain_b, g_chain_a, sizeof(g_chain_b));
    if (nodus_identity_generate(&g_id_a) != 0 || nodus_identity_generate(&g_id_b) != 0) {
        printf("FATAL: identities\n");
        return 1;
    }
    if (nodus_tcp_init(&g_dial, -1) != 0 || nodus_tcp_init(&g_acc, -1) != 0) {
        printf("FATAL: transports\n");
        return 1;
    }
    g_cfg_a.identity = &g_id_a; g_cfg_a.chain_id = chain_a;
    g_cfg_b.identity = &g_id_b; g_cfg_b.chain_id = chain_b;
    g_dial.auth_ctx = &g_cfg_a;
    g_acc.auth_ctx  = &g_cfg_b;
    g_dial.on_session = dial_on_session;
    g_dial.on_frame = dial_on_frame;
    g_dial.on_disconnect = dial_on_disconnect;
    g_acc.on_accept = acc_on_accept;
    g_acc.on_session = acc_on_session;
    g_acc.on_frame = acc_on_frame;
    g_acc.on_disconnect = acc_on_disconnect;
    if (nodus_tcp_listen(&g_acc, "127.0.0.1", 0) != 0) {
        printf("FATAL: listen\n");
        return 1;
    }

    test_right_pin();
    test_wrong_pin();
    test_wrong_chain();
    test_dialer_chain_unknown();
    test_null_pin_with_pooled_conn();
    test_dial_bound();
    test_acceptor_chain_unknown();
    test_plaintext_hello();

    nodus_tcp_close(&g_dial);
    nodus_tcp_close(&g_acc);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
