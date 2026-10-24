/**
 * Nodus — a send that the transport diverts to its queue-full fallback is NOT
 * "written" (DHT v2 3b-2 fix round, hint loss on queue full)
 *
 * PROVES (nodus_inter_pool_send_framed over a real authenticated node
 * session, real nodus_tcp queue-full path nodus_tcp.c send_sc_locked):
 *   Q1  while the peer's session takes the data, every send is
 *       NODUS_INTER_SEND_WRITTEN and tcp->on_pending_full is never called;
 *   Q2  once the peer stops reading and the connection's write buffer, the
 *       kernel buffers and the NODUS_PENDING_MAX_FRAMES pending queue are all
 *       full, the next send goes to tcp->on_pending_full — which makes
 *       nodus_tcp_send report 0 although nothing was written — and
 *       nodus_inter_pool_send_framed reports NODUS_INTER_SEND_QUEUED, NOT
 *       WRITTEN. The hinted-handoff retry deletes its durable row only on
 *       WRITTEN (test_hint_tristate); the fallback's own hint insert is an
 *       INSERT OR IGNORE against that very row, so returning WRITTEN here
 *       would lose the frame everywhere.
 *   Q3  no send returns FAILED on the way (the connection is not torn down
 *       by the diversion).
 *
 * REQUIRES: a default build (libnodus compiled with NODUS_TCP_SC); loopback.
 * No environment, no flag. LEAVES: nothing (two pools closed).
 * HOW IT CAN LIE: the loop is bounded (2000 frames of 60,000 bytes = 120 MB
 * offered); if the kernel buffered all of it the case FAILs ("queue never
 * filled") rather than passing. The on_pending_full hook here only counts —
 * it stands in for the hint-table insert; the point is the return value of
 * the pool send, not what the hook stores. The acceptor is simply not polled
 * after the handshake, which is how a slow consumer looks to the sender.
 */

#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;

static nodus_identity_t g_id_a, g_id_b;
static uint8_t g_chain[32];
static nodus_tcp_t g_dial, g_acc;
static nodus_inter_session_cfg_t g_cfg_a, g_cfg_b;
static int g_dial_sessions, g_acc_frames, g_full_calls;

static bool chain_fn(void *ctx, uint8_t out[32]) {
    (void)ctx;
    memcpy(out, g_chain, 32);
    return true;
}

static void acc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    conn->is_nodus = true;
    if (nodus_inter_session_enable(&g_acc, conn, false) != 0)
        nodus_tcp_disconnect(&g_acc, conn);
}

static void acc_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (nodus_inter_session_proven(conn) != 0) nodus_tcp_disconnect(&g_acc, conn);
    else nodus_inter_dial_conn_open(conn);
}

static void acc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *p, size_t l, void *ctx) {
    (void)conn; (void)p; (void)l; (void)ctx;
    g_acc_frames++;
}

static void dial_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (nodus_inter_session_proven(conn) != 0) { nodus_tcp_disconnect(&g_dial, conn); return; }
    g_dial_sessions++;
    nodus_inter_dial_conn_open(conn);
}

static void dial_on_frame(nodus_tcp_conn_t *conn, const uint8_t *p, size_t l, void *ctx) {
    (void)conn; (void)p; (void)l; (void)ctx;
}

static void dial_on_full(nodus_tcp_conn_t *conn, const uint8_t *p, size_t l, void *ctx) {
    (void)conn; (void)p; (void)l; (void)ctx;
    g_full_calls++;
}

#define BIG 60000
static uint8_t g_payload[BIG], g_frame[BIG + 16];

static nodus_inter_send_t send_big(void) {
    size_t fl = nodus_frame_encode(g_frame, sizeof(g_frame), g_payload, BIG);
    if (fl == 0) return NODUS_INTER_SEND_FAILED;
    return nodus_inter_pool_send_framed(&g_dial, "127.0.0.1", g_acc.port,
                                        &g_id_b.node_id, g_frame, fl);
}

static void check(bool ok, const char *name, const char *why) {
    printf("  %-66s", name);
    if (ok) { printf("PASS\n"); passed++; }
    else { printf("FAIL: %s\n", why); failed++; }
}

int main(void) {
    printf("=== a send diverted to the queue-full fallback is not WRITTEN ===\n");
    memset(g_chain, 0x5c, sizeof(g_chain));
    memset(g_payload, 0xa5, sizeof(g_payload));
    if (nodus_identity_generate(&g_id_a) != 0 || nodus_identity_generate(&g_id_b) != 0 ||
        nodus_tcp_init(&g_dial, -1) != 0 || nodus_tcp_init(&g_acc, -1) != 0) {
        printf("FATAL: setup\n");
        return 1;
    }
    g_cfg_a.identity = &g_id_a; g_cfg_a.chain_id = chain_fn;
    g_cfg_b.identity = &g_id_b; g_cfg_b.chain_id = chain_fn;
    g_dial.auth_ctx = &g_cfg_a;
    g_acc.auth_ctx  = &g_cfg_b;
    g_dial.on_session = dial_on_session;
    g_dial.on_frame = dial_on_frame;
    g_dial.on_pending_full = dial_on_full;
    g_acc.on_accept = acc_on_accept;
    g_acc.on_session = acc_on_session;
    g_acc.on_frame = acc_on_frame;
    if (nodus_tcp_listen(&g_acc, "127.0.0.1", 0) != 0) { printf("FATAL: listen\n"); return 1; }

    /* handshake: one small frame queued, then both ends polled until the
     * dialer's session is up and the frame arrived */
    uint8_t small[4] = { 1, 2, 3, 4 };
    uint8_t sf[32];
    size_t sl = nodus_frame_encode(sf, sizeof(sf), small, sizeof(small));
    nodus_inter_send_t rc = nodus_inter_pool_send_framed(&g_dial, "127.0.0.1", g_acc.port,
                                                         &g_id_b.node_id, sf, sl);
    for (int i = 0; i < 600 && (g_dial_sessions < 1 || g_acc_frames < 1); i++) {
        nodus_tcp_poll(&g_dial, 5);
        nodus_tcp_poll(&g_acc, 5);
    }
    if (rc != NODUS_INTER_SEND_QUEUED || g_dial_sessions != 1 || g_acc_frames != 1) {
        printf("FATAL: no authenticated session (rc=%d)\n", (int)rc);
        return 1;
    }

    /* the peer stops reading: only the sender is polled from here on */
    int written = 0, failed_sends = 0;
    nodus_inter_send_t last = NODUS_INTER_SEND_WRITTEN;
    int full_before_div = 0;
    for (int i = 0; i < 2000; i++) {
        int full0 = g_full_calls;
        last = send_big();
        nodus_tcp_poll(&g_dial, 0);
        if (last == NODUS_INTER_SEND_FAILED) { failed_sends++; break; }
        if (last == NODUS_INTER_SEND_WRITTEN) {
            written++;
            if (g_full_calls != full0) { full_before_div++; break; }
            continue;
        }
        if (last == NODUS_INTER_SEND_QUEUED) {
            if (g_full_calls == full0 + 1) break;   /* the diversion */
            break;                                   /* QUEUED without it: caught below */
        }
    }

    check(written > 0 && full_before_div == 0,
          "Q1 sends are WRITTEN while the session takes data, no fallback",
          "a send was reported WRITTEN although the fallback took it");
    check(last == NODUS_INTER_SEND_QUEUED && g_full_calls == 1,
          "Q2 the diverted send is QUEUED (not WRITTEN), the fallback ran once",
          "the queue-full send was not reported QUEUED (queue never filled?)");
    check(failed_sends == 0, "Q3 no send failed on the way",
          "a send returned FAILED / the connection was torn down");

    nodus_tcp_close(&g_dial);
    nodus_tcp_close(&g_acc);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
