/**
 * Nodus — frames queued during a 4002 dial's handshake are re-sent
 * ENCRYPTED, in order, when the channel key is set (split S5b fix round F2)
 *
 * Before the fix, nodus_inter_dial_conn_open DISCARDED the auth queue at
 * key_ack although every sender had been told "queued" (0):
 * nodus_inter_pool_send_framed (replication, republish, hinted retry — the
 * retry then deleted its hint row) and nodus_tcp_send (p_sync, a circuit's
 * ri_open). The frames never left.
 *
 * Pins down, with two real loopback transports (no event loop besides the
 * test's own bounded polls):
 *   - a dialed, auth_required connection that is not AUTH_OK queues three
 *     pre-framed frames (nodus_inter_pool_send_framed) and one payload
 *     (nodus_tcp_send) in its auth queue, and nothing reaches the peer;
 *   - after the channel key is set on both ends (the same
 *     nodus_channel_crypto_init the dialer module and the acceptor run at
 *     key_ack / key_init) and nodus_inter_dial_conn_open(conn, true) runs,
 *     the peer receives exactly those four payloads, in queue order, and
 *     the auth queue is empty;
 *   - they arrived ENCRYPTED: the accepting end has channel crypto
 *     established, so a plaintext frame would fail its decryption and be
 *     skipped (decrypt_skip_count) — the test requires zero skips.
 *
 * The ACCEPTING side (split S5): core's dispatch_inter key_init branch now
 * calls the same nodus_inter_dial_conn_open(conn, true) for an
 * authenticated peer instead of freeing its auth queue. Pinned here on the
 * shared function directly: an accepted conn gated like on_inter_accept
 * gates it (auth_required, not AUTH_OK) queues three payloads, nothing
 * reaches the dialing end; after the key is set on both ends (accepted =
 * RESPONDER, dialed = INITIATOR) and conn_open runs, the dialing end
 * receives exactly those three, in order, with zero decryption skips.
 * NOT driven here: dispatch_inter itself (needs a full server) — so its
 * "unauthenticated peer → gate stays closed, queue kept" branch is not
 * covered by this test.
 *
 * The CRIT-1 handshake itself is not run here (test_inter_dial covers the
 * module); the key is set directly on both ends.
 *
 * Requires: a default build; a loopback interface. Leaves behind: nothing.
 * How it can lie: every wait is a bounded poll loop whose exhaustion FAILs
 * the case.
 */

#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-64s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_tcp_t g_dial, g_acc;
static nodus_tcp_conn_t *g_acc_conn = NULL;
static char g_got[8][16];
static int  g_ngot = 0;

static void acc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    g_acc_conn = conn;
}

static void acc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    (void)conn; (void)ctx;
    if (g_ngot < 8 && len < sizeof(g_got[0])) {
        memcpy(g_got[g_ngot], payload, len);
        g_got[g_ngot][len] = '\0';
    }
    g_ngot++;
}

/* What the DIALING end receives (the acceptor-side case). */
static char g_dgot[8][16];
static int  g_dngot = 0;

static void dial_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                          size_t len, void *ctx) {
    (void)conn; (void)ctx;
    if (g_dngot < 8 && len < sizeof(g_dgot[0])) {
        memcpy(g_dgot[g_dngot], payload, len);
        g_dgot[g_dngot][len] = '\0';
    }
    g_dngot++;
}

static void poll_both(void) {
    nodus_tcp_poll(&g_dial, 5);
    nodus_tcp_poll(&g_acc, 5);
}

static void test_replay(void) {
    TEST("auth-queued frames re-sent encrypted, in order, at conn_open");
    nodus_key_t pin;
    memset(&pin, 0x42, sizeof(pin));
    nodus_tcp_conn_t *c = nodus_inter_pool_dial(&g_dial, "127.0.0.1",
                                                g_acc.port, &pin);
    if (!c) { FAIL("dial"); return; }
    for (int i = 0; i < 400 && (!g_acc_conn || c->state != NODUS_CONN_CONNECTED); i++)
        poll_both();
    if (!g_acc_conn || c->state != NODUS_CONN_CONNECTED) { FAIL("connect"); return; }
    if (!c->auth_required || c->auth_state == NODUS_CONN_AUTH_OK) {
        FAIL("the dial is not gated by auth");
        return;
    }

    /* Queue: three pre-framed frames, then one payload. */
    const char *pl[4] = { "one", "two", "three", "four" };
    for (int i = 0; i < 3; i++) {
        uint8_t fr[64];
        size_t fl = nodus_frame_encode(fr, sizeof(fr), (const uint8_t *)pl[i],
                                       (uint32_t)strlen(pl[i]));
        if (fl == 0 ||
            nodus_inter_pool_send_framed(&g_dial, "127.0.0.1", g_acc.port,
                                         &pin, fr, fl) != 0) {
            FAIL("queue a pre-framed frame");
            return;
        }
    }
    if (nodus_tcp_send(c, (const uint8_t *)pl[3], strlen(pl[3])) != 0) {
        FAIL("queue a payload");
        return;
    }
    for (int i = 0; i < 40; i++) poll_both();
    if (g_ngot != 0) { FAIL("a frame left before the handshake ended"); return; }
    if (!c->pending_buf || c->pending_len == 0) { FAIL("nothing queued"); return; }

    /* The key exchange's outcome on both ends. */
    uint8_t ss[32], nc[32], ns[32];
    nodus_random(ss, sizeof(ss));
    nodus_random(nc, sizeof(nc));
    nodus_random(ns, sizeof(ns));
    if (nodus_channel_crypto_init(&c->channel_crypto, ss, nc, ns,
                                  NODUS_CHANNEL_ROLE_INITIATOR) != 0 ||
        nodus_channel_crypto_init(&g_acc_conn->channel_crypto, ss, nc, ns,
                                  NODUS_CHANNEL_ROLE_RESPONDER) != 0) {
        FAIL("crypto init");
        return;
    }
    nodus_inter_dial_conn_open(c, true);
    if (c->pending_buf || c->pending_len != 0) {
        FAIL("the auth queue was not emptied");
        return;
    }
    for (int i = 0; i < 400 && g_ngot < 4; i++) poll_both();
    if (g_ngot != 4) {
        char m[96];
        snprintf(m, sizeof(m), "%d of 4 queued frames arrived", g_ngot);
        FAIL(m);
        return;
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(g_got[i], pl[i]) != 0) {
            FAIL("frames out of order or changed");
            return;
        }
    }
    if (g_acc_conn->decrypt_skip_count != 0 || g_acc.decrypt_fail_total != 0) {
        FAIL("a frame failed decryption (sent in plaintext?)");
        return;
    }
    PASS();
}

static void test_replay_acceptor(void) {
    TEST("accepted conn: auth-queued frames re-sent encrypted at key_init");
    g_acc_conn = NULL;
    /* A plain connect, not the pool: nodus_inter_pool_find would hand back
     * the first case's conn. */
    nodus_tcp_conn_t *d = nodus_tcp_connect(&g_dial, "127.0.0.1", g_acc.port);
    if (!d) { FAIL("dial"); return; }
    for (int i = 0; i < 400 && (!g_acc_conn || d->state != NODUS_CONN_CONNECTED); i++)
        poll_both();
    if (!g_acc_conn || d->state != NODUS_CONN_CONNECTED) { FAIL("connect"); return; }
    nodus_tcp_conn_t *a = g_acc_conn;
    /* Gated as core's on_inter_accept gates an accepted 4002 conn. */
    a->is_nodus = true;
    a->auth_required = true;
    if (a->auth_initiated_by_us || a->auth_state == NODUS_CONN_AUTH_OK) {
        FAIL("the accepted conn is not gated by auth");
        return;
    }

    /* Replies queued on the accepted conn before the key. */
    const char *pl[3] = { "r-one", "r-two", "r-three" };
    for (int i = 0; i < 3; i++) {
        if (nodus_tcp_send(a, (const uint8_t *)pl[i], strlen(pl[i])) != 0) {
            FAIL("queue a payload on the accepted conn");
            return;
        }
    }
    for (int i = 0; i < 40; i++) poll_both();
    if (g_dngot != 0) { FAIL("a frame left before the key was set"); return; }
    if (!a->pending_buf || a->pending_len == 0) { FAIL("nothing queued"); return; }

    /* key_init's outcome: accepted = RESPONDER, dialed = INITIATOR. */
    uint8_t ss[32], nc[32], ns[32];
    nodus_random(ss, sizeof(ss));
    nodus_random(nc, sizeof(nc));
    nodus_random(ns, sizeof(ns));
    if (nodus_channel_crypto_init(&d->channel_crypto, ss, nc, ns,
                                  NODUS_CHANNEL_ROLE_INITIATOR) != 0 ||
        nodus_channel_crypto_init(&a->channel_crypto, ss, nc, ns,
                                  NODUS_CHANNEL_ROLE_RESPONDER) != 0) {
        FAIL("crypto init");
        return;
    }
    nodus_inter_dial_conn_open(a, true);
    if (a->auth_state != NODUS_CONN_AUTH_OK) { FAIL("the gate was not opened"); return; }
    if (a->pending_buf || a->pending_len != 0) {
        FAIL("the auth queue was not emptied");
        return;
    }
    for (int i = 0; i < 400 && g_dngot < 3; i++) poll_both();
    if (g_dngot != 3) {
        char m[96];
        snprintf(m, sizeof(m), "%d of 3 queued frames arrived", g_dngot);
        FAIL(m);
        return;
    }
    for (int i = 0; i < 3; i++) {
        if (strcmp(g_dgot[i], pl[i]) != 0) {
            FAIL("frames out of order or changed");
            return;
        }
    }
    if (d->decrypt_skip_count != 0 || g_dial.decrypt_fail_total != 0) {
        FAIL("a frame failed decryption (sent in plaintext?)");
        return;
    }
    PASS();
}

int main(void) {
    printf("test_inter_pending_replay (split S5b F2, S5 acceptor)\n");
    if (nodus_tcp_init(&g_dial, -1) != 0 || nodus_tcp_init(&g_acc, -1) != 0) {
        printf("  setup FAILED\n");
        return 1;
    }
    g_dial.auth_required = true;
    g_acc.on_accept = acc_on_accept;
    g_acc.on_frame  = acc_on_frame;
    g_dial.on_frame = dial_on_frame;
    if (nodus_tcp_listen(&g_acc, "127.0.0.1", 0) != 0 || g_acc.port == 0) {
        printf("  listen FAILED\n");
        return 1;
    }

    test_replay();
    test_replay_acceptor();

    nodus_tcp_close(&g_dial);
    nodus_tcp_close(&g_acc);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
