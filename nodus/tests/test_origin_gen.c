/**
 * Nodus — DHT origins carry a session generation (component split item 29).
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md item 29
 * (approved 2026-10-02): a DHT reply sent LATER — here the batch forward's
 * result, nodus_dht_bf_send_result — goes only to the session that asked.
 * Before the fix the origin was a bare slot and the only check was "the
 * slot is open": a client accepted into the slot of one that went away got
 * the previous client's reply (nodus/BUGS.md "gecikmeli DHT cevabı yeniden
 * kullanılan oturum yuvasına gider").
 *
 * Pins down, in-process (no sockets, no store, no clock in any assertion):
 *   1. DHT guard alone (a capturing host): a recorded origin whose slot was
 *      closed and opened again with a new generation gets NO reply and the
 *      batch is freed; the same session still in its slot GETS the reply,
 *      addressed with its generation.
 *   2. Core guard alone (nodus_server_dht_host's send_to_origin): a frame
 *      for a live slot with another generation is NOT written to that
 *      slot's connection (-1); the matching generation is written. Client
 *      and 4002 sessions both.
 *   3. Both together (core's host under the in-process DHT): the reused
 *      slot's new connection receives nothing; its own deferred reply
 *      arrives, with its own txn id.
 *
 * Not covered here: the assignment of generations in core's accept /
 * connect callbacks (on_tcp_accept, on_inter_connect, on_inter_accept are
 * static transport callbacks a calloc'd server does not reach); cases 2
 * and 3 assign them the way those callbacks do.
 *
 * RED on the tree before item 29: nodus_dht_origin_t has no `gen`, and
 * case 1's reused-slot reply is delivered.
 */

#include "server/nodus_server.h"
#include "server/nodus_dht_backend.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

#define SLOT 5

static nodus_key_t g_key;

/* ── A host that records what the DHT sends ────────────────────────── */

typedef struct {
    int                calls;
    nodus_dht_origin_t last;
    uint8_t            frame[4096];
    size_t             len;
} capture_t;

static int capture_send(void *ctx, nodus_dht_origin_t origin,
                        const uint8_t *frame, size_t len) {
    capture_t *c = ctx;
    c->calls++;
    c->last = origin;
    c->len = len < sizeof(c->frame) ? len : sizeof(c->frame);
    memcpy(c->frame, frame, c->len);
    return 0;
}

static nodus_dht_origin_t client_origin(int slot, uint64_t gen) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, slot, gen };
    return o;
}

/* A single-GET batch whose forwards are all done: its result is
 * result_empty for `txn` (no candidate, no peer — single-node truth). */
static int batch_for(nodus_dht_t *dht, nodus_dht_origin_t origin, uint32_t txn,
                     dht_bf_batch_t **out) {
    dht_bf_batch_t *b = &dht->bf_state.batches[0];
    if (nodus_dht_bf_batch_setup(b, &g_key, 1) != 0) return -1;
    b->is_single_get = true;
    b->txn_id = txn;
    b->origin = origin;
    b->pending_forwards = 0;
    *out = b;
    return 0;
}

/* The txn id of the T2 payload `p` (`len` bytes), -1 when it does not
 * decode. */
static long payload_txn(const uint8_t *p, size_t len) {
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    if (nodus_t2_decode(p, len, &m) != 0) return -1;
    long txn = (long)m.txn_id;
    nodus_t2_msg_free(&m);
    return txn;
}

/* ── 1. the DHT's own guard ────────────────────────────────────────── */

static void test_dht_guard(void) {
    TEST("DHT: reused slot gets no deferred reply; same session does");
    capture_t cap;
    memset(&cap, 0, sizeof(cap));
    nodus_dht_host_t host;
    memset(&host, 0, sizeof(host));
    host.ctx = &cap;
    host.send_to_origin = capture_send;
    nodus_dht_backend_t *be = NULL;
    nodus_dht_t *dht = NULL;
    dht_bf_batch_t *b = NULL;
    CHECK(nodus_dht_backend_inproc_new(&host, &be) == 0, "backend");
    dht = nodus_dht_backend_inproc_state(be);

    /* Session A (gen 11) asks; it is gone and B (gen 12) holds the slot
     * when the result is ready. */
    be->ops->session_opened(be, client_origin(SLOT, 11));
    CHECK(batch_for(dht, client_origin(SLOT, 11), 101, &b) == 0, "batch A");
    be->ops->session_closed(be, client_origin(SLOT, 11));
    be->ops->session_opened(be, client_origin(SLOT, 12));
    CHECK(dht->sessions[SLOT].open && dht->sessions[SLOT].gen == 12, "B's shadow");
    nodus_dht_bf_send_result(dht, b);
    CHECK(cap.calls == 0, "A's deferred reply was sent into B's slot");
    CHECK(!b->active, "batch not freed after the dropped reply");

    /* B asks; B is still there: delivered, addressed with B's gen. */
    CHECK(batch_for(dht, client_origin(SLOT, 12), 202, &b) == 0, "batch B");
    nodus_dht_bf_send_result(dht, b);
    CHECK(cap.calls == 1, "B's own deferred reply was not sent");
    CHECK(cap.last.kind == NODUS_DHT_ORIGIN_CLIENT && cap.last.slot == SLOT &&
          cap.last.gen == 12, "reply not addressed to (CLIENT, slot, B's gen)");
    CHECK(payload_txn(cap.frame, cap.len) == 202, "reply is not B's txn");
    CHECK(!b->active, "batch not freed after the reply");

    /* The slot closed and not reopened: nothing (as before item 29). */
    CHECK(batch_for(dht, client_origin(SLOT, 12), 303, &b) == 0, "batch B2");
    be->ops->session_closed(be, client_origin(SLOT, 12));
    nodus_dht_bf_send_result(dht, b);
    CHECK(cap.calls == 1, "reply sent to a closed slot");
    PASS();
out:
    if (be) {
        be->ops->stop(be);                /* a batch a failed check left */
        be->ops->close(be);
    }
}

/* ── 2. core's guard ───────────────────────────────────────────────── */

static nodus_tcp_conn_t *conn_new(int slot) {
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = -1;
    c->slot = slot;
    c->state = NODUS_CONN_CONNECTED;   /* send writes into wbuf */
    snprintf(c->ip, sizeof(c->ip), "%s", "10.0.0.9");
    return c;
}

static void conn_free(nodus_tcp_conn_t *c) {
    if (!c) return;
    free(c->wbuf);
    free(c->rbuf);
    free(c->pending_buf);
    free(c);
}

static void test_core_guard(void) {
    TEST("core: send_to_origin writes only to the origin's generation");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_conn_t *cc = conn_new(SLOT);
    nodus_tcp_conn_t *ic = conn_new(SLOT);
    uint8_t payload[64];
    size_t plen = 0;
    nodus_dht_host_t host;
    nodus_dht_origin_t io = { NODUS_DHT_ORIGIN_INTER, SLOT, 8 };
    CHECK(srv && cc && ic, "alloc");
    CHECK(nodus_t2_error(7, NODUS_ERR_UNAVAILABLE, "x", payload, sizeof(payload),
                         &plen) == 0, "encode");
    nodus_server_dht_host(srv, &host);

    srv->sessions[SLOT].conn = cc;
    srv->sessions[SLOT].dht_gen = 8;
    srv->inter_sessions[SLOT].conn = ic;
    srv->inter_sessions[SLOT].dht_gen = 9;

    CHECK(host.send_to_origin(host.ctx, client_origin(SLOT, 7), payload, plen) == -1,
          "client: stale generation not refused");
    CHECK(cc->wlen == 0, "client: stale generation written to the connection");
    CHECK(host.send_to_origin(host.ctx, io, payload, plen) == -1,
          "inter: stale generation not refused");
    CHECK(ic->wlen == 0, "inter: stale generation written to the connection");

    /* The fixture connection has no socket (fd -1): the frame is appended to
     * wbuf, then the flush fails and nodus_tcp_send returns -1 (nodus_tcp.c
     * send_progress_locked, "write failed"). So the discriminator is the
     * buffer — written for the own generation, untouched for a stale one —
     * not the return code. */
    (void)host.send_to_origin(host.ctx, client_origin(SLOT, 8), payload, plen);
    CHECK(cc->wlen > 0, "client: own generation not written");
    io.gen = 9;
    (void)host.send_to_origin(host.ctx, io, payload, plen);
    CHECK(ic->wlen > 0, "inter: own generation not written");
    PASS();
out:
    conn_free(cc);
    conn_free(ic);
    free(srv);
}

/* ── 3. both, through core's host ──────────────────────────────────── */

/* What core does in on_tcp_accept / on_tcp_disconnect, for the slot. */
static void core_accept(nodus_server_t *srv, nodus_tcp_conn_t *conn) {
    nodus_session_t *s = &srv->sessions[conn->slot];
    memset(s, 0, sizeof(*s));
    s->conn = conn;
    s->dht_gen = ++srv->next_session_gen;
    srv->dht->ops->session_opened(srv->dht, client_origin(conn->slot, s->dht_gen));
}

static void core_disconnect(nodus_server_t *srv, nodus_tcp_conn_t *conn) {
    nodus_session_t *s = &srv->sessions[conn->slot];
    uint64_t gen = s->dht_gen;
    memset(s, 0, sizeof(*s));
    srv->dht->ops->session_closed(srv->dht, client_origin(conn->slot, gen));
}

static void test_end_to_end(void) {
    TEST("core + DHT: new client in a reused slot gets only its own reply");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_conn_t *a = conn_new(SLOT);
    nodus_tcp_conn_t *bc = conn_new(SLOT);
    nodus_dht_t *dht = NULL;
    dht_bf_batch_t *b = NULL;
    nodus_dht_host_t host;
    CHECK(srv && a && bc, "alloc");
    nodus_server_dht_host(srv, &host);
    CHECK(nodus_dht_backend_inproc_new(&host, &srv->dht) == 0, "backend");
    dht = nodus_dht_backend_inproc_state(srv->dht);

    core_accept(srv, a);
    CHECK(batch_for(dht, client_origin(SLOT, dht->sessions[SLOT].gen), 111, &b) == 0,
          "batch A");
    core_disconnect(srv, a);
    core_accept(srv, bc);
    CHECK(srv->sessions[SLOT].dht_gen == 2 && dht->sessions[SLOT].gen == 2,
          "B's generation");
    nodus_dht_bf_send_result(dht, b);
    CHECK(bc->wlen == 0, "A's deferred reply reached B's connection");
    CHECK(a->wlen == 0, "A's reply written after A left");

    CHECK(batch_for(dht, client_origin(SLOT, dht->sessions[SLOT].gen), 222, &b) == 0,
          "batch B");
    nodus_dht_bf_send_result(dht, b);
    CHECK(bc->wlen > NODUS_FRAME_HEADER_SIZE, "B's own reply did not arrive");
    {
        nodus_frame_t fr;
        CHECK(nodus_frame_decode(bc->wbuf, bc->wlen, &fr) > 0, "frame");
        CHECK(payload_txn(fr.payload, fr.payload_len) == 222, "B got another txn");
    }
    PASS();
out:
    if (srv && srv->dht) {
        srv->dht->ops->stop(srv->dht);    /* a batch a failed check left */
        srv->dht->ops->close(srv->dht);
    }
    conn_free(a);
    conn_free(bc);
    free(srv);
}

int main(void) {
    printf("=== Split item 29: DHT origins carry a session generation ===\n");
    memset(&g_key, 0xA5, sizeof(g_key));
    test_dht_guard();
    test_core_guard();
    test_end_to_end();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
