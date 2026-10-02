/**
 * Nodus — a deferred DHT reply never reaches a later occupant of the
 * client session slot it was recorded for.
 *
 * A client's get / get_all / get_batch that is forwarded (batch forward,
 * iterative lookup) is answered LATER, to the session slot recorded with
 * the request. The transport hands a freed slot to the next accepted
 * client (lowest free slot), so before this fix a client B accepted into
 * client A's old slot received A's reply: A's txn id and the rows of the
 * key A read. Every accept now gives the session a fresh generation
 * (nodus_session_t.gen from srv->next_session_gen); a deferred reply
 * records (slot, gen) and is sent only while both still match.
 *
 * In-process: a calloc'd server; client conns with fd -1 in state
 * CONNECTED, so nodus_tcp_send appends the frame to conn->wbuf (the
 * test_bf_forward_frames.c fixture) — what a client would receive is
 * read from wbuf, no sockets, no clock.
 *
 * Pins down:
 *   1. Accept assigns each occupant a distinct non-zero gen; disconnect
 *      leaves the slot free (conn NULL, gen 0).
 *   2. nodus_server_session_if_same: the occupant only for an in-range
 *      slot with a conn and the recorded gen; NULL otherwise.
 *   3. A batch reply recorded for (slot, gen) IS sent while that session
 *      is still the occupant (frame with the request's txn id in its wbuf).
 *   4. A batch reply recorded for (slot, gen) is NOT sent after the
 *      client disconnected and another client was accepted into the same
 *      slot — nothing in the new client's wbuf — and the batch is
 *      released all the same.
 *
 * RED on the tree before the fix: bf_send_result checked only
 * `sess->conn`, so step 4 wrote A's reply into B's wbuf.
 */

#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
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

/* A client conn that never touches a socket: nodus_tcp_send buffers the
 * frame in wbuf. */
static nodus_tcp_conn_t *client_conn(int slot, const char *ip) {
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = -1;
    c->slot = slot;
    c->state = NODUS_CONN_CONNECTED;
    snprintf(c->ip, sizeof(c->ip), "%s", ip);
    return c;
}

static void conn_free(nodus_tcp_conn_t *c) {
    if (!c) return;
    free(c->wbuf);
    free(c->rbuf);
    free(c);
}

/* A one-key single GET batch, deferred for (slot, gen). */
static int batch_for(dht_bf_batch_t *b, int slot, uint64_t gen, uint32_t txn) {
    nodus_key_t key;
    memset(&key, 0x4b, sizeof(key));
    if (nodus_server_bf_batch_setup(b, &key, 1) != 0) return -1;
    b->is_single_get = true;
    b->txn_id = txn;
    b->session_slot = slot;
    b->session_gen = gen;
    b->sets[0].peers = 1;
    return 0;
}

static void test_accept_assigns_gen(void) {
    TEST("accept: distinct non-zero gen per occupant; disconnect frees");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_conn_t *a = client_conn(0, "10.0.0.1");
    nodus_tcp_conn_t *b = client_conn(0, "10.0.0.2");
    nodus_tcp_conn_t *c = client_conn(1, "10.0.0.3");
    CHECK(srv && a && b && c, "alloc");

    nodus_server_client_accepted(srv, a);
    uint64_t ga = srv->sessions[0].gen;
    CHECK(srv->sessions[0].conn == a && ga != 0, "A bound with a gen");
    nodus_server_client_accepted(srv, c);
    uint64_t gc = srv->sessions[1].gen;
    CHECK(gc != 0 && gc != ga, "another slot: another gen");

    nodus_server_client_disconnected(srv, a);
    CHECK(srv->sessions[0].conn == NULL && srv->sessions[0].gen == 0,
          "disconnect: slot free, gen 0");
    nodus_server_client_accepted(srv, b);
    uint64_t gb = srv->sessions[0].gen;
    CHECK(srv->sessions[0].conn == b, "B reuses A's slot");
    CHECK(gb != 0 && gb != ga && gb != gc, "B's gen differs from every earlier one");
    PASS();
out:
    conn_free(a); conn_free(b); conn_free(c);
    free(srv);
}

static void test_session_if_same(void) {
    TEST("session_if_same: only the recorded occupant");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_conn_t *a = client_conn(0, "10.0.0.1");
    nodus_tcp_conn_t *b = client_conn(0, "10.0.0.2");
    CHECK(srv && a && b, "alloc");

    nodus_server_client_accepted(srv, a);
    uint64_t ga = srv->sessions[0].gen;
    CHECK(nodus_server_session_if_same(srv, 0, ga) == &srv->sessions[0],
          "same occupant found");
    CHECK(nodus_server_session_if_same(srv, 0, ga + 1) == NULL, "other gen: NULL");
    CHECK(nodus_server_session_if_same(srv, -1, ga) == NULL, "slot -1: NULL");
    CHECK(nodus_server_session_if_same(srv, NODUS_MAX_SESSIONS, ga) == NULL,
          "slot past the table: NULL");
    CHECK(nodus_server_session_if_same(srv, 1, 0) == NULL, "free slot: NULL");

    nodus_server_client_disconnected(srv, a);
    CHECK(nodus_server_session_if_same(srv, 0, ga) == NULL, "disconnected: NULL");
    nodus_server_client_accepted(srv, b);
    CHECK(nodus_server_session_if_same(srv, 0, ga) == NULL,
          "reused slot, old gen: NULL");
    CHECK(nodus_server_session_if_same(srv, 0, srv->sessions[0].gen) ==
          &srv->sessions[0], "reused slot, new gen: the new occupant");
    PASS();
out:
    conn_free(a); conn_free(b);
    free(srv);
}

static void test_reply_to_same_session(void) {
    TEST("deferred reply: sent while the same session holds the slot");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    dht_bf_batch_t *bt = calloc(1, sizeof(*bt));
    nodus_tcp_conn_t *a = client_conn(0, "10.0.0.1");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    CHECK(srv && bt && a, "alloc");

    nodus_server_client_accepted(srv, a);
    CHECK(batch_for(bt, 0, srv->sessions[0].gen, 41) == 0, "batch setup");
    nodus_server_bf_send_result(srv, bt);
    CHECK(!bt->active, "batch released");
    CHECK(a->wlen > NODUS_FRAME_HEADER_SIZE, "A received its reply");
    nodus_frame_t fr;
    CHECK(nodus_frame_decode(a->wbuf, a->wlen, &fr) > 0, "one whole frame");
    CHECK(nodus_t2_decode(fr.payload, fr.payload_len, &m) == 0, "T2 decode");
    CHECK(m.txn_id == 41, "the reply carries A's txn id");
    PASS();
out:
    nodus_t2_msg_free(&m);
    conn_free(a);
    free(bt);
    free(srv);
}

static void test_no_reply_to_reused_slot(void) {
    TEST("deferred reply: dropped once the slot holds another client");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    dht_bf_batch_t *bt = calloc(1, sizeof(*bt));
    nodus_tcp_conn_t *a = client_conn(0, "10.0.0.1");
    nodus_tcp_conn_t *b = client_conn(0, "10.0.0.2");
    CHECK(srv && bt && a && b, "alloc");

    nodus_server_client_accepted(srv, a);
    CHECK(batch_for(bt, 0, srv->sessions[0].gen, 42) == 0, "batch setup");
    nodus_server_client_disconnected(srv, a);
    nodus_server_client_accepted(srv, b);
    CHECK(srv->sessions[0].conn == b, "B holds A's old slot");

    nodus_server_bf_send_result(srv, bt);
    CHECK(!bt->active, "batch released");
    CHECK(b->wlen == 0, "B received nothing of A's reply");
    CHECK(a->wlen == 0, "nothing written to A's gone conn");
    PASS();
out:
    conn_free(a); conn_free(b);
    free(bt);
    free(srv);
}

int main(void) {
    printf("test_session_gen\n");
    test_accept_assigns_gen();
    test_session_if_same();
    test_reply_to_same_session();
    test_no_reply_to_reused_slot();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
