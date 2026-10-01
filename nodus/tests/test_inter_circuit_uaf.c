/**
 * Nodus — DHT Package A F1 / F1b: inter-circuits never outlive the 4002
 * link they ride on, and a ri_* frame only touches circuits of its own link.
 *
 * In-process: a calloc'd server, fake (never-connected) tcp conns used only
 * as pointer identities, client sessions WITHOUT a conn (so no notify is
 * sent anywhere). Driven through nodus_server_inter_conn_closed,
 * nodus_server_inter_sweep_orphans and nodus_server_dispatch_inter_frame
 * (nodus_server.h internal section).
 *
 * Pins down:
 *   1. F1: closing a 4002 conn frees every inter-circuit whose peer_conn is
 *      that conn AND the client circuit linked to it (no c->inter left
 *      pointing at a slot the next circuit reuses); circuits on another
 *      conn are untouched.
 *   2. F1: the orphan sweep (pending_open older than the limit) also
 *      unlinks the client circuit.
 *   3. F1b: ri_close arriving on a DIFFERENT 4002 conn than the circuit's
 *      is ignored; on the circuit's own conn it closes it.
 *   4. F1 through the transport's on_disconnect body
 *      (nodus_server_inter_disconnected), not only the helper.
 *   5. Rev 2 item 8: with two client circuits sharing a cid, releasing the
 *      inter-circuit frees the circuit LINKED to it (pointer identity) and
 *      leaves the other — by cid it freed the wrong one and left a stale
 *      c->inter. (The circ_open bump policy that keeps cids unique runs in
 *      the client-port handler, which has no in-process entry point.)
 *
 * RED on the tree before Package A: on_inter_disconnect never walked
 * inter_circuits, the sweep freed only the global entry, and the ri_*
 * handlers looked the circuit up by cid alone.
 */

#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static nodus_tcp_conn_t conn_a, conn_b;

static nodus_server_t *new_server(void) {
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    nodus_inter_circuit_table_init(&srv->inter_circuits);
    for (int i = 0; i < 4; i++) {
        nodus_circuit_table_init(&srv->sessions[i].circuits);
        srv->sessions[i].conn = NULL;   /* no client socket: notifies are skipped */
    }
    return srv;
}

static void fake_conn(nodus_tcp_conn_t *c, const char *ip) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->slot = -1;
    snprintf(c->ip, sizeof(c->ip), "%s", ip);
    c->port = 4002;
}

/* Link a client circuit on session s to a new inter entry over conn. */
static nodus_inter_circuit_t *link_circuit(nodus_server_t *srv, int s,
                                           nodus_tcp_conn_t *conn,
                                           nodus_circuit_t **c_out) {
    nodus_session_t *sess = &srv->sessions[s];
    nodus_circuit_t *c = nodus_circuit_alloc(&sess->circuits);
    nodus_inter_circuit_t *ic = nodus_inter_circuit_alloc(&srv->inter_circuits);
    if (!c || !ic) return NULL;
    ic->peer_conn = conn;
    ic->peer_cid = 900 + (uint64_t)s;
    ic->local_sess = (struct nodus_session *)sess;
    ic->local_cid = c->local_cid;
    ic->is_originator = false;
    c->is_local_bridge = false;
    c->inter = ic;
    *c_out = c;
    return ic;
}

static bool session_points_at(nodus_server_t *srv, int s, const nodus_inter_circuit_t *ic) {
    nodus_session_t *sess = &srv->sessions[s];
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++)
        if (sess->circuits.entries[i].in_use && sess->circuits.entries[i].inter == ic)
            return true;
    return false;
}

static void test_disconnect_closes_circuits(void) {
    TEST("F1: 4002 disconnect frees inter + client circuit");
    nodus_server_t *srv = new_server();
    nodus_circuit_t *c0 = NULL, *c1 = NULL;
    CHECK(srv, "alloc");
    nodus_inter_circuit_t *ic0 = link_circuit(srv, 0, &conn_a, &c0);
    nodus_inter_circuit_t *ic1 = link_circuit(srv, 1, &conn_b, &c1);
    CHECK(ic0 && ic1, "setup");
    uint64_t cid0 = ic0->our_cid, local0 = c0->local_cid;

    nodus_server_inter_conn_closed(srv, &conn_a);

    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid0) == NULL,
          "inter entry on the closed conn survived");
    CHECK(nodus_circuit_lookup(&srv->sessions[0].circuits, local0) == NULL,
          "client circuit on the closed conn survived");
    CHECK(ic1->in_use && ic1->peer_conn == &conn_b && c1->in_use && c1->inter == ic1,
          "circuit on the other conn was touched");

    /* The freed slot is reused: no client circuit may point at it. */
    nodus_inter_circuit_t *reused = nodus_inter_circuit_alloc(&srv->inter_circuits);
    CHECK(reused, "realloc");
    CHECK(!session_points_at(srv, 0, reused), "stale c->inter points at a reused slot");
    PASS();
out:
    free(srv);
}

static void test_orphan_sweep_unlinks(void) {
    TEST("F1: orphan sweep unlinks the client circuit");
    nodus_server_t *srv = new_server();
    nodus_circuit_t *c0 = NULL, *c1 = NULL;
    CHECK(srv, "alloc");
    nodus_inter_circuit_t *stuck = link_circuit(srv, 0, &conn_a, &c0);
    nodus_inter_circuit_t *live = link_circuit(srv, 1, &conn_a, &c1);
    CHECK(stuck && live, "setup");
    stuck->is_originator = true;
    stuck->pending_open = true;
    stuck->created_at_ms = 1000;
    live->created_at_ms = 1000;           /* not pending: never swept */
    uint64_t local0 = c0->local_cid;

    int freed = nodus_server_inter_sweep_orphans(srv, 1000 + 20000, 10000);
    CHECK(freed == 1, "freed count");
    CHECK(nodus_circuit_lookup(&srv->sessions[0].circuits, local0) == NULL,
          "client circuit of a swept orphan survived");
    CHECK(live->in_use && c1->in_use && c1->inter == live, "open circuit swept");
    PASS();
out:
    free(srv);
}

static void test_ri_close_wrong_conn_ignored(void) {
    TEST("F1b: ri_close on a different 4002 conn is ignored");
    nodus_server_t *srv = new_server();
    nodus_circuit_t *c0 = NULL;
    nodus_inter_session_t sess_a, sess_b;
    uint8_t buf[256];
    size_t len = 0;
    CHECK(srv, "alloc");
    srv->config.require_peer_auth = true;
    srv->identity.has_kyber = false;      /* F3 gate off: this test is about F1b */
    nodus_inter_circuit_t *ic = link_circuit(srv, 0, &conn_a, &c0);
    CHECK(ic, "setup");
    uint64_t cid = ic->our_cid;

    memset(&sess_a, 0, sizeof(sess_a));
    memset(&sess_b, 0, sizeof(sess_b));
    sess_a.conn = &conn_a; sess_a.authenticated = true;
    sess_b.conn = &conn_b; sess_b.authenticated = true;

    CHECK(nodus_t2_ri_close(0, cid, buf, sizeof(buf), &len) == 0, "encode");
    nodus_server_dispatch_inter_frame(srv, &sess_b, buf, len);
    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid) != NULL,
          "foreign link closed the circuit");
    CHECK(c0->in_use && c0->inter == ic, "client circuit touched");

    nodus_server_dispatch_inter_frame(srv, &sess_a, buf, len);
    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid) == NULL,
          "own link could not close the circuit");
    PASS();
out:
    free(srv);
}

static void test_disconnect_callback_path(void) {
    TEST("F1: the 4002 on_disconnect body releases the circuits");
    nodus_server_t *srv = new_server();
    nodus_circuit_t *c0 = NULL;
    CHECK(srv, "alloc");
    nodus_inter_circuit_t *ic = link_circuit(srv, 0, &conn_a, &c0);
    CHECK(ic, "setup");
    uint64_t cid = ic->our_cid, local0 = c0->local_cid;

    /* what the inter transport's on_disconnect callback runs */
    nodus_server_inter_disconnected(srv, &conn_a);

    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid) == NULL,
          "inter entry survived the disconnect callback");
    CHECK(nodus_circuit_lookup(&srv->sessions[0].circuits, local0) == NULL,
          "client circuit survived the disconnect callback");
    PASS();
out:
    free(srv);
}

static void test_duplicate_cid_pointer_identity(void) {
    TEST("item 8: duplicate cid — release frees the linked circuit only");
    nodus_server_t *srv = new_server();
    nodus_circuit_t *decoy = NULL, *linked = NULL;
    nodus_inter_session_t sess_a;
    uint8_t buf[256];
    size_t len = 0;
    CHECK(srv, "alloc");
    srv->config.require_peer_auth = true;
    srv->identity.has_kyber = false;      /* F3 gate off */
    nodus_session_t *s0 = &srv->sessions[0];

    /* entry 0: an unrelated circuit (a client-chosen cid); entry 1: the
     * inter-linked one carrying the SAME cid (a client cid that collided
     * with a generated one before the rev 2 bump policy). */
    decoy = nodus_circuit_alloc(&s0->circuits);
    CHECK(decoy, "decoy");
    nodus_inter_circuit_t *ic = link_circuit(srv, 0, &conn_a, &linked);
    CHECK(ic && linked && linked != decoy, "linked");
    linked->local_cid = decoy->local_cid;
    ic->local_cid = decoy->local_cid;
    uint64_t cid = ic->our_cid;

    memset(&sess_a, 0, sizeof(sess_a));
    sess_a.conn = &conn_a;
    sess_a.authenticated = true;
    CHECK(nodus_t2_ri_close(0, cid, buf, sizeof(buf), &len) == 0, "encode");
    nodus_server_dispatch_inter_frame(srv, &sess_a, buf, len);

    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid) == NULL, "inter entry");
    CHECK(decoy->in_use, "the unrelated circuit with the same cid was freed");
    CHECK(!linked->in_use, "the linked circuit survived (stale c->inter)");
    CHECK(s0->circuits.count == 1, "table count");
    PASS();
out:
    free(srv);
}

int main(void) {
    printf("=== DHT Package A F1/F1b: inter-circuit lifetime ===\n");
    fake_conn(&conn_a, "10.0.0.1");
    fake_conn(&conn_b, "10.0.0.2");
    test_disconnect_closes_circuits();
    test_orphan_sweep_unlinks();
    test_ri_close_wrong_conn_ignored();
    test_disconnect_callback_path();
    test_duplicate_cid_pointer_identity();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
