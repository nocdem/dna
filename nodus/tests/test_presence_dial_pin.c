/**
 * Nodus — core's outbound 4002 dials pin the expected peer identity
 * (component split S5a, decision 2026-10-01-nodus-component-split item 30).
 *
 * Before S5a only the DHT host's inter_send (replication / republish /
 * hinted retry) recorded conn->expected_peer_id on a new dial; presence
 * p_sync and circuits dialed without it, and the dialer's auth_ok handler
 * refused every such connection ("INTER CRIT-1: no expected peer identity
 * … cannot pin, refusing" — live EU-1, 6 times in 6 hours). Now all three
 * go through nodus_server_inter_dial, and the routing snapshot carries the
 * node_id presence pins.
 *
 * Pins down (fixture level, one real loopback listener, no event loop
 * run, no clock in any assertion):
 *   1. nodus_presence_tick dials the routing snapshot's peer with that
 *      entry's node_id recorded as conn->expected_peer_id (set + equal).
 *   2. nodus_server_inter_dial: a new dial records the given identity; a
 *      second call for the same ip:port returns the SAME connection with
 *      its pin unchanged (an existing pool entry is never re-pinned); a
 *      dial with no identity (NULL) records none.
 *
 * Not covered here: the circuit dial (handle_t2_circ_open is static and
 * needs a client session + presence + cluster fixture); it calls the same
 * nodus_server_inter_dial with the ALIVE cluster member's node_id.
 *
 * RED on the tree before S5a: nodus_dht_peer_addr_t has no node_id and
 * nodus_server_inter_dial does not exist (compile error); with the old
 * presence code expected_peer_id_set stays false.
 *
 * Requires: default build; a loopback interface (127.0.0.1). Leaves
 * behind: nothing (sockets closed).
 */

#include "server/nodus_server.h"
#include "server/nodus_presence.h"
#include "server/nodus_dht_backend.h"
#include "transport/nodus_tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

/* ── A DHT backend that only answers the routing snapshot ──────────── */

typedef struct {
    nodus_dht_backend_t   base;
    nodus_dht_peer_addr_t peer;
    int                   calls;
} fake_dht_t;

static int fake_routing_snapshot(nodus_dht_backend_t *b,
                                 nodus_dht_peer_addr_t *out, int max) {
    fake_dht_t *f = (fake_dht_t *)b;
    f->calls++;
    if (max < 1) return 0;
    out[0] = f->peer;
    return 1;
}

static const nodus_dht_backend_ops_t fake_ops = {
    .routing_snapshot = fake_routing_snapshot,
};

/* The pool entry for ip:port (NULL when none). */
static nodus_tcp_conn_t *pool_find(nodus_tcp_t *tcp, const char *ip, uint16_t port) {
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->port == port && strcmp(c->ip, ip) == 0) return c;
    }
    return NULL;
}

static void test_presence_dial_pinned(void) {
    TEST("presence p_sync dial pins the snapshot's node_id");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    fake_dht_t fake;
    nodus_tcp_t lst;
    bool lst_up = false, inter_up = false;
    nodus_key_t client_fp;
    nodus_tcp_conn_t *c = NULL;
    memset(&fake, 0, sizeof(fake));
    memset(&client_fp, 0x5a, sizeof(client_fp));
    CHECK(srv, "alloc");

    CHECK(nodus_tcp_init(&lst, -1) == 0, "listener init");
    lst_up = true;
    CHECK(nodus_tcp_listen(&lst, "127.0.0.1", 0) == 0 && lst.port != 0, "listen");
    CHECK(nodus_tcp_init(&srv->inter_tcp, -1) == 0, "inter_tcp init");
    inter_up = true;

    fake.base.ops = &fake_ops;
    memset(&fake.peer.node_id, 0xC3, sizeof(fake.peer.node_id));
    snprintf(fake.peer.ip, sizeof(fake.peer.ip), "%s", "127.0.0.1");
    fake.peer.tcp_port = lst.port;
    srv->dht = &fake.base;

    nodus_presence_add_local(srv, &client_fp);   /* something to sync */
    nodus_presence_tick(srv);

    CHECK(fake.calls == 1, "routing snapshot not read");
    c = pool_find(&srv->inter_tcp, "127.0.0.1", lst.port);
    CHECK(c != NULL, "presence did not dial the routing peer");
    CHECK(c->is_nodus, "dialed conn not marked is_nodus");
    CHECK(c->expected_peer_id_set, "presence dial carries no expected peer identity");
    CHECK(nodus_key_cmp(&c->expected_peer_id, &fake.peer.node_id) == 0,
          "presence dial pinned another identity than the snapshot's node_id");
    PASS();
out:
    if (srv) {
        srv->dht = NULL;
        if (inter_up) nodus_tcp_close(&srv->inter_tcp);
    }
    if (lst_up) nodus_tcp_close(&lst);
    free(srv);
}

static void test_inter_dial_semantics(void) {
    TEST("inter_dial: new conn pinned, existing kept, NULL unpinned");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_t lst_a, lst_b;
    bool a_up = false, b_up = false, inter_up = false;
    nodus_key_t id1, id2;
    nodus_tcp_conn_t *c1 = NULL, *c2 = NULL, *c3 = NULL;
    memset(&id1, 0x11, sizeof(id1));
    memset(&id2, 0x22, sizeof(id2));
    CHECK(srv, "alloc");

    CHECK(nodus_tcp_init(&lst_a, -1) == 0, "listener a init");
    a_up = true;
    CHECK(nodus_tcp_listen(&lst_a, "127.0.0.1", 0) == 0, "listen a");
    CHECK(nodus_tcp_init(&lst_b, -1) == 0, "listener b init");
    b_up = true;
    CHECK(nodus_tcp_listen(&lst_b, "127.0.0.1", 0) == 0, "listen b");
    CHECK(nodus_tcp_init(&srv->inter_tcp, -1) == 0, "inter_tcp init");
    inter_up = true;

    c1 = nodus_server_inter_dial(srv, "127.0.0.1", lst_a.port, &id1);
    CHECK(c1 != NULL, "dial a");
    CHECK(c1->is_nodus && c1->auth_initiated_by_us, "dial a: not an outbound nodus conn");
    CHECK(c1->expected_peer_id_set &&
          nodus_key_cmp(&c1->expected_peer_id, &id1) == 0, "dial a: pin not recorded");

    c2 = nodus_server_inter_dial(srv, "127.0.0.1", lst_a.port, &id2);
    CHECK(c2 == c1, "second dial to the same address opened another conn");
    CHECK(nodus_key_cmp(&c1->expected_peer_id, &id1) == 0,
          "an existing conn was re-pinned");

    c3 = nodus_server_inter_dial(srv, "127.0.0.1", lst_b.port, NULL);
    CHECK(c3 != NULL && c3 != c1, "dial b");
    CHECK(!c3->expected_peer_id_set, "a dial without identity recorded one");
    PASS();
out:
    if (inter_up) nodus_tcp_close(&srv->inter_tcp);
    if (a_up) nodus_tcp_close(&lst_a);
    if (b_up) nodus_tcp_close(&lst_b);
    free(srv);
}

int main(void) {
    printf("=== Split S5a item 30: core's 4002 dials pin the peer identity ===\n");
    test_presence_dial_pinned();
    test_inter_dial_semantics();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
