/* Suite selection flag: -DNODUS_TEST_INTER_CONFIG=1; ordinary target uses
 * the other branch. This only selects test fixtures, not protocol constants. */
#if defined(NODUS_TEST_INTER_CONFIG)
/* Build plan 4.3: nodus-core's actual entry point returns nonzero for
 * require_peer_auth=false, and its loader reads allow_duplicate_ip.
 * 4001 plan 4.5 / operator 2026-11-02 "ayar dosyasında kalsın.": the loader
 * reads client_session_depth / client_session_workers, leaves them 0 (the
 * code's defaults) when absent, and refuses a value that is not a positive
 * integer.
 * Flags: NODUS_TEST_INTER_CONFIG=1. Environment: none. Temporary config is unlinked. A mere
 * parse failure cannot pass: a valid positive config must load both flags.
 * Only the rejected entry-point invocation runs; no server is started. */
#define main nodus_core_entry
#include "nodus-core.c"
#undef main
#include <unistd.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
static void config_file(const char *path,bool auth) {
    FILE *f=fopen(path,"w"); CHECK(f);
    CHECK(fprintf(f,"{\"require_peer_auth\":%s,\"allow_duplicate_ip\":true,"
                    "\"storage_external\":true,\"witness_external\":true,"
                    "\"client_session_depth\":300,\"client_session_workers\":3}",
                    auth ? "true" : "false")>0);
    CHECK(fclose(f)==0);
}
static void raw_file(const char *path,const char *json) {
    FILE *f=fopen(path,"w"); CHECK(f); CHECK(fputs(json,f)>=0); CHECK(fclose(f)==0);
}
int main(void) {
    char path[]="/tmp/nodus_inter_config_XXXXXX";
    int fd=mkstemp(path); CHECK(fd>=0); close(fd);
    char *argv[]={"nodus-core","-c",path,NULL};
    config_file(path,true);
    nodus_server_config_t cfg={0};
    CHECK(nodus_node_config_load_storage(3,argv,"Nodus Core",&cfg)==-1);
    CHECK(cfg.require_peer_auth && cfg.p2p.allow_duplicate_ip);
    CHECK(cfg.client_session_depth==300 && cfg.client_session_workers==3);
    raw_file(path,"{\"storage_external\":true,\"witness_external\":true}");
    optind=1; memset(&cfg,0,sizeof(cfg));
    CHECK(nodus_node_config_load_storage(3,argv,"Nodus Core",&cfg)==-1);
    CHECK(cfg.client_session_depth==0 && cfg.client_session_workers==0);
    const char *bad[]={"{\"client_session_depth\":0}","{\"client_session_workers\":-1}",
                       "{\"client_session_depth\":\"256\"}","{\"client_session_workers\":2.5}"};
    for (size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        raw_file(path,bad[i]); optind=1;
        CHECK(nodus_node_config_load_storage(3,argv,"Nodus Core",&cfg)==1);
    }
    config_file(path,true);
    config_file(path,false);
    optind=1;
    CHECK(nodus_node_config_load_storage(3,argv,"Nodus Core",&cfg)==1);
    optind=1;
    CHECK(nodus_core_entry(3,argv)==1);
    CHECK(unlink(path)==0); return 0;
}
#else
/**
 * Nodus — core's outbound 4002 dials pin the expected peer identity
 * (component split S5a, decision 2026-10-01-nodus-component-split item 30),
 * and the S5a connection review's fixes to them (F2 pinned find-or-dial,
 * F5 presence dial backoff + per-tick cap).
 *
 * Before S5a only the DHT host's inter_send (replication / republish /
 * hinted retry) recorded conn->expected_peer_id on a new dial; presence
 * p_sync and circuits dialed without it, and the dialer's auth_ok handler
 * refused every such connection ("INTER CRIT-1: no expected peer identity
 * … cannot pin, refusing" — live EU-1, 6 times in 6 hours). Now all three
 * go through nodus_server_inter_dial, and the routing snapshot carries the
 * node_id presence pins.
 *
 * Pins down (fixture level, real loopback listeners, no event loop run, no
 * clock in any assertion — the backoff is driven through its pure
 * functions with literal timestamps, and the tick tests use entries whose
 * next_try is UINT64_MAX or no entry at all):
 *   1. nodus_presence_tick dials the routing snapshot's peer with that
 *      entry's node_id recorded as conn->expected_peer_id (set + equal).
 *   2. nodus_server_inter_dial (F2): a new dial records the given identity;
 *      a second pinned call with the SAME identity returns the same conn;
 *      a pinned call with ANOTHER identity does not reuse a conn pinned to
 *      the first — it dials a second conn to the same ip:port, pinned to
 *      its own identity, and the first conn's pin is unchanged; a pooled
 *      accepted (inbound) conn and a conn proven for another identity are
 *      never returned to a pinned call; a conn we dialed whose proven
 *      peer_id matches IS returned; a NULL-pin call keeps the old rule
 *      (the first pool entry for ip:port, no new dial).
 *   3. Dial backoff (F5), pure: delay 30/60/120/240/480/900/900 s; a
 *      recorded key is held back until exactly next_try; other node_id /
 *      port at the same ip are independent; clear forgets the key; a full
 *      table replaces the slot with the smallest next_try.
 *   4. Presence tick (F5): a key in backoff is not dialed while a key
 *      without an entry is; with DIAL_CAP + 3 unreachable-by-pool peers
 *      exactly DIAL_CAP conns are opened in one tick, each recorded once.
 *
 * Not covered here: the circuit dial (handle_t2_circ_open is static and
 * needs a client session + presence + cluster fixture); it calls the same
 * nodus_server_inter_dial with the ALIVE cluster member's node_id. The
 * "established conn clears the backoff" branch of the tick (it needs a
 * completed handshake); the pure clear is covered in 3.
 *
 * RED on the tree before the S5a review: nodus_server_inter_find and the
 * backoff functions do not exist (compile error); with the old find a
 * pinned call returned any conn at ip:port.
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

#define FAKE_MAX_PEERS (NODUS_PRESENCE_DIAL_CAP + 3)

typedef struct {
    nodus_dht_backend_t   base;
    nodus_dht_peer_addr_t peers[FAKE_MAX_PEERS];
    int                   n_peers;
    int                   calls;
} fake_dht_t;

static int fake_routing_snapshot(nodus_dht_backend_t *b,
                                 nodus_dht_peer_addr_t *out, int max) {
    fake_dht_t *f = (fake_dht_t *)b;
    f->calls++;
    int n = f->n_peers < max ? f->n_peers : max;
    for (int i = 0; i < n; i++) out[i] = f->peers[i];
    return n;
}

static const nodus_dht_backend_ops_t fake_ops = {
    .routing_snapshot = fake_routing_snapshot,
};

static void fake_peer(fake_dht_t *f, int i, uint8_t id_byte, uint16_t port) {
    memset(&f->peers[i].node_id, id_byte, sizeof(f->peers[i].node_id));
    snprintf(f->peers[i].ip, sizeof(f->peers[i].ip), "%s", "127.0.0.1");
    f->peers[i].tcp_port = port;
}

/* The first pool entry for ip:port (NULL when none). */
static nodus_tcp_conn_t *pool_find(nodus_tcp_t *tcp, const char *ip, uint16_t port) {
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->port == port && strcmp(c->ip, ip) == 0) return c;
    }
    return NULL;
}

/* How many pool entries for ip:port (port 0 = every entry). */
static int pool_count(nodus_tcp_t *tcp, const char *ip, uint16_t port) {
    int n = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (!c) continue;
        if (port == 0 || (c->port == port && strcmp(c->ip, ip) == 0)) n++;
    }
    return n;
}

/* These pool/backoff fixtures stop before a handshake; the separate
 * raw-machine dialer test asserts that this pin is checked at ENCAPS.
 * Flags/environment: none. Ephemeral listeners and identity released.
 * A missing session module must fail the positive dial assertions. */
static int fixture_transport(nodus_server_t *srv) {
    static const uint8_t chain[32]={0x42};
    if (!srv->identity.has_mlkem && nodus_identity_generate(&srv->identity)!=0) return -1;
    if (nodus_tcp_init(&srv->inter_tcp,-1)!=0) return -1;
    nodus_inter_session_config_t cfg={
        .identity=&srv->identity,.chain_id=chain,.inbound_depth=64,.outbound_depth=64
    };
    srv->inter_session=nodus_inter_session_new(&srv->inter_tcp,&cfg);
    return srv->inter_session ? 0 : -1;
}
static void fixture_close(nodus_server_t *srv) {
    nodus_tcp_close(&srv->inter_tcp);
    nodus_inter_session_free(srv->inter_session); srv->inter_session=NULL;
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
    CHECK(fixture_transport(srv) == 0, "inter_tcp init");
    inter_up = true;

    fake.base.ops = &fake_ops;
    fake_peer(&fake, 0, 0xC3, lst.port);
    fake.n_peers = 1;
    srv->dht = &fake.base;

    nodus_presence_add_local(srv, &client_fp);   /* something to sync */
    nodus_presence_tick(srv);

    CHECK(fake.calls == 1, "routing snapshot not read");
    c = pool_find(&srv->inter_tcp, "127.0.0.1", lst.port);
    CHECK(c != NULL, "presence did not dial the routing peer");
    CHECK(c->is_nodus, "dialed conn not marked is_nodus");
    CHECK(c->expected_peer_id_set, "presence dial carries no expected peer identity");
    CHECK(nodus_key_cmp(&c->expected_peer_id, &fake.peers[0].node_id) == 0,
          "presence dial pinned another identity than the snapshot's node_id");
    PASS();
out:
    if (srv) {
        srv->dht = NULL;
        if (inter_up) fixture_close(srv);
    }
    if (lst_up) nodus_tcp_close(&lst);
    if (srv) nodus_identity_clear(&srv->identity);
    free(srv);
}

static void test_inter_dial_semantics(void) {
    TEST("inter_dial: pinned reuse only for the same id; missing pin refused");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_t lst_a, lst_b;
    bool a_up = false, b_up = false, inter_up = false;
    nodus_key_t id1, id2, id3;
    nodus_tcp_conn_t *c1 = NULL, *c2 = NULL, *c3 = NULL, *r = NULL;
    memset(&id1, 0x11, sizeof(id1));
    memset(&id2, 0x22, sizeof(id2));
    memset(&id3, 0x33, sizeof(id3));
    CHECK(srv, "alloc");

    CHECK(nodus_tcp_init(&lst_a, -1) == 0, "listener a init");
    a_up = true;
    CHECK(nodus_tcp_listen(&lst_a, "127.0.0.1", 0) == 0, "listen a");
    CHECK(nodus_tcp_init(&lst_b, -1) == 0, "listener b init");
    b_up = true;
    CHECK(nodus_tcp_listen(&lst_b, "127.0.0.1", 0) == 0, "listen b");
    CHECK(fixture_transport(srv) == 0, "inter_tcp init");
    inter_up = true;

    /* A new pinned dial records its identity. */
    c1 = nodus_server_inter_dial(srv, "127.0.0.1", lst_a.port, &id1);
    CHECK(c1 != NULL, "dial a");
    CHECK(c1->is_nodus && c1->auth_initiated_by_us, "dial a: not an outbound nodus conn");
    CHECK(c1->expected_peer_id_set &&
          nodus_key_cmp(&c1->expected_peer_id, &id1) == 0, "dial a: pin not recorded");

    /* The same identity again: the same conn. */
    r = nodus_server_inter_dial(srv, "127.0.0.1", lst_a.port, &id1);
    CHECK(r == c1, "a pinned dial did not reuse the conn pinned to its identity");
    CHECK(pool_count(&srv->inter_tcp, "127.0.0.1", lst_a.port) == 1,
          "same-identity dial opened another conn");

    /* Another identity at the same ip:port: a second conn, pinned to it;
     * the first keeps its pin. */
    c2 = nodus_server_inter_dial(srv, "127.0.0.1", lst_a.port, &id2);
    CHECK(c2 != NULL && c2 != c1,
          "a conn pinned to another identity was reused");
    CHECK(c2->expected_peer_id_set &&
          nodus_key_cmp(&c2->expected_peer_id, &id2) == 0, "second conn not pinned to id2");
    CHECK(nodus_key_cmp(&c1->expected_peer_id, &id1) == 0, "an existing conn was re-pinned");
    CHECK(pool_count(&srv->inter_tcp, "127.0.0.1", lst_a.port) == 2,
          "expected two conns to the same ip:port");
    CHECK(nodus_server_inter_find(srv, "127.0.0.1", lst_a.port, &id1) == c1 &&
          nodus_server_inter_find(srv, "127.0.0.1", lst_a.port, &id2) == c2,
          "find does not tell the two pinned conns apart");

    /* A missing pin is refused before connecting or writing. */
    CHECK(nodus_server_inter_dial(srv,"127.0.0.1",lst_b.port,NULL)==NULL,
          "a missing-pin dial was allowed");
    c3=nodus_server_inter_dial(srv,"127.0.0.1",lst_b.port,&id3);
    CHECK(c3!=NULL,"dial b pinned");
    c3->expected_peer_id_set=false; /* lookup-only fixture */
    /* An unpinned conn is not returned to a pinned call. */
    CHECK(nodus_server_inter_find(srv, "127.0.0.1", lst_b.port, &id3) == NULL,
          "an unpinned conn was returned to a pinned find");

    /* A conn we dialed whose PROVEN identity matches (no expected pin) is
     * reused. */
    c3->peer_id = id3;
    c3->peer_id_set = true;
    r = nodus_server_inter_dial(srv, "127.0.0.1", lst_b.port, &id3);
    CHECK(r == c3, "a conn proven for the identity was not reused");

    /* Proven for another identity: not returned. */
    CHECK(nodus_server_inter_find(srv, "127.0.0.1", lst_b.port, &id1) == NULL,
          "a conn proven for another identity was returned");

    /* The same conn as an ACCEPTED one (the peer called us): never returned
     * to a pinned call, even with the matching identity. */
    c3->auth_initiated_by_us = false;
    CHECK(nodus_server_inter_find(srv, "127.0.0.1", lst_b.port, &id3) == NULL,
          "an inbound conn was returned to a pinned find");
    r = nodus_server_inter_dial(srv, "127.0.0.1", lst_b.port, &id3);
    CHECK(r != NULL && r != c3, "a pinned dial reused an inbound conn");
    CHECK(r->auth_initiated_by_us && r->expected_peer_id_set &&
          nodus_key_cmp(&r->expected_peer_id, &id3) == 0, "fresh conn not pinned to id3");
    CHECK(pool_count(&srv->inter_tcp, "127.0.0.1", lst_b.port) == 2,
          "expected the inbound conn and a fresh dial at b");

    CHECK(nodus_server_inter_dial(srv,"127.0.0.1",lst_b.port,NULL)==NULL,
          "a missing pin reused an existing connection");
    PASS();
out:
    if (inter_up) fixture_close(srv);
    if (a_up) nodus_tcp_close(&lst_a);
    if (b_up) nodus_tcp_close(&lst_b);
    if (srv) nodus_identity_clear(&srv->identity);
    free(srv);
}

/* ── F5: the backoff, pure ────────────────────────────────────────── */

static void test_backoff_pure(void) {
    TEST("backoff: delays, hold until next_try, clear, eviction");
    nodus_presence_backoff_table_t *t = calloc(1, sizeof(*t));
    nodus_key_t a, b;
    memset(&a, 0xA1, sizeof(a));
    memset(&b, 0xB2, sizeof(b));
    CHECK(t, "alloc");

    CHECK(nodus_presence_backoff_delay(0) == 0, "delay(0)");
    CHECK(nodus_presence_backoff_delay(1) == 30, "delay(1)");
    CHECK(nodus_presence_backoff_delay(2) == 60, "delay(2)");
    CHECK(nodus_presence_backoff_delay(3) == 120, "delay(3)");
    CHECK(nodus_presence_backoff_delay(4) == 240, "delay(4)");
    CHECK(nodus_presence_backoff_delay(5) == 480, "delay(5)");
    CHECK(nodus_presence_backoff_delay(6) == 900, "delay(6) not capped at 900");
    CHECK(nodus_presence_backoff_delay(7) == 900, "delay(7)");
    CHECK(nodus_presence_backoff_delay(UINT32_MAX) == 900, "delay(max)");

    CHECK(nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1000),
          "an unknown key is held back");
    nodus_presence_backoff_record(t, "10.0.0.1", 4002, &a, 1000);
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1029),
          "recorded key allowed before next_try");
    CHECK(nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1030),
          "recorded key held back at next_try");
    /* Independent keys: another node_id, another port, another ip. */
    CHECK(nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &b, 1001),
          "another node_id at the same address is held back");
    CHECK(nodus_presence_backoff_allows(t, "10.0.0.1", 4003, &a, 1001),
          "another port is held back");
    CHECK(nodus_presence_backoff_allows(t, "10.0.0.2", 4002, &a, 1001),
          "another ip is held back");

    /* Consecutive dials escalate. */
    nodus_presence_backoff_record(t, "10.0.0.1", 4002, &a, 1030);
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1089) &&
          nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1090),
          "second dial not held 60 s");
    nodus_presence_backoff_record(t, "10.0.0.1", 4002, &a, 1090);
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1209) &&
          nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1210),
          "third dial not held 120 s");

    /* Clear forgets it: the next record starts over at 30 s. */
    nodus_presence_backoff_clear(t, "10.0.0.1", 4002, &a);
    CHECK(nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 1210),
          "cleared key still held back");
    nodus_presence_backoff_record(t, "10.0.0.1", 4002, &a, 2000);
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 2029) &&
          nodus_presence_backoff_allows(t, "10.0.0.1", 4002, &a, 2030),
          "after clear the delay did not restart at 30 s");

    /* Full table: the slot with the smallest next_try is replaced. Fill
     * every slot with distinct ports; the key recorded at the smallest time
     * (port 7, now 10) is the one evicted. */
    memset(t, 0, sizeof(*t));
    for (int i = 0; i < NODUS_PRESENCE_BACKOFF_SLOTS; i++)
        nodus_presence_backoff_record(t, "10.0.0.9", (uint16_t)(1000 + i), &a,
                                      i == 7 ? 10 : 5000);
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.9", 1007, &a, 39),
          "port 1007 not recorded");
    nodus_presence_backoff_record(t, "10.0.0.9", 9999, &b, 6000);
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.9", 9999, &b, 6029),
          "the new key was not recorded in a full table");
    CHECK(nodus_presence_backoff_allows(t, "10.0.0.9", 1007, &a, 39),
          "the smallest-next_try entry was not the one evicted");
    CHECK(!nodus_presence_backoff_allows(t, "10.0.0.9", 1000, &a, 5029) &&
          !nodus_presence_backoff_allows(t, "10.0.0.9", 1008, &a, 5029),
          "another entry was evicted");
    PASS();
out:
    free(t);
}

/* ── F5: the tick honours the backoff and the per-tick cap ────────── */

static void test_tick_backoff_and_cap(void) {
    TEST("presence tick: backoff holds a dial; cap per tick");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    nodus_tcp_t *lst = calloc(FAKE_MAX_PEERS, sizeof(*lst));
    bool lst_up[FAKE_MAX_PEERS];
    bool inter_up = false;
    fake_dht_t fake;
    nodus_key_t client_fp;
    memset(lst_up, 0, sizeof(lst_up));
    memset(&fake, 0, sizeof(fake));
    memset(&client_fp, 0x5a, sizeof(client_fp));
    CHECK(srv && lst, "alloc");

    for (int i = 0; i < FAKE_MAX_PEERS; i++) {
        CHECK(nodus_tcp_init(&lst[i], -1) == 0, "listener init");
        lst_up[i] = true;
        CHECK(nodus_tcp_listen(&lst[i], "127.0.0.1", 0) == 0 && lst[i].port != 0,
              "listen");
    }
    CHECK(fixture_transport(srv) == 0, "inter_tcp init");
    inter_up = true;
    fake.base.ops = &fake_ops;
    srv->dht = &fake.base;
    nodus_presence_add_local(srv, &client_fp);   /* something to sync */

    /* 1. Two peers; peer 0's key is in backoff (next_try = never), peer 1
     *    has no entry: only peer 1 is dialed. */
    fake_peer(&fake, 0, 0x40, lst[0].port);
    fake_peer(&fake, 1, 0x41, lst[1].port);
    fake.n_peers = 2;
    {
        nodus_presence_backoff_table_t *bt = &srv->presence.dial_backoff;
        nodus_presence_backoff_record(bt, "127.0.0.1", lst[0].port,
                                      &fake.peers[0].node_id, 0);
        for (int s = 0; s < NODUS_PRESENCE_BACKOFF_SLOTS; s++)
            if (bt->slots[s].used) bt->slots[s].next_try = UINT64_MAX;
    }
    nodus_presence_tick(srv);
    CHECK(fake.calls == 1, "routing snapshot not read");
    CHECK(pool_count(&srv->inter_tcp, "127.0.0.1", lst[0].port) == 0,
          "a key in backoff was dialed");
    CHECK(pool_count(&srv->inter_tcp, "127.0.0.1", lst[1].port) == 1,
          "a key without backoff was not dialed");
    CHECK(!nodus_presence_backoff_allows(&srv->presence.dial_backoff, "127.0.0.1",
                                         lst[1].port, &fake.peers[1].node_id, 0),
          "the fresh dial was not recorded in the backoff table");

    /* 2. DIAL_CAP + 3 peers, none pooled (new identities): one tick opens
     *    exactly DIAL_CAP conns. */
    fixture_close(srv);
    inter_up = false;
    memset(&srv->presence.dial_backoff, 0, sizeof(srv->presence.dial_backoff));
    CHECK(fixture_transport(srv) == 0, "inter_tcp re-init");
    inter_up = true;
    for (int i = 0; i < FAKE_MAX_PEERS; i++)
        fake_peer(&fake, i, (uint8_t)(0x80 + i), lst[i].port);
    fake.n_peers = FAKE_MAX_PEERS;
    srv->presence.last_sync = 0;                 /* the next tick syncs */
    nodus_presence_tick(srv);
    CHECK(fake.calls == 2, "second tick did not sync");
    CHECK(pool_count(&srv->inter_tcp, NULL, 0) == NODUS_PRESENCE_DIAL_CAP,
          "a tick did not open exactly DIAL_CAP conns");
    {
        int recorded = 0;
        for (int s = 0; s < NODUS_PRESENCE_BACKOFF_SLOTS; s++)
            if (srv->presence.dial_backoff.slots[s].used) {
                recorded++;
                CHECK(srv->presence.dial_backoff.slots[s].fail_count == 1,
                      "a dial recorded more than once");
            }
        CHECK(recorded == NODUS_PRESENCE_DIAL_CAP,
              "capped peers were recorded, or dials were not");
    }
    PASS();
out:
    if (srv) {
        srv->dht = NULL;
        if (inter_up) fixture_close(srv);
    }
    if (lst)
        for (int i = 0; i < FAKE_MAX_PEERS; i++)
            if (lst_up[i]) nodus_tcp_close(&lst[i]);
    free(lst);
    if (srv) nodus_identity_clear(&srv->identity);
    free(srv);
}

/* The same raw-machine fixture also checks the point where the recorded
 * presence pin is enforced: no ENCAPS or SIGN job on a mismatching key. */
#undef CHECK
#define main inter_session_fixture_all_cases
#include "test_inter_session.c"
#undef main
int main(void) {
    printf("=== Split S5a item 30 + review: core's 4002 dials pin the peer identity ===\n");
    (void)inter_session_fixture_all_cases;
    CHECK(nodus_identity_generate(&ids[0])==0 && nodus_identity_generate(&ids[1])==0);
    wire_and_pin(true);
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]);
    test_presence_dial_pinned();
    test_inter_dial_semantics();
    test_backoff_pure();
    test_tick_backoff_and_cap();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
#endif
