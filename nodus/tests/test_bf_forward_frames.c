/**
 * Nodus — DHT Package A rev 2 item 17: the forwarded-read path driven with
 * CRAFTED 4002 reply frames, asserting the frame its client gets.
 *
 * In-process: a batch slot set up with nodus_dht_bf_batch_setup, one
 * fake forward (dht_bf_conn_t, no socket) per answering peer, reply frames
 * built with nodus_t2_result_get_batch_ex and fed to
 * nodus_dht_bf_absorb_reply (exactly what bf_handle_event feeds after
 * decryption), the client frame produced by nodus_dht_bf_encode_result
 * (exactly what bf_send_result sends) and decoded with nodus_t2_decode.
 * The responder side runs through nodus_server_dispatch_inter_frame on a
 * calloc'd server with the in-process DHT attached (split S4) and a real
 * (fixture) store, the 4002 session in slot 0; its reply is read back from
 * the fake conn's write buffer (fd -1: the bytes stay in wbuf).
 *
 * Pins down:
 *   1. item 11: a forged NEWER row from one peer does not displace the
 *      valid older row another peer sent — the client gets the valid row.
 *   2. item 14: a get with "own" merges the local row with forwarded ones
 *      and answers the newest verified row of that owner.
 *   3. item 16: duplicate keys in one batch — the m-th reply entry for a
 *      key fills the m-th request slot with that key; a surplus entry is
 *      dropped.
 *   4. items 13/15: an entry with "u" is not an answer — the client gets
 *      "u" for that key; when no key could be looked up and no row exists
 *      the whole reply is UNAVAILABLE.
 *   5. item 12: a peer answering ONE row with more=true does not hold the
 *      client's page to that row.
 *   6. F6: an entry for a key the forward did not ask is dropped and is
 *      not counted as an answer.
 *   7. items 13/15 responder: a 4002 get_batch whose local read FAULTS
 *      answers that key with "u" (not an empty entry); the originator
 *      with a local fault and only a "u" answer says UNAVAILABLE.
 *   8. rev 3 R-d: a paged 4002 get_batch that stops before a row too large
 *      for its per-key budget answers "nx" = that row's serialized
 *      estimate; the originator, fed the reply, counts the source as a
 *      full page (it bounds). Costs one 600 KB value in the fixture DB.
 *
 * Requires: default build. Leaves behind: nothing (fixture DB unlinked).
 * RED on the tree before rev 2: the merge took the first verified row per
 * PK as it arrived (no deferred candidates), matched duplicate keys to the
 * first slot, had no "u", any more=true source bounded the page, and a
 * storage fault answered an empty entry.
 */

#include "server/nodus_server.h"
#include "core/nodus_storage.h"
#include "core/nodus_value.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "test_storage_helper.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t id_a, id_b;
static nodus_key_t key_k, key_l;

static dht_bf_batch_t B;
static dht_bf_conn_t C;
static int C_idx[NODUS_MAX_BATCH_KEYS];
static uint8_t reply_buf[1 << 20];
static uint8_t client_buf[1 << 20];

static nodus_value_t *mk(const nodus_identity_t *id, const nodus_key_t *key,
                         uint64_t vid, uint64_t seq, const char *data) {
    nodus_value_t *v = NULL;
    if (nodus_value_create(key, (const uint8_t *)data, strlen(data),
                           NODUS_VALUE_PERMANENT, 0, vid, seq, &id->pk, &v) != 0)
        return NULL;
    if (nodus_value_sign(v, &id->sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

/* One fake forward asking the batch indices idx[0..n) (its own batch has
 * n keys — the responder's page budget is split over n). */
static void fwd(const int *idx, int n) {
    memset(&C, 0, sizeof(C));
    C.fd = -1;
    memcpy(C_idx, idx, (size_t)n * sizeof(int));
    C.key_indices = C_idx;
    C.key_count = n;
    C.batch_key_count = n;
    snprintf(C.ip, sizeof(C.ip), "%s", "10.0.0.9");
    C.port = 4002;
}

/* Feed one crafted reply ({k, vs[, more, next][, u]} per entry). */
static int feed(const nodus_key_t *keys, int n, nodus_value_t ***vals,
                const size_t *counts, const nodus_t2_page_info_t *pages,
                const bool *unavail) {
    size_t len = 0;
    if (nodus_t2_result_get_batch_ex(77, keys, n, vals, counts, pages, unavail,
                                     reply_buf, sizeof(reply_buf), &len) != 0)
        return -1;
    return nodus_dht_bf_absorb_reply(&B, &C, reply_buf, len);
}

/* What the client gets. */
static int client_reply(nodus_tier2_msg_t *m) {
    size_t len = 0;
    memset(m, 0, sizeof(*m));
    if (nodus_dht_bf_encode_result(&B, client_buf, sizeof(client_buf), &len) != 0)
        return -1;
    return nodus_t2_decode(client_buf, len, m);
}

static int setup(const nodus_key_t *keys, int n) {
    if (nodus_dht_bf_batch_setup(&B, keys, n) != 0) return -1;
    B.txn_id = 9;
    return 0;
}

static void done(void) { nodus_dht_bf_batch_cleanup(NULL, &B); }

/* The responder: a calloc'd server with the in-process DHT attached (its
 * phase one only — the test opens the store itself) and one authenticated
 * 4002 session in slot 0 on `conn`: the DHT answers origin (INTER, 0),
 * which the server writes to inter_sessions[0].conn. */
static nodus_server_t *responder_new(nodus_tcp_conn_t *conn) {
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    nodus_dht_host_t host;
    nodus_server_dht_host(srv, &host);
    if (nodus_dht_backend_inproc_new(&host, &srv->dht) != 0) {
        free(srv);
        return NULL;
    }
    srv->inter_sessions[0].conn = conn;
    srv->inter_sessions[0].authenticated = true;
    return srv;
}

static void responder_free(nodus_server_t *srv) {
    if (!srv) return;
    srv->dht->ops->close(srv->dht);
    free(srv);
}

static void test_forged_newer_frames(void) {
    TEST("item 11: forged newer from one peer, valid older from another");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_value_t *valid = mk(&id_a, &key_k, 7, 3, "valid-older");
    nodus_value_t *forged = mk(&id_a, &key_k, 7, 9, "forged-newer");
    CHECK(valid && forged && setup(&key_k, 1) == 0, "setup");
    forged->data[0] ^= 0x01;
    B.is_get_all = true;
    B.sets[0].peers = 2;
    {
        int idx[1] = { 0 };
        nodus_value_t *r1[1] = { forged };
        nodus_value_t **v1[1] = { r1 };
        size_t c1[1] = { 1 };
        fwd(idx, 1);
        CHECK(feed(&key_k, 1, v1, c1, NULL, NULL) == 0, "absorb forged");
        nodus_value_t *r2[1] = { valid };
        nodus_value_t **v2[1] = { r2 };
        fwd(idx, 1);
        CHECK(feed(&key_k, 1, v2, c1, NULL, NULL) == 0, "absorb valid");
    }
    CHECK(client_reply(&m) == 0 && m.type == 'r', "client frame");
    CHECK(m.value_count == 1 && m.values[0]->seq == 3 &&
          nodus_value_verify(m.values[0]) == 0, "valid older row not returned");
    PASS();
out:
    nodus_t2_msg_free(&m);
    nodus_value_free(valid);
    nodus_value_free(forged);
    done();
}

static void test_own_get_merges_local(void) {
    TEST("item 14: get+own merges the local row with forwarded rows");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_value_t *local = mk(&id_a, &key_k, 1, 1, "local-old");
    nodus_value_t *newer = mk(&id_a, &key_k, 1, 2, "replica-newer");
    nodus_value_t *other = mk(&id_b, &key_k, 4, 50, "other-owner");
    CHECK(local && newer && other && setup(&key_k, 1) == 0, "setup");
    B.is_single_get = true;
    B.has_own = true;
    B.own = id_a.node_id;
    B.sets[0].peers = 1;
    {
        nodus_value_t *lrow[1] = { local };
        CHECK(nodus_dht_keyset_add(&B.sets[0], lrow, 1, &key_k, &B.own, NULL, true,
                                   NULL) == 0, "seed local");
        local = lrow[0];   /* NULL once taken */
        int idx[1] = { 0 };
        nodus_value_t *r[2] = { other, newer };
        nodus_value_t **v[1] = { r };
        size_t c[1] = { 2 };
        fwd(idx, 1);
        CHECK(feed(&key_k, 1, v, c, NULL, NULL) == 0, "absorb");
    }
    CHECK(client_reply(&m) == 0 && m.type == 'r' && m.value, "client frame");
    CHECK(m.value->seq == 2 && nodus_key_cmp(&m.value->owner_fp, &id_a.node_id) == 0,
          "not the owner's newest row");
    PASS();
out:
    nodus_t2_msg_free(&m);
    nodus_value_free(local);
    nodus_value_free(newer);
    nodus_value_free(other);
    done();
}

static void test_duplicate_keys_by_position(void) {
    TEST("item 16: duplicate keys matched by position; surplus dropped");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_key_t keys[3] = { key_k, key_k, key_l };
    nodus_value_t *r1 = mk(&id_a, &key_k, 11, 1, "first");
    nodus_value_t *r2 = mk(&id_a, &key_k, 22, 1, "second");
    nodus_value_t *r3 = mk(&id_a, &key_k, 33, 1, "surplus");
    CHECK(r1 && r2 && r3 && setup(keys, 3) == 0, "setup");
    B.sets[0].peers = 1;
    B.sets[1].peers = 1;
    {
        int idx[2] = { 0, 1 };
        nodus_key_t fk[3] = { key_k, key_k, key_k };
        nodus_value_t *a[1] = { r1 }, *b[1] = { r2 }, *c[1] = { r3 };
        nodus_value_t **v[3] = { a, b, c };
        size_t cnt[3] = { 1, 1, 1 };
        fwd(idx, 2);
        CHECK(feed(fk, 3, v, cnt, NULL, NULL) == 0, "absorb");
    }
    CHECK(client_reply(&m) == 0 && m.type == 'r' && m.batch_key_count == 3, "client frame");
    CHECK(m.batch_val_counts[0] == 1 && m.batch_vals[0][0]->value_id == 11,
          "slot 0 must get the first entry");
    CHECK(m.batch_val_counts[1] == 1 && m.batch_vals[1][0]->value_id == 22,
          "slot 1 must get the second entry");
    CHECK(m.batch_val_counts[2] == 0, "key L got rows");
    CHECK(!m.batch_unavail[0] && !m.batch_unavail[1] && !m.batch_unavail[2],
          "no key may be unavailable");
    PASS();
out:
    nodus_t2_msg_free(&m);
    nodus_value_free(r1); nodus_value_free(r2); nodus_value_free(r3);
    done();
}

static void test_u_marker(void) {
    TEST("items 13/15: \"u\" entry → client \"u\"; all \"u\" → UNAVAILABLE");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_key_t keys[2] = { key_k, key_l };
    nodus_value_t *row = mk(&id_a, &key_l, 5, 1, "l-row");
    CHECK(row && setup(keys, 2) == 0, "setup");
    B.sets[0].peers = 1;
    B.sets[1].peers = 1;
    {
        int idx[2] = { 0, 1 };
        nodus_value_t *lr[1] = { row };
        nodus_value_t **v[2] = { NULL, lr };
        size_t cnt[2] = { 0, 1 };
        bool u[2] = { true, false };
        fwd(idx, 2);
        CHECK(feed(keys, 2, v, cnt, NULL, u) == 0, "absorb");
    }
    CHECK(B.sets[0].answered == 0 && B.sets[1].answered == 1, "u counted as an answer");
    CHECK(client_reply(&m) == 0 && m.type == 'r' && m.batch_key_count == 2, "client frame");
    CHECK(m.batch_unavail[0] && !m.batch_unavail[1], "u not passed to the client");
    CHECK(m.batch_val_counts[1] == 1, "row of the looked-up key lost");
    nodus_t2_msg_free(&m);
    done();

    /* every key "u", no row anywhere → the whole reply is UNAVAILABLE */
    CHECK(setup(keys, 2) == 0, "setup2");
    B.sets[0].peers = 1;
    B.sets[1].peers = 1;
    {
        int idx[2] = { 0, 1 };
        nodus_value_t **v[2] = { NULL, NULL };
        size_t cnt[2] = { 0, 0 };
        bool u[2] = { true, true };
        fwd(idx, 2);
        CHECK(feed(keys, 2, v, cnt, NULL, u) == 0, "absorb2");
    }
    CHECK(client_reply(&m) == 0 && m.type == 'e' &&
          m.error_code == NODUS_ERR_UNAVAILABLE, "expected UNAVAILABLE");
    PASS();
out:
    nodus_t2_msg_free(&m);
    nodus_value_free(row);
    done();
}

static void test_one_row_page_source(void) {
    TEST("item 12: 1-row more=true peer does not hold the client page");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_value_t *a1 = mk(&id_a, &key_k, 1, 1, "r1");
    nodus_value_t *b_rows[5];
    for (int i = 0; i < 5; i++) b_rows[i] = mk(&id_a, &key_k, (uint64_t)(i + 1), 1, "rN");
    CHECK(a1 && setup(&key_k, 1) == 0, "setup");
    for (int i = 0; i < 5; i++) CHECK(b_rows[i], "rows");
    B.is_get_all = true;
    B.paged = true;
    B.sets[0].peers = 2;
    {
        int idx[1] = { 0 };
        nodus_value_t *ra[1] = { a1 };
        nodus_value_t **va[1] = { ra };
        size_t ca[1] = { 1 };
        nodus_t2_page_info_t pa[1];
        memset(pa, 0, sizeof(pa));
        pa[0].more = true;
        pa[0].has_next = true;
        pa[0].next.owner = id_a.node_id;
        pa[0].next.vid = 1;
        fwd(idx, 1);
        CHECK(feed(&key_k, 1, va, ca, pa, NULL) == 0, "absorb A");

        nodus_value_t **vb[1] = { b_rows };
        size_t cb[1] = { 5 };
        nodus_t2_page_info_t pb[1];
        memset(pb, 0, sizeof(pb));
        fwd(idx, 1);
        CHECK(feed(&key_k, 1, vb, cb, pb, NULL) == 0, "absorb B");
    }
    CHECK(client_reply(&m) == 0 && m.type == 'r', "client frame");
    CHECK(m.value_count == 5, "page held to the 1-row peer");
    CHECK(m.has_more && m.more && m.has_next && m.next.vid == 5, "more / next");
    PASS();
out:
    nodus_t2_msg_free(&m);
    nodus_value_free(a1);
    for (int i = 0; i < 5; i++) nodus_value_free(b_rows[i]);
    done();
}

static void test_unasked_key_entry(void) {
    TEST("F6: entry for a key not asked dropped, not an answer");
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_value_t *row = mk(&id_a, &key_l, 3, 1, "not-asked");
    CHECK(row && setup(&key_k, 1) == 0, "setup");
    B.is_get_all = true;
    B.sets[0].peers = 1;
    {
        int idx[1] = { 0 };
        nodus_value_t *r[1] = { row };
        nodus_value_t **v[1] = { r };
        size_t c[1] = { 1 };
        fwd(idx, 1);
        CHECK(feed(&key_l, 1, v, c, NULL, NULL) == 0, "absorb");
    }
    CHECK(B.sets[0].answered == 0 && B.sets[0].n == 0, "unasked entry absorbed");
    CHECK(client_reply(&m) == 0 && m.type == 'e' &&
          m.error_code == NODUS_ERR_UNAVAILABLE, "expected UNAVAILABLE");
    PASS();
out:
    nodus_t2_msg_free(&m);
    nodus_value_free(row);
    done();
}

/* sqlite3_step on this statement fails at run time ("integer overflow"),
 * the technique test_storage_get_all_page.c uses. */
static int break_stmt(nodus_storage_t *st, sqlite3_stmt **slot) {
    sqlite3_finalize(*slot);
    *slot = NULL;
    return sqlite3_prepare_v2(st->db,
        "SELECT abs(-9223372036854775807 - 1), ?1, ?2, ?3, ?4",
        -1, slot, NULL) == SQLITE_OK ? 0 : -1;
}

static void test_storage_fault(void) {
    TEST("items 13/15: responder fault → \"u\"; originator → UNAVAILABLE");
    nodus_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    nodus_server_t *srv = conn ? responder_new(conn) : NULL;
    nodus_dht_t *dht = NULL;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    bool opened = false;
    CHECK(srv && conn, "alloc");
    dht = nodus_dht_backend_inproc_state(srv->dht);
    test_storage_open(&dht->storage);
    opened = true;
    CHECK(break_stmt(&dht->storage, &dht->storage.stmt_get_all_page) == 0, "break");
    srv->config.require_peer_auth = false;     /* isolate the responder */
    conn->fd = -1;
    conn->slot = 0;                            /* inter_sessions[0] */
    conn->state = NODUS_CONN_CONNECTED;        /* send writes into wbuf */
    snprintf(conn->ip, sizeof(conn->ip), "%s", "10.0.0.8");

    /* a forwarded get_batch with "own" → the paged/owner read → FAULT */
    {
        uint8_t q[4096];
        size_t qlen = 0;
        uint8_t tok[NODUS_SESSION_TOKEN_LEN];
        memset(tok, 0, sizeof(tok));
        nodus_t2_read_opts_t opts = { .own = &id_a.node_id, .page = false, .after = NULL };
        CHECK(nodus_t2_get_batch_ex(3, tok, &key_k, 1, &opts, q, sizeof(q), &qlen) == 0,
              "encode query");
        nodus_server_dispatch_inter_frame(srv, &srv->inter_sessions[0], q, qlen);
    }
    CHECK(conn->wlen > 7, "responder sent nothing");
    {
        /* The wire header's length is LITTLE-endian (nodus_wire.c
         * nodus_frame_encode); parse with the transport's own decoder. */
        nodus_frame_t fr;
        CHECK(nodus_frame_decode(conn->wbuf, conn->wlen, &fr) > 0, "frame length");
        uint32_t flen = fr.payload_len;
        CHECK(fr.payload == conn->wbuf + NODUS_FRAME_HEADER_SIZE, "payload offset");
        CHECK(nodus_t2_decode(conn->wbuf + 7, flen, &m) == 0, "decode responder reply");
        CHECK(m.batch_key_count == 1 && m.batch_unavail && m.batch_unavail[0],
              "fault answered as an empty entry, not \"u\"");
        CHECK(m.batch_val_counts[0] == 0, "rows beside u");

        /* the originator: local read faulted, the only peer said "u" */
        CHECK(setup(&key_k, 1) == 0, "setup");
        B.is_get_all = true;
        B.sets[0].peers = 1;
        B.sets[0].local_fault = true;
        int idx[1] = { 0 };
        fwd(idx, 1);
        CHECK(nodus_dht_bf_absorb_reply(&B, &C, conn->wbuf + 7, flen) == 0, "absorb");
        nodus_t2_msg_free(&m);
        CHECK(client_reply(&m) == 0 && m.type == 'e' &&
              m.error_code == NODUS_ERR_UNAVAILABLE, "expected UNAVAILABLE");
    }
    PASS();
out:
    nodus_t2_msg_free(&m);
    done();
    if (opened) test_storage_close(&dht->storage);
    if (conn) {
        free(conn->wbuf);
        free(conn->rbuf);
        free(conn->pending_buf);
    }
    free(conn);
    responder_free(srv);
}

/* Rev 3 R-d end to end. The responder's store holds a small row (vid 1)
 * and a LARGE row (vid 2) that does not fit the per-key budget of a
 * 4-key paged get_batch (2 MiB / 4). It answers vid 1, more = true, and
 * "nx" = NODUS_VALUE_SERIALIZED_EST of vid 2. The originator, fed that
 * reply, counts the page as full: the source bounds.
 * FAILS WITHOUT R-d: no "nx" in the reply (has_nx false), and the old
 * rule (EST(5) + EST(0) > 512 KiB) leaves the source not bounding. */
static void test_nx_responder(void) {
    TEST("R-d: responder sends nx; originator counts the page full");
    nodus_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    nodus_server_t *srv = conn ? responder_new(conn) : NULL;
    nodus_dht_t *dht = NULL;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    bool opened = false;
    const size_t big_len = 600000;
    uint8_t *big_data = malloc(big_len);
    nodus_value_t *small = mk(&id_a, &key_k, 1, 1, "small");
    nodus_value_t *large = NULL;
    CHECK(srv && conn && big_data && small, "alloc");
    memset(big_data, 'L', big_len);
    CHECK(nodus_value_create(&key_k, big_data, big_len, NODUS_VALUE_PERMANENT, 0, 2, 1,
                             &id_a.pk, &large) == 0 &&
          nodus_value_sign(large, &id_a.sk) == 0, "large value");
    dht = nodus_dht_backend_inproc_state(srv->dht);
    CHECK(test_storage_open(&dht->storage) == 0, "store");
    opened = true;
    CHECK(nodus_storage_put(&dht->storage, small) == 0 &&
          nodus_storage_put(&dht->storage, large) == 0, "put");
    srv->config.require_peer_auth = false;     /* isolate the responder */
    conn->fd = -1;
    conn->slot = 0;                            /* inter_sessions[0] */
    conn->state = NODUS_CONN_CONNECTED;        /* send writes into wbuf */
    snprintf(conn->ip, sizeof(conn->ip), "%s", "10.0.0.7");
    {
        uint8_t q[4096];
        size_t qlen = 0;
        uint8_t tok[NODUS_SESSION_TOKEN_LEN];
        memset(tok, 0, sizeof(tok));
        nodus_key_t keys[4] = { key_k, key_l, key_l, key_l };
        nodus_t2_read_opts_t opts = { .own = NULL, .page = true, .after = NULL };
        CHECK(nodus_t2_get_batch_ex(4, tok, keys, 4, &opts, q, sizeof(q), &qlen) == 0,
              "encode query");
        nodus_server_dispatch_inter_frame(srv, &srv->inter_sessions[0], q, qlen);
    }
    CHECK(conn->wlen > 7, "responder sent nothing");
    {
        nodus_frame_t fr;
        CHECK(nodus_frame_decode(conn->wbuf, conn->wlen, &fr) > 0, "frame");
        uint32_t flen = fr.payload_len;
        CHECK(nodus_t2_decode(conn->wbuf + NODUS_FRAME_HEADER_SIZE, flen, &m) == 0,
              "decode responder reply");
        CHECK(m.batch_key_count == 4 && m.batch_page, "entries");
        CHECK(m.batch_val_counts[0] == 1 && m.batch_vals[0][0]->value_id == 1,
              "the large row must not fit the page");
        CHECK(m.batch_page[0].more && m.batch_page[0].has_nx &&
              m.batch_page[0].nx == (uint64_t)NODUS_VALUE_SERIALIZED_EST(big_len),
              "nx must be the estimate of the row the page stopped on");
        CHECK(!m.batch_page[1].has_nx, "nx on a complete key");

        CHECK(setup(&key_k, 1) == 0, "setup");
        B.is_get_all = true;
        B.paged = true;
        B.sets[0].peers = 1;
        int idx[1] = { 0 };
        fwd(idx, 1);
        C.batch_key_count = 4;      /* the responder split its budget over 4 keys */
        CHECK(nodus_dht_bf_absorb_reply(&B, &C, conn->wbuf + NODUS_FRAME_HEADER_SIZE,
                                           flen) == 0, "absorb");
        CHECK(B.sets[0].nsrc == 1 && B.sets[0].src[0].noted, "source noted");
        CHECK(B.sets[0].src[0].bounds, "a source that stopped on a large row must bound");
    }
    PASS();
out:
    nodus_t2_msg_free(&m);
    done();
    if (opened) test_storage_close(&dht->storage);
    if (conn) {
        free(conn->wbuf);
        free(conn->rbuf);
        free(conn->pending_buf);
    }
    free(conn);
    responder_free(srv);
    free(big_data);
    nodus_value_free(small);
    nodus_value_free(large);
}

int main(void) {
    printf("=== DHT Package A rev 2: forward path with crafted 4002 frames ===\n");
    uint8_t seed[32];
    memset(seed, 0x51, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_a) != 0) { printf("FATAL: id_a\n"); return 1; }
    memset(seed, 0x52, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_b) != 0) { printf("FATAL: id_b\n"); return 1; }
    nodus_hash((const uint8_t *)"pkg-a:frames-k", 14, &key_k);
    nodus_hash((const uint8_t *)"pkg-a:frames-l", 14, &key_l);
    for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) B.forwards[i].fd = -1;

    test_forged_newer_frames();
    test_own_get_merges_local();
    test_duplicate_keys_by_position();
    test_u_marker();
    test_one_row_page_source();
    test_unasked_key_entry();
    test_storage_fault();
    test_nx_responder();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
