/**
 * Nodus — DHT Package A F2 / F3: nothing on 4002 is processed before the
 * peer authenticated AND the session key exists.
 *
 * In-process: a calloc'd server with require_peer_auth, one inter session
 * on a fake (never-connected, fd -1) conn, frames fed to
 * nodus_server_dispatch_inter_frame (nodus_server.h internal section). The
 * observable is a T1 "sub" (SUBSCRIBE_FWD): when processed it adds an
 * entry to srv->subscriptions, and it sends nothing.
 *
 * Pins down:
 *   1. F2: a frame that the T2 decoder REFUSES but the T1 decoder accepts
 *      (bstr "d" in both "a" and "r" — T2 refuses the double data owner,
 *      T1 skips "d") from an UNAUTHENTICATED peer is dropped. Positive
 *      control: the same frame from an authenticated peer (F3 off) is
 *      processed.
 *   2. F3: an AUTHENTICATED peer whose session key is not established yet
 *      (this node has Kyber) gets its "sub" dropped; once established, the
 *      same frame is processed.
 *   3. Rev 2 item 17: the same holds for a T2 method — a ri_close for a
 *      circuit on this conn is dropped before the session key, processed
 *      after.
 *
 * RED on the tree before Package A: the T1 dispatch had no auth check
 * (the T2 gate sat inside the T2-decode branch) and no handler read
 * channel_crypto.established.
 */

#include "server/nodus_server.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static nodus_tcp_conn_t conn;
static uint8_t frame[4096];

static nodus_server_t *new_server(bool has_kyber) {
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->config.require_peer_auth = true;
    srv->identity.has_kyber = has_kyber;
    nodus_inter_circuit_table_init(&srv->inter_circuits);
    return srv;
}

static void reset_conn(void) {
    memset(&conn, 0, sizeof(conn));
    conn.fd = -1;
    conn.slot = -1;
    snprintf(conn.ip, sizeof(conn.ip), "%s", "10.9.9.9");
    conn.port = 4002;
}

static int active_subs(const nodus_server_t *srv) {
    int n = 0;
    for (int i = 0; i < srv->subscriptions.count; i++)
        if (srv->subscriptions.entries[i].active) n++;
    return n;
}

/* {t, y:"q", q:"sub", a:{k: key, d: h'01'}, r:{d: h'01'}} */
static size_t t1_only_sub(const nodus_key_t *key) {
    const uint8_t one = 0x01;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, frame, sizeof(frame));
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "sub");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "k"); cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, &one, 1);
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, &one, 1);
    return cbor_encoder_len(&enc);
}

static void test_f2_unauth_t1_dropped(void) {
    TEST("F2: unauthenticated T2-refused/T1-valid frame dropped");
    nodus_server_t *srv = new_server(false);   /* F3 off: isolate F2 */
    nodus_inter_session_t sess;
    nodus_key_t key;
    memset(key.bytes, 0x3C, NODUS_KEY_BYTES);
    CHECK(srv, "alloc");
    reset_conn();
    memset(&sess, 0, sizeof(sess));
    sess.conn = &conn;
    sess.authenticated = false;

    size_t len = t1_only_sub(&key);
    /* Preconditions: this frame shape bypasses the T2 gate */
    {
        nodus_tier2_msg_t m2;
        nodus_tier1_msg_t m1;
        CHECK(nodus_t2_decode(frame, len, &m2) != 0, "T2 must refuse the frame");
        CHECK(nodus_t1_decode(frame, len, &m1) == 0 &&
              strcmp(m1.method, "sub") == 0, "T1 must accept the frame");
        nodus_t1_msg_free(&m1);
    }

    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(active_subs(srv) == 0, "unauthenticated T1 sub was processed");

    /* positive control: authenticated → processed */
    sess.authenticated = true;
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(active_subs(srv) == 1, "authenticated T1 sub was not processed");
    PASS();
out:
    free(srv);
}

static void test_f3_before_session_key(void) {
    TEST("F3: authenticated but no session key yet → dropped");
    nodus_server_t *srv = new_server(true);
    nodus_inter_session_t sess;
    nodus_key_t key;
    memset(key.bytes, 0x4D, NODUS_KEY_BYTES);
    size_t len = 0;
    CHECK(srv, "alloc");
    reset_conn();
    memset(&sess, 0, sizeof(sess));
    sess.conn = &conn;
    sess.authenticated = true;
    conn.channel_crypto.established = false;

    CHECK(nodus_t1_subscribe(1, &key, frame, sizeof(frame), &len) == 0, "encode");
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(active_subs(srv) == 0, "sub processed before the session key existed");

    /* the T2-refused / T1-valid shape is gated the same way */
    len = t1_only_sub(&key);
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(active_subs(srv) == 0, "T1-only sub processed before the session key existed");

    /* positive control: established → processed */
    conn.channel_crypto.established = true;
    CHECK(nodus_t1_subscribe(2, &key, frame, sizeof(frame), &len) == 0, "encode2");
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(active_subs(srv) == 1, "sub not processed after the session key existed");
    PASS();
out:
    free(srv);
}

/* Rev 2 item 17: the F3 gate also holds for T2 methods, not only T1 "sub":
 * a ri_close for a circuit routed over this very conn, from an
 * authenticated peer, is dropped until the session key exists. */
static void test_f3_t2_method_before_session_key(void) {
    TEST("F3: T2 method (ri_close) before the session key → dropped");
    nodus_server_t *srv = new_server(true);
    nodus_inter_session_t sess;
    uint8_t buf[256];
    size_t len = 0;
    CHECK(srv, "alloc");
    reset_conn();
    nodus_circuit_table_init(&srv->sessions[0].circuits);
    nodus_circuit_t *c = nodus_circuit_alloc(&srv->sessions[0].circuits);
    nodus_inter_circuit_t *ic = nodus_inter_circuit_alloc(&srv->inter_circuits);
    CHECK(c && ic, "circuit setup");
    ic->peer_conn = &conn;
    ic->peer_cid = 501;
    ic->local_sess = (struct nodus_session *)&srv->sessions[0];
    ic->local_cid = c->local_cid;
    c->inter = ic;
    uint64_t cid = ic->our_cid;

    memset(&sess, 0, sizeof(sess));
    sess.conn = &conn;
    sess.authenticated = true;
    conn.channel_crypto.established = false;

    CHECK(nodus_t2_ri_close(0, cid, buf, sizeof(buf), &len) == 0, "encode");
    nodus_server_dispatch_inter_frame(srv, &sess, buf, len);
    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid) != NULL,
          "ri_close processed before the session key existed");
    CHECK(c->in_use && c->inter == ic, "client circuit touched");

    /* positive control: established → processed */
    conn.channel_crypto.established = true;
    nodus_server_dispatch_inter_frame(srv, &sess, buf, len);
    CHECK(nodus_inter_circuit_lookup(&srv->inter_circuits, cid) == NULL,
          "ri_close not processed after the session key existed");
    PASS();
out:
    free(srv);
}

int main(void) {
    printf("=== DHT Package A F2/F3: 4002 pre-auth / pre-key gate ===\n");
    test_f2_unauth_t1_dropped();
    test_f3_before_session_key();
    test_f3_t2_method_before_session_key();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
