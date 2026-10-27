/**
 * Nodus — DHT Package A rev 2 item 7: 4002 handshake role split and the
 * accepting side's send gate.
 *
 * In-process: a calloc'd server, one inter session on a heap conn (fd -1,
 * state CONNECTED so handshake replies land in its write buffer), frames
 * fed to nodus_server_dispatch_inter_frame. srv->inter_tcp.poll_depth = 1
 * makes nodus_tcp_disconnect PARK the conn (close_pending) instead of
 * freeing it, so "was it disconnected" is observable; no on_disconnect
 * callback is installed, so the session is not cleared and its fields can
 * be checked after the frame.
 *
 * Pins down:
 *   1. A conn we ACCEPTED that receives a dialer-only frame (auth_ok,
 *      challenge, key_ack) is disconnected — and an inbound auth_ok does
 *      not mark the session authenticated (it did before rev 2).
 *   2. A conn we DIALED that receives an acceptor-only frame (hello, auth,
 *      key_init) is disconnected.
 *   3. Right-role frames are not: an inbound hello gets a challenge, an
 *      "error" is accepted on either side.
 *   4. A repeated auth_ok on a dialed, already authenticated conn is
 *      dropped (no second key exchange), not acted on.
 *   5. With Kyber, the accepting side keeps its send gate CLOSED after a
 *      valid auth (auth_state != AUTH_OK: nodus_tcp_send queues instead of
 *      writing plaintext) and opens it only when key_init produced the
 *      session key.
 *
 * Requires: default build. Leaves behind: nothing.
 * RED on the tree before rev 2: role-wrong frames were processed (inbound
 * auth_ok authenticated the session; an inbound challenge got an error
 * reply, not a disconnect; hello / auth on a dialed conn ran the acceptor
 * code) and the accepting side set AUTH_OK at auth.
 */

#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/enc/qgp_kyber.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t id_srv, id_peer;
static uint8_t frame[16384];

static nodus_server_t *new_server(bool with_identity) {
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->config.require_peer_auth = true;
    srv->inter_tcp.poll_depth = 1;          /* disconnect parks the conn */
    nodus_inter_circuit_table_init(&srv->inter_circuits);
    if (with_identity) srv->identity = id_srv;   /* has_kyber = true */
    return srv;
}

static nodus_tcp_conn_t *new_conn(bool dialed) {
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = -1;
    c->slot = -1;
    c->state = NODUS_CONN_CONNECTED;
    c->auth_initiated_by_us = dialed;
    c->auth_required = true;
    snprintf(c->ip, sizeof(c->ip), "%s", "10.7.7.7");
    c->port = 4002;
    return c;
}

static void free_conn(nodus_tcp_conn_t *c) {
    if (!c) return;
    free(c->wbuf);
    free(c->rbuf);
    free(c->pending_buf);
    free(c);
}

/* Feed one frame to a fresh session on a fresh conn; report whether the
 * conn was disconnected and whether the session got authenticated. */
static int feed_fresh(bool dialed, const uint8_t *f, size_t len,
                      bool *disconnected, bool *authed) {
    nodus_server_t *srv = new_server(false);
    nodus_tcp_conn_t *c = new_conn(dialed);
    nodus_inter_session_t sess;
    if (!srv || !c) { free(srv); free_conn(c); return -1; }
    memset(&sess, 0, sizeof(sess));
    sess.conn = c;
    nodus_server_dispatch_inter_frame(srv, &sess, f, len);
    *disconnected = c->close_pending;
    *authed = sess.authenticated || c->authenticated;
    free_conn(c);
    free(srv);
    return 0;
}

static void test_inbound_dialer_frames(void) {
    TEST("accepted conn: auth_ok / challenge / key_ack → disconnect");
    uint8_t tok[NODUS_SESSION_TOKEN_LEN], nonce[NODUS_NONCE_LEN];
    memset(tok, 0x11, sizeof(tok));
    memset(nonce, 0x22, sizeof(nonce));
    size_t len = 0;
    bool disc = false, authed = false;

    CHECK(nodus_t2_auth_ok(1, tok, frame, sizeof(frame), &len) == 0, "enc auth_ok");
    CHECK(feed_fresh(false, frame, len, &disc, &authed) == 0, "feed");
    CHECK(disc, "inbound auth_ok not disconnected");
    CHECK(!authed, "inbound auth_ok authenticated the session");

    CHECK(nodus_t2_challenge(2, nonce, frame, sizeof(frame), &len) == 0, "enc challenge");
    CHECK(feed_fresh(false, frame, len, &disc, &authed) == 0, "feed");
    CHECK(disc, "inbound challenge not disconnected");

    CHECK(nodus_t2_key_ack(3, nonce, frame, sizeof(frame), &len) == 0, "enc key_ack");
    CHECK(feed_fresh(false, frame, len, &disc, &authed) == 0, "feed");
    CHECK(disc, "inbound key_ack not disconnected");
    PASS();
out:
    return;
}

static void test_outbound_acceptor_frames(void) {
    TEST("dialed conn: hello / auth / key_init → disconnect");
    nodus_sig_t sig;
    memset(&sig, 0x33, sizeof(sig));
    uint8_t ct[NODUS_KYBER_CT_BYTES], nc[NODUS_NONCE_LEN];
    memset(ct, 0x44, sizeof(ct));
    memset(nc, 0x55, sizeof(nc));
    size_t len = 0;
    bool disc = false, authed = false;

    CHECK(nodus_t2_hello(1, &id_peer.pk, &id_peer.node_id, frame, sizeof(frame), &len) == 0,
          "enc hello");
    CHECK(feed_fresh(true, frame, len, &disc, &authed) == 0, "feed");
    CHECK(disc, "hello on a dialed conn not disconnected");

    CHECK(nodus_t2_auth(2, &sig, frame, sizeof(frame), &len) == 0, "enc auth");
    CHECK(feed_fresh(true, frame, len, &disc, &authed) == 0, "feed");
    CHECK(disc && !authed, "auth on a dialed conn not disconnected");

    CHECK(nodus_t2_key_init(3, ct, nc, 0, frame, sizeof(frame), &len) == 0, "enc key_init");
    CHECK(feed_fresh(true, frame, len, &disc, &authed) == 0, "feed");
    CHECK(disc, "key_init on a dialed conn not disconnected");
    PASS();
out:
    return;
}

static void test_right_role_kept(void) {
    TEST("right-role frames are processed, not disconnected");
    nodus_server_t *srv = new_server(false);
    nodus_tcp_conn_t *c = new_conn(false);
    nodus_inter_session_t sess;
    size_t len = 0;
    bool disc = false, authed = false;
    CHECK(srv && c, "alloc");
    memset(&sess, 0, sizeof(sess));
    sess.conn = c;

    /* inbound hello → challenge (nonce pending), conn kept */
    CHECK(nodus_t2_hello(1, &id_peer.pk, &id_peer.node_id, frame, sizeof(frame), &len) == 0,
          "enc hello");
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(!c->close_pending, "inbound hello disconnected");
    CHECK(sess.nonce_pending && c->wlen > 0, "no challenge sent");

    /* "error" on either side is not a role violation */
    CHECK(nodus_t2_error(2, NODUS_ERR_PROTOCOL_ERROR, "x", frame, sizeof(frame), &len) == 0,
          "enc error");
    CHECK(feed_fresh(true, frame, len, &disc, &authed) == 0 && !disc,
          "error on a dialed conn disconnected");
    CHECK(feed_fresh(false, frame, len, &disc, &authed) == 0 && !disc,
          "error on an accepted conn disconnected");
    PASS();
out:
    free_conn(c);
    free(srv);
}

static void test_repeated_auth_ok_dropped(void) {
    TEST("dialed conn: repeated auth_ok dropped, no second key exchange");
    nodus_server_t *srv = new_server(true);
    nodus_tcp_conn_t *c = new_conn(true);
    nodus_inter_session_t sess;
    uint8_t tok[NODUS_SESSION_TOKEN_LEN];
    memset(tok, 0x66, sizeof(tok));
    size_t len = 0;
    CHECK(srv && c, "alloc");
    memset(&sess, 0, sizeof(sess));
    sess.conn = c;
    sess.authenticated = true;              /* the handshake already ran */
    c->authenticated = true;
    c->channel_crypto.established = true;   /* past F3 */
    CHECK(nodus_t2_auth_ok(4, tok, frame, sizeof(frame), &len) == 0, "enc");
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(!c->close_pending, "right-role repeat disconnected");
    CHECK(!sess.dial.pending_kem && c->wlen == 0, "a second key exchange was started");
    PASS();
out:
    free_conn(c);
    free(srv);
}

static void test_accept_side_gate_until_key(void) {
    TEST("accepting side: send gate closed after auth, open after key_init");
    nodus_server_t *srv = new_server(true);
    nodus_tcp_conn_t *c = new_conn(false);
    nodus_inter_session_t sess;
    size_t len = 0;
    CHECK(srv && c, "alloc");
    memset(&sess, 0, sizeof(sess));
    sess.conn = c;
    /* state after a hello from id_peer (v2): challenge nonce pending */
    sess.client_pk = id_peer.pk;
    sess.client_fp = id_peer.node_id;
    sess.proto_version = 2;
    memset(sess.nonce, 0x77, NODUS_NONCE_LEN);
    sess.nonce_pending = true;

    nodus_sig_t sig;
    CHECK(nodus_sign_auth_challenge(&sig, sess.nonce, &id_peer.sk) == 0, "sign");
    CHECK(nodus_t2_auth(5, &sig, frame, sizeof(frame), &len) == 0, "enc auth");
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(!c->close_pending, "valid auth disconnected");
    CHECK(sess.authenticated, "valid auth not accepted");
    CHECK(c->auth_state != NODUS_CONN_AUTH_OK, "send gate opened before the session key");

    /* key_init encapsulated to this node's Kyber key */
    uint8_t ct[NODUS_KYBER_CT_BYTES], ss[NODUS_KYBER_SS_BYTES], nc[NODUS_NONCE_LEN];
    memset(nc, 0x12, sizeof(nc));
    CHECK(qgp_kem1024_encapsulate(ct, ss, srv->identity.kyber_pk) == 0, "encap");
    CHECK(nodus_t2_key_init(6, ct, nc, 0, frame, sizeof(frame), &len) == 0, "enc key_init");
    nodus_server_dispatch_inter_frame(srv, &sess, frame, len);
    CHECK(c->channel_crypto.established, "session key not established");
    CHECK(c->auth_state == NODUS_CONN_AUTH_OK, "send gate not opened after key_init");
    CHECK(!c->close_pending, "disconnected");
    PASS();
out:
    if (c) nodus_channel_crypto_clear(&c->channel_crypto);
    free_conn(c);
    free(srv);
}

int main(void) {
    printf("=== DHT Package A rev 2 item 7: 4002 handshake role split ===\n");
    uint8_t seed[32];
    memset(seed, 0x71, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_srv) != 0) { printf("FATAL: id_srv\n"); return 1; }
    memset(seed, 0x72, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_peer) != 0) { printf("FATAL: id_peer\n"); return 1; }

    test_inbound_dialer_frames();
    test_outbound_acceptor_frames();
    test_right_role_kept();
    test_repeated_auth_ok_dropped();
    test_accept_side_gate_until_key();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
