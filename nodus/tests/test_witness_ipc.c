/**
 * Nodus — witness IPC (component split S3)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md items
 * 5, 7, 19, 20. The core side (server/nodus_chain_backend_ipc.c, the IPC
 * chain backend nodus-server uses with "witness_external") against the
 * witness side (witness/nodus_witness_ipc.c, the nodus-witness listener),
 * over a real <dir>/witness.sock. The witness module itself is replaced by
 * test handlers (nodus_witness_ipc_handlers_t), so what is proven is the
 * IPC, not the chain. A "client" is a real connection too: the core's
 * client-facing end is the accepted side of a second Unix socket, so a
 * relayed reply is read by the test exactly as a client would read it.
 *
 * Proves:
 *   - a session's first dnac_* request dials the witness, the ipc_hello
 *     preface carries the session's key and token: the dnac handler runs
 *     with the request's method, on a connection whose peer_id is the
 *     fingerprint of that key (what the witness's dnac handlers read), and
 *     find_session_conn(pk, token) returns that same connection;
 *   - the handler's reply reaches the client byte-for-byte unchanged;
 *   - dnac_cc_collect reaches the cc_collect handler with the session's
 *     key and token, on the same session connection;
 *   - session_closed closes the session socket: find_session_conn(pk,
 *     token) becomes NULL (the delayed cc_collect reply has nowhere to go);
 *   - the control connection's status snapshot round-trips: chain_open,
 *     status (height, state root, chain id) and listen_port report what
 *     the witness answered;
 *   - a first frame that is not a preface closes the connection;
 *   - with no witness listening, a dnac_* request is answered at once with
 *     exactly the bytes a witness-less server sends (nodus_t2_error,
 *     NODUS_ERR_PROTOCOL_ERROR, NODUS_CHAIN_NO_WITNESS_MSG), and that
 *     backend reports no chain;
 *   - with the witness listening but the backend's control connection
 *     not up (never ticked), a dnac_* request gets that same error and
 *     NO session socket is dialled: the witness never sees a session for
 *     that key/token and its dnac handler never runs;
 *   - per-session bound: with the witness not reading, ~64 KiB requests
 *     are forwarded until the session socket holds
 *     NODUS_WITNESS_IPC_QUEUE_MAX queued bytes; the next request gets the
 *     decision-20 error bytes for ITS txn id, and the socket stays open —
 *     once the witness reads again it serves EVERY forwarded request on
 *     that same connection and the client gets every reply;
 *   - the read_pending op exists and is false on an idle IPC backend.
 *     (The in-process backend's read_pending is `return false`; it is not
 *     instantiated here — that needs a full nodus_witness_init — so that
 *     half is checked by reading nodus_chain_backend_inproc.c.)
 *
 * Requires: a default build; no environment. Uses two mkdtemp directories
 * under /tmp and removes them; no ports.
 * How it can lie: every wait is a bounded poll loop whose exhaustion FAILs
 * the case (a timeout is never a pass); the polls' own 5 ms waits only
 * pace the loop. Two checks are absences, read after a bounded number of
 * witness polls: "no session was dialled" (backed by the positive check
 * that the requester got the error, not the handler's reply), and, in the
 * bound case, "this request was forwarded" = no client frame after it —
 * a refusal's error is written to the client socket synchronously inside
 * dispatch, so a missed one would be counted as forwarded and the final
 * "every forwarded request served" count would FAIL, never pass.
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp under -std=c11 */

#include "server/nodus_chain_backend.h"
#include "witness/nodus_witness_ipc.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

#define POLL_ROUNDS 400

static int passed = 0;
static int failed = 0;

static char g_dir[64];      /* witness listening here */
static char g_dir2[64];     /* nothing listening here */

/* ── The witness stand-in ─────────────────────────────────────────── */

static const uint8_t k_reply[] = { 0xA1, 0x61, 0x78, 0x18, 0x2A };  /* {"x":42} */

static int               h_dnac_calls = 0;
static char              h_dnac_method[64];
static nodus_tcp_conn_t *h_dnac_conn = NULL;
static bool              h_dnac_peer_set = false;
static nodus_key_t       h_dnac_peer_id;
static int               h_cc_calls = 0;
static nodus_tcp_conn_t *h_cc_conn = NULL;
static uint8_t           h_cc_pk[NODUS_PK_BYTES];
static uint8_t           h_cc_token[NODUS_SESSION_TOKEN_LEN];

static void h_dispatch_dnac(void *ctx, nodus_tcp_conn_t *conn,
                            const uint8_t *payload, size_t len,
                            const char *method, uint32_t txn_id) {
    (void)ctx; (void)payload; (void)len; (void)txn_id;
    h_dnac_calls++;
    snprintf(h_dnac_method, sizeof(h_dnac_method), "%s", method);
    h_dnac_conn = conn;
    h_dnac_peer_set = conn->peer_id_set;
    h_dnac_peer_id = conn->peer_id;
    nodus_tcp_send(conn, k_reply, sizeof(k_reply));
}

static void h_cc_collect(void *ctx, nodus_tcp_conn_t *conn,
                         const uint8_t pk[NODUS_PK_BYTES],
                         const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                         const uint8_t *payload, size_t len,
                         uint32_t txn_id) {
    (void)ctx; (void)payload; (void)len; (void)txn_id;
    h_cc_calls++;
    h_cc_conn = conn;
    memcpy(h_cc_pk, pk, NODUS_PK_BYTES);
    memcpy(h_cc_token, token, NODUS_SESSION_TOKEN_LEN);
    /* no reply: a collection answers later, through find_session_conn */
}

static void fill_status(nodus_witness_ipc_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->chain_open = true;
    st->height = 4242;
    for (int i = 0; i < 64; i++) st->state_root[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 32; i++) st->chain_id[i] = (uint8_t)(0x10 + i);
    st->p2p_opened = true;
    st->listen_port = 14004;
}

static void h_status(void *ctx, nodus_witness_ipc_status_t *out) {
    (void)ctx;
    fill_status(out);
}

/* ── The client stand-in ──────────────────────────────────────────── */

static nodus_tcp_t       g_front;           /* core's client-facing side */
static nodus_tcp_t       g_cli;             /* the client */
static nodus_tcp_conn_t *g_client_conn = NULL;   /* accepted on g_front */
static int               cli_frames = 0;
static uint8_t           cli_last[1024];
static size_t            cli_last_len = 0;

static void front_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    g_client_conn = conn;
}

static void cli_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    (void)conn; (void)ctx;
    cli_frames++;
    cli_last_len = len <= sizeof(cli_last) ? len : 0;
    if (cli_last_len) memcpy(cli_last, payload, len);
}

/* A raw peer of the witness socket (the non-preface case). */
static nodus_tcp_t g_raw;
static int raw_disconnects = 0;

static void raw_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    raw_disconnects++;
}

/* ── Helpers ──────────────────────────────────────────────────────── */

static uint8_t g_pk[NODUS_PK_BYTES];
static uint8_t g_token[NODUS_SESSION_TOKEN_LEN];

static void poll_all(nodus_chain_backend_t *b, nodus_witness_ipc_t *ipc) {
    if (b) b->ops->tick(b);
    if (ipc) nodus_witness_ipc_poll(ipc, 5);
    if (b) b->ops->tick(b);
    nodus_tcp_poll(&g_front, 5);
    nodus_tcp_poll(&g_cli, 5);
}

/* A client tier-2 query frame {"t","y":"q","q":method,"tok"}. */
static size_t t2_query(uint32_t txn, const char *method,
                       uint8_t *buf, size_t cap) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t");   cbor_encode_uint(&enc, txn);
    cbor_encode_cstr(&enc, "y");   cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");   cbor_encode_cstr(&enc, method);
    cbor_encode_cstr(&enc, "tok"); cbor_encode_bstr(&enc, g_token,
                                                    sizeof(g_token));
    return cbor_encoder_len(&enc);
}

/* ── Cases ────────────────────────────────────────────────────────── */

static void test_session_roundtrip(nodus_chain_backend_t *b,
                                   nodus_witness_ipc_t *ipc) {
    TEST("dnac_* reaches the witness with the session; reply unchanged");
    uint8_t frame[256];
    size_t n = t2_query(7, "dnac_test", frame, sizeof(frame));
    if (n == 0) { FAIL("encode"); return; }

    int frames_before = cli_frames;
    b->ops->dispatch_dnac(b, g_client_conn, g_pk, g_token, frame, n,
                          "dnac_test", 7);
    for (int i = 0; i < POLL_ROUNDS &&
                    (h_dnac_calls < 1 || cli_frames <= frames_before); i++)
        poll_all(b, ipc);

    if (h_dnac_calls != 1) { FAIL("dnac handler not reached"); return; }
    if (strcmp(h_dnac_method, "dnac_test") != 0) { FAIL("method"); return; }

    nodus_pubkey_t pub;
    nodus_key_t fp;
    memcpy(pub.bytes, g_pk, sizeof(g_pk));
    nodus_fingerprint(&pub, &fp);
    if (!h_dnac_peer_set || nodus_key_cmp(&h_dnac_peer_id, &fp) != 0) {
        FAIL("session conn does not carry the requester's fingerprint");
        return;
    }
    if (nodus_witness_ipc_find_session_conn(ipc, g_pk, g_token) != h_dnac_conn) {
        FAIL("find_session_conn does not return the session conn");
        return;
    }
    if (cli_frames != frames_before + 1 || cli_last_len != sizeof(k_reply) ||
        memcmp(cli_last, k_reply, sizeof(k_reply)) != 0) {
        FAIL("reply did not reach the client unchanged");
        return;
    }
    PASS();
}

static void test_cc_collect(nodus_chain_backend_t *b, nodus_witness_ipc_t *ipc) {
    TEST("dnac_cc_collect reaches cc_collect with the session's pk/token");
    uint8_t frame[256];
    size_t n = t2_query(8, "dnac_cc_collect", frame, sizeof(frame));
    if (n == 0) { FAIL("encode"); return; }

    b->ops->cc_collect(b, g_client_conn, g_pk, g_token, frame, n, 8);
    for (int i = 0; i < POLL_ROUNDS && h_cc_calls < 1; i++)
        poll_all(b, ipc);

    if (h_cc_calls != 1) { FAIL("cc_collect handler not reached"); return; }
    if (memcmp(h_cc_pk, g_pk, sizeof(g_pk)) != 0 ||
        memcmp(h_cc_token, g_token, sizeof(g_token)) != 0) {
        FAIL("cc_collect got another key or token");
        return;
    }
    if (h_cc_conn != h_dnac_conn) {
        FAIL("cc_collect did not use the session's one connection");
        return;
    }
    PASS();
}

static void test_status(nodus_chain_backend_t *b, nodus_witness_ipc_t *ipc) {
    TEST("control connection: status snapshot round-trips");
    for (int i = 0; i < POLL_ROUNDS && !b->ops->chain_open(b); i++)
        poll_all(b, ipc);
    if (!b->ops->chain_open(b)) { FAIL("snapshot never arrived"); return; }

    nodus_witness_ipc_status_t want;
    fill_status(&want);
    nodus_t2_status_info_t info;
    memset(&info, 0, sizeof(info));
    b->ops->status(b, &info);
    bool opened = false;
    int port = b->ops->listen_port(b, &opened);
    if (info.block_height != want.height ||
        memcmp(info.state_root, want.state_root, 64) != 0 ||
        memcmp(info.chain_id, want.chain_id, 32) != 0) {
        FAIL("status fields differ from the witness's answer");
        return;
    }
    if (!opened || port != want.listen_port) {
        FAIL("listen_port differs from the witness's answer");
        return;
    }
    PASS();
}

static void test_session_closed(nodus_chain_backend_t *b,
                                nodus_witness_ipc_t *ipc) {
    TEST("session_closed: find_session_conn returns NULL");
    if (!nodus_witness_ipc_find_session_conn(ipc, g_pk, g_token)) {
        FAIL("no session to close (earlier case failed)");
        return;
    }
    b->ops->session_closed(b, g_client_conn);
    for (int i = 0; i < POLL_ROUNDS &&
                    nodus_witness_ipc_find_session_conn(ipc, g_pk, g_token); i++)
        poll_all(b, ipc);
    if (nodus_witness_ipc_find_session_conn(ipc, g_pk, g_token)) {
        FAIL("the witness still finds the closed session");
        return;
    }
    PASS();
}

static void test_non_preface(nodus_witness_ipc_t *ipc, const char *sock) {
    TEST("a non-preface first frame closes the connection");
    nodus_tcp_init(&g_raw, -1);
    g_raw.on_disconnect = raw_on_disconnect;
    nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&g_raw, sock,
                                                 NODUS_TCP_UNIX_UID_SELF);
    if (!c) { FAIL("connect"); nodus_tcp_close(&g_raw); return; }

    uint8_t frame[256];
    size_t n = t2_query(9, "dnac_test", frame, sizeof(frame));
    int calls_before = h_dnac_calls;
    nodus_tcp_send(c, frame, n);
    for (int i = 0; i < POLL_ROUNDS && raw_disconnects < 1; i++) {
        nodus_witness_ipc_poll(ipc, 5);
        nodus_tcp_poll(&g_raw, 5);
    }
    bool closed = raw_disconnects == 1;
    bool unserved = h_dnac_calls == calls_before;
    nodus_tcp_close(&g_raw);
    if (!closed) { FAIL("connection stayed open"); return; }
    if (!unserved) { FAIL("the frame was served"); return; }
    PASS();
}

static void test_no_witness(void) {
    TEST("no witness: dnac_* answered with the decision-20 error at once");
    nodus_chain_backend_t *b2 = NULL;
    if (nodus_chain_backend_ipc_open(g_dir2, &b2) != 0 || !b2) {
        FAIL("open");
        return;
    }
    uint8_t frame[256];
    size_t n = t2_query(11, "dnac_test", frame, sizeof(frame));
    uint8_t want[256];
    size_t want_len = 0;
    nodus_t2_error(11, NODUS_ERR_PROTOCOL_ERROR, NODUS_CHAIN_NO_WITNESS_MSG,
                   want, sizeof(want), &want_len);

    int frames_before = cli_frames;
    b2->ops->dispatch_dnac(b2, g_client_conn, g_pk, g_token, frame, n,
                           "dnac_test", 11);
    for (int i = 0; i < POLL_ROUNDS && cli_frames <= frames_before; i++)
        poll_all(b2, NULL);

    bool got = cli_frames == frames_before + 1 && cli_last_len == want_len &&
               memcmp(cli_last, want, want_len) == 0;
    bool no_chain = !b2->ops->chain_open(b2);
    b2->ops->close(b2);
    if (!got) { FAIL("not the witness-less error bytes"); return; }
    if (!no_chain) { FAIL("reports a chain without a witness"); return; }
    PASS();
}

static void test_no_dial_without_ctl(nodus_witness_ipc_t *ipc) {
    TEST("control conn down: dnac_* gets the error, no session dialled");
    nodus_chain_backend_t *b3 = NULL;
    /* The LIVE witness directory: a dial would succeed here. Never
     * ticked, so its control connection is not up. */
    if (nodus_chain_backend_ipc_open(g_dir, &b3) != 0 || !b3) {
        FAIL("open");
        return;
    }
    uint8_t tok3[NODUS_SESSION_TOKEN_LEN];
    for (int i = 0; i < NODUS_SESSION_TOKEN_LEN; i++)
        tok3[i] = (uint8_t)(0xC3 ^ i);

    uint8_t frame[256];
    size_t n = t2_query(12, "dnac_test", frame, sizeof(frame));
    uint8_t want[256];
    size_t want_len = 0;
    nodus_t2_error(12, NODUS_ERR_PROTOCOL_ERROR, NODUS_CHAIN_NO_WITNESS_MSG,
                   want, sizeof(want), &want_len);

    int frames_before = cli_frames;
    int calls_before = h_dnac_calls;
    b3->ops->dispatch_dnac(b3, g_client_conn, g_pk, tok3, frame, n,
                           "dnac_test", 12);
    for (int i = 0; i < POLL_ROUNDS && cli_frames <= frames_before; i++) {
        nodus_tcp_poll(&g_front, 5);
        nodus_tcp_poll(&g_cli, 5);
    }
    bool got = cli_frames == frames_before + 1 && cli_last_len == want_len &&
               memcmp(cli_last, want, want_len) == 0;

    /* Give a dial, had one happened, every chance to reach the witness. */
    for (int i = 0; i < 20; i++)
        nodus_witness_ipc_poll(ipc, 5);
    bool dialled = nodus_witness_ipc_find_session_conn(ipc, g_pk, tok3) != NULL;
    bool served = h_dnac_calls != calls_before;
    b3->ops->close(b3);
    if (!got) { FAIL("not the decision-20 error bytes"); return; }
    if (dialled) { FAIL("a session socket reached the witness"); return; }
    if (served) { FAIL("the witness served the request"); return; }
    PASS();
}

/* A client tier-2 query with an extra top-level "pad" byte string of
 * `pad` bytes (nodus_t2_decode skips unknown top-level keys). */
static size_t t2_query_padded(uint32_t txn, const char *method,
                              const uint8_t *pad, size_t pad_len,
                              uint8_t *buf, size_t cap) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "t");   cbor_encode_uint(&enc, txn);
    cbor_encode_cstr(&enc, "y");   cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");   cbor_encode_cstr(&enc, method);
    cbor_encode_cstr(&enc, "tok"); cbor_encode_bstr(&enc, g_token,
                                                    sizeof(g_token));
    cbor_encode_cstr(&enc, "pad"); cbor_encode_bstr(&enc, pad, pad_len);
    return cbor_encoder_len(&enc);
}

#define OVERCAP_PAD       (64 * 1024)
/* 200 x 64 KiB = 12.5 MiB: the 4 MiB bound plus any kernel socket buffer
 * a default Linux gives an AF_UNIX stream (~208 KiB) with a wide margin. */
#define OVERCAP_MAX_REQS  200

static void test_session_bound(nodus_chain_backend_t *b,
                               nodus_witness_ipc_t *ipc) {
    TEST("per-session bound: over-cap request refused, socket stays");
    static uint8_t pad[OVERCAP_PAD];
    static uint8_t frame[OVERCAP_PAD + 256];
    memset(pad, 0x5A, sizeof(pad));

    int calls_before = h_dnac_calls;
    int frames_before = cli_frames;
    int forwarded = 0;
    bool refused = false, right_bytes = false;

    /* The witness is NOT polled in this phase: nothing drains the
     * session socket, so its queue grows until the bound. */
    for (int i = 0; i < OVERCAP_MAX_REQS && !refused; i++) {
        uint32_t txn = 2000u + (uint32_t)i;
        size_t n = t2_query_padded(txn, "dnac_test", pad, sizeof(pad),
                                   frame, sizeof(frame));
        if (n == 0) { FAIL("encode"); return; }

        int f0 = cli_frames;
        b->ops->dispatch_dnac(b, g_client_conn, g_pk, g_token, frame, n,
                              "dnac_test", txn);
        for (int r = 0; r < 4 && cli_frames == f0; r++) {
            nodus_tcp_poll(&g_front, 0);
            nodus_tcp_poll(&g_cli, 0);
        }
        if (cli_frames == f0) {
            forwarded++;
            continue;
        }
        refused = true;
        uint8_t want[256];
        size_t want_len = 0;
        nodus_t2_error(txn, NODUS_ERR_PROTOCOL_ERROR,
                       NODUS_CHAIN_NO_WITNESS_MSG, want, sizeof(want),
                       &want_len);
        right_bytes = cli_frames == f0 + 1 && cli_last_len == want_len &&
                      memcmp(cli_last, want, want_len) == 0;
    }
    if (!refused) { FAIL("no request was refused within the bound"); return; }
    if (!right_bytes) { FAIL("the refusal is not the decision-20 error"); return; }
    if (forwarded < 1) { FAIL("nothing was forwarded before the bound"); return; }

    /* Let the witness read again: every forwarded request must be served
     * on the one session connection, and every reply relayed. */
    int replies_want = frames_before + 1 + forwarded;
    for (int i = 0; i < POLL_ROUNDS &&
                    (h_dnac_calls < calls_before + forwarded ||
                     cli_frames < replies_want); i++)
        poll_all(b, ipc);
    if (h_dnac_calls != calls_before + forwarded) {
        FAIL("forwarded requests were lost (the socket was closed?)");
        return;
    }
    if (cli_frames != replies_want) {
        FAIL("not every forwarded request's reply reached the client");
        return;
    }
    nodus_tcp_conn_t *sc = nodus_witness_ipc_find_session_conn(ipc, g_pk,
                                                               g_token);
    if (!sc || sc != h_dnac_conn) {
        FAIL("the session connection did not stay open");
        return;
    }
    PASS();
}

static void test_read_pending_op(void) {
    TEST("read_pending op exists; false on an idle IPC backend");
    nodus_chain_backend_t *b4 = NULL;
    if (nodus_chain_backend_ipc_open(g_dir2, &b4) != 0 || !b4) {
        FAIL("open");
        return;
    }
    bool has_op = b4->ops->read_pending != NULL;
    bool pending = has_op && b4->ops->read_pending(b4);
    b4->ops->close(b4);
    if (!has_op) { FAIL("no read_pending op"); return; }
    if (pending) { FAIL("an idle backend reports pending reads"); return; }
    PASS();
}

int main(void) {
    printf("test_witness_ipc:\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/nodus_wipc_XXXXXX");
    snprintf(g_dir2, sizeof(g_dir2), "/tmp/nodus_wipc2_XXXXXX");
    if (!mkdtemp(g_dir) || !mkdtemp(g_dir2)) {
        printf("mkdtemp failed\n");
        return 1;
    }
    for (int i = 0; i < NODUS_PK_BYTES; i++) g_pk[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < NODUS_SESSION_TOKEN_LEN; i++)
        g_token[i] = (uint8_t)(0x55 ^ i);

    char wsock[NODUS_TCP_UNIX_PATH_MAX], fsock[NODUS_TCP_UNIX_PATH_MAX];
    nodus_witness_ipc_sock_path(g_dir, wsock, sizeof(wsock));
    snprintf(fsock, sizeof(fsock), "%s/front.sock", g_dir);

    /* The witness side. */
    nodus_witness_ipc_handlers_t h = {
        .dispatch_dnac = h_dispatch_dnac,
        .cc_collect    = h_cc_collect,
        .status        = h_status,
        .ctx           = NULL,
    };
    nodus_witness_ipc_t *ipc = nodus_witness_ipc_new(&h);
    if (!ipc || nodus_witness_ipc_listen(ipc, wsock) != 0) {
        printf("witness IPC listen failed\n");
        return 1;
    }

    /* The client, and core's end of it. */
    nodus_tcp_init(&g_front, -1);
    nodus_tcp_init(&g_cli, -1);
    g_front.on_accept = front_on_accept;
    g_cli.on_frame = cli_on_frame;
    if (nodus_tcp_unix_listen(&g_front, fsock, NODUS_TCP_UNIX_UID_SELF) != 0 ||
        !nodus_tcp_unix_connect(&g_cli, fsock, NODUS_TCP_UNIX_UID_SELF)) {
        printf("client socket setup failed\n");
        return 1;
    }
    for (int i = 0; i < POLL_ROUNDS && !g_client_conn; i++)
        nodus_tcp_poll(&g_front, 5);
    if (!g_client_conn) {
        printf("client connection never accepted\n");
        return 1;
    }

    /* Core's backend. */
    nodus_chain_backend_t *b = NULL;
    if (nodus_chain_backend_ipc_open(g_dir, &b) != 0 || !b) {
        printf("backend open failed\n");
        return 1;
    }

    test_no_witness();
    test_no_dial_without_ctl(ipc);
    test_read_pending_op();
    /* The control connection first: without it no session socket is
     * dialled (the backend's no-dial-while-down rule). */
    test_status(b, ipc);
    test_session_roundtrip(b, ipc);
    test_cc_collect(b, ipc);
    test_session_closed(b, ipc);
    test_non_preface(ipc, wsock);
    test_session_bound(b, ipc);

    b->ops->close(b);
    nodus_witness_ipc_free(ipc);
    nodus_tcp_close(&g_cli);
    nodus_tcp_close(&g_front);
    rmdir(g_dir);
    rmdir(g_dir2);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
