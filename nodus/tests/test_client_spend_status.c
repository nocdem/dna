/**
 * Nodus — Client SDK: nodus_client_dnac_spend reply "status" handling
 *
 * Regression for commit 680f9475 (nodus_client.c, nodus_client_dnac_spend):
 * result_out is zeroed at entry and status 0 is NODUS_DNAC_APPROVED, so a
 * success reply ('r') that carried no readable uint "status" used to read
 * as "accepted". The function now returns NODUS_ERR_PROTOCOL_ERROR unless
 * "status" was decoded as a uint (the has_status flag).
 *
 * The REAL nodus_client_dnac_spend runs against a fake server built the
 * way test_client_pin.c builds its fake (nodus_tcp_t + nodus_t2_* encoders,
 * FAKE_NO_KPK handshake: plain auth_ok, unencrypted session). The fake
 * answers the client's "dnac_spend" query with a reply shape chosen per
 * case.
 *
 * What it proves:
 *   S1  reply {"status": 0, "ts": ..}      -> rc 0, status APPROVED.
 *   S1b reply {"status": 1, "ts": ..}      -> rc 0, status REJECTED
 *       (control: "status" is actually read, not left at the zeroed
 *       default — without it S1 passes even if the key were ignored).
 *   S2  reply without a "status" key (other fields present)
 *                                          -> NODUS_ERR_PROTOCOL_ERROR.
 *   S3  reply with "status" as a text string
 *                                          -> NODUS_ERR_PROTOCOL_ERROR.
 *   S4  error reply ('e', nodus_t2_error, code NODUS_ERR_DOUBLE_SPEND)
 *                                          -> rc NODUS_ERR_DOUBLE_SPEND.
 *
 * RED without the fix: remove has_status (the `if (!has_status) return
 * NODUS_ERR_PROTOCOL_ERROR;` before the final `return 0`) and S2 and S3
 * both get rc 0 with status == NODUS_DNAC_APPROVED (the memset value), so
 * their `rc == NODUS_ERR_PROTOCOL_ERROR` checks fail. S1, S1b and S4 pass
 * either way — they pin that the fix did not change honest replies.
 *
 * What it requires: default standalone nodus build; no environment.
 * Ports: the fake listens on 127.0.0.1:0 (kernel-chosen); no fixed port.
 * What it leaves behind: nothing (fake thread joined, client closed).
 *
 * How it can lie:
 *   - The fake's replies are hand-built; they prove the client's decoding,
 *     not that the node (nodus_witness_handlers.c handle_dnac_spend) sends
 *     "status" on every success reply.
 *   - A fake that never answers makes the client wait its 60 s spend
 *     timeout and return NODUS_ERR_TIMEOUT; each case asserts its exact
 *     code, so that shows up as a FAIL, never as a pass.
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── Fake server (test_client_pin.c pattern) ───────────────────────── */

typedef enum {
    REPLY_STATUS_APPROVED = 0,   /* {status: 0, ts}                     */
    REPLY_STATUS_REJECTED,       /* {status: 1, ts}                     */
    REPLY_NO_STATUS,             /* {ts, bnr, ti} — no "status"         */
    REPLY_STATUS_TEXT,           /* {status: "0", ts}                   */
    REPLY_ERROR                  /* 'e' reply, NODUS_ERR_DOUBLE_SPEND   */
} reply_mode_t;

typedef struct {
    nodus_tcp_t  *tcp;
    _Atomic int   mode;
    _Atomic bool  stop;
    pthread_t     tid;
    uint8_t      *buf;
} fake_server_t;

#define FAKE_BUF_SIZE 32768
#define FAKE_TS       1700000000ULL

static fake_server_t g_fake;

/* Same header layout as nodus_tier2.c enc_response_header (static there). */
static void fake_resp_header(cbor_encoder_t *enc, uint32_t txn, const char *method) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, method);
}

static void fake_send_spend_reply(nodus_tcp_conn_t *conn, uint32_t txn) {
    int mode = atomic_load(&g_fake.mode);
    size_t len = 0;

    if (mode == REPLY_ERROR) {
        if (nodus_t2_error(txn, NODUS_ERR_DOUBLE_SPEND, "double spend",
                           g_fake.buf, FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(conn, g_fake.buf, len);
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_fake.buf, FAKE_BUF_SIZE);
    fake_resp_header(&enc, txn, "dnac_spend");
    cbor_encode_cstr(&enc, "r");

    switch (mode) {
    case REPLY_STATUS_APPROVED:
    case REPLY_STATUS_REJECTED:
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "status");
        cbor_encode_uint(&enc, mode == REPLY_STATUS_APPROVED
                               ? NODUS_DNAC_APPROVED : NODUS_DNAC_REJECTED);
        cbor_encode_cstr(&enc, "ts"); cbor_encode_uint(&enc, FAKE_TS);
        break;
    case REPLY_NO_STATUS:
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "ts");  cbor_encode_uint(&enc, FAKE_TS);
        cbor_encode_cstr(&enc, "bnr"); cbor_encode_uint(&enc, 42);
        cbor_encode_cstr(&enc, "ti");  cbor_encode_uint(&enc, 0);
        break;
    case REPLY_STATUS_TEXT:
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "status"); cbor_encode_cstr(&enc, "0");
        cbor_encode_cstr(&enc, "ts");     cbor_encode_uint(&enc, FAKE_TS);
        break;
    default:
        return;
    }

    len = cbor_encoder_len(&enc);
    if (len > 0 && !enc.error) nodus_tcp_send(conn, g_fake.buf, len);
}

static void fake_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                           size_t len, void *ctx) {
    (void)ctx;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        return;
    }

    size_t out = 0;
    if (strcmp(msg.method, "hello") == 0) {
        uint8_t nonce[NODUS_NONCE_LEN];
        nodus_random(nonce, NODUS_NONCE_LEN);
        if (nodus_t2_challenge(msg.txn_id, nonce,
                                g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "auth") == 0) {
        /* Plain auth_ok (token only): unencrypted session, as W1 in
         * test_client_pin.c — an unpinned client accepts it. */
        uint8_t token[NODUS_SESSION_TOKEN_LEN];
        memset(token, 0x5a, sizeof(token));
        if (nodus_t2_auth_ok(msg.txn_id, token,
                              g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "dnac_spend") == 0) {
        fake_send_spend_reply(conn, msg.txn_id);
    }
    nodus_t2_msg_free(&msg);
}

static void *fake_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_fake.stop))
        nodus_tcp_poll(g_fake.tcp, 20);
    return NULL;
}

static int start_fake_server(void) {
    memset(&g_fake, 0, sizeof(g_fake));
    g_fake.tcp = calloc(1, sizeof(nodus_tcp_t));
    g_fake.buf = malloc(FAKE_BUF_SIZE);
    if (!g_fake.tcp || !g_fake.buf) return -1;
    if (nodus_tcp_init(g_fake.tcp, -1) != 0) return -1;
    g_fake.tcp->on_frame = fake_on_frame;
    if (nodus_tcp_listen(g_fake.tcp, "127.0.0.1", 0) != 0) return -1;
    atomic_store(&g_fake.mode, REPLY_STATUS_APPROVED);
    atomic_store(&g_fake.stop, false);
    return pthread_create(&g_fake.tid, NULL, fake_thread, NULL) == 0 ? 0 : -1;
}

static void stop_fake_server(void) {
    atomic_store(&g_fake.stop, true);
    pthread_join(g_fake.tid, NULL);
    nodus_tcp_close(g_fake.tcp);
    free(g_fake.tcp);
    free(g_fake.buf);
}

/* ── Spend call ────────────────────────────────────────────────────── */

/* Large — static, never stack locals. Contents are irrelevant to the
 * fake, which never verifies them. */
static nodus_pubkey_t g_sender_pk;
static nodus_sig_t    g_sender_sig;
static nodus_dnac_spend_result_t g_result;

static int spend_once(nodus_client_t *c) {
    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t tx_data[64];
    memset(tx_hash, 0x11, sizeof(tx_hash));
    memset(tx_data, 0x22, sizeof(tx_data));
    return nodus_client_dnac_spend(c, tx_hash, tx_data, sizeof(tx_data),
                                   &g_sender_pk, &g_sender_sig, 1000,
                                   &g_result);
}

static void run_cases(nodus_client_t *c) {
    int rc;

    TEST("S1 {status: 0} -> rc 0, APPROVED");
    atomic_store(&g_fake.mode, REPLY_STATUS_APPROVED);
    rc = spend_once(c);
    if (rc == 0 && g_result.status == NODUS_DNAC_APPROVED &&
        g_result.timestamp == FAKE_TS) PASS();
    else FAIL("well-formed approval not decoded");

    TEST("S1b {status: 1} -> rc 0, REJECTED (status is read)");
    atomic_store(&g_fake.mode, REPLY_STATUS_REJECTED);
    rc = spend_once(c);
    if (rc == 0 && g_result.status == NODUS_DNAC_REJECTED) PASS();
    else FAIL("status value not taken from the reply");

    TEST("S2 reply without \"status\" -> NODUS_ERR_PROTOCOL_ERROR");
    atomic_store(&g_fake.mode, REPLY_NO_STATUS);
    rc = spend_once(c);
    if (rc == NODUS_ERR_PROTOCOL_ERROR) PASS();
    else FAIL("reply without status read as a result");

    TEST("S3 \"status\" as text -> NODUS_ERR_PROTOCOL_ERROR");
    atomic_store(&g_fake.mode, REPLY_STATUS_TEXT);
    rc = spend_once(c);
    if (rc == NODUS_ERR_PROTOCOL_ERROR) PASS();
    else FAIL("non-uint status read as a result");

    TEST("S4 error reply -> its error code (NODUS_ERR_DOUBLE_SPEND)");
    atomic_store(&g_fake.mode, REPLY_ERROR);
    rc = spend_once(c);
    if (rc == NODUS_ERR_DOUBLE_SPEND) PASS();
    else FAIL("error reply code not returned");
}

int main(void) {
    printf("=== Nodus client dnac_spend reply status tests ===\n");

    nodus_identity_t *client_id = calloc(1, sizeof(*client_id));
    if (!client_id || nodus_identity_generate(client_id) != 0) {
        printf("FATAL: client identity\n");
        return 1;
    }

    if (start_fake_server() != 0) {
        printf("FATAL: fake server did not start\n");
        return 1;
    }

    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) {
        printf("FATAL: alloc\n");
        return 1;
    }
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = g_fake.tcp->port;
    cfg.server_count = 1;
    cfg.connect_timeout_ms = 3000;

    if (nodus_client_init(c, &cfg, client_id) != 0) {
        printf("FATAL: client init\n");
        return 1;
    }
    if (nodus_client_connect(c) != 0 || !nodus_client_is_ready(c)) {
        printf("FATAL: client did not connect to the fake server\n");
        nodus_client_close(c);
        return 1;
    }

    run_cases(c);

    nodus_client_close(c);
    free(c);
    stop_fake_server();
    nodus_identity_clear(client_id);
    free(client_id);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
