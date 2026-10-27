/**
 * Nodus — Client SDK: strict GET / GET_ALL (Nodus Connect design rev 5 §6.4 F1)
 *
 * The tier-2 decoder ignores nodus_value_deserialize's result, so a reply
 * whose "val" does not decode reaches the client as "no value", and
 * nodus_client_get answers NODUS_ERR_NOT_FOUND — the same answer as an
 * empty reply. nodus_client_get_strict / nodus_client_get_all_strict
 * (nodus/src/client/nodus_client_strict.h) re-read the raw reply and report
 * what the node sent.
 *
 * The REAL client runs against a fake server built the way
 * test_client_spend_status.c builds its fake (nodus_tcp_t + nodus_t2_*
 * encoders, plain auth_ok, unencrypted session). The fake answers "get" and
 * "get_all" with a reply shape chosen per case.
 *
 * What it proves:
 *   P1-P5 nodus_client_reply_value_shape over hand-built frames: no "r",
 *         empty "r", "val" bstr, "val" of another type, "vals" with mixed
 *         item types — counts and flags as documented; a non-map frame -> -1.
 *   G1  empty result          lenient NOT_FOUND, strict NOT_FOUND.
 *   G2  valid "val"           lenient 0, strict 0, same value bytes.
 *   G3  "val" = junk bytes    lenient NOT_FOUND (the F1 premise, behaviour
 *                             of the existing call is unchanged), strict
 *                             NODUS_ERR_PROTOCOL_ERROR.
 *   G4  "val" = a uint        lenient NOT_FOUND, strict PROTOCOL_ERROR.
 *   G5  error reply           both return the node's code.
 *   A1  "vals" = [good, junk, uint]
 *                             lenient: rc 0, 1 value (unchanged);
 *                             strict:  rc 0, 1 value, undecodable 2.
 *   A2  empty result          strict: rc 0, 0 values, undecodable 0.
 *
 * RED without the change: the strict functions do not exist (link error);
 * with them but without the raw-reply check, G3/G4 return NOT_FOUND and A1
 * reports undecodable 0.
 *
 * What it requires: default standalone nodus build; no environment.
 * Ports: the fake listens on 127.0.0.1:0 (kernel-chosen); no fixed port.
 * What it leaves behind: nothing (fake thread joined, client closed).
 *
 * How it can lie:
 *   - The replies are hand-built: they prove the client's classification,
 *     not that a real node ever sends an undecodable value (an honest node
 *     serialises what it stored; the case covers a faulty or hostile node).
 *   - A fake that never answers makes the call time out (NODUS_ERR_TIMEOUT);
 *     every case asserts its exact code, so that shows as FAIL, never PASS.
 */

#include "nodus/nodus.h"
#include "client/nodus_client_strict.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
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

typedef enum {
    MODE_EMPTY = 0,      /* "r": {}                               */
    MODE_VAL_OK,         /* "r": {"val": <serialized value>}      */
    MODE_VAL_JUNK,       /* "r": {"val": h'deadbeef'}             */
    MODE_VAL_UINT,       /* "r": {"val": 7}                       */
    MODE_ERROR,          /* 'e' reply, NODUS_ERR_RATE_LIMITED     */
    MODE_VALS_MIXED      /* "r": {"vals": [good, junk, 7]}        */
} reply_mode_t;

typedef struct {
    nodus_tcp_t  *tcp;
    _Atomic int   mode;
    _Atomic bool  stop;
    pthread_t     tid;
    uint8_t      *buf;
} fake_server_t;

#define FAKE_BUF_SIZE 65536

static fake_server_t g_fake;
static uint8_t  *g_good_val;         /* serialized valid value */
static size_t    g_good_len;

static const uint8_t JUNK[4] = { 0xde, 0xad, 0xbe, 0xef };

/* Same header layout as nodus_tier2.c enc_response_header (static there). */
static void fake_resp_header(cbor_encoder_t *enc, uint32_t txn) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, "result");
}

static void fake_send_result(nodus_tcp_conn_t *conn, uint32_t txn) {
    int mode = atomic_load(&g_fake.mode);
    size_t len = 0;

    if (mode == MODE_ERROR) {
        if (nodus_t2_error(txn, NODUS_ERR_RATE_LIMITED, "slow down",
                           g_fake.buf, FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(conn, g_fake.buf, len);
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_fake.buf, FAKE_BUF_SIZE);
    fake_resp_header(&enc, txn);
    cbor_encode_cstr(&enc, "r");
    switch (mode) {
    case MODE_EMPTY:
        cbor_encode_map(&enc, 0);
        break;
    case MODE_VAL_OK:
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "val");
        cbor_encode_bstr(&enc, g_good_val, g_good_len);
        break;
    case MODE_VAL_JUNK:
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "val");
        cbor_encode_bstr(&enc, JUNK, sizeof(JUNK));
        break;
    case MODE_VAL_UINT:
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "val");
        cbor_encode_uint(&enc, 7);
        break;
    case MODE_VALS_MIXED:
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "vals");
        cbor_encode_array(&enc, 3);
        cbor_encode_bstr(&enc, g_good_val, g_good_len);
        cbor_encode_bstr(&enc, JUNK, sizeof(JUNK));
        cbor_encode_uint(&enc, 7);
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
        uint8_t token[NODUS_SESSION_TOKEN_LEN];
        memset(token, 0x5a, sizeof(token));
        if (nodus_t2_auth_ok(msg.txn_id, token,
                              g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "get") == 0 ||
               strcmp(msg.method, "get_all") == 0) {
        fake_send_result(conn, msg.txn_id);
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
    atomic_store(&g_fake.mode, MODE_EMPTY);
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

/* ── Pure shape checks ─────────────────────────────────────────────── */

static uint8_t g_frame[4096];

static size_t frame_for(int mode, bool with_r) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_frame, sizeof(g_frame));
    if (!with_r) {
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 1);
        cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
        cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "result");
        return cbor_encoder_len(&enc);
    }
    fake_resp_header(&enc, 1);
    cbor_encode_cstr(&enc, "r");
    switch (mode) {
    case MODE_EMPTY:    cbor_encode_map(&enc, 0); break;
    case MODE_VAL_JUNK: cbor_encode_map(&enc, 1);
                        cbor_encode_cstr(&enc, "val");
                        cbor_encode_bstr(&enc, JUNK, sizeof(JUNK)); break;
    case MODE_VAL_UINT: cbor_encode_map(&enc, 1);
                        cbor_encode_cstr(&enc, "val");
                        cbor_encode_uint(&enc, 7); break;
    case MODE_VALS_MIXED:
                        cbor_encode_map(&enc, 1);
                        cbor_encode_cstr(&enc, "vals");
                        cbor_encode_array(&enc, 3);
                        cbor_encode_bstr(&enc, JUNK, sizeof(JUNK));
                        cbor_encode_bstr(&enc, JUNK, sizeof(JUNK));
                        cbor_encode_map(&enc, 1);
                        cbor_encode_cstr(&enc, "x");
                        cbor_encode_uint(&enc, 1); break;
    default: break;
    }
    return enc.error ? 0 : cbor_encoder_len(&enc);
}

static void run_shape_cases(void) {
    nodus_reply_value_shape_t s;
    size_t n;

    TEST("P1 frame without \"r\" -> 0, has_r false");
    n = frame_for(MODE_EMPTY, false);
    if (nodus_client_reply_value_shape(g_frame, n, &s) == 0 && !s.has_r &&
        !s.has_val && !s.has_vals) PASS();
    else FAIL("shape of a frame without r");

    TEST("P2 empty \"r\" -> has_r, no val, no vals");
    n = frame_for(MODE_EMPTY, true);
    if (nodus_client_reply_value_shape(g_frame, n, &s) == 0 && s.has_r &&
        !s.has_val && !s.has_vals) PASS();
    else FAIL("shape of an empty result");

    TEST("P3 \"val\" bstr -> has_val, val_is_bstr");
    n = frame_for(MODE_VAL_JUNK, true);
    if (nodus_client_reply_value_shape(g_frame, n, &s) == 0 && s.has_val &&
        s.val_is_bstr) PASS();
    else FAIL("shape of a bstr val");

    TEST("P4 \"val\" uint -> has_val, not bstr");
    n = frame_for(MODE_VAL_UINT, true);
    if (nodus_client_reply_value_shape(g_frame, n, &s) == 0 && s.has_val &&
        !s.val_is_bstr) PASS();
    else FAIL("shape of a uint val");

    TEST("P5 \"vals\" [bstr, bstr, map] -> total 3, bstr 2");
    n = frame_for(MODE_VALS_MIXED, true);
    if (nodus_client_reply_value_shape(g_frame, n, &s) == 0 && s.has_vals &&
        s.vals_total == 3 && s.vals_bstr == 2) PASS();
    else FAIL("shape of a mixed vals array");

    TEST("P6 non-map bytes -> -1");
    {
        const uint8_t not_map[2] = { 0x01, 0x02 };
        if (nodus_client_reply_value_shape(not_map, sizeof(not_map), &s) == -1) PASS();
        else FAIL("non-map frame accepted");
    }
}

/* ── Client cases ──────────────────────────────────────────────────── */

static void run_client_cases(nodus_client_t *c) {
    nodus_key_t key;
    memset(key.bytes, 0x42, sizeof(key.bytes));
    nodus_value_t *v = NULL;
    int rc_l, rc_s;

    TEST("G1 empty result: lenient NOT_FOUND, strict NOT_FOUND");
    atomic_store(&g_fake.mode, MODE_EMPTY);
    rc_l = nodus_client_get(c, &key, &v);
    rc_s = nodus_client_get_strict(c, &key, &v);
    if (rc_l == NODUS_ERR_NOT_FOUND && rc_s == NODUS_ERR_NOT_FOUND && !v) PASS();
    else FAIL("empty result classification");

    TEST("G2 valid val: both 0, value decoded");
    atomic_store(&g_fake.mode, MODE_VAL_OK);
    rc_s = nodus_client_get_strict(c, &key, &v);
    {
        bool ok = (rc_s == 0 && v && v->data_len == 5 &&
                   memcmp(v->data, "hello", 5) == 0);
        nodus_value_free(v); v = NULL;
        rc_l = nodus_client_get(c, &key, &v);
        ok = ok && rc_l == 0 && v;
        nodus_value_free(v); v = NULL;
        if (ok) PASS(); else FAIL("valid value not returned");
    }

    TEST("G3 junk val: lenient NOT_FOUND (unchanged), strict PROTOCOL_ERROR");
    atomic_store(&g_fake.mode, MODE_VAL_JUNK);
    rc_l = nodus_client_get(c, &key, &v);
    rc_s = nodus_client_get_strict(c, &key, &v);
    if (rc_l == NODUS_ERR_NOT_FOUND && rc_s == NODUS_ERR_PROTOCOL_ERROR && !v) PASS();
    else FAIL("undecodable val read as absent by the strict call");

    TEST("G4 uint val: lenient NOT_FOUND, strict PROTOCOL_ERROR");
    atomic_store(&g_fake.mode, MODE_VAL_UINT);
    rc_l = nodus_client_get(c, &key, &v);
    rc_s = nodus_client_get_strict(c, &key, &v);
    if (rc_l == NODUS_ERR_NOT_FOUND && rc_s == NODUS_ERR_PROTOCOL_ERROR && !v) PASS();
    else FAIL("non-bstr val read as absent by the strict call");

    TEST("G5 error reply: both return the node's code");
    atomic_store(&g_fake.mode, MODE_ERROR);
    rc_l = nodus_client_get(c, &key, &v);
    rc_s = nodus_client_get_strict(c, &key, &v);
    if (rc_l == NODUS_ERR_RATE_LIMITED && rc_s == NODUS_ERR_RATE_LIMITED) PASS();
    else FAIL("error code not returned");

    TEST("A1 vals [good, junk, uint]: lenient 1 value; strict 1 + undecodable 2");
    atomic_store(&g_fake.mode, MODE_VALS_MIXED);
    {
        nodus_value_t **vals = NULL;
        size_t count = 0, bad = 99;
        rc_l = nodus_client_get_all(c, &key, &vals, &count);
        bool ok = (rc_l == 0 && count == 1);
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals); vals = NULL; count = 0;
        rc_s = nodus_client_get_all_strict(c, &key, &vals, &count, &bad);
        ok = ok && rc_s == 0 && count == 1 && bad == 2;
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        if (ok) PASS(); else FAIL("undecodable get_all items not counted");
    }

    TEST("A2 empty result: strict rc 0, 0 values, undecodable 0");
    atomic_store(&g_fake.mode, MODE_EMPTY);
    {
        nodus_value_t **vals = NULL;
        size_t count = 7, bad = 7;
        rc_s = nodus_client_get_all_strict(c, &key, &vals, &count, &bad);
        if (rc_s == 0 && count == 0 && bad == 0 && !vals) PASS();
        else FAIL("empty get_all misreported");
    }
}

int main(void) {
    printf("=== Nodus client strict GET / GET_ALL tests ===\n");

    run_shape_cases();

    nodus_identity_t *client_id = calloc(1, sizeof(*client_id));
    nodus_identity_t *writer = calloc(1, sizeof(*writer));
    if (!client_id || !writer || nodus_identity_generate(client_id) != 0 ||
        nodus_identity_generate(writer) != 0) {
        printf("FATAL: identities\n");
        return 1;
    }

    /* A correctly signed value to serve as the "good" item. */
    {
        nodus_key_t key;
        memset(key.bytes, 0x42, sizeof(key.bytes));
        nodus_value_t *val = NULL;
        if (nodus_value_create(&key, (const uint8_t *)"hello", 5,
                               NODUS_VALUE_EPHEMERAL, 3600, 1, 1,
                               &writer->pk, &val) != 0 ||
            nodus_value_sign(val, &writer->sk) != 0 ||
            nodus_value_serialize(val, &g_good_val, &g_good_len) != 0) {
            printf("FATAL: good value\n");
            return 1;
        }
        nodus_value_free(val);
    }

    if (start_fake_server() != 0) {
        printf("FATAL: fake server did not start\n");
        return 1;
    }

    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) { printf("FATAL: alloc\n"); return 1; }
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

    run_client_cases(c);

    nodus_client_close(c);
    free(c);
    stop_fake_server();
    free(g_good_val);
    nodus_identity_clear(client_id);
    nodus_identity_clear(writer);
    free(client_id);
    free(writer);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
