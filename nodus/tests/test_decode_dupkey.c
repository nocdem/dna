/**
 * Nodus — duplicate-key refusal in the wire decoders (P0-A, 2026-09-28)
 *
 * What it proves:
 *   - nodus_t2_decode / nodus_t1_decode refuse (-1) a frame in which any
 *     map repeats a key: top level ("a"), "a" ("val", "d", "name"),
 *     "r" ("val", "vals", "batch"), and array-entry maps ("vs" inside a
 *     batch entry, "d" inside a posts entry). Before the fix every repeat
 *     re-ran an allocation over the previous one and leaked it — on the
 *     server this is pre-auth (nodus_server.c decodes before its auth gate).
 *   - A heap field reachable from two maps is written once per frame:
 *     "ks" in "a" + "batch" in "r", "counts" + "batch", "val" in "a" and
 *     in "r" are refused (the "ks"+"batch" pair used to leave
 *     batch_key_count describing a different allocation than batch_vals,
 *     and nodus_t2_msg_free then walked batch_vals past its end).
 *   - A map with more than NODUS_MAP_MAX_KEYS text keys is refused, so the
 *     duplicate check can never be outrun.
 *   - nodus_value_deserialize refuses a non-NULL *val_out (leaving it
 *     untouched), a repeated key, and any "type" outside {1,2,3} — 259
 *     signs as 3 (low byte) but would miss every EXCLUSIVE check — and
 *     nodus_value_create refuses the same types.
 *   - Well-formed frames from this tree's own encoders still decode
 *     (value_changed, result_get_batch, ch_posts, t1 sv / fv_r / fn_r).
 *
 * Leak coverage: every refused frame is decoded and freed
 * DUPKEY_ITERATIONS times; under ASan/LSan any allocation the refusal
 * path forgets is reported at exit. Without a sanitizer build the loop
 * only proves the return codes — it cannot see a leak.
 *
 * Requires: a default standalone nodus build; no environment.
 * Leaves behind: nothing (no files, no sockets).
 * How it can lie: the leak half of each case is silent without ASan/LSan;
 * the return-code half is not.
 */

#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_DUPKEY"

#define DUPKEY_ITERATIONS 64

static int passed = 0;
static int failed = 0;

#define CHECK(cond, name) do {                                          \
    if (cond) { passed++; }                                             \
    else { failed++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s (%s:%d): %s",      \
                                   (name), __FILE__, __LINE__, #cond); } \
} while (0)

static uint8_t g_frame[65536];

/* ── Fixtures ────────────────────────────────────────────────────── */

/* A serialized value of the given type. Built without a signature — no
 * decoder under test verifies one. Returns heap bytes (caller frees). */
static uint8_t *value_bytes(uint64_t type, const char *data, size_t *len_out) {
    nodus_value_t v;
    memset(&v, 0, sizeof(v));
    nodus_hash((const uint8_t *)"dupkey:key", 10, &v.key_hash);
    v.type = (nodus_value_type_t)type;
    v.ttl = 3600;
    v.value_id = 1;
    v.seq = 1;
    v.data = (uint8_t *)data;
    v.data_len = strlen(data);
    uint8_t *out = NULL;
    if (nodus_value_serialize(&v, &out, len_out) != 0) return NULL;
    return out;
}

static nodus_value_t *value_obj(const char *data) {
    nodus_value_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    nodus_hash((const uint8_t *)"dupkey:key", 10, &v->key_hash);
    v->type = NODUS_VALUE_EPHEMERAL;
    v->ttl = 3600;
    v->value_id = 1;
    v->seq = 1;
    v->data_len = strlen(data);
    v->data = malloc(v->data_len);
    if (!v->data) { free(v); return NULL; }
    memcpy(v->data, data, v->data_len);
    return v;
}

static void frame_head(cbor_encoder_t *e, size_t top_count,
                       const char *y, const char *method) {
    cbor_encoder_init(e, g_frame, sizeof(g_frame));
    cbor_encode_map(e, top_count);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, 7);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, y);
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, method);
}

/* Decode a tier-2 frame DUPKEY_ITERATIONS times; every decode must return
 * `want`, and a refused frame must come back zeroed (heap fields NULL). */
static void t2_expect(const char *name, size_t len, int want) {
    int ok = 1;
    for (int i = 0; i < DUPKEY_ITERATIONS; i++) {
        nodus_tier2_msg_t msg;
        int rc = nodus_t2_decode(g_frame, len, &msg);
        if (rc != want) ok = 0;
        if (rc != 0 && (msg.value || msg.values || msg.data ||
                        msg.batch_keys || msg.batch_vals || msg.ch_posts ||
                        msg.ch_name || msg.pq_fps))
            ok = 0;
        nodus_t2_msg_free(&msg);
    }
    CHECK(ok, name);
}

static void t1_expect(const char *name, size_t len, int want) {
    int ok = 1;
    for (int i = 0; i < DUPKEY_ITERATIONS; i++) {
        nodus_tier1_msg_t msg;
        int rc = nodus_t1_decode(g_frame, len, &msg);
        if (rc != want) ok = 0;
        if (rc != 0 && msg.value) ok = 0;
        nodus_t1_msg_free(&msg);
    }
    CHECK(ok, name);
}

/* ── Tier 2: repeated keys ───────────────────────────────────────── */

static void test_t2_dup_val_in_args(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    cbor_encoder_t e;
    frame_head(&e, 4, "q", "value_changed");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    t2_expect("t2: repeated \"val\" in \"a\"", cbor_encoder_len(&e), -1);
    free(vb);
}

static void test_t2_dup_d_in_args(void) {
    cbor_encoder_t e;
    frame_head(&e, 4, "q", "put");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "d"); cbor_encode_bstr(&e, (const uint8_t *)"aaaa", 4);
    cbor_encode_cstr(&e, "d"); cbor_encode_bstr(&e, (const uint8_t *)"bbbb", 4);
    t2_expect("t2: repeated \"d\" in \"a\"", cbor_encoder_len(&e), -1);
}

static void test_t2_dup_name_in_args(void) {
    cbor_encoder_t e;
    frame_head(&e, 4, "q", "ch_create");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "name"); cbor_encode_cstr(&e, "one");
    cbor_encode_cstr(&e, "name"); cbor_encode_cstr(&e, "two");
    t2_expect("t2: repeated \"name\" in \"a\"", cbor_encoder_len(&e), -1);
}

static void test_t2_dup_top_level_a(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    cbor_encoder_t e;
    frame_head(&e, 5, "q", "value_changed");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    t2_expect("t2: repeated top-level \"a\"", cbor_encoder_len(&e), -1);
    free(vb);
}

static void test_t2_dup_val_in_result(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_PERMANENT, "v", &vlen);
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "result");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    t2_expect("t2: repeated \"val\" in \"r\"", cbor_encoder_len(&e), -1);
    free(vb);
}

static void test_t2_val_in_args_and_result(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_PERMANENT, "v", &vlen);
    cbor_encoder_t e;
    frame_head(&e, 5, "r", "result");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    t2_expect("t2: \"val\" in both \"a\" and \"r\"", cbor_encoder_len(&e), -1);
    free(vb);
}

static void test_t2_dup_vals(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "result");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "vals");
    cbor_encode_array(&e, 2);
    cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_cstr(&e, "vals");
    cbor_encode_array(&e, 1);
    cbor_encode_bstr(&e, vb, vlen);
    t2_expect("t2: repeated \"vals\" in \"r\"", cbor_encoder_len(&e), -1);
    free(vb);
}

static void enc_batch_entry(cbor_encoder_t *e, const nodus_key_t *k,
                            const uint8_t *vb, size_t vlen, int vs_times) {
    cbor_encode_map(e, (size_t)(1 + vs_times));
    cbor_encode_cstr(e, "k"); cbor_encode_bstr(e, k->bytes, NODUS_KEY_BYTES);
    for (int i = 0; i < vs_times; i++) {
        cbor_encode_cstr(e, "vs");
        cbor_encode_array(e, 1);
        cbor_encode_bstr(e, vb, vlen);
    }
}

static void test_t2_dup_batch(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    nodus_key_t k;
    nodus_hash((const uint8_t *)"bk", 2, &k);
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "get_batch");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "batch");
    cbor_encode_array(&e, 2);
    enc_batch_entry(&e, &k, vb, vlen, 1);
    enc_batch_entry(&e, &k, vb, vlen, 1);
    cbor_encode_cstr(&e, "batch");
    cbor_encode_array(&e, 1);
    enc_batch_entry(&e, &k, vb, vlen, 1);
    t2_expect("t2: repeated \"batch\" in \"r\"", cbor_encoder_len(&e), -1);
    free(vb);
}

/* The refusal lands INSIDE an entry whose "vs" array is already allocated;
 * that slot must still be freed (LSan half of the case). */
static void test_t2_dup_vs_in_batch_entry(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    nodus_key_t k;
    nodus_hash((const uint8_t *)"bk", 2, &k);
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "get_batch");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "batch");
    cbor_encode_array(&e, 1);
    enc_batch_entry(&e, &k, vb, vlen, 2);
    t2_expect("t2: repeated \"vs\" inside a batch entry",
              cbor_encoder_len(&e), -1);
    free(vb);
}

/* "ks" (args) and "batch" (results) both own batch_keys/batch_key_count:
 * 3 keys in "ks" against a 1-slot batch_vals used to make msg_free walk
 * batch_vals[1..2] past its allocation. Both orders are refused. */
static void test_t2_ks_and_batch(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    nodus_key_t k;
    nodus_hash((const uint8_t *)"bk", 2, &k);

    for (int order = 0; order < 2; order++) {
        cbor_encoder_t e;
        frame_head(&e, 5, "r", "get_batch");
        for (int part = 0; part < 2; part++) {
            if ((part == 0) == (order == 0)) {
                cbor_encode_cstr(&e, "r");
                cbor_encode_map(&e, 1);
                cbor_encode_cstr(&e, "batch");
                cbor_encode_array(&e, 1);
                enc_batch_entry(&e, &k, vb, vlen, 1);
            } else {
                cbor_encode_cstr(&e, "a");
                cbor_encode_map(&e, 1);
                cbor_encode_cstr(&e, "ks");
                cbor_encode_array(&e, 3);
                for (int j = 0; j < 3; j++)
                    cbor_encode_bstr(&e, k.bytes, NODUS_KEY_BYTES);
            }
        }
        t2_expect(order == 0 ? "t2: \"batch\" then \"ks\" (count desync)"
                             : "t2: \"ks\" then \"batch\" (count desync)",
                  cbor_encoder_len(&e), -1);
    }
    free(vb);
}

static void test_t2_counts_and_batch(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    nodus_key_t k;
    nodus_hash((const uint8_t *)"bk", 2, &k);
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "cnt_batch");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "counts");
    cbor_encode_array(&e, 3);
    for (int j = 0; j < 3; j++) {
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "k"); cbor_encode_bstr(&e, k.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&e, "c"); cbor_encode_uint(&e, 1);
    }
    cbor_encode_cstr(&e, "batch");
    cbor_encode_array(&e, 1);
    enc_batch_entry(&e, &k, vb, vlen, 1);
    t2_expect("t2: \"counts\" and \"batch\" in one \"r\"",
              cbor_encoder_len(&e), -1);
    free(vb);
}

static void test_t2_dup_d_in_post(void) {
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "ch_posts");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "posts");
    cbor_encode_array(&e, 1);
    cbor_encode_map(&e, 3);
    cbor_encode_cstr(&e, "ra"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "d"); cbor_encode_bstr(&e, (const uint8_t *)"one", 3);
    cbor_encode_cstr(&e, "d"); cbor_encode_bstr(&e, (const uint8_t *)"two", 3);
    t2_expect("t2: repeated \"d\" inside a posts entry",
              cbor_encoder_len(&e), -1);
}

static void test_t2_dup_posts(void) {
    cbor_encoder_t e;
    frame_head(&e, 4, "r", "ch_posts");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 2);
    for (int p = 0; p < 2; p++) {
        cbor_encode_cstr(&e, "posts");
        cbor_encode_array(&e, 1);
        cbor_encode_map(&e, 1);
        cbor_encode_cstr(&e, "d"); cbor_encode_bstr(&e, (const uint8_t *)"x", 1);
    }
    t2_expect("t2: repeated \"posts\" in \"r\"", cbor_encoder_len(&e), -1);
}

/* NODUS_MAP_MAX_KEYS distinct keys are accepted; one more is refused. */
static void test_t2_key_cap(void) {
    for (int extra = 0; extra < 2; extra++) {
        size_t n = NODUS_MAP_MAX_KEYS + (size_t)extra;
        cbor_encoder_t e;
        frame_head(&e, 4, "q", "unknown_method");
        cbor_encode_cstr(&e, "a");
        cbor_encode_map(&e, n);
        for (size_t j = 0; j < n; j++) {
            char name[16];
            snprintf(name, sizeof(name), "x%zu", j);
            cbor_encode_cstr(&e, name);
            cbor_encode_uint(&e, j);
        }
        t2_expect(extra == 0 ? "t2: NODUS_MAP_MAX_KEYS distinct keys accepted"
                             : "t2: NODUS_MAP_MAX_KEYS+1 keys refused",
                  cbor_encoder_len(&e), extra == 0 ? 0 : -1);
    }
}

/* ── Tier 2: honest frames still decode ──────────────────────────── */

static void test_t2_wellformed(void) {
    nodus_value_t *v0 = value_obj("zero");
    nodus_value_t *v1 = value_obj("one");
    nodus_key_t keys[2];
    nodus_hash((const uint8_t *)"wk0", 3, &keys[0]);
    nodus_hash((const uint8_t *)"wk1", 3, &keys[1]);
    size_t len = 0;

    int rc = nodus_t2_value_changed(9, &keys[0], v0, g_frame, sizeof(g_frame), &len);
    nodus_tier2_msg_t msg;
    int drc = rc == 0 ? nodus_t2_decode(g_frame, len, &msg) : -1;
    CHECK(drc == 0 && msg.value && msg.value->data_len == 4 &&
          memcmp(msg.value->data, "zero", 4) == 0,
          "t2: value_changed round-trip");
    if (drc == 0) nodus_t2_msg_free(&msg);

    nodus_value_t *k0v[] = { v0, v1 };
    nodus_value_t *k1v[] = { v1 };
    nodus_value_t **per_key[] = { k0v, k1v };
    size_t counts[] = { 2, 1 };
    rc = nodus_t2_result_get_batch(10, keys, 2, per_key, counts,
                                   g_frame, sizeof(g_frame), &len);
    drc = rc == 0 ? nodus_t2_decode(g_frame, len, &msg) : -1;
    CHECK(drc == 0 && msg.batch_key_count == 2 &&
          msg.batch_val_counts[0] == 2 && msg.batch_val_counts[1] == 1 &&
          nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0,
          "t2: result_get_batch round-trip");
    if (drc == 0) nodus_t2_msg_free(&msg);

    static char body0[] = "first";
    static char body1[] = "second";
    nodus_channel_post_t posts[2];
    memset(posts, 0, sizeof(posts));
    posts[0].received_at = 1; posts[0].body = body0; posts[0].body_len = 5;
    posts[1].received_at = 2; posts[1].body = body1; posts[1].body_len = 6;
    rc = nodus_t2_ch_posts(11, posts, 2, g_frame, sizeof(g_frame), &len);
    drc = rc == 0 ? nodus_t2_decode(g_frame, len, &msg) : -1;
    CHECK(drc == 0 && msg.ch_post_count == 2 &&
          msg.ch_posts[1].body_len == 6 &&
          memcmp(msg.ch_posts[1].body, "second", 6) == 0,
          "t2: ch_posts round-trip");
    if (drc == 0) nodus_t2_msg_free(&msg);

    nodus_value_free(v0);
    nodus_value_free(v1);
}

/* ── Tier 1 ──────────────────────────────────────────────────────── */

static void test_t1_dup_val(void) {
    size_t vlen = 0;
    uint8_t *vb = value_bytes(NODUS_VALUE_EPHEMERAL, "v", &vlen);
    const char *where[2] = { "a", "r" };
    for (int w = 0; w < 2; w++) {
        cbor_encoder_t e;
        frame_head(&e, 4, w == 0 ? "q" : "r", w == 0 ? "sv" : "fv_r");
        cbor_encode_cstr(&e, where[w]);
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
        cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
        t1_expect(w == 0 ? "t1: repeated \"val\" in \"a\""
                         : "t1: repeated \"val\" in \"r\"",
                  cbor_encoder_len(&e), -1);
    }

    cbor_encoder_t e;
    frame_head(&e, 5, "q", "ntf");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    t1_expect("t1: \"val\" in both \"a\" and \"r\"", cbor_encoder_len(&e), -1);

    frame_head(&e, 5, "q", "sv");
    for (int r = 0; r < 2; r++) {
        cbor_encode_cstr(&e, "a");
        cbor_encode_map(&e, 1);
        cbor_encode_cstr(&e, "val"); cbor_encode_bstr(&e, vb, vlen);
    }
    t1_expect("t1: repeated top-level \"a\"", cbor_encoder_len(&e), -1);
    free(vb);
}

static void test_t1_target_and_k(void) {
    nodus_key_t k;
    nodus_hash((const uint8_t *)"t1", 2, &k);
    cbor_encoder_t e;
    frame_head(&e, 4, "q", "fv");
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "target"); cbor_encode_bstr(&e, k.bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&e, "k");      cbor_encode_bstr(&e, k.bytes, NODUS_KEY_BYTES);
    t1_expect("t1: \"target\" and \"k\" (one field) refused",
              cbor_encoder_len(&e), -1);
}

static void test_t1_wellformed(void) {
    nodus_value_t *v = value_obj("hello");
    size_t len = 0;
    nodus_tier1_msg_t msg;

    int rc = nodus_t1_store_value(3, v, g_frame, sizeof(g_frame), &len);
    int drc = rc == 0 ? nodus_t1_decode(g_frame, len, &msg) : -1;
    CHECK(drc == 0 && msg.has_value && msg.value->data_len == 5,
          "t1: store_value round-trip");
    if (drc == 0) nodus_t1_msg_free(&msg);

    rc = nodus_t1_value_found(4, v, g_frame, sizeof(g_frame), &len);
    drc = rc == 0 ? nodus_t1_decode(g_frame, len, &msg) : -1;
    CHECK(drc == 0 && msg.has_value, "t1: value_found round-trip");
    if (drc == 0) nodus_t1_msg_free(&msg);

    nodus_peer_t peers[2];
    memset(peers, 0, sizeof(peers));
    snprintf(peers[0].ip, sizeof(peers[0].ip), "10.0.0.1");
    snprintf(peers[1].ip, sizeof(peers[1].ip), "10.0.0.2");
    peers[1].udp_port = 4000;
    rc = nodus_t1_nodes_found(5, peers, 2, g_frame, sizeof(g_frame), &len);
    drc = rc == 0 ? nodus_t1_decode(g_frame, len, &msg) : -1;
    CHECK(drc == 0 && msg.peer_count == 2 && msg.peers[1].udp_port == 4000,
          "t1: nodes_found round-trip");
    if (drc == 0) nodus_t1_msg_free(&msg);

    nodus_value_free(v);
}

/* ── nodus_value ─────────────────────────────────────────────────── */

static void test_value_type_set(void) {
    for (uint64_t t = 1; t <= 3; t++) {
        size_t len = 0;
        uint8_t *b = value_bytes(t, "ok", &len);
        nodus_value_t *out = NULL;
        int rc = b ? nodus_value_deserialize(b, len, &out) : -1;
        CHECK(rc == 0 && out && (uint64_t)out->type == t,
              "value: types 1/2/3 decode");
        nodus_value_free(out);
        free(b);
    }

    const uint64_t bad[] = { 0, 4, 259, 0x100000003ULL };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        /* serialize writes (uint64_t)val->type — encode the wide value
         * directly instead, so 0x100000003 reaches the wire intact. */
        cbor_encoder_t e;
        cbor_encoder_init(&e, g_frame, sizeof(g_frame));
        cbor_encode_map(&e, 3);
        cbor_encode_cstr(&e, "type"); cbor_encode_uint(&e, bad[i]);
        cbor_encode_cstr(&e, "ttl");  cbor_encode_uint(&e, 60);
        cbor_encode_cstr(&e, "data"); cbor_encode_bstr(&e, (const uint8_t *)"x", 1);
        nodus_value_t *out = NULL;
        int rc = nodus_value_deserialize(g_frame, cbor_encoder_len(&e), &out);
        CHECK(rc == -1 && out == NULL, "value: type outside {1,2,3} refused");
    }

    nodus_key_t k;
    nodus_pubkey_t pk;
    memset(&pk, 0x5A, sizeof(pk));
    nodus_hash((const uint8_t *)"create", 6, &k);
    nodus_value_t *made = NULL;
    CHECK(nodus_value_create(&k, (const uint8_t *)"x", 1,
                             (nodus_value_type_t)259, 60, 1, 1, &pk, &made) == -1 &&
          made == NULL, "value: create refuses type 259");
    CHECK(nodus_value_create(&k, (const uint8_t *)"x", 1,
                             (nodus_value_type_t)0, 60, 1, 1, &pk, &made) == -1 &&
          made == NULL, "value: create refuses type 0");
}

static void test_value_into_nonnull(void) {
    size_t len = 0;
    uint8_t *b = value_bytes(NODUS_VALUE_EPHEMERAL, "keep", &len);
    nodus_value_t *first = NULL;
    int rc = b ? nodus_value_deserialize(b, len, &first) : -1;
    nodus_value_t *held = first;
    int rc2 = b ? nodus_value_deserialize(b, len, &first) : 0;
    CHECK(rc == 0 && rc2 == -1 && first == held,
          "value: deserialize into non-NULL refused, pointer untouched");
    nodus_value_free(first);
    free(b);
}

static void test_value_dup_key(void) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 3);
    cbor_encode_cstr(&e, "type"); cbor_encode_uint(&e, NODUS_VALUE_EPHEMERAL);
    cbor_encode_cstr(&e, "data"); cbor_encode_bstr(&e, (const uint8_t *)"one", 3);
    cbor_encode_cstr(&e, "data"); cbor_encode_bstr(&e, (const uint8_t *)"two", 3);
    int ok = 1;
    for (int i = 0; i < DUPKEY_ITERATIONS; i++) {
        nodus_value_t *out = NULL;
        if (nodus_value_deserialize(g_frame, cbor_encoder_len(&e), &out) != -1 ||
            out != NULL)
            ok = 0;
    }
    CHECK(ok, "value: repeated \"data\" refused");
}

int main(void) {
    QGP_LOG_INFO(LOG_TAG, "=== Nodus decoder duplicate-key tests ===");

    test_t2_dup_val_in_args();
    test_t2_dup_d_in_args();
    test_t2_dup_name_in_args();
    test_t2_dup_top_level_a();
    test_t2_dup_val_in_result();
    test_t2_val_in_args_and_result();
    test_t2_dup_vals();
    test_t2_dup_batch();
    test_t2_dup_vs_in_batch_entry();
    test_t2_ks_and_batch();
    test_t2_counts_and_batch();
    test_t2_dup_d_in_post();
    test_t2_dup_posts();
    test_t2_key_cap();
    test_t2_wellformed();

    test_t1_dup_val();
    test_t1_target_and_k();
    test_t1_wellformed();

    test_value_type_set();
    test_value_into_nonnull();
    test_value_dup_key();

    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===", passed, failed);
    return failed > 0 ? 1 : 0;
}
