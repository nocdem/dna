/**
 * Nodus — DHT Package A wire: owner filter ("own") and opt-in paging
 * ("pg", "after" / "more", "next") on get, get_all, get_batch.
 *
 * Pins down:
 *   1. Without options every encoder emits the PRE-Package-A frame byte
 *      for byte (the legacy frame — query and get_batch reply — is rebuilt
 *      here with the raw CBOR encoder, exactly as nodus_tier2.c wrote it
 *      before the change; never compared encoder against encoder).
 *   2. own / pg / after round-trip through nodus_t2_decode, including a
 *      value_id >= 2^63 (carried as raw uint64 bits).
 *   3. The paged replies (result_page, result_get_batch_ex) round-trip
 *      "more" / "next"; "next" is absent when more == false.
 *   4. A malformed new key refuses the frame (decode -1); an unknown key
 *      is still skipped.
 *   5. Rev 2 item 15: the per-entry could-not-look marker "u" round-trips,
 *      is emitted only as true (an all-false array = the hand-built legacy
 *      reply, byte for byte), and a non-bool "u" refuses the frame.
 *   6. Rev 3 R-d: the per-entry "nx" (uint) round-trips, is written only
 *      beside more = true, is never written by result_page, and a
 *      non-uint "nx" refuses the frame.
 *
 * Requires: default build. Leaves behind: nothing (in-process).
 * RED on the tree before Package A: the _ex / _owner / result_page
 * encoders and the decoded fields do not exist. RED before rev 3: no "nx".
 */

#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static uint8_t buf_a[65536];
static uint8_t buf_b[65536];
static uint8_t buf_c[65536];
static uint8_t tok[NODUS_SESSION_TOKEN_LEN];

static nodus_identity_t id_a;

static void fill_key(nodus_key_t *k, uint8_t b) { memset(k->bytes, b, NODUS_KEY_BYTES); }

/* The pre-Package-A query frame: {t, y:"q", q:<m>, tok, a:{<akey>: ...}} */
static size_t legacy_query(uint8_t *buf, size_t cap, uint32_t txn, const char *method,
                           const char *akey, const nodus_key_t *keys, int nkeys) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, txn);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, method);
    cbor_encode_cstr(&enc, "tok"); cbor_encode_bstr(&enc, tok, NODUS_SESSION_TOKEN_LEN);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, akey);
    if (nkeys < 0) {
        cbor_encode_bstr(&enc, keys[0].bytes, NODUS_KEY_BYTES);
    } else {
        cbor_encode_array(&enc, (size_t)nkeys);
        for (int i = 0; i < nkeys; i++)
            cbor_encode_bstr(&enc, keys[i].bytes, NODUS_KEY_BYTES);
    }
    return cbor_encoder_len(&enc);
}

static nodus_value_t *mk_value(const nodus_key_t *key, uint64_t vid, uint64_t seq,
                               const char *data) {
    nodus_value_t *v = NULL;
    if (nodus_value_create(key, (const uint8_t *)data, strlen(data),
                           NODUS_VALUE_PERMANENT, 0, vid, seq, &id_a.pk, &v) != 0)
        return NULL;
    return v;
}

/* The pre-Package-A get_batch reply for two keys, the first carrying `v`:
 * {t, y:"r", q:"result", r:{batch:[{k, vs:[<v>]}, {k, vs:[]}]}}, written
 * with the raw CBOR encoder exactly as nodus_tier2.c wrote it before the
 * change (main 4d943bc3). Returns 0 if `v` does not serialize. */
static size_t legacy_batch_reply(uint8_t *buf, size_t cap, uint32_t txn,
                                 const nodus_key_t keys[2], const nodus_value_t *v) {
    uint8_t *vbuf = NULL;
    size_t vlen = 0;
    if (nodus_value_serialize(v, &vbuf, &vlen) != 0) return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, txn);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "result");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "batch");
    cbor_encode_array(&enc, 2);
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "k"); cbor_encode_bstr(&enc, keys[0].bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "vs");
    cbor_encode_array(&enc, 1);
    cbor_encode_bstr(&enc, vbuf, vlen);
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "k"); cbor_encode_bstr(&enc, keys[1].bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "vs");
    cbor_encode_array(&enc, 0);
    free(vbuf);
    return cbor_encoder_len(&enc);
}

static void test_legacy_bytes_unchanged(void) {
    TEST("no options = pre-Package-A frames, byte for byte");
    nodus_key_t keys[2];
    fill_key(&keys[0], 0x11);
    fill_key(&keys[1], 0x22);
    size_t la = 0, lb = 0;

    lb = legacy_query(buf_b, sizeof(buf_b), 7, "get", "k", keys, -1);
    CHECK(nodus_t2_get(7, tok, &keys[0], buf_a, sizeof(buf_a), &la) == 0, "get enc");
    CHECK(la == lb && memcmp(buf_a, buf_b, la) == 0, "get bytes differ");
    CHECK(nodus_t2_get_owner(7, tok, &keys[0], NULL, buf_a, sizeof(buf_a), &la) == 0,
          "get_owner enc");
    CHECK(la == lb && memcmp(buf_a, buf_b, la) == 0, "get_owner(NULL) bytes differ");

    lb = legacy_query(buf_b, sizeof(buf_b), 8, "get_all", "k", keys, -1);
    CHECK(nodus_t2_get_all(8, tok, &keys[0], buf_a, sizeof(buf_a), &la) == 0, "get_all enc");
    CHECK(la == lb && memcmp(buf_a, buf_b, la) == 0, "get_all bytes differ");
    nodus_t2_read_opts_t none = { .own = NULL, .page = false, .after = NULL };
    CHECK(nodus_t2_get_all_ex(8, tok, &keys[0], &none, buf_a, sizeof(buf_a), &la) == 0,
          "get_all_ex enc");
    CHECK(la == lb && memcmp(buf_a, buf_b, la) == 0, "get_all_ex(unset) bytes differ");

    lb = legacy_query(buf_b, sizeof(buf_b), 9, "get_batch", "ks", keys, 2);
    CHECK(nodus_t2_get_batch(9, tok, keys, 2, buf_a, sizeof(buf_a), &la) == 0, "get_batch enc");
    CHECK(la == lb && memcmp(buf_a, buf_b, la) == 0, "get_batch bytes differ");
    CHECK(nodus_t2_get_batch_ex(9, tok, keys, 2, NULL, buf_a, sizeof(buf_a), &la) == 0,
          "get_batch_ex enc");
    CHECK(la == lb && memcmp(buf_a, buf_b, la) == 0, "get_batch_ex(NULL) bytes differ");

    {
        nodus_value_t *v = mk_value(&keys[0], 1, 1, "x");
        CHECK(v != NULL, "value");
        nodus_value_t *row[1] = { v };
        nodus_value_t **vpk[2] = { row, NULL };
        size_t cnt[2] = { 1, 0 };
        /* nodus_t2_result_get_batch now delegates to _ex, so comparing the
         * two proves nothing; the oracle is the legacy reply rebuilt here. */
        size_t lo = legacy_batch_reply(buf_c, sizeof(buf_c), 3, keys, v);
        size_t l1 = 0, l2 = 0, l3 = 0;
        int r1 = nodus_t2_result_get_batch(3, keys, 2, vpk, cnt, buf_a, sizeof(buf_a), &l1);
        int r2 = nodus_t2_result_get_batch_ex(3, keys, 2, vpk, cnt, NULL, NULL,
                                               buf_b, sizeof(buf_b), &l2);
        CHECK(lo > 0, "legacy batch oracle");
        CHECK(r1 == 0 && r2 == 0, "result_get_batch enc");
        CHECK(l1 == lo && memcmp(buf_a, buf_c, lo) == 0, "result_get_batch bytes differ");
        CHECK(l2 == lo && memcmp(buf_b, buf_c, lo) == 0,
              "result_get_batch_ex(NULL) bytes differ");
        /* rev 2 item 15: an all-false "u" array is the legacy frame too */
        bool no_u[2] = { false, false };
        int r3 = nodus_t2_result_get_batch_ex(3, keys, 2, vpk, cnt, NULL, no_u,
                                               buf_a, sizeof(buf_a), &l3);
        nodus_value_free(v);
        CHECK(r3 == 0, "result_get_batch_ex(all u false) enc");
        CHECK(l3 == lo && memcmp(buf_a, buf_c, lo) == 0,
              "result_get_batch_ex(all u false) bytes differ");
    }
    PASS();
out:
    return;
}

static void test_request_args_roundtrip(void) {
    TEST("own / pg / after round-trip (value_id >= 2^63)");
    nodus_key_t key, own;
    fill_key(&key, 0x33);
    fill_key(&own, 0x44);
    nodus_t2_cursor_t after;
    fill_key(&after.owner, 0x55);
    after.vid = 0x8000000000000001ULL;
    nodus_t2_read_opts_t opts = { .own = &own, .page = true, .after = &after };
    size_t len = 0;
    nodus_tier2_msg_t m;

    CHECK(nodus_t2_get_all_ex(1, tok, &key, &opts, buf_a, sizeof(buf_a), &len) == 0, "enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "decode");
    CHECK(strcmp(m.method, "get_all") == 0, "method");
    CHECK(nodus_key_cmp(&m.key, &key) == 0, "key");
    CHECK(m.has_own && nodus_key_cmp(&m.own_fp, &own) == 0, "own");
    CHECK(m.page, "pg");
    CHECK(m.has_after && nodus_key_cmp(&m.after.owner, &after.owner) == 0 &&
          m.after.vid == after.vid, "after");
    nodus_t2_msg_free(&m);

    CHECK(nodus_t2_get_owner(2, tok, &key, &own, buf_a, sizeof(buf_a), &len) == 0, "get enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "get decode");
    CHECK(strcmp(m.method, "get") == 0 && m.has_own &&
          nodus_key_cmp(&m.own_fp, &own) == 0 && !m.page && !m.has_after, "get own");
    nodus_t2_msg_free(&m);

    nodus_key_t keys[1] = { key };
    CHECK(nodus_t2_get_batch_ex(3, tok, keys, 1, &opts, buf_a, sizeof(buf_a), &len) == 0,
          "batch enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "batch decode");
    CHECK(m.batch_key_count == 1 && nodus_key_cmp(&m.batch_keys[0], &key) == 0, "batch keys");
    CHECK(m.has_own && m.page && m.has_after && m.after.vid == after.vid, "batch opts");
    nodus_t2_msg_free(&m);

    /* Legacy frame decodes with every new field unset. */
    CHECK(nodus_t2_get_all(4, tok, &key, buf_a, sizeof(buf_a), &len) == 0, "legacy enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "legacy decode");
    CHECK(!m.has_own && !m.page && !m.has_after && !m.has_more && !m.has_next, "legacy unset");
    nodus_t2_msg_free(&m);
    PASS();
out:
    return;
}

static void test_result_page_roundtrip(void) {
    TEST("result_page: vals + more + next round-trip");
    nodus_key_t key;
    fill_key(&key, 0x66);
    nodus_value_t *v1 = mk_value(&key, 1, 10, "one");
    nodus_value_t *v2 = mk_value(&key, 0xFFFFFFFFFFFFFFFFULL, 11, "two");
    nodus_value_t *vals[2] = { v1, v2 };
    nodus_t2_page_info_t pg;
    memset(&pg, 0, sizeof(pg));
    size_t len = 0;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    CHECK(v1 && v2, "values");
    pg.more = true;
    pg.has_next = true;
    pg.next.owner = v2->owner_fp;
    pg.next.vid = v2->value_id;

    CHECK(nodus_t2_result_page(5, vals, 2, &pg, buf_a, sizeof(buf_a), &len) == 0, "enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "decode");
    CHECK(m.value_count == 2 && m.values && m.values[1]->value_id == v2->value_id, "vals");
    CHECK(m.has_more && m.more, "more");
    CHECK(m.has_next && m.next.vid == 0xFFFFFFFFFFFFFFFFULL &&
          nodus_key_cmp(&m.next.owner, &v2->owner_fp) == 0, "next");
    nodus_t2_msg_free(&m);

    /* more = false → no "next" on the wire even if the caller set one */
    pg.more = false;
    CHECK(nodus_t2_result_page(6, vals, 0, &pg, buf_a, sizeof(buf_a), &len) == 0, "enc2");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "decode2");
    CHECK(m.value_count == 0 && m.has_more && !m.more && !m.has_next, "empty page");
    nodus_t2_msg_free(&m);
    PASS();
out:
    nodus_value_free(v1);
    nodus_value_free(v2);
}

static void test_result_get_batch_pages(void) {
    TEST("result_get_batch_ex: per-key more / next round-trip");
    nodus_key_t keys[2];
    fill_key(&keys[0], 0x71);
    fill_key(&keys[1], 0x72);
    nodus_value_t *v = mk_value(&keys[0], 9, 1, "row");
    nodus_value_t *row[1] = { v };
    nodus_value_t **vpk[2] = { row, NULL };
    size_t cnt[2] = { 1, 0 };
    nodus_t2_page_info_t pages[2];
    memset(pages, 0, sizeof(pages));
    size_t len = 0;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    CHECK(v != NULL, "value");
    pages[0].more = true;
    pages[0].has_next = true;
    pages[0].next.owner = v->owner_fp;
    pages[0].next.vid = 9;

    CHECK(nodus_t2_result_get_batch_ex(4, keys, 2, vpk, cnt, pages, NULL,
                                        buf_a, sizeof(buf_a), &len) == 0, "enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "decode");
    CHECK(m.batch_key_count == 2 && m.batch_page, "entries");
    CHECK(m.batch_val_counts[0] == 1 && m.batch_val_counts[1] == 0, "counts");
    CHECK(m.batch_page[0].more && m.batch_page[0].has_next &&
          m.batch_page[0].next.vid == 9, "key0 page");
    CHECK(!m.batch_page[1].more && !m.batch_page[1].has_next, "key1 page");
    nodus_t2_msg_free(&m);

    /* Legacy batch reply: page info decodes as all-zero. */
    CHECK(nodus_t2_result_get_batch(4, keys, 2, vpk, cnt, buf_a, sizeof(buf_a), &len) == 0,
          "legacy enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "legacy decode");
    CHECK(m.batch_page && !m.batch_page[0].more && !m.batch_page[0].has_next, "legacy page");
    nodus_t2_msg_free(&m);
    PASS();
out:
    nodus_value_free(v);
}

/* Rev 2 item 15: per-entry could-not-look marker "u". */
static void test_result_get_batch_unavail(void) {
    TEST("result_get_batch_ex: per-key \"u\" round-trip; bad type refused");
    nodus_key_t keys[2];
    fill_key(&keys[0], 0x73);
    fill_key(&keys[1], 0x74);
    nodus_value_t *v = mk_value(&keys[1], 3, 1, "row");
    nodus_value_t *row[1] = { v };
    nodus_value_t **vpk[2] = { NULL, row };
    size_t cnt[2] = { 0, 1 };
    bool u[2] = { true, false };
    size_t len = 0;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    CHECK(v != NULL, "value");

    CHECK(nodus_t2_result_get_batch_ex(5, keys, 2, vpk, cnt, NULL, u,
                                        buf_a, sizeof(buf_a), &len) == 0, "enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "decode");
    CHECK(m.batch_key_count == 2 && m.batch_unavail, "entries");
    CHECK(m.batch_unavail[0] && !m.batch_unavail[1], "u flags");
    CHECK(m.batch_val_counts[0] == 0 && m.batch_val_counts[1] == 1, "counts");
    /* no "more" was added for an unpaged reply */
    CHECK(m.batch_page && !m.batch_page[0].more && !m.batch_page[1].more, "no page info");
    nodus_t2_msg_free(&m);

    /* {t, y:"r", q:"result", r:{batch:[{k, vs:[], u: 1}]}} — "u" as uint */
    {
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf_b, sizeof(buf_b));
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 6);
        cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
        cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "result");
        cbor_encode_cstr(&enc, "r");
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "batch");
        cbor_encode_array(&enc, 1);
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "k"); cbor_encode_bstr(&enc, keys[0].bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, "vs"); cbor_encode_array(&enc, 0);
        cbor_encode_cstr(&enc, "u"); cbor_encode_uint(&enc, 1);
        size_t bl = cbor_encoder_len(&enc);
        memset(&m, 0, sizeof(m));
        CHECK(nodus_t2_decode(buf_b, bl, &m) != 0, "non-bool u accepted");
        nodus_t2_msg_free(&m);
    }
    PASS();
out:
    nodus_value_free(v);
}

/* Rev 3 R-d: per-entry "nx". Emitted only beside more = true; round-trips
 * as a uint (value above 2^32 to catch narrowing); never written by
 * nodus_t2_result_page; a non-uint "nx" refuses the frame.
 * FAILS WITHOUT R-d: the encoder writes no "nx" (has_nx stays false) and
 * the decoder has no field to fill. */
static void test_result_get_batch_nx(void) {
    TEST("result_get_batch_ex: \"nx\" round-trip; only with more");
    nodus_key_t keys[2];
    fill_key(&keys[0], 0x75);
    fill_key(&keys[1], 0x76);
    nodus_value_t *v = mk_value(&keys[0], 4, 1, "row");
    nodus_value_t *row[1] = { v };
    nodus_value_t **vpk[2] = { row, NULL };
    size_t cnt[2] = { 1, 0 };
    nodus_t2_page_info_t pages[2];
    memset(pages, 0, sizeof(pages));
    size_t len = 0, len2 = 0;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    CHECK(v != NULL, "value");
    pages[0].more = true;
    pages[0].has_next = true;
    pages[0].next.owner = v->owner_fp;
    pages[0].next.vid = 4;
    pages[0].has_nx = true;
    pages[0].nx = 0x123456789ULL;
    pages[1].has_nx = true;          /* more = false: must not be sent */
    pages[1].nx = 5;

    CHECK(nodus_t2_result_get_batch_ex(7, keys, 2, vpk, cnt, pages, NULL,
                                        buf_a, sizeof(buf_a), &len) == 0, "enc");
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "decode");
    CHECK(m.batch_key_count == 2 && m.batch_page, "entries");
    CHECK(m.batch_page[0].more && m.batch_page[0].has_nx &&
          m.batch_page[0].nx == 0x123456789ULL, "nx lost");
    CHECK(!m.batch_page[1].more && !m.batch_page[1].has_nx, "nx sent without more");
    nodus_t2_msg_free(&m);

    /* result_page (client get_all) never carries nx: same bytes with or
     * without it set */
    CHECK(nodus_t2_result_page(8, row, 1, &pages[0], buf_b, sizeof(buf_b), &len) == 0,
          "page enc");
    pages[0].has_nx = false;
    CHECK(nodus_t2_result_page(8, row, 1, &pages[0], buf_c, sizeof(buf_c), &len2) == 0,
          "page enc2");
    CHECK(len == len2 && memcmp(buf_b, buf_c, len) == 0, "result_page wrote nx");

    /* {..., r:{batch:[{k, vs:[], more:true, nx: h'00'}]}} — "nx" as bstr */
    {
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf_b, sizeof(buf_b));
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 9);
        cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
        cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "result");
        cbor_encode_cstr(&enc, "r");
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "batch");
        cbor_encode_array(&enc, 1);
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "k"); cbor_encode_bstr(&enc, keys[0].bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, "vs"); cbor_encode_array(&enc, 0);
        cbor_encode_cstr(&enc, "more"); cbor_encode_bool(&enc, true);
        cbor_encode_cstr(&enc, "nx"); cbor_encode_bstr(&enc, keys[0].bytes, 1);
        size_t bl = cbor_encoder_len(&enc);
        memset(&m, 0, sizeof(m));
        CHECK(nodus_t2_decode(buf_b, bl, &m) != 0, "non-uint nx accepted");
        nodus_t2_msg_free(&m);
    }
    PASS();
out:
    nodus_value_free(v);
}

/* {t, y:"q", q:"get_all", a:{k:key, <name>: <one raw item>}} */
static size_t frame_with_arg(uint8_t *buf, size_t cap, const nodus_key_t *key,
                             const char *name, int kind) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "get_all");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "k"); cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, name);
    switch (kind) {
    case 0: cbor_encode_bstr(&enc, key->bytes, 32); break;          /* short own */
    case 1: cbor_encode_uint(&enc, 1); break;                       /* pg as uint */
    case 2: cbor_encode_map(&enc, 1);                               /* after w/o v */
            cbor_encode_cstr(&enc, "o");
            cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES); break;
    default: cbor_encode_uint(&enc, 5); break;                      /* unknown key */
    }
    return cbor_encoder_len(&enc);
}

static void test_malformed_refused(void) {
    TEST("malformed own / pg / after refused; unknown key skipped");
    nodus_key_t key;
    fill_key(&key, 0x7A);
    nodus_tier2_msg_t m;
    size_t len;

    len = frame_with_arg(buf_a, sizeof(buf_a), &key, "own", 0);
    CHECK(nodus_t2_decode(buf_a, len, &m) != 0, "32-byte own accepted");
    len = frame_with_arg(buf_a, sizeof(buf_a), &key, "pg", 1);
    CHECK(nodus_t2_decode(buf_a, len, &m) != 0, "uint pg accepted");
    len = frame_with_arg(buf_a, sizeof(buf_a), &key, "after", 2);
    CHECK(nodus_t2_decode(buf_a, len, &m) != 0, "after without v accepted");
    len = frame_with_arg(buf_a, sizeof(buf_a), &key, "zz", 3);
    CHECK(nodus_t2_decode(buf_a, len, &m) == 0, "unknown key refused");
    CHECK(nodus_key_cmp(&m.key, &key) == 0 && !m.has_own, "unknown key frame");
    nodus_t2_msg_free(&m);
    PASS();
out:
    return;
}

int main(void) {
    printf("=== DHT Package A wire: own / pg / after / more / next ===\n");
    uint8_t seed[32];
    memset(seed, 0x5A, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_a) != 0) {
        printf("FATAL: identity\n");
        return 1;
    }
    memset(tok, 0xA5, sizeof(tok));

    test_legacy_bytes_unchanged();
    test_request_args_roundtrip();
    test_result_page_roundtrip();
    test_result_get_batch_pages();
    test_result_get_batch_unavail();
    test_result_get_batch_nx();
    test_malformed_refused();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
