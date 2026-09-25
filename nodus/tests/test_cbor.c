/**
 * Nodus — CBOR Encoder/Decoder Tests
 */

#include "protocol/nodus_cbor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* ── Encoder tests ───────────────────────────────────────────────── */

static void test_encode_uint_small(void) {
    TEST("encode uint small (0-23)");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_uint(&enc, 0);
    cbor_encode_uint(&enc, 1);
    cbor_encode_uint(&enc, 23);

    size_t len = cbor_encoder_len(&enc);
    if (len == 3 && buf[0] == 0x00 && buf[1] == 0x01 && buf[2] == 0x17)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_uint_1byte(void) {
    TEST("encode uint 1-byte (24-255)");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_uint(&enc, 24);
    cbor_encode_uint(&enc, 255);

    size_t len = cbor_encoder_len(&enc);
    if (len == 4 && buf[0] == 0x18 && buf[1] == 24 &&
        buf[2] == 0x18 && buf[3] == 0xFF)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_uint_2byte(void) {
    TEST("encode uint 2-byte (256-65535)");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_uint(&enc, 1000);  /* 0x03E8 */

    size_t len = cbor_encoder_len(&enc);
    if (len == 3 && buf[0] == 0x19 && buf[1] == 0x03 && buf[2] == 0xE8)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_uint_4byte(void) {
    TEST("encode uint 4-byte");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_uint(&enc, 1000000);  /* 0x000F4240 */

    size_t len = cbor_encoder_len(&enc);
    if (len == 5 && buf[0] == 0x1A &&
        buf[1] == 0x00 && buf[2] == 0x0F && buf[3] == 0x42 && buf[4] == 0x40)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_uint_8byte(void) {
    TEST("encode uint 8-byte");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_uint(&enc, 0x0100000000ULL);

    size_t len = cbor_encoder_len(&enc);
    if (len == 9 && buf[0] == 0x1B)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_bstr(void) {
    TEST("encode byte string");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    cbor_encode_bstr(&enc, data, 4);

    size_t len = cbor_encoder_len(&enc);
    if (len == 5 && buf[0] == 0x44 &&
        buf[1] == 0xDE && buf[2] == 0xAD && buf[3] == 0xBE && buf[4] == 0xEF)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_tstr(void) {
    TEST("encode text string");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_cstr(&enc, "hello");

    size_t len = cbor_encoder_len(&enc);
    if (len == 6 && buf[0] == 0x65 && memcmp(buf + 1, "hello", 5) == 0)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_empty_bstr(void) {
    TEST("encode empty byte string");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_bstr(&enc, (const uint8_t *)"", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 1 && buf[0] == 0x40)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_map(void) {
    TEST("encode map {\"a\": 1, \"b\": 2}");
    uint8_t buf[64];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "b");
    cbor_encode_uint(&enc, 2);

    size_t len = cbor_encoder_len(&enc);
    /* A2 61 61 01 61 62 02 */
    if (len == 7 && buf[0] == 0xA2)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_array(void) {
    TEST("encode array [1, 2, 3]");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_array(&enc, 3);
    cbor_encode_uint(&enc, 1);
    cbor_encode_uint(&enc, 2);
    cbor_encode_uint(&enc, 3);

    size_t len = cbor_encoder_len(&enc);
    /* 83 01 02 03 */
    if (len == 4 && buf[0] == 0x83 && buf[1] == 1 && buf[2] == 2 && buf[3] == 3)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_bool(void) {
    TEST("encode booleans");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_bool(&enc, true);
    cbor_encode_bool(&enc, false);

    size_t len = cbor_encoder_len(&enc);
    if (len == 2 && buf[0] == 0xF5 && buf[1] == 0xF4)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_null(void) {
    TEST("encode null");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_null(&enc);

    size_t len = cbor_encoder_len(&enc);
    if (len == 1 && buf[0] == 0xF6)
        PASS();
    else
        FAIL("unexpected encoding");
}

static void test_encode_overflow(void) {
    TEST("encode overflow detection");
    uint8_t buf[2];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_cstr(&enc, "hello");  /* Needs 6 bytes, only 2 available */

    size_t len = cbor_encoder_len(&enc);
    if (len == 0)
        PASS();
    else
        FAIL("should return 0 on overflow");
}

/* ── Decoder tests ───────────────────────────────────────────────── */

static void test_decode_uint(void) {
    TEST("decode unsigned integers");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_uint(&enc, 42);
    cbor_encode_uint(&enc, 1000);
    cbor_encode_uint(&enc, 0x0100000000ULL);

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, cbor_encoder_len(&enc));

    cbor_item_t i1 = cbor_decode_next(&dec);
    cbor_item_t i2 = cbor_decode_next(&dec);
    cbor_item_t i3 = cbor_decode_next(&dec);

    if (i1.type == CBOR_ITEM_UINT && i1.uint_val == 42 &&
        i2.type == CBOR_ITEM_UINT && i2.uint_val == 1000 &&
        i3.type == CBOR_ITEM_UINT && i3.uint_val == 0x0100000000ULL)
        PASS();
    else
        FAIL("decoded values don't match");
}

static void test_decode_bstr(void) {
    TEST("decode byte string");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    uint8_t data[] = {0xCA, 0xFE};
    cbor_encode_bstr(&enc, data, 2);

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, cbor_encoder_len(&enc));

    cbor_item_t item = cbor_decode_next(&dec);
    if (item.type == CBOR_ITEM_BSTR && item.bstr.len == 2 &&
        item.bstr.ptr[0] == 0xCA && item.bstr.ptr[1] == 0xFE)
        PASS();
    else
        FAIL("decoded bstr doesn't match");
}

static void test_decode_tstr(void) {
    TEST("decode text string");
    uint8_t buf[32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_cstr(&enc, "nodus");

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, cbor_encoder_len(&enc));

    cbor_item_t item = cbor_decode_next(&dec);
    if (item.type == CBOR_ITEM_TSTR && item.tstr.len == 5 &&
        memcmp(item.tstr.ptr, "nodus", 5) == 0)
        PASS();
    else
        FAIL("decoded tstr doesn't match");
}

static void test_decode_map(void) {
    TEST("decode map and find key");
    uint8_t buf[128];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "x");
    cbor_encode_uint(&enc, 10);
    cbor_encode_cstr(&enc, "y");
    cbor_encode_uint(&enc, 20);
    cbor_encode_cstr(&enc, "z");
    cbor_encode_uint(&enc, 30);

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, cbor_encoder_len(&enc));

    /* Skip map header */
    cbor_item_t map_item = cbor_decode_next(&dec);
    if (map_item.type != CBOR_ITEM_MAP) {
        FAIL("not a map");
        return;
    }

    cbor_item_t val = cbor_map_find(&dec, map_item.count, "y");
    if (val.type == CBOR_ITEM_UINT && val.uint_val == 20)
        PASS();
    else
        FAIL("map_find returned wrong value");
}

static void test_decode_nested(void) {
    TEST("decode nested: map containing array");
    uint8_t buf[128];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "name");
    cbor_encode_cstr(&enc, "test");
    cbor_encode_cstr(&enc, "vals");
    cbor_encode_array(&enc, 3);
    cbor_encode_uint(&enc, 1);
    cbor_encode_uint(&enc, 2);
    cbor_encode_uint(&enc, 3);

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, cbor_encoder_len(&enc));

    /* Map header */
    cbor_item_t map_item = cbor_decode_next(&dec);
    assert(map_item.type == CBOR_ITEM_MAP);

    /* Key "name" */
    cbor_item_t k1 = cbor_decode_next(&dec);
    assert(k1.type == CBOR_ITEM_TSTR);
    cbor_item_t v1 = cbor_decode_next(&dec);
    assert(v1.type == CBOR_ITEM_TSTR);

    /* Key "vals" */
    cbor_item_t k2 = cbor_decode_next(&dec);
    assert(k2.type == CBOR_ITEM_TSTR);
    cbor_item_t arr = cbor_decode_next(&dec);
    assert(arr.type == CBOR_ITEM_ARRAY && arr.count == 3);

    cbor_item_t a1 = cbor_decode_next(&dec);
    cbor_item_t a2 = cbor_decode_next(&dec);
    cbor_item_t a3 = cbor_decode_next(&dec);

    if (a1.uint_val == 1 && a2.uint_val == 2 && a3.uint_val == 3)
        PASS();
    else
        FAIL("nested values wrong");
}

static void test_decode_skip(void) {
    TEST("decode skip complex item");
    uint8_t buf[128];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    /* Map with nested map, followed by a uint */
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "nested");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "b");
    cbor_encode_uint(&enc, 2);

    /* Trailing uint after the map */
    cbor_encode_uint(&enc, 42);

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, cbor_encoder_len(&enc));

    /* Skip the entire outer map */
    cbor_decode_skip(&dec);

    /* Should land on the trailing 42 */
    cbor_item_t item = cbor_decode_next(&dec);
    if (item.type == CBOR_ITEM_UINT && item.uint_val == 42)
        PASS();
    else
        FAIL("skip didn't advance correctly");
}

static void test_roundtrip_protocol_message(void) {
    TEST("roundtrip: protocol PUT message");
    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    /* Encode a PUT message */
    cbor_encode_map(&enc, 4);

    cbor_encode_cstr(&enc, "t");
    cbor_encode_uint(&enc, 42);

    cbor_encode_cstr(&enc, "y");
    cbor_encode_cstr(&enc, "q");

    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "put");

    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "k");
    uint8_t key[64];
    memset(key, 0xAB, 64);
    cbor_encode_bstr(&enc, key, 64);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_cstr(&enc, "hello world");
    cbor_encode_cstr(&enc, "ttl");
    cbor_encode_uint(&enc, 604800);

    size_t total = cbor_encoder_len(&enc);
    if (total == 0) {
        FAIL("encode failed");
        return;
    }

    /* Decode */
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, total);

    cbor_item_t map = cbor_decode_next(&dec);
    if (map.type != CBOR_ITEM_MAP || map.count != 4) {
        FAIL("outer map wrong");
        return;
    }

    /* Read transaction_id */
    cbor_item_t val = cbor_map_find(&dec, map.count, "t");
    if (val.type != CBOR_ITEM_UINT || val.uint_val != 42) {
        FAIL("transaction_id wrong");
        return;
    }

    PASS();
}

/* ── Signed integers — RFC 8949 §3.1 (D-22) ──────────────────────────
 *
 * WHAT THESE PROVE. That cbor_encode_int emits exactly the bytes RFC 8949
 * §3.1 defines ("a negative integer ... the value of the item is -1 minus
 * the argument") in the shortest argument form (§4.2.1), that
 * cbor_decode_int reads them back exactly, that both edges of int64_t
 * survive the round trip, and that a CBOR integer outside int64_t rejects
 * instead of wrapping.
 *
 * WHAT THEY REQUIRE. Nothing: no flag, no environment, no I/O.
 *
 * WHAT THEY LEAVE BEHIND. Nothing.
 *
 * HOW THEY CAN LIE. The vectors are DERIVED from the §3.1 rule and happen
 * to coincide with RFC 8949 Appendix A; they were not copied from an
 * implementation, so a shared misreading of §3.1 would make encoder and
 * vectors agree while both were wrong. The two legacy-pin cases are the
 * load-bearing ones: if cbor_decode_next ever stops erroring on major type
 * 1, every legacy arg decoder silently changes from reject to
 * accept-with-zero, and nothing else in the suite would notice. */

static int tm_bytes_eq(const uint8_t *got, size_t got_len,
                       const uint8_t *want, size_t want_len) {
    return got_len == want_len && memcmp(got, want, want_len) == 0;
}

static void test_encode_int_vectors(void) {
    TEST("encode int — RFC 8949 §3.1 vectors");

    static const struct { int64_t v; uint8_t b[9]; size_t n; } vec[] = {
        {                     0, { 0x00 },                                              1 },
        {                     1, { 0x01 },                                              1 },
        {                    23, { 0x17 },                                              1 },
        {                    24, { 0x18, 0x18 },                                        2 },
        {                    -1, { 0x20 },                                              1 },
        {                   -10, { 0x29 },                                              1 },
        {                  -100, { 0x38, 0x63 },                                        2 },
        {                 -1000, { 0x39, 0x03, 0xE7 },                                  3 },
        {           INT64_MAX,   { 0x1B, 0x7F, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF },                            9 },
        {           INT64_MIN,   { 0x3B, 0x7F, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF },                            9 },
    };

    for (size_t i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
        uint8_t buf[32];
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        cbor_encode_int(&enc, vec[i].v);
        size_t len = cbor_encoder_len(&enc);
        if (!tm_bytes_eq(buf, len, vec[i].b, vec[i].n)) {
            printf("(vector %llu) ", (unsigned long long)i);
            FAIL("encoding does not match RFC 8949 §3.1");
            return;
        }
    }
    PASS();
}

static void test_decode_int_roundtrip(void) {
    TEST("decode int — round-trips every vector");

    static const int64_t vals[] = {
        0, 1, 23, 24, 255, 256, 65535, 65536,
        -1, -10, -100, -1000, -24, -25, -256, -257,
        INT64_MAX, INT64_MIN
    };

    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        uint8_t buf[32];
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        cbor_encode_int(&enc, vals[i]);
        size_t len = cbor_encoder_len(&enc);
        if (len == 0) { FAIL("encode produced nothing"); return; }

        cbor_decoder_t dec;
        cbor_decoder_init(&dec, buf, len);
        int64_t got = 0;
        if (!cbor_decode_int(&dec, &got) || dec.error) {
            printf("(value %lld) ", (long long)vals[i]);
            FAIL("decode rejected its own encoding");
            return;
        }
        if (got != vals[i]) {
            printf("(want %lld got %lld) ", (long long)vals[i], (long long)got);
            FAIL("round-trip value mismatch");
            return;
        }
    }
    PASS();
}

static void test_decode_int_rejects(void) {
    TEST("decode int — rejects out-of-range and non-integers");

    /* -2^64: a legal CBOR negative integer that int64_t cannot hold. */
    static const uint8_t neg_2_64[] = { 0x3B, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF };
    /* 2^63: a legal CBOR unsigned that int64_t cannot hold. */
    static const uint8_t pos_2_63[] = { 0x1B, 0x80, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00 };
    static const uint8_t a_bstr[]   = { 0x42, 0xAA, 0xBB };        /* bstr(2)  */
    static const uint8_t a_tstr[]   = { 0x61, 0x41 };              /* tstr "A" */
    static const uint8_t a_map[]    = { 0xA0 };                    /* map(0)   */
    static const uint8_t a_bool[]   = { 0xF5 };                    /* true     */
    static const uint8_t trunc_u[]  = { 0x1B, 0x00, 0x00 };        /* short u64 */
    static const uint8_t trunc_n[]  = { 0x3B, 0x00 };              /* short neg */
    static const uint8_t reserved[] = { 0x1C };                    /* ai 28     */

    static const struct { const char *what; const uint8_t *b; size_t n; } bad[] = {
        { "-2^64",          neg_2_64, sizeof(neg_2_64) },
        { "2^63",           pos_2_63, sizeof(pos_2_63) },
        { "bstr",           a_bstr,   sizeof(a_bstr)   },
        { "tstr",           a_tstr,   sizeof(a_tstr)   },
        { "map",            a_map,    sizeof(a_map)    },
        { "bool",           a_bool,   sizeof(a_bool)   },
        { "truncated uint", trunc_u,  sizeof(trunc_u)  },
        { "truncated neg",  trunc_n,  sizeof(trunc_n)  },
        { "reserved ai 28", reserved, sizeof(reserved) },
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cbor_decoder_t dec;
        cbor_decoder_init(&dec, bad[i].b, bad[i].n);
        int64_t got = 0x5A5A5A5A;
        if (cbor_decode_int(&dec, &got)) {
            printf("(%s) ", bad[i].what);
            FAIL("accepted an item it must reject");
            return;
        }
        if (!dec.error) {
            printf("(%s) ", bad[i].what);
            FAIL("rejected without setting dec.error");
            return;
        }
        if (got != 0x5A5A5A5A) {
            printf("(%s) ", bad[i].what);
            FAIL("wrote to *out on a rejected item");
            return;
        }
    }

    /* Empty input. */
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, bad[0].b, 0);
    int64_t got = 0;
    if (cbor_decode_int(&dec, &got)) { FAIL("accepted an empty buffer"); return; }

    PASS();
}

static void test_negint_legacy_pin(void) {
    TEST("legacy pin — cbor_decode_next still errors on major type 1");

    /* THE POINT OF THIS TEST. 42+ call sites reach cbor_decode_next and
     * every legacy arg decoder skips anything that is not CBOR_ITEM_UINT.
     * If this function ever starts returning a negative integer item, a
     * malformed legacy message stops being rejected and starts being
     * accepted with the field left at zero. Teaching the codec negative
     * numbers must never change this door — only cbor_decode_int opens
     * major type 1. */
    static const uint8_t neg_one[] = { 0x20 };          /* -1 */

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, neg_one, sizeof(neg_one));
    cbor_item_t item = cbor_decode_next(&dec);
    if (item.type != CBOR_ITEM_ERROR) {
        FAIL("cbor_decode_next accepted a negative integer");
        return;
    }
    if (!dec.error) { FAIL("no error flag set"); return; }

    /* peek reports the same verdict */
    cbor_decoder_t dec2;
    cbor_decoder_init(&dec2, neg_one, sizeof(neg_one));
    if (cbor_decode_peek(&dec2) != CBOR_ITEM_ERROR) {
        FAIL("cbor_decode_peek accepted a negative integer");
        return;
    }

    /* and skipping over one is an error, not a silent step */
    cbor_decoder_t dec3;
    cbor_decoder_init(&dec3, neg_one, sizeof(neg_one));
    cbor_decode_skip(&dec3);
    if (!dec3.error) { FAIL("cbor_decode_skip walked over a NEGINT"); return; }

    PASS();
}

/* ── cbor_decode_skip_signed — D-22 rev 2 ────────────────────────────
 *
 * WHAT THESE PROVE. That the signed walker differs from cbor_decode_skip in
 * exactly one respect — it steps over a major type 1 item and reports that
 * it did — and in NO other respect. The parity cases are the real content:
 * for every non-negative item, and for every malformed input, both walkers
 * are run over the SAME bytes and their final position, error flag and
 * depth are required to be identical. That is the whole equivalence
 * argument behind leaving the shared walker untouched.
 *
 * WHAT THEY REQUIRE / LEAVE BEHIND. Nothing, and nothing.
 *
 * HOW THEY CAN LIE. Parity is only asserted for the shapes listed here; a
 * shape neither list covers is untested in both walkers alike. And parity
 * of the OBSERVABLE state (pos/error/depth) is not proof of identical
 * control flow — it is the property the callers actually depend on. */

/* Run both walkers over the same bytes and compare what a caller can see. */
static int tm_skip_parity(const uint8_t *b, size_t n, const char **why) {
    cbor_decoder_t plain, signd;
    bool saw = false;

    cbor_decoder_init(&plain, b, n);
    cbor_decoder_init(&signd, b, n);
    cbor_decode_skip(&plain);
    cbor_decode_skip_signed(&signd, &saw);

    if (plain.pos != signd.pos)     { *why = "pos differs";   return 0; }
    if (plain.error != signd.error) { *why = "error differs"; return 0; }
    if (plain.depth != signd.depth) { *why = "depth differs"; return 0; }
    if (saw)                        { *why = "flag set with no negative"; return 0; }
    return 1;
}

static void test_skip_signed_negatives(void) {
    TEST("skip_signed — steps over negatives, sets the flag");

    /* (a) a bare negative scalar */
    static const uint8_t scalar[] = { 0x20 };                 /* -1 */
    cbor_decoder_t dec;
    bool saw = false;
    cbor_decoder_init(&dec, scalar, sizeof(scalar));
    cbor_decode_skip_signed(&dec, &saw);
    if (dec.error)        { FAIL("errored on a negative scalar"); return; }
    if (dec.pos != 1)     { FAIL("did not advance by exactly one byte"); return; }
    if (!saw)             { FAIL("flag not set"); return; }

    /* (b) a negative as a map VALUE: {"a": -1000} */
    static const uint8_t in_map[] = { 0xA1, 0x61, 0x61, 0x39, 0x03, 0xE7 };
    saw = false;
    cbor_decoder_init(&dec, in_map, sizeof(in_map));
    cbor_decode_skip_signed(&dec, &saw);
    if (dec.error)                 { FAIL("errored on a negative in a map"); return; }
    if (dec.pos != sizeof(in_map)) { FAIL("map not fully consumed"); return; }
    if (!saw)                      { FAIL("flag not set for a nested negative"); return; }
    if (dec.depth != 0)            { FAIL("depth not restored"); return; }

    /* (c) a negative as an ARRAY element, nested one deeper: [[-1, 1]] */
    static const uint8_t in_arr[] = { 0x81, 0x82, 0x20, 0x01 };
    saw = false;
    cbor_decoder_init(&dec, in_arr, sizeof(in_arr));
    cbor_decode_skip_signed(&dec, &saw);
    if (dec.error)                 { FAIL("errored on a negative in an array"); return; }
    if (dec.pos != sizeof(in_arr)) { FAIL("array not fully consumed"); return; }
    if (!saw)                      { FAIL("flag not set for an array negative"); return; }
    if (dec.depth != 0)            { FAIL("depth not restored"); return; }

    /* (f) a NULL flag pointer is allowed — the caller may not care */
    cbor_decoder_init(&dec, scalar, sizeof(scalar));
    cbor_decode_skip_signed(&dec, NULL);
    if (dec.error || dec.pos != 1) { FAIL("NULL saw_negint mishandled"); return; }

    /* -2^64 is a legal CBOR negative that int64_t cannot hold; the signed
     * walker inherits cbor_decode_int's rule and refuses it. */
    static const uint8_t neg_2_64[] = { 0x3B, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF };
    saw = false;
    cbor_decoder_init(&dec, neg_2_64, sizeof(neg_2_64));
    cbor_decode_skip_signed(&dec, &saw);
    if (!dec.error) { FAIL("-2^64 was stepped over instead of refused"); return; }

    PASS();
}

static void test_skip_signed_parity(void) {
    TEST("skip_signed — identical to cbor_decode_skip otherwise");

    /* Well-formed shapes: every item type the codec supports. */
    static const uint8_t v_uint[]  = { 0x18, 0x2A };                  /* 42        */
    static const uint8_t v_bstr[]  = { 0x43, 0x01, 0x02, 0x03 };      /* bstr(3)   */
    static const uint8_t v_tstr[]  = { 0x62, 0x68, 0x69 };            /* "hi"      */
    static const uint8_t v_map[]   = { 0xA1, 0x61, 0x61, 0x01 };      /* {"a":1}   */
    static const uint8_t v_arr[]   = { 0x83, 0x01, 0x02, 0x03 };      /* [1,2,3]   */
    static const uint8_t v_bool[]  = { 0xF5 };                        /* true      */
    static const uint8_t v_null[]  = { 0xF6 };                        /* null      */
    static const uint8_t v_nest[]  = { 0x81, 0xA1, 0x61, 0x61, 0x01 };/* [{"a":1}] */
    /* Malformed / unsupported shapes: the failure modes must match too. */
    static const uint8_t m_tag[]   = { 0xC0 };                        /* tag       */
    static const uint8_t m_float[] = { 0xF9, 0x3C, 0x00 };            /* float16   */
    static const uint8_t m_trmap[] = { 0xA2, 0x61, 0x61, 0x01 };      /* short map */
    static const uint8_t m_trneg[] = { 0x39, 0x03 };                  /* short neg */
    static const uint8_t m_empty[] = { 0x00 };                        /* (see below) */

    static const struct { const char *what; const uint8_t *b; size_t n; } cases[] = {
        { "uint",            v_uint,  sizeof(v_uint)  },
        { "bstr",            v_bstr,  sizeof(v_bstr)  },
        { "tstr",            v_tstr,  sizeof(v_tstr)  },
        { "map",             v_map,   sizeof(v_map)   },
        { "array",           v_arr,   sizeof(v_arr)   },
        { "bool",            v_bool,  sizeof(v_bool)  },
        { "null",            v_null,  sizeof(v_null)  },
        { "map in array",    v_nest,  sizeof(v_nest)  },
        { "tag",             m_tag,   sizeof(m_tag)   },
        { "float",           m_float, sizeof(m_float) },
        { "truncated map",   m_trmap, sizeof(m_trmap) },
        { "truncated neg",   m_trneg, sizeof(m_trneg) },
        { "empty input",     m_empty, 0               },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *why = "";
        if (!tm_skip_parity(cases[i].b, cases[i].n, &why)) {
            printf("(%s: %s) ", cases[i].what, why);
            FAIL("the two walkers diverged");
            return;
        }
    }

    /* Depth: 33 nested arrays must hit CBOR_MAX_DEPTH in both walkers, at
     * the same byte, leaving the same depth counter. */
    uint8_t deep[34];
    for (size_t i = 0; i < 33; i++) deep[i] = 0x81;   /* array(1) */
    deep[33] = 0x00;                                  /* 0        */
    const char *why = "";
    if (!tm_skip_parity(deep, sizeof(deep), &why)) {
        printf("(depth 33: %s) ", why);
        FAIL("depth handling diverged");
        return;
    }
    /* and it really is an error, not a silent walk */
    cbor_decoder_t d;
    cbor_decoder_init(&d, deep, sizeof(deep));
    cbor_decode_skip_signed(&d, NULL);
    if (!d.error) { FAIL("CBOR_MAX_DEPTH not enforced by the signed walker"); return; }

    PASS();
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== Nodus CBOR Tests ===\n");

    test_encode_uint_small();
    test_encode_uint_1byte();
    test_encode_uint_2byte();
    test_encode_uint_4byte();
    test_encode_uint_8byte();
    test_encode_bstr();
    test_encode_tstr();
    test_encode_empty_bstr();
    test_encode_map();
    test_encode_array();
    test_encode_bool();
    test_encode_null();
    test_encode_overflow();

    test_decode_uint();
    test_decode_bstr();
    test_decode_tstr();
    test_decode_map();
    test_decode_nested();
    test_decode_skip();
    test_roundtrip_protocol_message();

    /* Signed integers — RFC 8949 §3.1 (D-22). */
    test_encode_int_vectors();
    test_decode_int_roundtrip();
    test_decode_int_rejects();
    test_negint_legacy_pin();
    test_skip_signed_negatives();
    test_skip_signed_parity();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
