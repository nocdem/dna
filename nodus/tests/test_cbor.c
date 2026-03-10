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

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
