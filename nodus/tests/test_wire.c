/**
 * Nodus v5 — Wire Frame Protocol Tests
 */

#include "protocol/nodus_wire.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_encode_basic(void) {
    TEST("encode basic frame");
    uint8_t buf[64];
    uint8_t payload[] = "hello";

    size_t total = nodus_frame_encode(buf, sizeof(buf), payload, 5);
    if (total == 12 &&
        buf[0] == 0x4E && buf[1] == 0x44 &&  /* "ND" */
        buf[2] == 0x01 &&                      /* version 1 */
        buf[3] == 5 && buf[4] == 0 && buf[5] == 0 && buf[6] == 0 &&  /* len=5 LE */
        memcmp(buf + 7, "hello", 5) == 0)
        PASS();
    else
        FAIL("wrong encoding");
}

static void test_encode_empty_payload(void) {
    TEST("encode empty payload");
    uint8_t buf[16];

    size_t total = nodus_frame_encode(buf, sizeof(buf), NULL, 0);
    if (total == 7 &&
        buf[0] == 0x4E && buf[1] == 0x44 &&
        buf[3] == 0 && buf[4] == 0 && buf[5] == 0 && buf[6] == 0)
        PASS();
    else
        FAIL("wrong encoding");
}

static void test_encode_buffer_too_small(void) {
    TEST("encode fails if buffer too small");
    uint8_t buf[4];
    uint8_t payload[] = "data";

    size_t total = nodus_frame_encode(buf, sizeof(buf), payload, 4);
    if (total == 0)
        PASS();
    else
        FAIL("should return 0");
}

static void test_decode_basic(void) {
    TEST("decode basic frame");
    uint8_t buf[64];
    uint8_t payload[] = "world";
    nodus_frame_encode(buf, sizeof(buf), payload, 5);

    nodus_frame_t frame;
    int rc = nodus_frame_decode(buf, 12, &frame);
    if (rc == 12 &&
        frame.version == 1 &&
        frame.payload_len == 5 &&
        memcmp(frame.payload, "world", 5) == 0)
        PASS();
    else
        FAIL("decode mismatch");
}

static void test_decode_incomplete_header(void) {
    TEST("decode returns 0 on incomplete header");
    uint8_t buf[] = {0x4E, 0x44, 0x01};  /* Only 3 bytes */

    nodus_frame_t frame;
    int rc = nodus_frame_decode(buf, 3, &frame);
    if (rc == 0)
        PASS();
    else
        FAIL("should return 0");
}

static void test_decode_incomplete_payload(void) {
    TEST("decode returns 0 on incomplete payload");
    uint8_t buf[64];
    uint8_t payload[] = "hello";
    nodus_frame_encode(buf, sizeof(buf), payload, 5);

    nodus_frame_t frame;
    /* Only provide 10 bytes (header=7 + 3 of payload) */
    int rc = nodus_frame_decode(buf, 10, &frame);
    if (rc == 0)
        PASS();
    else
        FAIL("should return 0 for incomplete payload");
}

static void test_decode_bad_magic(void) {
    TEST("decode rejects bad magic");
    uint8_t buf[] = {0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00};

    nodus_frame_t frame;
    int rc = nodus_frame_decode(buf, 7, &frame);
    if (rc == -1)
        PASS();
    else
        FAIL("should return -1");
}

static void test_validate_udp(void) {
    TEST("validate UDP frame size limit");
    nodus_frame_t frame = {
        .version = NODUS_FRAME_VERSION,
        .payload_len = 1400,
        .payload = NULL
    };

    if (nodus_frame_validate(&frame, true)) {
        /* Now exceed limit */
        frame.payload_len = 1401;
        if (!nodus_frame_validate(&frame, true))
            PASS();
        else
            FAIL("should reject 1401 bytes for UDP");
    } else {
        FAIL("should accept 1400 bytes for UDP");
    }
}

static void test_validate_tcp(void) {
    TEST("validate TCP frame size limit");
    nodus_frame_t frame = {
        .version = NODUS_FRAME_VERSION,
        .payload_len = 4 * 1024 * 1024,  /* 4MB exactly */
        .payload = NULL
    };

    if (nodus_frame_validate(&frame, false)) {
        frame.payload_len = 4 * 1024 * 1024 + 1;
        if (!nodus_frame_validate(&frame, false))
            PASS();
        else
            FAIL("should reject >4MB for TCP");
    } else {
        FAIL("should accept 4MB for TCP");
    }
}

static void test_validate_bad_version(void) {
    TEST("validate rejects bad version");
    nodus_frame_t frame = {
        .version = 0x99,
        .payload_len = 10,
        .payload = NULL
    };

    if (!nodus_frame_validate(&frame, false))
        PASS();
    else
        FAIL("should reject bad version");
}

static void test_roundtrip_large_payload(void) {
    TEST("roundtrip with 1000-byte payload");
    uint8_t buf[2048];
    uint8_t payload[1000];
    memset(payload, 0xAA, sizeof(payload));

    size_t total = nodus_frame_encode(buf, sizeof(buf), payload, sizeof(payload));
    if (total != 1007) {
        FAIL("wrong total size");
        return;
    }

    nodus_frame_t frame;
    int rc = nodus_frame_decode(buf, total, &frame);
    if (rc == (int)total &&
        frame.payload_len == 1000 &&
        memcmp(frame.payload, payload, 1000) == 0)
        PASS();
    else
        FAIL("roundtrip mismatch");
}

int main(void) {
    printf("=== Nodus Wire Frame Tests ===\n");

    test_encode_basic();
    test_encode_empty_payload();
    test_encode_buffer_too_small();
    test_decode_basic();
    test_decode_incomplete_header();
    test_decode_incomplete_payload();
    test_decode_bad_magic();
    test_validate_udp();
    test_validate_tcp();
    test_validate_bad_version();
    test_roundtrip_large_payload();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
