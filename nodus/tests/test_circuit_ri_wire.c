/**
 * Inter-node circuit (ri_*) wire protocol roundtrip tests (Faz 1)
 */
#include "protocol/nodus_tier2.h"
#include <stdio.h>
#include <string.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;
static uint8_t msgbuf[NODUS_MAX_CIRCUIT_PAYLOAD + 2048];

static void test_ri_open_roundtrip(void) {
    TEST("ri_open encode/decode");
    nodus_key_t src, dst;
    for (int i = 0; i < NODUS_KEY_BYTES; i++) { src.bytes[i] = (uint8_t)i; dst.bytes[i] = (uint8_t)(0xFF - i); }
    size_t len = 0;
    nodus_t2_ri_open(100, 0xAAAA, &src, &dst, msgbuf, sizeof(msgbuf), &len);
    nodus_tier2_msg_t msg;
    int rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.has_ri && msg.type == 'q' &&
        strcmp(msg.method, "ri_open") == 0 &&
        msg.ri_ups_cid == 0xAAAA &&
        nodus_key_cmp(&msg.ri_src_fp, &src) == 0 &&
        nodus_key_cmp(&msg.ri_dst_fp, &dst) == 0) {
        PASS();
    } else { FAIL("decode"); }
    nodus_t2_msg_free(&msg);
}

static void test_ri_open_ok_roundtrip(void) {
    TEST("ri_open_ok encode/decode");
    size_t len = 0;
    nodus_t2_ri_open_ok(101, 0xAAAA, 0xBBBB, msgbuf, sizeof(msgbuf), &len);
    nodus_tier2_msg_t msg;
    int rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.type == 'r' && strcmp(msg.method, "ri_open_ok") == 0 &&
        msg.ri_ups_cid == 0xAAAA && msg.ri_dns_cid == 0xBBBB) {
        PASS();
    } else { FAIL("decode"); }
    nodus_t2_msg_free(&msg);
}

static void test_ri_open_err_roundtrip(void) {
    TEST("ri_open_err encode/decode");
    size_t len = 0;
    nodus_t2_ri_open_err(102, 0xAAAA, NODUS_ERR_PEER_OFFLINE, msgbuf, sizeof(msgbuf), &len);
    nodus_tier2_msg_t msg;
    int rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && strcmp(msg.method, "ri_open_err") == 0 &&
        msg.ri_ups_cid == 0xAAAA && msg.ri_err_code == NODUS_ERR_PEER_OFFLINE) {
        PASS();
    } else { FAIL("decode"); }
    nodus_t2_msg_free(&msg);
}

static void test_ri_data_roundtrip(void) {
    TEST("ri_data encode/decode (2KB)");
    uint8_t payload[2048];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)((i * 7) & 0xFF);
    size_t len = 0;
    nodus_t2_ri_data(103, 0xCAFE, payload, sizeof(payload), msgbuf, sizeof(msgbuf), &len);
    nodus_tier2_msg_t msg;
    int rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && strcmp(msg.method, "ri_data") == 0 &&
        msg.ri_cid == 0xCAFE && msg.ri_data_len == sizeof(payload) &&
        msg.ri_data != NULL && memcmp(msg.ri_data, payload, sizeof(payload)) == 0) {
        PASS();
    } else { FAIL("decode"); }
    nodus_t2_msg_free(&msg);
}

static void test_ri_close_roundtrip(void) {
    TEST("ri_close encode/decode");
    size_t len = 0;
    nodus_t2_ri_close(104, 0xDEAD, msgbuf, sizeof(msgbuf), &len);
    nodus_tier2_msg_t msg;
    int rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && strcmp(msg.method, "ri_close") == 0 && msg.ri_cid == 0xDEAD) {
        PASS();
    } else { FAIL("decode"); }
    nodus_t2_msg_free(&msg);
}

int main(void) {
    printf("Inter-node circuit (ri_*) wire tests:\n");
    test_ri_open_roundtrip();
    test_ri_open_ok_roundtrip();
    test_ri_open_err_roundtrip();
    test_ri_data_roundtrip();
    test_ri_close_roundtrip();
    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
