/**
 * Nodus — Tier 2 cluster-status wire round-trip test
 *
 * Verifies nodus_t2_status_result encoder + nodus_t2_decode response
 * decoder for the cluster-status query introduced in Phase 0 / Task 0.2:
 *
 *   info → encode → bytes → decode → info'
 *
 * and asserts every field survives the round-trip. Catches accidental
 * key-string typos, mismatched lengths, and dispatch-table omissions in
 * the decoder. End-to-end testing against a live nodus-server is
 * deferred until the staging cluster is upgraded.
 */

#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_status_result_round_trip(void) {
    TEST("status_result encode → decode round-trip");

    nodus_t2_status_info_t in;
    memset(&in, 0, sizeof(in));
    in.block_height = 12345;
    for (int i = 0; i < 64; i++) in.state_root[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 32; i++) in.chain_id[i]   = (uint8_t)(0xA0 + i);
    in.peer_count   = 7;
    in.uptime_sec   = 86400 + 3600 + 42;   /* 1d 1h 42s */
    in.wall_clock   = 1700000000;

    uint8_t buf[2048];
    size_t  len = 0;
    int rc = nodus_t2_status_result(/*txn=*/12345, &in, buf, sizeof(buf), &len);
    if (rc != 0 || len == 0) { FAIL("encode failed"); return; }

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t2_decode(buf, len, &msg);
    if (rc != 0) { FAIL("decode failed"); return; }
    if (!msg.has_status_info) { FAIL("has_status_info not set"); nodus_t2_msg_free(&msg); return; }
    if (msg.txn_id != 12345) { FAIL("txn_id mismatch"); nodus_t2_msg_free(&msg); return; }

    if (msg.status_info.block_height != in.block_height) { FAIL("block_height"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.status_info.state_root, in.state_root, 64) != 0) { FAIL("state_root bytes"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.status_info.chain_id, in.chain_id, 32) != 0) { FAIL("chain_id bytes"); nodus_t2_msg_free(&msg); return; }
    if (msg.status_info.peer_count != in.peer_count) { FAIL("peer_count"); nodus_t2_msg_free(&msg); return; }
    if (msg.status_info.uptime_sec != in.uptime_sec) { FAIL("uptime_sec"); nodus_t2_msg_free(&msg); return; }
    if (msg.status_info.wall_clock != in.wall_clock) { FAIL("wall_clock"); nodus_t2_msg_free(&msg); return; }

    nodus_t2_msg_free(&msg);
    PASS();
}

static void test_status_query_encodes(void) {
    TEST("status query encodes with token");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    for (size_t i = 0; i < sizeof(token); i++) token[i] = (uint8_t)i;

    uint8_t buf[2048];
    size_t  len = 0;
    int rc = nodus_t2_status(/*txn=*/777, token, buf, sizeof(buf), &len);
    if (rc != 0 || len == 0) { FAIL("encode failed"); return; }

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t2_decode(buf, len, &msg);
    if (rc != 0) { FAIL("decode failed"); nodus_t2_msg_free(&msg); return; }
    if (msg.txn_id != 777) { FAIL("txn_id mismatch"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'q') { FAIL("expected query type 'q'"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "status") != 0) { FAIL("method != status"); nodus_t2_msg_free(&msg); return; }

    nodus_t2_msg_free(&msg);
    PASS();
}

int main(void) {
    printf("\nNodus Tier 2 cluster-status wire tests\n");
    printf("==========================================\n\n");

    test_status_query_encodes();
    test_status_result_round_trip();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
