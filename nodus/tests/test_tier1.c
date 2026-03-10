/**
 * Nodus — Tier 1 Protocol Tests
 *
 * Tests encode/decode roundtrips for all Tier 1 message types.
 */

#include "protocol/nodus_tier1.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Large buffer for protocol messages */
static uint8_t msgbuf[32768];

static nodus_key_t make_key(uint8_t fill) {
    nodus_key_t k;
    memset(k.bytes, fill, NODUS_KEY_BYTES);
    return k;
}

static void test_ping_roundtrip(void) {
    TEST("ping encode/decode");
    nodus_key_t node_id = make_key(0x42);
    size_t len = 0;
    int rc = nodus_t1_ping(1, &node_id, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier1_msg_t msg;
    rc = nodus_t1_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 1 && msg.type == 'q' &&
        strcmp(msg.method, "ping") == 0 &&
        nodus_key_cmp(&msg.node_id, &node_id) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

static void test_pong_roundtrip(void) {
    TEST("pong encode/decode");
    nodus_key_t node_id = make_key(0xAA);
    size_t len = 0;
    nodus_t1_pong(99, &node_id, msgbuf, sizeof(msgbuf), &len);

    nodus_tier1_msg_t msg;
    nodus_t1_decode(msgbuf, len, &msg);
    if (msg.txn_id == 99 && msg.type == 'r' &&
        strcmp(msg.method, "pong") == 0 &&
        nodus_key_cmp(&msg.node_id, &node_id) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

static void test_find_node_roundtrip(void) {
    TEST("find_node encode/decode");
    nodus_key_t target = make_key(0x77);
    size_t len = 0;
    nodus_t1_find_node(10, &target, msgbuf, sizeof(msgbuf), &len);

    nodus_tier1_msg_t msg;
    nodus_t1_decode(msgbuf, len, &msg);
    if (msg.txn_id == 10 && msg.type == 'q' &&
        strcmp(msg.method, "fn") == 0 &&
        nodus_key_cmp(&msg.target, &target) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

static void test_nodes_found_roundtrip(void) {
    TEST("nodes_found encode/decode");
    nodus_peer_t peers[3];
    memset(peers, 0, sizeof(peers));
    for (int i = 0; i < 3; i++) {
        memset(peers[i].node_id.bytes, (uint8_t)(i + 1), NODUS_KEY_BYTES);
        snprintf(peers[i].ip, sizeof(peers[i].ip), "10.0.0.%d", i + 1);
        peers[i].udp_port = (uint16_t)(4000 + i);
        peers[i].tcp_port = (uint16_t)(4001 + i);
    }

    size_t len = 0;
    nodus_t1_nodes_found(20, peers, 3, msgbuf, sizeof(msgbuf), &len);

    nodus_tier1_msg_t msg;
    nodus_t1_decode(msgbuf, len, &msg);
    if (msg.txn_id == 20 && msg.peer_count == 3 &&
        strcmp(msg.method, "fn_r") == 0 &&
        msg.peers[0].udp_port == 4000 &&
        msg.peers[2].tcp_port == 4003 &&
        strcmp(msg.peers[1].ip, "10.0.0.2") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

static void test_store_value_roundtrip(void) {
    TEST("store_value encode/decode");

    /* Create a test value */
    nodus_identity_t id;
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &id);

    nodus_key_t key;
    nodus_hash((const uint8_t *)"test:store", 10, &key);

    nodus_value_t *val = NULL;
    nodus_value_create(&key, (const uint8_t *)"hello", 5,
                        NODUS_VALUE_EPHEMERAL, 3600, 1, 0, &id.pk, &val);
    nodus_value_sign(val, &id.sk);

    size_t len = 0;
    int rc = nodus_t1_store_value(30, val, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); nodus_value_free(val); return; }

    nodus_tier1_msg_t msg;
    rc = nodus_t1_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 30 && msg.has_value &&
        msg.value->data_len == 5 &&
        memcmp(msg.value->data, "hello", 5) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }

    nodus_value_free(val);
    nodus_t1_msg_free(&msg);
    nodus_identity_clear(&id);
}

static void test_store_ack_roundtrip(void) {
    TEST("store_ack encode/decode");
    size_t len = 0;
    nodus_t1_store_ack(31, msgbuf, sizeof(msgbuf), &len);

    nodus_tier1_msg_t msg;
    nodus_t1_decode(msgbuf, len, &msg);
    if (msg.txn_id == 31 && msg.type == 'r' &&
        strcmp(msg.method, "sv_ack") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

static void test_find_value_roundtrip(void) {
    TEST("find_value encode/decode");
    nodus_key_t key = make_key(0x55);
    size_t len = 0;
    nodus_t1_find_value(40, &key, msgbuf, sizeof(msgbuf), &len);

    nodus_tier1_msg_t msg;
    nodus_t1_decode(msgbuf, len, &msg);
    if (msg.txn_id == 40 && msg.type == 'q' &&
        strcmp(msg.method, "fv") == 0 &&
        nodus_key_cmp(&msg.target, &key) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

static void test_subscribe_roundtrip(void) {
    TEST("subscribe encode/decode");
    nodus_key_t key = make_key(0xBB);
    size_t len = 0;
    nodus_t1_subscribe(50, &key, msgbuf, sizeof(msgbuf), &len);

    nodus_tier1_msg_t msg;
    nodus_t1_decode(msgbuf, len, &msg);
    if (msg.txn_id == 50 && msg.type == 'q' &&
        strcmp(msg.method, "sub") == 0 &&
        nodus_key_cmp(&msg.target, &key) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t1_msg_free(&msg);
}

int main(void) {
    printf("=== Nodus Tier 1 Protocol Tests ===\n");

    test_ping_roundtrip();
    test_pong_roundtrip();
    test_find_node_roundtrip();
    test_nodes_found_roundtrip();
    test_store_value_roundtrip();
    test_store_ack_roundtrip();
    test_find_value_roundtrip();
    test_subscribe_roundtrip();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
