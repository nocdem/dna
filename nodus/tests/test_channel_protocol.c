/**
 * Nodus — Channel Rewrite Protocol Tests
 *
 * Tests encode/decode roundtrips for the new node-to-node channel
 * protocol messages (TCP 4003).
 */

#include "protocol/nodus_tier2.h"
#include "channel/nodus_hashring.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Large buffer for protocol messages (pubkeys are 2592 bytes) */
static uint8_t msgbuf[65536];

static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static void test_node_hello_roundtrip(void) {
    TEST("node_hello encode/decode");
    size_t len = 0;
    uint32_t rv = 7;
    int rc = nodus_t2_ch_node_hello(10, &test_id.pk, &test_id.node_id, rv,
                                     msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id == 10 && msg.type == 'q' &&
        strcmp(msg.method, "node_hello") == 0 &&
        memcmp(msg.pk.bytes, test_id.pk.bytes, NODUS_PK_BYTES) == 0 &&
        nodus_key_cmp(&msg.fp, &test_id.node_id) == 0 &&
        msg.ring_version == rv) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_node_auth_ok_roundtrip(void) {
    TEST("node_auth_ok encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xDD, sizeof(token));
    uint32_t rv = 12;

    nodus_ring_member_t members[2];
    memset(&members, 0, sizeof(members));
    memset(members[0].node_id.bytes, 0x11, NODUS_KEY_BYTES);
    snprintf(members[0].ip, sizeof(members[0].ip), "10.0.0.1");
    members[0].tcp_port = 4003;
    memset(members[1].node_id.bytes, 0x22, NODUS_KEY_BYTES);
    snprintf(members[1].ip, sizeof(members[1].ip), "10.0.0.2");
    members[1].tcp_port = 4003;

    size_t len = 0;
    int rc = nodus_t2_ch_node_auth_ok(20, token, sizeof(token), rv,
                                       members, 2,
                                       msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id == 20 && msg.type == 'r' &&
        strcmp(msg.method, "node_auth_ok") == 0 &&
        msg.has_token &&
        memcmp(msg.token, token, NODUS_SESSION_TOKEN_LEN) == 0 &&
        msg.ring_version == rv &&
        msg.server_count == 2 &&
        strcmp(msg.servers[0].ip, "10.0.0.1") == 0 &&
        msg.servers[0].tcp_port == 4003 &&
        strcmp(msg.servers[1].ip, "10.0.0.2") == 0 &&
        msg.servers[1].tcp_port == 4003) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_heartbeat_roundtrip(void) {
    TEST("ch_heartbeat encode/decode");
    size_t len = 0;
    int rc = nodus_t2_ch_heartbeat(30, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id == 30 && msg.type == 'q' &&
        strcmp(msg.method, "ch_hb") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_heartbeat_ack_roundtrip(void) {
    TEST("ch_heartbeat_ack encode/decode");
    size_t len = 0;
    int rc = nodus_t2_ch_heartbeat_ack(31, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id == 31 && msg.type == 'r' &&
        strcmp(msg.method, "ch_hb_ack") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_sync_request_roundtrip(void) {
    TEST("ch_sync_request encode/decode");
    uint8_t ch_uuid[NODUS_UUID_BYTES];
    memset(ch_uuid, 0xAB, sizeof(ch_uuid));
    uint64_t since = 1710000000000ULL;

    size_t len = 0;
    int rc = nodus_t2_ch_sync_request(40, ch_uuid, since,
                                       msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id == 40 && msg.type == 'q' &&
        strcmp(msg.method, "ch_sync_req") == 0 &&
        memcmp(msg.channel_uuid, ch_uuid, NODUS_UUID_BYTES) == 0 &&
        msg.ch_since_ms == since) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_sync_response_roundtrip(void) {
    TEST("ch_sync_response encode/decode");
    uint8_t ch_uuid[NODUS_UUID_BYTES];
    memset(ch_uuid, 0xCD, sizeof(ch_uuid));

    /* Create a test post */
    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    post.received_at = 1710000001000ULL;
    memset(post.post_uuid, 0xEE, NODUS_UUID_BYTES);
    memset(post.author_fp.bytes, 0xFF, NODUS_KEY_BYTES);
    post.timestamp = 1710000000500ULL;
    post.body = strdup("test post body");
    post.body_len = strlen(post.body);
    memset(post.signature.bytes, 0x99, NODUS_SIG_BYTES);

    size_t len = 0;
    int rc = nodus_t2_ch_sync_response(50, ch_uuid, &post, 1,
                                        msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { free(post.body); FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { free(post.body); FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    bool ok = (msg.txn_id == 50 && msg.type == 'r' &&
               strcmp(msg.method, "ch_sync_res") == 0 &&
               memcmp(msg.channel_uuid, ch_uuid, NODUS_UUID_BYTES) == 0 &&
               msg.ch_post_count == 1 &&
               msg.ch_posts != NULL &&
               msg.ch_posts[0].received_at == post.received_at &&
               memcmp(msg.ch_posts[0].post_uuid, post.post_uuid, NODUS_UUID_BYTES) == 0 &&
               memcmp(msg.ch_posts[0].author_fp.bytes, post.author_fp.bytes, NODUS_KEY_BYTES) == 0 &&
               msg.ch_posts[0].timestamp == post.timestamp &&
               msg.ch_posts[0].body_len == post.body_len &&
               memcmp(msg.ch_posts[0].body, post.body, post.body_len) == 0 &&
               memcmp(msg.ch_posts[0].signature.bytes, post.signature.bytes, NODUS_SIG_BYTES) == 0);

    if (ok) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    free(post.body);
    nodus_t2_msg_free(&msg);
}

static void test_ring_rejoin_roundtrip(void) {
    TEST("ring_rejoin encode/decode");
    nodus_key_t nid;
    memset(nid.bytes, 0x33, NODUS_KEY_BYTES);
    uint32_t rv = 5;

    size_t len = 0;
    int rc = nodus_t2_ch_ring_rejoin(60, &nid, rv,
                                      msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id == 60 && msg.type == 'q' &&
        strcmp(msg.method, "ring_rejoin") == 0 &&
        memcmp(msg.ring_node_id.bytes, nid.bytes, NODUS_KEY_BYTES) == 0 &&
        msg.ring_version == rv) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

int main(void) {
    printf("=== Channel Rewrite Protocol Tests ===\n");
    init_test_identity();

    test_node_hello_roundtrip();
    test_node_auth_ok_roundtrip();
    test_heartbeat_roundtrip();
    test_heartbeat_ack_roundtrip();
    test_sync_request_roundtrip();
    test_sync_response_roundtrip();
    test_ring_rejoin_roundtrip();

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
