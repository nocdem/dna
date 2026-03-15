/**
 * Test CRIT-2/CRIT-3: Dilithium5 authenticated UDP Kademlia messages.
 *
 * Tests:
 *  1. v2 PING encode/decode with signature verification
 *  2. v2 PONG encode/decode with signature verification
 *  3. node_id == SHA3-512(pubkey) verification
 *  4. Replay protection (timestamp skew rejection)
 *  5. v2 NODES_FOUND with pubkeys (CRIT-3)
 *  6. Pubkey caching: PING without pubkey (signature only)
 *  7. v1 backward compatibility
 *  8. Invalid signature rejection
 *  9. node_id/pubkey mismatch rejection
 */

#include "protocol/nodus_tier1.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  %-55s", name); } while(0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while(0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while(0)

/* ── Test 1: v2 PING encode/decode with full pubkey ──────────────── */

static void test_ping_v2_with_pubkey(void) {
    TEST("v2 PING encode/decode with pubkey");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    uint8_t buf[16384];
    size_t len = 0;
    int rc = nodus_t1_ping_v2(42, &id.node_id, &id.pk, &id.sk,
                               true, buf, sizeof(buf), &len);
    ASSERT(rc == 0, "encode failed");
    ASSERT(len > 0, "zero length");

    /* Decode */
    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");
    ASSERT(strcmp(msg.method, "ping") == 0, "wrong method");
    ASSERT(msg.txn_id == 42, "wrong txn_id");
    ASSERT(msg.proto_version == NODUS_T1_PROTOCOL_VERSION, "wrong version");
    ASSERT(msg.has_pubkey, "no pubkey");
    ASSERT(msg.has_signature, "no signature");
    ASSERT(nodus_key_cmp(&msg.node_id, &id.node_id) == 0, "wrong node_id");

    /* Verify node_id matches pubkey */
    ASSERT(nodus_t1_verify_node_id(&msg.node_id, &msg.sender_pk) == 0,
           "node_id/pubkey mismatch");

    /* Verify signature */
    uint8_t sign_payload[NODUS_KEY_BYTES + 8];
    memcpy(sign_payload, msg.node_id.bytes, NODUS_KEY_BYTES);
    uint64_t ts = msg.timestamp;
    for (int i = 7; i >= 0; i--) {
        sign_payload[NODUS_KEY_BYTES + i] = (uint8_t)(ts & 0xFF);
        ts >>= 8;
    }
    ASSERT(nodus_verify(&msg.signature, sign_payload,
                         NODUS_KEY_BYTES + 8, &msg.sender_pk) == 0,
           "signature invalid");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 2: v2 PONG encode/decode with signature ────────────────── */

static void test_pong_v2_with_pubkey(void) {
    TEST("v2 PONG encode/decode with pubkey");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    uint8_t buf[16384];
    size_t len = 0;
    int rc = nodus_t1_pong_v2(99, &id.node_id, &id.pk, &id.sk,
                               true, buf, sizeof(buf), &len);
    ASSERT(rc == 0, "encode failed");

    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");
    ASSERT(strcmp(msg.method, "pong") == 0, "wrong method");
    ASSERT(msg.txn_id == 99, "wrong txn_id");
    ASSERT(msg.proto_version == 2, "wrong version");
    ASSERT(msg.has_pubkey, "no pubkey");
    ASSERT(msg.has_signature, "no signature");

    /* Verify */
    ASSERT(nodus_t1_verify_node_id(&msg.node_id, &msg.sender_pk) == 0,
           "node_id/pubkey mismatch");

    uint8_t sign_payload[NODUS_KEY_BYTES + 8];
    memcpy(sign_payload, msg.node_id.bytes, NODUS_KEY_BYTES);
    uint64_t ts = msg.timestamp;
    for (int i = 7; i >= 0; i--) {
        sign_payload[NODUS_KEY_BYTES + i] = (uint8_t)(ts & 0xFF);
        ts >>= 8;
    }
    ASSERT(nodus_verify(&msg.signature, sign_payload,
                         NODUS_KEY_BYTES + 8, &msg.sender_pk) == 0,
           "signature invalid");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 3: node_id verification ────────────────────────────────── */

static void test_node_id_verification(void) {
    TEST("node_id == SHA3-512(pubkey) verification");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    /* Valid: node_id matches */
    ASSERT(nodus_t1_verify_node_id(&id.node_id, &id.pk) == 0,
           "valid node_id rejected");

    /* Invalid: corrupt one byte */
    nodus_key_t bad_id = id.node_id;
    bad_id.bytes[0] ^= 0xFF;
    ASSERT(nodus_t1_verify_node_id(&bad_id, &id.pk) != 0,
           "corrupted node_id accepted");

    PASS();
}

/* ── Test 4: v2 PING without pubkey (cached mode) ───────────────── */

static void test_ping_v2_no_pubkey(void) {
    TEST("v2 PING without pubkey (signature only)");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    uint8_t buf[16384];
    size_t len = 0;
    int rc = nodus_t1_ping_v2(7, &id.node_id, &id.pk, &id.sk,
                               false,  /* no pubkey */
                               buf, sizeof(buf), &len);
    ASSERT(rc == 0, "encode failed");

    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");
    ASSERT(!msg.has_pubkey, "pubkey should not be present");
    ASSERT(msg.has_signature, "signature should be present");
    ASSERT(msg.proto_version == 2, "wrong version");

    /* Should be verifiable with the known pubkey */
    uint8_t sign_payload[NODUS_KEY_BYTES + 8];
    memcpy(sign_payload, msg.node_id.bytes, NODUS_KEY_BYTES);
    uint64_t ts = msg.timestamp;
    for (int i = 7; i >= 0; i--) {
        sign_payload[NODUS_KEY_BYTES + i] = (uint8_t)(ts & 0xFF);
        ts >>= 8;
    }
    ASSERT(nodus_verify(&msg.signature, sign_payload,
                         NODUS_KEY_BYTES + 8, &id.pk) == 0,
           "signature invalid with known pk");

    /* Message is significantly smaller without pubkey */
    ASSERT(len < 5000, "without pubkey should be <5KB");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 5: v1 backward compatibility ───────────────────────────── */

static void test_v1_backward_compat(void) {
    TEST("v1 unsigned PING backward compatibility");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    uint8_t buf[256];
    size_t len = 0;
    int rc = nodus_t1_ping(1, &id.node_id, buf, sizeof(buf), &len);
    ASSERT(rc == 0, "v1 encode failed");

    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "v1 decode failed");
    ASSERT(msg.proto_version == 0, "v1 should have version 0");
    ASSERT(!msg.has_pubkey, "v1 should not have pubkey");
    ASSERT(!msg.has_signature, "v1 should not have signature");
    ASSERT(strcmp(msg.method, "ping") == 0, "wrong method");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 6: Invalid signature rejection ─────────────────────────── */

static void test_invalid_signature_rejection(void) {
    TEST("invalid signature rejection");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    uint8_t buf[16384];
    size_t len = 0;
    int rc = nodus_t1_ping_v2(1, &id.node_id, &id.pk, &id.sk,
                               true, buf, sizeof(buf), &len);
    ASSERT(rc == 0, "encode failed");

    /* Decode and corrupt the signature */
    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");
    ASSERT(msg.has_signature, "no signature");

    /* Corrupt sig */
    msg.signature.bytes[0] ^= 0xFF;

    /* Verify should fail */
    uint8_t sign_payload[NODUS_KEY_BYTES + 8];
    memcpy(sign_payload, msg.node_id.bytes, NODUS_KEY_BYTES);
    uint64_t ts = msg.timestamp;
    for (int i = 7; i >= 0; i--) {
        sign_payload[NODUS_KEY_BYTES + i] = (uint8_t)(ts & 0xFF);
        ts >>= 8;
    }
    ASSERT(nodus_verify(&msg.signature, sign_payload,
                         NODUS_KEY_BYTES + 8, &msg.sender_pk) != 0,
           "corrupted signature should fail verification");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 7: Wrong key rejection ─────────────────────────────────── */

static void test_wrong_key_rejection(void) {
    TEST("wrong signer key rejection");

    nodus_identity_t id1, id2;
    nodus_identity_generate(&id1);
    nodus_identity_generate(&id2);

    /* Sign with id1's key, claim to be id2 */
    uint8_t buf[16384];
    size_t len = 0;
    /* We can't easily forge this with the API, so verify manually:
     * encode id2's node_id but sign with id1's key */
    int rc = nodus_t1_ping_v2(1, &id2.node_id, &id1.pk, &id1.sk,
                               true, buf, sizeof(buf), &len);
    ASSERT(rc == 0, "encode failed");

    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");

    /* node_id (id2) != SHA3-512(pubkey) (id1's pk) → reject */
    ASSERT(nodus_t1_verify_node_id(&msg.node_id, &msg.sender_pk) != 0,
           "mismatched node_id/pubkey should fail");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 8: v2 NODES_FOUND with pubkeys (CRIT-3) ───────────────── */

static void test_nodes_found_v2_with_pubkeys(void) {
    TEST("v2 NODES_FOUND with pubkeys (CRIT-3)");

    /* Create 3 peer identities */
    nodus_identity_t ids[3];
    nodus_peer_t peers[3];
    for (int i = 0; i < 3; i++) {
        nodus_identity_generate(&ids[i]);
        memset(&peers[i], 0, sizeof(peers[i]));
        peers[i].node_id = ids[i].node_id;
        snprintf(peers[i].ip, sizeof(peers[i].ip), "10.0.0.%d", i + 1);
        peers[i].udp_port = 4000 + (uint16_t)i;
        peers[i].tcp_port = 4002 + (uint16_t)i;
        memcpy(peers[i].pubkey.bytes, ids[i].pk.bytes, NODUS_PK_BYTES);
        peers[i].pubkey_verified = true;
    }

    /* Encode */
    size_t buf_size = 3 * (NODUS_PK_BYTES + 256) + 256;
    uint8_t *buf = malloc(buf_size);
    ASSERT(buf != NULL, "malloc failed");

    size_t len = 0;
    int rc = nodus_t1_nodes_found_v2(55, peers, 3, buf, buf_size, &len);
    ASSERT(rc == 0, "encode failed");

    /* Decode */
    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");
    ASSERT(strcmp(msg.method, "fn_r") == 0, "wrong method");
    ASSERT(msg.proto_version == 2, "wrong version");
    ASSERT(msg.peer_count == 3, "wrong peer count");

    /* Verify each peer's pubkey matches its node_id */
    for (int i = 0; i < 3; i++) {
        /* Check pubkey is present */
        bool has_pk = false;
        for (int b = 0; b < NODUS_PK_BYTES; b++) {
            if (msg.peers[i].pubkey.bytes[b] != 0) { has_pk = true; break; }
        }
        ASSERT(has_pk, "peer missing pubkey");

        /* Verify node_id matches */
        ASSERT(nodus_t1_verify_node_id(&msg.peers[i].node_id,
                                        &msg.peers[i].pubkey) == 0,
               "peer node_id/pubkey mismatch");
    }

    nodus_t1_msg_free(&msg);
    free(buf);
    PASS();
}

/* ── Test 9: NODES_FOUND without pubkey (v1 peers) ──────────────── */

static void test_nodes_found_v1_compat(void) {
    TEST("v1 NODES_FOUND without pubkeys (backward compat)");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    nodus_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.node_id = id.node_id;
    snprintf(peer.ip, sizeof(peer.ip), "1.2.3.4");
    peer.udp_port = 4000;
    peer.tcp_port = 4002;
    /* No pubkey set → pubkey_verified = false */

    uint8_t buf[4096];
    size_t len = 0;
    int rc = nodus_t1_nodes_found(1, &peer, 1, buf, sizeof(buf), &len);
    ASSERT(rc == 0, "encode failed");

    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = nodus_t1_decode(buf, len, &msg);
    ASSERT(rc == 0, "decode failed");
    ASSERT(msg.peer_count == 1, "wrong count");

    /* Pubkey should be all zeros */
    bool all_zero = true;
    for (int b = 0; b < NODUS_PK_BYTES; b++) {
        if (msg.peers[0].pubkey.bytes[b] != 0) { all_zero = false; break; }
    }
    ASSERT(all_zero, "v1 peer should have no pubkey");

    nodus_t1_msg_free(&msg);
    PASS();
}

/* ── Test 10: Message size comparison ────────────────────────────── */

static void test_message_sizes(void) {
    TEST("v2 message sizes (with/without pubkey)");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    /* v1 PING */
    uint8_t v1_buf[256];
    size_t v1_len = 0;
    nodus_t1_ping(1, &id.node_id, v1_buf, sizeof(v1_buf), &v1_len);

    /* v2 PING with pubkey */
    uint8_t *v2_full = malloc(16384);
    size_t v2_full_len = 0;
    nodus_t1_ping_v2(1, &id.node_id, &id.pk, &id.sk, true,
                      v2_full, 16384, &v2_full_len);

    /* v2 PING without pubkey (cached) */
    uint8_t *v2_cached = malloc(16384);
    size_t v2_cached_len = 0;
    nodus_t1_ping_v2(1, &id.node_id, &id.pk, &id.sk, false,
                      v2_cached, 16384, &v2_cached_len);

    printf("\n    v1 PING: %zu bytes, v2+pk: %zu bytes, v2 cached: %zu bytes ... ",
           v1_len, v2_full_len, v2_cached_len);

    /* Sanity checks */
    ASSERT(v1_len < 200, "v1 too large");
    ASSERT(v2_full_len > 7000, "v2+pk should be >7KB (Dilithium5)");
    ASSERT(v2_full_len < 10000, "v2+pk should be <10KB");
    ASSERT(v2_cached_len > 4500, "v2 cached should be >4.5KB (sig only)");
    ASSERT(v2_cached_len < 6000, "v2 cached should be <6KB");
    ASSERT(v2_cached_len < v2_full_len, "cached should be smaller");

    free(v2_full);
    free(v2_cached);
    PASS();
}

int main(void) {
    printf("\n=== CRIT-2/CRIT-3: UDP Dilithium5 Authentication Tests ===\n\n");

    test_ping_v2_with_pubkey();
    test_pong_v2_with_pubkey();
    test_node_id_verification();
    test_ping_v2_no_pubkey();
    test_v1_backward_compat();
    test_invalid_signature_rejection();
    test_wrong_key_rejection();
    test_nodes_found_v2_with_pubkeys();
    test_nodes_found_v1_compat();
    test_message_sizes();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
