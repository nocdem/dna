/**
 * Nodus — Tier 2 Protocol Tests
 *
 * Tests encode/decode roundtrips for Client-Nodus messages.
 */

#include "protocol/nodus_tier2.h"
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

/* Large buffer for protocol messages (pubkeys are 2592 bytes) */
static uint8_t msgbuf[32768];

static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static void test_hello_roundtrip(void) {
    TEST("hello encode/decode");
    size_t len = 0;
    int rc = nodus_t2_hello(1, &test_id.pk, &test_id.node_id,
                             msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 1 && msg.type == 'q' &&
        strcmp(msg.method, "hello") == 0 &&
        memcmp(msg.pk.bytes, test_id.pk.bytes, NODUS_PK_BYTES) == 0 &&
        nodus_key_cmp(&msg.fp, &test_id.node_id) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_challenge_roundtrip(void) {
    TEST("challenge encode/decode");
    uint8_t nonce[NODUS_NONCE_LEN];
    memset(nonce, 0xAA, sizeof(nonce));

    size_t len = 0;
    nodus_t2_challenge(1, nonce, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 1 && msg.type == 'r' &&
        strcmp(msg.method, "challenge") == 0 &&
        memcmp(msg.nonce, nonce, NODUS_NONCE_LEN) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_auth_roundtrip(void) {
    TEST("auth encode/decode");
    /* Sign a nonce (C2: domain-tagged AUTH_CHALLENGE) */
    uint8_t nonce[NODUS_NONCE_LEN];
    memset(nonce, 0xBB, sizeof(nonce));
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, nonce, &test_id.sk);

    size_t len = 0;
    nodus_t2_auth(2, &sig, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 2 && strcmp(msg.method, "auth") == 0 &&
        memcmp(msg.sig.bytes, sig.bytes, NODUS_SIG_BYTES) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_auth_ok_roundtrip(void) {
    TEST("auth_ok encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xCC, sizeof(token));

    size_t len = 0;
    nodus_t2_auth_ok(2, token, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 2 && strcmp(msg.method, "auth_ok") == 0 &&
        msg.has_token &&
        memcmp(msg.token, token, NODUS_SESSION_TOKEN_LEN) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_put_roundtrip(void) {
    TEST("put encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xDD, sizeof(token));

    nodus_key_t key;
    nodus_hash((const uint8_t *)"test:key", 8, &key);

    const uint8_t data[] = "test payload data";
    nodus_sig_t sig;
    memset(&sig, 0xEE, sizeof(sig));

    size_t len = 0;
    int rc = nodus_t2_put(10, token, &key, data, sizeof(data) - 1,
                           NODUS_VALUE_EPHEMERAL, 3600, 1, 5, &sig,
                           msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 10 && strcmp(msg.method, "put") == 0 &&
        msg.has_token &&
        nodus_key_cmp(&msg.key, &key) == 0 &&
        msg.data_len == sizeof(data) - 1 &&
        memcmp(msg.data, data, msg.data_len) == 0 &&
        msg.val_type == NODUS_VALUE_EPHEMERAL &&
        msg.ttl == 3600 && msg.vid == 1 && msg.seq == 5) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_get_roundtrip(void) {
    TEST("get encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x11, sizeof(token));

    nodus_key_t key;
    memset(key.bytes, 0x55, NODUS_KEY_BYTES);

    size_t len = 0;
    nodus_t2_get(20, token, &key, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 20 && strcmp(msg.method, "get") == 0 &&
        nodus_key_cmp(&msg.key, &key) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_listen_roundtrip(void) {
    TEST("listen encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x22, sizeof(token));

    nodus_key_t key;
    memset(key.bytes, 0x66, NODUS_KEY_BYTES);

    size_t len = 0;
    nodus_t2_listen(30, token, &key, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 30 && strcmp(msg.method, "listen") == 0 &&
        nodus_key_cmp(&msg.key, &key) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_error_roundtrip(void) {
    TEST("error encode/decode");
    size_t len = 0;
    nodus_t2_error(40, NODUS_ERR_NOT_FOUND, "key not found",
                    msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 40 && msg.type == 'e' &&
        msg.error_code == NODUS_ERR_NOT_FOUND &&
        strcmp(msg.error_msg, "key not found") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_result_with_value(void) {
    TEST("result with value encode/decode");

    nodus_key_t key;
    nodus_hash((const uint8_t *)"test:result", 11, &key);

    nodus_value_t *val = NULL;
    nodus_value_create(&key, (const uint8_t *)"result data", 11,
                        NODUS_VALUE_PERMANENT, 0, 1, 3, &test_id.pk, &val);
    nodus_value_sign(val, &test_id.sk);

    size_t len = 0;
    int rc = nodus_t2_result(50, val, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); nodus_value_free(val); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 50 && msg.value != NULL &&
        msg.value->data_len == 11 &&
        memcmp(msg.value->data, "result data", 11) == 0 &&
        msg.value->seq == 3) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }

    nodus_value_free(val);
    nodus_t2_msg_free(&msg);
}

static void test_get_batch_roundtrip(void) {
    TEST("get_batch request encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xCC, sizeof(token));

    nodus_key_t keys[3];
    nodus_hash((const uint8_t *)"key:0", 5, &keys[0]);
    nodus_hash((const uint8_t *)"key:1", 5, &keys[1]);
    nodus_hash((const uint8_t *)"key:2", 5, &keys[2]);

    size_t len = 0;
    int rc = nodus_t2_get_batch(70, token, keys, 3,
                                 msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 70 && msg.type == 'q' &&
        strcmp(msg.method, "get_batch") == 0 &&
        msg.batch_key_count == 3 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[2], &keys[2]) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_get_batch_result_roundtrip(void) {
    TEST("get_batch result encode/decode");

    nodus_key_t keys[2];
    nodus_hash((const uint8_t *)"bk:0", 4, &keys[0]);
    nodus_hash((const uint8_t *)"bk:1", 4, &keys[1]);

    /* Create test values for key 0 (2 values) and key 1 (1 value) */
    nodus_value_t *v0a = NULL, *v0b = NULL, *v1a = NULL;
    nodus_value_create(&keys[0], (const uint8_t *)"val0a", 5,
                        NODUS_VALUE_PERMANENT, 0, 1, 1, &test_id.pk, &v0a);
    nodus_value_sign(v0a, &test_id.sk);
    nodus_value_create(&keys[0], (const uint8_t *)"val0b", 5,
                        NODUS_VALUE_PERMANENT, 0, 2, 1, &test_id.pk, &v0b);
    nodus_value_sign(v0b, &test_id.sk);
    nodus_value_create(&keys[1], (const uint8_t *)"val1a", 5,
                        NODUS_VALUE_PERMANENT, 0, 3, 1, &test_id.pk, &v1a);
    nodus_value_sign(v1a, &test_id.sk);

    nodus_value_t *k0_vals[] = {v0a, v0b};
    nodus_value_t *k1_vals[] = {v1a};
    nodus_value_t **vals_per_key[] = {k0_vals, k1_vals};
    size_t counts[] = {2, 1};

    size_t len = 0;
    int rc = nodus_t2_result_get_batch(71, keys, 2, vals_per_key, counts,
                                        msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) {
        FAIL("encode");
        nodus_value_free(v0a); nodus_value_free(v0b); nodus_value_free(v1a);
        return;
    }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.batch_key_count == 2 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0 &&
        msg.batch_val_counts[0] == 2 &&
        msg.batch_val_counts[1] == 1 &&
        msg.batch_vals[0][0]->data_len == 5 &&
        memcmp(msg.batch_vals[0][0]->data, "val0a", 5) == 0 &&
        msg.batch_vals[1][0]->data_len == 5 &&
        memcmp(msg.batch_vals[1][0]->data, "val1a", 5) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }

    nodus_value_free(v0a); nodus_value_free(v0b); nodus_value_free(v1a);
    nodus_t2_msg_free(&msg);
}

static void test_count_batch_roundtrip(void) {
    TEST("count_batch request encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xDD, sizeof(token));

    nodus_key_t keys[2];
    nodus_hash((const uint8_t *)"cnt:0", 5, &keys[0]);
    nodus_hash((const uint8_t *)"cnt:1", 5, &keys[1]);

    nodus_key_t caller_fp;
    nodus_hash((const uint8_t *)"caller", 6, &caller_fp);

    size_t len = 0;
    int rc = nodus_t2_count_batch(80, token, keys, 2, &caller_fp,
                                   msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 80 && msg.type == 'q' &&
        strcmp(msg.method, "cnt_batch") == 0 &&
        msg.batch_key_count == 2 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0 &&
        nodus_key_cmp(&msg.fp, &caller_fp) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_count_batch_result_roundtrip(void) {
    TEST("count_batch result encode/decode");

    nodus_key_t keys[3];
    nodus_hash((const uint8_t *)"cr:0", 4, &keys[0]);
    nodus_hash((const uint8_t *)"cr:1", 4, &keys[1]);
    nodus_hash((const uint8_t *)"cr:2", 4, &keys[2]);

    size_t counts[] = {42, 0, 7};
    bool has_mine[] = {true, false, true};

    size_t len = 0;
    int rc = nodus_t2_result_count_batch(81, keys, 3, counts, has_mine,
                                          msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.batch_key_count == 3 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[2], &keys[2]) == 0 &&
        msg.batch_counts[0] == 42 &&
        msg.batch_counts[1] == 0 &&
        msg.batch_counts[2] == 7 &&
        msg.batch_has_mine[0] == true &&
        msg.batch_has_mine[1] == false &&
        msg.batch_has_mine[2] == true) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_pong_roundtrip(void) {
    TEST("pong encode/decode");
    size_t len = 0;
    nodus_t2_pong(60, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 60 && msg.type == 'r' &&
        strcmp(msg.method, "pong") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

int main(void) {
    printf("=== Nodus Tier 2 Protocol Tests ===\n");
    init_test_identity();

    test_hello_roundtrip();
    test_challenge_roundtrip();
    test_auth_roundtrip();
    test_auth_ok_roundtrip();
    test_put_roundtrip();
    test_get_roundtrip();
    test_listen_roundtrip();
    test_error_roundtrip();
    test_result_with_value();
    test_get_batch_roundtrip();
    test_get_batch_result_roundtrip();
    test_count_batch_roundtrip();
    test_count_batch_result_roundtrip();
    test_pong_roundtrip();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    nodus_identity_clear(&test_id);
    return failed > 0 ? 1 : 0;
}
