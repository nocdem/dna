/**
 * Nodus v5 — NodusValue Tests
 *
 * Tests create, sign, verify, serialize/deserialize roundtrip.
 */

#include "core/nodus_value.h"
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

static nodus_identity_t test_id;
static bool id_initialized = false;

static void init_test_identity(void) {
    if (id_initialized) return;
    /* Deterministic seed for reproducible tests */
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    if (nodus_identity_from_seed(seed, &test_id) != 0) {
        fprintf(stderr, "FATAL: failed to create test identity\n");
        exit(1);
    }
    id_initialized = true;
}

static void test_create_ephemeral(void) {
    TEST("create ephemeral value");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:key", 8, &key_hash);

    const uint8_t data[] = "hello nodus";
    nodus_value_t *val = NULL;

    int rc = nodus_value_create(&key_hash, data, sizeof(data) - 1,
                                NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                                1, 0, &test_id.pk, &val);
    if (rc == 0 && val != NULL &&
        val->type == NODUS_VALUE_EPHEMERAL &&
        val->data_len == 11 &&
        memcmp(val->data, "hello nodus", 11) == 0 &&
        val->ttl == NODUS_DEFAULT_TTL &&
        val->expires_at > 0) {
        PASS();
    } else {
        FAIL("create failed or wrong values");
    }
    nodus_value_free(val);
}

static void test_create_permanent(void) {
    TEST("create permanent value");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:perm", 9, &key_hash);

    const uint8_t data[] = "permanent";
    nodus_value_t *val = NULL;

    int rc = nodus_value_create(&key_hash, data, 9,
                                NODUS_VALUE_PERMANENT, 0,
                                1, 0, &test_id.pk, &val);
    if (rc == 0 && val != NULL &&
        val->type == NODUS_VALUE_PERMANENT &&
        val->expires_at == 0) {
        PASS();
    } else {
        FAIL("create permanent failed");
    }
    nodus_value_free(val);
}

static void test_sign_verify(void) {
    TEST("sign and verify value");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:sign", 9, &key_hash);

    const uint8_t data[] = "signed data";
    nodus_value_t *val = NULL;

    nodus_value_create(&key_hash, data, 11,
                       NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                       1, 0, &test_id.pk, &val);

    int sign_rc = nodus_value_sign(val, &test_id.sk);
    if (sign_rc != 0) {
        FAIL("sign failed");
        nodus_value_free(val);
        return;
    }

    int verify_rc = nodus_value_verify(val);
    if (verify_rc == 0) {
        PASS();
    } else {
        FAIL("verify failed");
    }
    nodus_value_free(val);
}

static void test_verify_tampered(void) {
    TEST("reject tampered value");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:tamper", 11, &key_hash);

    const uint8_t data[] = "original";
    nodus_value_t *val = NULL;

    nodus_value_create(&key_hash, data, 8,
                       NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                       1, 0, &test_id.pk, &val);

    nodus_value_sign(val, &test_id.sk);

    /* Tamper with data */
    val->data[0] = 'X';

    int verify_rc = nodus_value_verify(val);
    if (verify_rc != 0) {
        PASS();
    } else {
        FAIL("should reject tampered value");
    }
    nodus_value_free(val);
}

static void test_serialize_deserialize(void) {
    TEST("serialize/deserialize roundtrip");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:serde", 10, &key_hash);

    const uint8_t data[] = "roundtrip test data";
    nodus_value_t *val = NULL;

    nodus_value_create(&key_hash, data, sizeof(data) - 1,
                       NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                       42, 7, &test_id.pk, &val);
    nodus_value_sign(val, &test_id.sk);

    /* Serialize */
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    int rc = nodus_value_serialize(val, &buf, &buf_len);
    if (rc != 0 || buf == NULL) {
        FAIL("serialize failed");
        nodus_value_free(val);
        return;
    }

    /* Deserialize */
    nodus_value_t *val2 = NULL;
    rc = nodus_value_deserialize(buf, buf_len, &val2);
    if (rc != 0 || val2 == NULL) {
        FAIL("deserialize failed");
        free(buf);
        nodus_value_free(val);
        return;
    }

    /* Compare */
    bool match = true;
    match &= (nodus_key_cmp(&val->key_hash, &val2->key_hash) == 0);
    match &= (val->value_id == val2->value_id);
    match &= (val->data_len == val2->data_len);
    match &= (val->data_len > 0 && memcmp(val->data, val2->data, val->data_len) == 0);
    match &= (val->type == val2->type);
    match &= (val->ttl == val2->ttl);
    match &= (val->seq == val2->seq);
    match &= (memcmp(val->owner_pk.bytes, val2->owner_pk.bytes, NODUS_PK_BYTES) == 0);
    match &= (memcmp(val->signature.bytes, val2->signature.bytes, NODUS_SIG_BYTES) == 0);

    if (match) {
        /* Verify deserialized value's signature */
        if (nodus_value_verify(val2) == 0)
            PASS();
        else
            FAIL("deserialized value fails signature check");
    } else {
        FAIL("field mismatch after roundtrip");
    }

    free(buf);
    nodus_value_free(val);
    nodus_value_free(val2);
}

static void test_expiry(void) {
    TEST("value expiry check");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:expiry", 11, &key_hash);

    nodus_value_t *val = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)"x", 1,
                       NODUS_VALUE_EPHEMERAL, 60, /* 60 seconds TTL */
                       1, 0, &test_id.pk, &val);

    /* Should not be expired at creation time */
    bool expired_now = nodus_value_is_expired(val, val->created_at);

    /* Should be expired 61 seconds later */
    bool expired_later = nodus_value_is_expired(val, val->created_at + 61);

    /* Permanent values never expire */
    nodus_value_t *pval = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)"p", 1,
                       NODUS_VALUE_PERMANENT, 0,
                       1, 0, &test_id.pk, &pval);
    bool perm_expired = nodus_value_is_expired(pval, val->created_at + 999999);

    if (!expired_now && expired_later && !perm_expired) {
        PASS();
    } else {
        FAIL("expiry logic wrong");
    }

    nodus_value_free(val);
    nodus_value_free(pval);
}

static void test_empty_data(void) {
    TEST("value with empty data (tombstone)");
    init_test_identity();

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:empty", 10, &key_hash);

    nodus_value_t *val = NULL;
    int rc = nodus_value_create(&key_hash, NULL, 0,
                                NODUS_VALUE_PERMANENT, 0,
                                1, 0, &test_id.pk, &val);
    if (rc != 0) {
        FAIL("create with empty data failed");
        return;
    }

    /* Sign and verify empty data */
    nodus_value_sign(val, &test_id.sk);
    if (nodus_value_verify(val) == 0 && val->data_len == 0) {
        PASS();
    } else {
        FAIL("empty data sign/verify failed");
    }
    nodus_value_free(val);
}

int main(void) {
    printf("=== Nodus Value Tests ===\n");

    test_create_ephemeral();
    test_create_permanent();
    test_sign_verify();
    test_verify_tampered();
    test_serialize_deserialize();
    test_expiry();
    test_empty_data();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    nodus_identity_clear(&test_id);
    return failed > 0 ? 1 : 0;
}
