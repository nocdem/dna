/**
 * Nodus — Storage Cleanup Tests
 *
 * Validates:
 * - Expired ephemeral values are cleaned up
 * - Permanent values are NOT cleaned up
 * - Non-expired ephemeral values survive cleanup
 */

#include "core/nodus_storage.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "test_storage_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static nodus_value_t *make_value(const char *key_str, const char *data_str,
                                  uint64_t vid, uint64_t seq,
                                  nodus_value_type_t type, uint32_t ttl) {
    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key_hash);

    nodus_value_t *val = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)data_str, strlen(data_str),
                       type, ttl, vid, seq, &test_id.pk, &val);
    nodus_value_sign(val, &test_id.sk);
    return val;
}

static void test_cleanup_empty_db(void) {
    TEST("cleanup on empty database returns 0");
    nodus_storage_t store;
    test_storage_open(&store);

    int cleaned = nodus_storage_cleanup(&store);
    if (cleaned == 0)
        PASS();
    else
        FAIL("should return 0 for empty db");

    test_storage_close(&store);
}

static void test_permanent_values_survive(void) {
    TEST("permanent values survive cleanup");
    nodus_storage_t store;
    test_storage_open(&store);

    /* Insert permanent values */
    for (int i = 0; i < 3; i++) {
        char key[16], data[16];
        snprintf(key, sizeof(key), "perm_%d", i);
        snprintf(data, sizeof(data), "data_%d", i);
        nodus_value_t *v = make_value(key, data, (uint64_t)i, 1,
                                       NODUS_VALUE_PERMANENT, 0);
        nodus_storage_put(&store, v);
        nodus_value_free(v);
    }

    int cleaned = nodus_storage_cleanup(&store);
    int count = nodus_storage_count(&store);

    if (cleaned == 0 && count == 3)
        PASS();
    else
        FAIL("permanent values should not be cleaned");

    test_storage_close(&store);
}

static void test_fresh_ephemeral_survives(void) {
    TEST("fresh ephemeral values survive cleanup");
    nodus_storage_t store;
    test_storage_open(&store);

    /* Insert ephemeral with long TTL (7 days) */
    nodus_value_t *v = make_value("ephem1", "data", 1, 1,
                                   NODUS_VALUE_EPHEMERAL, 604800);
    nodus_storage_put(&store, v);
    nodus_value_free(v);

    int cleaned = nodus_storage_cleanup(&store);
    int count = nodus_storage_count(&store);

    if (cleaned == 0 && count == 1)
        PASS();
    else
        FAIL("fresh ephemeral should survive");

    test_storage_close(&store);
}

static void test_expired_ephemeral_cleaned(void) {
    TEST("expired ephemeral values are cleaned up");
    nodus_storage_t store;
    test_storage_open(&store);

    /* Insert ephemeral with TTL=1 second */
    nodus_value_t *v = make_value("expire1", "data", 1, 1,
                                   NODUS_VALUE_EPHEMERAL, 1);
    nodus_storage_put(&store, v);
    nodus_value_free(v);

    /* Wait for it to expire */
    sleep(2);

    int cleaned = nodus_storage_cleanup(&store);
    int count = nodus_storage_count(&store);

    if (cleaned == 1 && count == 0)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "cleaned=%d count=%d (expected 1, 0)", cleaned, count);
        FAIL(buf);
    }

    test_storage_close(&store);
}

static void test_mixed_cleanup(void) {
    TEST("mixed: only expired ephemeral cleaned");
    nodus_storage_t store;
    test_storage_open(&store);

    /* 2 permanent */
    for (int i = 0; i < 2; i++) {
        char key[16], data[16];
        snprintf(key, sizeof(key), "perm_%d", i);
        snprintf(data, sizeof(data), "pdata_%d", i);
        nodus_value_t *v = make_value(key, data, (uint64_t)i, 1,
                                       NODUS_VALUE_PERMANENT, 0);
        nodus_storage_put(&store, v);
        nodus_value_free(v);
    }

    /* 1 expired ephemeral */
    nodus_value_t *v_exp = make_value("exp", "edata", 10, 1,
                                       NODUS_VALUE_EPHEMERAL, 1);
    nodus_storage_put(&store, v_exp);
    nodus_value_free(v_exp);

    /* 1 fresh ephemeral */
    nodus_value_t *v_fresh = make_value("fresh", "fdata", 11, 1,
                                         NODUS_VALUE_EPHEMERAL, 604800);
    nodus_storage_put(&store, v_fresh);
    nodus_value_free(v_fresh);

    sleep(2);

    int cleaned = nodus_storage_cleanup(&store);
    int count = nodus_storage_count(&store);

    /* Should clean 1 (expired ephemeral), leave 3 (2 permanent + 1 fresh ephemeral) */
    if (cleaned == 1 && count == 3)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "cleaned=%d count=%d (expected 1, 3)", cleaned, count);
        FAIL(buf);
    }

    test_storage_close(&store);
}

int main(void) {
    printf("=== Nodus Storage Cleanup Tests ===\n");
    init_test_identity();

    test_cleanup_empty_db();
    test_permanent_values_survive();
    test_fresh_ephemeral_survives();
    test_expired_ephemeral_cleaned();
    test_mixed_cleanup();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
