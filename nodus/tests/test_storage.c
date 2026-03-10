/**
 * Nodus — SQLite Storage Tests
 */

#include "core/nodus_storage.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static const char *TEST_DB = "/tmp/nodus_test_storage.db";
static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static nodus_value_t *make_test_value(const char *key_str, const char *data_str,
                                       uint64_t vid, uint64_t seq, uint32_t ttl) {
    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key_hash);

    nodus_value_type_t type = (ttl == 0) ? NODUS_VALUE_PERMANENT : NODUS_VALUE_EPHEMERAL;
    nodus_value_t *val = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)data_str, strlen(data_str),
                       type, ttl, vid, seq, &test_id.pk, &val);
    nodus_value_sign(val, &test_id.sk);
    return val;
}

static void test_open_close(void) {
    TEST("open and close database");
    unlink(TEST_DB);

    nodus_storage_t store;
    int rc = nodus_storage_open(TEST_DB, &store);
    if (rc == 0) {
        nodus_storage_close(&store);
        PASS();
    } else {
        FAIL("open failed");
    }
    unlink(TEST_DB);
}

static void test_put_get(void) {
    TEST("put and get value");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *val = make_test_value("test:key1", "hello storage", 1, 0, NODUS_DEFAULT_TTL);
    int rc = nodus_storage_put(&store, val);
    if (rc != 0) {
        FAIL("put failed");
        nodus_value_free(val);
        nodus_storage_close(&store);
        unlink(TEST_DB);
        return;
    }

    nodus_value_t *got = NULL;
    rc = nodus_storage_get(&store, &val->key_hash, &got);
    if (rc == 0 && got != NULL &&
        got->data_len == 13 &&
        memcmp(got->data, "hello storage", 13) == 0 &&
        got->value_id == 1) {
        PASS();
    } else {
        FAIL("get didn't return correct value");
    }

    nodus_value_free(val);
    nodus_value_free(got);
    nodus_storage_close(&store);
    unlink(TEST_DB);
}

static void test_put_replace(void) {
    TEST("put replaces on same key+owner+vid");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *v1 = make_test_value("test:replace", "version1", 1, 0, NODUS_DEFAULT_TTL);
    nodus_storage_put(&store, v1);

    nodus_value_t *v2 = make_test_value("test:replace", "version2", 1, 1, NODUS_DEFAULT_TTL);
    nodus_storage_put(&store, v2);

    /* Should only have 1 value, the latest */
    int count = nodus_storage_count(&store);
    nodus_value_t *got = NULL;
    nodus_storage_get(&store, &v2->key_hash, &got);

    if (count == 1 && got != NULL &&
        memcmp(got->data, "version2", 8) == 0) {
        PASS();
    } else {
        FAIL("replace didn't work");
    }

    nodus_value_free(v1);
    nodus_value_free(v2);
    nodus_value_free(got);
    nodus_storage_close(&store);
    unlink(TEST_DB);
}

static void test_get_all_multiwriter(void) {
    TEST("get_all returns multi-writer values");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    /* Value from identity 1 */
    nodus_value_t *v1 = make_test_value("test:multi", "from_owner1", 1, 0, NODUS_DEFAULT_TTL);
    nodus_storage_put(&store, v1);

    /* Value from identity 2 (different owner) */
    uint8_t seed2[32];
    memset(seed2, 0x99, sizeof(seed2));
    nodus_identity_t id2;
    nodus_identity_from_seed(seed2, &id2);

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:multi", 10, &key_hash);
    nodus_value_t *v2 = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)"from_owner2", 11,
                       NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                       1, 0, &id2.pk, &v2);
    nodus_value_sign(v2, &id2.sk);
    nodus_storage_put(&store, v2);

    /* Get all */
    nodus_value_t **vals = NULL;
    size_t count = 0;
    int rc = nodus_storage_get_all(&store, &key_hash, &vals, &count);

    if (rc == 0 && count == 2) {
        PASS();
    } else {
        FAIL("expected 2 values from different owners");
    }

    for (size_t i = 0; i < count; i++)
        nodus_value_free(vals[i]);
    free(vals);
    nodus_value_free(v1);
    nodus_value_free(v2);
    nodus_identity_clear(&id2);
    nodus_storage_close(&store);
    unlink(TEST_DB);
}

static void test_delete(void) {
    TEST("delete specific value");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *val = make_test_value("test:del", "delete me", 1, 0, NODUS_DEFAULT_TTL);
    nodus_storage_put(&store, val);

    nodus_storage_delete(&store, &val->key_hash, &val->owner_fp, val->value_id);

    int count = nodus_storage_count(&store);
    if (count == 0) {
        PASS();
    } else {
        FAIL("delete didn't work");
    }

    nodus_value_free(val);
    nodus_storage_close(&store);
    unlink(TEST_DB);
}

static void test_cleanup_expired(void) {
    TEST("cleanup removes expired values");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    /* Create a value with TTL=1 second and set created_at in the past */
    nodus_value_t *val = make_test_value("test:expire", "temporary", 1, 0, 1);
    /* Override timestamps to simulate expiry */
    val->created_at = 1000;
    val->expires_at = 1001;
    nodus_value_sign(val, &test_id.sk);
    nodus_storage_put(&store, val);

    /* Also add a permanent value that should survive */
    nodus_value_t *perm = make_test_value("test:perm", "forever", 1, 0, 0);
    nodus_storage_put(&store, perm);

    int cleaned = nodus_storage_cleanup(&store);
    int remaining = nodus_storage_count(&store);

    if (cleaned == 1 && remaining == 1) {
        PASS();
    } else {
        FAIL("cleanup wrong");
    }

    nodus_value_free(val);
    nodus_value_free(perm);
    nodus_storage_close(&store);
    unlink(TEST_DB);
}

static void test_count(void) {
    TEST("count values");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    for (int i = 0; i < 5; i++) {
        char key[32];
        snprintf(key, sizeof(key), "test:count:%d", i);
        nodus_value_t *val = make_test_value(key, "data", 1, 0, NODUS_DEFAULT_TTL);
        nodus_storage_put(&store, val);
        nodus_value_free(val);
    }

    int count = nodus_storage_count(&store);
    if (count == 5) {
        PASS();
    } else {
        FAIL("wrong count");
    }

    nodus_storage_close(&store);
    unlink(TEST_DB);
}

static void test_persistence(void) {
    TEST("values persist across close/reopen");
    unlink(TEST_DB);

    /* Write */
    {
        nodus_storage_t store;
        nodus_storage_open(TEST_DB, &store);
        nodus_value_t *val = make_test_value("test:persist", "survives", 1, 0, NODUS_DEFAULT_TTL);
        nodus_storage_put(&store, val);
        nodus_value_free(val);
        nodus_storage_close(&store);
    }

    /* Read */
    {
        nodus_storage_t store;
        nodus_storage_open(TEST_DB, &store);
        nodus_key_t key;
        nodus_hash((const uint8_t *)"test:persist", 12, &key);
        nodus_value_t *got = NULL;
        int rc = nodus_storage_get(&store, &key, &got);
        if (rc == 0 && got && memcmp(got->data, "survives", 8) == 0) {
            PASS();
        } else {
            FAIL("data didn't persist");
        }
        nodus_value_free(got);
        nodus_storage_close(&store);
    }

    unlink(TEST_DB);
}

int main(void) {
    printf("=== Nodus Storage Tests ===\n");
    init_test_identity();

    test_open_close();
    test_put_get();
    test_put_replace();
    test_get_all_multiwriter();
    test_delete();
    test_cleanup_expired();
    test_count();
    test_persistence();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    nodus_identity_clear(&test_id);
    return failed > 0 ? 1 : 0;
}
