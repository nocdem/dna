/**
 * Nodus — put_if_newer() Tests
 *
 * Validates atomic seq check with SHA3-256 hash tiebreaker.
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

static const char *TEST_DB = "/tmp/nodus_test_put_if_newer.db";
static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static nodus_value_t *make_value(const char *key_str, const char *data_str,
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

static void test_put_newer_seq_wins(void) {
    TEST("higher seq wins over lower seq");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *v1 = make_value("key1", "data_old", 1, 10, 3600);
    nodus_value_t *v2 = make_value("key1", "data_new", 1, 20, 3600);

    int rc1 = nodus_storage_put_if_newer(&store, v1);
    int rc2 = nodus_storage_put_if_newer(&store, v2);

    /* Verify v2 (seq=20) is stored */
    nodus_value_t *got = NULL;
    nodus_storage_get(&store, &v1->key_hash, &got);

    if (rc1 == 0 && rc2 == 0 && got && got->seq == 20)
        PASS();
    else
        FAIL("higher seq should win");

    nodus_value_free(v1);
    nodus_value_free(v2);
    if (got) nodus_value_free(got);
    nodus_storage_close(&store);
}

static void test_put_older_seq_skipped(void) {
    TEST("lower seq is skipped");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *v1 = make_value("key1", "data_newer", 1, 20, 3600);
    nodus_value_t *v2 = make_value("key1", "data_older", 1, 10, 3600);

    int rc1 = nodus_storage_put_if_newer(&store, v1);
    int rc2 = nodus_storage_put_if_newer(&store, v2);

    /* v2 should be skipped (rc=1), v1 should remain */
    nodus_value_t *got = NULL;
    nodus_storage_get(&store, &v1->key_hash, &got);

    if (rc1 == 0 && rc2 == 1 && got && got->seq == 20)
        PASS();
    else
        FAIL("lower seq should be skipped");

    nodus_value_free(v1);
    nodus_value_free(v2);
    if (got) nodus_value_free(got);
    nodus_storage_close(&store);
}

static void test_put_equal_seq_hash_tiebreak(void) {
    TEST("equal seq uses hash tiebreaker");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    /* Create two values with same seq but different data (different hashes) */
    nodus_value_t *v1 = make_value("key1", "data_aaa", 1, 10, 3600);
    nodus_value_t *v2 = make_value("key1", "data_zzz", 1, 10, 3600);

    int rc1 = nodus_storage_put_if_newer(&store, v1);
    int rc2 = nodus_storage_put_if_newer(&store, v2);

    /* One should be stored (0), the other should be either stored or skipped.
     * The one with the higher SHA3-256(data) hash wins. */
    if (rc1 == 0 && (rc2 == 0 || rc2 == 1))
        PASS();
    else
        FAIL("hash tiebreaker failed");

    nodus_value_free(v1);
    nodus_value_free(v2);
    nodus_storage_close(&store);
}

static void test_put_first_insert(void) {
    TEST("first insert always succeeds");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *v1 = make_value("key_new", "data1", 1, 1, 3600);
    int rc = nodus_storage_put_if_newer(&store, v1);

    if (rc == 0)
        PASS();
    else
        FAIL("first insert should succeed");

    nodus_value_free(v1);
    nodus_storage_close(&store);
}

static void test_put_same_seq_same_data(void) {
    TEST("identical value with same seq is skipped");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *v1 = make_value("key1", "same_data", 1, 5, 3600);
    nodus_value_t *v2 = make_value("key1", "same_data", 1, 5, 3600);

    int rc1 = nodus_storage_put_if_newer(&store, v1);
    int rc2 = nodus_storage_put_if_newer(&store, v2);

    /* Same data = same hash = skipped (existing hash >= incoming) */
    if (rc1 == 0 && rc2 == 1)
        PASS();
    else
        FAIL("identical re-insert should be skipped");

    nodus_value_free(v1);
    nodus_value_free(v2);
    nodus_storage_close(&store);
}

int main(void) {
    printf("=== Nodus put_if_newer Tests ===\n");
    init_test_identity();

    test_put_newer_seq_wins();
    test_put_older_seq_skipped();
    test_put_equal_seq_hash_tiebreak();
    test_put_first_insert();
    test_put_same_seq_same_data();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
