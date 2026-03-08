/**
 * Nodus v5 — Storage Fetch Batch Tests
 *
 * Validates bookmark pagination for republish:
 * - First batch (NULL bookmark) starts from beginning
 * - Subsequent batches use last key_hash as bookmark
 * - Returns fewer than batch_size at end of data
 * - Empty database returns 0
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

static const char *TEST_DB = "/tmp/nodus_test_fetch_batch.db";
static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static nodus_value_t *make_value(const char *key_str, const char *data_str,
                                  uint64_t vid, uint64_t seq) {
    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key_hash);

    nodus_value_t *val = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)data_str, strlen(data_str),
                       NODUS_VALUE_PERMANENT, 0, vid, seq, &test_id.pk, &val);
    nodus_value_sign(val, &test_id.sk);
    return val;
}

static void test_empty_database(void) {
    TEST("fetch from empty database returns 0");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_value_t *batch[5];
    int fetched = nodus_storage_fetch_batch(&store, NULL, batch, 5);

    if (fetched == 0)
        PASS();
    else
        FAIL("should return 0 for empty db");

    nodus_storage_close(&store);
}

static void test_first_batch(void) {
    TEST("first batch (NULL bookmark) returns data");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    /* Insert 3 values with different keys */
    for (int i = 0; i < 3; i++) {
        char key[16], data[16];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(data, sizeof(data), "data_%d", i);
        nodus_value_t *v = make_value(key, data, (uint64_t)i, 1);
        nodus_storage_put(&store, v);
        nodus_value_free(v);
    }

    nodus_value_t *batch[5];
    int fetched = nodus_storage_fetch_batch(&store, NULL, batch, 5);

    if (fetched == 3) {
        PASS();
        for (int i = 0; i < fetched; i++)
            nodus_value_free(batch[i]);
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected 3, got %d", fetched);
        FAIL(buf);
    }

    nodus_storage_close(&store);
}

static void test_pagination(void) {
    TEST("bookmark pagination across batches");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    /* Insert 7 values */
    for (int i = 0; i < 7; i++) {
        char key[16], data[16];
        snprintf(key, sizeof(key), "k%d", i);
        snprintf(data, sizeof(data), "d%d", i);
        nodus_value_t *v = make_value(key, data, (uint64_t)i, 1);
        nodus_storage_put(&store, v);
        nodus_value_free(v);
    }

    /* Fetch in batches of 3 */
    int total = 0;
    nodus_key_t *bookmark = NULL;
    nodus_key_t last_key;

    for (int round = 0; round < 5; round++) {
        nodus_value_t *batch[3];
        int fetched = nodus_storage_fetch_batch(&store, bookmark, batch, 3);
        if (fetched == 0) break;

        total += fetched;
        last_key = batch[fetched - 1]->key_hash;
        bookmark = &last_key;

        for (int i = 0; i < fetched; i++)
            nodus_value_free(batch[i]);

        if (fetched < 3) break;  /* End of data */
    }

    if (total == 7)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected 7 total, got %d", total);
        FAIL(buf);
    }

    nodus_storage_close(&store);
}

static void test_batch_ordering(void) {
    TEST("batch returns values ordered by key_hash");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    /* Insert 5 values */
    for (int i = 0; i < 5; i++) {
        char key[16], data[16];
        snprintf(key, sizeof(key), "order_%d", i);
        snprintf(data, sizeof(data), "data_%d", i);
        nodus_value_t *v = make_value(key, data, (uint64_t)i, 1);
        nodus_storage_put(&store, v);
        nodus_value_free(v);
    }

    nodus_value_t *batch[5];
    int fetched = nodus_storage_fetch_batch(&store, NULL, batch, 5);

    bool ordered = true;
    for (int i = 1; i < fetched; i++) {
        if (nodus_key_cmp(&batch[i-1]->key_hash, &batch[i]->key_hash) >= 0) {
            ordered = false;
            break;
        }
    }

    if (fetched == 5 && ordered)
        PASS();
    else
        FAIL("values not ordered by key_hash");

    for (int i = 0; i < fetched; i++)
        nodus_value_free(batch[i]);
    nodus_storage_close(&store);
}

int main(void) {
    printf("=== Nodus Fetch Batch Tests ===\n");
    init_test_identity();

    test_empty_database();
    test_first_batch();
    test_pagination();
    test_batch_ordering();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
