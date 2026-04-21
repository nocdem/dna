/**
 * Nodus — SQLite Storage Tests
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

    nodus_storage_t store;
    int rc = test_storage_open(&store);
    if (rc == 0) {
        test_storage_close(&store);
        PASS();
    } else {
        FAIL("open failed");
    }
}

static void test_put_get(void) {
    TEST("put and get value");
    nodus_storage_t store;
    test_storage_open(&store);

    nodus_value_t *val = make_test_value("test:key1", "hello storage", 1, 0, NODUS_DEFAULT_TTL);
    int rc = nodus_storage_put(&store, val);
    if (rc != 0) {
        FAIL("put failed");
        nodus_value_free(val);
        test_storage_close(&store);
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
    test_storage_close(&store);
}

static void test_put_replace(void) {
    TEST("put replaces on same key+owner+vid");
    nodus_storage_t store;
    test_storage_open(&store);

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
    test_storage_close(&store);
}

static void test_get_all_multiwriter(void) {
    TEST("get_all returns multi-writer values");
    nodus_storage_t store;
    test_storage_open(&store);

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
    test_storage_close(&store);
}

static void test_get_all_seq_order(void) {
    TEST("get_all returns values in seq DESC order");
    nodus_storage_t store;
    test_storage_open(&store);

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:order", 10, &key_hash);

    /* Put 3 values with different seq; insertion order unrelated to seq. */
    uint64_t seqs[] = {5, 1, 3};
    for (int i = 0; i < 3; i++) {
        nodus_value_t *v = NULL;
        nodus_value_create(&key_hash, (const uint8_t *)"x", 1,
                           NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                           (uint64_t)(i + 1), seqs[i], &test_id.pk, &v);
        nodus_value_sign(v, &test_id.sk);
        nodus_storage_put(&store, v);
        nodus_value_free(v);
    }

    nodus_value_t **vals = NULL;
    size_t count = 0;
    int rc = nodus_storage_get_all(&store, &key_hash, &vals, &count);

    /* Expected: seq=5, 3, 1 (DESC). Deterministic across nodes. */
    if (rc == 0 && count == 3 &&
        vals[0]->seq == 5 && vals[1]->seq == 3 && vals[2]->seq == 1) {
        PASS();
    } else {
        FAIL("ordering wrong");
    }

    for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
    free(vals);
    test_storage_close(&store);
}

static void test_get_all_byte_cap(void) {
    TEST("get_all caps cumulative byte budget at 16MB");
    nodus_storage_t store;
    test_storage_open(&store);

    /* 5 × 3.5 MB = 17.5 MB under same key. Byte cap (16 MB) truncates at 4. */
    const size_t val_size = 3 * 1024 * 1024 + 512 * 1024;  /* 3.5 MB */
    char *big_data = malloc(val_size);
    if (!big_data) { FAIL("malloc"); test_storage_close(&store); return; }
    memset(big_data, 'X', val_size);

    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)"test:bytecap", 12, &key_hash);

    nodus_value_t *vals_in[5] = {0};
    for (int i = 0; i < 5; i++) {
        nodus_value_create(&key_hash, (const uint8_t *)big_data, val_size,
                           NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                           (uint64_t)(100 + i), 0, &test_id.pk, &vals_in[i]);
        nodus_value_sign(vals_in[i], &test_id.sk);
        nodus_storage_put(&store, vals_in[i]);
    }
    free(big_data);

    nodus_value_t **vals = NULL;
    size_t count = 0;
    int rc = nodus_storage_get_all(&store, &key_hash, &vals, &count);

    /* 4 × 3.5MB = 14MB; 5th would push to 17.5MB > 16MB → stop at 4. */
    if (rc == 0 && count == 4) {
        PASS();
    } else {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 4, got %zu", count);
        FAIL(msg);
    }

    for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
    free(vals);
    for (int i = 0; i < 5; i++) nodus_value_free(vals_in[i]);
    test_storage_close(&store);
}

static void test_delete(void) {
    TEST("delete specific value");
    nodus_storage_t store;
    test_storage_open(&store);

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
    test_storage_close(&store);
}

static void test_cleanup_expired(void) {
    TEST("cleanup removes expired values");
    nodus_storage_t store;
    test_storage_open(&store);

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
    test_storage_close(&store);
}

static void test_count(void) {
    TEST("count values");
    nodus_storage_t store;
    test_storage_open(&store);

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

    test_storage_close(&store);
}

static void test_persistence(void) {
    TEST("values persist across close/reopen");

    /* Persistence test needs two open/close cycles on the SAME path,
     * so we manage the path manually instead of using test_storage_open. */
    char path[32];
    if (test_storage_make_path(path, sizeof(path)) != 0) {
        FAIL("mkstemp");
        return;
    }

    /* Write */
    {
        nodus_storage_t store;
        nodus_storage_open(path, &store);
        nodus_value_t *val = make_test_value("test:persist", "survives", 1, 0, NODUS_DEFAULT_TTL);
        nodus_storage_put(&store, val);
        nodus_value_free(val);
        nodus_storage_close(&store);
    }

    /* Read */
    {
        nodus_storage_t store;
        nodus_storage_open(path, &store);
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

    test_storage_cleanup_path(path);
}

/* ── EXCLUSIVE ownership tests ──────────────────────────────────── */

static nodus_value_t *make_exclusive_value(const char *key_str, const char *data_str,
                                            uint64_t vid, uint64_t seq,
                                            nodus_identity_t *id) {
    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key_hash);

    nodus_value_t *val = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)data_str, strlen(data_str),
                       NODUS_VALUE_EXCLUSIVE, 0, vid, seq, &id->pk, &val);
    nodus_value_sign(val, &id->sk);
    return val;
}

static nodus_value_t *make_value_with_identity(const char *key_str, const char *data_str,
                                                nodus_value_type_t type, uint32_t ttl,
                                                uint64_t vid, uint64_t seq,
                                                nodus_identity_t *id) {
    nodus_key_t key_hash;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key_hash);

    nodus_value_t *val = NULL;
    nodus_value_create(&key_hash, (const uint8_t *)data_str, strlen(data_str),
                       type, ttl, vid, seq, &id->pk, &val);
    nodus_value_sign(val, &id->sk);
    return val;
}

static void test_exclusive_first_writer_wins(void) {
    TEST("exclusive: first writer wins");

    nodus_storage_t store;
    nodus_storage_open(":memory:", &store);

    /* Owner A */
    uint8_t seedA[32]; memset(seedA, 0xAA, sizeof(seedA));
    nodus_identity_t idA; nodus_identity_from_seed(seedA, &idA);

    /* Owner B */
    uint8_t seedB[32]; memset(seedB, 0xBB, sizeof(seedB));
    nodus_identity_t idB; nodus_identity_from_seed(seedB, &idB);

    /* Owner A writes EXCLUSIVE */
    nodus_value_t *vA1 = make_exclusive_value("excl:key1", "owner_a_v1", 1, 0, &idA);
    int rc = nodus_storage_put(&store, vA1);
    if (rc != 0) { FAIL("owner A put failed"); goto cleanup_fww; }

    /* Owner B tries EXCLUSIVE on same key → should be rejected */
    nodus_value_t *vB = make_exclusive_value("excl:key1", "owner_b_attempt", 1, 1, &idB);
    rc = nodus_storage_put(&store, vB);
    if (rc != -2) { FAIL("owner B should be rejected with -2"); goto cleanup_fww; }

    /* Owner A can still update */
    nodus_value_t *vA2 = make_exclusive_value("excl:key1", "owner_a_v2", 1, 1, &idA);
    rc = nodus_storage_put(&store, vA2);
    if (rc != 0) { FAIL("owner A update failed"); goto cleanup_fww; }

    /* GET returns owner A's latest value */
    nodus_value_t *got = NULL;
    nodus_storage_get(&store, &vA1->key_hash, &got);
    if (got && got->data_len == 10 && memcmp(got->data, "owner_a_v2", 10) == 0) {
        PASS();
    } else {
        FAIL("GET did not return owner A's latest value");
    }
    nodus_value_free(got);

cleanup_fww:
    nodus_value_free(vA1);
    nodus_value_free(vB);
    nodus_value_free(vA2);
    nodus_identity_clear(&idA);
    nodus_identity_clear(&idB);
    nodus_storage_close(&store);
}

static void test_exclusive_blocks_permanent_bypass(void) {
    TEST("exclusive: blocks PERMANENT bypass");

    nodus_storage_t store;
    nodus_storage_open(":memory:", &store);

    uint8_t seedA[32]; memset(seedA, 0xAA, sizeof(seedA));
    nodus_identity_t idA; nodus_identity_from_seed(seedA, &idA);

    uint8_t seedB[32]; memset(seedB, 0xBB, sizeof(seedB));
    nodus_identity_t idB; nodus_identity_from_seed(seedB, &idB);

    /* Owner A writes EXCLUSIVE */
    nodus_value_t *vA = make_exclusive_value("excl:key2", "owner_a", 1, 0, &idA);
    int rc = nodus_storage_put(&store, vA);
    if (rc != 0) { FAIL("owner A put failed"); goto cleanup_bp; }

    /* Owner B tries PERMANENT with high seq → should be rejected */
    nodus_value_t *vB = make_value_with_identity("excl:key2", "bypass_attempt",
                                                  NODUS_VALUE_PERMANENT, 0,
                                                  1, 999999, &idB);
    rc = nodus_storage_put(&store, vB);
    if (rc != -2) { FAIL("PERMANENT bypass should be rejected with -2"); goto cleanup_bp; }

    /* GET still returns owner A */
    nodus_value_t *got = NULL;
    nodus_storage_get(&store, &vA->key_hash, &got);
    if (got && got->data_len == 7 && memcmp(got->data, "owner_a", 7) == 0) {
        PASS();
    } else {
        FAIL("GET did not return owner A's value");
    }
    nodus_value_free(got);

cleanup_bp:
    nodus_value_free(vA);
    nodus_value_free(vB);
    nodus_identity_clear(&idA);
    nodus_identity_clear(&idB);
    nodus_storage_close(&store);
}

static void test_exclusive_put_if_newer(void) {
    TEST("exclusive: put_if_newer rejects other owner");

    nodus_storage_t store;
    nodus_storage_open(":memory:", &store);

    uint8_t seedA[32]; memset(seedA, 0xAA, sizeof(seedA));
    nodus_identity_t idA; nodus_identity_from_seed(seedA, &idA);

    uint8_t seedB[32]; memset(seedB, 0xBB, sizeof(seedB));
    nodus_identity_t idB; nodus_identity_from_seed(seedB, &idB);

    /* Owner A writes EXCLUSIVE via put() */
    nodus_value_t *vA = make_exclusive_value("excl:key3", "owner_a", 1, 0, &idA);
    int rc = nodus_storage_put(&store, vA);
    if (rc != 0) { FAIL("owner A put failed"); goto cleanup_pin; }

    /* Owner B tries put_if_newer() → should be rejected */
    nodus_value_t *vB = make_exclusive_value("excl:key3", "owner_b_newer", 1, 100, &idB);
    rc = nodus_storage_put_if_newer(&store, vB);
    if (rc != -2) { FAIL("put_if_newer should be rejected with -2"); goto cleanup_pin; }

    PASS();

cleanup_pin:
    nodus_value_free(vA);
    nodus_value_free(vB);
    nodus_identity_clear(&idA);
    nodus_identity_clear(&idB);
    nodus_storage_close(&store);
}

static void test_exclusive_get_priority(void) {
    TEST("exclusive: GET prioritizes EXCLUSIVE over PERMANENT");

    nodus_storage_t store;
    nodus_storage_open(":memory:", &store);

    uint8_t seedA[32]; memset(seedA, 0xAA, sizeof(seedA));
    nodus_identity_t idA; nodus_identity_from_seed(seedA, &idA);

    uint8_t seedB[32]; memset(seedB, 0xBB, sizeof(seedB));
    nodus_identity_t idB; nodus_identity_from_seed(seedB, &idB);

    /* Owner B writes PERMANENT with high seq FIRST (pre-fix attack simulation) */
    nodus_value_t *vB = make_value_with_identity("excl:key4", "attacker_perm",
                                                  NODUS_VALUE_PERMANENT, 0,
                                                  1, 999999, &idB);
    int rc = nodus_storage_put(&store, vB);
    if (rc != 0) { FAIL("owner B permanent put failed"); goto cleanup_gp; }

    /* Owner A writes EXCLUSIVE with low seq */
    nodus_value_t *vA = make_exclusive_value("excl:key4", "real_owner", 1, 100, &idA);
    rc = nodus_storage_put(&store, vA);
    if (rc != 0) { FAIL("owner A exclusive put failed"); goto cleanup_gp; }

    /* GET should return owner A's EXCLUSIVE value (type priority over seq) */
    nodus_value_t *got = NULL;
    nodus_storage_get(&store, &vA->key_hash, &got);
    if (got && got->data_len == 10 && memcmp(got->data, "real_owner", 10) == 0 &&
        got->type == NODUS_VALUE_EXCLUSIVE) {
        PASS();
    } else {
        FAIL("GET did not prioritize EXCLUSIVE over PERMANENT");
    }
    nodus_value_free(got);

cleanup_gp:
    nodus_value_free(vA);
    nodus_value_free(vB);
    nodus_identity_clear(&idA);
    nodus_identity_clear(&idB);
    nodus_storage_close(&store);
}

int main(void) {
    printf("=== Nodus Storage Tests ===\n");
    init_test_identity();

    test_open_close();
    test_put_get();
    test_put_replace();
    test_get_all_multiwriter();
    test_get_all_seq_order();
    test_get_all_byte_cap();
    test_delete();
    test_cleanup_expired();
    test_count();
    test_persistence();
    test_exclusive_first_writer_wins();
    test_exclusive_blocks_permanent_bypass();
    test_exclusive_put_if_newer();
    test_exclusive_get_priority();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    nodus_identity_clear(&test_id);
    return failed > 0 ? 1 : 0;
}
