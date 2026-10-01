/**
 * Nodus — nodus_storage_put refuses a stale seq (DHT Package A, F7)
 *
 * Proves: for the same (key, owner, value_id) a PUT whose seq is STRICTLY
 * lower than the stored row's is refused with -4 and the stored row is kept;
 * an equal seq replaces (today's behaviour, TTL refreshed); a higher seq
 * replaces; a different value_id of the same owner is independent; the
 * EXCLUSIVE lock check (-2) still runs first, so a foreign owner gets -2
 * even with a lower seq.
 *
 * Requires: default build. Leaves behind: nothing (fixture DB unlinked).
 * How it can lie: none known — every case reads the row back.
 */

#include "core/nodus_storage.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "test_storage_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t id_a;
static nodus_identity_t id_b;

static void init_ids(void) {
    uint8_t seed[32];
    memset(seed, 0x61, sizeof(seed));
    nodus_identity_from_seed(seed, &id_a);
    memset(seed, 0x62, sizeof(seed));
    nodus_identity_from_seed(seed, &id_b);
}

static nodus_value_t *make_val(const nodus_identity_t *id, const char *key_str,
                               const char *data, nodus_value_type_t type,
                               uint64_t vid, uint64_t seq) {
    nodus_key_t kh;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &kh);
    uint32_t ttl = (type == NODUS_VALUE_EPHEMERAL) ? 3600 : 0;
    nodus_value_t *v = NULL;
    if (nodus_value_create(&kh, (const uint8_t *)data, strlen(data), type, ttl,
                           vid, seq, &id->pk, &v) != 0)
        return NULL;
    if (nodus_value_sign(v, &id->sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

static int put_free(nodus_storage_t *st, nodus_value_t *v) {
    if (!v) return -100;
    int rc = nodus_storage_put(st, v);
    nodus_value_free(v);
    return rc;
}

/* Read the owner's row back; returns seq or 0 if absent, data copied out. */
static uint64_t stored_seq(nodus_storage_t *st, const nodus_identity_t *id,
                           const char *key_str, char *data_out, size_t cap) {
    nodus_key_t kh;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &kh);
    nodus_key_t fp;
    nodus_fingerprint(&id->pk, &fp);
    nodus_value_t *got = NULL;
    if (nodus_storage_get_owner(st, &kh, &fp, &got) != 0 || !got) return 0;
    uint64_t seq = got->seq;
    if (data_out && cap) {
        size_t n = got->data_len < cap - 1 ? got->data_len : cap - 1;
        memcpy(data_out, got->data, n);
        data_out[n] = '\0';
    }
    nodus_value_free(got);
    return seq;
}

static void test_lower_seq_refused(void) {
    TEST("seq 5 stored, then seq 3 -> -4, row unchanged");
    nodus_storage_t st;
    test_storage_open(&st);
    int rc1 = put_free(&st, make_val(&id_a, "k-stale", "five", NODUS_VALUE_EPHEMERAL, 1, 5));
    int rc2 = put_free(&st, make_val(&id_a, "k-stale", "three", NODUS_VALUE_EPHEMERAL, 1, 3));
    char d[16] = {0};
    uint64_t seq = stored_seq(&st, &id_a, "k-stale", d, sizeof(d));
    if (rc1 == 0 && rc2 == -4 && seq == 5 && strcmp(d, "five") == 0) PASS();
    else FAIL("lower seq must be -4 and keep the stored row");
    test_storage_close(&st);
}

static void test_equal_seq_replaces(void) {
    TEST("seq 5 stored, then seq 5 other data -> 0, replaced");
    nodus_storage_t st;
    test_storage_open(&st);
    int rc1 = put_free(&st, make_val(&id_a, "k-eq", "first", NODUS_VALUE_EPHEMERAL, 1, 5));
    int rc2 = put_free(&st, make_val(&id_a, "k-eq", "second", NODUS_VALUE_EPHEMERAL, 1, 5));
    int rc3 = put_free(&st, make_val(&id_a, "k-eq", "second", NODUS_VALUE_EPHEMERAL, 1, 5));
    char d[16] = {0};
    uint64_t seq = stored_seq(&st, &id_a, "k-eq", d, sizeof(d));
    if (rc1 == 0 && rc2 == 0 && rc3 == 0 && seq == 5 && strcmp(d, "second") == 0) PASS();
    else FAIL("equal seq must replace (today's behaviour), identical re-put ok");
    test_storage_close(&st);
}

static void test_higher_seq_replaces(void) {
    TEST("seq 5 stored, then seq 6 -> 0, replaced");
    nodus_storage_t st;
    test_storage_open(&st);
    int rc1 = put_free(&st, make_val(&id_a, "k-hi", "five", NODUS_VALUE_EPHEMERAL, 1, 5));
    int rc2 = put_free(&st, make_val(&id_a, "k-hi", "six", NODUS_VALUE_EPHEMERAL, 1, 6));
    char d[16] = {0};
    uint64_t seq = stored_seq(&st, &id_a, "k-hi", d, sizeof(d));
    if (rc1 == 0 && rc2 == 0 && seq == 6 && strcmp(d, "six") == 0) PASS();
    else FAIL("higher seq must replace");
    test_storage_close(&st);
}

static void test_other_value_id_independent(void) {
    TEST("seq 5 at vid 1; seq 3 at vid 2 (same owner/key) -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int rc1 = put_free(&st, make_val(&id_a, "k-vid", "v1", NODUS_VALUE_EPHEMERAL, 1, 5));
    int rc2 = put_free(&st, make_val(&id_a, "k-vid", "v2", NODUS_VALUE_EPHEMERAL, 2, 3));
    nodus_key_t kh;
    nodus_hash((const uint8_t *)"k-vid", 5, &kh);
    int n = nodus_storage_count_key(&st, &kh);
    if (rc1 == 0 && rc2 == 0 && n == 2) PASS();
    else FAIL("stale check must be scoped to the value_id");
    test_storage_close(&st);
}

static void test_other_owner_independent(void) {
    TEST("A seq 5; B seq 3 at same key/vid (not exclusive) -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int rc1 = put_free(&st, make_val(&id_a, "k-own", "a", NODUS_VALUE_EPHEMERAL, 1, 5));
    int rc2 = put_free(&st, make_val(&id_b, "k-own", "b", NODUS_VALUE_EPHEMERAL, 1, 3));
    if (rc1 == 0 && rc2 == 0) PASS();
    else FAIL("stale check must be scoped to the owner");
    test_storage_close(&st);
}

static void test_lock_before_stale(void) {
    TEST("A EXCLUSIVE seq 5; B seq 3 -> -2 (lock first)");
    nodus_storage_t st;
    test_storage_open(&st);
    int rc1 = put_free(&st, make_val(&id_a, "k-lock", "a", NODUS_VALUE_EXCLUSIVE, 1, 5));
    int rc2 = put_free(&st, make_val(&id_b, "k-lock", "b", NODUS_VALUE_EXCLUSIVE, 1, 3));
    /* the owner's own stale write is -4, not -2 */
    int rc3 = put_free(&st, make_val(&id_a, "k-lock", "a-old", NODUS_VALUE_EXCLUSIVE, 1, 3));
    if (rc1 == 0 && rc2 == -2 && rc3 == -4) PASS();
    else FAIL("foreign owner -2 must keep priority; owner stale -4");
    test_storage_close(&st);
}

int main(void) {
    printf("=== Nodus put stale-seq refusal ===\n");
    init_ids();

    test_lower_seq_refused();
    test_equal_seq_replaces();
    test_higher_seq_replaces();
    test_other_value_id_independent();
    test_other_owner_independent();
    test_lock_before_stale();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
