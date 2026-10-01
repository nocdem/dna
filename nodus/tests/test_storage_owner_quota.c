/**
 * Nodus — per-owner BYTE quota (DHT Package A, F5)
 *
 * Proves: one owner cannot hold more than NODUS_STORAGE_OWNER_MAX_BYTES
 * (16 MiB) of value data on a node, through EITHER write path
 * (nodus_storage_put for clients, nodus_storage_put_if_newer for replicas);
 * the quota counts only growth, so a replace that does not grow always
 * passes; another owner is unaffected; a stale replica is still reported
 * as "skipped" (1), not as quota.
 *
 * Requires: default build. Leaves behind: nothing (fixture DB unlinked).
 * How it can lie: if NODUS_STORAGE_OWNER_MAX_BYTES were changed to a value
 * that is not a multiple of CHUNK the boundary cases shift — the fill loop
 * derives its count from the constant and asserts the exact boundary.
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

#define CHUNK (4u * 1024u * 1024u)   /* 4 MiB data per value */
#define N_FILL ((int)(NODUS_STORAGE_OWNER_MAX_BYTES / CHUNK))

static uint8_t *g_buf;   /* CHUNK + 1 bytes, heap */

static void init_ids(void) {
    uint8_t seed[32];
    memset(seed, 0x51, sizeof(seed));
    nodus_identity_from_seed(seed, &id_a);
    memset(seed, 0x52, sizeof(seed));
    nodus_identity_from_seed(seed, &id_b);
}

/* key index → key "quota-key-<i>"; data = g_buf[0..len) with byte `fill` */
static nodus_value_t *make_val(const nodus_identity_t *id, int key_i,
                               size_t len, uint8_t fill, uint64_t seq) {
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "quota-key-%d", key_i);
    nodus_key_t kh;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &kh);
    memset(g_buf, fill, len);
    nodus_value_t *v = NULL;
    if (nodus_value_create(&kh, g_buf, len, NODUS_VALUE_PERMANENT, 0,
                           1, seq, &id->pk, &v) != 0)
        return NULL;
    if (nodus_value_sign(v, &id->sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

typedef int (*put_fn)(nodus_storage_t *, const nodus_value_t *);

static int put_and_free(put_fn fn, nodus_storage_t *st, nodus_value_t *v) {
    if (!v) return -100;
    int rc = fn(st, v);
    nodus_value_free(v);
    return rc;
}

/* Fill owner A with exactly NODUS_STORAGE_OWNER_MAX_BYTES; all must store. */
static int fill_owner(put_fn fn, nodus_storage_t *st) {
    for (int i = 0; i < N_FILL; i++) {
        if (put_and_free(fn, st, make_val(&id_a, i, CHUNK, 0x10, 10)) != 0)
            return -1;
    }
    return 0;
}

static void test_put_quota(void) {
    TEST("put: exactly 16 MiB stores; 1 more byte -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = (N_FILL * (uint64_t)CHUNK == NODUS_STORAGE_OWNER_MAX_BYTES) &&
             fill_owner(nodus_storage_put, &st) == 0;
    int rc = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1000, 1, 0x11, 10));
    if (ok && rc == -3) PASS(); else FAIL("expected fill ok and -3");
    test_storage_close(&st);
}

static void test_put_replace_not_growing(void) {
    TEST("put: at quota, same-size and shrinking replace -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 0, CHUNK, 0x20, 11));
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, CHUNK - 100, 0x21, 11));
    /* the 100 freed bytes can now be used by growth elsewhere */
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2000, 100, 0x22, 1));
    if (ok && rc1 == 0 && rc2 == 0 && rc3 == 0) PASS();
    else FAIL("non-growing replace / freed space must pass");
    test_storage_close(&st);
}

static void test_put_replace_growing(void) {
    TEST("put: at quota, replace growing by 1 byte -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int rc = put_and_free(nodus_storage_put, &st, make_val(&id_a, 0, CHUNK + 1, 0x30, 11));
    /* the original row must be intact */
    nodus_value_t *probe = make_val(&id_a, 0, 1, 0, 0);
    nodus_value_t *got = NULL;
    int grc = probe ? nodus_storage_get(&st, &probe->key_hash, &got) : -1;
    if (ok && rc == -3 && grc == 0 && got && got->seq == 10 && got->data_len == CHUNK)
        PASS();
    else
        FAIL("growth over quota must be refused, old row kept");
    if (got) nodus_value_free(got);
    if (probe) nodus_value_free(probe);
    test_storage_close(&st);
}

static void test_put_other_owner(void) {
    TEST("put: owner A at quota does not limit owner B");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int rc = put_and_free(nodus_storage_put, &st, make_val(&id_b, 3000, CHUNK, 0x40, 1));
    if (ok && rc == 0) PASS(); else FAIL("owner B must store");
    test_storage_close(&st);
}

static void test_put_if_newer_quota(void) {
    TEST("put_if_newer: exactly 16 MiB stores; 1 more byte -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 1000, 1, 0x50, 10));
    if (ok && rc == -3) PASS(); else FAIL("expected fill ok and -3");
    test_storage_close(&st);
}

static void test_put_if_newer_replace_not_growing(void) {
    TEST("put_if_newer: at quota, newer same-size replace -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, CHUNK, 0x60, 11));
    if (ok && rc == 0) PASS(); else FAIL("non-growing newer replace must store");
    test_storage_close(&st);
}

static void test_put_if_newer_growing(void) {
    TEST("put_if_newer: at quota, newer replace growing -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, CHUNK + 1, 0x70, 11));
    if (ok && rc == -3) PASS(); else FAIL("growing newer replace must be -3");
    test_storage_close(&st);
}

static void test_put_if_newer_stale_is_skip(void) {
    TEST("put_if_newer: at quota, OLDER larger replica -> 1 (skip)");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, CHUNK + 1, 0x80, 9));
    if (ok && rc == 1) PASS(); else FAIL("stale replica must report skipped");
    test_storage_close(&st);
}

int main(void) {
    printf("=== Nodus per-owner byte quota ===\n");
    g_buf = malloc(CHUNK + 1);
    if (!g_buf) { printf("alloc failed\n"); return 1; }
    init_ids();

    test_put_quota();
    test_put_replace_not_growing();
    test_put_replace_growing();
    test_put_other_owner();
    test_put_if_newer_quota();
    test_put_if_newer_replace_not_growing();
    test_put_if_newer_growing();
    test_put_if_newer_stale_is_skip();

    free(g_buf);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
