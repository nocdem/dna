/**
 * Nodus — Encrypted Channel Tests
 *
 * Tests for encrypted channel metadata, push targets, and pending push
 * store-and-forward functionality.
 */

#include "channel/nodus_channel_store.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-55s ", tests_run, name); \
} while (0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

static char db_path[256];
static nodus_channel_store_t store;

/* Test UUIDs */
static const uint8_t enc_uuid[16] = {
    0xE0, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4,
    0xA7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x01
};

static const uint8_t plain_uuid[16] = {
    0xB0, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4,
    0xA7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x02
};

static const uint8_t nonexist_uuid[16] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* ── Test 1: Create encrypted channel ──────────────────────────── */

static void test_create_encrypted_channel(void) {
    TEST("create encrypted channel — flag persists");

    int rc = nodus_channel_create(&store, enc_uuid, true, NULL, NULL, false);
    if (rc != 0) { FAIL("create failed"); return; }

    if (!nodus_channel_exists(&store, enc_uuid)) {
        FAIL("channel not found after create"); return;
    }

    if (!nodus_channel_is_encrypted(&store, enc_uuid)) {
        FAIL("encrypted flag not set"); return;
    }

    /* Verify via load_meta */
    nodus_channel_meta_t meta;
    rc = nodus_channel_load_meta(&store, enc_uuid, &meta);
    if (rc != 0) { FAIL("load_meta failed"); return; }
    if (!meta.encrypted) { FAIL("meta.encrypted is false"); return; }
    if (meta.created_at == 0) { FAIL("meta.created_at is 0"); return; }
    if (memcmp(meta.uuid, enc_uuid, NODUS_UUID_BYTES) != 0) {
        FAIL("meta.uuid mismatch"); return;
    }

    PASS();
}

/* ── Test 2: Create non-encrypted channel (backward compat) ────── */

static void test_create_plain_channel(void) {
    TEST("create non-encrypted channel — backward compat");

    int rc = nodus_channel_create(&store, plain_uuid, false, NULL, NULL, false);
    if (rc != 0) { FAIL("create failed"); return; }

    if (!nodus_channel_exists(&store, plain_uuid)) {
        FAIL("channel not found"); return;
    }

    if (nodus_channel_is_encrypted(&store, plain_uuid)) {
        FAIL("plain channel reported as encrypted"); return;
    }

    nodus_channel_meta_t meta;
    rc = nodus_channel_load_meta(&store, plain_uuid, &meta);
    if (rc != 0) { FAIL("load_meta failed"); return; }
    if (meta.encrypted) { FAIL("meta.encrypted should be false"); return; }

    PASS();
}

/* ── Test 3: Add push targets — verify CRUD ────────────────────── */

static void test_add_push_targets(void) {
    TEST("add push targets — verify CRUD");

    nodus_key_t fp1, fp2;
    memset(fp1.bytes, 0xAA, NODUS_KEY_BYTES);
    memset(fp2.bytes, 0xBB, NODUS_KEY_BYTES);

    int rc = nodus_push_target_add(&store, enc_uuid, &fp1);
    if (rc != 0) { FAIL("add fp1 failed"); return; }

    rc = nodus_push_target_add(&store, enc_uuid, &fp2);
    if (rc != 0) { FAIL("add fp2 failed"); return; }

    /* Verify both exist */
    if (!nodus_push_target_has(&store, enc_uuid, &fp1)) {
        FAIL("fp1 not found"); return;
    }
    if (!nodus_push_target_has(&store, enc_uuid, &fp2)) {
        FAIL("fp2 not found"); return;
    }

    /* Get all targets */
    nodus_push_target_t *targets = NULL;
    size_t count = 0;
    rc = nodus_push_target_get(&store, enc_uuid, &targets, &count);
    if (rc != 0) { FAIL("get failed"); free(targets); return; }
    if (count != 2) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 2 targets, got %zu", count);
        FAIL(msg); free(targets); return;
    }

    free(targets);
    PASS();
}

/* ── Test 4: Remove push target ────────────────────────────────── */

static void test_remove_push_target(void) {
    TEST("remove push target — verify removal");

    nodus_key_t fp1;
    memset(fp1.bytes, 0xAA, NODUS_KEY_BYTES);

    int rc = nodus_push_target_remove(&store, enc_uuid, &fp1);
    if (rc != 0) { FAIL("remove failed"); return; }

    if (nodus_push_target_has(&store, enc_uuid, &fp1)) {
        FAIL("fp1 still present after remove"); return;
    }

    /* fp2 should still be there */
    nodus_key_t fp2;
    memset(fp2.bytes, 0xBB, NODUS_KEY_BYTES);
    if (!nodus_push_target_has(&store, enc_uuid, &fp2)) {
        FAIL("fp2 disappeared after removing fp1"); return;
    }

    /* Count should be 1 */
    nodus_push_target_t *targets = NULL;
    size_t count = 0;
    rc = nodus_push_target_get(&store, enc_uuid, &targets, &count);
    if (rc != 0 || count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 target, got %zu", count);
        FAIL(msg); free(targets); return;
    }

    free(targets);
    PASS();
}

/* ── Test 5: Add pending push entry ────────────────────────────── */

static void test_add_pending_push(void) {
    TEST("add pending push entry — verify storage");

    nodus_key_t fp;
    memset(fp.bytes, 0xCC, NODUS_KEY_BYTES);

    const uint8_t data[] = "encrypted post payload";
    uint64_t expires = (uint64_t)time(NULL) + 7 * 86400;  /* 7 days */

    int rc = nodus_pending_push_add(&store, enc_uuid, &fp,
                                     data, sizeof(data), expires);
    if (rc != 0) { FAIL("add failed"); return; }

    /* Verify retrieval */
    nodus_pending_push_t *entries = NULL;
    size_t count = 0;
    rc = nodus_pending_push_get(&store, enc_uuid, &fp, 100, &entries, &count);
    if (rc != 0) { FAIL("get failed"); nodus_pending_push_free(entries, count); return; }
    if (count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 entry, got %zu", count);
        FAIL(msg); nodus_pending_push_free(entries, count); return;
    }
    if (entries[0].post_data_len != sizeof(data)) {
        FAIL("data length mismatch"); nodus_pending_push_free(entries, count); return;
    }
    if (memcmp(entries[0].post_data, data, sizeof(data)) != 0) {
        FAIL("data content mismatch"); nodus_pending_push_free(entries, count); return;
    }

    nodus_pending_push_free(entries, count);
    PASS();
}

/* ── Test 6: Get pending push by fingerprint ───────────────────── */

static void test_get_pending_push_by_fp(void) {
    TEST("get pending push by fingerprint — verify retrieval");

    nodus_key_t fp_cc, fp_dd;
    memset(fp_cc.bytes, 0xCC, NODUS_KEY_BYTES);
    memset(fp_dd.bytes, 0xDD, NODUS_KEY_BYTES);

    /* Add another entry for a different fingerprint */
    const uint8_t data2[] = "payload for DD";
    uint64_t expires = (uint64_t)time(NULL) + 7 * 86400;
    int rc = nodus_pending_push_add(&store, enc_uuid, &fp_dd,
                                     data2, sizeof(data2), expires);
    if (rc != 0) { FAIL("add for DD failed"); return; }

    /* Get for CC — should only return CC's entry */
    nodus_pending_push_t *entries = NULL;
    size_t count = 0;
    rc = nodus_pending_push_get(&store, enc_uuid, &fp_cc, 100, &entries, &count);
    if (rc != 0) { FAIL("get CC failed"); nodus_pending_push_free(entries, count); return; }
    if (count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 CC entry, got %zu", count);
        FAIL(msg); nodus_pending_push_free(entries, count); return;
    }
    nodus_pending_push_free(entries, count);

    /* Get for DD — should only return DD's entry */
    entries = NULL; count = 0;
    rc = nodus_pending_push_get(&store, enc_uuid, &fp_dd, 100, &entries, &count);
    if (rc != 0) { FAIL("get DD failed"); nodus_pending_push_free(entries, count); return; }
    if (count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 DD entry, got %zu", count);
        FAIL(msg); nodus_pending_push_free(entries, count); return;
    }
    nodus_pending_push_free(entries, count);

    PASS();
}

/* ── Test 7: Delete pending push after delivery ────────────────── */

static void test_delete_pending_push(void) {
    TEST("delete pending push after delivery — verify cleanup");

    nodus_key_t fp;
    memset(fp.bytes, 0xCC, NODUS_KEY_BYTES);

    /* Get CC's entry to find its ID */
    nodus_pending_push_t *entries = NULL;
    size_t count = 0;
    int rc = nodus_pending_push_get(&store, enc_uuid, &fp, 100, &entries, &count);
    if (rc != 0 || count != 1) {
        FAIL("get before delete failed");
        nodus_pending_push_free(entries, count); return;
    }

    int64_t id = entries[0].id;
    nodus_pending_push_free(entries, count);

    /* Delete it */
    rc = nodus_pending_push_delete(&store, id);
    if (rc != 0) { FAIL("delete failed"); return; }

    /* Verify gone */
    entries = NULL; count = 0;
    rc = nodus_pending_push_get(&store, enc_uuid, &fp, 100, &entries, &count);
    if (rc != 0) { FAIL("get after delete failed"); nodus_pending_push_free(entries, count); return; }
    if (count != 0) {
        FAIL("entry still present after delete");
        nodus_pending_push_free(entries, count); return;
    }

    PASS();
}

/* ── Test 8: Expire old pending push entries ───────────────────── */

static void test_expire_pending_push(void) {
    TEST("expire old pending push entries (>7 days)");

    nodus_key_t fp;
    memset(fp.bytes, 0xEE, NODUS_KEY_BYTES);

    /* Add entry with expires_at in the past (already expired) */
    const uint8_t data[] = "expired payload";
    uint64_t past_expires = (uint64_t)time(NULL) - 1;  /* Already expired */
    int rc = nodus_pending_push_add(&store, enc_uuid, &fp,
                                     data, sizeof(data), past_expires);
    if (rc != 0) { FAIL("add expired entry failed"); return; }

    /* Add entry with expires_at in the future (should survive) */
    const uint8_t data2[] = "fresh payload";
    uint64_t future_expires = (uint64_t)time(NULL) + 7 * 86400;
    rc = nodus_pending_push_add(&store, enc_uuid, &fp,
                                 data2, sizeof(data2), future_expires);
    if (rc != 0) { FAIL("add fresh entry failed"); return; }

    /* Run cleanup */
    int cleaned = nodus_pending_push_cleanup(&store);
    if (cleaned < 0) { FAIL("cleanup returned error"); return; }
    if (cleaned < 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected >=1 cleaned, got %d", cleaned);
        FAIL(msg); return;
    }

    /* Only fresh entry should remain */
    nodus_pending_push_t *entries = NULL;
    size_t count = 0;
    rc = nodus_pending_push_get(&store, enc_uuid, &fp, 100, &entries, &count);
    if (rc != 0) { FAIL("get after cleanup failed"); nodus_pending_push_free(entries, count); return; }
    if (count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 surviving entry, got %zu", count);
        FAIL(msg); nodus_pending_push_free(entries, count); return;
    }
    if (entries[0].post_data_len != sizeof(data2)) {
        FAIL("wrong entry survived"); nodus_pending_push_free(entries, count); return;
    }
    nodus_pending_push_free(entries, count);

    PASS();
}

/* ── Test 9: Push target dedup ─────────────────────────────────── */

static void test_push_target_dedup(void) {
    TEST("push target dedup — adding same target twice");

    nodus_key_t fp;
    memset(fp.bytes, 0x11, NODUS_KEY_BYTES);

    int rc = nodus_push_target_add(&store, enc_uuid, &fp);
    if (rc != 0) { FAIL("first add failed"); return; }

    /* Second add of same fp — should succeed (INSERT OR IGNORE) */
    rc = nodus_push_target_add(&store, enc_uuid, &fp);
    if (rc != 0) { FAIL("duplicate add failed"); return; }

    /* Should still only have one entry for this fp */
    if (!nodus_push_target_has(&store, enc_uuid, &fp)) {
        FAIL("fp not found"); return;
    }

    /* Count all targets for enc_uuid (fp2=0xBB from test 3/4 + fp=0x11) */
    nodus_push_target_t *targets = NULL;
    size_t count = 0;
    rc = nodus_push_target_get(&store, enc_uuid, &targets, &count);
    if (rc != 0) { FAIL("get failed"); free(targets); return; }
    if (count != 2) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 2 targets (BB+11), got %zu", count);
        FAIL(msg); free(targets); return;
    }

    free(targets);
    PASS();
}

/* ── Test 10: Pending push for non-existent channel ────────────── */

static void test_pending_push_nonexistent_channel(void) {
    TEST("pending push for non-existent channel — graceful");

    nodus_key_t fp;
    memset(fp.bytes, 0x99, NODUS_KEY_BYTES);

    /* Adding pending push for a channel that doesn't exist in channel tables
     * The pending_push table doesn't have FK constraints, so this should work
     * at the DB level (the channel routing logic handles the semantics) */
    const uint8_t data[] = "orphan payload";
    uint64_t expires = (uint64_t)time(NULL) + 3600;
    int rc = nodus_pending_push_add(&store, nonexist_uuid, &fp,
                                     data, sizeof(data), expires);
    if (rc != 0) { FAIL("add to nonexistent channel failed"); return; }

    /* Should be retrievable */
    nodus_pending_push_t *entries = NULL;
    size_t count = 0;
    rc = nodus_pending_push_get(&store, nonexist_uuid, &fp, 100, &entries, &count);
    if (rc != 0) { FAIL("get failed"); nodus_pending_push_free(entries, count); return; }
    if (count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 entry, got %zu", count);
        FAIL(msg); nodus_pending_push_free(entries, count); return;
    }

    /* Verify the nonexist channel is not encrypted (not in meta table) */
    if (nodus_channel_is_encrypted(&store, nonexist_uuid)) {
        FAIL("nonexistent channel reported as encrypted");
        nodus_pending_push_free(entries, count); return;
    }

    /* Clean up */
    nodus_pending_push_delete(&store, entries[0].id);
    nodus_pending_push_free(entries, count);

    PASS();
}

int main(void) {
    printf("test_channel_encrypted: Encrypted channel tests\n");

    /* Open temp DB */
    snprintf(db_path, sizeof(db_path), "/tmp/nodus_enc_test_%d.db", getpid());
    if (nodus_channel_store_open(db_path, &store) != 0) {
        printf("  FATAL: failed to open test database\n");
        return 1;
    }

    test_create_encrypted_channel();
    test_create_plain_channel();
    test_add_push_targets();
    test_remove_push_target();
    test_add_pending_push();
    test_get_pending_push_by_fp();
    test_delete_pending_push();
    test_expire_pending_push();
    test_push_target_dedup();
    test_pending_push_nonexistent_channel();

    /* Cleanup */
    nodus_channel_store_close(&store);
    unlink(db_path);
    char wal[270], shm[270];
    snprintf(wal, sizeof(wal), "%s-wal", db_path);
    snprintf(shm, sizeof(shm), "%s-shm", db_path);
    unlink(wal);
    unlink(shm);

    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
