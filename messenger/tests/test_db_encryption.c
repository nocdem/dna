/**
 * Unit tests for database encryption module (SQLCipher integration).
 *
 * Tests key derivation determinism, hex output validity, encrypted DB
 * open/reopen, legacy unencrypted DB handling, and NULL parameter rejection.
 *
 * @file test_db_encryption.c
 * @date 2026-04-02
 */

#include "database/db_encryption.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>

/* Test DB paths in /tmp */
#define TEST_DB_ENCRYPTED   "/tmp/test_sqlcipher_encrypted.db"
#define TEST_DB_REOPEN      "/tmp/test_sqlcipher_reopen.db"
#define TEST_DB_LEGACY      "/tmp/test_sqlcipher_legacy.db"
#define TEST_DB_NO_KEY      "/tmp/test_sqlcipher_nokey.db"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS(name) do { \
    printf("  PASS: %s\n", name); \
    tests_passed++; \
} while (0)

#define TEST_FAIL(name, reason) do { \
    printf("  FAIL: %s — %s\n", name, reason); \
    tests_failed++; \
} while (0)

/* Clean up a test DB and its WAL/SHM files */
static void cleanup_db(const char *path)
{
    char buf[1060];
    remove(path);
    snprintf(buf, sizeof(buf), "%s-wal", path);
    remove(buf);
    snprintf(buf, sizeof(buf), "%s-shm", path);
    remove(buf);
}

/* Fake secret key for testing (not a real Dilithium key, just deterministic bytes) */
static void fill_test_key(uint8_t *key, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        key[i] = (uint8_t)((seed + i) & 0xFF);
    }
}

/* =========================================================================
 * Test 1: Key derivation is deterministic
 * ========================================================================= */
static void test_key_derivation_deterministic(void)
{
    const char *name = "key derivation is deterministic";
    uint8_t secret[4896];
    fill_test_key(secret, sizeof(secret), 0x42);

    char hex1[129] = {0};
    char hex2[129] = {0};

    int rc1 = db_derive_encryption_key(secret, sizeof(secret), hex1, sizeof(hex1));
    int rc2 = db_derive_encryption_key(secret, sizeof(secret), hex2, sizeof(hex2));

    if (rc1 != 0 || rc2 != 0) {
        TEST_FAIL(name, "db_derive_encryption_key returned error");
        return;
    }

    if (strcmp(hex1, hex2) != 0) {
        TEST_FAIL(name, "two calls produced different output");
        return;
    }

    TEST_PASS(name);
}

/* =========================================================================
 * Test 2: Key derivation produces valid 128-char hex
 * ========================================================================= */
static void test_key_derivation_valid_hex(void)
{
    const char *name = "key derivation produces valid hex";
    uint8_t secret[4896];
    fill_test_key(secret, sizeof(secret), 0xAB);

    char hex[129] = {0};
    int rc = db_derive_encryption_key(secret, sizeof(secret), hex, sizeof(hex));
    if (rc != 0) {
        TEST_FAIL(name, "db_derive_encryption_key returned error");
        return;
    }

    size_t len = strlen(hex);
    if (len != 128) {
        char msg[128];
        snprintf(msg, sizeof(msg), "expected 128 hex chars, got %zu", len);
        TEST_FAIL(name, msg);
        return;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex[i])) {
            TEST_FAIL(name, "non-hex character in output");
            return;
        }
    }

    TEST_PASS(name);
}

/* =========================================================================
 * Test 3: Encrypted DB cannot be opened without key
 * ========================================================================= */
static void test_encrypted_db_no_key_fails(void)
{
    const char *name = "encrypted DB cannot be opened without key";
    const char *path = TEST_DB_NO_KEY;
    cleanup_db(path);

    uint8_t secret[4896];
    fill_test_key(secret, sizeof(secret), 0x01);
    char hex[129] = {0};
    db_derive_encryption_key(secret, sizeof(secret), hex, sizeof(hex));

    /* Create an encrypted DB with some data */
    sqlite3 *db = NULL;
    int rc = dna_db_open_encrypted(path, hex, &db);
    if (rc != 0 || !db) {
        TEST_FAIL(name, "failed to create encrypted DB");
        cleanup_db(path);
        return;
    }
    sqlite3_exec(db, "CREATE TABLE test_tbl (id INTEGER PRIMARY KEY, val TEXT);", NULL, NULL, NULL);
    sqlite3_exec(db, "INSERT INTO test_tbl VALUES (1, 'secret_data');", NULL, NULL, NULL);
    sqlite3_close(db);
    db = NULL;

    /* Try to open with plain sqlite3_open_v2 (no key) */
    rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        /* Could not even open the file — encryption is working */
        if (db) sqlite3_close(db);
        TEST_PASS(name);
        cleanup_db(path);
        return;
    }

    /* Opened, but SELECT should fail with SQLITE_NOTADB on encrypted file */
    rc = sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
    sqlite3_close(db);

    if (rc == SQLITE_NOTADB || rc != SQLITE_OK) {
        TEST_PASS(name);
    } else {
        TEST_FAIL(name, "plain open + SELECT succeeded on encrypted DB");
    }

    cleanup_db(path);
}

/* =========================================================================
 * Test 4: Encrypted DB can be reopened with same key
 * ========================================================================= */
static void test_encrypted_db_reopen(void)
{
    const char *name = "encrypted DB can be reopened with same key";
    const char *path = TEST_DB_REOPEN;
    cleanup_db(path);

    uint8_t secret[4896];
    fill_test_key(secret, sizeof(secret), 0x77);
    char hex[129] = {0};
    db_derive_encryption_key(secret, sizeof(secret), hex, sizeof(hex));

    /* Create and write data */
    sqlite3 *db = NULL;
    int rc = dna_db_open_encrypted(path, hex, &db);
    if (rc != 0 || !db) {
        TEST_FAIL(name, "failed to create encrypted DB");
        cleanup_db(path);
        return;
    }
    sqlite3_exec(db, "CREATE TABLE reopen_test (id INTEGER, data TEXT);", NULL, NULL, NULL);
    sqlite3_exec(db, "INSERT INTO reopen_test VALUES (42, 'hello_encrypted');", NULL, NULL, NULL);
    sqlite3_close(db);
    db = NULL;

    /* Reopen with same key */
    rc = dna_db_open_encrypted(path, hex, &db);
    if (rc != 0 || !db) {
        TEST_FAIL(name, "failed to reopen encrypted DB");
        cleanup_db(path);
        return;
    }

    /* Verify data is readable */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT data FROM reopen_test WHERE id = 42;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        TEST_FAIL(name, "prepare SELECT failed after reopen");
        sqlite3_close(db);
        cleanup_db(path);
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        TEST_FAIL(name, "no row returned after reopen");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        cleanup_db(path);
        return;
    }

    const char *val = (const char *)sqlite3_column_text(stmt, 0);
    if (!val || strcmp(val, "hello_encrypted") != 0) {
        TEST_FAIL(name, "data mismatch after reopen");
    } else {
        TEST_PASS(name);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    cleanup_db(path);
}

/* =========================================================================
 * Test 5: Unencrypted legacy DB is deleted and recreated
 * ========================================================================= */
static void test_legacy_db_replaced(void)
{
    const char *name = "unencrypted legacy DB is deleted and recreated";
    const char *path = TEST_DB_LEGACY;
    cleanup_db(path);

    /* Create a plain unencrypted DB with data */
    sqlite3 *plain_db = NULL;
    int rc = sqlite3_open_v2(path, &plain_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        TEST_FAIL(name, "failed to create plain DB");
        if (plain_db) sqlite3_close(plain_db);
        cleanup_db(path);
        return;
    }
    sqlite3_exec(plain_db, "CREATE TABLE legacy_data (id INTEGER, info TEXT);", NULL, NULL, NULL);
    sqlite3_exec(plain_db, "INSERT INTO legacy_data VALUES (1, 'old_stuff');", NULL, NULL, NULL);
    sqlite3_close(plain_db);
    plain_db = NULL;

    /* Now open with dna_db_open_encrypted — should delete and recreate */
    uint8_t secret[4896];
    fill_test_key(secret, sizeof(secret), 0xCC);
    char hex[129] = {0};
    db_derive_encryption_key(secret, sizeof(secret), hex, sizeof(hex));

    sqlite3 *enc_db = NULL;
    rc = dna_db_open_encrypted(path, hex, &enc_db);
    if (rc != 0 || !enc_db) {
        TEST_FAIL(name, "dna_db_open_encrypted failed on legacy DB");
        cleanup_db(path);
        return;
    }

    /* The old legacy_data table should NOT exist (DB was recreated empty) */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(enc_db,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='legacy_data';",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        TEST_FAIL(name, "prepare query on recreated DB failed");
        sqlite3_close(enc_db);
        cleanup_db(path);
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        TEST_FAIL(name, "no row from sqlite_master query");
        sqlite3_finalize(stmt);
        sqlite3_close(enc_db);
        cleanup_db(path);
        return;
    }

    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    sqlite3_close(enc_db);

    if (count == 0) {
        TEST_PASS(name);
    } else {
        TEST_FAIL(name, "legacy_data table still exists after migration");
    }

    cleanup_db(path);
}

/* =========================================================================
 * Test 6: NULL/invalid parameters rejected
 * ========================================================================= */
static void test_null_parameters_rejected(void)
{
    const char *name = "NULL/invalid parameters rejected";
    char hex[129] = {0};
    uint8_t secret[32] = {0};
    sqlite3 *db = NULL;
    int failures = 0;

    /* db_derive_encryption_key: NULL secret_key */
    if (db_derive_encryption_key(NULL, 32, hex, sizeof(hex)) != -1) {
        printf("    sub-fail: NULL secret_key not rejected\n");
        failures++;
    }

    /* db_derive_encryption_key: zero sk_len */
    if (db_derive_encryption_key(secret, 0, hex, sizeof(hex)) != -1) {
        printf("    sub-fail: zero sk_len not rejected\n");
        failures++;
    }

    /* db_derive_encryption_key: NULL hex_key_out */
    if (db_derive_encryption_key(secret, sizeof(secret), NULL, 129) != -1) {
        printf("    sub-fail: NULL hex_key_out not rejected\n");
        failures++;
    }

    /* db_derive_encryption_key: buffer too small */
    if (db_derive_encryption_key(secret, sizeof(secret), hex, 64) != -1) {
        printf("    sub-fail: small buffer not rejected\n");
        failures++;
    }

    /* dna_db_open_encrypted: NULL path */
    if (dna_db_open_encrypted(NULL, "aabbcc", &db) != -1) {
        printf("    sub-fail: NULL path not rejected\n");
        failures++;
    }

    /* dna_db_open_encrypted: NULL hex_key */
    if (dna_db_open_encrypted("/tmp/test_null.db", NULL, &db) != -1) {
        printf("    sub-fail: NULL hex_key not rejected\n");
        failures++;
    }

    /* dna_db_open_encrypted: NULL db_out */
    if (dna_db_open_encrypted("/tmp/test_null.db", "aabbcc", NULL) != -1) {
        printf("    sub-fail: NULL db_out not rejected\n");
        failures++;
    }

    if (failures == 0) {
        TEST_PASS(name);
    } else {
        char msg[64];
        snprintf(msg, sizeof(msg), "%d sub-checks failed", failures);
        TEST_FAIL(name, msg);
    }
}

/* ========================================================================= */

int main(void)
{
    printf("=== Database Encryption Tests (SQLCipher) ===\n\n");

    test_key_derivation_deterministic();
    test_key_derivation_valid_hex();
    test_encrypted_db_no_key_fails();
    test_encrypted_db_reopen();
    test_legacy_db_replaced();
    test_null_parameters_rejected();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
