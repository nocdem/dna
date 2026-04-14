/*
 * Test: groups.db schema v2 -> v3 migration adds dht_salt + has_dht_salt
 *
 * Phase 6 / Plan 03 target. RED today, GREEN after plan 03.
 *
 * CORE-04: per-group DHT salts must live on the groups row. Plan 03 adds the
 * schema and the v2->v3 migration; this test is the regression guard.
 *
 * Today the schema only goes to v2 (no dht_salt columns). Both halves of this
 * test fail (RED) by design.
 *
 * Strategy:
 *   1. Override HOME to a private tmp dir so group_database_init() targets
 *      <tmp>/.dna/db/groups.db instead of the developer's real ~/.dna.
 *   2. Pre-create a v2 schema (no salt columns) at that path.
 *   3. Call group_database_init(NULL) to drive the migration.
 *   4. Re-open the file with sqlite3 directly and PRAGMA table_info(groups);
 *      assert dht_salt and has_dht_salt are present and metadata version='3'.
 *   5. Repeat from-scratch: empty tmp, fresh init, must also end at v3.
 *
 * TODO(plan-03): remove the RED guard at the end once SCHEMA_SQL ends at v3
 *                and a MIGRATION_V2_TO_V3 block is added to group_database.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3.h>

/* sqlite3_key is a SQLCipher extension — its prototype lives in sqlcipher's
 * sqlite3.h, but the test include search path may resolve to the stock
 * sqlite3.h. Declare it explicitly to silence -Wimplicit-function-declaration.
 * The runtime symbol is provided by libsqlcipher (linked via TEST_LIBS). */
extern int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);

#include "messenger/group_database.h"

/* Deterministic test key (128 hex chars = 64 bytes) — SQLCipher format.
 * The test uses the same key for the pre-populated v2 database and for
 * the group_database_init() call so the migration path can open it. */
static const char *TEST_DB_KEY =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static int set_tmp_home(char *out, size_t out_size) {
    char tmpl[] = "/tmp/phase6-grpdb-XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp) {
        fprintf(stderr, "FAIL: mkdtemp failed\n");
        return -1;
    }
    snprintf(out, out_size, "%s", tmp);
    if (setenv("HOME", out, 1) != 0) {
        fprintf(stderr, "FAIL: setenv HOME failed\n");
        return -1;
    }
    return 0;
}

static int build_v2_schema(const char *db_path) {
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "FAIL: sqlite3_open %s\n", db_path);
        return -1;
    }
    /* Apply SQLCipher key so group_database_init can open this file. */
    if (sqlite3_key(db, TEST_DB_KEY, (int)strlen(TEST_DB_KEY)) != SQLITE_OK) {
        fprintf(stderr, "FAIL: sqlite3_key on v2 fixture\n");
        sqlite3_close(db);
        return -1;
    }
    const char *v2_sql =
        "CREATE TABLE groups ("
        "  uuid TEXT PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  is_owner INTEGER DEFAULT 0,"
        "  owner_fp TEXT NOT NULL"
        ");"
        "CREATE TABLE metadata ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT"
        ");"
        "INSERT INTO metadata VALUES ('version', '2');";
    char *err = NULL;
    if (sqlite3_exec(db, v2_sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "FAIL: build v2 schema: %s\n", err ? err : "?");
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;
}

static int has_columns_and_v3(const char *db_path) {
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "FAIL: re-open %s\n", db_path);
        return -1;
    }
    if (sqlite3_key(db, TEST_DB_KEY, (int)strlen(TEST_DB_KEY)) != SQLITE_OK) {
        fprintf(stderr, "FAIL: sqlite3_key on inspection handle\n");
        sqlite3_close(db);
        return -1;
    }

    int saw_dht_salt = 0;
    int saw_has_dht_salt = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(groups)", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "FAIL: prepare table_info\n");
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *col = sqlite3_column_text(stmt, 1);
        if (!col) continue;
        if (strcmp((const char *)col, "dht_salt") == 0)     saw_dht_salt = 1;
        if (strcmp((const char *)col, "has_dht_salt") == 0) saw_has_dht_salt = 1;
    }
    sqlite3_finalize(stmt);

    int version = 0;
    if (sqlite3_prepare_v2(db,
                           "SELECT value FROM metadata WHERE key='version'",
                           -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(stmt, 0);
            if (v) version = atoi((const char *)v);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);

    fprintf(stderr,
            "  dht_salt=%d has_dht_salt=%d version=%d\n",
            saw_dht_salt, saw_has_dht_salt, version);

    if (saw_dht_salt && saw_has_dht_salt && version == 3) return 0;
    return -1;
}

int main(void) {
    fprintf(stderr, "Test: groups.db v2->v3 migration (CORE-04)\n");
    fprintf(stderr, "==========================================\n");

    /* Sandbox HOME so we never touch the real ~/.dna */
    char home[256];
    if (set_tmp_home(home, sizeof(home)) != 0) return 1;
    fprintf(stderr, "HOME=%s\n", home);

    /* Build .dna/db/ and a v2 groups.db inside the sandbox.
     * Buffers grow with each suffix so gcc -Wformat-truncation is satisfied:
     * dna_dir = home + "/.dna", db_dir = dna_dir + "/db",
     * db_path = db_dir  + "/groups.db". */
    char dna_dir[320], db_dir[384], db_path[448];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna",      home);
    snprintf(db_dir,  sizeof(db_dir),  "%s/db",        dna_dir);
    snprintf(db_path, sizeof(db_path), "%s/groups.db", db_dir);
    mkdir(dna_dir, 0700);
    mkdir(db_dir,  0700);

    if (build_v2_schema(db_path) != 0) return 1;
    fprintf(stderr, "v2 schema built at %s\n", db_path);

    /* Drive the migration via the public lifecycle. */
    group_database_context_t *ctx = group_database_init(TEST_DB_KEY);
    if (!ctx) {
        fprintf(stderr, "FAIL: group_database_init returned NULL\n");
        return 1;
    }
    group_database_close(ctx);

    /* (1) Migration assertion */
    int migrated = has_columns_and_v3(db_path);
    if (migrated != 0) {
        fprintf(stderr,
                "RED: TODO(plan-03) — groups.db v2->v3 migration not "
                "implemented; dht_salt / has_dht_salt columns missing or "
                "metadata version != 3.\n");
        return 1;
    }
    fprintf(stderr, "PASS: v2->v3 migration added expected columns\n");

    /* (2) Fresh-init also lands at v3 */
    unlink(db_path);
    ctx = group_database_init(TEST_DB_KEY);
    if (!ctx) {
        fprintf(stderr, "FAIL: fresh group_database_init returned NULL\n");
        return 1;
    }
    group_database_close(ctx);
    if (has_columns_and_v3(db_path) != 0) {
        fprintf(stderr,
                "RED: TODO(plan-03) — fresh schema does not land at v3\n");
        return 1;
    }
    fprintf(stderr, "PASS: fresh init lands at v3\n");

    /* Cleanup */
    unlink(db_path);
    rmdir(db_dir);
    rmdir(dna_dir);
    rmdir(home);

    return 0;
}
