/**
 * Nodus — Ledger V2 S5: versioned schema + atomic migration tests
 * (INACTIVE layer). Real witness chain DBs in temp dirs (heap fixture).
 *
 * §20 "Schema and migration" matrix:
 *   1. fresh DB → migrate → user_version 5, all six v2 tables + the
 *      utxo_set.domain_id column exist;
 *   2. S4-shaped DB (current schema) → migrate;
 *   3. legacy/V1-shaped DB (hand-rolled minimal schema WITHOUT the S4
 *      tables) → migrate;
 *   4. repeated migration is a no-op (idempotent);
 *   5. deterministic failure at EVERY migration stage → full rollback:
 *      user_version still 0, no v2 table, no domain_id column, and a
 *      subsequent migration succeeds;
 *   6. restart after successful migration keeps version + schema;
 *   7. malformed/unknown user_version (7) fails closed, nothing changes;
 *   8. pre-existing UTXOs map to DNA_CORE exactly once (NOT NULL single
 *      column — no duplicate, no missing ownership);
 *   9. no CPUNK table or ownership anywhere.
 *
 * @file test_v2_schema.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_schema_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x22, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int count_q(sqlite3 *db, const char *sql, int *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    *out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return 0;
}

static int has_table(sqlite3 *db, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 1 : 0;
}

static int has_domain_col(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(utxo_set)", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, "domain_id") == 0) found = 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? found : -1;
}

static const char *V2_TABLES[6] = {
    "v2_blocks", "v2_domain_heads", "v2_domain_updates",
    "v2_root_history", "v2_tx_index", "v2_tx_local_index"
};

static int schema_absent(sqlite3 *db) {
    for (int i = 0; i < 6; i++)
        if (has_table(db, V2_TABLES[i]) != 0) return 0;
    if (has_domain_col(db) != 0) return 0;
    return 1;
}

static int schema_present(sqlite3 *db) {
    for (int i = 0; i < 6; i++)
        if (has_table(db, V2_TABLES[i]) != 1) return 0;
    if (has_domain_col(db) != 1) return 0;
    return 1;
}

int main(void) {
    /* ── 1+2. fresh / S4-shaped DB (current production schema) ──────── */
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture open"); OK();

    uint32_t ver = 99;
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 0,
          "fresh DB version != 0"); OK();
    CHECK(schema_absent(fx.w->db), "v2 schema pre-exists"); OK();

    /* pre-existing "legacy" UTXOs (inserted BEFORE the migration, with
     * the production column list — no domain column) */
    CHECK(run_sql(fx.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        " tx_hash, output_index, block_height, created_at, unlock_block) "
        "VALUES (x'01', 'fpA', 100, x'00', x'aa', 0, 1, 0, 0),"
        "       (x'02', 'fpB', 250, x'00', x'bb', 0, 1, 0, 0)") == 0,
        "seed utxos"); OK();

    /* ── 5. failure at EVERY stage → full rollback, then success ────── */
    for (int stage = V2MIG_FAIL_AFTER_BEGIN;
         stage <= V2MIG_FAIL_BEFORE_COMMIT; stage++) {
        CHECK(nodus_witness_db_migrate_v2s5_ex(fx.w,
                  (nodus_v2_mig_fail_t)stage) == -1,
              "staged failure did not fail");
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 0,
              "failed migration left a version");
        CHECK(schema_absent(fx.w->db),
              "failed migration left schema fragments");
    }
    OK();

    /* the DB is still fully usable and migrates cleanly afterwards */
    CHECK(nodus_witness_db_migrate_v2s5(fx.w) == 0, "migrate"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 5,
          "version != 5"); OK();
    CHECK(schema_present(fx.w->db), "schema incomplete"); OK();

    /* ── 4. idempotent re-run ───────────────────────────────────────── */
    CHECK(nodus_witness_db_migrate_v2s5(fx.w) == 0, "re-migrate"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 5,
          "re-migrate changed version"); OK();

    /* ── 8. every pre-existing UTXO owned by DNA_CORE exactly once ──── */
    int n = -1;
    CHECK(count_q(fx.w->db, "SELECT COUNT(*) FROM utxo_set", &n) == 0 &&
          n == 2, "utxo count"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id = 1", &n) == 0 &&
          n == 2, "legacy UTXOs not DNA_CORE-owned"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id IS NULL", &n) == 0
          && n == 0, "nullable ownership"); OK();
    /* NO permanent domain default exists: an insert that does not name
     * its owning domain FAILS (NOT NULL, no default) — ownership is
     * always explicit on the generic path. */
    {
        char *err = NULL;
        CHECK(sqlite3_exec(fx.w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            " tx_hash, output_index, block_height, created_at, "
            "unlock_block) "
            "VALUES (x'03', 'fpC', 7, x'00', x'cc', 0, 2, 0, 0)",
            NULL, NULL, &err) != SQLITE_OK,
            "ownerless insert must fail");
        sqlite3_free(err);
        OK();
    }
    /* the schema itself carries no default for domain_id */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT dflt_value FROM pragma_table_info('utxo_set') "
              "WHERE name='domain_id'", -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_NULL,
              "domain_id must have NO schema default");
        sqlite3_finalize(st);
        OK();
    }
    /* an EXPLICITLY-owned insert works */
    CHECK(run_sql(fx.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        " tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (x'03', 'fpC', 7, x'00', x'cc', 0, 2, 0, 0, 1)") == 0,
        "explicit-owner insert");
    CHECK(count_q(fx.w->db,
          "SELECT domain_id FROM utxo_set WHERE nullifier = x'03'", &n) == 0
          && n == 1, "explicit UTXO ownership"); OK();

    /* ── 6. restart keeps version + schema + ownership ──────────────── */
    CHECK(fx_reopen(&fx) == 0, "reopen");
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 5,
          "restart lost version"); OK();
    CHECK(schema_present(fx.w->db), "restart lost schema"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id = 1", &n) == 0 &&
          n == 3, "restart lost ownership"); OK();

    /* ── 9. no CPUNK table or ownership anywhere ────────────────────── */
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM sqlite_master "
          "WHERE LOWER(name) LIKE '%cpunk%'", &n) == 0 && n == 0,
          "CPUNK table exists"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id NOT IN (0, 1)",
          &n) == 0 && n == 0, "foreign domain ownership"); OK();
    fx_close(&fx);

    /* ── 7. malformed/unknown version fails closed ──────────────────── */
    fixture_t fx2;
    CHECK(fx_open(&fx2) == 0, "fixture 2");
    CHECK(run_sql(fx2.w->db, "PRAGMA user_version = 7") == 0, "set 7");
    CHECK(nodus_witness_db_migrate_v2s5(fx2.w) == -1,
          "unknown version migrated"); OK();
    CHECK(nodus_witness_db_schema_version(fx2.w, &ver) == 0 && ver == 7,
          "unknown version mutated"); OK();
    CHECK(schema_absent(fx2.w->db), "unknown version got schema"); OK();
    fx_close(&fx2);

    /* ── 3. legacy/V1-shaped DB: minimal hand-rolled schema WITHOUT any
     * S4 table — the migration must still succeed (it touches only
     * utxo_set + new tables) ───────────────────────────────────────── */
    {
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL, "alloc");
        CHECK(sqlite3_open(":memory:", &w->db) == SQLITE_OK, "mem db");
        CHECK(run_sql(w->db,
            "CREATE TABLE utxo_set ("
            "  nullifier BLOB PRIMARY KEY, owner TEXT NOT NULL,"
            "  amount INTEGER NOT NULL, token_id BLOB NOT NULL,"
            "  tx_hash BLOB NOT NULL, output_index INTEGER NOT NULL,"
            "  block_height INTEGER NOT NULL DEFAULT 0,"
            "  created_at INTEGER NOT NULL DEFAULT 0,"
            "  unlock_block INTEGER NOT NULL DEFAULT 0);"
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id,"
            " tx_hash, output_index) VALUES (x'aa', 'legacy', 42, x'00',"
            " x'11', 0)") == 0, "legacy schema"); OK();
        CHECK(nodus_witness_db_migrate_v2s5(w) == 0, "legacy migrate");
        OK();
        uint32_t v2 = 0;
        CHECK(nodus_witness_db_schema_version(w, &v2) == 0 && v2 == 5,
              "legacy version"); OK();
        int m = -1;
        CHECK(count_q(w->db,
              "SELECT domain_id FROM utxo_set WHERE nullifier = x'aa'",
              &m) == 0 && m == 1, "legacy UTXO ownership"); OK();
        sqlite3_close(w->db);
        free(w);
    }

    printf("test_v2_schema: ALL %d checks passed\n", g_checks);
    return 0;
}
