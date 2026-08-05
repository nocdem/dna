/**
 * @file nodus_witness_v2_schema.c
 * @brief Ledger V2 Season 5 — versioned schema + atomic migration
 *        implementation (INACTIVE). Contract: nodus_witness_v2_schema.h.
 *
 * @file nodus_witness_v2_schema.c
 */

#include "witness/nodus_witness_v2_schema.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2SCHEMA"

/* The six S5 tables. IF NOT EXISTS keeps re-entry harmless; the explicit
 * verification step below makes "silently did nothing" impossible. */
static const char *V2_TABLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_blocks ("
    "  global_height INTEGER PRIMARY KEY,"
    "  block_id BLOB NOT NULL UNIQUE,"
    "  prev_block_id BLOB NOT NULL,"
    "  epoch INTEGER NOT NULL,"
    "  tx_root BLOB NOT NULL,"
    "  domain_updates_root BLOB NOT NULL,"
    "  domains_root BLOB NOT NULL,"
    "  system_root BLOB NOT NULL,"
    "  core_root BLOB NOT NULL,"
    "  global_root BLOB NOT NULL,"
    "  vset_hash BLOB NOT NULL,"
    "  tx_count INTEGER NOT NULL,"
    "  qc BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_domain_heads ("
    "  domain_id INTEGER PRIMARY KEY,"
    "  head BLOB NOT NULL,"
    "  domain_height INTEGER NOT NULL,"
    "  last_updated_global INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_domain_updates ("
    "  global_height INTEGER NOT NULL,"
    "  domain_id INTEGER NOT NULL,"
    "  upd BLOB NOT NULL,"
    "  upd_hash BLOB NOT NULL,"
    "  PRIMARY KEY (global_height, domain_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_root_history ("
    "  domain_id INTEGER NOT NULL,"
    "  domain_height INTEGER NOT NULL,"
    "  global_height INTEGER NOT NULL,"
    "  state_root BLOB NOT NULL,"
    "  upd_hash BLOB NOT NULL,"
    "  ruleset_version INTEGER NOT NULL,"
    "  ruleset_hash BLOB NOT NULL,"
    "  PRIMARY KEY (domain_id, domain_height)"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_tx_index ("
    "  global_height INTEGER NOT NULL,"
    "  global_index INTEGER NOT NULL,"
    "  tx_id BLOB NOT NULL UNIQUE,"
    "  owner_domain INTEGER NOT NULL,"
    "  touched BLOB NOT NULL,"
    "  wire_version INTEGER NOT NULL,"
    "  PRIMARY KEY (global_height, global_index)"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_tx_local_index ("
    "  tx_id BLOB NOT NULL,"
    "  domain_id INTEGER NOT NULL,"
    "  domain_height INTEGER NOT NULL,"
    "  local_index INTEGER NOT NULL,"
    "  PRIMARY KEY (domain_id, domain_height, local_index),"
    "  UNIQUE (tx_id, domain_id)"
    ");";

int nodus_witness_db_schema_version(nodus_witness_t *w, uint32_t *out) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "PRAGMA user_version", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    sqlite3_int64 v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (v < 0) return -1;
    *out = (uint32_t)v;
    return 0;
}

/* 1 = utxo_set has a domain_id column, 0 = not, -1 = fault. */
static int utxo_has_domain_col(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "PRAGMA table_info(utxo_set)", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, "domain_id") == 0) found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    return found;
}

/* 1 = table exists, 0 = not, -1 = fault. */
static int table_exists(nodus_witness_t *w, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "SQL failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_migrate_v2s5_ex(nodus_witness_t *w,
                                     nodus_v2_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION) return 0;        /* idempotent    */
    if (ver != 0) {
        /* Unknown/newer schema: this build must not touch it. */
        QGP_LOG_ERROR(LOG_TAG,
                      "unknown schema version %u — refusing to migrate",
                      ver);
        return -1;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    do {
        if (fail_at == V2MIG_FAIL_AFTER_BEGIN) break;

        if (exec_sql(w, V2_TABLES_DDL) != 0) break;
        if (fail_at == V2MIG_FAIL_AFTER_TABLES) break;

        /* Legacy backfill: every pre-existing UTXO becomes DNA_CORE-owned
         * through the NOT NULL DEFAULT — one owner, never nullable. */
        int has = utxo_has_domain_col(w);
        if (has < 0) break;
        if (has == 0 &&
            exec_sql(w, "ALTER TABLE utxo_set ADD COLUMN domain_id "
                        "INTEGER NOT NULL DEFAULT 1") != 0)
            break;
        if (fail_at == V2MIG_FAIL_AFTER_ALTER) break;

        /* Verify the schema actually materialized — a DDL that silently
         * did nothing must not be reported as success. */
        static const char *required[] = {
            "v2_blocks", "v2_domain_heads", "v2_domain_updates",
            "v2_root_history", "v2_tx_index", "v2_tx_local_index"
        };
        int verified = 1;
        for (size_t i = 0;
             i < sizeof(required) / sizeof(required[0]) && verified; i++)
            if (table_exists(w, required[i]) != 1) verified = 0;
        if (utxo_has_domain_col(w) != 1) verified = 0;
        if (!verified) break;
        if (fail_at == V2MIG_FAIL_AFTER_VERIFY) break;

        /* user_version participates in the transaction (DB-header field
         * covered by the rollback journal). */
        if (exec_sql(w, "PRAGMA user_version = 5") != 0) break;
        if (fail_at == V2MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (!ok) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    return 0;
}

int nodus_witness_db_migrate_v2s5(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s5_ex(w, V2MIG_FAIL_NONE);
}

/* ── S6: the three generic manifest/claim tables (5 → 6) ────────────── */

static const char *V2S6_TABLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_manifests ("
    "  manifest_seq INTEGER PRIMARY KEY,"
    "  manifest_hash BLOB NOT NULL UNIQUE,"
    "  manifest BLOB NOT NULL,"
    "  committed_height INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_dist_state ("
    "  manifest_seq INTEGER PRIMARY KEY,"
    "  remaining INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_claims_spent ("
    "  nullifier BLOB PRIMARY KEY,"
    "  manifest_seq INTEGER NOT NULL,"
    "  leaf_index INTEGER NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  claimed_height INTEGER NOT NULL,"
    "  utxo_id BLOB NOT NULL"
    ");";

int nodus_witness_db_migrate_v2s6_ex(nodus_witness_t *w,
                                     nodus_v2s6_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S6) return 0;     /* idempotent    */
    if (ver == 0) {
        /* Fresh/legacy: reach version 5 first (its own atomic txn — a
         * crash between the stages leaves a VALID version-5 schema and
         * re-running resumes here). */
        if (nodus_witness_db_migrate_v2s5(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION;
    }
    if (ver != NODUS_V2_SCHEMA_VERSION) {
        /* Unknown/newer schema: this build must not touch it. */
        QGP_LOG_ERROR(LOG_TAG,
                      "unknown schema version %u — refusing S6 migration",
                      ver);
        return -1;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    do {
        if (fail_at == V2S6MIG_FAIL_AFTER_BEGIN) break;

        if (exec_sql(w, V2S6_TABLES_DDL) != 0) break;
        if (fail_at == V2S6MIG_FAIL_AFTER_TABLES) break;

        /* Verify the schema actually materialized. */
        static const char *required[] = {
            "v2_manifests", "v2_dist_state", "v2_claims_spent"
        };
        int verified = 1;
        for (size_t i = 0;
             i < sizeof(required) / sizeof(required[0]) && verified; i++)
            if (table_exists(w, required[i]) != 1) verified = 0;
        if (!verified) break;
        if (fail_at == V2S6MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 6") != 0) break;
        if (fail_at == V2S6MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (!ok) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    return 0;
}

int nodus_witness_db_migrate_v2s6(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s6_ex(w, V2S6MIG_FAIL_NONE);
}
