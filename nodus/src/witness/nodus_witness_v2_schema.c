/**
 * @file nodus_witness_v2_schema.c
 * @brief Ledger V2 Season 5 — versioned schema + atomic migration
 *        implementation (INACTIVE). Contract: nodus_witness_v2_schema.h.
 *
 * @file nodus_witness_v2_schema.c
 */

#include "witness/nodus_witness_v2_schema.h"
#include "dnac/ledger_roots_v2.h"   /* DNA_V2_STORAGE_ACTIVE / EXITING */

#include <sqlite3.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2SCHEMA"

/* The six S5 tables. IF NOT EXISTS keeps re-entry harmless; the explicit
 * verification step below makes "silently did nothing" impossible. */
/* v2_blocks carries GENERIC commitments only (tx / updates / domains /
 * global). Per-domain state roots live in v2_domain_heads /
 * v2_root_history keyed by explicit domain_id — a global structure never
 * carries a named-domain field. */
static const char *V2_TABLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_blocks ("
    "  global_height INTEGER PRIMARY KEY,"
    "  block_id BLOB NOT NULL UNIQUE,"
    "  prev_block_id BLOB NOT NULL,"
    "  epoch INTEGER NOT NULL,"
    "  tx_root BLOB NOT NULL,"
    "  domain_updates_root BLOB NOT NULL,"
    "  domains_root BLOB NOT NULL,"
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

/* 1 = `table` has a column named `col`, 0 = not, -1 = fault. Generic
 * single-column presence check — S15's DROP COLUMN gate needs "does this
 * one column exist", not the exact-shape match `table_cols_exact` makes. */
static int col_present(nodus_witness_t *w, const char *table,
                       const char *col) {
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(\"%s\")", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, col) == 0) found = 1;
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

/* 1 = index `name` exists ON table `table`, 0 = not, -1 = fault. */
static int index_exists(nodus_witness_t *w, const char *name,
                        const char *table) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1 "
            "AND tbl_name=?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, table, -1, SQLITE_TRANSIENT);
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

/* Committed rows in v2_tx_index. >= 0 count, -1 on ANY fault.
 *
 * O15B §9 — a fault is deliberately NOT zero. This number decides whether a
 * migration that cannot be undone may proceed, so "the table could not be
 * read" must never be answered with "the table is empty". */
static int s8_tx_index_rows(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM v2_tx_index",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 rows = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rows < 0) return -1;
    return (rows > INT_MAX) ? INT_MAX : (int)rows;
}

/* ── O15B §9: the schema-version re-read every migration owes ─────────
 *
 * Every pre-BEGIN `PRAGMA user_version` read decides NOTHING. It is a cheap
 * early-out that runs while no lock is held, so between it and
 * `BEGIN IMMEDIATE` another connection may complete an arbitrary number of
 * migrations. Two concrete consequences, both real before this season:
 *
 *  - DOWNGRADE. We read 7, park on BEGIN IMMEDIATE, a peer migrates 7→8→9,
 *    we wake and stamp `PRAGMA user_version = 8` over a version-9 schema.
 *    The database then advertises a version whose tables it no longer has.
 *  - LOST REFUSAL. S8 refuses to run against a populated `v2_tx_index`
 *    because committed intents cannot be back-derived. It counted the rows
 *    pre-BEGIN, so a transaction committed in the window slipped past the
 *    very guard that exists to catch it.
 *
 * O15A closed exactly this for the 8→9 migration. This helper generalises
 * the fix so S5-S8 cannot drift back: the version is re-read INSIDE the
 * write transaction, where `BEGIN IMMEDIATE` guarantees no other writer can
 * intervene between the check and the mutation.
 *
 * Returns:
 *   1  proceed — the database is still at `expect_from`
 *   0  ALREADY DONE — a concurrent writer reached `expect_to` first. This is
 *      idempotent SUCCESS, not an error: the caller wanted the database at
 *      `expect_to`, and it is. Refusing here would turn a benign race into a
 *      startup failure.
 *  -1  refuse — any other version, or a read fault.
 */
static int mig_revalidate_version(nodus_witness_t *w,
                                  uint32_t expect_from,
                                  uint32_t expect_to,
                                  const char *stage) {
    uint32_t now = 0;
    if (nodus_witness_db_schema_version(w, &now) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
                      "%s: in-transaction schema re-read failed", stage);
        return -1;
    }
    if (now == expect_from) return 1;
    if (now == expect_to) {
        QGP_LOG_INFO(LOG_TAG,
                     "%s: another writer completed this migration first "
                     "(version %u) — idempotent success", stage, now);
        return 0;
    }
    QGP_LOG_ERROR(LOG_TAG,
                  "%s: schema moved to %u under us (expected %u) — refusing",
                  stage, now, expect_from);
    return -1;
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

        /* O15B §9 — the pre-BEGIN version read decided nothing. */
        int rv = mig_revalidate_version(w, 0, NODUS_V2_SCHEMA_VERSION, "S5");
        if (rv < 0) break;
        if (rv == 0) {
            /* A peer finished this migration while we waited for the
             * write lock. Nothing was written here, so release the lock
             * rather than COMMIT an empty transaction, and report the
             * success the caller actually asked for: the database is at
             * the target version. */
            (void)exec_sql(w, "ROLLBACK");
            return 0;
        }
        if (fail_at == V2MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2_TABLES_DDL) != 0) break;
        if (fail_at == V2MIG_FAIL_AFTER_TABLES) break;

        /* Domain ownership of the UTXO table: rebuild utxo_set with an
         * EXPLICIT `domain_id INTEGER NOT NULL` column and NO schema
         * default — ownership is written by every insert, never implied.
         * The legacy assignment (pre-existing DNA rows → the configured
         * legacy CORE domain, id 1) is the EXPLICIT `, 1` in the copy
         * SELECT below: a one-time migration rule, not a lasting
         * default. Fail-closed: the live column set must match the
         * pinned production layout exactly before the rebuild. */
        int has = utxo_has_domain_col(w);
        if (has < 0) break;
        if (has == 0) {
            static const char *expect_cols[] = {
                "nullifier", "owner", "amount", "token_id", "tx_hash",
                "output_index", "block_height", "created_at",
                "unlock_block"
            };
            sqlite3_stmt *ti = NULL;
            if (sqlite3_prepare_v2(w->db, "PRAGMA table_info(utxo_set)",
                                   -1, &ti, NULL) != SQLITE_OK)
                break;
            size_t ci = 0;
            int rc2, cols_ok = 1;
            while ((rc2 = sqlite3_step(ti)) == SQLITE_ROW) {
                const unsigned char *nm = sqlite3_column_text(ti, 1);
                if (ci >= sizeof(expect_cols) / sizeof(expect_cols[0]) ||
                    !nm || strcmp((const char *)nm, expect_cols[ci]) != 0) {
                    cols_ok = 0;
                    break;
                }
                ci++;
            }
            sqlite3_finalize(ti);
            if (!cols_ok || rc2 != SQLITE_DONE ||
                ci != sizeof(expect_cols) / sizeof(expect_cols[0])) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "utxo_set column drift — "
                              "refusing the domain-ownership rebuild");
                break;
            }
            if (exec_sql(w,
                "CREATE TABLE utxo_set_v2mig ("
                "  nullifier BLOB PRIMARY KEY,"
                "  owner TEXT NOT NULL,"
                "  amount INTEGER NOT NULL,"
                "  token_id BLOB NOT NULL DEFAULT x'"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "',"
                "  tx_hash BLOB NOT NULL,"
                "  output_index INTEGER NOT NULL,"
                "  block_height INTEGER NOT NULL DEFAULT 0,"
                "  created_at INTEGER NOT NULL DEFAULT 0,"
                "  unlock_block INTEGER NOT NULL DEFAULT 0,"
                "  domain_id INTEGER NOT NULL"
                ");"
                "INSERT INTO utxo_set_v2mig (nullifier, owner, amount, "
                "token_id, tx_hash, output_index, block_height, "
                "created_at, unlock_block, domain_id) "
                "SELECT nullifier, owner, amount, token_id, tx_hash, "
                "output_index, block_height, created_at, unlock_block, 1 "
                "FROM utxo_set;"
                "DROP TABLE utxo_set;"
                "ALTER TABLE utxo_set_v2mig RENAME TO utxo_set;"
                "CREATE INDEX IF NOT EXISTS idx_utxo_owner "
                "ON utxo_set(owner);"
                "CREATE INDEX IF NOT EXISTS idx_utxo_token "
                "ON utxo_set(token_id);") != 0)
                break;
        }
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

/* Generic distribution/claim state is namespaced by COMMITTED identity:
 * manifest_hash (the distribution id), target_domain_id and
 * target_asset_ref. manifest_seq survives only in v2_manifests as an
 * internal database locator — it keys NOTHING generic and appears in no
 * signature, nullifier or root. No column here carries a domain
 * default: ownership is written explicitly on every insert. */
static const char *V2S6_TABLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_manifests ("
    "  manifest_seq INTEGER PRIMARY KEY,"      /* LOCAL locator only     */
    "  manifest_hash BLOB NOT NULL UNIQUE,"    /* committed identity     */
    "  manifest BLOB NOT NULL,"
    "  committed_height INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_dist_state ("
    "  manifest_hash BLOB PRIMARY KEY,"
    "  target_domain_id INTEGER NOT NULL,"
    "  target_asset_ref BLOB NOT NULL,"
    "  remaining INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_claims_spent ("
    "  nullifier BLOB PRIMARY KEY,"
    "  manifest_hash BLOB NOT NULL,"
    "  target_domain_id INTEGER NOT NULL,"
    "  target_asset_ref BLOB NOT NULL,"
    "  leaf_index INTEGER NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  claimed_height INTEGER NOT NULL,"
    "  output_id BLOB NOT NULL"                /* runtime-owned identity */
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

        /* O15B §9 — the pre-BEGIN version read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION,
                                        NODUS_V2_SCHEMA_VERSION_S6, "S6");
        if (rv < 0) break;
        if (rv == 0) {
            /* A peer finished this migration while we waited for the
             * write lock. Nothing was written here, so release the lock
             * rather than COMMIT an empty transaction, and report the
             * success the caller actually asked for: the database is at
             * the target version. */
            (void)exec_sql(w, "ROLLBACK");
            return 0;
        }
        if (fail_at == V2S6MIG_FAIL_AFTER_REVALIDATE) break;

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

/* ── S7: the four generic pool-state tables (6 → 7) ─────────────────── */

/* Generic pool state is namespaced by (domain_id, pool_id) — a pool id
 * is unique only INSIDE its owning domain. No column carries a domain,
 * pool or asset default: ownership is written explicitly on every
 * insert. v2_pool_notes is the DERIVED O(count) commitment list (path
 * serving / recovery); the consensus O(D) state lives in v2_pools. */
static const char *V2S7_TABLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_pools ("
    "  domain_id INTEGER NOT NULL,"
    "  pool_id INTEGER NOT NULL,"
    "  config_version INTEGER NOT NULL,"
    "  tree_depth INTEGER NOT NULL,"
    "  history_limit INTEGER NOT NULL,"
    "  asset_ref BLOB NOT NULL,"
    "  note_count INTEGER NOT NULL,"
    "  note_root BLOB NOT NULL,"
    "  frontier BLOB NOT NULL,"
    "  nul_count INTEGER NOT NULL,"
    "  nul_root BLOB NOT NULL,"
    "  balance INTEGER NOT NULL,"
    "  hist_count INTEGER NOT NULL,"
    "  hist_next_seq INTEGER NOT NULL,"
    "  PRIMARY KEY (domain_id, pool_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_pool_notes ("
    "  domain_id INTEGER NOT NULL,"
    "  pool_id INTEGER NOT NULL,"
    "  position INTEGER NOT NULL,"
    "  commitment BLOB NOT NULL,"
    "  global_height INTEGER NOT NULL,"
    "  tx_index INTEGER NOT NULL,"
    "  output_slot INTEGER NOT NULL,"
    "  PRIMARY KEY (domain_id, pool_id, position)"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_pool_nullifiers ("
    "  domain_id INTEGER NOT NULL,"
    "  pool_id INTEGER NOT NULL,"
    "  nullifier BLOB NOT NULL,"
    "  position INTEGER NOT NULL,"
    "  global_height INTEGER NOT NULL,"
    "  tx_index INTEGER NOT NULL,"
    "  input_slot INTEGER NOT NULL,"
    "  PRIMARY KEY (domain_id, pool_id, nullifier),"
    "  UNIQUE (domain_id, pool_id, position)"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_pool_roots ("
    "  domain_id INTEGER NOT NULL,"
    "  pool_id INTEGER NOT NULL,"
    "  seq INTEGER NOT NULL,"
    "  note_root BLOB NOT NULL,"
    "  global_height INTEGER NOT NULL,"
    "  PRIMARY KEY (domain_id, pool_id, seq),"
    "  UNIQUE (domain_id, pool_id, note_root)"
    ");";

/* 1 = the table's column-name sequence matches `cols` exactly,
 * 0 = drift/partial/missing, -1 = fault. A DDL that silently did
 * nothing — or a pre-existing table with a different shape — must not
 * be reported as a migrated schema. */
static int table_cols_exact(nodus_witness_t *w, const char *table,
                            const char *const *cols, size_t n_cols) {
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(\"%s\")", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    size_t ci = 0;
    int rc, ok = 1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *nm = sqlite3_column_text(st, 1);
        if (ci >= n_cols || !nm ||
            strcmp((const char *)nm, cols[ci]) != 0) {
            ok = 0;
            break;
        }
        ci++;
    }
    sqlite3_finalize(st);
    if (!ok) return 0;
    if (rc != SQLITE_DONE) return -1;
    return ci == n_cols ? 1 : 0;
}

int nodus_witness_db_migrate_v2s7_ex(nodus_witness_t *w,
                                     nodus_v2s7_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S7) return 0;     /* idempotent    */
    if (ver == 0 || ver == NODUS_V2_SCHEMA_VERSION) {
        /* Fresh/legacy/S5: reach version 6 first (its own atomic
         * stage chain — a crash leaves a VALID intermediate version
         * and re-running resumes here). */
        if (nodus_witness_db_migrate_v2s6(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S6;
    }
    if (ver != NODUS_V2_SCHEMA_VERSION_S6) {
        /* Unknown/newer schema (8+): this build must not touch it. */
        QGP_LOG_ERROR(LOG_TAG,
                      "unknown schema version %u — refusing S7 migration",
                      ver);
        return -1;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    do {
        if (fail_at == V2S7MIG_FAIL_AFTER_BEGIN) break;

        /* O15B §9 — the pre-BEGIN version read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S6,
                                        NODUS_V2_SCHEMA_VERSION_S7, "S7");
        if (rv < 0) break;
        if (rv == 0) {
            /* A peer finished this migration while we waited for the
             * write lock. Nothing was written here, so release the lock
             * rather than COMMIT an empty transaction, and report the
             * success the caller actually asked for: the database is at
             * the target version. */
            (void)exec_sql(w, "ROLLBACK");
            return 0;
        }
        if (fail_at == V2S7MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2S7_TABLES_DDL) != 0) break;
        if (fail_at == V2S7MIG_FAIL_AFTER_TABLES) break;

        /* Verify the schema actually materialized with EXACTLY the
         * expected shape — column drift and partial tables reject. */
        static const char *const pools_cols[] = {
            "domain_id", "pool_id", "config_version", "tree_depth",
            "history_limit", "asset_ref", "note_count", "note_root",
            "frontier", "nul_count", "nul_root", "balance",
            "hist_count", "hist_next_seq"
        };
        static const char *const notes_cols[] = {
            "domain_id", "pool_id", "position", "commitment",
            "global_height", "tx_index", "output_slot"
        };
        static const char *const nuls_cols[] = {
            "domain_id", "pool_id", "nullifier", "position",
            "global_height", "tx_index", "input_slot"
        };
        static const char *const roots_cols[] = {
            "domain_id", "pool_id", "seq", "note_root", "global_height"
        };
        int verified = 1;
        if (table_cols_exact(w, "v2_pools", pools_cols,
                sizeof(pools_cols) / sizeof(pools_cols[0])) != 1)
            verified = 0;
        if (verified && table_cols_exact(w, "v2_pool_notes", notes_cols,
                sizeof(notes_cols) / sizeof(notes_cols[0])) != 1)
            verified = 0;
        if (verified && table_cols_exact(w, "v2_pool_nullifiers",
                nuls_cols, sizeof(nuls_cols) / sizeof(nuls_cols[0])) != 1)
            verified = 0;
        if (verified && table_cols_exact(w, "v2_pool_roots", roots_cols,
                sizeof(roots_cols) / sizeof(roots_cols[0])) != 1)
            verified = 0;
        if (!verified) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S7 schema shape drift — refusing");
            break;
        }
        if (fail_at == V2S7MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 7") != 0) break;
        if (fail_at == V2S7MIG_FAIL_BEFORE_COMMIT) break;

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

int nodus_witness_db_migrate_v2s7(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s7_ex(w, V2S7MIG_FAIL_NONE);
}

/* ── S8: the semantic-intent index (7 → 8, intent season) ───────────── */

/* v2_intent_index is the SEMANTIC transaction index: intent_id is the
 * canonical authorization-witness-independent identity (dna_env_intent_id)
 * and the PRIMARY KEY — a committed intent exists at most once per chain.
 * tx_id is the accepted FULL-WIRE realization of that intent (the same
 * value v2_tx_index carries) and is UNIQUE — one intent, one accepted
 * wire realization, and one wire realization can never serve two intents.
 * Both uniqueness constraints are the fail-closed DATABASE backstop
 * behind the apply engine's pre-BEGIN replay guard. */
static const char *V2S8_TABLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_intent_index ("
    "  intent_id BLOB NOT NULL PRIMARY KEY,"
    "  tx_id BLOB NOT NULL UNIQUE,"
    "  global_height INTEGER NOT NULL,"
    "  global_index INTEGER NOT NULL"
    ");";

/* 1 = v2_intent_index carries EXACTLY the two uniqueness constraints the
 * replay backstop leans on (intent_id PRIMARY KEY; ONE unique index over
 * exactly tx_id), 0 = missing/different, -1 = fault. Column NAMES alone
 * are not shape: the DDL is CREATE TABLE IF NOT EXISTS, so a
 * pre-existing constraint-free table with matching names would otherwise
 * migrate with NO database backstop behind the pre-BEGIN replay guard
 * (intent-season review finding — this check closes it). */
static int s8_intent_constraints_ok(nodus_witness_t *w) {
    /* intent_id must be the single-column PRIMARY KEY: PRAGMA table_info
     * pk ordinal 1 on intent_id, 0 on every other column. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "PRAGMA table_info(\"v2_intent_index\")", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    int rc, ok = 1, saw_intent = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *nm = sqlite3_column_text(st, 1);
        int pk = sqlite3_column_int(st, 5);
        if (!nm) { ok = 0; break; }
        if (strcmp((const char *)nm, "intent_id") == 0) {
            saw_intent = 1;
            if (pk != 1) { ok = 0; break; }
        } else if (pk != 0) {
            ok = 0;
            break;
        }
    }
    sqlite3_finalize(st);
    if (ok && rc != SQLITE_DONE) return -1;
    if (!ok || !saw_intent) return 0;

    /* Exactly ONE declared UNIQUE index (origin 'u'), covering exactly
     * the single column tx_id. (The PRIMARY KEY's own sqlite_autoindex
     * reports origin 'pk' and is accounted above.) */
    if (sqlite3_prepare_v2(w->db,
            "PRAGMA index_list(\"v2_intent_index\")", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    int n_unique_u = 0;
    char uname[128] = { 0 };
    ok = 1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int is_unique = sqlite3_column_int(st, 2);
        const unsigned char *origin = sqlite3_column_text(st, 3);
        if (!origin) { ok = 0; break; }
        if (is_unique && strcmp((const char *)origin, "u") == 0) {
            const unsigned char *nm = sqlite3_column_text(st, 1);
            if (!nm) { ok = 0; break; }
            n_unique_u++;
            snprintf(uname, sizeof(uname), "%s", (const char *)nm);
        }
    }
    sqlite3_finalize(st);
    if (ok && rc != SQLITE_DONE) return -1;
    if (!ok || n_unique_u != 1) return 0;

    char sql[192];
    snprintf(sql, sizeof(sql), "PRAGMA index_info(\"%s\")", uname);
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n_cols = 0;
    ok = 1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *cn = sqlite3_column_text(st, 2);
        if (!cn || strcmp((const char *)cn, "tx_id") != 0) { ok = 0; break; }
        n_cols++;
    }
    sqlite3_finalize(st);
    if (ok && rc != SQLITE_DONE) return -1;
    return (ok && n_cols == 1) ? 1 : 0;
}

int nodus_witness_db_migrate_v2s8_ex(nodus_witness_t *w,
                                     nodus_v2s8_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S8) return 0;     /* idempotent    */
    if (ver == 0 || ver == NODUS_V2_SCHEMA_VERSION ||
        ver == NODUS_V2_SCHEMA_VERSION_S6) {
        /* Fresh/legacy/S5/S6: reach version 7 first (its own atomic
         * stage chain — a crash leaves a VALID intermediate version and
         * re-running resumes here). */
        if (nodus_witness_db_migrate_v2s7(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S7;
    }
    if (ver != NODUS_V2_SCHEMA_VERSION_S7) {
        /* Unknown/newer schema (9+): this build must not touch it. */
        QGP_LOG_ERROR(LOG_TAG,
                      "unknown schema version %u — refusing S8 migration",
                      ver);
        return -1;
    }

    /* Cheap early-out ONLY — this DECIDES NOTHING.
     *
     * O15B §9: this count used to be the migration's whole defence and it
     * ran with no lock held, so a V2 transaction committed between here and
     * BEGIN IMMEDIATE walked straight past it. The authoritative copy now
     * runs INSIDE the transaction (below); this one exists purely to avoid
     * taking a write lock in the common already-populated case. A fault is
     * still a refusal — an unreadable index is not an empty one. */
    {
        int rows = s8_tx_index_rows(w);
        if (rows < 0) return -1;
        if (rows > 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "v2_tx_index holds committed row(s) whose intent "
                          "identities cannot be derived — refusing S8 "
                          "migration (fail closed, pre-BEGIN early-out)");
            return -1;
        }
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    do {
        if (fail_at == V2S8MIG_FAIL_AFTER_BEGIN) break;

        /* O15B §9 — BOTH pre-BEGIN reads are re-taken here, under the write
         * lock, where nothing can commit between the check and the DDL. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S7,
                                        NODUS_V2_SCHEMA_VERSION_S8, "S8");
        if (rv < 0) break;
        if (rv == 0) {
            /* A peer finished this migration while we waited for the
             * write lock. Nothing was written here, so release the lock
             * rather than COMMIT an empty transaction, and report the
             * success the caller actually asked for: the database is at
             * the target version. */
            (void)exec_sql(w, "ROLLBACK");
            return 0;
        }

        /* FAIL CLOSED on a populated wire index: an intent_id can only be
         * derived from the ORIGINAL envelope bytes, which v2_tx_index does
         * not store, so a database that already committed V2 transactions
         * cannot be backfilled with their intent identities. Migrating it
         * anyway would leave every pre-migration intent silently unguarded
         * against semantic replay. */
        {
            int rows = s8_tx_index_rows(w);
            if (rows < 0) break;
            if (rows > 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "v2_tx_index gained %d committed row(s) after "
                              "the pre-BEGIN check — refusing S8 migration "
                              "(fail closed, in-transaction)", rows);
                break;
            }
        }
        if (fail_at == V2S8MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2S8_TABLES_DDL) != 0) break;
        if (fail_at == V2S8MIG_FAIL_AFTER_TABLES) break;

        /* Verify the schema actually materialized with EXACTLY the
         * expected shape — column drift and partial tables reject. */
        static const char *const intent_cols[] = {
            "intent_id", "tx_id", "global_height", "global_index"
        };
        if (table_cols_exact(w, "v2_intent_index", intent_cols,
                sizeof(intent_cols) / sizeof(intent_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S8 schema shape drift — refusing");
            break;
        }
        /* Names are necessary, not sufficient: the uniqueness
         * CONSTRAINTS are the replay backstop, so their existence is
         * verified explicitly (helper doc above). */
        if (s8_intent_constraints_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "v2_intent_index lacks the "
                          "declared uniqueness constraints — refusing");
            break;
        }
        if (fail_at == V2S8MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 8") != 0) break;
        if (fail_at == V2S8MIG_FAIL_BEFORE_COMMIT) break;

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

int nodus_witness_db_migrate_v2s8(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s8_ex(w, V2S8MIG_FAIL_NONE);
}

/* ── O14 (8 → 9): v2_blocks carries the canonical header bytes ───────
 * Rebuild rather than ALTER: the column is NOT NULL and SQLite cannot
 * add a NOT NULL column without a default — and a defaulted header is
 * precisely the silent hole this column exists to close. Safe because
 * the migration refuses to run on a populated table (below). */
static const char *const V2S9_TABLES_DDL =
    "DROP TABLE IF EXISTS v2_blocks;"
    "CREATE TABLE v2_blocks ("
    "  global_height INTEGER PRIMARY KEY,"
    "  block_id BLOB NOT NULL UNIQUE,"
    "  prev_block_id BLOB NOT NULL,"
    "  epoch INTEGER NOT NULL,"
    "  tx_root BLOB NOT NULL,"
    "  domain_updates_root BLOB NOT NULL,"
    "  domains_root BLOB NOT NULL,"
    "  global_root BLOB NOT NULL,"
    "  vset_hash BLOB NOT NULL,"
    "  tx_count INTEGER NOT NULL,"
    "  header BLOB NOT NULL,"
    "  qc BLOB"
    ");";

int nodus_witness_db_migrate_v2s9_ex(nodus_witness_t *w,
                                     nodus_v2s9_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S9) return 0;     /* idempotent    */
    if (ver == 0 || ver == NODUS_V2_SCHEMA_VERSION ||
        ver == NODUS_V2_SCHEMA_VERSION_S6 ||
        ver == NODUS_V2_SCHEMA_VERSION_S7) {
        /* Reach version 8 first (its own atomic stage chain — a crash
         * leaves a VALID intermediate version and re-running resumes). */
        if (nodus_witness_db_migrate_v2s8(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S8;
    }
    if (ver != NODUS_V2_SCHEMA_VERSION_S8) {
        /* Unknown/newer schema (10+): this build must not touch it. */
        QGP_LOG_ERROR(LOG_TAG,
                      "unknown schema version %u — refusing S9 migration",
                      ver);
        return -1;
    }

    /* An early, CHEAP rejection so the common failure does not have to
     * take a write lock. It decides NOTHING: the authoritative check is
     * re-run inside the transaction below, and only that one is trusted.
     * See the TOCTOU note there. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM v2_blocks", -1, &st, NULL)
            != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        sqlite3_int64 rows =
            (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0) : -1;
        sqlite3_finalize(st);
        if (rows < 0) return -1;
        if (rows > 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "v2_blocks holds %lld committed row(s) whose "
                          "canonical header bytes cannot be derived — "
                          "refusing S9 migration (fail closed)",
                          (long long)rows);
            return -1;
        }
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S9MIG_FAIL_AFTER_BEGIN) break;

        /* ── O15A: RE-VALIDATE EVERY LOAD-BEARING CONDITION HERE ──────
         * The state that was validated MUST be the state that is
         * migrated. Every check above ran before BEGIN IMMEDIATE took
         * its write lock, so between reading them and mutating there was
         * a window in which another connection could commit. That is not
         * a theoretical concern here: the DDL below begins with
         * `DROP TABLE IF EXISTS v2_blocks`, so a block committed inside
         * that window would be destroyed by a migration that had already
         * concluded the table was empty — and those canonical header
         * bytes are, by this migration's own reasoning, unrecoverable.
         *
         * Re-reading under the lock closes it: from BEGIN IMMEDIATE
         * onwards no other connection can write, so what is observed
         * here is what gets migrated. A concurrent writer must now land
         * either wholly before this snapshot (and be seen) or wholly
         * after the migration commits — never between.
         *
         * Note this is NOT "the earlier check, repeated": the earlier one
         * is an optimisation, this one is the decision. */
        uint32_t ver_tx = 0;
        if (nodus_witness_db_schema_version(w, &ver_tx) != 0) break;
        if (ver_tx == NODUS_V2_SCHEMA_VERSION_S9) {
            /* Another connection completed this migration while we were
             * queuing for the lock. Nothing to do, and NOT an error — the
             * post-condition the caller asked for already holds. */
            already = 1;
            break;
        }
        if (ver_tx != NODUS_V2_SCHEMA_VERSION_S8) {
            QGP_LOG_ERROR(LOG_TAG,
                          "schema version changed to %u under the "
                          "migration — refusing (fail closed)", ver_tx);
            break;
        }

        {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT COUNT(*) FROM v2_blocks", -1, &st, NULL)
                != SQLITE_OK)
                break;
            int rc = sqlite3_step(st);
            sqlite3_int64 rows =
                (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0) : -1;
            sqlite3_finalize(st);
            if (rows < 0) break;
            if (rows > 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "v2_blocks gained %lld row(s) between the "
                              "preflight and the migration — refusing "
                              "(fail closed)", (long long)rows);
                break;
            }
        }
        if (fail_at == V2S9MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2S9_TABLES_DDL) != 0) break;
        if (fail_at == V2S9MIG_FAIL_AFTER_TABLES) break;

        /* Verify the schema actually materialized with EXACTLY the
         * expected shape — column drift and partial tables reject. */
        static const char *const block_cols[] = {
            "global_height", "block_id", "prev_block_id", "epoch",
            "tx_root", "domain_updates_root", "domains_root",
            "global_root", "vset_hash", "tx_count", "header", "qc"
        };
        if (table_cols_exact(w, "v2_blocks", block_cols,
                sizeof(block_cols) / sizeof(block_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S9 schema shape drift — refusing");
            break;
        }
        if (fail_at == V2S9MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 9") != 0) break;
        if (fail_at == V2S9MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    /* The migration was already done by someone else: release the lock
     * without writing, and report the post-condition as satisfied. */
    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s9(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s9_ex(w, V2S9MIG_FAIL_NONE);
}

/* ═══ S10 — O15C activation authority ═══════════════════════════════════ */

int nodus_witness_db_migrate_v2s10_ex(nodus_witness_t *w,
                                      nodus_v2s10_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S10) return 0;    /* idempotent    */
    if (ver == 0 || ver == NODUS_V2_SCHEMA_VERSION ||
        ver == NODUS_V2_SCHEMA_VERSION_S6 ||
        ver == NODUS_V2_SCHEMA_VERSION_S7 ||
        ver == NODUS_V2_SCHEMA_VERSION_S8) {
        if (nodus_witness_db_migrate_v2s9(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S9;
    }
    if (ver != NODUS_V2_SCHEMA_VERSION_S9) {
        QGP_LOG_ERROR(LOG_TAG,
                      "unknown schema version %u — refusing S10 migration",
                      ver);
        return -1;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S10MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S9,
                                        NODUS_V2_SCHEMA_VERSION_S10, "S10");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S10MIG_FAIL_AFTER_REVALIDATE) break;

        /* O15J Faz 3 — S10 IS NOW AN EMPTY RUNG.
         *
         * It created the two activation-authority tables (`v2_activation`
         * + `v2_activation_readiness`) and verified their exact column
         * shape. Both went with the activation ceremony, so this stage
         * creates nothing and there is nothing to verify.
         *
         * The RUNG ITSELF STAYS, and deliberately: the ladder is a chain
         * of exact predecessors (S11 refuses anything but a version-10
         * database, and every fresh database — the genesis derivation's
         * nodus_witness_db_migrate_v2s16 cascade included — climbs
         * through it), and version 10 databases exist. Collapsing 9→11 would
         * renumber every rung above it and strand them. The two fail
         * injection points below are kept at their numbers for the same
         * reason — removing them would renumber
         * V2S10MIG_FAIL_BEFORE_COMMIT — and now simply abort a stage that
         * writes only the version. */
        if (fail_at == V2S10MIG_FAIL_AFTER_TABLES) break;
        if (fail_at == V2S10MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 10") != 0) break;
        if (fail_at == V2S10MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s10(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s10_ex(w, V2S10MIG_FAIL_NONE);
}

/* ── S11 (O15E Faz B): canonical envelope byte availability — an EMPTY
 * rung since the tokenomics-v3 P4 fix round (see inside) ────────────── */

int nodus_witness_db_migrate_v2s11_ex(nodus_witness_t *w,
                                      nodus_v2s11_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S11) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S10) {
        if (nodus_witness_db_migrate_v2s10(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S10;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S11MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S10,
                                        NODUS_V2_SCHEMA_VERSION_S11, "S11");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S11MIG_FAIL_AFTER_REVALIDATE) break;

        /* tokenomics-v3 P4 fix round — S11 IS NOW AN EMPTY RUNG (the
         * O15J Faz 3 S10 precedent above).
         *
         * It created `v2_tx_bytes` (the canonical envelope bytes of every
         * committed transaction, for the retired BlockMessage v1 assembly)
         * and verified its exact column shape. The table had NO reader
         * left — its BlockMessage consumer was deleted with the closed
         * consensus lane (R3 W4) — and its `tx_id UNIQUE` column turned a
         * byte-identical envelope in a later block into a failed insert,
         * a node FAULT on every node: a chain halt one proposer could
         * trigger. It was OUT of every state root (roots_v2 / merkle code
         * never read it), so deleting it moves no root byte. The chain is
         * devnet and wipes, so there is no drop rung: a fresh database
         * simply never gets the table.
         *
         * The RUNG ITSELF STAYS (the ladder is a chain of exact
         * predecessors — S12 refuses anything but a version-11 database —
         * and every fresh database climbs through it), and the fail
         * injection points keep their numbers; they now abort a stage
         * that creates nothing, still proving the version write rolls
         * back. */
        if (fail_at == V2S11MIG_FAIL_AFTER_TABLES) break;
        if (fail_at == V2S11MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 11") != 0) break;
        if (fail_at == V2S11MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s11(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s11_ex(w, V2S11MIG_FAIL_NONE);
}

/* ── S12 (O15F Task 4): per-block canonical claim byte availability ──── */

int nodus_witness_db_migrate_v2s12_ex(nodus_witness_t *w,
                                      nodus_v2s12_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S12) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S11) {
        if (nodus_witness_db_migrate_v2s11(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S11;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S12MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S11,
                                        NODUS_V2_SCHEMA_VERSION_S12, "S12");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S12MIG_FAIL_AFTER_REVALIDATE) break;

        /* v2_claim_bytes: PK (global_height, claim_index) is the canonical
         * block claim order the applier re-executes in; claim_hash =
         * SHA3-512(claim) is the persisted digest of the SAME canonical
         * bytes admission verified. NO default on any column.
         * v2_claim_counts: one row per committed block (PK global_height),
         * so "zero claims" is distinguishable from "pre-S12 height". */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_claim_bytes ("
                "  global_height INTEGER NOT NULL,"
                "  claim_index INTEGER NOT NULL,"
                "  claim_hash BLOB NOT NULL,"
                "  claim BLOB NOT NULL,"
                "  PRIMARY KEY (global_height, claim_index)"
                ")") != 0)
            break;
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_claim_counts ("
                "  global_height INTEGER PRIMARY KEY,"
                "  n_claims INTEGER NOT NULL"
                ")") != 0)
            break;
        if (fail_at == V2S12MIG_FAIL_AFTER_TABLES) break;

        static const char *const cb_cols[] = {
            "global_height", "claim_index", "claim_hash", "claim"
        };
        static const char *const cc_cols[] = {
            "global_height", "n_claims"
        };
        if (table_cols_exact(w, "v2_claim_bytes", cb_cols,
                sizeof(cb_cols) / sizeof(cb_cols[0])) != 1 ||
            table_cols_exact(w, "v2_claim_counts", cc_cols,
                sizeof(cc_cols) / sizeof(cc_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S12 schema shape drift — refusing");
            break;
        }
        if (fail_at == V2S12MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 12") != 0) break;
        if (fail_at == V2S12MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s12(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s12_ex(w, V2S12MIG_FAIL_NONE);
}

/* ── S13 (T3 wave 1): Tendermint WAL, state row, canonical commit cert ─ */

int nodus_witness_db_migrate_v2s13_ex(nodus_witness_t *w,
                                      nodus_v2s13_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S13) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S12) {
        if (nodus_witness_db_migrate_v2s12(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S12;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S13MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S12,
                                        NODUS_V2_SCHEMA_VERSION_S13, "S13");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S13MIG_FAIL_AFTER_REVALIDATE) break;

        /* tm_wal: PK (protocol_id, height, seq) is the replay order —
         * seq is monotonic per protocol_id and continues ACROSS heights,
         * so (height, seq) is a total order over the log. `bytes` is
         * SHA3-512(payload) ‖ payload; the digest is the only integrity
         * check a kind-2/3 row has (they carry no signature), and a
         * mismatch halts replay rather than skipping the row.
         * tm_state: exactly one row per protocol_id — the current
         * validator set, replaced in place, never appended to.
         * NO default on any column. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS tm_wal ("
                "  protocol_id INTEGER NOT NULL,"
                "  height INTEGER NOT NULL,"
                "  seq INTEGER NOT NULL,"
                "  kind INTEGER NOT NULL,"
                "  bytes BLOB NOT NULL,"
                "  PRIMARY KEY (protocol_id, height, seq)"
                ")") != 0)
            break;
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS tm_state ("
                "  protocol_id INTEGER PRIMARY KEY,"
                "  bytes BLOB NOT NULL"
                ")") != 0)
            break;
        /* The canonical certificate of h, written at h+1 (D-17 rev 3).
         * NULLABLE and unwritten here: every existing row keeps its
         * values and reads NULL, which is what "purely additive" means
         * for a column. Named commit_cert, not commit — see the header
         * (SQLite reserves COMMIT; measured on 3.44.4). */
        if (exec_sql(w,
                "ALTER TABLE v2_blocks ADD COLUMN commit_cert BLOB") != 0)
            break;
        if (fail_at == V2S13MIG_FAIL_AFTER_TABLES) break;

        static const char *const wal_cols[] = {
            "protocol_id", "height", "seq", "kind", "bytes"
        };
        static const char *const state_cols[] = {
            "protocol_id", "bytes"
        };
        /* v2_blocks is verified WHOLE: the S9 shape with commit_cert
         * appended. A column added in the wrong place — or an earlier
         * column quietly lost — is drift, not a migrated schema. */
        static const char *const block_cols[] = {
            "global_height", "block_id", "prev_block_id", "epoch",
            "tx_root", "domain_updates_root", "domains_root",
            "global_root", "vset_hash", "tx_count", "header", "qc",
            "commit_cert"
        };
        if (table_cols_exact(w, "tm_wal", wal_cols,
                sizeof(wal_cols) / sizeof(wal_cols[0])) != 1 ||
            table_cols_exact(w, "tm_state", state_cols,
                sizeof(state_cols) / sizeof(state_cols[0])) != 1 ||
            table_cols_exact(w, "v2_blocks", block_cols,
                sizeof(block_cols) / sizeof(block_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S13 schema shape drift — refusing");
            break;
        }
        if (fail_at == V2S13MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 13") != 0) break;
        if (fail_at == V2S13MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s13(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s13_ex(w, V2S13MIG_FAIL_NONE);
}

/* ── S14 (FLEET-TM-R3 W1): the four Comet stores, D-17 rev 5 ──────────
 *
 * Reachable in W1 ONLY from the unit tests (`test_cmt_host.c`): the
 * live path still stops at S12 (see the header paragraph) and R3-C1
 * flips it. */

int nodus_witness_db_migrate_v2s14_ex(nodus_witness_t *w,
                                      nodus_v2s14_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    /* The rung's DROP COLUMNs need SQLite ≥ 3.35.0 (header constant).
     * Asked FIRST — before the S13 chain below writes anything and
     * before BEGIN — against the RUN-TIME library, so an older library
     * refuses the whole call with nothing written instead of failing
     * three DDL statements deep with a generic rollback. It precedes
     * the idempotent version read on purpose: the requirement is the
     * witness's on its linked library, stated once at the S14 entry, so
     * a database ALREADY at S14 opened under a pre-3.35 library fails
     * closed here too. The linked library here is 3.40.1 (measured,
     * `sqlite3_libversion()`), so this guard passes on this tree; it
     * cannot be exercised by a test without an older libsqlite3. */
    if (sqlite3_libversion_number() < NODUS_V2_S14_SQLITE_MIN_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "S14 needs SQLite >= 3.35.0 (ALTER TABLE "
                      "DROP COLUMN); linked library is %s (%d) — refusing, "
                      "nothing written", sqlite3_libversion(),
                      sqlite3_libversion_number());
        return -1;
    }

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S14) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S13) {
        if (nodus_witness_db_migrate_v2s13(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S13;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S14MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S13,
                                        NODUS_V2_SCHEMA_VERSION_S14, "S14");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S14MIG_FAIL_AFTER_REVALIDATE) break;

        /* The reference's dbm.DB stores are byte-keyed maps
         * (store/store.go:632-716 key builders; state/store.go:25-45).
         * A key is the reference's own byte string, a value the proto
         * message the reference marshals. Point lookups only — the
         * reference never ranges over these keys either — so the BLOB
         * collation order of `H:10` vs `H:9` is irrelevant.
         * NO default on any column. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS cmt_blockstore ("
                "  key BLOB PRIMARY KEY,"
                "  value BLOB NOT NULL"
                ")") != 0)
            break;
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS cmt_state ("
                "  key BLOB PRIMARY KEY,"
                "  value BLOB NOT NULL"
                ")") != 0)
            break;
        /* cmt_wal: the S13 tm_wal row shape (D-15 rev 5) under the cmt_
         * name — PK (protocol_id, height, seq) is the replay order, seq
         * monotonic per protocol_id across heights, `bytes` =
         * SHA3-512(payload) ‖ payload. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS cmt_wal ("
                "  protocol_id INTEGER NOT NULL,"
                "  height INTEGER NOT NULL,"
                "  seq INTEGER NOT NULL,"
                "  kind INTEGER NOT NULL,"
                "  bytes BLOB NOT NULL,"
                "  PRIMARY KEY (protocol_id, height, seq)"
                ")") != 0)
            break;
        /* cmt_wal_sync: the DURABILITY BARRIER `FlushAndSync` needs, and
         * nothing else. D-15 rev 5 (4) routes the Write class through the
         * NORMAL connection and leaves the FlushAndSync MECHANISM to R3
         * under D-13. In SQLite a connection cannot fsync on demand — only
         * a COMMIT at `synchronous=FULL` does, and an EMPTY transaction
         * commits nothing and syncs nothing (measured). So the flush
         * bumps ONE counter row on the FULL connection: that commit
         * fdatasyncs the shared `-wal` file, which is the same file the
         * NORMAL connection appended its rows to, so every earlier row
         * becomes durable with it (measured: three NORMAL autocommit rows
         * issue zero fdatasync; one FULL commit issues exactly one, on the
         * `-wal` fd). `PRAGMA wal_checkpoint` was the alternative and is
         * REFUSED: it can return BUSY and then syncs nothing, which is a
         * durability hole that depends on timing. The counter's value is
         * never read by consensus and is in no hash. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS cmt_wal_sync ("
                "  protocol_id INTEGER PRIMARY KEY,"
                "  n INTEGER NOT NULL"
                ")") != 0)
            break;
        /* cmt_light: named by D-17 rev 5, filled by R3-L. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS cmt_light ("
                "  key BLOB PRIMARY KEY,"
                "  value BLOB NOT NULL"
                ")") != 0)
            break;
        /* S13's tables never reached a live chain (no live path writes
         * them); D-17 rev 5 drops both. */
        if (exec_sql(w, "DROP TABLE IF EXISTS tm_wal") != 0) break;
        if (exec_sql(w, "DROP TABLE IF EXISTS tm_state") != 0) break;
        /* The old consensus's header / seen certificate / canonical
         * certificate columns. Under Comet the header is in BlockMeta
         * (`H:<h>`), the seen commit in `SC:<h>`, the canonical commit
         * in `C:<h>`. None of the three is indexed, keyed or referenced
         * by a constraint (S9 DDL above), so DROP COLUMN is permitted;
         * measured on the linked 3.40.1. The library version that makes
         * DROP COLUMN exist at all was checked at the top of this
         * function (NODUS_V2_S14_SQLITE_MIN_VERSION), not here. */
        if (exec_sql(w, "ALTER TABLE v2_blocks DROP COLUMN header") != 0)
            break;
        if (exec_sql(w, "ALTER TABLE v2_blocks DROP COLUMN qc") != 0)
            break;
        if (exec_sql(w, "ALTER TABLE v2_blocks DROP COLUMN commit_cert") != 0)
            break;
        if (fail_at == V2S14MIG_FAIL_AFTER_TABLES) break;

        static const char *const kv_cols[] = { "key", "value" };
        static const char *const wal_cols[] = {
            "protocol_id", "height", "seq", "kind", "bytes"
        };
        static const char *const wal_sync_cols[] = { "protocol_id", "n" };
        /* v2_blocks is verified WHOLE: S13's list minus the three. */
        static const char *const block_cols[] = {
            "global_height", "block_id", "prev_block_id", "epoch",
            "tx_root", "domain_updates_root", "domains_root",
            "global_root", "vset_hash", "tx_count"
        };
        if (table_cols_exact(w, "cmt_blockstore", kv_cols,
                sizeof(kv_cols) / sizeof(kv_cols[0])) != 1 ||
            table_cols_exact(w, "cmt_state", kv_cols,
                sizeof(kv_cols) / sizeof(kv_cols[0])) != 1 ||
            table_cols_exact(w, "cmt_wal", wal_cols,
                sizeof(wal_cols) / sizeof(wal_cols[0])) != 1 ||
            table_cols_exact(w, "cmt_wal_sync", wal_sync_cols,
                sizeof(wal_sync_cols) / sizeof(wal_sync_cols[0])) != 1 ||
            table_cols_exact(w, "cmt_light", kv_cols,
                sizeof(kv_cols) / sizeof(kv_cols[0])) != 1 ||
            table_cols_exact(w, "v2_blocks", block_cols,
                sizeof(block_cols) / sizeof(block_cols[0])) != 1 ||
            table_exists(w, "tm_wal") != 0 ||
            table_exists(w, "tm_state") != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S14 schema shape drift — refusing");
            break;
        }
        if (fail_at == V2S14MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 14") != 0) break;
        if (fail_at == V2S14MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s14(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s14_ex(w, V2S14MIG_FAIL_NONE);
}

/* ── S15 migration: tokenomics-v3 P1 (Q2, "clean path") ────────────────
 * Contract: nodus_witness_v2_schema.h. */

int nodus_witness_db_migrate_v2s15_ex(nodus_witness_t *w,
                                      nodus_v2s15_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S15) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S14) {
        if (nodus_witness_db_migrate_v2s14(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S14;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S15MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S14,
                                        NODUS_V2_SCHEMA_VERSION_S15, "S15");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S15MIG_FAIL_AFTER_REVALIDATE) break;

        /* 1. The two out-of-root attendance tables. Neither is a leg of
         * any root by itself (ledger_roots_v2.h "attendance_root").
         * Round 2 (R2-1): both tables now ALSO live in the base schema
         * (WITNESS_DB_SCHEMA, nodus_witness.c) because they are
         * lane-independent bookkeeping, same as validators/
         * validator_stats — a fixture that migrates straight to an
         * earlier rung (e.g. S9) still needs them to exist. This
         * CREATE TABLE IF NOT EXISTS is now a no-op on any chain DB
         * this build created; it stays REQUIRED for a database an
         * OLDER build already created and is now migrating forward —
         * that database has neither table until this rung runs. The
         * shape verification below is unconditional either way. This
         * step's remaining REAL work is step 2: dropping the two
         * retired validators columns. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_attendance ("
                "  voter_id BLOB PRIMARY KEY,"
                "  signed_count INTEGER NOT NULL,"
                "  last_signed_height INTEGER NOT NULL"
                ")") != 0)
            break;
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_attendance_epoch ("
                "  epoch_start INTEGER PRIMARY KEY,"
                "  digest BLOB NOT NULL"
                ")") != 0)
            break;

        /* 2. Drop the two retired per-block counters, WHEN PRESENT — a
         * database that reached S14 without ever having them (a future
         * from-scratch fixture) is not asked to drop what it lacks.
         * SQLite >= 3.35 (DROP COLUMN) is already required by S14; no
         * new library check here. */
        {
            int lsig = col_present(w, "validators", "last_signed_block");
            int sepo = col_present(w, "validators",
                                   "signed_blocks_this_epoch");
            if (lsig < 0 || sepo < 0) break;
            if (lsig == 1 &&
                exec_sql(w, "ALTER TABLE validators "
                            "DROP COLUMN last_signed_block") != 0)
                break;
            if (sepo == 1 &&
                exec_sql(w, "ALTER TABLE validators "
                            "DROP COLUMN signed_blocks_this_epoch") != 0)
                break;
        }
        if (fail_at == V2S15MIG_FAIL_AFTER_TABLES) break;

        /* Verify: the two new tables exist with their exact shape, and
         * the two retired columns are gone from validators. */
        static const char *const att_cols[] =
            { "voter_id", "signed_count", "last_signed_height" };
        static const char *const attep_cols[] =
            { "epoch_start", "digest" };
        if (table_cols_exact(w, "v2_attendance", att_cols,
                sizeof(att_cols) / sizeof(att_cols[0])) != 1 ||
            table_cols_exact(w, "v2_attendance_epoch", attep_cols,
                sizeof(attep_cols) / sizeof(attep_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "S15 attendance table shape drift — refusing");
            break;
        }
        {
            int lsig2 = col_present(w, "validators", "last_signed_block");
            int sepo2 = col_present(w, "validators",
                                    "signed_blocks_this_epoch");
            if (lsig2 != 0 || sepo2 != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "S15 validators column drop verification "
                              "failed — refusing");
                break;
            }
        }
        if (fail_at == V2S15MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 15") != 0) break;
        if (fail_at == V2S15MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s15(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s15_ex(w, V2S15MIG_FAIL_NONE);
}

/* ── S16 migration: tokenomics-v3 P2 (rewards, fees, the reward pool) ─
 * Contract: nodus_witness_v2_schema.h. */

int nodus_witness_db_migrate_v2s16_ex(nodus_witness_t *w,
                                      nodus_v2s16_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S16) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S15) {
        if (nodus_witness_db_migrate_v2s15(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S15;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S16MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S15,
                                        NODUS_V2_SCHEMA_VERSION_S16, "S16");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S16MIG_FAIL_AFTER_REVALIDATE) break;

        /* 1. supply_tracking.reward_pool, WHEN ABSENT. Every DB this
         * build created carries it from WITNESS_DB_SCHEMA and the
         * every-open v18 leg; only a DB an older build created and that
         * has not been opened by this one since reaches the ALTER. A
         * probe FAULT (-1) is never "absent". */
        {
            int rp = col_present(w, "supply_tracking", "reward_pool");
            if (rp < 0) break;
            if (rp == 0 &&
                exec_sql(w, "ALTER TABLE supply_tracking ADD COLUMN "
                            "reward_pool INTEGER NOT NULL DEFAULT 0") != 0)
                break;
        }

        /* 2 + 3. The two reward tables — byte-identical to the base
         * schema's (nodus_witness.c), a no-op on any DB this build
         * created. Final pre-testnet wipe, W-B: v2_balance_copy gained
         * `kind` (0 bond, 1 delegation) in its primary key, so a
         * self-delegation and its validator's bond are two rows. Changed
         * IN this rung, like W-A's treasury table below and for the same
         * reason (wipe, no migration). A DB an older build created holds
         * the old four-column table, which CREATE TABLE IF NOT EXISTS
         * leaves alone: at S15 the shape check below REFUSES it; at S16
         * (this rung never re-runs) the copy writer's INSERT names a
         * `kind` column the old table lacks, its prepare fails and the
         * boundary FAULTS (nodus_witness_v2_balance_copy_write) — either
         * way the node stops rather than run the copy under the old key.
         * The package ships with the chain wipe that removes such DBs. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_reward_accrual ("
                "  owner_fp BLOB PRIMARY KEY,"
                "  amount INTEGER NOT NULL"
                ")") != 0)
            break;
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_balance_copy ("
                "  epoch_start INTEGER NOT NULL,"
                "  validator_fp BLOB NOT NULL,"
                "  owner_fp BLOB NOT NULL,"
                "  kind INTEGER NOT NULL,"
                "  amount INTEGER NOT NULL,"
                "  PRIMARY KEY (epoch_start, validator_fp, owner_fp, kind)"
                ")") != 0)
            break;
        /* 4. Final pre-testnet wipe, W-A: the keyless treasury pools —
         * byte-identical to the base schema's (nodus_witness.c). Added
         * to THIS rung rather than a new one: the package ships with a
         * chain wipe and no migration (devnet), and every DB this build
         * opens gains the table from WITNESS_DB_SCHEMA anyway — this
         * CREATE is the rung's own statement of its shape, verified
         * below. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_treasury ("
                "  pool_id INTEGER PRIMARY KEY,"
                "  balance INTEGER NOT NULL"
                ")") != 0)
            break;
        if (fail_at == V2S16MIG_FAIL_AFTER_TABLES) break;

        /* Verify: the three tables exist with their exact shape, and the
         * column is present. */
        static const char *const acc_cols[] = { "owner_fp", "amount" };
        static const char *const copy_cols[] =
            { "epoch_start", "validator_fp", "owner_fp", "kind", "amount" };
        static const char *const treas_cols[] = { "pool_id", "balance" };
        if (table_cols_exact(w, "v2_reward_accrual", acc_cols,
                sizeof(acc_cols) / sizeof(acc_cols[0])) != 1 ||
            table_cols_exact(w, "v2_balance_copy", copy_cols,
                sizeof(copy_cols) / sizeof(copy_cols[0])) != 1 ||
            table_cols_exact(w, "v2_treasury", treas_cols,
                sizeof(treas_cols) / sizeof(treas_cols[0])) != 1 ||
            col_present(w, "supply_tracking", "reward_pool") != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "S16 reward schema shape drift — refusing");
            break;
        }
        if (fail_at == V2S16MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 16") != 0) break;
        if (fail_at == V2S16MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s16(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s16_ex(w, V2S16MIG_FAIL_NONE);
}

/* ── S17 migration: Nodus EVM, the EVM domain's state ───────────────────────
 * Contract: nodus_witness_v2_schema.h. Every table is created EMPTY; the
 * one evm_meta row is the EVM runtime's state_init's (activation), never
 * this rung's. */

static const char *V2_S17_EVM_DDL =
    "CREATE TABLE IF NOT EXISTS evm_accounts ("
    "  addr BLOB PRIMARY KEY,"
    "  nonce INTEGER NOT NULL,"
    "  balance BLOB NOT NULL,"
    "  code_hash BLOB NOT NULL,"
    "  code_size INTEGER NOT NULL,"
    "  code_digest BLOB NOT NULL,"
    "  storage_count INTEGER NOT NULL,"
    "  storage_root BLOB NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_slots ("
    "  addr BLOB NOT NULL,"
    "  slot BLOB NOT NULL,"
    "  value BLOB NOT NULL,"
    "  PRIMARY KEY (addr, slot)"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_code ("
    "  digest BLOB NOT NULL,"
    "  chunk INTEGER NOT NULL,"
    "  bytes BLOB NOT NULL,"
    "  PRIMARY KEY (digest, chunk)"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_code_refs ("
    "  digest BLOB PRIMARY KEY,"
    "  refs INTEGER NOT NULL,"
    "  code_size INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_tickets ("
    "  ticket_id BLOB PRIMARY KEY,"
    "  amount_raw INTEGER NOT NULL,"
    "  dest_fp BLOB NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_meta ("
    "  id INTEGER PRIMARY KEY CHECK (id = 1),"
    "  wei_live BLOB NOT NULL,"
    "  wei_tickets BLOB NOT NULL,"
    "  wei_lost BLOB NOT NULL,"
    "  account_trie_root BLOB NOT NULL,"
    "  tickets_root BLOB NOT NULL"
    ");"
    /* the CORE EVM reserve bucket (design §5) — CORE state, one row */
    "CREATE TABLE IF NOT EXISTS v2_evm_reserve ("
    "  id INTEGER PRIMARY KEY CHECK (id = 1),"
    "  reserve_raw INTEGER NOT NULL CHECK (reserve_raw >= 0)"
    ");"
    "INSERT INTO v2_evm_reserve (id, reserve_raw) VALUES (1, 0);"
    "CREATE TABLE IF NOT EXISTS evm_trie_nodes ("
    "  digest BLOB PRIMARY KEY,"
    "  rlp BLOB NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_receipts ("
    "  intent_id BLOB PRIMARY KEY,"
    "  global_height INTEGER NOT NULL,"
    "  item_index INTEGER NOT NULL,"
    "  receipt BLOB NOT NULL,"
    "  digest BLOB NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS evm_logs ("
    "  intent_id BLOB NOT NULL,"
    "  log_index INTEGER NOT NULL,"
    "  global_height INTEGER NOT NULL,"
    "  addr BLOB NOT NULL,"
    "  topics BLOB NOT NULL,"
    "  data BLOB NOT NULL,"
    "  PRIMARY KEY (intent_id, log_index)"
    ");"
    /* the first §18 evm_logs range index (kept: an S17 database built
     * before the cursor scan carries it, and dropping it would be a
     * shape change; the cursor scan below does not read it) */
    "CREATE INDEX IF NOT EXISTS evm_logs_by_height "
    "ON evm_logs(global_height);"
    /* the cursor-order scan's two indexes (S17_LOG_INDEXES_DDL below —
     * also ensured at open on a database already at S17) */
    "CREATE INDEX IF NOT EXISTS evm_receipts_by_pos "
    "ON evm_receipts(global_height, item_index);"
    "CREATE INDEX IF NOT EXISTS evm_logs_by_addr "
    "ON evm_logs(addr, global_height, intent_id, log_index);";

/* The node-local §18 evm_logs scan indexes (red-team 1 F4) — the same two
 * statements as the tail of V2_S17_EVM_DDL, run alone by the at-open
 * ensure step (nodus_witness_db_ensure_v2s17_indexes) on a database that
 * reached S17 before they existed. Indexes only: no table, column or
 * row changes, nothing any root reads. */
static const char *S17_LOG_INDEXES_DDL =
    "CREATE INDEX IF NOT EXISTS evm_receipts_by_pos "
    "ON evm_receipts(global_height, item_index);"
    "CREATE INDEX IF NOT EXISTS evm_logs_by_addr "
    "ON evm_logs(addr, global_height, intent_id, log_index);";

/* 1 = index `name` exists on `table` with EXACTLY the key columns `cols`
 * in order, 0 = absent or another shape, -1 = fault. */
static int index_cols_exact(nodus_witness_t *w, const char *name,
                            const char *table, const char *const *cols,
                            size_t n_cols) {
    int ex = index_exists(w, name, table);
    if (ex != 1) return ex;
    char sql[160];
    snprintf(sql, sizeof(sql), "PRAGMA index_info(\"%s\")", name);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    /* index_info rows come in key order (seqno 0, 1, …): column 2 is the
     * table column name */
    size_t ci = 0;
    int rc, ok = 1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *nm = sqlite3_column_text(st, 2);
        if (ci >= n_cols || sqlite3_column_int64(st, 0) != (sqlite3_int64)ci ||
            !nm || strcmp((const char *)nm, cols[ci]) != 0) {
            ok = 0;
            break;
        }
        ci++;
    }
    sqlite3_finalize(st);
    if (!ok) return 0;
    if (rc != SQLITE_DONE) return -1;
    return ci == n_cols ? 1 : 0;
}

/* 1 = both scan indexes exist with their exact key columns, 0 = not,
 * -1 = fault. */
static int s17_log_indexes_ok(nodus_witness_t *w) {
    static const char *const pos_cols[] = { "global_height", "item_index" };
    static const char *const addr_cols[] = { "addr", "global_height",
                                             "intent_id", "log_index" };
    int a = index_cols_exact(w, "evm_receipts_by_pos", "evm_receipts",
                             pos_cols, 2);
    if (a != 1) return a;
    return index_cols_exact(w, "evm_logs_by_addr", "evm_logs", addr_cols, 4);
}

int nodus_witness_db_migrate_v2s17_ex(nodus_witness_t *w,
                                      nodus_v2s17_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S17) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S16) {
        /* the S9…S16 chain; an unknown version (18+) fails closed there */
        if (nodus_witness_db_migrate_v2s16(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S16;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S17MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S16,
                                        NODUS_V2_SCHEMA_VERSION_S17, "S17");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S17MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2_S17_EVM_DDL) != 0) break;
        if (fail_at == V2S17MIG_FAIL_AFTER_TABLES) break;

        /* Verify: every table exists with its exact shape, and the
         * evm_logs height index exists — a DDL that silently did nothing,
         * or a pre-existing table of another shape, is not a migrated
         * schema. */
        static const char *const acct_cols[] = {
            "addr", "nonce", "balance", "code_hash", "code_size",
            "code_digest", "storage_count", "storage_root" };
        static const char *const slot_cols[] = { "addr", "slot", "value" };
        static const char *const code_cols[] = { "digest", "chunk", "bytes" };
        static const char *const ref_cols[] = { "digest", "refs",
                                                "code_size" };
        static const char *const tkt_cols[] = { "ticket_id", "amount_raw",
                                                "dest_fp" };
        static const char *const meta_cols[] = {
            "id", "wei_live", "wei_tickets", "wei_lost",
            "account_trie_root", "tickets_root" };
        static const char *const rsv_cols[] = { "id", "reserve_raw" };
        static const char *const node_cols[] = { "digest", "rlp" };
        static const char *const rcpt_cols[] = {
            "intent_id", "global_height", "item_index", "receipt",
            "digest" };
        static const char *const log_cols[] = {
            "intent_id", "log_index", "global_height", "addr", "topics",
            "data" };
#define S17_COLS(t, c) table_cols_exact(w, t, c, sizeof(c) / sizeof(c[0]))
        if (S17_COLS("evm_accounts", acct_cols) != 1 ||
            S17_COLS("evm_slots", slot_cols) != 1 ||
            S17_COLS("evm_code", code_cols) != 1 ||
            S17_COLS("evm_code_refs", ref_cols) != 1 ||
            S17_COLS("evm_tickets", tkt_cols) != 1 ||
            S17_COLS("evm_meta", meta_cols) != 1 ||
            S17_COLS("evm_trie_nodes", node_cols) != 1 ||
            S17_COLS("evm_receipts", rcpt_cols) != 1 ||
            S17_COLS("evm_logs", log_cols) != 1 ||
            S17_COLS("v2_evm_reserve", rsv_cols) != 1 ||
            index_exists(w, "evm_logs_by_height", "evm_logs") != 1 ||
            s17_log_indexes_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "S17 EVM schema shape drift — refusing");
            break;
        }
#undef S17_COLS
        /* the reserve row exists, exactly one, at 0: nothing writes it
         * before the EVM generation's CORE does (design §5) */
        {
            sqlite3_stmt *rs = NULL;
            int one = 0;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT COUNT(*), COALESCE(SUM(reserve_raw), -1) "
                    "FROM v2_evm_reserve", -1, &rs, NULL) == SQLITE_OK &&
                sqlite3_step(rs) == SQLITE_ROW &&
                sqlite3_column_int64(rs, 0) == 1 &&
                sqlite3_column_int64(rs, 1) == 0)
                one = 1;
            sqlite3_finalize(rs);
            if (!one) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "S17 reserve row is not exactly (1, 0) — "
                              "refusing");
                break;
            }
        }
        if (fail_at == V2S17MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 17") != 0) break;
        if (fail_at == V2S17MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s17(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s17_ex(w, V2S17MIG_FAIL_NONE);
}

int nodus_witness_db_ensure_v2s17_indexes(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    /* S17, S18 or S19 (HF-6 3a: S18 = S17 + v2_validator_roles; HF-7
     * P1b: S19 = S18 + v2_replay, its index and one column; the at-open
     * rung reaches S19 before this step runs — header) */
    if (ver != NODUS_V2_SCHEMA_VERSION_S17 &&
        ver != NODUS_V2_SCHEMA_VERSION_S18 &&
        ver != NODUS_V2_SCHEMA_VERSION_S19 &&
        ver != NODUS_V2_SCHEMA_VERSION_S20) return 0;   /* not this rung */
    int have = s17_log_indexes_ok(w);
    if (have < 0) return -1;
    if (have == 1) return 0;                            /* idempotent    */

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;
    int ok = 0;
    do {
        /* the version is re-read inside the transaction (O15B: the
         * pre-BEGIN read decided nothing) */
        uint32_t v2 = 0;
        if (nodus_witness_db_schema_version(w, &v2) != 0 ||
            v2 != ver)
            break;
        if (exec_sql(w, S17_LOG_INDEXES_DDL) != 0) break;
        /* an index of the same name and another shape is not ours:
         * refuse rather than read through it */
        if (s17_log_indexes_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "S17 EVM log scan index shape drift — refusing");
            break;
        }
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
    QGP_LOG_INFO(LOG_TAG, "%s",
                 "S17: the EVM log scan indexes were created (node-local; "
                 "no root reads them)");
    return 0;
}

/* ── S18 migration: HF-6 sub-slice 3a, the validator-role side table ─────
 * Contract: nodus_witness_v2_schema.h. The table is created EMPTY; its
 * writers are the HF-6 activation edge (sub-slice 3b) and the
 * generation-4 STAKE (slice 4). The column definitions are byte-identical
 * to the base schema's (nodus_witness.c). */

static const char *V2_S18_ROLES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_validator_roles ("
    "  validator_id BLOB PRIMARY KEY,"
    "  owner_fp BLOB NOT NULL,"
    "  pending_consensus_pubkey BLOB NOT NULL,"
    "  consensus_key_effective_epoch INTEGER NOT NULL"
    ")";

/* HF-6 slice 4 (design rev 6 §4) — the consensus-key reservation table,
 * added to the SAME unreleased rung (S18 exists on branch hf6 only). One
 * unique key column: a consensus key appears at most once. Created EMPTY;
 * PERMANENT and append-only (khan decision 2026-10-13-kurultay-18-
 * summary.md items 1 and 4); writers: the generation-4 edge (one role-1
 * row per migrated validator, every status) and the generation-4 STAKE
 * (role 1). Nothing deletes a row. */
static const char *V2_S18_KEYS_DDL =
    "CREATE TABLE IF NOT EXISTS v2_consensus_keys ("
    "  consensus_pk_hash BLOB PRIMARY KEY,"
    "  validator_id BLOB NOT NULL,"
    "  role INTEGER NOT NULL"
    ")";

int nodus_witness_db_migrate_v2s18_ex(nodus_witness_t *w,
                                      nodus_v2s18_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S18) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S17) {
        /* the S9…S17 chain; an unknown version (19+) fails closed there */
        if (nodus_witness_db_migrate_v2s17(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S17;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S18MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S17,
                                        NODUS_V2_SCHEMA_VERSION_S18, "S18");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S18MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2_S18_ROLES_DDL) != 0) break;
        if (exec_sql(w, V2_S18_KEYS_DDL) != 0) break;
        if (fail_at == V2S18MIG_FAIL_AFTER_TABLES) break;

        /* Verify: each table exists with its exact column sequence — a
         * DDL that silently did nothing, or a pre-existing table of
         * another shape, is not a migrated schema. */
        static const char *const roles_cols[] = {
            "validator_id", "owner_fp", "pending_consensus_pubkey",
            "consensus_key_effective_epoch" };
        static const char *const keys_cols[] = {
            "consensus_pk_hash", "validator_id", "role" };
        if (table_cols_exact(w, "v2_validator_roles", roles_cols,
                sizeof(roles_cols) / sizeof(roles_cols[0])) != 1 ||
            table_cols_exact(w, "v2_consensus_keys", keys_cols,
                sizeof(keys_cols) / sizeof(keys_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "S18 validator-role / consensus-key schema shape "
                          "drift — refusing");
            break;
        }
        if (fail_at == V2S18MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 18") != 0) break;
        if (fail_at == V2S18MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s18(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s18_ex(w, V2S18MIG_FAIL_NONE);
}

/* ── S19 migration: HF-7 P1b, the replay relation + the head column ─────
 * Contract: nodus_witness_v2_schema.h. The table is created EMPTY and the
 * column NULL on every row; writers and readers arrive with HF-7 P1c. */

/* The replay relation (design §10.2 item 4; khan decision D: expiry an
 * INTEGER with a CHECK on the range). Each column holds ONE storage class
 * (typeof), as the base-schema tables of nodus_witness.h do: an expiry
 * stored as text or a blob would compare above every integer, pass a
 * bare `>= 1` check and never meet the `expiry_height <= H` prune. */
static const char *V2_S19_REPLAY_DDL =
    "CREATE TABLE IF NOT EXISTS v2_replay ("
    "  tx_id BLOB NOT NULL PRIMARY KEY"
    "    CHECK(typeof(tx_id)='blob' AND length(tx_id)=64),"
    "  intent_id BLOB NOT NULL UNIQUE"
    "    CHECK(typeof(intent_id)='blob' AND length(intent_id)=64),"
    "  expiry_height INTEGER NOT NULL"
    "    CHECK(typeof(expiry_height)='integer' AND expiry_height >= 1)"
    ")";

/* The prune's index (Kurultay #27 item 3: `DELETE FROM v2_replay WHERE
 * expiry_height <= H` every block). */
static const char *V2_S19_REPLAY_INDEX_DDL =
    "CREATE INDEX IF NOT EXISTS v2_replay_by_expiry "
    "ON v2_replay(expiry_height)";

/* 1 = `table`'s stored sqlite_master.sql equals what THIS build's SQLite
 * stores for `ddl`, 0 = absent or another definition, -1 = fault. The
 * reference text comes from executing the same statement into a private
 * ":memory:" database — the same library answers both sides, so nothing
 * is assumed about how SQLite normalizes stored DDL. Column names alone
 * (table_cols_exact) cannot see a type, a CHECK or a UNIQUE: a
 * pre-existing constraint-free table of the same name would otherwise
 * migrate. The pattern of nodus_witness.c witness_ddl_shape_check, as a
 * rung-local helper. */
static int table_ddl_exact(nodus_witness_t *w, const char *table,
                           const char *ddl) {
    static const char *const q =
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1";
    sqlite3 *mem = NULL;
    sqlite3_stmt *a = NULL, *b = NULL;
    int out = -1;
    if (sqlite3_open(":memory:", &mem) != SQLITE_OK) {
        if (mem) sqlite3_close(mem);
        return -1;
    }
    if (sqlite3_exec(mem, ddl, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(mem, q, -1, &a, NULL) == SQLITE_OK &&
        sqlite3_bind_text(a, 1, table, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_prepare_v2(w->db, q, -1, &b, NULL) == SQLITE_OK &&
        sqlite3_bind_text(b, 1, table, -1, SQLITE_STATIC) == SQLITE_OK) {
        int ra = sqlite3_step(a);
        int rb = sqlite3_step(b);
        if (ra != SQLITE_ROW) {
            out = -1;                   /* the reference must exist       */
        } else if (rb == SQLITE_DONE) {
            out = 0;                    /* absent                         */
        } else if (rb != SQLITE_ROW) {
            out = -1;
        } else {
            const unsigned char *sa = sqlite3_column_text(a, 0);
            const unsigned char *sb = sqlite3_column_text(b, 0);
            int la = sqlite3_column_bytes(a, 0);
            int lb = sqlite3_column_bytes(b, 0);
            out = (sa && sb && la == lb &&
                   memcmp(sa, sb, (size_t)la) == 0) ? 1 : 0;
        }
    }
    sqlite3_finalize(a);
    sqlite3_finalize(b);
    sqlite3_close(mem);
    return out;
}

/* 1 = v2_domain_heads is EXACTLY the S5 shape with last_upd_hash
 * appended, and last_upd_hash is declared BLOB, nullable, no default, not
 * a key column; 0 = another shape; -1 = fault. */
static int s19_heads_shape_ok(nodus_witness_t *w) {
    static const char *const cols[] = {
        "domain_id", "head", "domain_height", "last_updated_global",
        "last_upd_hash" };
    int ex = table_cols_exact(w, "v2_domain_heads", cols,
                              sizeof(cols) / sizeof(cols[0]));
    if (ex != 1) return ex;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT type, \"notnull\", dflt_value IS NULL, pk "
            "FROM pragma_table_info('v2_domain_heads') "
            "WHERE name = 'last_upd_hash'", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ok = 0;
    if (rc == SQLITE_ROW) {
        const unsigned char *ty = sqlite3_column_text(st, 0);
        ok = (ty && strcmp((const char *)ty, "BLOB") == 0 &&
              sqlite3_column_int(st, 1) == 0 &&
              sqlite3_column_int(st, 2) == 1 &&
              sqlite3_column_int(st, 3) == 0) ? 1 : 0;
    } else if (rc != SQLITE_DONE) {
        ok = -1;
    }
    sqlite3_finalize(st);
    return ok;
}

int nodus_witness_db_migrate_v2s19_ex(nodus_witness_t *w,
                                      nodus_v2s19_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S19) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S18) {
        /* the S9…S18 chain; an unknown version (20+) fails closed there */
        if (nodus_witness_db_migrate_v2s18(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S18;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S19MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S18,
                                        NODUS_V2_SCHEMA_VERSION_S19, "S19");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S19MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2_S19_REPLAY_DDL) != 0) break;
        if (exec_sql(w, V2_S19_REPLAY_INDEX_DDL) != 0) break;
        /* v2_domain_heads.last_upd_hash, WHEN ABSENT (the S16
         * reward_pool precedent): NULLABLE and unwritten here, so every
         * existing head row keeps its values and reads NULL. A probe
         * FAULT (-1) is never "absent"; a column already present is
         * accepted only through the shape check below. */
        {
            int cp = col_present(w, "v2_domain_heads", "last_upd_hash");
            if (cp < 0) break;
            if (cp == 0 &&
                exec_sql(w, "ALTER TABLE v2_domain_heads ADD COLUMN "
                            "last_upd_hash BLOB") != 0)
                break;
        }
        if (fail_at == V2S19MIG_FAIL_AFTER_TABLES) break;

        /* Verify: the table's whole stored definition (types, CHECKs,
         * PRIMARY KEY, UNIQUE), the index's exact key column and the
         * head table's exact column sequence — a DDL that silently did
         * nothing, or a pre-existing object of another shape, is not a
         * migrated schema. The table is EMPTY: nothing writes it before
         * HF-7 P1c. */
        {
            static const char *const ix_cols[] = { "expiry_height" };
            sqlite3_stmt *cs = NULL;
            int empty = 0;
            if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM v2_replay",
                                   -1, &cs, NULL) == SQLITE_OK &&
                sqlite3_step(cs) == SQLITE_ROW &&
                sqlite3_column_int64(cs, 0) == 0)
                empty = 1;
            sqlite3_finalize(cs);
            if (table_ddl_exact(w, "v2_replay", V2_S19_REPLAY_DDL) != 1 ||
                index_cols_exact(w, "v2_replay_by_expiry", "v2_replay",
                                 ix_cols, 1) != 1 ||
                s19_heads_shape_ok(w) != 1 || !empty) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "S19 replay-relation / domain-head schema "
                              "shape drift — refusing");
                break;
            }
        }
        if (fail_at == V2S19MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 19") != 0) break;
        if (fail_at == V2S19MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s19(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s19_ex(w, V2S19MIG_FAIL_NONE);
}

/* ── S20 migration: HF-9, the supply running totals ─────────────────────
 * Contract: nodus_witness_v2_schema.h. Plan §9.1. */

_Static_assert(DNA_V2_STORAGE_ACTIVE == 1 && DNA_V2_STORAGE_EXITING == 2,
               "the v2_bond_total triggers name status 1 and 2 literally");

/* The two tables, the plan §9.1 shapes (token_id is the utxo_set key as
 * stored: no length check, so a row the old SUM helper ignored can never
 * make a seed refuse the database). utxo_total is NOT range-checked: the
 * invariant type- and range-checks the stored value and answers -1
 * (plan §9.1), so a total that overflowed int64 (SQLite turns an
 * overflowing integer sum into a REAL) is visible there, never wrapped. */
static const char *V2_S20_SUPPLY_TOTALS_DDL =
    "CREATE TABLE IF NOT EXISTS v2_supply_totals ("
    "  token_id BLOB NOT NULL PRIMARY KEY,"
    "  utxo_total INTEGER NOT NULL"
    ") WITHOUT ROWID";

static const char *V2_S20_BOND_TOTAL_DDL =
    "CREATE TABLE IF NOT EXISTS v2_bond_total ("
    "  id INTEGER NOT NULL PRIMARY KEY CHECK(id = 1),"
    "  total INTEGER NOT NULL"
    ") WITHOUT ROWID";

/* The six supply triggers. A deleted or updated row leaves its token's
 * total with an UPDATE (the row exists: the insert created it); an insert
 * and the new side of an update UPSERT. An INSERT OR IGNORE that inserts
 * nothing fires nothing. */
static const char *V2_S20_SUPPLY_TRIGGERS_DDL =
    "CREATE TRIGGER IF NOT EXISTS v2_supply_utxo_ins AFTER INSERT ON utxo_set "
    "BEGIN "
    "  INSERT INTO v2_supply_totals(token_id, utxo_total) "
    "    VALUES (NEW.token_id, NEW.amount) "
    "    ON CONFLICT(token_id) DO UPDATE SET "
    "      utxo_total = utxo_total + excluded.utxo_total; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS v2_supply_utxo_del AFTER DELETE ON utxo_set "
    "BEGIN "
    "  UPDATE v2_supply_totals SET utxo_total = utxo_total - OLD.amount "
    "    WHERE token_id = OLD.token_id; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS v2_supply_utxo_upd "
    "AFTER UPDATE OF amount, token_id ON utxo_set "
    "BEGIN "
    "  UPDATE v2_supply_totals SET utxo_total = utxo_total - OLD.amount "
    "    WHERE token_id = OLD.token_id; "
    "  INSERT INTO v2_supply_totals(token_id, utxo_total) "
    "    VALUES (NEW.token_id, NEW.amount) "
    "    ON CONFLICT(token_id) DO UPDATE SET "
    "      utxo_total = utxo_total + excluded.utxo_total; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS v2_supply_bond_ins "
    "AFTER INSERT ON v2_storage_nodes BEGIN "
    "  UPDATE v2_bond_total SET total = total + "
    "    (CASE WHEN NEW.status IN (1, 2) THEN NEW.bond ELSE 0 END) "
    "    WHERE id = 1; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS v2_supply_bond_del "
    "AFTER DELETE ON v2_storage_nodes BEGIN "
    "  UPDATE v2_bond_total SET total = total - "
    "    (CASE WHEN OLD.status IN (1, 2) THEN OLD.bond ELSE 0 END) "
    "    WHERE id = 1; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS v2_supply_bond_upd "
    "AFTER UPDATE OF bond, status ON v2_storage_nodes BEGIN "
    "  UPDATE v2_bond_total SET total = total - "
    "    (CASE WHEN OLD.status IN (1, 2) THEN OLD.bond ELSE 0 END) + "
    "    (CASE WHEN NEW.status IN (1, 2) THEN NEW.bond ELSE 0 END) "
    "    WHERE id = 1; "
    "END;";

/* Re-seed: every sum from its source table; the native row and the bond
 * row always exist afterwards (an empty GROUP BY writes no native row). */
static const char *V2_S20_SUPPLY_RESEED_SQL =
    "DELETE FROM v2_supply_totals;"
    "INSERT INTO v2_supply_totals(token_id, utxo_total) "
    "  SELECT token_id, SUM(amount) FROM utxo_set GROUP BY token_id;"
    "INSERT OR IGNORE INTO v2_supply_totals(token_id, utxo_total) "
    "  VALUES (zeroblob(64), 0);"
    "DELETE FROM v2_bond_total;"
    "INSERT INTO v2_bond_total(id, total) "
    "  SELECT 1, COALESCE(SUM(bond), 0) FROM v2_storage_nodes "
    "  WHERE status IN (1, 2);";

/* The six trigger names, for the shape verification. */
static const char *const V2_S20_SUPPLY_TRIGGER_NAMES[6] = {
    "v2_supply_utxo_ins", "v2_supply_utxo_del", "v2_supply_utxo_upd",
    "v2_supply_bond_ins", "v2_supply_bond_del", "v2_supply_bond_upd"
};

/* 1 = every trigger in `names` (n of them) has a stored SQL equal to what
 * THIS build's SQLite stores for the statements in `trig_ddl` (reference:
 * a private ":memory:" database holding the stub tables `prereq_ddl` and
 * then `trig_ddl`), 0 = one is absent or another definition, -1 = fault.
 * The table_ddl_exact pattern, one reference database for the whole set. */
static int triggers_sql_exact(nodus_witness_t *w, const char *const *names,
                              size_t n, const char *prereq_ddl,
                              const char *trig_ddl) {
    static const char *const q =
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1";
    sqlite3 *mem = NULL;
    sqlite3_stmt *a = NULL, *b = NULL;
    int out = -1;
    if (sqlite3_open(":memory:", &mem) != SQLITE_OK) {
        if (mem) sqlite3_close(mem);
        return -1;
    }
    if (sqlite3_exec(mem, prereq_ddl, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_exec(mem, trig_ddl, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(mem, q, -1, &a, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(w->db, q, -1, &b, NULL) == SQLITE_OK) {
        out = 1;
        for (size_t i = 0; i < n && out == 1; i++) {
            if (sqlite3_reset(a) != SQLITE_OK ||
                sqlite3_reset(b) != SQLITE_OK ||
                sqlite3_bind_text(a, 1, names[i], -1, SQLITE_STATIC)
                    != SQLITE_OK ||
                sqlite3_bind_text(b, 1, names[i], -1, SQLITE_STATIC)
                    != SQLITE_OK) {
                out = -1;
                break;
            }
            int ra = sqlite3_step(a);
            int rb = sqlite3_step(b);
            if (ra != SQLITE_ROW) {
                out = -1;               /* the reference must exist       */
            } else if (rb == SQLITE_DONE) {
                out = 0;                /* absent                         */
            } else if (rb != SQLITE_ROW) {
                out = -1;
            } else {
                const unsigned char *sa = sqlite3_column_text(a, 0);
                const unsigned char *sb = sqlite3_column_text(b, 0);
                int la = sqlite3_column_bytes(a, 0);
                int lb = sqlite3_column_bytes(b, 0);
                if (!(sa && sb && la == lb &&
                      memcmp(sa, sb, (size_t)la) == 0))
                    out = 0;
            }
        }
    }
    sqlite3_finalize(a);
    sqlite3_finalize(b);
    sqlite3_close(mem);
    return out;
}

/* The stub source tables the reference database needs for the supply
 * triggers (columns the trigger bodies name). */
static const char *V2_S20_SUPPLY_STUBS_DDL =
    "CREATE TABLE utxo_set(nullifier BLOB, amount INTEGER, token_id BLOB);"
    "CREATE TABLE v2_storage_nodes(node_fp BLOB, bond INTEGER, "
    "  status INTEGER);"
    "CREATE TABLE v2_supply_totals(token_id BLOB PRIMARY KEY, "
    "  utxo_total INTEGER) WITHOUT ROWID;"
    "CREATE TABLE v2_bond_total(id INTEGER PRIMARY KEY, total INTEGER) "
    "  WITHOUT ROWID;";

/* 1 = the two tables and all six triggers are exactly this build's,
 * 0 = drift, -1 = fault. */
static int s20_supply_shape_ok(nodus_witness_t *w) {
    int r = table_ddl_exact(w, "v2_supply_totals", V2_S20_SUPPLY_TOTALS_DDL);
    if (r != 1) return r;
    r = table_ddl_exact(w, "v2_bond_total", V2_S20_BOND_TOTAL_DDL);
    if (r != 1) return r;
    return triggers_sql_exact(w, V2_S20_SUPPLY_TRIGGER_NAMES, 6,
                              V2_S20_SUPPLY_STUBS_DDL,
                              V2_S20_SUPPLY_TRIGGERS_DDL);
}

/* ── HF-9 WP2: the keyed-trie tables, indexes and the 24 dirty-capture
 *    triggers (plan §5.1, §5.2, §5.5). Contract: nodus_witness_v2_schema.h */

/* Digest-addressed node store of the eight leg tries (plan §5.1). NOT NULL
 * closes the Z-51 class at the schema too. */
static const char *V2_S20_TRIE_NODES_DDL =
    "CREATE TABLE IF NOT EXISTS v2_trie_nodes ("
    "  digest BLOB NOT NULL PRIMARY KEY,"
    "  rlp BLOB NOT NULL"
    ") WITHOUT ROWID";

/* The committed root of each leg (plan §5.1). */
static const char *V2_S20_TRIE_ROOTS_DDL =
    "CREATE TABLE IF NOT EXISTS v2_trie_roots ("
    "  leg INTEGER NOT NULL PRIMARY KEY,"
    "  root BLOB NOT NULL"
    ") WITHOUT ROWID";

/* The primary keys written in this block, duplicates collapsed (plan
 * §5.1; physical layout DF-9). `key` has no declared type: it holds the
 * source row's primary key AS STORED — a BLOB for the legs whose key is a
 * blob, an INTEGER for the segment and the two epoch legs. The 8-byte
 * big-endian encoding of an integer key is made in C at the flush, because
 * the linked SQLite (3.40.1) has no unhex(); inside one leg ORDER BY key
 * is already the canonical key order (non-negative integers ascend as
 * their big-endian bytes do, blobs by memcmp). */
static const char *V2_S20_TRIE_DIRTY_DDL =
    "CREATE TABLE IF NOT EXISTS v2_trie_dirty ("
    "  leg INTEGER NOT NULL,"
    "  key NOT NULL,"
    "  PRIMARY KEY (leg, key)"
    ") WITHOUT ROWID";

/* The CONSENSUS capture flag (plan §5.1): 0 before activation (the
 * migration writes the row), 1 only by the activation edge or a
 * generation >= 6 genesis. */
static const char *V2_S20_TRIE_STATE_DDL =
    "CREATE TABLE IF NOT EXISTS v2_trie_state ("
    "  id INTEGER NOT NULL PRIMARY KEY CHECK(id = 1),"
    "  capture INTEGER NOT NULL CHECK(capture IN (0, 1))"
    ") WITHOUT ROWID";

/* Node-local shadow status (plan §5.1; the values are the shadow
 * package's). Created without a row; nothing in this package reads or
 * writes it. */
static const char *V2_S20_TRIE_SHADOW_STATE_DDL =
    "CREATE TABLE IF NOT EXISTS v2_trie_shadow_state ("
    "  id INTEGER NOT NULL PRIMARY KEY CHECK(id = 1),"
    "  status INTEGER"
    ") WITHOUT ROWID";

/* plan §5.5 */
static const char *V2_S20_STORAGE_STATUS_INDEX_DDL =
    "CREATE INDEX IF NOT EXISTS v2_storage_nodes_by_status "
    "ON v2_storage_nodes(status, node_fp)";

/* ── HF-9 WP4: the retained-assignment tables (plan §8.4, AD-6) and the
 *    capacity rebuild of the two storage tables (plan §8.7) ──────────────
 * Derived node state written inside the block transaction, never part of
 * any root; empty until the generation-6 edge (E-s2) writes them. No
 * garbage collection (D6): rows are ended (to_h = B), never deleted. The
 * physical layout is the package's within the §8.4 contracts (DF-9 class).
 *
 * v2_storage_assign — holders(k, H) = the rows with from_h <= H and
 *   (to_h IS NULL or to_h > H). score = the rendezvous score of (k, node)
 *   (the join rule's stored scores); the key carries from_h because a
 *   member can leave and return. to_h >= from_h: the transition rows (E-s2)
 *   carry from_h = B1 and an event AT B1 ends some of them with to_h = B1,
 *   a row that is never current for any H.
 * v2_storage_assign_basis — the eligible members the CURRENT rows reflect
 *   (<= 1024 fps) and v2_storage_assign_state — the R of those rows, the
 *   boundary they were made at and `xfer` (1 while the one-use transition
 *   table is pending: set by E-s2, cleared at B1) (one row once written; absent before E-s2).
 * v2_storage_held — current rows per member (>= 1 row exists only for a
 *   holder; the member's row is deleted when its count falls to 0 so the
 *   table stays bounded by the live members, an ended assignment row keeps
 *   its history in v2_storage_assign).
 * v2_storage_member_epoch — per member of each frozen set: the union of
 *   its holdings over the epoch's current and previous relation and the
 *   segments newly taken over (the grace input); pruned with the set
 *   members (same rule).
 * v2_storage_xfer_diff — the one-use table of the transition (E-s3): per
 *   member, the segments ended / newly taken between XOR(set(H2)) and the
 *   rendezvous rows; its ROWS are cleared at B1, the table stays (a DROP
 *   would change the schema shape every open verifies). */
static const char *V2_S20_ASSIGN_DDL =
    "CREATE TABLE IF NOT EXISTS v2_storage_assign ("
    "  k INTEGER NOT NULL CHECK(typeof(k)='integer' AND k >= 1),"
    "  node_fp BLOB NOT NULL CHECK(typeof(node_fp)='blob' AND "
    "length(node_fp)=64),"
    "  score BLOB NOT NULL CHECK(typeof(score)='blob' AND "
    "length(score)=64),"
    "  from_h INTEGER NOT NULL CHECK(typeof(from_h)='integer' AND "
    "from_h >= 1),"
    "  to_h INTEGER CHECK(to_h IS NULL OR (typeof(to_h)='integer' AND "
    "to_h >= from_h)),"
    "  PRIMARY KEY (k, node_fp, from_h)"
    ") WITHOUT ROWID";
static const char *V2_S20_ASSIGN_INDEX_CUR_DDL =
    "CREATE INDEX IF NOT EXISTS v2_storage_assign_cur "
    "ON v2_storage_assign(k) WHERE to_h IS NULL";
static const char *V2_S20_ASSIGN_INDEX_NODE_DDL =
    "CREATE INDEX IF NOT EXISTS v2_storage_assign_by_node "
    "ON v2_storage_assign(node_fp, k)";
static const char *V2_S20_ASSIGN_BASIS_DDL =
    "CREATE TABLE IF NOT EXISTS v2_storage_assign_basis ("
    "  node_fp BLOB NOT NULL PRIMARY KEY CHECK(typeof(node_fp)='blob' AND "
    "length(node_fp)=64)"
    ") WITHOUT ROWID";
static const char *V2_S20_ASSIGN_STATE_DDL =
    "CREATE TABLE IF NOT EXISTS v2_storage_assign_state ("
    "  id INTEGER NOT NULL PRIMARY KEY CHECK(id = 1),"
    "  copies INTEGER NOT NULL CHECK(typeof(copies)='integer' AND "
    "copies BETWEEN 1 AND 16),"
    "  boundary INTEGER NOT NULL CHECK(typeof(boundary)='integer' AND "
    "boundary >= 0),"
    "  xfer INTEGER NOT NULL CHECK(typeof(xfer)='integer' AND "
    "xfer IN (0, 1))"
    ") WITHOUT ROWID";
static const char *V2_S20_HELD_DDL =
    "CREATE TABLE IF NOT EXISTS v2_storage_held ("
    "  node_fp BLOB NOT NULL PRIMARY KEY CHECK(typeof(node_fp)='blob' AND "
    "length(node_fp)=64),"
    "  held INTEGER NOT NULL CHECK(typeof(held)='integer' AND held >= 1)"
    ") WITHOUT ROWID";
static const char *V2_S20_MEMBER_EPOCH_DDL =
    "CREATE TABLE IF NOT EXISTS v2_storage_member_epoch ("
    "  epoch_start INTEGER NOT NULL CHECK(typeof(epoch_start)='integer' AND "
    "epoch_start >= 1),"
    "  node_fp BLOB NOT NULL CHECK(typeof(node_fp)='blob' AND "
    "length(node_fp)=64),"
    "  held_union INTEGER NOT NULL CHECK(typeof(held_union)='integer' AND "
    "held_union >= 0),"
    "  n_new INTEGER NOT NULL CHECK(typeof(n_new)='integer' AND n_new >= 0),"
    "  PRIMARY KEY (epoch_start, node_fp)"
    ") WITHOUT ROWID";
static const char *V2_S20_XFER_DIFF_DDL =
    "CREATE TABLE IF NOT EXISTS v2_storage_xfer_diff ("
    "  node_fp BLOB NOT NULL PRIMARY KEY CHECK(typeof(node_fp)='blob' AND "
    "length(node_fp)=64),"
    "  ended_x INTEGER NOT NULL CHECK(typeof(ended_x)='integer' AND "
    "ended_x >= 0),"
    "  new_x INTEGER NOT NULL CHECK(typeof(new_x)='integer' AND new_x >= 0)"
    ") WITHOUT ROWID";

/* 1 = the stored sqlite_master.sql of index `name` equals what THIS
 * build's SQLite stores for `ddl` executed over the stub `prereq_ddl` in a
 * private ":memory:" database (the table_ddl_exact pattern) - the whole
 * definition, the partial WHERE predicate included; 0 = absent or another
 * definition; -1 = fault. (index_cols_exact sees only name, table and
 * columns - plan §8.4 "(k) WHERE to_h IS NULL", §5.5 revalidation.) */
static int index_ddl_exact(nodus_witness_t *w, const char *name,
                           const char *prereq_ddl, const char *ddl) {
    static const char *const q =
        "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1";
    sqlite3 *mem = NULL;
    sqlite3_stmt *a = NULL, *b = NULL;
    int out = -1;
    if (sqlite3_open(":memory:", &mem) != SQLITE_OK) {
        if (mem) sqlite3_close(mem);
        return -1;
    }
    if (sqlite3_exec(mem, prereq_ddl, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_exec(mem, ddl, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(mem, q, -1, &a, NULL) == SQLITE_OK &&
        sqlite3_bind_text(a, 1, name, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_prepare_v2(w->db, q, -1, &b, NULL) == SQLITE_OK &&
        sqlite3_bind_text(b, 1, name, -1, SQLITE_STATIC) == SQLITE_OK) {
        int ra = sqlite3_step(a);
        int rb = sqlite3_step(b);
        if (ra != SQLITE_ROW) {
            out = -1;                       /* the reference must exist   */
        } else if (rb == SQLITE_DONE) {
            out = 0;                        /* absent                     */
        } else if (rb != SQLITE_ROW) {
            out = -1;
        } else {
            const unsigned char *sa = sqlite3_column_text(a, 0);
            const unsigned char *sb = sqlite3_column_text(b, 0);
            int la = sqlite3_column_bytes(a, 0);
            int lb = sqlite3_column_bytes(b, 0);
            out = (sa && sb && la == lb &&
                   memcmp(sa, sb, (size_t)la) == 0) ? 1 : 0;
        }
    }
    sqlite3_finalize(a);
    sqlite3_finalize(b);
    sqlite3_close(mem);
    return out;
}

/* 1 = the six §8.4 tables, their two indexes and the capacity-rebuilt
 * v2_storage_sets / v2_storage_reports are exactly this build's, 0 = drift,
 * -1 = fault. */
static int s20_storage_shape_ok(nodus_witness_t *w) {
    static const struct { const char *t; const char **ddl; } T[] = {
        { "v2_storage_assign",        &V2_S20_ASSIGN_DDL },
        { "v2_storage_assign_basis",  &V2_S20_ASSIGN_BASIS_DDL },
        { "v2_storage_assign_state",  &V2_S20_ASSIGN_STATE_DDL },
        { "v2_storage_held",          &V2_S20_HELD_DDL },
        { "v2_storage_member_epoch",  &V2_S20_MEMBER_EPOCH_DDL },
        { "v2_storage_xfer_diff",     &V2_S20_XFER_DIFF_DDL }
    };
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
        int r = table_ddl_exact(w, T[i].t, *T[i].ddl);
        if (r == 0 && strcmp(T[i].t, "v2_storage_xfer_diff") == 0) {
            /* plan §8.6: the one-use table is DROPPED after B1. Its absence
             * is the shape only when the state row exists and says xfer = 0
             * (consumed or never pending); every other absence is drift. */
            int absent = table_exists(w, T[i].t);
            if (absent < 0) return -1;
            if (absent == 0) {
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db, "SELECT xfer FROM "
                        "v2_storage_assign_state WHERE id = 1", -1, &st,
                        NULL) != SQLITE_OK)
                    return -1;
                int sr = sqlite3_step(st);
                int consumed = sr == SQLITE_ROW &&
                               sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                               sqlite3_column_int64(st, 0) == 0;
                sqlite3_finalize(st);
                if (sr != SQLITE_ROW && sr != SQLITE_DONE) return -1;
                if (consumed) continue;
            }
        }
        if (r != 1) return r;
    }
    int r = table_ddl_exact(w, "v2_storage_sets", NODUS_V2_STSETS_DDL_S20);
    if (r != 1) return r;
    r = table_ddl_exact(w, "v2_storage_reports", NODUS_V2_STREPS_DDL_S20);
    if (r != 1) return r;
    /* the whole stored definition, the partial predicate included */
    static const char *const stub =
        "CREATE TABLE v2_storage_assign (k, node_fp, to_h)";
    r = index_ddl_exact(w, "v2_storage_assign_cur", stub,
                        V2_S20_ASSIGN_INDEX_CUR_DDL);
    if (r != 1) return r;
    return index_ddl_exact(w, "v2_storage_assign_by_node", stub,
                           V2_S20_ASSIGN_INDEX_NODE_DDL);
}

/* Rebuild one storage table with its S20 text: copy the rows aside, DROP,
 * CREATE with the exact S20 statement, copy back, drop the copy. The table
 * is created by the statement itself (not by RENAME, which would rewrite
 * the stored text), so the stored definition equals the reference text.
 * The precedent is the S5 rebuild of utxo_set (migrate_v2s5_ex). All
 * inside the caller's transaction. @return 0 / -1. */
static int s20_rebuild_storage_table(nodus_witness_t *w, const char *table,
                                     const char *ddl_s20) {
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "CREATE TABLE v2_s20_rebuild_tmp AS SELECT * FROM %s",
                     table);
    if (n <= 0 || (size_t)n >= sizeof(sql)) return -1;
    if (exec_sql(w, sql) != 0) return -1;
    n = snprintf(sql, sizeof(sql), "DROP TABLE %s", table);
    if (n <= 0 || (size_t)n >= sizeof(sql)) return -1;
    if (exec_sql(w, sql) != 0) return -1;
    if (exec_sql(w, ddl_s20) != 0) return -1;
    n = snprintf(sql, sizeof(sql),
                 "INSERT INTO %s SELECT * FROM v2_s20_rebuild_tmp", table);
    if (n <= 0 || (size_t)n >= sizeof(sql)) return -1;
    if (exec_sql(w, sql) != 0) return -1;
    return exec_sql(w, "DROP TABLE v2_s20_rebuild_tmp");
}

/* The migration's DDL for the storage part: the capacity rebuild of the
 * sets and reports tables, the six tables, the indexes. @return 0 / -1. */
static int s20_storage_create(nodus_witness_t *w) {
    if (s20_rebuild_storage_table(w, "v2_storage_sets",
                                  NODUS_V2_STSETS_DDL_S20) != 0) return -1;
    if (s20_rebuild_storage_table(w, "v2_storage_reports",
                                  NODUS_V2_STREPS_DDL_S20) != 0) return -1;
    if (exec_sql(w, V2_S20_ASSIGN_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_ASSIGN_INDEX_CUR_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_ASSIGN_INDEX_NODE_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_ASSIGN_BASIS_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_ASSIGN_STATE_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_HELD_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_MEMBER_EPOCH_DDL) != 0) return -1;
    return exec_sql(w, V2_S20_XFER_DIFF_DDL);
}

/* The eight migrated tables: leg id (plan §4.2 order L1..L8), table,
 * primary-key column. */
static const struct {
    int         leg;
    const char *table;
    const char *pk;
} V2_S20_TRIE_LEGS[8] = {
    { 1, "utxo_set",                "nullifier"    },
    { 2, "tokens",                  "token_id"     },
    { 3, "v2_claims_spent",         "nullifier"    },
    { 4, "v2_names",                "name"         },
    { 5, "v2_storage_nodes",        "node_fp"      },
    { 6, "v2_storage_segments",     "k"            },
    { 7, "validator_set_snapshots", "epoch_start"  },
    { 8, "v2_attendance_epoch",     "epoch_start"  }
};

#define S20_TRIE_N_TRIGGERS 24
#define S20_TRIE_TRIG_NAME_LEN 24
#define S20_TRIE_DDL_CAP (S20_TRIE_N_TRIGGERS * 512 + 64)

/* Build the 24 trigger statements (ins, del, upd for each of the eight
 * tables, in leg order) into `ddl`, and their names into
 * names[i] (storage `store`, S20_TRIE_N_TRIGGERS * S20_TRIE_TRIG_NAME_LEN
 * bytes, name pointers returned in `names`). Every trigger is gated by
 * WHEN (SELECT capture FROM v2_trie_state WHERE id = 1) = 1 — a missing
 * state row makes the condition NULL (never true), which is why the
 * block-start check reads the row and faults on its absence (plan §5.2).
 * An UPDATE records the OLD and the NEW key (the key may change), a
 * DELETE the OLD key, an INSERT the NEW key; INSERT OR IGNORE collapses
 * duplicates. @return 0 / -1 (buffer too small: never). */
static int s20_trie_triggers(char *ddl, size_t ddl_cap,
                             char store[][S20_TRIE_TRIG_NAME_LEN],
                             const char **names) {
    static const char *const when =
        "WHEN (SELECT capture FROM v2_trie_state WHERE id = 1) = 1 ";
    size_t off = 0;
    size_t ti = 0;
    for (size_t i = 0; i < 8; i++) {
        const int leg = V2_S20_TRIE_LEGS[i].leg;
        const char *tab = V2_S20_TRIE_LEGS[i].table;
        const char *pk = V2_S20_TRIE_LEGS[i].pk;
        static const char *const kind[3] = { "ins", "del", "upd" };
        for (int k = 0; k < 3; k++) {
            int nn = snprintf(store[ti], S20_TRIE_TRIG_NAME_LEN,
                              "v2_trie_l%d_%s", leg, kind[k]);
            if (nn <= 0 || nn >= S20_TRIE_TRIG_NAME_LEN) return -1;
            names[ti] = store[ti];
            ti++;
            int w;
            if (k == 0) {
                w = snprintf(ddl + off, ddl_cap - off,
                    "CREATE TRIGGER IF NOT EXISTS v2_trie_l%d_ins "
                    "AFTER INSERT ON %s %s"
                    "BEGIN INSERT OR IGNORE INTO v2_trie_dirty(leg, key) "
                    "VALUES (%d, NEW.%s); END;",
                    leg, tab, when, leg, pk);
            } else if (k == 1) {
                w = snprintf(ddl + off, ddl_cap - off,
                    "CREATE TRIGGER IF NOT EXISTS v2_trie_l%d_del "
                    "AFTER DELETE ON %s %s"
                    "BEGIN INSERT OR IGNORE INTO v2_trie_dirty(leg, key) "
                    "VALUES (%d, OLD.%s); END;",
                    leg, tab, when, leg, pk);
            } else {
                w = snprintf(ddl + off, ddl_cap - off,
                    "CREATE TRIGGER IF NOT EXISTS v2_trie_l%d_upd "
                    "AFTER UPDATE ON %s %s"
                    "BEGIN INSERT OR IGNORE INTO v2_trie_dirty(leg, key) "
                    "VALUES (%d, OLD.%s); "
                    "INSERT OR IGNORE INTO v2_trie_dirty(leg, key) "
                    "VALUES (%d, NEW.%s); END;",
                    leg, tab, when, leg, pk, leg, pk);
            }
            if (w <= 0 || (size_t)w >= ddl_cap - off) return -1;
            off += (size_t)w;
        }
    }
    return 0;
}

/* Stub source tables for the reference database: only the primary-key
 * column each trigger names, plus the two tables its body names. */
static int s20_trie_stubs(char *out, size_t cap) {
    size_t off = 0;
    int w = snprintf(out, cap,
        "CREATE TABLE v2_trie_state(id INTEGER PRIMARY KEY, capture "
        "INTEGER);"
        "CREATE TABLE v2_trie_dirty(leg INTEGER, key, PRIMARY KEY (leg, "
        "key)) WITHOUT ROWID;");
    if (w <= 0 || (size_t)w >= cap) return -1;
    off = (size_t)w;
    for (size_t i = 0; i < 8; i++) {
        w = snprintf(out + off, cap - off, "CREATE TABLE %s(%s);",
                     V2_S20_TRIE_LEGS[i].table, V2_S20_TRIE_LEGS[i].pk);
        if (w <= 0 || (size_t)w >= cap - off) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* 1 = the five trie tables, the registry index and all 24 triggers are
 * exactly this build's, 0 = drift, -1 = fault. */
static int s20_trie_shape_ok(nodus_witness_t *w) {
    int r = table_ddl_exact(w, "v2_trie_nodes", V2_S20_TRIE_NODES_DDL);
    if (r != 1) return r;
    r = table_ddl_exact(w, "v2_trie_roots", V2_S20_TRIE_ROOTS_DDL);
    if (r != 1) return r;
    r = table_ddl_exact(w, "v2_trie_dirty", V2_S20_TRIE_DIRTY_DDL);
    if (r != 1) return r;
    r = table_ddl_exact(w, "v2_trie_state", V2_S20_TRIE_STATE_DDL);
    if (r != 1) return r;
    r = table_ddl_exact(w, "v2_trie_shadow_state",
                        V2_S20_TRIE_SHADOW_STATE_DDL);
    if (r != 1) return r;
    {
        static const char *const ix_cols[] = { "status", "node_fp" };
        r = index_cols_exact(w, "v2_storage_nodes_by_status",
                             "v2_storage_nodes", ix_cols, 2);
        if (r != 1) return r;
    }
    char *ddl = malloc(S20_TRIE_DDL_CAP);
    char *stubs = malloc(2048);
    char (*store)[S20_TRIE_TRIG_NAME_LEN] =
        malloc(S20_TRIE_N_TRIGGERS * S20_TRIE_TRIG_NAME_LEN);
    const char *names[S20_TRIE_N_TRIGGERS];
    r = -1;
    if (ddl && stubs && store &&
        s20_trie_triggers(ddl, S20_TRIE_DDL_CAP, store, names) == 0 &&
        s20_trie_stubs(stubs, 2048) == 0)
        r = triggers_sql_exact(w, names, S20_TRIE_N_TRIGGERS, stubs, ddl);
    free(ddl);
    free(stubs);
    free(store);
    return r;
}

/* The migration's DDL for the trie part: tables, index, triggers, and the
 * capture row at 0. @return 0 / -1. */
static int s20_trie_create(nodus_witness_t *w) {
    if (exec_sql(w, V2_S20_TRIE_NODES_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_TRIE_ROOTS_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_TRIE_DIRTY_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_TRIE_STATE_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_TRIE_SHADOW_STATE_DDL) != 0) return -1;
    if (exec_sql(w, V2_S20_STORAGE_STATUS_INDEX_DDL) != 0) return -1;
    char *ddl = malloc(S20_TRIE_DDL_CAP);
    char (*store)[S20_TRIE_TRIG_NAME_LEN] =
        malloc(S20_TRIE_N_TRIGGERS * S20_TRIE_TRIG_NAME_LEN);
    const char *names[S20_TRIE_N_TRIGGERS];
    int rc = -1;
    if (ddl && store &&
        s20_trie_triggers(ddl, S20_TRIE_DDL_CAP, store, names) == 0)
        rc = exec_sql(w, ddl);
    free(ddl);
    free(store);
    if (rc != 0) return -1;
    /* the capture flag starts at 0 (consensus-off until the edge) */
    return exec_sql(w, "INSERT INTO v2_trie_state (id, capture) "
                       "VALUES (1, 0)");
}

int nodus_witness_db_s20_trie_shape_ok(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    return s20_trie_shape_ok(w);
}

int nodus_witness_db_s20_trie_capture(nodus_witness_t *w, int *capture) {
    if (!w || !w->db || !capture) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT capture, typeof(capture) FROM v2_trie_state "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 1);
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (t && strcmp(t, "integer") == 0 && (v == 0 || v == 1) &&
            sqlite3_step(st) == SQLITE_DONE) {
            *capture = (int)v;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

int nodus_witness_db_migrate_v2s20_ex(nodus_witness_t *w,
                                      nodus_v2s20_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S20) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S19) {
        /* the S9...S19 chain; an unknown version (21+) fails closed there */
        if (nodus_witness_db_migrate_v2s19(w) != 0) return -1;
        ver = NODUS_V2_SCHEMA_VERSION_S19;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;

    int ok = 0;
    int already = 0;
    do {
        if (fail_at == V2S20MIG_FAIL_AFTER_BEGIN) break;

        /* O15B discipline: the pre-BEGIN read decided nothing. */
        int rv = mig_revalidate_version(w, NODUS_V2_SCHEMA_VERSION_S19,
                                        NODUS_V2_SCHEMA_VERSION_S20, "S20");
        if (rv < 0) break;
        if (rv == 0) { already = 1; break; }
        if (fail_at == V2S20MIG_FAIL_AFTER_REVALIDATE) break;

        if (exec_sql(w, V2_S20_SUPPLY_TOTALS_DDL) != 0) break;
        if (exec_sql(w, V2_S20_BOND_TOTAL_DDL) != 0) break;
        if (exec_sql(w, V2_S20_SUPPLY_TRIGGERS_DDL) != 0) break;
        if (exec_sql(w, V2_S20_SUPPLY_RESEED_SQL) != 0) break;
        /* HF-9 WP2: the keyed-trie tables, the registry index, the 24
         * dirty-capture triggers and the capture row at 0 */
        if (s20_trie_create(w) != 0) break;
        /* HF-9 WP4: the capacity rebuild of v2_storage_sets / _reports
         * (1024 / 128) and the retained-assignment tables (§8.4) */
        if (s20_storage_create(w) != 0) break;
        if (fail_at == V2S20MIG_FAIL_AFTER_TABLES) break;

        /* Verify: every table's whole stored definition, the index's
         * exact key columns and every trigger's stored SQL — a DDL that
         * silently did nothing, or a pre-existing object of another
         * shape, is not a migrated schema. */
        if (s20_supply_shape_ok(w) != 1 || s20_trie_shape_ok(w) != 1 ||
            s20_storage_shape_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S20 supply-totals / keyed-trie / "
                          "storage-assignment schema shape drift — "
                          "refusing");
            break;
        }
        if (fail_at == V2S20MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 20") != 0) break;
        if (fail_at == V2S20MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        (void)exec_sql(w, "ROLLBACK");
        return 0;
    }
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

int nodus_witness_db_migrate_v2s20(nodus_witness_t *w) {
    return nodus_witness_db_migrate_v2s20_ex(w, V2S20MIG_FAIL_NONE);
}

int nodus_witness_db_s20_reseed(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver < NODUS_V2_SCHEMA_VERSION_S20) return 0;
    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;
    int ok = 0;
    do {
        uint32_t v2 = 0;
        if (nodus_witness_db_schema_version(w, &v2) != 0 || v2 != ver)
            break;
        if (exec_sql(w, V2_S20_SUPPLY_TOTALS_DDL) != 0) break;
        if (exec_sql(w, V2_S20_BOND_TOTAL_DDL) != 0) break;
        if (exec_sql(w, V2_S20_SUPPLY_TRIGGERS_DDL) != 0) break;
        if (exec_sql(w, V2_S20_SUPPLY_RESEED_SQL) != 0) break;
        if (s20_supply_shape_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S20 supply-totals schema shape "
                          "drift at open — refusing");
            break;
        }
        /* plan §5.2: the keyed-trie tables and the 24 triggers are
         * verified at EVERY open of an S20 database, independent of any
         * shadow setting and before activation (a missing or altered
         * trigger = refuse to start: DROP TABLE removes triggers). They
         * are never recreated here — a repaired trigger would hide that
         * writes went uncaptured. */
        if (s20_trie_shape_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S20 keyed-trie schema or trigger "
                          "missing or altered at open — refusing");
            break;
        }
        if (s20_storage_shape_ok(w) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S20 storage-assignment tables or "
                          "the capacity-rebuilt storage sets / reports "
                          "missing or altered at open — refusing");
            break;
        }
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

/* ── the §18 evm_logs cursor scan (red-team 1 F4) ──────────────────────
 * Contract: nodus_witness_v2_schema.h. Every statement is served by an
 * index in the scan's own order — no full scan, no sort (pinned by
 * test_v2_schema.c over EXPLAIN QUERY PLAN of these exact texts). */

enum {
    EVL_SQL_H_ANY = 0,  /* the next height ≥ pos.h holding any receipt  */
    EVL_SQL_H_ADDR,     /* the next height ≥ pos.h holding a log of addr */
    EVL_SQL_R,          /* the receipts of one height, item order        */
    EVL_SQL_L_ANY,      /* the logs of one receipt, log order            */
    EVL_SQL_L_ADDR,     /* the logs of one receipt from addr, log order  */
    EVL_SQL_DATA,       /* one MATCHING log's data, by rowid             */
    EVL_SQL_N
};

const char *const nodus_evm_logs_scan_sql[NODUS_EVM_LOGS_SCAN_SQL_N] = {
    [EVL_SQL_H_ANY] =
        "SELECT global_height FROM evm_receipts "
        "WHERE global_height >= ?1 AND global_height <= ?2 "
        "ORDER BY global_height LIMIT 1",
    [EVL_SQL_H_ADDR] =
        "SELECT global_height FROM evm_logs "
        "WHERE addr = ?3 AND global_height >= ?1 AND global_height <= ?2 "
        "ORDER BY global_height LIMIT 1",
    [EVL_SQL_R] =
        "SELECT item_index, intent_id FROM evm_receipts "
        "WHERE global_height = ?1 AND item_index >= ?2 "
        "ORDER BY item_index",
    /* length(data), not data: an examined log that does not match never
     * loads its data (SQLite's OP_Column with OPFLAG_LENGTHARG does not
     * load the content of a blob — READ in the 3.47.2 amalgamation
     * source, OP_Column comment "The content of large blobs is not
     * loaded"; the nodus build links the system SQLite 3.40.1 (CMakeCache
     * FIND_PACKAGE_MESSAGE_DETAILS_SQLite3), whose source was not read);
     * a match reads it by rowid, one more examined row */
    [EVL_SQL_L_ANY] =
        "SELECT log_index, addr, topics, length(data), global_height, rowid "
        "FROM evm_logs WHERE intent_id = ?1 AND log_index >= ?2 "
        "ORDER BY log_index",
    [EVL_SQL_L_ADDR] =
        "SELECT log_index, addr, topics, length(data), global_height, rowid "
        "FROM evm_logs WHERE addr = ?3 AND global_height = ?4 "
        "AND intent_id = ?1 AND log_index >= ?2 ORDER BY log_index",
    [EVL_SQL_DATA] =
        "SELECT data FROM evm_logs WHERE rowid = ?1",
};

typedef char evl_sql_n_matches[(EVL_SQL_N == NODUS_EVM_LOGS_SCAN_SQL_N)
                               ? 1 : -1];

/* What one returned log adds to the reply estimate: its data and topics,
 * the 32-byte address, the 64-byte intent id and 96 bytes of keys / CBOR
 * heads (the estimate the handler used before the cursor). */
static size_t evl_row_est(size_t data_len, size_t topics_len) {
    return data_len + topics_len + 32 + 64 + 96;
}

static uint64_t evl_gas(uint64_t examined, size_t bytes) {
    return examined * NODUS_EVM_RPC_GAS_PER_ROW +
           (uint64_t)bytes * NODUS_EVM_RPC_GAS_PER_BYTE;
}

void nodus_witness_evm_logs_page_free(nodus_evm_logs_page_t *p) {
    if (!p) return;
    if (p->rows)
        for (size_t k = 0; k < p->n; k++) free(p->rows[k].data);
    free(p->rows);
    p->rows = NULL;
    p->n = 0;
}

int nodus_witness_evm_logs_scan(nodus_witness_t *w,
                                const nodus_evm_logs_scan_t *q,
                                nodus_evm_logs_page_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!w || !w->db || !q || q->lim < 1 ||
        q->lim > NODUS_EVM_LOGS_SCAN_MAX_LIM ||
        q->th > (uint64_t)INT64_MAX || q->from.h > q->th ||
        q->from.x > NODUS_EVM_LOG_POS_MAX ||
        q->from.li > NODUS_EVM_LOG_POS_MAX)
        return -1;
    out->rows = calloc(q->lim, sizeof(*out->rows));
    if (!out->rows) return -1;

    sqlite3_stmt *st[EVL_SQL_N] = { NULL };
    for (int k = 0; k < EVL_SQL_N; k++)
        if (sqlite3_prepare_v2(w->db, nodus_evm_logs_scan_sql[k], -1, &st[k],
                               NULL) != SQLITE_OK) {
            for (int j = 0; j < k; j++) sqlite3_finalize(st[j]);
            nodus_witness_evm_logs_page_free(out);
            return -1;
        }

    /* pos = the first position not yet processed: every log before it was
     * examined and either returned or did not match; every unreturned
     * match is at or after it. The cursor a truncated page returns. */
    nodus_evm_log_pos_t pos = q->from;
    uint64_t examined = 0;
    size_t bytes = 0;
    int ret = -1, stop = 0, done = 0;

/* one more examined row: the step may run only if it is affordable */
#define EVL_CAN_STEP() \
    (examined + 1 <= q->max_examined && \
     evl_gas(examined + 1, bytes) <= q->gas_cap)

    while (!stop && !done) {
        /* ── the next height at or after pos.h that can hold a match ── */
        if (!EVL_CAN_STEP()) { stop = 1; break; }
        sqlite3_stmt *sh = st[q->addr ? EVL_SQL_H_ADDR : EVL_SQL_H_ANY];
        sqlite3_reset(sh);
        sqlite3_bind_int64(sh, 1, (sqlite3_int64)pos.h);
        sqlite3_bind_int64(sh, 2, (sqlite3_int64)q->th);
        if (q->addr) sqlite3_bind_blob(sh, 3, q->addr, 32, SQLITE_TRANSIENT);
        examined++;
        int rc = sqlite3_step(sh);
        if (rc == SQLITE_DONE) { done = 1; break; }
        if (rc != SQLITE_ROW) goto out;
        sqlite3_int64 hh = sqlite3_column_int64(sh, 0);
        if (hh < 0 || (uint64_t)hh < pos.h || (uint64_t)hh > q->th) goto out;
        if ((uint64_t)hh > pos.h) {
            pos.h = (uint64_t)hh;
            pos.x = 0;
            pos.li = 0;
        }
        sqlite3_reset(sh);

        /* ── the receipts of height pos.h from pos.x, item order ───── */
        sqlite3_stmt *sr = st[EVL_SQL_R];
        sqlite3_reset(sr);
        sqlite3_bind_int64(sr, 1, (sqlite3_int64)pos.h);
        sqlite3_bind_int64(sr, 2, (sqlite3_int64)pos.x);
        for (;;) {
            if (!EVL_CAN_STEP()) { stop = 1; break; }
            examined++;
            rc = sqlite3_step(sr);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) goto out;
            sqlite3_int64 xi = sqlite3_column_int64(sr, 0);
            if (xi < 0 || xi > (sqlite3_int64)UINT32_MAX ||
                (uint64_t)xi < pos.x || sqlite3_column_bytes(sr, 1) != 64)
                goto out;
            uint8_t intent[64];
            memcpy(intent, sqlite3_column_blob(sr, 1), 64);
            if ((uint64_t)xi > pos.x) {
                pos.x = (uint64_t)xi;
                pos.li = 0;
            }

            /* ── its logs from pos.li, log order ─────────────────── */
            sqlite3_stmt *sl = st[q->addr ? EVL_SQL_L_ADDR : EVL_SQL_L_ANY];
            sqlite3_reset(sl);
            sqlite3_bind_blob(sl, 1, intent, 64, SQLITE_TRANSIENT);
            sqlite3_bind_int64(sl, 2, (sqlite3_int64)pos.li);
            if (q->addr) {
                sqlite3_bind_blob(sl, 3, q->addr, 32, SQLITE_TRANSIENT);
                sqlite3_bind_int64(sl, 4, (sqlite3_int64)pos.h);
            }
            for (;;) {
                if (!EVL_CAN_STEP()) { stop = 1; break; }
                examined++;
                rc = sqlite3_step(sl);
                if (rc == SQLITE_DONE) break;
                if (rc != SQLITE_ROW) goto out;
                sqlite3_int64 li = sqlite3_column_int64(sl, 0);
                int tl = sqlite3_column_bytes(sl, 2);
                sqlite3_int64 dl = sqlite3_column_int64(sl, 3);
                if (li < 0 || li > (sqlite3_int64)UINT32_MAX ||
                    (uint64_t)li < pos.li ||
                    sqlite3_column_type(sl, 3) != SQLITE_INTEGER ||
                    sqlite3_column_bytes(sl, 1) != 32 ||
                    tl < 0 || tl % 32 != 0 || tl > 4 * 32 || dl < 0 ||
                    dl > INT_MAX ||
                    sqlite3_column_int64(sl, 4) != (sqlite3_int64)pos.h)
                    goto out;
                pos.li = (uint64_t)li;
                const uint8_t *la = sqlite3_column_blob(sl, 1);
                const uint8_t *lt = sqlite3_column_blob(sl, 2);
                int match = !q->addr || memcmp(la, q->addr, 32) == 0;
                for (int t = 0; t < 4 && match; t++)
                    if (q->topic[t] &&
                        (tl < (t + 1) * 32 ||
                         memcmp(lt + (size_t)t * 32, q->topic[t], 32) != 0))
                        match = 0;
                if (match) {
                    size_t est = evl_row_est((size_t)dl, (size_t)tl);
                    /* a match that does not fit — the page is full, the
                     * reply byte budget, or the data read plus its bytes
                     * are not affordable — stays unreturned AT pos */
                    if (out->n == q->lim ||
                        (out->n > 0 && bytes + est > q->max_bytes) ||
                        examined + 1 > q->max_examined ||
                        evl_gas(examined + 1, bytes + est) > q->gas_cap) {
                        stop = 1;
                        break;
                    }
                    nodus_evm_log_row_t *e = &out->rows[out->n];
                    e->h = pos.h;
                    e->x = pos.x;
                    e->li = pos.li;
                    memcpy(e->addr, la, 32);
                    memcpy(e->intent_id, intent, 64);
                    e->n_topics = (uint8_t)(tl / 32);
                    if (tl) memcpy(e->topics, lt, (size_t)tl);
                    if (dl) {
                        /* the data, by rowid — exactly length(data) */
                        sqlite3_stmt *sd = st[EVL_SQL_DATA];
                        sqlite3_reset(sd);
                        sqlite3_bind_int64(sd, 1,
                                           sqlite3_column_int64(sl, 5));
                        examined++;
                        if (sqlite3_step(sd) != SQLITE_ROW ||
                            sqlite3_column_bytes(sd, 0) != (int)dl)
                            goto out;
                        e->data = malloc((size_t)dl);
                        if (!e->data) goto out;
                        memcpy(e->data, sqlite3_column_blob(sd, 0),
                               (size_t)dl);
                        sqlite3_reset(sd);
                    }
                    e->data_len = (size_t)dl;
                    out->n++;
                    bytes += est;
                }
                pos.li++;                   /* this log is processed     */
            }
            sqlite3_reset(sl);
            if (stop) break;
            pos.x++;                        /* this receipt is processed */
            pos.li = 0;
        }
        sqlite3_reset(sr);
        if (stop) break;
        /* this height is processed */
        if (pos.h == q->th) { done = 1; break; }
        pos.h++;
        pos.x = 0;
        pos.li = 0;
    }
#undef EVL_CAN_STEP

    out->truncated = stop && !done;
    if (out->truncated) out->next = pos;
    ret = 0;
out:
    out->examined = examined;
    out->bytes = bytes;
    out->gas = evl_gas(examined, bytes);
    for (int k = 0; k < EVL_SQL_N; k++) sqlite3_finalize(st[k]);
    if (ret != 0) nodus_witness_evm_logs_page_free(out);
    return ret;
}
