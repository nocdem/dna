/**
 * @file nodus_witness_v2_schema.c
 * @brief Ledger V2 Season 5 — versioned schema + atomic migration
 *        implementation (INACTIVE). Contract: nodus_witness_v2_schema.h.
 *
 * @file nodus_witness_v2_schema.c
 */

#include "witness/nodus_witness_v2_schema.h"

#include <sqlite3.h>
#include <limits.h>
#include <stdarg.h>
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
    /* S17, S18, S19 or S20 (HF-6 3a: S18 = S17 + v2_validator_roles; HF-7
     * P1b: S19 = S18 + v2_replay, its index and one column; HF-9 H2: S20
     * = S19 + the tree tables and the storage-table rebuilds; the at-open
     * rung reaches S20 before this step runs — header) */
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

/* ── S20 migration: HF-9 H2, the node-local tree tables + the four
 *    storage-table rebuilds ───────────────────────────────────────────────
 * Contract: nodus_witness_v2_schema.h. Spec: docs/plans/2026-10-23-hf9-
 * byte-spec.md rev 3 §8 (tables, rebuilds), §9 (the source tables of the
 * shadow), §4 (the dirty tables' key columns). Everything is created
 * EMPTY; nothing reads or writes it before HF-9 H3. */

/* The fixed tree tables, spec §8 verbatim. */
static const struct { const char *table; const char *ddl; } V2_S20_TREE[] = {
    { "v2_tree_ctx",
      "CREATE TABLE IF NOT EXISTS v2_tree_ctx ("
      "id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL)" },
    { "v2_tree_nodes",
      "CREATE TABLE IF NOT EXISTS v2_tree_nodes ("
      "digest BLOB PRIMARY KEY CHECK(typeof(digest)='blob' AND "
      "length(digest)=64), rlp BLOB NOT NULL) WITHOUT ROWID" },
    { "v2_tree_roots",
      "CREATE TABLE IF NOT EXISTS v2_tree_roots ("
      "scope INTEGER, leg INTEGER, sub INTEGER, domain INTEGER, "
      "height INTEGER, root BLOB NOT NULL CHECK(length(root)=64), "
      "PRIMARY KEY(scope, leg, sub, domain, height)) WITHOUT ROWID" },
    { "v2_tree_compwit",
      "CREATE TABLE IF NOT EXISTS v2_tree_compwit ("
      "height INTEGER, kind INTEGER, domain INTEGER, slot INTEGER, "
      "data BLOB NOT NULL, "
      "PRIMARY KEY(height, kind, domain, slot)) WITHOUT ROWID" }
};

/* One dirty table per trie of spec §3 (JUDGMENT, spec names no table
 * names: v2_tree_dirty_<trie> with the storage tries spelled st_*). The
 * columns are the key columns of spec §4 under the SOURCE table's column
 * names (the H3 triggers copy OLD/NEW straight across), + the domain for
 * pools and claims; PK = those columns. */
static const struct {
    const char *trie;
    const char *cols;
    const char *pk;
} V2_S20_DIRTY[] = {
    { "utxo",        "nullifier BLOB NOT NULL", "nullifier" },
    { "token",       "token_id BLOB NOT NULL", "token_id" },
    { "pools",       "domain_id INTEGER NOT NULL, pool_id INTEGER NOT NULL",
                     "domain_id, pool_id" },
    { "claims",      "target_domain_id INTEGER NOT NULL, "
                     "nullifier BLOB NOT NULL",
                     "target_domain_id, nullifier" },
    { "names",       "name BLOB NOT NULL", "name" },
    { "accrual",     "owner_fp BLOB NOT NULL", "owner_fp" },
    { "validator",   "pubkey_hash BLOB NOT NULL", "pubkey_hash" },
    { "delegation",  "delegator_hash BLOB NOT NULL, "
                     "validator_hash BLOB NOT NULL",
                     "delegator_hash, validator_hash" },
    { "chain_config", "param_id INTEGER NOT NULL, "
                     "effective_block INTEGER NOT NULL",
                     "param_id, effective_block" },
    { "vset",        "epoch_start INTEGER NOT NULL", "epoch_start" },
    { "manifest",    "manifest_hash BLOB NOT NULL", "manifest_hash" },
    { "attendance",  "epoch_start INTEGER NOT NULL", "epoch_start" },
    { "st_registry", "node_fp BLOB NOT NULL", "node_fp" },
    { "st_sets",     "epoch_start INTEGER NOT NULL", "epoch_start" },
    { "st_reports",  "epoch_start INTEGER NOT NULL, seat INTEGER NOT NULL",
                     "epoch_start, seat" },
    { "st_segments", "k INTEGER NOT NULL", "k" },
    { "bcopy",       "epoch_start INTEGER NOT NULL, "
                     "validator_fp BLOB NOT NULL, owner_fp BLOB NOT NULL, "
                     "kind INTEGER NOT NULL",
                     "epoch_start, validator_fp, owner_fp, kind" },
    { "stmem",       "epoch_start INTEGER NOT NULL, node_fp BLOB NOT NULL",
                     "epoch_start, node_fp" },
    { "replay",      "tx_id BLOB NOT NULL", "tx_id" }
};

/* One shadow table per SOURCE table of the spec §9 dependency matrix. */
static const char *const V2_S20_SHADOW_SRC[] = {
    "utxo_set", "tokens", "v2_pools", "v2_pool_roots", "v2_claims_spent",
    "v2_names", "v2_reward_accrual", "chain_config_history",
    "validator_set_snapshots", "v2_manifests", "v2_attendance_epoch",
    "v2_storage_reports", "v2_storage_segments", "v2_balance_copy",
    "v2_replay", "validators", "v2_validator_roles", "delegations",
    "v2_storage_sets", "v2_storage_set_members", "v2_storage_nodes"
};

#define S20_DDL_MAX 4096u
#define S20_PK_MAX  8u
#define S20_COL_MAX 64u

/* Append printf-formatted text to buf[0..cap), tracking *len. 0 ok,
 * -1 = it does not fit (never truncated). */
static int s20_cat(char *buf, size_t cap, size_t *len, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *len) return -1;
    *len += (size_t)n;
    return 0;
}

/* The shadow table's DDL for `src`, read from the LIVE source table (spec
 * §9: "the source table's full column list"): height, op, then every
 * source column in table order under its declared type, NO constraint
 * (op = 0 rows carry NULLs), PRIMARY KEY (height, <source PK in key
 * order>), WITHOUT ROWID. 0 ok, -1 = the source is absent / has no PK /
 * a column would collide with height or op / the text does not fit /
 * a SQLite fault. */
static int s20_shadow_ddl(nodus_witness_t *w, const char *src,
                          char *out, size_t cap) {
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(\"%s\")", src);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    char pk[S20_PK_MAX][S20_COL_MAX];
    size_t n_pk = 0, n_cols = 0, len = 0;
    int bad = 0, rc;
    memset(pk, 0, sizeof(pk));
    if (s20_cat(out, cap, &len, "CREATE TABLE IF NOT EXISTS "
                "v2_tree_shadow_%s (height INTEGER NOT NULL, "
                "op INTEGER NOT NULL CHECK(op IN (0, 1))", src) != 0)
        bad = 1;
    while (!bad && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *nm = (const char *)sqlite3_column_text(st, 1);
        const char *ty = (const char *)sqlite3_column_text(st, 2);
        int pki = sqlite3_column_int(st, 5);
        if (!nm || !ty || strchr(nm, '"') || strlen(nm) >= S20_COL_MAX ||
            strcmp(nm, "height") == 0 || strcmp(nm, "op") == 0 ||
            pki < 0 || (size_t)pki > S20_PK_MAX) {
            bad = 1;
            break;
        }
        if (pki > 0) {
            if (pk[pki - 1][0] != '\0') { bad = 1; break; }
            snprintf(pk[pki - 1], S20_COL_MAX, "%s", nm);
            if ((size_t)pki > n_pk) n_pk = (size_t)pki;
        }
        if (s20_cat(out, cap, &len, ", \"%s\" %s", nm, ty) != 0) {
            bad = 1;
            break;
        }
        n_cols++;
    }
    if (!bad && rc != SQLITE_DONE) bad = 1;
    sqlite3_finalize(st);
    if (bad || n_cols == 0 || n_pk == 0) {
        QGP_LOG_ERROR(LOG_TAG, "S20: cannot derive the shadow table of %s "
                      "(absent, no primary key or an unusable column)",
                      src);
        return -1;
    }
    if (s20_cat(out, cap, &len, ", PRIMARY KEY (height") != 0) return -1;
    for (size_t i = 0; i < n_pk; i++) {
        if (pk[i][0] == '\0' ||                /* a gap in the key order */
            s20_cat(out, cap, &len, ", \"%s\"", pk[i]) != 0)
            return -1;
    }
    if (s20_cat(out, cap, &len, ")) WITHOUT ROWID") != 0) return -1;
    return 0;
}

/* Create `ddl` (CREATE TABLE IF NOT EXISTS) and require the table that
 * now exists to carry EXACTLY that stored text: a pre-existing table of
 * the same name and another shape is refused, not read through. */
static int s20_make_table(nodus_witness_t *w, const char *table,
                          const char *ddl, int create) {
    if (create && exec_sql(w, ddl) != 0) return -1;
    if (table_ddl_exact(w, table, ddl) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "S20: %s exists with another shape — "
                      "refusing", table);
        return -1;
    }
    return 0;
}

typedef struct {
    const char *table;
    const char *s19_ddl;     /* the text a database below S20 stores   */
    const char *s20_ddl;     /* the text it must carry from S20 on     */
    const char *copy_cols;   /* the columns both texts share           */
} s20_rebuild_t;

/* The four storage tables of spec §8. Bound to the macros of
 * nodus_witness.h, which the open-time shape check uses too. */
static const s20_rebuild_t V2_S20_REBUILD[] = {
    { "v2_storage_sets",        NODUS_V2_STSETS_S19_DDL, NODUS_V2_STSETS_DDL,
      "epoch_start, set_hash, member_count" },
    { "v2_storage_reports",     NODUS_V2_STREPS_S19_DDL, NODUS_V2_STREPS_DDL,
      "epoch_start, seat, set_hash, bitmap" },
    { "v2_storage_set_members", NODUS_V2_STMEMB_S19_DDL, NODUS_V2_STMEMB_DDL,
      "epoch_start, node_fp, fail_streak, grace_until" },
    { "v2_storage_nodes",       NODUS_V2_STORAGE_S19_DDL,
      NODUS_V2_STORAGE_DDL,
      "node_fp, node_pk, payee_fp, bond, status, registered_height, "
      "exit_height, fail_streak, grace_until" }
};

/* COUNT(*) of `table`; -1 on a fault. */
static int64_t s20_count(nodus_witness_t *w, const char *table) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM \"%s\"", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* Bring one storage table to its S20 text. Already in the S20 text (a
 * database the new base schema created, or a re-entry): nothing. In the
 * S19 text: rename it away, create the S20 table under the real name by
 * the exact statement the shape check executes, copy every row (the new
 * columns take their DEFAULTs), require the same row count, drop the
 * old one. In neither text: refuse. Inside the caller's transaction. */
static int s20_rebuild_table(nodus_witness_t *w, const s20_rebuild_t *r) {
    int cur = table_ddl_exact(w, r->table, r->s20_ddl);
    if (cur < 0) return -1;
    if (cur == 1) return 0;
    if (table_ddl_exact(w, r->table, r->s19_ddl) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "S20: %s is in neither the S19 nor the S20 "
                      "text — refusing", r->table);
        return -1;
    }
    int64_t before = s20_count(w, r->table);
    if (before < 0) return -1;

    char sql[1024];
    snprintf(sql, sizeof(sql), "ALTER TABLE \"%s\" RENAME TO "
             "\"%s_s19old\"", r->table, r->table);
    if (exec_sql(w, sql) != 0) return -1;
    if (exec_sql(w, r->s20_ddl) != 0) return -1;
    int n = snprintf(sql, sizeof(sql), "INSERT INTO \"%s\" (%s) SELECT %s "
                     "FROM \"%s_s19old\"", r->table, r->copy_cols,
                     r->copy_cols, r->table);
    if (n < 0 || (size_t)n >= sizeof(sql) || exec_sql(w, sql) != 0)
        return -1;
    if (s20_count(w, r->table) != before) {
        QGP_LOG_ERROR(LOG_TAG, "S20: %s lost rows in the rebuild — "
                      "refusing", r->table);
        return -1;
    }
    snprintf(sql, sizeof(sql), "DROP TABLE \"%s_s19old\"", r->table);
    if (exec_sql(w, sql) != 0) return -1;
    if (table_ddl_exact(w, r->table, r->s20_ddl) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "S20: the rebuilt %s does not carry the S20 "
                      "text — refusing", r->table);
        return -1;
    }
    return 0;
}

/* The fixed, dirty and shadow tables, each required to carry EXACTLY its
 * S20 text. create = 1: created first (the rung); create = 0: read-only,
 * a missing or drifted table is refused (the open-time verifier). 0 ok,
 * -1 refused / fault. */
static int s20_tree_tables(nodus_witness_t *w, int create) {
    for (size_t i = 0; i < sizeof(V2_S20_TREE) / sizeof(V2_S20_TREE[0]); i++)
        if (s20_make_table(w, V2_S20_TREE[i].table, V2_S20_TREE[i].ddl,
                           create) != 0)
            return -1;
    for (size_t i = 0; i < sizeof(V2_S20_DIRTY) / sizeof(V2_S20_DIRTY[0]);
         i++) {
        char name[96], ddl[S20_DDL_MAX];
        int a = snprintf(name, sizeof(name), "v2_tree_dirty_%s",
                         V2_S20_DIRTY[i].trie);
        int b = snprintf(ddl, sizeof(ddl), "CREATE TABLE IF NOT EXISTS "
                         "%s (%s, PRIMARY KEY (%s)) WITHOUT ROWID",
                         name, V2_S20_DIRTY[i].cols, V2_S20_DIRTY[i].pk);
        if (a < 0 || (size_t)a >= sizeof(name) || b < 0 ||
            (size_t)b >= sizeof(ddl) ||
            s20_make_table(w, name, ddl, create) != 0)
            return -1;
    }
    /* the shadow tables, from the live source tables */
    for (size_t i = 0; i < sizeof(V2_S20_SHADOW_SRC) /
                           sizeof(V2_S20_SHADOW_SRC[0]); i++) {
        char name[96], ddl[S20_DDL_MAX];
        int a = snprintf(name, sizeof(name), "v2_tree_shadow_%s",
                         V2_S20_SHADOW_SRC[i]);
        if (a < 0 || (size_t)a >= sizeof(name) ||
            s20_shadow_ddl(w, V2_S20_SHADOW_SRC[i], ddl, sizeof(ddl)) != 0 ||
            s20_make_table(w, name, ddl, create) != 0)
            return -1;
    }
    return 0;
}

/* Every storage table in the S20 text (the segments table is untouched by
 * the rung and held too) and the payee index on exactly payee_fp. 0 ok,
 * -1 drift / fault (logged). Read-only. */
static int s20_storage_verify(nodus_witness_t *w) {
    static const char *const ix_cols[] = { "payee_fp" };
    int v = 1;
    for (size_t i = 0; i < sizeof(V2_S20_REBUILD) /
                           sizeof(V2_S20_REBUILD[0]); i++)
        if (table_ddl_exact(w, V2_S20_REBUILD[i].table,
                            V2_S20_REBUILD[i].s20_ddl) != 1)
            v = 0;
    if (table_ddl_exact(w, "v2_storage_segments", NODUS_V2_STSEGS_DDL) != 1 ||
        index_cols_exact(w, "idx_v2_storage_nodes_payee",
                         "v2_storage_nodes", ix_cols, 1) != 1)
        v = 0;
    if (!v) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "S20 storage-table schema shape drift "
                      "— refusing");
        return -1;
    }
    return 0;
}

int nodus_witness_db_migrate_v2s20_ex(nodus_witness_t *w,
                                      nodus_v2s20_mig_fail_t fail_at) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver == NODUS_V2_SCHEMA_VERSION_S20) return 0;    /* idempotent    */
    if (ver != NODUS_V2_SCHEMA_VERSION_S19) {
        /* the S9…S19 chain; an unknown version (21+) fails closed there */
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

        int fail = 0;
        /* the four storage tables first: the shadows below read their NEW
         * column lists */
        for (size_t i = 0; !fail && i < sizeof(V2_S20_REBUILD) /
                                         sizeof(V2_S20_REBUILD[0]); i++)
            if (s20_rebuild_table(w, &V2_S20_REBUILD[i]) != 0) fail = 1;
        /* A rebuild drops every index of the old table with it (an index
         * moves with a rename and goes with the DROP). Recreated here:
         * every index the REPOSITORY defines on the four rebuilt tables —
         * a grep of the whole tree found exactly one, the registry's
         * payee index (nodus_witness.c, every open). Only
         * repository-defined indexes are guaranteed: an index someone
         * added by hand to a rebuilt table is not carried over. Idempotent
         * where the table was not rebuilt. */
        if (!fail && exec_sql(w, "CREATE INDEX IF NOT EXISTS "
                                 "idx_v2_storage_nodes_payee ON "
                                 "v2_storage_nodes(payee_fp)") != 0)
            fail = 1;
        /* the fixed, dirty and shadow tables */
        if (!fail && s20_tree_tables(w, 1) != 0) fail = 1;
        if (fail) break;
        if (fail_at == V2S20MIG_FAIL_AFTER_TABLES) break;

        /* Verify what the rebuild promised: every storage table in the
         * S20 text (the segments table is untouched and checked too), the
         * payee index on exactly payee_fp. */
        if (s20_storage_verify(w) != 0) break;
        if (fail_at == V2S20MIG_FAIL_AFTER_VERIFY) break;

        if (exec_sql(w, "PRAGMA user_version = 20") != 0) break;
        if (fail_at == V2S20MIG_FAIL_BEFORE_COMMIT) break;

        ok = 1;
    } while (0);

    if (already) {
        /* nothing was written; a rollback that FAILS leaves a transaction
         * open on the handle — an error, not an idempotent success */
        return exec_sql(w, "ROLLBACK") == 0 ? 0 : -1;
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

int nodus_witness_db_verify_v2s20_shape(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver != NODUS_V2_SCHEMA_VERSION_S20) return 0;   /* nothing to hold */
    if (s20_tree_tables(w, 0) != 0 || s20_storage_verify(w) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "S20 database whose tree / storage tables drifted "
                      "from the S20 shape — refusing");
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
