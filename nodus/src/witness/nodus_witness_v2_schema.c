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
#include <stdio.h>
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
         * database, and nodus_witness_v2_gen_derive climbs to S12 through
         * it), and version 10 databases exist. Collapsing 9→11 would
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

/* ── S11 (O15E Faz B): canonical envelope byte availability ─────────── */

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

        /* tx_id UNIQUE mirrors v2_tx_index (one committed wire tx, one
         * byte record); the PK is the canonical batch order the block
         * message re-assembles in. NO default on any column. */
        if (exec_sql(w,
                "CREATE TABLE IF NOT EXISTS v2_tx_bytes ("
                "  global_height INTEGER NOT NULL,"
                "  global_index INTEGER NOT NULL,"
                "  tx_id BLOB NOT NULL UNIQUE,"
                "  env BLOB NOT NULL,"
                "  PRIMARY KEY (global_height, global_index)"
                ")") != 0)
            break;
        if (fail_at == V2S11MIG_FAIL_AFTER_TABLES) break;

        static const char *const txb_cols[] = {
            "global_height", "global_index", "tx_id", "env"
        };
        if (table_cols_exact(w, "v2_tx_bytes", txb_cols,
                sizeof(txb_cols) / sizeof(txb_cols[0])) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "S11 schema shape drift — refusing");
            break;
        }
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
