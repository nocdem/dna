/**
 * @file db.c
 * @brief SQLite database operations for DNAC
 */

#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include "dnac/epoch.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#define LOG_TAG "DNAC_DB"

/* Database schema version */
#define DNAC_DB_VERSION 6

/* Pending spend status values */
#define DNAC_PENDING_STATUS_ACTIVE    0
#define DNAC_PENDING_STATUS_COMPLETE  1
#define DNAC_PENDING_STATUS_EXPIRED   2
#define DNAC_PENDING_STATUS_FAILED    3

/* Schema version table - created first */
static const char *SCHEMA_VERSION_SQL =
    "CREATE TABLE IF NOT EXISTS dnac_schema_version ("
    "    version INTEGER NOT NULL,"
    "    applied_at INTEGER NOT NULL"
    ");";

static const char *SCHEMA_SQL =
    /* UTXOs table */
    "CREATE TABLE IF NOT EXISTS dnac_utxos ("
    "    id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    tx_hash             BLOB NOT NULL,"
    "    output_index        INTEGER NOT NULL,"
    "    amount              INTEGER NOT NULL,"
    "    nullifier           BLOB NOT NULL UNIQUE,"
    "    owner_fingerprint   TEXT NOT NULL,"
    "    status              INTEGER NOT NULL DEFAULT 0,"
    "    received_at         INTEGER NOT NULL,"
    "    spent_at            INTEGER,"
    "    spent_in_tx         BLOB"
    ");"

    /* Transactions table */
    "CREATE TABLE IF NOT EXISTS dnac_transactions ("
    "    id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    tx_hash             BLOB NOT NULL UNIQUE,"
    "    raw_tx              BLOB,"
    "    type                INTEGER NOT NULL,"
    "    counterparty_fp     TEXT,"
    "    created_at          INTEGER NOT NULL,"
    "    confirmed_at        INTEGER,"
    "    amount_in           INTEGER NOT NULL DEFAULT 0,"
    "    amount_out          INTEGER NOT NULL DEFAULT 0,"
    "    amount_fee          INTEGER NOT NULL DEFAULT 0"
    ");"

    /* Pending spends table */
    "CREATE TABLE IF NOT EXISTS dnac_pending_spends ("
    "    id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    tx_hash             BLOB NOT NULL,"
    "    nullifier           BLOB NOT NULL,"
    "    witnesses_needed    INTEGER NOT NULL DEFAULT 2,"
    "    witnesses_received  INTEGER NOT NULL DEFAULT 0,"
    "    witness_signatures  BLOB,"
    "    created_at          INTEGER NOT NULL,"
    "    expires_at          INTEGER NOT NULL,"
    "    status              INTEGER NOT NULL DEFAULT 0"
    ");"

    /* Indexes */
    "CREATE INDEX IF NOT EXISTS idx_utxos_status ON dnac_utxos(status);"
    "CREATE INDEX IF NOT EXISTS idx_utxos_owner ON dnac_utxos(owner_fingerprint);"
    "CREATE INDEX IF NOT EXISTS idx_pending_status ON dnac_pending_spends(status);";

/* Forward declarations for internal functions */
static int dnac_db_get_version(sqlite3 *db);
static int dnac_db_set_version(sqlite3 *db, int version);

int dnac_db_init(sqlite3 *db) {
    if (!db) return DNAC_ERROR_INVALID_PARAM;

    char *err_msg = NULL;

    /* Create schema version table first */
    int rc = sqlite3_exec(db, SCHEMA_VERSION_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "DB version table error: %s", err_msg);
        sqlite3_free(err_msg);
        return DNAC_ERROR_DATABASE;
    }

    /* Check current version */
    int current_version = dnac_db_get_version(db);

    /* Apply schema if new database */
    if (current_version < 1) {
        rc = sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "DB init error: %s", err_msg);
            sqlite3_free(err_msg);
            return DNAC_ERROR_DATABASE;
        }
        dnac_db_set_version(db, 1);
    }

    /* Gap 22 Fix (v0.6.0): Add wallet config table for owner salt */
    if (current_version < 2) {
        const char *migration_v2 =
            "CREATE TABLE IF NOT EXISTS dnac_wallet_config ("
            "    key TEXT PRIMARY KEY,"
            "    value BLOB NOT NULL"
            ");";
        rc = sqlite3_exec(db, migration_v2, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "DB migration v2 error: %s", err_msg);
            sqlite3_free(err_msg);
            return DNAC_ERROR_DATABASE;
        }
        dnac_db_set_version(db, 2);
    }

    /* P0-4 (v0.7.0): Add ledger confirmation tracking columns */
    if (current_version < 3) {
        /* Execute each ALTER separately (SQLite doesn't support multi-statement ALTER) */
        const char *alters[] = {
            "ALTER TABLE dnac_utxos ADD COLUMN ledger_seq INTEGER;",
            "ALTER TABLE dnac_utxos ADD COLUMN ledger_epoch INTEGER;",
            "ALTER TABLE dnac_transactions ADD COLUMN ledger_seq INTEGER;",
            "ALTER TABLE dnac_transactions ADD COLUMN ledger_epoch INTEGER;",
            NULL
        };

        for (int i = 0; alters[i] != NULL; i++) {
            rc = sqlite3_exec(db, alters[i], NULL, NULL, &err_msg);
            if (rc != SQLITE_OK) {
                /* Column might already exist - ignore "duplicate column" errors */
                if (strstr(err_msg, "duplicate column") == NULL) {
                    QGP_LOG_ERROR(LOG_TAG, "DB migration v3 error: %s", err_msg);
                    sqlite3_free(err_msg);
                    return DNAC_ERROR_DATABASE;
                }
                sqlite3_free(err_msg);
                err_msg = NULL;
            }
        }
        dnac_db_set_version(db, 3);
    }

    /* v4: Recreate dnac_transactions with nullable raw_tx
     * (remote history entries have no raw TX data — cache only) */
    if (current_version < 4) {
        sqlite3_exec(db, "DROP TABLE IF EXISTS dnac_transactions;",
                     NULL, NULL, NULL);
        const char *recreate =
            "CREATE TABLE IF NOT EXISTS dnac_transactions ("
            "    id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
            "    tx_hash             BLOB NOT NULL UNIQUE,"
            "    raw_tx              BLOB,"
            "    type                INTEGER NOT NULL,"
            "    counterparty_fp     TEXT,"
            "    created_at          INTEGER NOT NULL,"
            "    confirmed_at        INTEGER,"
            "    amount_in           INTEGER NOT NULL DEFAULT 0,"
            "    amount_out          INTEGER NOT NULL DEFAULT 0,"
            "    amount_fee          INTEGER NOT NULL DEFAULT 0,"
            "    ledger_seq          INTEGER,"
            "    ledger_epoch        INTEGER"
            ");";
        sqlite3_exec(db, recreate, NULL, NULL, NULL);
        dnac_db_set_version(db, 4);
    }

    /* v5: Multi-token support — token_id column on UTXOs + token registry table */
    if (current_version < 5) {
        const char *stmts[] = {
            "ALTER TABLE dnac_utxos ADD COLUMN token_id BLOB NOT NULL DEFAULT x'"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "';",
            "CREATE TABLE IF NOT EXISTS dnac_tokens ("
            "  token_id BLOB PRIMARY KEY,"
            "  name TEXT NOT NULL,"
            "  symbol TEXT NOT NULL,"
            "  decimals INTEGER NOT NULL DEFAULT 8,"
            "  supply INTEGER NOT NULL,"
            "  creator_fp TEXT NOT NULL,"
            "  flags INTEGER NOT NULL DEFAULT 0,"
            "  block_height INTEGER NOT NULL DEFAULT 0,"
            "  timestamp INTEGER NOT NULL DEFAULT 0"
            ");",
            "CREATE INDEX IF NOT EXISTS idx_utxos_token ON dnac_utxos(token_id);",
            NULL
        };

        for (int i = 0; stmts[i] != NULL; i++) {
            rc = sqlite3_exec(db, stmts[i], NULL, NULL, &err_msg);
            if (rc != SQLITE_OK) {
                /* Column might already exist from partial migration */
                if (strstr(err_msg, "duplicate column") == NULL) {
                    QGP_LOG_ERROR(LOG_TAG, "DB migration v5 error: %s", err_msg);
                    sqlite3_free(err_msg);
                    return DNAC_ERROR_DATABASE;
                }
                sqlite3_free(err_msg);
                err_msg = NULL;
            }
        }
        dnac_db_set_version(db, 5);
    }

    /* v6 (Fix #4 B): pending broadcast persistence — lets dnac_send reuse
     * the same TX across retries instead of rebuilding with a fresh
     * timestamp (which produces a different tx_hash and hits DOUBLE_SPEND
     * on the committed nullifiers). The four new columns are additive;
     * existing rows with NULL values are treated as legacy pending_spends
     * entries and are invisible to the new find_active_broadcast lookup. */
    if (current_version < 6) {
        static const char *const v6_stmts[] = {
            "ALTER TABLE dnac_pending_spends ADD COLUMN tx_data BLOB;",
            "ALTER TABLE dnac_pending_spends ADD COLUMN recipient_fp TEXT;",
            "ALTER TABLE dnac_pending_spends ADD COLUMN amount INTEGER;",
            "ALTER TABLE dnac_pending_spends ADD COLUMN token_id BLOB;",
            "CREATE INDEX IF NOT EXISTS idx_pending_recipient "
            "ON dnac_pending_spends(recipient_fp, status);",
            NULL
        };

        for (int i = 0; v6_stmts[i] != NULL; i++) {
            sqlite3_stmt *mstmt = NULL;
            rc = sqlite3_prepare_v2(db, v6_stmts[i], -1, &mstmt, NULL);
            if (rc == SQLITE_OK) {
                rc = sqlite3_step(mstmt);
                sqlite3_finalize(mstmt);
                if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
                    const char *emsg = sqlite3_errmsg(db);
                    /* Idempotent — ignore duplicate column on re-run. */
                    if (emsg && strstr(emsg, "duplicate column") == NULL) {
                        QGP_LOG_ERROR(LOG_TAG, "DB migration v6 step error: %s", emsg);
                        return DNAC_ERROR_DATABASE;
                    }
                }
            } else {
                const char *emsg = sqlite3_errmsg(db);
                if (emsg && strstr(emsg, "duplicate column") == NULL) {
                    QGP_LOG_ERROR(LOG_TAG, "DB migration v6 prepare error: %s", emsg);
                    return DNAC_ERROR_DATABASE;
                }
            }
        }
        dnac_db_set_version(db, 6);
    }

    return DNAC_SUCCESS;
}

static int dnac_db_get_version(sqlite3 *db) {
    const char *sql = "SELECT MAX(version) FROM dnac_schema_version";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    return version;
}

static int dnac_db_set_version(sqlite3 *db, int version) {
    const char *sql =
        "INSERT INTO dnac_schema_version (version, applied_at) "
        "VALUES (?, strftime('%s','now'))";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_int(stmt, 1, version);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_store_utxo(sqlite3 *db, const dnac_utxo_t *utxo) {
    if (!db || !utxo) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT INTO dnac_utxos "
        "(tx_hash, output_index, amount, nullifier, owner_fingerprint, status, received_at, token_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, utxo->tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, utxo->output_index);
    sqlite3_bind_int64(stmt, 3, utxo->amount);
    sqlite3_bind_blob(stmt, 4, utxo->nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, utxo->owner_fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, utxo->status);
    sqlite3_bind_int64(stmt, 7, utxo->received_at);
    sqlite3_bind_blob(stmt, 8, utxo->token_id, DNAC_TOKEN_ID_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_unspent_utxos(sqlite3 *db,
                              const char *owner_fp,
                              dnac_utxo_t **utxos_out,
                              int *count_out) {
    if (!db || !owner_fp || !utxos_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *utxos_out = NULL;
    *count_out = 0;

    /* First count */
    const char *count_sql =
        "SELECT COUNT(*) FROM dnac_utxos WHERE owner_fingerprint = ? AND status = 0";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_text(stmt, 1, owner_fp, -1, SQLITE_STATIC);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (count == 0) return DNAC_SUCCESS;

    /* Allocate and fetch */
    dnac_utxo_t *utxos = calloc(count, sizeof(dnac_utxo_t));
    if (!utxos) return DNAC_ERROR_OUT_OF_MEMORY;

    const char *select_sql =
        "SELECT tx_hash, output_index, amount, nullifier, owner_fingerprint, "
        "status, received_at, spent_at, token_id "
        "FROM dnac_utxos WHERE owner_fingerprint = ? AND status = 0 "
        "ORDER BY amount ASC";

    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(utxos);
        return DNAC_ERROR_DATABASE;
    }

    sqlite3_bind_text(stmt, 1, owner_fp, -1, SQLITE_STATIC);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        memcpy(utxos[i].tx_hash, sqlite3_column_blob(stmt, 0), DNAC_TX_HASH_SIZE);
        utxos[i].output_index = sqlite3_column_int(stmt, 1);
        utxos[i].amount = sqlite3_column_int64(stmt, 2);
        memcpy(utxos[i].nullifier, sqlite3_column_blob(stmt, 3), DNAC_NULLIFIER_SIZE);
        strncpy(utxos[i].owner_fingerprint,
                (const char*)sqlite3_column_text(stmt, 4),
                DNAC_FINGERPRINT_SIZE - 1);
        utxos[i].status = sqlite3_column_int(stmt, 5);
        utxos[i].received_at = sqlite3_column_int64(stmt, 6);
        utxos[i].spent_at = sqlite3_column_int64(stmt, 7);
        const void *tid = sqlite3_column_blob(stmt, 8);
        if (tid && sqlite3_column_bytes(stmt, 8) == DNAC_TOKEN_ID_SIZE) {
            memcpy(utxos[i].token_id, tid, DNAC_TOKEN_ID_SIZE);
        }
        i++;
    }
    sqlite3_finalize(stmt);

    *utxos_out = utxos;
    *count_out = i;
    return DNAC_SUCCESS;
}

int dnac_db_mark_utxo_spent(sqlite3 *db,
                            const uint8_t *nullifier,
                            const uint8_t *spent_in_tx) {
    if (!db || !nullifier) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "UPDATE dnac_utxos SET status = 2, spent_at = strftime('%s','now'), "
        "spent_in_tx = ? WHERE nullifier = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    if (spent_in_tx) {
        sqlite3_bind_blob(stmt, 1, spent_in_tx, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 1);
    }
    sqlite3_bind_blob(stmt, 2, nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

/* ============================================================================
 * Transaction Storage Functions
 * ========================================================================== */

int dnac_db_store_transaction(sqlite3 *db,
                               const uint8_t *tx_hash,
                               const uint8_t *raw_tx,
                               size_t raw_tx_len,
                               dnac_tx_type_t type,
                               const char *counterparty_fp,
                               uint64_t amount_in,
                               uint64_t amount_out,
                               uint64_t amount_fee) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT OR REPLACE INTO dnac_transactions "
        "(tx_hash, raw_tx, type, counterparty_fp, created_at, "
        "amount_in, amount_out, amount_fee) "
        "VALUES (?, ?, ?, ?, strftime('%s','now'), ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    if (raw_tx && raw_tx_len > 0)
        sqlite3_bind_blob(stmt, 2, raw_tx, (int)raw_tx_len, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 2);
    sqlite3_bind_int(stmt, 3, type);
    if (counterparty_fp) {
        sqlite3_bind_text(stmt, 4, counterparty_fp, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 4);
    }
    sqlite3_bind_int64(stmt, 5, amount_in);
    sqlite3_bind_int64(stmt, 6, amount_out);
    sqlite3_bind_int64(stmt, 7, amount_fee);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_transaction(sqlite3 *db,
                             const uint8_t *tx_hash,
                             uint8_t **raw_tx_out,
                             size_t *raw_tx_len_out) {
    if (!db || !tx_hash || !raw_tx_out || !raw_tx_len_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *raw_tx_out = NULL;
    *raw_tx_len_out = 0;

    const char *sql = "SELECT raw_tx FROM dnac_transactions WHERE tx_hash = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    int blob_len = sqlite3_column_bytes(stmt, 0);
    const void *blob = sqlite3_column_blob(stmt, 0);

    uint8_t *raw_tx = malloc(blob_len);
    if (!raw_tx) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    memcpy(raw_tx, blob, blob_len);
    sqlite3_finalize(stmt);

    *raw_tx_out = raw_tx;
    *raw_tx_len_out = blob_len;
    return DNAC_SUCCESS;
}

int dnac_db_confirm_transaction(sqlite3 *db, const uint8_t *tx_hash) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "UPDATE dnac_transactions SET confirmed_at = strftime('%s','now') "
        "WHERE tx_hash = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_transactions(sqlite3 *db,
                              dnac_tx_history_t **history_out,
                              int *count_out,
                              int limit) {
    if (!db || !history_out || !count_out) return DNAC_ERROR_INVALID_PARAM;

    *history_out = NULL;
    *count_out = 0;

    /* Count first */
    const char *count_sql = "SELECT COUNT(*) FROM dnac_transactions";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    int total = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        total = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (total == 0) return DNAC_SUCCESS;

    int fetch_count = (limit > 0 && limit < total) ? limit : total;

    dnac_tx_history_t *history = calloc(fetch_count, sizeof(dnac_tx_history_t));
    if (!history) return DNAC_ERROR_OUT_OF_MEMORY;

    const char *select_sql =
        "SELECT tx_hash, type, counterparty_fp, "
        "amount_in, amount_out, amount_fee, created_at "
        "FROM dnac_transactions ORDER BY created_at DESC LIMIT ?";

    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(history);
        return DNAC_ERROR_DATABASE;
    }

    sqlite3_bind_int(stmt, 1, fetch_count);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < fetch_count) {
        memcpy(history[i].tx_hash, sqlite3_column_blob(stmt, 0), DNAC_TX_HASH_SIZE);
        history[i].type = sqlite3_column_int(stmt, 1);

        const char *cp = (const char*)sqlite3_column_text(stmt, 2);
        if (cp) {
            strncpy(history[i].counterparty, cp, DNAC_FINGERPRINT_SIZE - 1);
        }

        uint64_t amount_in = sqlite3_column_int64(stmt, 3);
        uint64_t amount_out = sqlite3_column_int64(stmt, 4);
        history[i].fee = sqlite3_column_int64(stmt, 5);
        history[i].amount_delta = (int64_t)amount_in - (int64_t)amount_out;
        history[i].timestamp = sqlite3_column_int64(stmt, 6);

        i++;
    }
    sqlite3_finalize(stmt);

    *history_out = history;
    *count_out = i;
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Pending Spend Functions
 * ========================================================================== */

int dnac_db_store_pending_spend(sqlite3 *db,
                                 const uint8_t *tx_hash,
                                 const uint8_t *nullifier,
                                 int witnesses_needed,
                                 uint64_t expires_at) {
    if (!db || !tx_hash || !nullifier) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT INTO dnac_pending_spends "
        "(tx_hash, nullifier, witnesses_needed, witnesses_received, "
        "created_at, expires_at, status) "
        "VALUES (?, ?, ?, 0, strftime('%s','now'), ?, 0)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, witnesses_needed);
    sqlite3_bind_int64(stmt, 4, expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_update_pending_witness(sqlite3 *db,
                                   const uint8_t *tx_hash,
                                   const uint8_t *witness_sig,
                                   size_t witness_sig_len) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    /* Get current witness data */
    const char *select_sql =
        "SELECT witness_signatures, witnesses_received FROM dnac_pending_spends "
        "WHERE tx_hash = ? AND status = 0";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    int current_len = sqlite3_column_bytes(stmt, 0);
    const void *current_sigs = sqlite3_column_blob(stmt, 0);
    int witnesses_received = sqlite3_column_int(stmt, 1);

    /* Append new signature */
    size_t new_len = current_len + witness_sig_len;
    uint8_t *new_sigs = malloc(new_len);
    if (!new_sigs) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    if (current_len > 0 && current_sigs) {
        memcpy(new_sigs, current_sigs, current_len);
    }
    if (witness_sig && witness_sig_len > 0) {
        memcpy(new_sigs + current_len, witness_sig, witness_sig_len);
    }
    sqlite3_finalize(stmt);

    /* Update record */
    const char *update_sql =
        "UPDATE dnac_pending_spends SET "
        "witness_signatures = ?, witnesses_received = ? "
        "WHERE tx_hash = ? AND status = 0";

    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(new_sigs);
        return DNAC_ERROR_DATABASE;
    }

    sqlite3_bind_blob(stmt, 1, new_sigs, (int)new_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, witnesses_received + 1);
    sqlite3_bind_blob(stmt, 3, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(new_sigs);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_pending_spend(sqlite3 *db,
                               const uint8_t *tx_hash,
                               int *witnesses_received,
                               int *witnesses_needed,
                               uint8_t **witness_sigs,
                               size_t *witness_sigs_len) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "SELECT witnesses_received, witnesses_needed, witness_signatures "
        "FROM dnac_pending_spends WHERE tx_hash = ? AND status = 0";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    if (witnesses_received) *witnesses_received = sqlite3_column_int(stmt, 0);
    if (witnesses_needed) *witnesses_needed = sqlite3_column_int(stmt, 1);

    if (witness_sigs && witness_sigs_len) {
        int len = sqlite3_column_bytes(stmt, 2);
        const void *blob = sqlite3_column_blob(stmt, 2);

        if (len > 0 && blob) {
            *witness_sigs = malloc(len);
            if (*witness_sigs) {
                memcpy(*witness_sigs, blob, len);
                *witness_sigs_len = len;
            }
        } else {
            *witness_sigs = NULL;
            *witness_sigs_len = 0;
        }
    }

    sqlite3_finalize(stmt);
    return DNAC_SUCCESS;
}

int dnac_db_complete_pending_spend(sqlite3 *db, const uint8_t *tx_hash) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "UPDATE dnac_pending_spends SET status = ? WHERE tx_hash = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_int(stmt, 1, DNAC_PENDING_STATUS_COMPLETE);
    sqlite3_bind_blob(stmt, 2, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_expire_pending_spends(sqlite3 *db) {
    if (!db) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "UPDATE dnac_pending_spends SET status = ? "
        "WHERE status = 0 AND expires_at < strftime('%s','now')";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_int(stmt, 1, DNAC_PENDING_STATUS_EXPIRED);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

/* ─── Pending broadcast persistence (Fix #4 B) ─────────────────────── */

/* Persist the full serialized TX alongside the pending_spend record so a
 * retry of dnac_send can re-broadcast the exact same tx_hash (and thus
 * hit server-side idempotency via dnac_spend_replay) instead of rebuilding
 * a fresh TX that would collide on nullifiers. */
int dnac_db_store_pending_broadcast(sqlite3 *db,
                                     const uint8_t *tx_hash,
                                     const uint8_t *tx_data, size_t tx_data_len,
                                     const char *recipient_fp,
                                     uint64_t amount,
                                     const uint8_t token_id[32],
                                     uint64_t expires_at) {
    if (!db || !tx_hash || !tx_data || tx_data_len == 0 || !recipient_fp)
        return DNAC_ERROR_INVALID_PARAM;

    /* Update existing row (inserted by dnac_db_store_pending_spend earlier
     * in the same flow) with the broadcast-retry payload. Matches by
     * tx_hash and status=ACTIVE to avoid stomping completed/expired rows. */
    const char *sql =
        "UPDATE dnac_pending_spends SET "
        "    tx_data = ?, recipient_fp = ?, amount = ?, token_id = ?, "
        "    expires_at = ? "
        "WHERE tx_hash = ? AND status = 0";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_data, (int)tx_data_len, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, recipient_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)amount);
    if (token_id) {
        sqlite3_bind_blob(stmt, 4, token_id, 32, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 4);
    }
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)expires_at);
    sqlite3_bind_blob(stmt, 6, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

/* Look up an active (non-expired, status=ACTIVE) pending broadcast matching
 * (recipient_fp, amount, token_id). Returns DNAC_SUCCESS on hit with
 * tx_hash_out + tx_data_out populated (caller frees *tx_data_out), or
 * DNAC_ERROR_NOT_FOUND otherwise. */
int dnac_db_find_active_broadcast(sqlite3 *db,
                                    const char *recipient_fp,
                                    uint64_t amount,
                                    const uint8_t token_id[32],
                                    uint8_t *tx_hash_out,
                                    uint8_t **tx_data_out,
                                    size_t *tx_data_len_out) {
    if (!db || !recipient_fp || !tx_hash_out || !tx_data_out || !tx_data_len_out)
        return DNAC_ERROR_INVALID_PARAM;

    *tx_data_out = NULL;
    *tx_data_len_out = 0;

    /* Match on recipient + amount + token_id with token_id comparison
     * robust to NULL (legacy rows pre-v6). expires_at must still be in
     * the future so we don't reuse stale TXes whose nullifiers may have
     * been republished on chain. */
    const char *sql =
        "SELECT tx_hash, tx_data FROM dnac_pending_spends "
        "WHERE recipient_fp = ? AND amount = ? "
        "  AND (token_id = ? OR (token_id IS NULL AND ? IS NULL)) "
        "  AND status = 0 "
        "  AND expires_at > strftime('%s','now') "
        "  AND tx_data IS NOT NULL "
        "ORDER BY created_at DESC LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_text(stmt, 1, recipient_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)amount);
    if (token_id) {
        sqlite3_bind_blob(stmt, 3, token_id, 32, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 4, token_id, 32, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_null(stmt, 4);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    int hash_bytes = sqlite3_column_bytes(stmt, 0);
    const void *hash_blob = sqlite3_column_blob(stmt, 0);
    if (hash_bytes != DNAC_TX_HASH_SIZE || !hash_blob) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_DATABASE;
    }
    memcpy(tx_hash_out, hash_blob, DNAC_TX_HASH_SIZE);

    int data_bytes = sqlite3_column_bytes(stmt, 1);
    const void *data_blob = sqlite3_column_blob(stmt, 1);
    if (data_bytes <= 0 || !data_blob) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_DATABASE;
    }
    *tx_data_out = malloc((size_t)data_bytes);
    if (!*tx_data_out) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*tx_data_out, data_blob, (size_t)data_bytes);
    *tx_data_len_out = (size_t)data_bytes;

    sqlite3_finalize(stmt);
    return DNAC_SUCCESS;
}

int dnac_db_clear_utxos(sqlite3 *db, const char *owner_fp) {
    if (!db || !owner_fp) return DNAC_ERROR_INVALID_PARAM;

    const char *sql = "DELETE FROM dnac_utxos WHERE owner_fingerprint = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_text(stmt, 1, owner_fp, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_clear_transactions(sqlite3 *db) {
    if (!db) return DNAC_ERROR_INVALID_PARAM;

    const char *sql = "DELETE FROM dnac_transactions";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

/* ============================================================================
 * Wallet Config Functions (Gap 22: v0.6.0)
 * ========================================================================== */

int dnac_db_get_owner_salt(sqlite3 *db, uint8_t *salt_out) {
    if (!db || !salt_out) return DNAC_ERROR_INVALID_PARAM;

    const char *sql = "SELECT value FROM dnac_wallet_config WHERE key = 'owner_salt'";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_size = sqlite3_column_bytes(stmt, 0);

    if (!blob || blob_size != 32) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_DATABASE;
    }

    memcpy(salt_out, blob, 32);
    sqlite3_finalize(stmt);
    return DNAC_SUCCESS;
}

int dnac_db_set_owner_salt(sqlite3 *db, const uint8_t *salt) {
    if (!db || !salt) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT OR REPLACE INTO dnac_wallet_config (key, value) VALUES ('owner_salt', ?)";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, salt, 32, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_stored_chain_id(sqlite3 *db, uint8_t *chain_id_out) {
    if (!db || !chain_id_out) return DNAC_ERROR_INVALID_PARAM;

    const char *sql = "SELECT value FROM dnac_wallet_config WHERE key = 'chain_id'";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_size = sqlite3_column_bytes(stmt, 0);

    if (!blob || blob_size != 32) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_DATABASE;
    }

    memcpy(chain_id_out, blob, 32);
    sqlite3_finalize(stmt);
    return DNAC_SUCCESS;
}

int dnac_db_set_stored_chain_id(sqlite3 *db, const uint8_t *chain_id) {
    if (!db || !chain_id) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT OR REPLACE INTO dnac_wallet_config (key, value) VALUES ('chain_id', ?)";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, chain_id, 32, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

/* ============================================================================
 * P0-4 (v0.7.0): Confirmation Tracking Functions
 * ========================================================================== */

int dnac_db_update_tx_confirmation(sqlite3 *db, const uint8_t *tx_hash,
                                    uint64_t ledger_seq, uint64_t ledger_epoch) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "UPDATE dnac_transactions SET ledger_seq = ?, ledger_epoch = ?, "
        "confirmed_at = COALESCE(confirmed_at, strftime('%s','now')) "
        "WHERE tx_hash = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_int64(stmt, 1, (int64_t)ledger_seq);
    sqlite3_bind_int64(stmt, 2, (int64_t)ledger_epoch);
    sqlite3_bind_blob(stmt, 3, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_tx_confirmation(sqlite3 *db, const uint8_t *tx_hash,
                                 uint64_t *ledger_seq_out, uint64_t *ledger_epoch_out) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "SELECT ledger_seq, ledger_epoch FROM dnac_transactions WHERE tx_hash = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Check for NULL values (unconfirmed TX) */
    if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;  /* TX exists but not confirmed on ledger */
    }

    if (ledger_seq_out) *ledger_seq_out = (uint64_t)sqlite3_column_int64(stmt, 0);
    if (ledger_epoch_out) *ledger_epoch_out = (uint64_t)sqlite3_column_int64(stmt, 1);

    sqlite3_finalize(stmt);
    return DNAC_SUCCESS;
}

int dnac_db_update_utxo_confirmation(sqlite3 *db, const uint8_t *tx_hash,
                                      uint32_t output_index,
                                      uint64_t ledger_seq, uint64_t ledger_epoch) {
    if (!db || !tx_hash) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "UPDATE dnac_utxos SET ledger_seq = ?, ledger_epoch = ? "
        "WHERE tx_hash = ? AND output_index = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_int64(stmt, 1, (int64_t)ledger_seq);
    sqlite3_bind_int64(stmt, 2, (int64_t)ledger_epoch);
    sqlite3_bind_blob(stmt, 3, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, (int)output_index);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

/* ============================================================================
 * Token Registry Functions
 * ========================================================================== */

int dnac_db_store_token(sqlite3 *db, const dnac_token_t *token) {
    if (!db || !token) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT OR REPLACE INTO dnac_tokens "
        "(token_id, name, symbol, decimals, supply, creator_fp, flags, block_height, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, token->token_id, DNAC_TOKEN_ID_SIZE, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, token->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, token->symbol, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, token->decimals);
    sqlite3_bind_int64(stmt, 5, (int64_t)token->initial_supply);
    sqlite3_bind_text(stmt, 6, token->creator_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, token->flags);
    sqlite3_bind_int64(stmt, 8, (int64_t)token->block_height);
    sqlite3_bind_int64(stmt, 9, (int64_t)token->timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? DNAC_SUCCESS : DNAC_ERROR_DATABASE;
}

int dnac_db_get_token(sqlite3 *db, const uint8_t *token_id, dnac_token_t *out) {
    if (!db || !token_id || !out) return DNAC_ERROR_INVALID_PARAM;

    memset(out, 0, sizeof(*out));

    const char *sql =
        "SELECT token_id, name, symbol, decimals, supply, creator_fp, "
        "flags, block_height, timestamp "
        "FROM dnac_tokens WHERE token_id = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, token_id, DNAC_TOKEN_ID_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return DNAC_ERROR_NOT_FOUND;
    }

    const void *tid = sqlite3_column_blob(stmt, 0);
    if (tid) memcpy(out->token_id, tid, DNAC_TOKEN_ID_SIZE);

    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    if (name) strncpy(out->name, name, sizeof(out->name) - 1);

    const char *symbol = (const char *)sqlite3_column_text(stmt, 2);
    if (symbol) strncpy(out->symbol, symbol, sizeof(out->symbol) - 1);

    out->decimals = (uint8_t)sqlite3_column_int(stmt, 3);
    out->initial_supply = (uint64_t)sqlite3_column_int64(stmt, 4);

    const char *creator = (const char *)sqlite3_column_text(stmt, 5);
    if (creator) strncpy(out->creator_fp, creator, DNAC_FINGERPRINT_SIZE - 1);

    out->flags = (uint8_t)sqlite3_column_int(stmt, 6);
    out->block_height = (uint64_t)sqlite3_column_int64(stmt, 7);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 8);

    sqlite3_finalize(stmt);
    return DNAC_SUCCESS;
}

int dnac_db_list_tokens(sqlite3 *db, dnac_token_t *out, int max, int *count) {
    if (!db || !out || !count || max <= 0) return DNAC_ERROR_INVALID_PARAM;

    *count = 0;

    const char *sql =
        "SELECT token_id, name, symbol, decimals, supply, creator_fp, "
        "flags, block_height, timestamp "
        "FROM dnac_tokens ORDER BY name LIMIT ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_int(stmt, 1, max);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < max) {
        memset(&out[i], 0, sizeof(out[i]));

        const void *tid = sqlite3_column_blob(stmt, 0);
        if (tid) memcpy(out[i].token_id, tid, DNAC_TOKEN_ID_SIZE);

        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        if (name) strncpy(out[i].name, name, sizeof(out[i].name) - 1);

        const char *symbol = (const char *)sqlite3_column_text(stmt, 2);
        if (symbol) strncpy(out[i].symbol, symbol, sizeof(out[i].symbol) - 1);

        out[i].decimals = (uint8_t)sqlite3_column_int(stmt, 3);
        out[i].initial_supply = (uint64_t)sqlite3_column_int64(stmt, 4);

        const char *creator = (const char *)sqlite3_column_text(stmt, 5);
        if (creator) strncpy(out[i].creator_fp, creator, DNAC_FINGERPRINT_SIZE - 1);

        out[i].flags = (uint8_t)sqlite3_column_int(stmt, 6);
        out[i].block_height = (uint64_t)sqlite3_column_int64(stmt, 7);
        out[i].timestamp = (uint64_t)sqlite3_column_int64(stmt, 8);

        i++;
    }
    sqlite3_finalize(stmt);

    *count = i;
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Public API Wrappers (using dnac_context)
 * ========================================================================== */

/* Public API wrappers using dnac_context for database access. */

int dnac_get_history(dnac_context_t *ctx,
                     dnac_tx_history_t **history,
                     int *count) {
    if (!ctx || !history || !count) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    return dnac_db_get_transactions(db, history, count, 0);
}

void dnac_free_history(dnac_tx_history_t *history, int count) {
    (void)count;
    free(history);
}

/* ============================================================================
 * P0-4 (v0.7.0): Confirmation API
 * ========================================================================== */

int dnac_get_confirmation(dnac_context_t *ctx,
                          const uint8_t *tx_hash,
                          dnac_confirmation_t *confirmation_out) {
    if (!ctx || !tx_hash || !confirmation_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    memset(confirmation_out, 0, sizeof(*confirmation_out));

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    /* Get TX's ledger confirmation data */
    uint64_t ledger_seq = 0;
    uint64_t ledger_epoch = 0;
    int rc = dnac_db_get_tx_confirmation(db, tx_hash, &ledger_seq, &ledger_epoch);

    if (rc == DNAC_ERROR_NOT_FOUND) {
        /* TX exists but not confirmed on ledger yet */
        confirmation_out->is_confirmed = false;
        confirmation_out->is_final = false;
        return DNAC_SUCCESS;
    } else if (rc != DNAC_SUCCESS) {
        return rc;
    }

    confirmation_out->ledger_sequence = ledger_seq;
    confirmation_out->ledger_epoch = ledger_epoch;
    confirmation_out->is_confirmed = true;

    /* Get current ledger state from witnesses
     * For now, use local estimate. Full implementation would query witnesses.
     */
    uint64_t current_epoch = (uint64_t)(time(NULL) / DNAC_EPOCH_DURATION_SEC);

    /* Query local DB for latest known TX sequence */
    const char *sql = "SELECT MAX(ledger_seq) FROM dnac_transactions WHERE ledger_seq IS NOT NULL";
    sqlite3_stmt *stmt = NULL;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            confirmation_out->current_sequence = (uint64_t)sqlite3_column_int64(stmt, 0);
        }
    }
    if (stmt) sqlite3_finalize(stmt);

    confirmation_out->current_epoch = current_epoch;

    /* Calculate depths */
    if (confirmation_out->current_sequence >= ledger_seq) {
        confirmation_out->sequence_depth = confirmation_out->current_sequence - ledger_seq;
    }
    if (current_epoch >= ledger_epoch) {
        confirmation_out->epoch_depth = current_epoch - ledger_epoch;
    }

    /* A TX is considered final when it has survived at least 2 epoch boundaries */
    confirmation_out->is_final = (confirmation_out->epoch_depth >= 2);

    return DNAC_SUCCESS;
}
