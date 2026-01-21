/**
 * @file db.c
 * @brief SQLite database operations for DNAC
 */

#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Database schema version */
#define DNAC_DB_VERSION 1

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
    "    raw_tx              BLOB NOT NULL,"
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
        fprintf(stderr, "DNAC DB version table error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return DNAC_ERROR_DATABASE;
    }

    /* Check current version */
    int current_version = dnac_db_get_version(db);

    /* Apply schema if new database */
    if (current_version < 1) {
        rc = sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "DNAC DB init error: %s\n", err_msg);
            sqlite3_free(err_msg);
            return DNAC_ERROR_DATABASE;
        }
        dnac_db_set_version(db, 1);
    }

    /* Future migrations would go here:
     * if (current_version < 2) { migrate_v1_to_v2(); dnac_db_set_version(db, 2); }
     */

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
        "(tx_hash, output_index, amount, nullifier, owner_fingerprint, status, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

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
        "status, received_at, spent_at "
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
    if (!db || !tx_hash || !raw_tx) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT INTO dnac_transactions "
        "(tx_hash, raw_tx, type, counterparty_fp, created_at, "
        "amount_in, amount_out, amount_fee) "
        "VALUES (?, ?, ?, ?, strftime('%s','now'), ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, raw_tx, (int)raw_tx_len, SQLITE_STATIC);
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

/* ============================================================================
 * Public API Wrappers (using dnac_context)
 * ========================================================================== */

/* Note: These require dnac_context to hold the db pointer.
 * For now, these are stubs that will be connected when context is implemented. */

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
