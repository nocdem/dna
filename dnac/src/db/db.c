/**
 * @file db.c
 * @brief SQLite database operations for DNAC
 */

#include "dnac/dnac.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Database schema version */
#define DNAC_DB_VERSION 1

static const char *SCHEMA_SQL =
    /* UTXOs table */
    "CREATE TABLE IF NOT EXISTS dnac_utxos ("
    "    id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    commitment          BLOB NOT NULL UNIQUE,"
    "    tx_hash             BLOB NOT NULL,"
    "    output_index        INTEGER NOT NULL,"
    "    amount              INTEGER NOT NULL,"
    "    blinding_factor     BLOB NOT NULL,"
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
    "    anchors_needed      INTEGER NOT NULL DEFAULT 2,"
    "    anchors_received    INTEGER NOT NULL DEFAULT 0,"
    "    anchor_signatures   BLOB,"
    "    created_at          INTEGER NOT NULL,"
    "    expires_at          INTEGER NOT NULL,"
    "    status              INTEGER NOT NULL DEFAULT 0"
    ");"

    /* Indexes */
    "CREATE INDEX IF NOT EXISTS idx_utxos_status ON dnac_utxos(status);"
    "CREATE INDEX IF NOT EXISTS idx_utxos_owner ON dnac_utxos(owner_fingerprint);"
    "CREATE INDEX IF NOT EXISTS idx_pending_status ON dnac_pending_spends(status);";

int dnac_db_init(sqlite3 *db) {
    if (!db) return DNAC_ERROR_INVALID_PARAM;

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "DNAC DB init error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return DNAC_ERROR_DATABASE;
    }

    return DNAC_SUCCESS;
}

int dnac_db_store_utxo(sqlite3 *db, const dnac_utxo_t *utxo) {
    if (!db || !utxo) return DNAC_ERROR_INVALID_PARAM;

    const char *sql =
        "INSERT INTO dnac_utxos "
        "(commitment, tx_hash, output_index, amount, blinding_factor, "
        "nullifier, owner_fingerprint, status, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return DNAC_ERROR_DATABASE;

    sqlite3_bind_blob(stmt, 1, utxo->commitment, DNAC_COMMITMENT_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, utxo->tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, utxo->output_index);
    sqlite3_bind_int64(stmt, 4, utxo->amount);
    sqlite3_bind_blob(stmt, 5, utxo->blinding_factor, DNAC_BLINDING_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, utxo->nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, utxo->owner_fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 8, utxo->status);
    sqlite3_bind_int64(stmt, 9, utxo->received_at);

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
        "SELECT commitment, tx_hash, output_index, amount, blinding_factor, "
        "nullifier, owner_fingerprint, status, received_at, spent_at "
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
        memcpy(utxos[i].commitment, sqlite3_column_blob(stmt, 0), DNAC_COMMITMENT_SIZE);
        memcpy(utxos[i].tx_hash, sqlite3_column_blob(stmt, 1), DNAC_TX_HASH_SIZE);
        utxos[i].output_index = sqlite3_column_int(stmt, 2);
        utxos[i].amount = sqlite3_column_int64(stmt, 3);
        memcpy(utxos[i].blinding_factor, sqlite3_column_blob(stmt, 4), DNAC_BLINDING_SIZE);
        memcpy(utxos[i].nullifier, sqlite3_column_blob(stmt, 5), DNAC_NULLIFIER_SIZE);
        strncpy(utxos[i].owner_fingerprint,
                (const char*)sqlite3_column_text(stmt, 6),
                DNAC_FINGERPRINT_SIZE - 1);
        utxos[i].status = sqlite3_column_int(stmt, 7);
        utxos[i].received_at = sqlite3_column_int64(stmt, 8);
        utxos[i].spent_at = sqlite3_column_int64(stmt, 9);
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

/* History functions */
int dnac_get_history(dnac_context_t *ctx,
                     dnac_tx_history_t **history,
                     int *count) {
    if (!ctx || !history || !count) return DNAC_ERROR_INVALID_PARAM;
    *history = NULL;
    *count = 0;
    /* TODO: Query transactions table */
    return DNAC_SUCCESS;
}

void dnac_free_history(dnac_tx_history_t *history, int count) {
    (void)count;
    free(history);
}

int dnac_debug_get_utxo(dnac_context_t *ctx,
                        const uint8_t *commitment,
                        dnac_utxo_t *utxo) {
    if (!ctx || !commitment || !utxo) return DNAC_ERROR_INVALID_PARAM;
    /* TODO: Query by commitment */
    return DNAC_ERROR_NOT_FOUND;
}
