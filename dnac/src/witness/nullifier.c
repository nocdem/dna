/**
 * @file nullifier.c
 * @brief Nullifier database operations for witness server
 *
 * Uses SQLite to track spent nullifiers for double-spend prevention.
 * Also manages genesis state (v0.5.0).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/witness.h"
#include "dnac/genesis.h"
#include <sqlite3.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_DB"

/* Shared database handle - used by ledger.c and utxo_tree.c */
sqlite3 *nullifier_db = NULL;

int witness_nullifier_init(const char *db_path) {
    if (nullifier_db) {
        QGP_LOG_WARN(LOG_TAG, "Nullifier DB already initialized");
        return 0;
    }

    int rc = sqlite3_open(db_path, &nullifier_db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s", sqlite3_errmsg(nullifier_db));
        return -1;
    }

    /* Create schema */
    const char *schema =
        /* Nullifier tracking (v0.1.0) */
        "CREATE TABLE IF NOT EXISTS nullifiers ("
        "  nullifier BLOB PRIMARY KEY,"
        "  tx_hash BLOB NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  replicated INTEGER DEFAULT 0"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_nullifiers_replicated ON nullifiers(replicated);"

        /* Genesis state table (v0.5.0) - only one row ever allowed */
        "CREATE TABLE IF NOT EXISTS genesis_state ("
        "  id INTEGER PRIMARY KEY CHECK (id = 1),"
        "  genesis_hash BLOB NOT NULL,"
        "  total_supply INTEGER NOT NULL,"
        "  genesis_timestamp INTEGER NOT NULL,"
        "  genesis_commitment BLOB NOT NULL"
        ");"

        /* Transaction ledger (v0.5.0) - permanent audit trail */
        "CREATE TABLE IF NOT EXISTS ledger_entries ("
        "  sequence_number INTEGER PRIMARY KEY,"
        "  tx_hash BLOB UNIQUE NOT NULL,"
        "  tx_type INTEGER NOT NULL,"
        "  nullifiers BLOB,"
        "  output_commitment BLOB,"
        "  merkle_root BLOB NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  epoch INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_ledger_tx_hash ON ledger_entries(tx_hash);"
        "CREATE INDEX IF NOT EXISTS idx_ledger_epoch ON ledger_entries(epoch);"

        /* Supply tracking (v0.5.0) - single row */
        "CREATE TABLE IF NOT EXISTS supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK (id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");"

        /* UTXO commitments (v0.5.0) - global UTXO state */
        "CREATE TABLE IF NOT EXISTS utxo_commitments ("
        "  commitment BLOB PRIMARY KEY,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  owner_commit BLOB NOT NULL,"
        "  created_epoch INTEGER NOT NULL,"
        "  spent_epoch INTEGER,"
        "  UNIQUE(tx_hash, output_index)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_utxo_owner ON utxo_commitments(owner_commit);"
        "CREATE INDEX IF NOT EXISTS idx_utxo_unspent ON utxo_commitments(spent_epoch) WHERE spent_epoch IS NULL;"

        /* Epoch roots (v0.5.0) - signed snapshots
         * v0.7.0: Added first_sequence/last_sequence for block boundaries */
        "CREATE TABLE IF NOT EXISTS epoch_roots ("
        "  epoch INTEGER PRIMARY KEY,"
        "  first_sequence INTEGER,"
        "  last_sequence INTEGER,"
        "  utxo_root BLOB NOT NULL,"
        "  ledger_root BLOB NOT NULL,"
        "  utxo_count INTEGER NOT NULL,"
        "  total_supply INTEGER NOT NULL,"
        "  timestamp INTEGER NOT NULL"
        ");"

        /* P0-3 (v0.7.0): Merkle checkpoints for proof generation */
        "CREATE TABLE IF NOT EXISTS ledger_checkpoints ("
        "  checkpoint_seq INTEGER PRIMARY KEY,"
        "  merkle_root BLOB NOT NULL"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(nullifier_db, schema, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create schema: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(nullifier_db);
        nullifier_db = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Nullifier database initialized: %s", db_path);
    return 0;
}

void witness_nullifier_shutdown(void) {
    if (nullifier_db) {
        sqlite3_close(nullifier_db);
        nullifier_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Nullifier database closed");
    }
}

/* ============================================================================
 * Transaction Wrappers (Gap 11: v0.6.0)
 * These provide atomicity for multi-nullifier commits
 * ========================================================================== */

int witness_db_begin_transaction(void) {
    if (!nullifier_db) return -1;

    char *err = NULL;
    int rc = sqlite3_exec(nullifier_db, "BEGIN TRANSACTION", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "BEGIN TRANSACTION failed: %s", err);
        sqlite3_free(err);
        return -1;
    }
    QGP_LOG_DEBUG(LOG_TAG, "BEGIN TRANSACTION");
    return 0;
}

int witness_db_commit(void) {
    if (!nullifier_db) return -1;

    char *err = NULL;
    int rc = sqlite3_exec(nullifier_db, "COMMIT", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "COMMIT failed: %s", err);
        sqlite3_free(err);
        return -1;
    }
    QGP_LOG_DEBUG(LOG_TAG, "COMMIT");
    return 0;
}

int witness_db_rollback(void) {
    if (!nullifier_db) return -1;

    char *err = NULL;
    int rc = sqlite3_exec(nullifier_db, "ROLLBACK", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        QGP_LOG_WARN(LOG_TAG, "ROLLBACK failed: %s", err);
        sqlite3_free(err);
        return -1;
    }
    QGP_LOG_DEBUG(LOG_TAG, "ROLLBACK");
    return 0;
}

bool witness_nullifier_exists(const uint8_t *nullifier) {
    if (!nullifier_db || !nullifier) return false;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT 1 FROM nullifiers WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare exists query: %s",
                      sqlite3_errmsg(nullifier_db));
        return false;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return exists;
}

int witness_nullifier_add(const uint8_t *nullifier, const uint8_t *tx_hash) {
    if (!nullifier_db || !nullifier || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "INSERT OR IGNORE INTO nullifiers (nullifier, tx_hash, timestamp, replicated) "
        "VALUES (?, ?, ?, 0)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare insert: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert nullifier: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    return 0;
}

int witness_nullifier_mark_replicated(const uint8_t *nullifier) {
    if (!nullifier_db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "UPDATE nullifiers SET replicated = 1 WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare update: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int witness_nullifier_get_unreplicated(uint8_t (*nullifiers)[64], int max_count) {
    if (!nullifier_db || !nullifiers || max_count <= 0) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT nullifier FROM nullifiers WHERE replicated = 0 LIMIT ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, max_count);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_count) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_size = sqlite3_column_bytes(stmt, 0);

        if (blob && blob_size == 64) {
            memcpy(nullifiers[count], blob, 64);
            count++;
        }
    }

    sqlite3_finalize(stmt);
    return count;
}

/* ============================================================================
 * Genesis State Functions (v0.5.0)
 * ========================================================================== */

bool witness_genesis_exists(void) {
    if (!nullifier_db) return false;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT 1 FROM genesis_state WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare genesis exists query: %s",
                      sqlite3_errmsg(nullifier_db));
        return false;
    }

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return exists;
}

int witness_genesis_set(const uint8_t *tx_hash,
                        uint64_t total_supply,
                        const uint8_t *commitment) {
    if (!nullifier_db || !tx_hash || !commitment) return -1;

    /* Check if genesis already exists */
    if (witness_genesis_exists()) {
        QGP_LOG_ERROR(LOG_TAG, "Genesis already exists - cannot set again");
        return -2;  /* Genesis already exists */
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "INSERT INTO genesis_state (id, genesis_hash, total_supply, "
        "genesis_timestamp, genesis_commitment) VALUES (1, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare genesis insert: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));
    sqlite3_bind_blob(stmt, 4, commitment, DNAC_GENESIS_COMMITMENT_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert genesis state: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Genesis state recorded: supply=%llu",
                 (unsigned long long)total_supply);
    return 0;
}

int witness_genesis_get(dnac_genesis_state_t *state_out) {
    if (!nullifier_db || !state_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT genesis_hash, total_supply, genesis_timestamp, genesis_commitment "
        "FROM genesis_state WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare genesis get query: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* No genesis found */
    }

    /* Extract data */
    const void *hash_blob = sqlite3_column_blob(stmt, 0);
    int hash_size = sqlite3_column_bytes(stmt, 0);
    if (hash_blob && hash_size == DNAC_TX_HASH_SIZE) {
        memcpy(state_out->genesis_hash, hash_blob, DNAC_TX_HASH_SIZE);
    }

    state_out->total_supply = (uint64_t)sqlite3_column_int64(stmt, 1);
    state_out->genesis_timestamp = (uint64_t)sqlite3_column_int64(stmt, 2);

    const void *commit_blob = sqlite3_column_blob(stmt, 3);
    int commit_size = sqlite3_column_bytes(stmt, 3);
    if (commit_blob && commit_size == DNAC_GENESIS_COMMITMENT_SIZE) {
        memcpy(state_out->genesis_commitment, commit_blob, DNAC_GENESIS_COMMITMENT_SIZE);
    }

    sqlite3_finalize(stmt);
    return 0;
}
