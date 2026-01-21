/**
 * @file nullifier.c
 * @brief Nullifier database operations for witness server
 *
 * Uses SQLite to track spent nullifiers for double-spend prevention.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/witness.h"
#include <sqlite3.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_DB"

static sqlite3 *nullifier_db = NULL;

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
        "CREATE TABLE IF NOT EXISTS nullifiers ("
        "  nullifier BLOB PRIMARY KEY,"
        "  tx_hash BLOB NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  replicated INTEGER DEFAULT 0"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_nullifiers_replicated ON nullifiers(replicated);";

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
