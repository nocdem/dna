/**
 * Wallet Balance Cache Implementation
 * GLOBAL SQLite cache for wallet balances (stale-while-revalidate)
 *
 * Follows the same pattern as feed_cache.c:
 * - Global database at <data_dir>/wallet_cache.db
 * - Thread-safe via SQLITE_OPEN_FULLMUTEX
 * - Upsert on save, instant read on get
 *
 * @file wallet_cache.c
 * @date 2026-02-23
 */

#include "wallet_cache.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#define LOG_TAG "WALLET_CACHE"

static sqlite3 *g_db = NULL;

/* ── Internal helpers ──────────────────────────────────────────────── */

static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }
    snprintf(path_out, path_size, "%s/wallet_cache.db", data_dir);
    return 0;
}

static int create_schema(void) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS wallet_balances ("
        "    wallet_index INTEGER NOT NULL,"
        "    token        TEXT NOT NULL,"
        "    network      TEXT NOT NULL,"
        "    balance      TEXT NOT NULL,"
        "    cached_at    INTEGER NOT NULL,"
        "    PRIMARY KEY(wallet_index, token, network)"
        ");";

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create schema: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

int wallet_cache_init(void) {
    if (g_db) {
        return 0; /* Already initialized */
    }

    char db_path[512];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    int rc = sqlite3_open_v2(db_path, &g_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s",
                      g_db ? sqlite3_errmsg(g_db) : "unknown");
        if (g_db) {
            sqlite3_close(g_db);
            g_db = NULL;
        }
        return -1;
    }

    /* WAL mode for concurrent read/write */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    if (create_schema() != 0) {
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Wallet cache initialized: %s", db_path);
    return 0;
}

void wallet_cache_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_DEBUG(LOG_TAG, "Wallet cache closed");
    }
}

/* ── Balance operations ────────────────────────────────────────────── */

int wallet_cache_save_balances(int wallet_index,
                               const dna_balance_t *balances, int count) {
    if (!g_db || !balances || count <= 0) {
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO wallet_balances "
        "(wallet_index, token, network, balance, cached_at) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare save statement: %s",
                      sqlite3_errmsg(g_db));
        return -1;
    }

    int64_t now = (int64_t)time(NULL);
    int errors = 0;

    for (int i = 0; i < count; i++) {
        sqlite3_reset(stmt);
        sqlite3_bind_int(stmt, 1, wallet_index);
        sqlite3_bind_text(stmt, 2, balances[i].token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, balances[i].network, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, balances[i].balance, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, now);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to save balance %s/%s: %s",
                          balances[i].token, balances[i].network,
                          sqlite3_errmsg(g_db));
            errors++;
        }
    }

    sqlite3_finalize(stmt);

    if (errors == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "Saved %d balances for wallet %d", count, wallet_index);
    }

    return errors > 0 ? -1 : 0;
}

int wallet_cache_get_balances(int wallet_index,
                              dna_balance_t **balances_out, int *count_out) {
    if (!g_db || !balances_out || !count_out) {
        return -1;
    }

    *balances_out = NULL;
    *count_out = 0;

    /* First count rows */
    const char *count_sql =
        "SELECT COUNT(*) FROM wallet_balances WHERE wallet_index = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, wallet_index);
    int total = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        total = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (total <= 0) {
        return -2; /* No cached data */
    }

    /* Fetch rows */
    const char *select_sql =
        "SELECT token, network, balance FROM wallet_balances "
        "WHERE wallet_index = ? ORDER BY rowid;";
    rc = sqlite3_prepare_v2(g_db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, wallet_index);

    dna_balance_t *balances = calloc((size_t)total, sizeof(dna_balance_t));
    if (!balances) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < total) {
        const char *token   = (const char *)sqlite3_column_text(stmt, 0);
        const char *network = (const char *)sqlite3_column_text(stmt, 1);
        const char *balance = (const char *)sqlite3_column_text(stmt, 2);

        if (token)   strncpy(balances[idx].token,   token,   sizeof(balances[idx].token) - 1);
        if (network) strncpy(balances[idx].network, network, sizeof(balances[idx].network) - 1);
        if (balance) strncpy(balances[idx].balance, balance, sizeof(balances[idx].balance) - 1);
        idx++;
    }

    sqlite3_finalize(stmt);

    *balances_out = balances;
    *count_out = idx;

    QGP_LOG_DEBUG(LOG_TAG, "Loaded %d cached balances for wallet %d", idx, wallet_index);
    return 0;
}

int wallet_cache_clear(void) {
    if (!g_db) {
        return -1;
    }

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, "DELETE FROM wallet_balances;",
                          NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to clear cache: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Wallet cache cleared");
    return 0;
}
