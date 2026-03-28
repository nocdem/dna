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

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#define LOG_TAG "WALLET_CACHE"

static sqlite3 *g_db = NULL;

#ifdef _WIN32
static CRITICAL_SECTION g_wallet_cs;
static LONG g_wallet_cs_init = 0;
static void wallet_lock(void) {
    if (InterlockedCompareExchange(&g_wallet_cs_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_wallet_cs);
    }
    EnterCriticalSection(&g_wallet_cs);
}
static void wallet_unlock(void) { LeaveCriticalSection(&g_wallet_cs); }
#else
static pthread_mutex_t g_wallet_mutex = PTHREAD_MUTEX_INITIALIZER;
static void wallet_lock(void)   { pthread_mutex_lock(&g_wallet_mutex); }
static void wallet_unlock(void) { pthread_mutex_unlock(&g_wallet_mutex); }
#endif

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
    const char *balances_sql =
        "CREATE TABLE IF NOT EXISTS wallet_balances ("
        "    wallet_index INTEGER NOT NULL,"
        "    token        TEXT NOT NULL,"
        "    network      TEXT NOT NULL,"
        "    balance      TEXT NOT NULL,"
        "    cached_at    INTEGER NOT NULL,"
        "    PRIMARY KEY(wallet_index, token, network)"
        ");";

    const char *transactions_sql =
        "CREATE TABLE IF NOT EXISTS wallet_transactions ("
        "    tx_hash       TEXT NOT NULL,"
        "    wallet_index  INTEGER NOT NULL,"
        "    network       TEXT NOT NULL,"
        "    direction     TEXT NOT NULL,"
        "    amount        TEXT NOT NULL,"
        "    token         TEXT NOT NULL,"
        "    other_address TEXT NOT NULL DEFAULT '',"
        "    timestamp     TEXT NOT NULL,"
        "    status        TEXT NOT NULL DEFAULT 'CONFIRMED',"
        "    cached_at     INTEGER NOT NULL,"
        "    PRIMARY KEY(tx_hash)"
        ");";

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, balances_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create balances schema: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    rc = sqlite3_exec(g_db, transactions_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create transactions schema: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    const char *verifications_sql =
        "CREATE TABLE IF NOT EXISTS transfer_verifications ("
        "    tx_hash      TEXT PRIMARY KEY,"
        "    chain        TEXT NOT NULL,"
        "    status       INTEGER NOT NULL DEFAULT 0,"
        "    last_checked INTEGER NOT NULL"
        ");";

    rc = sqlite3_exec(g_db, verifications_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create verifications schema: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

int wallet_cache_init(void) {
    wallet_lock();

    if (g_db) {
        wallet_unlock();
        return 0; /* Already initialized */
    }

    char db_path[512];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        wallet_unlock();
        return -1;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(db_path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s",
                      db ? sqlite3_errmsg(db) : "unknown");
        if (db) {
            sqlite3_close(db);
        }
        wallet_unlock();
        return -1;
    }

    /* WAL mode for concurrent read/write */
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    g_db = db;

    if (create_schema() != 0) {
        sqlite3_close(g_db);
        g_db = NULL;
        wallet_unlock();
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Wallet cache initialized: %s", db_path);
    wallet_unlock();
    return 0;
}

void wallet_cache_close(void) {
    wallet_lock();
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_DEBUG(LOG_TAG, "Wallet cache closed");
    }
    wallet_unlock();
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

/* ── Balance age query ─────────────────────────────────────────────── */

int wallet_cache_get_oldest_cached_at(int wallet_index, int64_t *oldest_out) {
    if (!g_db || !oldest_out) return -1;

    const char *sql =
        "SELECT MIN(cached_at) FROM wallet_balances WHERE wallet_index = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, wallet_index);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        *oldest_out = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;  /* No cached data */
}

/* ── Transaction operations ─────────────────────────────────────────── */

int wallet_cache_save_transactions(int wallet_index, const char *network,
                                    const dna_transaction_t *txs, int count) {
    if (!g_db || !txs || count <= 0 || !network) {
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO wallet_transactions "
        "(tx_hash, wallet_index, network, direction, amount, token, "
        "other_address, timestamp, status, cached_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare tx save: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    int64_t now = (int64_t)time(NULL);
    int saved = 0;

    for (int i = 0; i < count; i++) {
        if (txs[i].tx_hash[0] == '\0') continue;

        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, txs[i].tx_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, wallet_index);
        sqlite3_bind_text(stmt, 3, network, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, txs[i].direction, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, txs[i].amount, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, txs[i].token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, txs[i].other_address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, txs[i].timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, txs[i].status, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 10, now);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to save tx %s: %s",
                          txs[i].tx_hash, sqlite3_errmsg(g_db));
        } else {
            saved++;
        }
    }

    sqlite3_finalize(stmt);
    QGP_LOG_DEBUG(LOG_TAG, "Cached %d/%d transactions for wallet %d/%s",
                  saved, count, wallet_index, network);
    return 0;
}

int wallet_cache_get_transactions(int wallet_index, const char *network,
                                   dna_transaction_t **txs_out, int *count_out) {
    if (!g_db || !txs_out || !count_out || !network) {
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Count rows */
    const char *count_sql =
        "SELECT COUNT(*) FROM wallet_transactions "
        "WHERE wallet_index = ? AND network = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, wallet_index);
    sqlite3_bind_text(stmt, 2, network, -1, SQLITE_TRANSIENT);

    int total = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        total = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (total <= 0) return -2;

    /* Fetch rows ordered by timestamp descending (newest first) */
    const char *select_sql =
        "SELECT tx_hash, direction, amount, token, other_address, timestamp, status "
        "FROM wallet_transactions "
        "WHERE wallet_index = ? AND network = ? "
        "ORDER BY CAST(timestamp AS INTEGER) DESC;";
    rc = sqlite3_prepare_v2(g_db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, wallet_index);
    sqlite3_bind_text(stmt, 2, network, -1, SQLITE_TRANSIENT);

    dna_transaction_t *txs = calloc((size_t)total, sizeof(dna_transaction_t));
    if (!txs) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < total) {
        const char *hash  = (const char *)sqlite3_column_text(stmt, 0);
        const char *dir   = (const char *)sqlite3_column_text(stmt, 1);
        const char *amt   = (const char *)sqlite3_column_text(stmt, 2);
        const char *tok   = (const char *)sqlite3_column_text(stmt, 3);
        const char *other = (const char *)sqlite3_column_text(stmt, 4);
        const char *ts    = (const char *)sqlite3_column_text(stmt, 5);
        const char *stat  = (const char *)sqlite3_column_text(stmt, 6);

        if (hash)  strncpy(txs[idx].tx_hash,       hash,  sizeof(txs[idx].tx_hash) - 1);
        if (dir)   strncpy(txs[idx].direction,      dir,   sizeof(txs[idx].direction) - 1);
        if (amt)   strncpy(txs[idx].amount,         amt,   sizeof(txs[idx].amount) - 1);
        if (tok)   strncpy(txs[idx].token,          tok,   sizeof(txs[idx].token) - 1);
        if (other) strncpy(txs[idx].other_address,  other, sizeof(txs[idx].other_address) - 1);
        if (ts)    strncpy(txs[idx].timestamp,       ts,    sizeof(txs[idx].timestamp) - 1);
        if (stat)  strncpy(txs[idx].status,          stat,  sizeof(txs[idx].status) - 1);
        idx++;
    }

    sqlite3_finalize(stmt);

    *txs_out = txs;
    *count_out = idx;

    QGP_LOG_DEBUG(LOG_TAG, "Loaded %d cached transactions for wallet %d/%s",
                  idx, wallet_index, network);
    return 0;
}

/* ── Transfer verification operations ──────────────────────────────── */

int wallet_cache_get_tx_status(const char *tx_hash, int *status_out) {
    if (!g_db || !tx_hash || !status_out) return -1;

    const char *sql = "SELECT status FROM transfer_verifications WHERE tx_hash = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, tx_hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *status_out = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}

int wallet_cache_save_tx_status(const char *tx_hash, const char *chain, int status) {
    if (!g_db || !tx_hash || !chain) return -1;

    const char *sql =
        "INSERT OR REPLACE INTO transfer_verifications "
        "(tx_hash, chain, status, last_checked) VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, tx_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, chain, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, status);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int wallet_cache_clear(void) {
    if (!g_db) {
        return -1;
    }

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db,
        "DELETE FROM wallet_balances; DELETE FROM wallet_transactions; "
        "DELETE FROM transfer_verifications;",
        NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to clear cache: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Wallet cache cleared");
    return 0;
}
