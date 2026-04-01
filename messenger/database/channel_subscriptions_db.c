/**
 * Channel Subscriptions Database Implementation
 * Local SQLite database for channel subscriptions (per-identity)
 */

#include "channel_subscriptions_db.h"
#include "db_encryption.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#define LOG_TAG "CHANNEL_SUBS_DB"

static sqlite3 *g_db = NULL;
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Get database path */
static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }
    snprintf(path_out, path_size, "%s/db/channel_subscriptions.db", data_dir);
    return 0;
}

/* Ensure directory exists */
static int ensure_directory(const char *db_path) {
    char dir_path[512];
    strncpy(dir_path, db_path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';

    char *last_slash = strrchr(dir_path, '/');
    if (!last_slash) last_slash = strrchr(dir_path, '\\');
    if (last_slash) *last_slash = '\0';

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", dir_path);
    size_t len = strlen(tmp);
    if (len > 0 && (tmp[len - 1] == '/' || tmp[len - 1] == '\\')) {
        tmp[len - 1] = '\0';
    }

    char *p = tmp;
#ifdef _WIN32
    if (len >= 3 && tmp[1] == ':' && (tmp[2] == '\\' || tmp[2] == '/')) {
        p = tmp + 3;
    }
#else
    p = tmp + 1;
#endif

    for (; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
            struct stat st;
            if (stat(tmp, &st) != 0) {
                if (mkdir(tmp, 0700) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s", tmp);
                    return -1;
                }
            }
            *p = sep;
        }
    }

    struct stat st;
    if (stat(tmp, &st) != 0) {
        if (mkdir(tmp, 0700) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s", tmp);
            return -1;
        }
    }

    return 0;
}

int channel_subscriptions_db_init(const char *db_key) {
    pthread_mutex_lock(&g_db_mutex);

    if (g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;  /* Already initialized */
    }

    char db_path[512];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    if (ensure_directory(db_path) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    if (dna_db_open_encrypted(db_path, db_key, &g_db) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open encrypted database");
        g_db = NULL;
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    /* Android force-close recovery: Set busy timeout and force WAL checkpoint */
    sqlite3_busy_timeout(g_db, 5000);
    sqlite3_wal_checkpoint(g_db, NULL);

    /* Create subscriptions table */
    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS subscriptions ("
        "  channel_uuid TEXT PRIMARY KEY,"
        "  subscribed_at INTEGER NOT NULL,"
        "  last_synced INTEGER DEFAULT 0,"
        "  last_read_at INTEGER DEFAULT 0"
        ");";

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, create_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create table: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Channel subscriptions database initialized: %s", db_path);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

void channel_subscriptions_db_close(void) {
    pthread_mutex_lock(&g_db_mutex);
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Channel subscriptions database closed");
    }
    pthread_mutex_unlock(&g_db_mutex);
}

int channel_subscriptions_db_subscribe(const char *channel_uuid) {
    if (!channel_uuid || strlen(channel_uuid) < 36) {
        return -2;
    }

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return -3;
    }

    /* Check if already subscribed */
    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT 1 FROM subscriptions WHERE channel_uuid = ?;";
    int rc = sqlite3_prepare_v2(g_db, check_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -4;
    }
    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;  /* Already subscribed */
    }

    /* Insert subscription */
    const char *insert_sql =
        "INSERT INTO subscriptions (channel_uuid, subscribed_at, last_synced, last_read_at) "
        "VALUES (?, ?, 0, 0);";
    rc = sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -5;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        return -6;
    }

    QGP_LOG_INFO(LOG_TAG, "Subscribed to channel: %.8s...", channel_uuid);
    return 0;
}

int channel_subscriptions_db_unsubscribe(const char *channel_uuid) {
    if (!channel_uuid || strlen(channel_uuid) < 36) {
        return -2;
    }

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return -3;
    }

    const char *delete_sql = "DELETE FROM subscriptions WHERE channel_uuid = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, delete_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -4;
    }

    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    int changes = sqlite3_changes(g_db);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        return -5;
    }

    if (changes == 0) {
        return -1;  /* Not subscribed */
    }

    QGP_LOG_INFO(LOG_TAG, "Unsubscribed from channel: %.8s...", channel_uuid);
    return 0;
}

bool channel_subscriptions_db_is_subscribed(const char *channel_uuid) {
    if (!channel_uuid || strlen(channel_uuid) < 36) {
        return false;
    }

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return false;
    }

    const char *sql = "SELECT 1 FROM subscriptions WHERE channel_uuid = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return false;
    }

    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);
    return (rc == SQLITE_ROW);
}

int channel_subscriptions_db_get_all(channel_subscription_t **out_subscriptions, int *out_count) {
    if (!out_subscriptions || !out_count) {
        return -1;
    }

    *out_subscriptions = NULL;
    *out_count = 0;

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return -2;
    }

    /* Count first */
    const char *count_sql = "SELECT COUNT(*) FROM subscriptions;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -3;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (count == 0) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    /* Allocate array */
    channel_subscription_t *subs = calloc((size_t)count, sizeof(channel_subscription_t));
    if (!subs) {
        pthread_mutex_unlock(&g_db_mutex);
        return -4;
    }

    /* Fetch all */
    const char *select_sql =
        "SELECT channel_uuid, subscribed_at, last_synced, last_read_at FROM subscriptions "
        "ORDER BY subscribed_at DESC;";
    rc = sqlite3_prepare_v2(g_db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(subs);
        pthread_mutex_unlock(&g_db_mutex);
        return -5;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
        if (uuid) {
            strncpy(subs[idx].channel_uuid, uuid, sizeof(subs[idx].channel_uuid) - 1);
        }
        subs[idx].subscribed_at = (uint64_t)sqlite3_column_int64(stmt, 1);
        subs[idx].last_synced = (uint64_t)sqlite3_column_int64(stmt, 2);
        subs[idx].last_read_at = (uint64_t)sqlite3_column_int64(stmt, 3);
        idx++;
    }
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);

    *out_subscriptions = subs;
    *out_count = idx;

    QGP_LOG_DEBUG(LOG_TAG, "Retrieved %d channel subscriptions", idx);
    return 0;
}

void channel_subscriptions_db_free(channel_subscription_t *subscriptions, int count) {
    (void)count;
    if (subscriptions) {
        free(subscriptions);
    }
}

int channel_subscriptions_db_update_synced(const char *channel_uuid) {
    if (!channel_uuid || strlen(channel_uuid) < 36) {
        return -1;
    }

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return -2;
    }

    const char *sql = "UPDATE subscriptions SET last_synced = ? WHERE channel_uuid = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -3;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    sqlite3_bind_text(stmt, 2, channel_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);
    return (rc == SQLITE_DONE) ? 0 : -4;
}

int channel_subscriptions_db_mark_read(const char *channel_uuid, uint64_t timestamp) {
    if (!channel_uuid || strlen(channel_uuid) < 36) {
        return -1;
    }

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return -2;
    }

    const char *sql = "UPDATE subscriptions SET last_read_at = ? WHERE channel_uuid = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return -3;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)timestamp);
    sqlite3_bind_text(stmt, 2, channel_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    int changes = sqlite3_changes(g_db);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        return -4;
    }

    if (changes == 0) {
        return -2;  /* Not found */
    }

    return 0;
}

uint64_t channel_subscriptions_db_get_last_read(const char *channel_uuid) {
    if (!channel_uuid || strlen(channel_uuid) < 36) {
        return 0;
    }

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    const char *sql = "SELECT last_read_at FROM subscriptions WHERE channel_uuid = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);

    uint64_t last_read = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        last_read = (uint64_t)sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);
    return last_read;
}
