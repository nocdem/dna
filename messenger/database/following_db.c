/**
 * Following Database Implementation
 * Local SQLite database for follow list management (per-identity)
 */

#include "following_db.h"
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

#define LOG_TAG "FOLLOWING_DB"

static sqlite3 *g_db = NULL;
static char g_owner_identity[256] = {0};
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

static void following_db_close_unlocked(void);

static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }
    snprintf(path_out, path_size, "%s/db/following.db", data_dir);
    return 0;
}

static int ensure_directory(const char *db_path) {
    char dir_path[512];
    strncpy(dir_path, db_path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';

    char *last_slash = strrchr(dir_path, '/');
    if (!last_slash) last_slash = strrchr(dir_path, '\\');
    if (last_slash) *last_slash = '\0';

    struct stat st;
    if (stat(dir_path, &st) != 0) {
        if (mkdir(dir_path, 0700) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s", dir_path);
            return -1;
        }
    }
    return 0;
}

int following_db_init(const char *owner_identity, const char *db_key) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid owner_identity");
        return -1;
    }

    pthread_mutex_lock(&g_db_mutex);

    /* Already initialized for same identity */
    if (g_db && strcmp(g_owner_identity, owner_identity) == 0) {
        pthread_mutex_unlock(&g_db_mutex);
        return 0;
    }

    /* Different identity — close old db */
    if (g_db) {
        following_db_close_unlocked();
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

    int rc = dna_db_open_encrypted(db_path, db_key, &g_db);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open encrypted database");
        g_db = NULL;
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    /* WAL mode for concurrent reads */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS following ("
        "    fingerprint TEXT PRIMARY KEY,"
        "    followed_at INTEGER DEFAULT 0"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, create_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create table: %s", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    strncpy(g_owner_identity, owner_identity, sizeof(g_owner_identity) - 1);
    g_owner_identity[sizeof(g_owner_identity) - 1] = '\0';

    QGP_LOG_INFO(LOG_TAG, "Database initialized for %.16s...", owner_identity);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

int following_db_add(const char *fingerprint) {
    if (!g_db || !fingerprint || strlen(fingerprint) != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Add: invalid args (db=%p, fp_len=%zu)",
                      (void *)g_db, fingerprint ? strlen(fingerprint) : 0);
        return -1;
    }

    const char *sql = "INSERT OR IGNORE INTO following (fingerprint, followed_at) VALUES (?, ?);";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Add prepare failed: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Add step failed: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    if (sqlite3_changes(g_db) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Already following %.16s...", fingerprint);
        return -2;
    }

    QGP_LOG_INFO(LOG_TAG, "Now following %.16s...", fingerprint);
    return 0;
}

int following_db_remove(const char *fingerprint) {
    if (!g_db || !fingerprint) return -1;

    const char *sql = "DELETE FROM following WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Remove prepare failed: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Remove step failed: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Unfollowed %.16s...", fingerprint);
    return 0;
}

bool following_db_exists(const char *fingerprint) {
    if (!g_db || !fingerprint) return false;

    const char *sql = "SELECT 1 FROM following WHERE fingerprint = ? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

int following_db_list(following_list_t **list_out) {
    if (!g_db || !list_out) return -1;

    *list_out = calloc(1, sizeof(following_list_t));
    if (!*list_out) return -1;

    const char *sql = "SELECT fingerprint, followed_at FROM following ORDER BY followed_at DESC;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "List prepare failed: %s", sqlite3_errmsg(g_db));
        free(*list_out);
        *list_out = NULL;
        return -1;
    }

    /* First pass: count rows */
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) count++;
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    (*list_out)->entries = calloc(count, sizeof(following_entry_t));
    if (!(*list_out)->entries) {
        sqlite3_finalize(stmt);
        free(*list_out);
        *list_out = NULL;
        return -1;
    }

    /* Second pass: read data */
    size_t idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 0);
        if (fp) {
            strncpy((*list_out)->entries[idx].fingerprint, fp, 128);
            (*list_out)->entries[idx].fingerprint[128] = '\0';
        }
        (*list_out)->entries[idx].followed_at = (uint64_t)sqlite3_column_int64(stmt, 1);
        idx++;
    }
    (*list_out)->count = idx;

    sqlite3_finalize(stmt);
    return 0;
}

int following_db_count(void) {
    if (!g_db) return -1;

    const char *sql = "SELECT COUNT(*) FROM following;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int following_db_clear_all(void) {
    if (!g_db) return -1;

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, "DELETE FROM following;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Clear all failed: %s", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Cleared all following entries");
    return 0;
}

void following_db_free_list(following_list_t *list) {
    if (!list) return;
    free(list->entries);
    free(list);
}

static void following_db_close_unlocked(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
    g_owner_identity[0] = '\0';
}

void following_db_close(void) {
    pthread_mutex_lock(&g_db_mutex);
    following_db_close_unlocked();
    pthread_mutex_unlock(&g_db_mutex);
    QGP_LOG_INFO(LOG_TAG, "Database closed");
}
