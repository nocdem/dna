/**
 * @file group_database.c
 * @brief Group Database Module Implementation
 *
 * SQLite database for all group-related data, separate from messages.db.
 *
 * Database: ~/.dna/db/groups.db
 *
 * Tables:
 * - groups: Group metadata (uuid, name, owner, etc.)
 * - group_members: Group member list
 * - group_geks: Group Encryption Keys per version
 * - pending_invitations: Pending group invites
 * - group_messages: Decrypted group message cache
 * - metadata: Schema version tracking
 *
 * Part of DNA Messenger - GEK System
 *
 * @date 2026-01-15
 */

#include "group_database.h"
#include "../crypto/utils/qgp_log.h"
#include "../crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>

#define LOG_TAG "GRP_DB"

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct group_database_context {
    sqlite3 *db;
    char db_path[512];
};

/* Global singleton instance */
static group_database_context_t *g_instance = NULL;

/* ============================================================================
 * SCHEMA
 * ============================================================================ */

/**
 * Database Schema v1
 *
 * Clean schema for group data - migrated from message_backup.c v9
 */
static const char *SCHEMA_SQL =
    /* Groups table - core group metadata */
    "CREATE TABLE IF NOT EXISTS groups ("
    "  uuid TEXT PRIMARY KEY,"
    "  name TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  is_owner INTEGER DEFAULT 0,"
    "  owner_fp TEXT NOT NULL"
    ");"

    /* Group members table */
    "CREATE TABLE IF NOT EXISTS group_members ("
    "  group_uuid TEXT NOT NULL,"
    "  fingerprint TEXT NOT NULL,"
    "  added_at INTEGER NOT NULL,"
    "  PRIMARY KEY (group_uuid, fingerprint)"
    ");"

    /* Group GEKs table - encrypted keys per version */
    "CREATE TABLE IF NOT EXISTS group_geks ("
    "  group_uuid TEXT NOT NULL,"
    "  version INTEGER NOT NULL,"
    "  encrypted_key BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  expires_at INTEGER NOT NULL,"
    "  PRIMARY KEY (group_uuid, version)"
    ");"

    /* Pending invitations table */
    "CREATE TABLE IF NOT EXISTS pending_invitations ("
    "  group_uuid TEXT PRIMARY KEY,"
    "  group_name TEXT NOT NULL,"
    "  owner_fp TEXT NOT NULL,"
    "  received_at INTEGER NOT NULL"
    ");"

    /* Group messages table - decrypted message cache */
    "CREATE TABLE IF NOT EXISTS group_messages ("
    "  id INTEGER PRIMARY KEY,"
    "  group_uuid TEXT NOT NULL,"
    "  message_id INTEGER NOT NULL,"
    "  sender_fp TEXT NOT NULL,"
    "  timestamp_ms INTEGER NOT NULL,"
    "  gek_version INTEGER NOT NULL,"
    "  plaintext TEXT NOT NULL,"
    "  received_at INTEGER NOT NULL,"
    "  UNIQUE (group_uuid, sender_fp, message_id)"
    ");"

    /* Metadata table for schema versioning */
    "CREATE TABLE IF NOT EXISTS metadata ("
    "  key TEXT PRIMARY KEY,"
    "  value TEXT"
    ");"

    /* Indexes for common queries */
    "CREATE INDEX IF NOT EXISTS idx_group_members_uuid ON group_members(group_uuid);"
    "CREATE INDEX IF NOT EXISTS idx_group_geks_uuid ON group_geks(group_uuid);"
    "CREATE INDEX IF NOT EXISTS idx_group_messages_uuid ON group_messages(group_uuid);"
    "CREATE INDEX IF NOT EXISTS idx_group_messages_timestamp ON group_messages(timestamp_ms);"

    /* Set schema version */
    "INSERT OR IGNORE INTO metadata (key, value) VALUES ('version', '1');";

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

/**
 * Get database path: ~/.dna/db/groups.db
 */
static int get_db_path(char *path_out, size_t path_len) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    /* Create <data_dir>/db directory if it doesn't exist */
    char db_dir[512];
    snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);

    struct stat st = {0};
    if (stat(db_dir, &st) == -1) {
        if (qgp_platform_mkdir(db_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create %s: %s\n", db_dir, strerror(errno));
            return -1;
        }
    }

    /* Database path: <data_dir>/db/groups.db */
    snprintf(path_out, path_len, "%s/groups.db", db_dir);
    return 0;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

group_database_context_t* group_database_init(void) {
    /* Return existing instance if already initialized */
    if (g_instance) {
        QGP_LOG_DEBUG(LOG_TAG, "Returning existing group database instance\n");
        return g_instance;
    }

    group_database_context_t *ctx = calloc(1, sizeof(group_database_context_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        return NULL;
    }

    /* Get database path */
    if (get_db_path(ctx->db_path, sizeof(ctx->db_path)) != 0) {
        free(ctx);
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Opening group database: %s\n", ctx->db_path);

    /* Open SQLite database with FULLMUTEX for thread safety */
    int rc = sqlite3_open_v2(ctx->db_path, &ctx->db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", sqlite3_errmsg(ctx->db));
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    // Android force-close recovery: Set busy timeout and force WAL checkpoint
    sqlite3_busy_timeout(ctx->db, 5000);
    sqlite3_wal_checkpoint(ctx->db, NULL);

    /* Create schema if needed */
    char *err_msg = NULL;
    rc = sqlite3_exec(ctx->db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create schema: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    /* Store as global singleton */
    g_instance = ctx;

    QGP_LOG_INFO(LOG_TAG, "Group database initialized successfully\n");
    return ctx;
}

group_database_context_t* group_database_get_instance(void) {
    return g_instance;
}

void* group_database_get_db(group_database_context_t *ctx) {
    if (!ctx) return NULL;
    return ctx->db;
}

void group_database_close(group_database_context_t *ctx) {
    if (!ctx) return;

    if (ctx->db) {
        sqlite3_close(ctx->db);
        ctx->db = NULL;
    }

    /* Clear global singleton if this is it */
    if (g_instance == ctx) {
        g_instance = NULL;
    }

    free(ctx);
    QGP_LOG_INFO(LOG_TAG, "Group database closed\n");
}

/* ============================================================================
 * STATISTICS
 * ============================================================================ */

int group_database_get_stats(group_database_context_t *ctx,
                              int *group_count,
                              int *member_count,
                              int *message_count) {
    if (!ctx || !ctx->db) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc;

    /* Count groups */
    if (group_count) {
        rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM groups", -1, &stmt, NULL);
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            *group_count = sqlite3_column_int(stmt, 0);
        } else {
            *group_count = 0;
        }
        sqlite3_finalize(stmt);
    }

    /* Count members */
    if (member_count) {
        rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM group_members", -1, &stmt, NULL);
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            *member_count = sqlite3_column_int(stmt, 0);
        } else {
            *member_count = 0;
        }
        sqlite3_finalize(stmt);
    }

    /* Count messages */
    if (message_count) {
        rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM group_messages", -1, &stmt, NULL);
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            *message_count = sqlite3_column_int(stmt, 0);
        } else {
            *message_count = 0;
        }
        sqlite3_finalize(stmt);
    }

    return 0;
}
