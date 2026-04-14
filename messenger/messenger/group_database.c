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
 * Part of DNA Connect - GEK System
 *
 * @date 2026-01-15
 */

#include "group_database.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "database/db_encryption.h"
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
 * Database Schema v3
 *
 * v1: Initial schema - migrated from message_backup.c v9
 * v2: Added status and is_outgoing columns to group_messages for send tracking
 * v3: Added dht_salt + has_dht_salt columns to groups for per-group DHT key
 *     privacy salt storage (CORE-04, Phase 6 plan 03). Foundation for plan 04
 *     (group outbox salt hard cutover).
 */
static const char *SCHEMA_SQL =
    /* Groups table - core group metadata */
    "CREATE TABLE IF NOT EXISTS groups ("
    "  uuid TEXT PRIMARY KEY,"
    "  name TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  is_owner INTEGER DEFAULT 0,"
    "  owner_fp TEXT NOT NULL,"
    "  dht_salt BLOB DEFAULT NULL,"
    "  has_dht_salt INTEGER DEFAULT 0"
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

    /* Group messages table - decrypted message cache
     * v2: Added status (0=pending, 1=sent, 3=failed) and is_outgoing columns */
    "CREATE TABLE IF NOT EXISTS group_messages ("
    "  id INTEGER PRIMARY KEY,"
    "  group_uuid TEXT NOT NULL,"
    "  message_id INTEGER NOT NULL,"
    "  sender_fp TEXT NOT NULL,"
    "  timestamp_ms INTEGER NOT NULL,"
    "  gek_version INTEGER NOT NULL,"
    "  plaintext TEXT NOT NULL,"
    "  received_at INTEGER NOT NULL,"
    "  status INTEGER DEFAULT 1,"
    "  is_outgoing INTEGER DEFAULT 0,"
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
    "INSERT OR IGNORE INTO metadata (key, value) VALUES ('version', '3');";

/**
 * Migration SQL for v1 -> v2
 * Adds status and is_outgoing columns to group_messages
 */
static const char *MIGRATION_V1_TO_V2 =
    "ALTER TABLE group_messages ADD COLUMN status INTEGER DEFAULT 1;"
    "ALTER TABLE group_messages ADD COLUMN is_outgoing INTEGER DEFAULT 0;"
    "UPDATE metadata SET value = '2' WHERE key = 'version';";

/**
 * Migration SQL for v2 -> v3 (CORE-04, Phase 6 plan 03)
 * Adds dht_salt + has_dht_salt columns to groups. No data loss: ALTER TABLE
 * ADD COLUMN preserves all existing rows; existing groups end up with
 * has_dht_salt=0 and dht_salt=NULL. Salt provisioning happens in plan 04.
 */
static const char *MIGRATION_V2_TO_V3 =
    "ALTER TABLE groups ADD COLUMN dht_salt BLOB DEFAULT NULL;"
    "ALTER TABLE groups ADD COLUMN has_dht_salt INTEGER DEFAULT 0;"
    "UPDATE metadata SET value = '3' WHERE key = 'version';";

/* Per-group DHT salt size (matches DM/contact salt size). */
#define GROUP_DHT_SALT_SIZE 32

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

group_database_context_t* group_database_init(const char *db_key) {
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

    /* Open SQLite database (encrypted if db_key provided) */
    int rc = dna_db_open_encrypted(ctx->db_path, db_key, &ctx->db);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", ctx->db_path);
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

    /* Check schema version and run migrations if needed */
    sqlite3_stmt *stmt = NULL;
    int schema_version = 0;
    rc = sqlite3_prepare_v2(ctx->db, "SELECT value FROM metadata WHERE key = 'version'", -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *ver_str = (const char *)sqlite3_column_text(stmt, 0);
        if (ver_str) schema_version = atoi(ver_str);
    }
    sqlite3_finalize(stmt);

    /* Run v1 -> v2 migration if needed */
    if (schema_version == 1) {
        QGP_LOG_INFO(LOG_TAG, "Migrating group database from v1 to v2...\n");
        rc = sqlite3_exec(ctx->db, MIGRATION_V1_TO_V2, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            QGP_LOG_WARN(LOG_TAG, "Migration v1->v2 partial: %s (columns may already exist)\n", err_msg);
            sqlite3_free(err_msg);
            /* Try updating version even if ALTER fails (column may already exist) */
            sqlite3_exec(ctx->db, "UPDATE metadata SET value = '2' WHERE key = 'version'", NULL, NULL, NULL);
        } else {
            QGP_LOG_INFO(LOG_TAG, "Migration v1->v2 completed successfully\n");
        }
        schema_version = 2;
    }

    /* Run v2 -> v3 migration if needed (CORE-04: per-group DHT salt columns) */
    if (schema_version == 2) {
        QGP_LOG_INFO(LOG_TAG, "Migrating groups.db v2 -> v3 (CORE-04 dht_salt)\n");
        rc = sqlite3_exec(ctx->db, MIGRATION_V2_TO_V3, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            QGP_LOG_WARN(LOG_TAG, "Migration v2->v3 partial: %s (columns may already exist)\n",
                         err_msg ? err_msg : "?");
            sqlite3_free(err_msg);
            /* Try updating version even if ALTER fails (column may already exist) */
            sqlite3_exec(ctx->db, "UPDATE metadata SET value = '3' WHERE key = 'version'", NULL, NULL, NULL);
        } else {
            QGP_LOG_INFO(LOG_TAG, "Migration v2->v3 completed successfully\n");
        }
        schema_version = 3;
    }

    /* Store as global singleton */
    g_instance = ctx;

    QGP_LOG_INFO(LOG_TAG, "Group database initialized successfully (schema v3)\n");
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

/* ============================================================================
 * DHT SALT ACCESSORS (CORE-04 — per-group DHT key privacy salt)
 *
 * Mirrors the per-contact pattern in messenger/database/contacts_db.c
 * (contacts_db_set_salt / contacts_db_get_salt). group_database has no
 * dedicated mutex — it shares the sqlite3 handle with other group modules
 * and relies on SQLite's busy-timeout for cross-thread serialization, same
 * as the existing group_database_get_stats() path above.
 * ============================================================================ */

int group_database_has_dht_salt(const char *group_uuid) {
    if (!g_instance || !g_instance->db || !group_uuid) {
        return 0;
    }

    const char *sql = "SELECT has_dht_salt FROM groups WHERE uuid = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_instance->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "has_dht_salt: prepare failed: %s\n",
                      sqlite3_errmsg(g_instance->db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0) ? 1 : 0;
    }
    sqlite3_finalize(stmt);
    return result;
}

int group_database_get_dht_salt(const char *group_uuid, uint8_t *salt_out) {
    if (!g_instance || !g_instance->db || !group_uuid || !salt_out) {
        return -1;
    }

    const char *sql = "SELECT dht_salt, has_dht_salt FROM groups WHERE uuid = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_instance->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "get_dht_salt: prepare failed: %s\n",
                      sqlite3_errmsg(g_instance->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int has_salt = sqlite3_column_int(stmt, 1);
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        if (has_salt && blob && blob_len == GROUP_DHT_SALT_SIZE) {
            memcpy(salt_out, blob, GROUP_DHT_SALT_SIZE);
            result = 0;
            QGP_LOG_DEBUG(LOG_TAG, "get_dht_salt: found for %.20s...\n", group_uuid);
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "get_dht_salt: no salt for %.20s... (has=%d len=%d)\n",
                          group_uuid, has_salt, blob_len);
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "get_dht_salt: no row found for %.20s...\n", group_uuid);
    }

    sqlite3_finalize(stmt);
    return result;
}

int group_database_set_dht_salt(const char *group_uuid, const uint8_t *salt) {
    if (!g_instance || !g_instance->db || !group_uuid || !salt) {
        return -1;
    }

    const char *sql =
        "UPDATE groups SET dht_salt = ?, has_dht_salt = 1 WHERE uuid = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_instance->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "set_dht_salt: prepare failed: %s\n",
                      sqlite3_errmsg(g_instance->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, salt, GROUP_DHT_SALT_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(g_instance->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "set_dht_salt: step failed: %s\n",
                      sqlite3_errmsg(g_instance->db));
        return -1;
    }
    if (changes == 0) {
        QGP_LOG_WARN(LOG_TAG, "set_dht_salt: no group row updated for %.20s...\n",
                     group_uuid);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "set_dht_salt: stored salt for %.20s...\n", group_uuid);
    return 0;
}
