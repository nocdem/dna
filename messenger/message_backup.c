/**
 * Local Message Backup Implementation (PLAINTEXT STORAGE)
 *
 * SQLite-based local message storage.
 * Messages stored as plaintext - database encryption via SQLCipher planned.
 *
 * v14: Changed from encrypted BLOB to plaintext TEXT storage.
 */

#include "message_backup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "MSG_BACKUP"

/**
 * Backup Context
 */
struct message_backup_context {
    sqlite3 *db;
    char identity[256];
    char db_path[512];
};

/**
 * Database Schema (v14)
 *
 * v13: Legacy - encrypted BLOB storage
 * v14: PLAINTEXT storage - decryption happens at receive/send time
 *
 * This database contains ONLY direct messages between users.
 * Group data (groups, members, GEKs, group messages) is in groups.db.
 *
 * Message Types:
 *   0 = regular chat message (default)
 *   1 = group invitation
 *
 * Invitation Status (only for message_type=1):
 *   0 = pending (default)
 *   1 = accepted
 *   2 = declined
 */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS messages ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  sender TEXT NOT NULL,"
    "  recipient TEXT NOT NULL,"
    "  sender_fingerprint TEXT,"          // Sender fingerprint (128 char hex, v14)
    "  plaintext TEXT NOT NULL,"          // Decrypted message content (v14)
    "  timestamp INTEGER NOT NULL,"
    "  delivered INTEGER DEFAULT 1,"
    "  read INTEGER DEFAULT 0,"
    "  is_outgoing INTEGER DEFAULT 0,"
    "  status INTEGER DEFAULT 1,"         // 0=PENDING, 1=SENT(legacy), 2=FAILED, 3=DELIVERED, 4=READ
    "  group_id INTEGER DEFAULT 0,"       // 0=direct message, >0=group ID (Phase 5.2)
    "  message_type INTEGER DEFAULT 0,"   // 0=chat, 1=group_invitation (Phase 6.2)
    "  invitation_status INTEGER DEFAULT 0,"  // 0=pending, 1=accepted, 2=declined (Phase 6.2)
    "  retry_count INTEGER DEFAULT 0,"    // Send retry attempts
    "  offline_seq INTEGER DEFAULT 0"     // Watermark sequence number
    ");"
    ""
    "CREATE INDEX IF NOT EXISTS idx_sender ON messages(sender);"
    "CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient);"
    "CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp DESC);"
    "CREATE INDEX IF NOT EXISTS idx_sender_fingerprint ON messages(sender_fingerprint);"
    ""
    "CREATE TABLE IF NOT EXISTS metadata ("
    "  key TEXT PRIMARY KEY,"
    "  value TEXT"
    ");"
    ""
    "CREATE TABLE IF NOT EXISTS offline_seq ("
    "  recipient TEXT PRIMARY KEY,"
    "  next_seq INTEGER DEFAULT 1"
    ");"
    ""
    "INSERT OR IGNORE INTO metadata (key, value) VALUES ('version', '14');";

/**
 * Get database path
 * v0.3.0: Flat structure - db/messages.db
 */
static int get_db_path(const char *identity, char *path_out, size_t path_len) {
    (void)identity;  // Unused in v0.3.0 flat structure

    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // v0.3.0: Create <data_dir>/db directory if it doesn't exist
    char db_dir[512];
    snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);

    struct stat st = {0};
    if (stat(db_dir, &st) == -1) {
        if (qgp_platform_mkdir(db_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create %s: %s\n", db_dir, strerror(errno));
            return -1;
        }
    }

    // v0.3.0: Database path: <data_dir>/db/messages.db (flat structure)
    snprintf(path_out, path_len, "%s/messages.db", db_dir);
    return 0;
}

/**
 * Initialize backup system
 */
message_backup_context_t* message_backup_init(const char *identity) {
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Identity cannot be NULL\n");
        return NULL;
    }

    message_backup_context_t *ctx = calloc(1, sizeof(message_backup_context_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        return NULL;
    }

    strncpy(ctx->identity, identity, sizeof(ctx->identity) - 1);

    // Get database path
    if (get_db_path(identity, ctx->db_path, sizeof(ctx->db_path)) != 0) {
        free(ctx);
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Opening database: %s\n", ctx->db_path);

    // Open SQLite database with FULLMUTEX for thread safety (DHT callbacks + main thread)
    int rc = sqlite3_open_v2(ctx->db_path, &ctx->db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", sqlite3_errmsg(ctx->db));
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    // Create schema if needed
    char *err_msg = NULL;
    rc = sqlite3_exec(ctx->db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create schema: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    // Migration: Add status column if it doesn't exist (v1 -> v2)
    const char *migration_sql = "ALTER TABLE messages ADD COLUMN status INTEGER DEFAULT 1;";
    rc = sqlite3_exec(ctx->db, migration_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning: %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v2 (added status column)\n");
    }

    // Migration: Add group_id column if it doesn't exist (v2 -> v3, Phase 5.2)
    const char *migration_sql_v3 = "ALTER TABLE messages ADD COLUMN group_id INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v3, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v3): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v3 (added group_id column)\n");
    }

    // Create index on group_id (safe to run now that column exists)
    const char *index_sql = "CREATE INDEX IF NOT EXISTS idx_group_id ON messages(group_id);";
    rc = sqlite3_exec(ctx->db, index_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create group_id index: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    // Migration: Add message_type column if it doesn't exist (v3 -> v4, Phase 6.2)
    const char *migration_sql_v4 = "ALTER TABLE messages ADD COLUMN message_type INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v4, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v4): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v4 (added message_type column)\n");
    }

    // Migration: Add invitation_status column if it doesn't exist (v4 -> v5, Phase 6.2)
    const char *migration_sql_v5 = "ALTER TABLE messages ADD COLUMN invitation_status INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v5, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v5): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v5 (added invitation_status column)\n");
    }

    // Migration: Add sender_fingerprint column if it doesn't exist (v5 -> v6, Phase 12)
    const char *migration_sql_v6 = "ALTER TABLE messages ADD COLUMN sender_fingerprint BLOB;";
    rc = sqlite3_exec(ctx->db, migration_sql_v6, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v6): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v6 (added sender_fingerprint column)\n");
    }

    // Create index on sender_fingerprint (safe to run now that column exists)
    const char *index_sql_v6 = "CREATE INDEX IF NOT EXISTS idx_sender_fingerprint ON messages(sender_fingerprint);";
    rc = sqlite3_exec(ctx->db, index_sql_v6, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create sender_fingerprint index: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    // Migration: Add gsk_version column if it doesn't exist (v6 -> v7, Phase 13 - GEK)
    const char *migration_sql_v7 = "ALTER TABLE messages ADD COLUMN gsk_version INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v7, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v7): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v7 (added gsk_version column)\n");
    }

    // Migration: Create offline_seq table if it doesn't exist (v8 - Watermark pruning)
    // Tracks monotonic sequence numbers for offline message watermarks
    const char *migration_sql_v8 =
        "CREATE TABLE IF NOT EXISTS offline_seq ("
        "  recipient TEXT PRIMARY KEY,"   // Recipient fingerprint
        "  next_seq INTEGER DEFAULT 1"    // Next seq_num to use
        ");";
    rc = sqlite3_exec(ctx->db, migration_sql_v8, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Migration warning (v8): %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v8 (added offline_seq table)\n");
    }

    // Migration v13: Drop group tables - now in separate groups.db
    // Group data moved to group_database.c for clean separation
    const char *migration_sql_v13 =
        "DROP TABLE IF EXISTS dht_group_gsks;"
        "DROP TABLE IF EXISTS dht_groups;"
        "DROP TABLE IF EXISTS dht_group_members;"
        "DROP TABLE IF EXISTS groups;"
        "DROP TABLE IF EXISTS group_members;"
        "DROP TABLE IF EXISTS group_geks;"
        "DROP TABLE IF EXISTS pending_invitations;"
        "DROP TABLE IF EXISTS group_messages;"
        "DROP INDEX IF EXISTS idx_group_members_uuid;"
        "DROP INDEX IF EXISTS idx_group_geks_uuid;"
        "DROP INDEX IF EXISTS idx_group_messages_uuid;"
        "DROP INDEX IF EXISTS idx_group_messages_timestamp;";

    rc = sqlite3_exec(ctx->db, migration_sql_v13, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Log but don't fail - tables may not exist
        QGP_LOG_DEBUG(LOG_TAG, "v13 cleanup note: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "v13: Removed group tables from messages.db (now in groups.db)\n");
    }

    // Migration: Add retry_count column if it doesn't exist (v10 - Message Retry)
    const char *migration_sql_v10 = "ALTER TABLE messages ADD COLUMN retry_count INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v10, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v10): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v10 (added retry_count column)\n");
    }

    // Migration: Fix old messages with delivered=1 but status=0 or status=1 (v11)
    // These should be status=3 (DELIVERED) since delivered flag was already set.
    // This fixes messages from before we prioritized the status field over boolean flags.
    const char *migration_sql_v11 =
        "UPDATE messages SET status = 3 WHERE delivered = 1 AND status IN (0, 1);";
    rc = sqlite3_exec(ctx->db, migration_sql_v11, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Migration warning (v11): %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        int changes = sqlite3_changes(ctx->db);
        if (changes > 0) {
            QGP_LOG_INFO(LOG_TAG, "Migrated %d messages to DELIVERED status (v11 - fix status field)\n", changes);
        }
    }

    // Migration: Add offline_seq column to messages table (v12)
    // Stores sequence number for watermark-based delivery confirmation
    const char *migration_sql_v12 =
        "ALTER TABLE messages ADD COLUMN offline_seq INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v12, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        if (strstr(err_msg, "duplicate column") == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning (v12): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v12 (added offline_seq column)\n");
    }

    // Migration v14: BREAKING CHANGE - encrypted BLOB -> plaintext TEXT
    // Check if old schema (has encrypted_message column) - if so, drop and recreate
    // This is a fresh start migration - old messages will be lost
    sqlite3_stmt *check_stmt;
    const char *check_sql = "SELECT encrypted_message FROM messages LIMIT 1;";
    rc = sqlite3_prepare_v2(ctx->db, check_sql, -1, &check_stmt, NULL);
    if (rc == SQLITE_OK) {
        // Old schema detected - has encrypted_message column
        sqlite3_finalize(check_stmt);
        QGP_LOG_WARN(LOG_TAG, "v14 BREAKING MIGRATION: Dropping old encrypted messages table\n");

        const char *drop_old =
            "DROP TABLE IF EXISTS messages;"
            "DROP INDEX IF EXISTS idx_sender;"
            "DROP INDEX IF EXISTS idx_recipient;"
            "DROP INDEX IF EXISTS idx_timestamp;"
            "DROP INDEX IF EXISTS idx_sender_fingerprint;"
            "DROP INDEX IF EXISTS idx_group_id;";

        rc = sqlite3_exec(ctx->db, drop_old, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "v14 migration failed: %s\n", err_msg);
            sqlite3_free(err_msg);
        }

        // Recreate with new schema
        rc = sqlite3_exec(ctx->db, SCHEMA_SQL, NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "v14 schema creation failed: %s\n", err_msg);
            sqlite3_free(err_msg);
            sqlite3_close(ctx->db);
            free(ctx);
            return NULL;
        }

        // Update version in metadata
        const char *ver_update = "UPDATE metadata SET value = '14' WHERE key = 'version';";
        sqlite3_exec(ctx->db, ver_update, NULL, NULL, NULL);

        QGP_LOG_INFO(LOG_TAG, "Migrated to v14 (PLAINTEXT storage) - old messages dropped\n");
    } else {
        // No encrypted_message column - already v14 or fresh install
        sqlite3_finalize(check_stmt);
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized successfully for identity: %s (PLAINTEXT STORAGE)\n", identity);
    return ctx;
}

/**
 * Check if message already exists (duplicate check by sender + recipient + timestamp)
 */
bool message_backup_exists(message_backup_context_t *ctx,
                           const char *sender_fp,
                           const char *recipient,
                           time_t timestamp) {
    if (!ctx || !ctx->db || !sender_fp || !recipient) {
        return false;
    }

    // Check by sender fingerprint + recipient + timestamp (within 1 second tolerance)
    const char *sql = "SELECT COUNT(*) FROM messages WHERE sender_fingerprint = ? AND recipient = ? AND ABS(timestamp - ?) < 2";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare duplicate check: %s\n", sqlite3_errmsg(ctx->db));
        return false;
    }

    sqlite3_bind_text(stmt, 1, sender_fp, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)timestamp);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        exists = (count > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

/**
 * Save plaintext message to backup
 * offline_seq: sequence number for outgoing messages (for watermark tracking), 0 for incoming
 */
int message_backup_save(message_backup_context_t *ctx,
                        const char *sender,
                        const char *recipient,
                        const char *plaintext,
                        const char *sender_fingerprint,
                        time_t timestamp,
                        bool is_outgoing,
                        int group_id,
                        int message_type,
                        uint64_t offline_seq) {
    if (!ctx || !ctx->db) return -1;
    if (!sender || !recipient || !plaintext) return -1;

    // Check for duplicate (Spillway: same message may be in multiple contacts' outboxes)
    if (sender_fingerprint && message_backup_exists(ctx, sender_fingerprint, recipient, timestamp)) {
        QGP_LOG_INFO(LOG_TAG, "Skipping duplicate message: %s → %s (already exists)\n",
               sender, recipient);
        return 1;  // Return 1 to indicate duplicate (not an error)
    }

    const char *sql =
        "INSERT INTO messages (sender, recipient, plaintext, sender_fingerprint, timestamp, is_outgoing, delivered, read, status, group_id, message_type, offline_seq) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)";  // delivered=0 until watermark confirms

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, plaintext, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, sender_fingerprint ? sender_fingerprint : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)timestamp);
    sqlite3_bind_int(stmt, 6, is_outgoing ? 1 : 0);
    sqlite3_bind_int(stmt, 7, 0);  // status = 0 (PENDING) - will be updated after send
    sqlite3_bind_int(stmt, 8, group_id);  // Phase 5.2: group ID
    sqlite3_bind_int(stmt, 9, message_type);  // Phase 6.2: message type
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)offline_seq);  // v12: watermark seq

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save message: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Saved message: %s → %s (plaintext, status=PENDING)\n", sender, recipient);
    return 0;
}

/**
 * Mark message as delivered
 */
int message_backup_mark_delivered(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) return -1;

    const char *sql = "UPDATE messages SET delivered = 1 WHERE id = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, message_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/**
 * Mark message as read
 */
int message_backup_mark_read(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) return -1;

    const char *sql = "UPDATE messages SET read = 1 WHERE id = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, message_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/**
 * Get unread message count for a specific contact
 */
int message_backup_get_unread_count(message_backup_context_t *ctx, const char *contact_identity) {
    if (!ctx || !ctx->db || !contact_identity) return -1;

    /* Count unread incoming messages from contact (where I am recipient) */
    const char *sql =
        "SELECT COUNT(*) FROM messages "
        "WHERE sender = ? AND recipient = ? AND read = 0 AND is_outgoing = 0";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare unread count query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ctx->identity, -1, SQLITE_STATIC);

    int count = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    return count;
}

/**
 * Get conversation history (returns encrypted messages)
 */
int message_backup_get_conversation(message_backup_context_t *ctx,
                                     const char *contact_identity,
                                     backup_message_t **messages_out,
                                     int *count_out) {
    // Wrapper that loads all messages (for backward compatibility)
    // Uses paginated function internally with large limit
    int total = 0;
    int result = message_backup_get_conversation_page(ctx, contact_identity,
                                                       100000,  // Large limit to get all
                                                       0,       // No offset
                                                       messages_out,
                                                       count_out,
                                                       &total);
    if (result != 0 || *count_out <= 1) {
        return result;
    }

    // Paginated function returns DESC order - reverse for ASC (backward compatibility)
    backup_message_t *messages = *messages_out;
    int count = *count_out;
    for (int i = 0; i < count / 2; i++) {
        backup_message_t tmp = messages[i];
        messages[i] = messages[count - 1 - i];
        messages[count - 1 - i] = tmp;
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d ENCRYPTED messages for conversation with %s\n",
                 count, contact_identity);
    return 0;
}

/**
 * Get conversation history with pagination
 * Returns messages ordered by timestamp DESC (newest first) for reverse-scroll chat UI
 */
int message_backup_get_conversation_page(message_backup_context_t *ctx,
                                          const char *contact_identity,
                                          int limit,
                                          int offset,
                                          backup_message_t **messages_out,
                                          int *count_out,
                                          int *total_out) {
    if (!ctx || !ctx->db || !contact_identity) return -1;
    if (limit <= 0) limit = 50;  // Default page size
    if (offset < 0) offset = 0;

    // First, get total count for this conversation
    const char *count_sql =
        "SELECT COUNT(*) FROM messages "
        "WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)";

    sqlite3_stmt *count_stmt;
    int rc = sqlite3_prepare_v2(ctx->db, count_sql, -1, &count_stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare count query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(count_stmt, 1, ctx->identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(count_stmt, 2, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(count_stmt, 3, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(count_stmt, 4, ctx->identity, -1, SQLITE_STATIC);

    int total = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        total = sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    if (total_out) *total_out = total;

    if (total == 0 || offset >= total) {
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Get paginated messages - ORDER BY timestamp DESC for newest-first
    // This allows efficient loading for reverse-scroll chat UI
    const char *sql =
        "SELECT id, sender, recipient, plaintext, sender_fingerprint, timestamp, delivered, read, status, group_id, message_type, is_outgoing "
        "FROM messages "
        "WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) "
        "ORDER BY timestamp DESC "
        "LIMIT ? OFFSET ?";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare page query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ctx->identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, ctx->identity, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, limit);
    sqlite3_bind_int(stmt, 6, offset);

    // Allocate array for max possible messages
    backup_message_t *messages = calloc(limit, sizeof(backup_message_t));
    if (!messages) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch messages
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        messages[idx].id = sqlite3_column_int(stmt, 0);
        strncpy(messages[idx].sender, (const char*)sqlite3_column_text(stmt, 1), 255);
        strncpy(messages[idx].recipient, (const char*)sqlite3_column_text(stmt, 2), 255);

        // Copy plaintext (TEXT)
        const char *text = (const char*)sqlite3_column_text(stmt, 3);
        messages[idx].plaintext = text ? strdup(text) : strdup("");

        // Copy sender fingerprint
        const char *fp = (const char*)sqlite3_column_text(stmt, 4);
        if (fp) strncpy(messages[idx].sender_fingerprint, fp, 128);

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);
        messages[idx].group_id = sqlite3_column_int(stmt, 9);
        messages[idx].message_type = sqlite3_column_int(stmt, 10);
        messages[idx].is_outgoing = sqlite3_column_int(stmt, 11) != 0;
        idx++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = idx;

    QGP_LOG_DEBUG(LOG_TAG, "Retrieved page: %d messages (offset=%d, total=%d) for %s\n",
                  idx, offset, total, contact_identity);
    return 0;
}

/**
 * Get group conversation history (Phase 5.2)
 */
int message_backup_get_group_conversation(message_backup_context_t *ctx,
                                           int group_id,
                                           backup_message_t **messages_out,
                                           int *count_out) {
    if (!ctx || !ctx->db) return -1;
    if (group_id <= 0) return -1;  // group_id must be positive

    const char *sql =
        "SELECT id, sender, recipient, plaintext, sender_fingerprint, timestamp, delivered, read, status, group_id, is_outgoing "
        "FROM messages "
        "WHERE group_id = ? "
        "ORDER BY timestamp ASC";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, group_id);

    // Count results first
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Allocate array
    backup_message_t *messages = calloc(count, sizeof(backup_message_t));
    if (!messages) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch messages
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        messages[idx].id = sqlite3_column_int(stmt, 0);
        strncpy(messages[idx].sender, (const char*)sqlite3_column_text(stmt, 1), 255);
        strncpy(messages[idx].recipient, (const char*)sqlite3_column_text(stmt, 2), 255);

        // Copy plaintext (TEXT)
        const char *text = (const char*)sqlite3_column_text(stmt, 3);
        messages[idx].plaintext = text ? strdup(text) : strdup("");

        // Copy sender fingerprint
        const char *fp = (const char*)sqlite3_column_text(stmt, 4);
        if (fp) strncpy(messages[idx].sender_fingerprint, fp, 128);

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);
        messages[idx].group_id = sqlite3_column_int(stmt, 9);
        messages[idx].is_outgoing = sqlite3_column_int(stmt, 10) != 0;
        idx++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = count;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d group messages (group_id=%d)\n", count, group_id);
    return 0;
}

/**
 * Update message status (PENDING/FAILED/DELIVERED/READ)
 * Note: SENT(1) is legacy - new messages go directly PENDING→DELIVERED via watermark
 */
int message_backup_update_status(message_backup_context_t *ctx, int message_id, int status) {
    if (!ctx || !ctx->db) return -1;

    const char *sql = "UPDATE messages SET status = ? WHERE id = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, status);
    sqlite3_bind_int(stmt, 2, message_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_INFO(LOG_TAG, "Updated message %d status to %d\n", message_id, status);
        return 0;
    }

    return -1;
}

/**
 * Increment retry count for a message
 */
int message_backup_increment_retry_count(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) return -1;

    const char *sql = "UPDATE messages SET retry_count = retry_count + 1 WHERE id = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, message_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_DEBUG(LOG_TAG, "Incremented retry_count for message %d\n", message_id);
        return 0;
    }

    return -1;
}

/**
 * Mark message as stale (30+ days without delivery)
 */
int message_backup_mark_stale(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) return -1;

    const char *sql = "UPDATE messages SET status = 5 WHERE id = ?";  // 5 = STALE

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare mark_stale: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, message_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_INFO(LOG_TAG, "Message %d marked as STALE (30+ days old)\n", message_id);
        return 0;
    }

    return -1;
}

/**
 * Get message age in days
 */
int message_backup_get_age_days(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) return -1;

    const char *sql = "SELECT timestamp FROM messages WHERE id = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, message_id);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    time_t msg_timestamp = (time_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    time_t now = time(NULL);
    int age_days = (int)((now - msg_timestamp) / (24 * 60 * 60));

    return age_days >= 0 ? age_days : 0;
}

/**
 * Get all pending/failed outgoing messages for retry
 */
int message_backup_get_pending_messages(message_backup_context_t *ctx,
                                         int max_retries,
                                         backup_message_t **messages_out,
                                         int *count_out) {
    if (!ctx || !ctx->db || !messages_out || !count_out) return -1;

    *messages_out = NULL;
    *count_out = 0;

    // Query outgoing messages with status PENDING(0) or FAILED(2)
    // max_retries=0 means unlimited (no retry_count filter)
    const char *sql_unlimited =
        "SELECT id, sender, recipient, plaintext, sender_fingerprint, timestamp, delivered, read, status, group_id, message_type, retry_count "
        "FROM messages "
        "WHERE is_outgoing = 1 AND (status = 0 OR status = 2) "
        "ORDER BY timestamp ASC";

    const char *sql_limited =
        "SELECT id, sender, recipient, plaintext, sender_fingerprint, timestamp, delivered, read, status, group_id, message_type, retry_count "
        "FROM messages "
        "WHERE is_outgoing = 1 AND (status = 0 OR status = 2) AND retry_count < ? "
        "ORDER BY timestamp ASC";

    const char *sql = (max_retries == 0) ? sql_unlimited : sql_limited;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare pending messages query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    // Only bind max_retries if using the limited query
    if (max_retries > 0) {
        sqlite3_bind_int(stmt, 1, max_retries);
    }

    // Count results first
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate array
    backup_message_t *messages = calloc(count, sizeof(backup_message_t));
    if (!messages) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch messages
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        messages[idx].id = sqlite3_column_int(stmt, 0);
        strncpy(messages[idx].sender, (const char*)sqlite3_column_text(stmt, 1), 255);
        strncpy(messages[idx].recipient, (const char*)sqlite3_column_text(stmt, 2), 255);

        // Copy plaintext (TEXT)
        const char *text = (const char*)sqlite3_column_text(stmt, 3);
        messages[idx].plaintext = text ? strdup(text) : strdup("");

        // Copy sender fingerprint
        const char *fp = (const char*)sqlite3_column_text(stmt, 4);
        if (fp) strncpy(messages[idx].sender_fingerprint, fp, 128);

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);
        messages[idx].group_id = sqlite3_column_int(stmt, 9);
        messages[idx].message_type = sqlite3_column_int(stmt, 10);
        messages[idx].retry_count = sqlite3_column_int(stmt, 11);
        messages[idx].is_outgoing = true;
        idx++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = count;

    QGP_LOG_INFO(LOG_TAG, "Found %d pending/failed messages for retry\n", count);
    return 0;
}

/**
 * Update message status by sender/recipient/timestamp
 * Useful when message ID is not known (e.g., after async send)
 */
int message_backup_update_status_by_key(
    message_backup_context_t *ctx,
    const char *sender,
    const char *recipient,
    time_t timestamp,
    int status
) {
    if (!ctx || !ctx->db || !sender || !recipient) return -1;

    const char *sql = "UPDATE messages SET status = ? WHERE sender = ? AND recipient = ? AND timestamp = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, status);
    sqlite3_bind_text(stmt, 2, sender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, recipient, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)timestamp);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/**
 * Get the last inserted message ID
 */
int message_backup_get_last_id(message_backup_context_t *ctx) {
    if (!ctx || !ctx->db) return -1;
    return (int)sqlite3_last_insert_rowid(ctx->db);
}

/**
 * Get recent contacts
 */
int message_backup_get_recent_contacts(message_backup_context_t *ctx,
                                        char ***contacts_out,
                                        int *count_out) {
    if (!ctx || !ctx->db) return -1;

    const char *sql =
        "SELECT DISTINCT "
        "  CASE "
        "    WHEN sender = ? THEN recipient "
        "    ELSE sender "
        "  END AS contact "
        "FROM messages "
        "WHERE sender = ? OR recipient = ? "
        "ORDER BY timestamp DESC";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, ctx->identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ctx->identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, ctx->identity, -1, SQLITE_STATIC);

    // Count results
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        *contacts_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Allocate array
    char **contacts = calloc(count, sizeof(char*));
    if (!contacts) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch contacts
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *contact = (const char*)sqlite3_column_text(stmt, 0);
        contacts[idx] = strdup(contact);
        idx++;
    }

    sqlite3_finalize(stmt);

    *contacts_out = contacts;
    *count_out = count;
    return 0;
}

/**
 * Search messages by sender/recipient identity
 */
int message_backup_search_by_identity(message_backup_context_t *ctx,
                                       const char *identity,
                                       backup_message_t **messages_out,
                                       int *count_out) {
    if (!ctx || !ctx->db || !identity) return -1;

    const char *sql =
        "SELECT id, sender, recipient, plaintext, sender_fingerprint, timestamp, delivered, read, status, is_outgoing "
        "FROM messages "
        "WHERE sender = ? OR recipient = ? "
        "ORDER BY timestamp DESC";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, identity, -1, SQLITE_STATIC);

    // Count and fetch
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    backup_message_t *messages = calloc(count, sizeof(backup_message_t));
    if (!messages) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        messages[idx].id = sqlite3_column_int(stmt, 0);
        strncpy(messages[idx].sender, (const char*)sqlite3_column_text(stmt, 1), 255);
        strncpy(messages[idx].recipient, (const char*)sqlite3_column_text(stmt, 2), 255);

        // Copy plaintext (TEXT)
        const char *text = (const char*)sqlite3_column_text(stmt, 3);
        messages[idx].plaintext = text ? strdup(text) : strdup("");

        // Copy sender fingerprint
        const char *fp = (const char*)sqlite3_column_text(stmt, 4);
        if (fp) strncpy(messages[idx].sender_fingerprint, fp, 128);

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);
        messages[idx].is_outgoing = sqlite3_column_int(stmt, 9) != 0;
        idx++;
    }

    sqlite3_finalize(stmt);
    *messages_out = messages;
    *count_out = count;
    return 0;
}

/**
 * Delete a message by ID
 */
int message_backup_delete(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context\n");
        return -1;
    }

    const char *sql = "DELETE FROM messages WHERE id = ?";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare delete: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, message_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete message: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    int changes = sqlite3_changes(ctx->db);
    if (changes == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Message %d not found\n", message_id);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted message %d\n", message_id);
    return 0;
}

/**
 * Free messages array
 */
void message_backup_free_messages(backup_message_t *messages, int count) {
    if (messages) {
        for (int i = 0; i < count; i++) {
            if (messages[i].plaintext) {
                free(messages[i].plaintext);
            }
        }
        free(messages);
    }
}

/**
 * Get database handle from backup context
 */
void* message_backup_get_db(message_backup_context_t *ctx) {
    return ctx ? ctx->db : NULL;
}

/**
 * Get and increment the next sequence number for a recipient
 *
 * Uses INSERT OR REPLACE to atomically get-and-increment.
 */
uint64_t message_backup_get_next_seq(message_backup_context_t *ctx, const char *recipient) {
    if (!ctx || !ctx->db || !recipient) {
        return 1;  // Safe default
    }

    uint64_t seq_num = 1;

    // First, try to get existing value
    const char *select_sql = "SELECT next_seq FROM offline_seq WHERE recipient = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, select_sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, recipient, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            seq_num = (uint64_t)sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Now increment and store the next value
    const char *upsert_sql =
        "INSERT INTO offline_seq (recipient, next_seq) VALUES (?, ?)"
        "ON CONFLICT(recipient) DO UPDATE SET next_seq = ?";
    rc = sqlite3_prepare_v2(ctx->db, upsert_sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, recipient, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(seq_num + 1));
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)(seq_num + 1));
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to update offline_seq: %s\n", sqlite3_errmsg(ctx->db));
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "Seq num for %.20s...: %lu (next: %lu)\n",
           recipient, (unsigned long)seq_num, (unsigned long)(seq_num + 1));
    return seq_num;
}

/**
 * Mark all outgoing messages as DELIVERED up to a sequence number
 *
 * Note: The current messages table doesn't store seq_num per message.
 * Marks outgoing messages with offline_seq <= max_seq_num as DELIVERED.
 * Only affects messages with status PENDING(0) or SENT(1).
 *
 * Status flow: PENDING(0) → SENT(1) → DELIVERED(3) via watermark.
 */
int message_backup_mark_delivered_up_to_seq(
    message_backup_context_t *ctx,
    const char *sender,
    const char *recipient,
    uint64_t max_seq_num
) {
    if (!ctx || !ctx->db || !sender || !recipient) {
        return -1;
    }

    // Update outgoing messages where offline_seq <= max_seq_num
    // This ensures only messages that the recipient has actually fetched are marked
    const char *sql =
        "UPDATE messages SET status = 3 "
        "WHERE sender = ? AND recipient = ? AND is_outgoing = 1 "
        "AND status IN (0, 1) AND offline_seq > 0 AND offline_seq <= ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare mark_delivered query: %s\n",
               sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)max_seq_num);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(ctx->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to mark messages delivered: %s\n",
               sqlite3_errmsg(ctx->db));
        return -1;
    }

    if (changes > 0) {
        QGP_LOG_INFO(LOG_TAG, "Marked %d messages as DELIVERED to %.20s...\n",
               changes, recipient);
    }

    return changes;
}

/**
 * Get unique recipients with pending outgoing messages
 */
int message_backup_get_pending_recipients(
    message_backup_context_t *ctx,
    char recipients_out[][129],
    int max_recipients,
    int *count_out
) {
    if (!ctx || !ctx->db || !recipients_out || !count_out) {
        return -1;
    }

    *count_out = 0;

    // Get distinct recipients of outgoing messages with PENDING status
    const char *sql =
        "SELECT DISTINCT recipient FROM messages "
        "WHERE is_outgoing = 1 AND status = 0 "
        "LIMIT ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare pending recipients query: %s\n",
                      sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, max_recipients);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_recipients) {
        const char *recipient = (const char *)sqlite3_column_text(stmt, 0);
        if (recipient && strlen(recipient) == 128) {
            strncpy(recipients_out[count], recipient, 128);
            recipients_out[count][128] = '\0';
            count++;
        }
    }

    sqlite3_finalize(stmt);

    *count_out = count;
    QGP_LOG_INFO(LOG_TAG, "Found %d unique recipients with pending messages\n", count);
    return 0;
}

/**
 * Close backup context
 */
void message_backup_close(message_backup_context_t *ctx) {
    if (!ctx) return;

    if (ctx->db) {
        sqlite3_close(ctx->db);
    }

    free(ctx);
    QGP_LOG_INFO(LOG_TAG, "Closed backup context\n");
}
