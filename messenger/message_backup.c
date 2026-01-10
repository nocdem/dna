/**
 * Local Message Backup Implementation (ENCRYPTED STORAGE)
 *
 * SQLite-based local message storage with encrypted-at-rest security.
 * Messages stored as encrypted ciphertext for data sovereignty.
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
 * Database Schema (v11)
 *
 * v9:  GEK group tables (groups, group_members, group_geks, pending_invitations, group_messages)
 * v10: retry_count column for message retry system
 * v11: Fix status field for old messages where delivered=1 but status was 0/1
 *
 * SECURITY: Messages stored as encrypted BLOB for data sovereignty.
 * If database is stolen, messages remain unreadable.
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
    "  sender_fingerprint BLOB,"          // SHA3-512 fingerprint (64 bytes, v0.07)
    "  encrypted_message BLOB NOT NULL,"  // Encrypted ciphertext
    "  encrypted_len INTEGER NOT NULL,"   // Ciphertext length
    "  timestamp INTEGER NOT NULL,"
    "  delivered INTEGER DEFAULT 1,"
    "  read INTEGER DEFAULT 0,"
    "  is_outgoing INTEGER DEFAULT 0,"
    "  status INTEGER DEFAULT 1,"         // 0=PENDING, 1=SENT(legacy), 2=FAILED, 3=DELIVERED, 4=READ
    "  group_id INTEGER DEFAULT 0,"       // 0=direct message, >0=group ID (Phase 5.2)
    "  message_type INTEGER DEFAULT 0,"   // 0=chat, 1=group_invitation (Phase 6.2)
    "  invitation_status INTEGER DEFAULT 0"  // 0=pending, 1=accepted, 2=declined (Phase 6.2)
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
    "INSERT OR IGNORE INTO metadata (key, value) VALUES ('version', '11');";

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

    // Open SQLite database
    int rc = sqlite3_open(ctx->db_path, &ctx->db);
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

    // Migration: Add gsk_version column if it doesn't exist (v6 -> v7, Phase 13 - GSK)
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

    // Migration: Create GEK (Group Encryption Key) tables (v9 - GEK system)
    // Fresh start for group system - drop old tables and create new schema
    const char *migration_sql_v9 =
        // Drop old group tables (clean slate - no migration needed)
        "DROP TABLE IF EXISTS dht_group_gsks;"
        "DROP TABLE IF EXISTS dht_groups;"
        "DROP TABLE IF EXISTS dht_group_members;"

        // Create groups table
        "CREATE TABLE IF NOT EXISTS groups ("
        "  uuid TEXT PRIMARY KEY,"              // Group UUID (canonical lowercase)
        "  name TEXT NOT NULL,"                 // Group display name
        "  created_at INTEGER NOT NULL,"        // Creation timestamp (Unix epoch)
        "  is_owner INTEGER DEFAULT 0,"         // 1 if we are the group owner
        "  owner_fp TEXT NOT NULL"              // Owner's fingerprint (128 hex chars)
        ");"

        // Create group_members table
        "CREATE TABLE IF NOT EXISTS group_members ("
        "  group_uuid TEXT NOT NULL,"           // FK to groups.uuid
        "  fingerprint TEXT NOT NULL,"          // Member fingerprint (128 hex chars)
        "  added_at INTEGER NOT NULL,"          // When member was added
        "  PRIMARY KEY (group_uuid, fingerprint)"
        ");"

        // Create group_geks table - stores encrypted GEK keys per version
        "CREATE TABLE IF NOT EXISTS group_geks ("
        "  group_uuid TEXT NOT NULL,"           // FK to groups.uuid
        "  version INTEGER NOT NULL,"           // GEK version (monotonic)
        "  encrypted_key BLOB NOT NULL,"        // Kyber1024-encrypted GEK (1628 bytes)
        "  created_at INTEGER NOT NULL,"        // Creation timestamp
        "  expires_at INTEGER NOT NULL,"        // Expiration timestamp
        "  PRIMARY KEY (group_uuid, version)"
        ");"

        // Create pending_invitations table
        "CREATE TABLE IF NOT EXISTS pending_invitations ("
        "  group_uuid TEXT PRIMARY KEY,"        // Group UUID
        "  group_name TEXT NOT NULL,"           // Group display name
        "  owner_fp TEXT NOT NULL,"             // Owner's fingerprint
        "  received_at INTEGER NOT NULL"        // When invitation was received
        ");"

        // Create group_messages table - decrypted group message cache
        "CREATE TABLE IF NOT EXISTS group_messages ("
        "  id INTEGER PRIMARY KEY,"             // Local message ID
        "  group_uuid TEXT NOT NULL,"           // FK to groups.uuid
        "  message_id INTEGER NOT NULL,"        // Sender's message ID (per-sender sequence)
        "  sender_fp TEXT NOT NULL,"            // Sender fingerprint
        "  timestamp_ms INTEGER NOT NULL,"      // Message timestamp (milliseconds)
        "  gek_version INTEGER NOT NULL,"       // GEK version used for encryption
        "  plaintext TEXT NOT NULL,"            // Decrypted message content
        "  received_at INTEGER NOT NULL,"       // When we received the message
        "  UNIQUE (group_uuid, sender_fp, message_id)"  // Deduplication key
        ");"

        // Create indexes for common queries
        "CREATE INDEX IF NOT EXISTS idx_group_members_uuid ON group_members(group_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_group_geks_uuid ON group_geks(group_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_group_messages_uuid ON group_messages(group_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_group_messages_timestamp ON group_messages(timestamp_ms);";

    rc = sqlite3_exec(ctx->db, migration_sql_v9, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Log but don't fail - tables may already exist
        QGP_LOG_DEBUG(LOG_TAG, "GEK migration note: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Migrated database schema to v9 (added GEK group tables)\n");
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

    QGP_LOG_INFO(LOG_TAG, "Initialized successfully for identity: %s (ENCRYPTED STORAGE)\n", identity);
    return ctx;
}

/**
 * Check if message already exists (duplicate check by ciphertext)
 */
bool message_backup_exists_ciphertext(message_backup_context_t *ctx,
                                       const uint8_t *encrypted_message,
                                       size_t encrypted_len) {
    if (!ctx || !ctx->db || !encrypted_message || encrypted_len == 0) {
        return false;
    }

    // Check if this exact ciphertext already exists in database
    const char *sql = "SELECT COUNT(*) FROM messages WHERE encrypted_message = ? AND encrypted_len = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare duplicate check: %s\n", sqlite3_errmsg(ctx->db));
        return false;
    }

    sqlite3_bind_blob(stmt, 1, encrypted_message, encrypted_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)encrypted_len);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        exists = (count > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

/**
 * Save encrypted message to backup
 */
int message_backup_save(message_backup_context_t *ctx,
                        const char *sender,
                        const char *recipient,
                        const uint8_t *encrypted_message,
                        size_t encrypted_len,
                        time_t timestamp,
                        bool is_outgoing,
                        int group_id,
                        int message_type) {
    if (!ctx || !ctx->db) return -1;
    if (!sender || !recipient || !encrypted_message) return -1;

    // Check for duplicate (Spillway: same message may be in multiple contacts' outboxes)
    if (message_backup_exists_ciphertext(ctx, encrypted_message, encrypted_len)) {
        QGP_LOG_INFO(LOG_TAG, "Skipping duplicate message: %s → %s (%zu bytes, already exists)\n",
               sender, recipient, encrypted_len);
        return 1;  // Return 1 to indicate duplicate (not an error)
    }

    const char *sql =
        "INSERT INTO messages (sender, recipient, encrypted_message, encrypted_len, timestamp, is_outgoing, delivered, read, status, group_id, message_type) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?)";  // delivered=0 until watermark confirms

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encrypted_message, encrypted_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)encrypted_len);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)timestamp);
    sqlite3_bind_int(stmt, 6, is_outgoing ? 1 : 0);
    sqlite3_bind_int(stmt, 7, 0);  // status = 0 (PENDING) - will be updated after send
    sqlite3_bind_int(stmt, 8, group_id);  // Phase 5.2: group ID
    sqlite3_bind_int(stmt, 9, message_type);  // Phase 6.2: message type

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save message: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Saved ENCRYPTED message: %s → %s (%zu bytes ciphertext, status=PENDING)\n",
           sender, recipient, encrypted_len);
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
    if (!ctx || !ctx->db || !contact_identity) return -1;

    const char *sql =
        "SELECT id, sender, recipient, encrypted_message, encrypted_len, timestamp, delivered, read, status, group_id, message_type "
        "FROM messages "
        "WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) "
        "ORDER BY timestamp ASC";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ctx->identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, ctx->identity, -1, SQLITE_STATIC);

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

        // Copy encrypted message (BLOB)
        int blob_len = sqlite3_column_bytes(stmt, 3);
        const void *blob_data = sqlite3_column_blob(stmt, 3);
        messages[idx].encrypted_message = malloc(blob_len);
        if (messages[idx].encrypted_message) {
            memcpy(messages[idx].encrypted_message, blob_data, blob_len);
            messages[idx].encrypted_len = blob_len;
        }

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);  // Read status column (default 1 for old messages)
        messages[idx].group_id = sqlite3_column_int(stmt, 9);  // Phase 5.2: group ID
        messages[idx].message_type = sqlite3_column_int(stmt, 10);  // Phase 6.2: message type (0=chat, 1=group_invitation)
        idx++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = count;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d ENCRYPTED messages for conversation with %s\n", count, contact_identity);
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
        "SELECT id, sender, recipient, encrypted_message, encrypted_len, timestamp, delivered, read, status, group_id "
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

        // Copy encrypted message (BLOB)
        int blob_len = sqlite3_column_bytes(stmt, 3);
        const void *blob_data = sqlite3_column_blob(stmt, 3);
        messages[idx].encrypted_message = malloc(blob_len);
        if (messages[idx].encrypted_message) {
            memcpy(messages[idx].encrypted_message, blob_data, blob_len);
            messages[idx].encrypted_len = blob_len;
        }

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);
        messages[idx].group_id = sqlite3_column_int(stmt, 9);
        idx++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = count;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d ENCRYPTED group messages (group_id=%d)\n", count, group_id);
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
 * Get all pending/failed outgoing messages for retry
 */
int message_backup_get_pending_messages(message_backup_context_t *ctx,
                                         int max_retries,
                                         backup_message_t **messages_out,
                                         int *count_out) {
    if (!ctx || !ctx->db || !messages_out || !count_out) return -1;

    *messages_out = NULL;
    *count_out = 0;

    // Query outgoing messages with status PENDING(0) or FAILED(2) that haven't exceeded max_retries
    const char *sql =
        "SELECT id, sender, recipient, encrypted_message, encrypted_len, timestamp, delivered, read, status, group_id, message_type, retry_count "
        "FROM messages "
        "WHERE is_outgoing = 1 AND (status = 0 OR status = 2) AND retry_count < ? "
        "ORDER BY timestamp ASC";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare pending messages query: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, max_retries);

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

        // Copy encrypted message (BLOB)
        int blob_len = sqlite3_column_bytes(stmt, 3);
        const void *blob_data = sqlite3_column_blob(stmt, 3);
        messages[idx].encrypted_message = malloc(blob_len);
        if (messages[idx].encrypted_message) {
            memcpy(messages[idx].encrypted_message, blob_data, blob_len);
            messages[idx].encrypted_len = blob_len;
        }

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
        messages[idx].status = sqlite3_column_int(stmt, 8);
        messages[idx].group_id = sqlite3_column_int(stmt, 9);
        messages[idx].message_type = sqlite3_column_int(stmt, 10);
        messages[idx].retry_count = sqlite3_column_int(stmt, 11);
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
 * (Cannot search content - messages are encrypted)
 */
int message_backup_search_by_identity(message_backup_context_t *ctx,
                                       const char *identity,
                                       backup_message_t **messages_out,
                                       int *count_out) {
    if (!ctx || !ctx->db || !identity) return -1;

    const char *sql =
        "SELECT id, sender, recipient, encrypted_message, encrypted_len, timestamp, delivered, read "
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

        int blob_len = sqlite3_column_bytes(stmt, 3);
        const void *blob_data = sqlite3_column_blob(stmt, 3);
        messages[idx].encrypted_message = malloc(blob_len);
        if (messages[idx].encrypted_message) {
            memcpy(messages[idx].encrypted_message, blob_data, blob_len);
            messages[idx].encrypted_len = blob_len;
        }

        messages[idx].timestamp = (time_t)sqlite3_column_int64(stmt, 5);
        messages[idx].delivered = sqlite3_column_int(stmt, 6) != 0;
        messages[idx].read = sqlite3_column_int(stmt, 7) != 0;
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
            if (messages[i].encrypted_message) {
                free(messages[i].encrypted_message);
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
 * This implementation marks ALL outgoing PENDING/SENT messages to the recipient
 * as DELIVERED. A future enhancement would add seq_num tracking per message.
 *
 * Status flow: PENDING(0) → DELIVERED(3) via watermark. SENT(1) is legacy.
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

    (void)max_seq_num;  // Not used yet - future: add seq_num column to messages

    // Update all outgoing messages to recipient with status PENDING(0) or SENT(1) to DELIVERED(3)
    // With async DHT PUT, messages stay PENDING until watermark confirms delivery
    // is_outgoing = 1 means we sent it, sender = our fingerprint
    const char *sql =
        "UPDATE messages SET status = 3 "
        "WHERE sender = ? AND recipient = ? AND is_outgoing = 1 AND status IN (0, 1)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare mark_delivered query: %s\n",
               sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_TRANSIENT);

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
