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

/**
 * Backup Context
 */
struct message_backup_context {
    sqlite3 *db;
    char identity[256];
    char db_path[512];
};

/**
 * Database Schema (v6) - Add sender_fingerprint for v0.07 message format (Phase 12)
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
    "  status INTEGER DEFAULT 1,"         // 0=PENDING, 1=SENT, 2=FAILED
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
    "INSERT OR IGNORE INTO metadata (key, value) VALUES ('version', '6');";

/**
 * Get database path
 */
static int get_db_path(const char *identity, char *path_out, size_t path_len) {
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) {
            fprintf(stderr, "[Backup] HOME/USERPROFILE environment variable not set\n");
            return -1;
        }
    }

    // Create ~/.dna directory if it doesn't exist
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    struct stat st = {0};
    if (stat(dna_dir, &st) == -1) {
#ifdef _WIN32
        // Windows mkdir() only takes 1 argument
        if (mkdir(dna_dir) != 0) {
#else
        // POSIX mkdir() takes mode as second argument
        if (mkdir(dna_dir, 0700) != 0) {
#endif
            fprintf(stderr, "[Backup] Failed to create %s: %s\n", dna_dir, strerror(errno));
            return -1;
        }
    }

    // Database path: ~/.dna/<identity>_messages.db (per-identity)
    snprintf(path_out, path_len, "%s/%s_messages.db", dna_dir, identity);
    return 0;
}

/**
 * Initialize backup system
 */
message_backup_context_t* message_backup_init(const char *identity) {
    if (!identity) {
        fprintf(stderr, "[Backup] Identity cannot be NULL\n");
        return NULL;
    }

    message_backup_context_t *ctx = calloc(1, sizeof(message_backup_context_t));
    if (!ctx) {
        fprintf(stderr, "[Backup] Memory allocation failed\n");
        return NULL;
    }

    strncpy(ctx->identity, identity, sizeof(ctx->identity) - 1);

    // Get database path
    if (get_db_path(identity, ctx->db_path, sizeof(ctx->db_path)) != 0) {
        free(ctx);
        return NULL;
    }

    printf("[Backup] Opening database: %s\n", ctx->db_path);

    // Open SQLite database
    int rc = sqlite3_open(ctx->db_path, &ctx->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to open database: %s\n", sqlite3_errmsg(ctx->db));
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    // Create schema if needed
    char *err_msg = NULL;
    rc = sqlite3_exec(ctx->db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to create schema: %s\n", err_msg);
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
            fprintf(stderr, "[Backup] Migration warning: %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        printf("[Backup] Migrated database schema to v2 (added status column)\n");
    }

    // Migration: Add group_id column if it doesn't exist (v2 -> v3, Phase 5.2)
    const char *migration_sql_v3 = "ALTER TABLE messages ADD COLUMN group_id INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v3, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            fprintf(stderr, "[Backup] Migration warning (v3): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        printf("[Backup] Migrated database schema to v3 (added group_id column)\n");
    }

    // Create index on group_id (safe to run now that column exists)
    const char *index_sql = "CREATE INDEX IF NOT EXISTS idx_group_id ON messages(group_id);";
    rc = sqlite3_exec(ctx->db, index_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to create group_id index: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    // Migration: Add message_type column if it doesn't exist (v3 -> v4, Phase 6.2)
    const char *migration_sql_v4 = "ALTER TABLE messages ADD COLUMN message_type INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v4, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            fprintf(stderr, "[Backup] Migration warning (v4): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        printf("[Backup] Migrated database schema to v4 (added message_type column)\n");
    }

    // Migration: Add invitation_status column if it doesn't exist (v4 -> v5, Phase 6.2)
    const char *migration_sql_v5 = "ALTER TABLE messages ADD COLUMN invitation_status INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v5, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            fprintf(stderr, "[Backup] Migration warning (v5): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        printf("[Backup] Migrated database schema to v5 (added invitation_status column)\n");
    }

    // Migration: Add sender_fingerprint column if it doesn't exist (v5 -> v6, Phase 12)
    const char *migration_sql_v6 = "ALTER TABLE messages ADD COLUMN sender_fingerprint BLOB;";
    rc = sqlite3_exec(ctx->db, migration_sql_v6, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            fprintf(stderr, "[Backup] Migration warning (v6): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        printf("[Backup] Migrated database schema to v6 (added sender_fingerprint column)\n");
    }

    // Create index on sender_fingerprint (safe to run now that column exists)
    const char *index_sql_v6 = "CREATE INDEX IF NOT EXISTS idx_sender_fingerprint ON messages(sender_fingerprint);";
    rc = sqlite3_exec(ctx->db, index_sql_v6, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to create sender_fingerprint index: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    // Migration: Add gsk_version column if it doesn't exist (v6 -> v7, Phase 13 - GSK)
    const char *migration_sql_v7 = "ALTER TABLE messages ADD COLUMN gsk_version INTEGER DEFAULT 0;";
    rc = sqlite3_exec(ctx->db, migration_sql_v7, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        // Column might already exist (not an error)
        if (strstr(err_msg, "duplicate column") == NULL) {
            fprintf(stderr, "[Backup] Migration warning (v7): %s\n", err_msg);
        }
        sqlite3_free(err_msg);
    } else {
        printf("[Backup] Migrated database schema to v7 (added gsk_version column)\n");
    }

    printf("[Backup] Initialized successfully for identity: %s (ENCRYPTED STORAGE)\n", identity);
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
        fprintf(stderr, "[Backup] Failed to prepare duplicate check: %s\n", sqlite3_errmsg(ctx->db));
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

    // Check for duplicate (Model E: same message may be in multiple contacts' outboxes)
    if (message_backup_exists_ciphertext(ctx, encrypted_message, encrypted_len)) {
        printf("[Backup] Skipping duplicate message: %s → %s (%zu bytes, already exists)\n",
               sender, recipient, encrypted_len);
        return 1;  // Return 1 to indicate duplicate (not an error)
    }

    const char *sql =
        "INSERT INTO messages (sender, recipient, encrypted_message, encrypted_len, timestamp, is_outgoing, delivered, read, status, group_id, message_type) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to prepare statement: %s\n", sqlite3_errmsg(ctx->db));
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
        fprintf(stderr, "[Backup] Failed to save message: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    printf("[Backup] Saved ENCRYPTED message: %s → %s (%zu bytes ciphertext, status=PENDING)\n",
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
 * Get conversation history (returns encrypted messages)
 */
int message_backup_get_conversation(message_backup_context_t *ctx,
                                     const char *contact_identity,
                                     backup_message_t **messages_out,
                                     int *count_out) {
    if (!ctx || !ctx->db || !contact_identity) return -1;

    const char *sql =
        "SELECT id, sender, recipient, encrypted_message, encrypted_len, timestamp, delivered, read, status, group_id "
        "FROM messages "
        "WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) "
        "ORDER BY timestamp ASC";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to prepare query: %s\n", sqlite3_errmsg(ctx->db));
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
        idx++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = count;

    printf("[Backup] Retrieved %d ENCRYPTED messages for conversation with %s\n", count, contact_identity);
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
        fprintf(stderr, "[Backup] Failed to prepare query: %s\n", sqlite3_errmsg(ctx->db));
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

    printf("[Backup] Retrieved %d ENCRYPTED group messages (group_id=%d)\n", count, group_id);
    return 0;
}

/**
 * Update message status (PENDING/SENT/FAILED)
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
        printf("[Backup] Updated message %d status to %d\n", message_id, status);
        return 0;
    }

    return -1;
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
        "ORDER BY timestamp DESC LIMIT 100";

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
 * Get statistics
 */
int message_backup_get_stats(message_backup_context_t *ctx,
                              int *total_messages_out,
                              int *unread_count_out,
                              long *db_size_bytes_out) {
    if (!ctx || !ctx->db) return -1;

    // Total messages
    const char *sql1 = "SELECT COUNT(*) FROM messages";
    sqlite3_stmt *stmt1;
    if (sqlite3_prepare_v2(ctx->db, sql1, -1, &stmt1, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt1) == SQLITE_ROW) {
            *total_messages_out = sqlite3_column_int(stmt1, 0);
        }
        sqlite3_finalize(stmt1);
    }

    // Unread messages
    const char *sql2 = "SELECT COUNT(*) FROM messages WHERE read = 0 AND recipient = ?";
    sqlite3_stmt *stmt2;
    if (sqlite3_prepare_v2(ctx->db, sql2, -1, &stmt2, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt2, 1, ctx->identity, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt2) == SQLITE_ROW) {
            *unread_count_out = sqlite3_column_int(stmt2, 0);
        }
        sqlite3_finalize(stmt2);
    }

    // Database file size
    struct stat st;
    if (stat(ctx->db_path, &st) == 0) {
        *db_size_bytes_out = st.st_size;
    } else {
        *db_size_bytes_out = 0;
    }

    return 0;
}

/**
 * Export to JSON (NOTE: Exports ENCRYPTED messages for security)
 */
int message_backup_export_json(message_backup_context_t *ctx,
                                const char *output_path) {
    if (!ctx || !ctx->db || !output_path) return -1;

    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "[Backup] Failed to open %s for writing\n", output_path);
        return -1;
    }

    fprintf(fp, "{\n  \"identity\": \"%s\",\n", ctx->identity);
    fprintf(fp, "  \"note\": \"Messages are encrypted - use DNA Messenger to decrypt\",\n");
    fprintf(fp, "  \"messages\": [\n");

    const char *sql = "SELECT sender, recipient, encrypted_len, timestamp FROM messages ORDER BY timestamp ASC";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fclose(fp);
        return -1;
    }

    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) fprintf(fp, ",\n");
        first = 0;

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"sender\": \"%s\",\n", sqlite3_column_text(stmt, 0));
        fprintf(fp, "      \"recipient\": \"%s\",\n", sqlite3_column_text(stmt, 1));
        fprintf(fp, "      \"encrypted_size\": %d,\n", sqlite3_column_int(stmt, 2));
        fprintf(fp, "      \"timestamp\": %lld\n", (long long)sqlite3_column_int64(stmt, 3));
        fprintf(fp, "    }");
    }

    fprintf(fp, "\n  ]\n}\n");
    sqlite3_finalize(stmt);
    fclose(fp);

    printf("[Backup] Exported ENCRYPTED messages to %s\n", output_path);
    return 0;
}

/**
 * Delete a message by ID
 */
int message_backup_delete(message_backup_context_t *ctx, int message_id) {
    if (!ctx || !ctx->db) {
        fprintf(stderr, "[Backup] Invalid context\n");
        return -1;
    }

    const char *sql = "DELETE FROM messages WHERE id = ?";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Backup] Failed to prepare delete: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, message_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[Backup] Failed to delete message: %s\n", sqlite3_errmsg(ctx->db));
        return -1;
    }

    int changes = sqlite3_changes(ctx->db);
    if (changes == 0) {
        fprintf(stderr, "[Backup] Message %d not found\n", message_id);
        return -1;
    }

    printf("[Backup] Deleted message %d\n", message_id);
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
 * Close backup context
 */
void message_backup_close(message_backup_context_t *ctx) {
    if (!ctx) return;

    if (ctx->db) {
        sqlite3_close(ctx->db);
    }

    free(ctx);
    printf("[Backup] Closed backup context\n");
}
