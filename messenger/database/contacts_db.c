/**
 * Contacts Database Implementation
 * Local SQLite database for contact management (per-identity)
 */

#include "contacts_db.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#define LOG_TAG "MSG_CONTACTS"

static sqlite3 *g_db = NULL;
static char g_owner_identity[256] = {0};  // Current database owner

// Get database path for specific identity
static int get_db_path(const char *owner_identity, char *path_out, size_t path_size) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid owner_identity\n");
        return -1;
    }

    // Validate owner_identity to prevent path traversal attacks (BOTH platforms)
    // Use whitelist approach: only allow alphanumeric, dash, underscore
    size_t identity_len = strlen(owner_identity);
    if (identity_len == 0 || identity_len > 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid identity length: %zu (must be 1-128 chars)\n", identity_len);
        return -1;
    }

    for (size_t i = 0; i < identity_len; i++) {
        char c = owner_identity[i];

        // Explicitly block path traversal characters on all platforms
        if (c == '\\' || c == '/' || c == ':' || c == '.') {
            QGP_LOG_ERROR(LOG_TAG, "Path traversal character blocked: 0x%02X at position %zu\n",
                    (unsigned char)c, i);
            QGP_LOG_ERROR(LOG_TAG, "Backslash, slash, colon, and dot not allowed\n");
            return -1;
        }

        // Whitelist: only allow alphanumeric, dash, underscore
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid character in identity: 0x%02X at position %zu\n",
                    (unsigned char)c, i);
            QGP_LOG_ERROR(LOG_TAG, "Only alphanumeric, dash, and underscore allowed\n");
            return -1;
        }
    }

    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    snprintf(path_out, path_size, "%s/%s/db/contacts.db", data_dir, owner_identity);
    return 0;
}

// Ensure directory exists (creates all parent directories)
static int ensure_directory(const char *db_path) {
    char dir_path[512];
    strncpy(dir_path, db_path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';

    // Find last slash to get parent directory
    char *last_slash = strrchr(dir_path, '/');
    if (!last_slash) {
        last_slash = strrchr(dir_path, '\\');
    }
    if (last_slash) {
        *last_slash = '\0';
    }

    // Create directories recursively (like mkdir -p)
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir_path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            struct stat st;
            if (stat(tmp, &st) != 0) {
                if (mkdir(tmp, 0700) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s\n", tmp);
                    return -1;
                }
            }
            *p = '/';
        }
    }

    // Create final directory
    struct stat st;
    if (stat(tmp, &st) != 0) {
        if (mkdir(tmp, 0700) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s\n", tmp);
            return -1;
        }
    }

    return 0;
}

// Initialize database
int contacts_db_init(const char *owner_identity) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid owner_identity\n");
        return -1;
    }

    // If already initialized for same identity, return success
    if (g_db && strcmp(g_owner_identity, owner_identity) == 0) {
        return 0;
    }

    // If initialized for different identity, close first
    if (g_db) {
        QGP_LOG_INFO(LOG_TAG, "Closing previous database for '%s'\n", g_owner_identity);
        contacts_db_close();
    }

    // Store owner identity
    strncpy(g_owner_identity, owner_identity, sizeof(g_owner_identity) - 1);
    g_owner_identity[sizeof(g_owner_identity) - 1] = '\0';

    // Get database path
    char db_path[512];
    if (get_db_path(owner_identity, db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    // Ensure directory exists
    if (ensure_directory(db_path) != 0) {
        return -1;
    }

    // Open database
    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        g_owner_identity[0] = '\0';
        return -1;
    }

    // Set performance pragmas to avoid UI blocking
    const char *pragmas = 
        "PRAGMA synchronous = NORMAL;"     // Faster than FULL, still safe
        "PRAGMA journal_mode = WAL;"       // Write-Ahead Logging for better concurrency
        "PRAGMA temp_store = MEMORY;"      // Store temp data in memory
        "PRAGMA cache_size = -2000;";     // 2MB cache

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, pragmas, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set pragmas: %s\n", err_msg);
        sqlite3_free(err_msg);
        // Continue anyway - not fatal
    }

    // Create contacts table if not exists
    const char *sql_contacts =
        "CREATE TABLE IF NOT EXISTS contacts ("
        "    identity TEXT PRIMARY KEY,"
        "    added_timestamp INTEGER NOT NULL,"
        "    notes TEXT,"
        "    status INTEGER DEFAULT 0"  /* 0=mutual, 1=pending_outgoing */
        ");";

    rc = sqlite3_exec(g_db, sql_contacts, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create contacts table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        g_owner_identity[0] = '\0';
        return -1;
    }

    // Create contact_requests table for incoming requests
    const char *sql_requests =
        "CREATE TABLE IF NOT EXISTS contact_requests ("
        "    fingerprint TEXT PRIMARY KEY,"
        "    display_name TEXT,"
        "    message TEXT,"
        "    requested_at INTEGER NOT NULL,"
        "    status INTEGER DEFAULT 0"  /* 0=pending, 1=approved, 2=denied */
        ");";

    rc = sqlite3_exec(g_db, sql_requests, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create contact_requests table: %s\n", err_msg);
        sqlite3_free(err_msg);
        /* Continue - not fatal, table may already exist without this column */
    }

    // Create blocked_users table
    const char *sql_blocked =
        "CREATE TABLE IF NOT EXISTS blocked_users ("
        "    fingerprint TEXT PRIMARY KEY,"
        "    blocked_at INTEGER NOT NULL,"
        "    reason TEXT"
        ");";

    rc = sqlite3_exec(g_db, sql_blocked, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create blocked_users table: %s\n", err_msg);
        sqlite3_free(err_msg);
        /* Continue - not fatal */
    }

    // Add status column to contacts table if it doesn't exist (migration)
    const char *sql_add_status =
        "ALTER TABLE contacts ADD COLUMN status INTEGER DEFAULT 0;";
    rc = sqlite3_exec(g_db, sql_add_status, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        /* Ignore error - column may already exist */
        sqlite3_free(err_msg);
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized for identity '%s': %s\n", owner_identity, db_path);
    return 0;
}

// Add contact
int contacts_db_add(const char *identity, const char *notes) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid identity\n");
        return -1;
    }

    // Check if already exists
    if (contacts_db_exists(identity)) {
        return -2;  // Already exists
    }

    // Insert
    const char *sql = "INSERT INTO contacts (identity, added_timestamp, notes) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, time(NULL));
    if (notes) {
        sqlite3_bind_text(stmt, 3, notes, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 3);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added contact: %s\n", identity);
    return 0;
}

// Remove contact
int contacts_db_remove(const char *identity) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid identity\n");
        return -1;
    }

    const char *sql = "DELETE FROM contacts WHERE identity = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Removed contact: %s\n", identity);
    return 0;
}

// Update notes
int contacts_db_update_notes(const char *identity, const char *notes) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid identity\n");
        return -1;
    }

    const char *sql = "UPDATE contacts SET notes = ? WHERE identity = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    if (notes) {
        sqlite3_bind_text(stmt, 1, notes, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 1);
    }
    sqlite3_bind_text(stmt, 2, identity, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

// Check if contact exists
bool contacts_db_exists(const char *identity) {
    if (!g_db || !identity) {
        return false;
    }

    const char *sql = "SELECT COUNT(*) FROM contacts WHERE identity = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_TRANSIENT);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        exists = (count > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

// List all contacts
int contacts_db_list(contact_list_t **list_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!list_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid output parameter\n");
        return -1;
    }

    // Count contacts
    int count = contacts_db_count();
    if (count < 0) {
        return -1;
    }

    // Allocate list
    contact_list_t *list = malloc(sizeof(contact_list_t));
    if (!list) {
        return -1;
    }

    list->count = count;
    list->contacts = NULL;

    if (count == 0) {
        *list_out = list;
        return 0;
    }

    list->contacts = calloc(count, sizeof(contact_entry_t));
    if (!list->contacts) {
        free(list);
        return -1;
    }

    // Query contacts
    const char *sql = "SELECT identity, added_timestamp, notes FROM contacts ORDER BY identity;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(list->contacts);
        free(list);
        return -1;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        const char *identity = (const char*)sqlite3_column_text(stmt, 0);
        uint64_t timestamp = sqlite3_column_int64(stmt, 1);
        const char *notes = (const char*)sqlite3_column_text(stmt, 2);

        strncpy(list->contacts[i].identity, identity, sizeof(list->contacts[i].identity) - 1);
        list->contacts[i].added_timestamp = timestamp;

        if (notes) {
            strncpy(list->contacts[i].notes, notes, sizeof(list->contacts[i].notes) - 1);
        } else {
            list->contacts[i].notes[0] = '\0';
        }

        i++;
    }

    sqlite3_finalize(stmt);

    *list_out = list;
    return 0;
}

// Get contact count
int contacts_db_count(void) {
    if (!g_db) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM contacts;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

// Clear all contacts from database
int contacts_db_clear_all(void) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    const char *sql = "DELETE FROM contacts;";
    char *err_msg = NULL;

    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to clear contacts: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Cleared all contacts\n");
    return 0;
}

// Free contact list
void contacts_db_free_list(contact_list_t *list) {
    if (list) {
        if (list->contacts) {
            free(list->contacts);
        }
        free(list);
    }
}

// Close database
void contacts_db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Closed database for identity '%s'\n", g_owner_identity);
        g_owner_identity[0] = '\0';  // Clear owner identity
    }
}

// Migrate contacts from global database to per-identity database
int contacts_db_migrate_from_global(const char *owner_identity) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid owner_identity for migration\n");
        return -1;
    }

    // Get old global database path
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    char old_db_path[512];
    snprintf(old_db_path, sizeof(old_db_path), "%s/contacts.db", data_dir);

    // Check if old database exists
    struct stat st;
    if (stat(old_db_path, &st) != 0) {
        // No old database, nothing to migrate
        return 0;
    }

    // Get new per-identity database path
    char new_db_path[512];
    if (get_db_path(owner_identity, new_db_path, sizeof(new_db_path)) != 0) {
        return -1;
    }

    // Check if new database already exists
    if (stat(new_db_path, &st) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Per-identity database already exists, skipping migration\n");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Migrating contacts from global database to '%s'\n", owner_identity);

    // Open old database
    sqlite3 *old_db = NULL;
    int rc = sqlite3_open(old_db_path, &old_db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open old database: %s\n", sqlite3_errmsg(old_db));
        if (old_db) sqlite3_close(old_db);
        return -1;
    }

    // Query all contacts from old database
    const char *query = "SELECT identity, added_timestamp, notes FROM contacts;";
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(old_db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(old_db));
        sqlite3_close(old_db);
        return -1;
    }

    // Read all contacts into memory
    typedef struct {
        char identity[256];
        uint64_t timestamp;
        char notes[512];
    } migrate_contact_t;

    migrate_contact_t *contacts = NULL;
    size_t contact_count = 0;
    size_t capacity = 100;

    contacts = (migrate_contact_t*)malloc(capacity * sizeof(migrate_contact_t));
    if (!contacts) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for migration\n");
        sqlite3_finalize(stmt);
        sqlite3_close(old_db);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (contact_count >= capacity) {
            capacity *= 2;
            migrate_contact_t *new_contacts = (migrate_contact_t*)realloc(contacts, capacity * sizeof(migrate_contact_t));
            if (!new_contacts) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to reallocate memory\n");
                free(contacts);
                sqlite3_finalize(stmt);
                sqlite3_close(old_db);
                return -1;
            }
            contacts = new_contacts;
        }

        const char *identity = (const char*)sqlite3_column_text(stmt, 0);
        uint64_t timestamp = sqlite3_column_int64(stmt, 1);
        const char *notes = (const char*)sqlite3_column_text(stmt, 2);

        strncpy(contacts[contact_count].identity, identity ? identity : "", sizeof(contacts[contact_count].identity) - 1);
        contacts[contact_count].identity[sizeof(contacts[contact_count].identity) - 1] = '\0';
        contacts[contact_count].timestamp = timestamp;

        if (notes) {
            strncpy(contacts[contact_count].notes, notes, sizeof(contacts[contact_count].notes) - 1);
            contacts[contact_count].notes[sizeof(contacts[contact_count].notes) - 1] = '\0';
        } else {
            contacts[contact_count].notes[0] = '\0';
        }

        contact_count++;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(old_db);

    if (contact_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No contacts to migrate\n");
        free(contacts);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu contacts to migrate\n", contact_count);

    // Initialize new per-identity database
    if (contacts_db_init(owner_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize new database\n");
        free(contacts);
        return -1;
    }

    // Insert all contacts into new database
    size_t migrated = 0;
    for (size_t i = 0; i < contact_count; i++) {
        int result = contacts_db_add(contacts[i].identity,
                                     contacts[i].notes[0] ? contacts[i].notes : NULL);
        if (result == 0 || result == -2) {  // Success or already exists
            migrated++;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to migrate contact '%s'\n", contacts[i].identity);
        }
    }

    free(contacts);

    QGP_LOG_INFO(LOG_TAG, "Migration complete: %zu/%zu contacts migrated\n", migrated, contact_count);

    // Rename old database to backup
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.migrated", old_db_path);
    if (rename(old_db_path, backup_path) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Old database backed up to: %s\n", backup_path);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Warning: Could not rename old database (you can delete it manually)\n");
    }

    return (int)migrated;
}

/* ============================================================================
 * CONTACT REQUEST FUNCTIONS (ICQ-style approval system)
 * ============================================================================ */

// Add incoming contact request
int contacts_db_add_incoming_request(
    const char *fingerprint,
    const char *display_name,
    const char *message,
    uint64_t timestamp)
{
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length: %zu (expected 128)\n",
                      fingerprint ? strlen(fingerprint) : 0);
        return -1;
    }

    // Check if already exists
    if (contacts_db_request_exists(fingerprint)) {
        QGP_LOG_INFO(LOG_TAG, "Request from %s already exists\n", fingerprint);
        return -2;
    }

    // Check if blocked
    if (contacts_db_is_blocked(fingerprint)) {
        QGP_LOG_INFO(LOG_TAG, "Request from %s is blocked\n", fingerprint);
        return -1;
    }

    const char *sql = "INSERT INTO contact_requests (fingerprint, display_name, message, requested_at, status) "
                      "VALUES (?, ?, ?, ?, 0);";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, display_name ? display_name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, message ? message : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (int64_t)timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert request: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added contact request from: %.20s...\n", fingerprint);
    return 0;
}

// Get all pending incoming requests
int contacts_db_get_incoming_requests(incoming_request_t **requests_out, int *count_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!requests_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid output parameters\n");
        return -1;
    }

    // Count pending requests
    int count = contacts_db_pending_request_count();
    if (count < 0) {
        return -1;
    }

    if (count == 0) {
        *requests_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Allocate array
    incoming_request_t *requests = (incoming_request_t*)calloc(count, sizeof(incoming_request_t));
    if (!requests) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate requests array\n");
        return -1;
    }

    // Query pending requests (status = 0)
    const char *sql = "SELECT fingerprint, display_name, message, requested_at, status "
                      "FROM contact_requests WHERE status = 0 ORDER BY requested_at DESC;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(requests);
        return -1;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        const char *fingerprint = (const char*)sqlite3_column_text(stmt, 0);
        const char *display_name = (const char*)sqlite3_column_text(stmt, 1);
        const char *message = (const char*)sqlite3_column_text(stmt, 2);
        uint64_t requested_at = sqlite3_column_int64(stmt, 3);
        int status = sqlite3_column_int(stmt, 4);

        strncpy(requests[i].fingerprint, fingerprint ? fingerprint : "", 128);
        requests[i].fingerprint[128] = '\0';

        strncpy(requests[i].display_name, display_name ? display_name : "", 63);
        requests[i].display_name[63] = '\0';

        strncpy(requests[i].message, message ? message : "", 255);
        requests[i].message[255] = '\0';

        requests[i].requested_at = requested_at;
        requests[i].status = status;

        i++;
    }

    sqlite3_finalize(stmt);

    *requests_out = requests;
    *count_out = i;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d pending contact requests\n", i);
    return 0;
}

// Get count of pending incoming requests
int contacts_db_pending_request_count(void) {
    if (!g_db) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM contact_requests WHERE status = 0;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

// Approve a contact request
int contacts_db_approve_request(const char *fingerprint) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    // Get request details first
    const char *sql_get = "SELECT display_name FROM contact_requests WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;
    char display_name[64] = {0};

    int rc = sqlite3_prepare_v2(g_db, sql_get, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *name = (const char*)sqlite3_column_text(stmt, 0);
            if (name) {
                strncpy(display_name, name, 63);
            }
        }
        sqlite3_finalize(stmt);
    }

    // Update request status to approved
    const char *sql_update = "UPDATE contact_requests SET status = 1 WHERE fingerprint = ?;";
    rc = sqlite3_prepare_v2(g_db, sql_update, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update request status: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // Add to contacts as mutual
    const char *sql_insert = "INSERT OR REPLACE INTO contacts (identity, added_timestamp, notes, status) "
                             "VALUES (?, ?, ?, 0);";
    rc = sqlite3_prepare_v2(g_db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, time(NULL));
    sqlite3_bind_text(stmt, 3, display_name[0] ? display_name : NULL, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add contact: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Approved contact request from: %.20s...\n", fingerprint);
    return 0;
}

// Deny a contact request
int contacts_db_deny_request(const char *fingerprint) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    const char *sql = "UPDATE contact_requests SET status = 2 WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deny request: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Denied contact request from: %.20s...\n", fingerprint);
    return 0;
}

// Remove a contact request
int contacts_db_remove_request(const char *fingerprint) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    const char *sql = "DELETE FROM contact_requests WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove request: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Removed contact request from: %.20s...\n", fingerprint);
    return 0;
}

// Check if a request exists
bool contacts_db_request_exists(const char *fingerprint) {
    if (!g_db || !fingerprint) {
        return false;
    }

    const char *sql = "SELECT COUNT(*) FROM contact_requests WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        exists = (count > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

// Free incoming requests array
void contacts_db_free_requests(incoming_request_t *requests, int count) {
    if (requests) {
        free(requests);
    }
}

/* ============================================================================
 * BLOCKED USER FUNCTIONS
 * ============================================================================ */

// Block a user permanently
int contacts_db_block_user(const char *fingerprint, const char *reason) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    // Check if already blocked
    if (contacts_db_is_blocked(fingerprint)) {
        return -2;
    }

    const char *sql = "INSERT INTO blocked_users (fingerprint, blocked_at, reason) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, time(NULL));
    if (reason) {
        sqlite3_bind_text(stmt, 3, reason, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 3);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to block user: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // Also remove any pending request from this user
    contacts_db_remove_request(fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Blocked user: %.20s...\n", fingerprint);
    return 0;
}

// Unblock a user
int contacts_db_unblock_user(const char *fingerprint) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    const char *sql = "DELETE FROM blocked_users WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to unblock user: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Unblocked user: %.20s...\n", fingerprint);
    return 0;
}

// Check if a user is blocked
bool contacts_db_is_blocked(const char *fingerprint) {
    if (!g_db || !fingerprint) {
        return false;
    }

    const char *sql = "SELECT COUNT(*) FROM blocked_users WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_TRANSIENT);

    bool blocked = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        blocked = (count > 0);
    }

    sqlite3_finalize(stmt);
    return blocked;
}

// Get all blocked users
int contacts_db_get_blocked_users(blocked_user_t **blocked_out, int *count_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!blocked_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid output parameters\n");
        return -1;
    }

    // Count blocked users
    int count = contacts_db_blocked_count();
    if (count < 0) {
        return -1;
    }

    if (count == 0) {
        *blocked_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Allocate array
    blocked_user_t *blocked = (blocked_user_t*)calloc(count, sizeof(blocked_user_t));
    if (!blocked) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blocked array\n");
        return -1;
    }

    const char *sql = "SELECT fingerprint, blocked_at, reason FROM blocked_users ORDER BY blocked_at DESC;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(blocked);
        return -1;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        const char *fingerprint = (const char*)sqlite3_column_text(stmt, 0);
        uint64_t blocked_at = sqlite3_column_int64(stmt, 1);
        const char *reason = (const char*)sqlite3_column_text(stmt, 2);

        strncpy(blocked[i].fingerprint, fingerprint ? fingerprint : "", 128);
        blocked[i].fingerprint[128] = '\0';

        blocked[i].blocked_at = blocked_at;

        strncpy(blocked[i].reason, reason ? reason : "", 255);
        blocked[i].reason[255] = '\0';

        i++;
    }

    sqlite3_finalize(stmt);

    *blocked_out = blocked;
    *count_out = i;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d blocked users\n", i);
    return 0;
}

// Get count of blocked users
int contacts_db_blocked_count(void) {
    if (!g_db) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM blocked_users;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

// Free blocked users array
void contacts_db_free_blocked(blocked_user_t *blocked, int count) {
    if (blocked) {
        free(blocked);
    }
}
