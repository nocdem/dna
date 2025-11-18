/**
 * Contacts Database Implementation
 * Local SQLite database for contact management (per-identity)
 */

#include "contacts_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#include <shlobj.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#include <pwd.h>
#endif

static sqlite3 *g_db = NULL;
static char g_owner_identity[256] = {0};  // Current database owner

// Get database path for specific identity
static int get_db_path(const char *owner_identity, char *path_out, size_t path_size) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        fprintf(stderr, "[CONTACTS_DB] Invalid owner_identity\n");
        return -1;
    }

    // Validate owner_identity to prevent path traversal attacks (BOTH platforms)
    // Use whitelist approach: only allow alphanumeric, dash, underscore
    size_t identity_len = strlen(owner_identity);
    if (identity_len == 0 || identity_len > 128) {
        fprintf(stderr, "[CONTACTS_DB] Invalid identity length: %zu (must be 1-128 chars)\n", identity_len);
        return -1;
    }

    for (size_t i = 0; i < identity_len; i++) {
        char c = owner_identity[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            fprintf(stderr, "[CONTACTS_DB] Invalid character in identity: 0x%02X at position %zu\n",
                    (unsigned char)c, i);
            fprintf(stderr, "[CONTACTS_DB] Only alphanumeric, dash, and underscore allowed\n");
            return -1;
        }
    }

#ifdef _WIN32
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to get AppData path\n");
        return -1;
    }
    snprintf(path_out, path_size, "%s\\.dna\\%s_contacts.db", appdata, owner_identity);
#else
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    if (!home) {
        fprintf(stderr, "[CONTACTS_DB] Failed to get home directory\n");
        return -1;
    }

    snprintf(path_out, path_size, "%s/.dna/%s_contacts.db", home, owner_identity);
#endif
    return 0;
}

// Ensure directory exists
static int ensure_directory(const char *db_path) {
    char dir_path[512];
    strncpy(dir_path, db_path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';

    // Find last slash
    char *last_slash = strrchr(dir_path, '/');
    if (!last_slash) {
        last_slash = strrchr(dir_path, '\\');
    }
    if (last_slash) {
        *last_slash = '\0';
    }

    // Check if directory exists
    struct stat st;
    if (stat(dir_path, &st) != 0) {
        // Create directory
        if (mkdir(dir_path, 0700) != 0) {
            fprintf(stderr, "[CONTACTS_DB] Failed to create directory: %s\n", dir_path);
            return -1;
        }
    }

    return 0;
}

// Initialize database
int contacts_db_init(const char *owner_identity) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        fprintf(stderr, "[CONTACTS_DB] Invalid owner_identity\n");
        return -1;
    }

    // If already initialized for same identity, return success
    if (g_db && strcmp(g_owner_identity, owner_identity) == 0) {
        return 0;
    }

    // If initialized for different identity, close first
    if (g_db) {
        printf("[CONTACTS_DB] Closing previous database for '%s'\n", g_owner_identity);
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
        fprintf(stderr, "[CONTACTS_DB] Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        g_owner_identity[0] = '\0';
        return -1;
    }

    // Create table if not exists
    const char *sql =
        "CREATE TABLE IF NOT EXISTS contacts ("
        "    identity TEXT PRIMARY KEY,"
        "    added_timestamp INTEGER NOT NULL,"
        "    notes TEXT"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        g_owner_identity[0] = '\0';
        return -1;
    }

    printf("[CONTACTS_DB] Initialized for identity '%s': %s\n", owner_identity, db_path);
    return 0;
}

// Add contact
int contacts_db_add(const char *identity, const char *notes) {
    if (!g_db) {
        fprintf(stderr, "[CONTACTS_DB] Database not initialized\n");
        return -1;
    }

    if (!identity) {
        fprintf(stderr, "[CONTACTS_DB] Invalid identity\n");
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
        fprintf(stderr, "[CONTACTS_DB] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
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
        fprintf(stderr, "[CONTACTS_DB] Failed to insert: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    printf("[CONTACTS_DB] Added contact: %s\n", identity);
    return 0;
}

// Remove contact
int contacts_db_remove(const char *identity) {
    if (!g_db) {
        fprintf(stderr, "[CONTACTS_DB] Database not initialized\n");
        return -1;
    }

    if (!identity) {
        fprintf(stderr, "[CONTACTS_DB] Invalid identity\n");
        return -1;
    }

    const char *sql = "DELETE FROM contacts WHERE identity = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[CONTACTS_DB] Failed to delete: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    printf("[CONTACTS_DB] Removed contact: %s\n", identity);
    return 0;
}

// Update notes
int contacts_db_update_notes(const char *identity, const char *notes) {
    if (!g_db) {
        fprintf(stderr, "[CONTACTS_DB] Database not initialized\n");
        return -1;
    }

    if (!identity) {
        fprintf(stderr, "[CONTACTS_DB] Invalid identity\n");
        return -1;
    }

    const char *sql = "UPDATE contacts SET notes = ? WHERE identity = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
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
        fprintf(stderr, "[CONTACTS_DB] Failed to update: %s\n", sqlite3_errmsg(g_db));
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
        fprintf(stderr, "[CONTACTS_DB] Database not initialized\n");
        return -1;
    }

    if (!list_out) {
        fprintf(stderr, "[CONTACTS_DB] Invalid output parameter\n");
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
        fprintf(stderr, "[CONTACTS_DB] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
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
        fprintf(stderr, "[CONTACTS_DB] Database not initialized\n");
        return -1;
    }

    const char *sql = "DELETE FROM contacts;";
    char *err_msg = NULL;

    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to clear contacts: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    printf("[CONTACTS_DB] Cleared all contacts\n");
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
        printf("[CONTACTS_DB] Closed database for identity '%s'\n", g_owner_identity);
        g_owner_identity[0] = '\0';  // Clear owner identity
    }
}

// Migrate contacts from global database to per-identity database
int contacts_db_migrate_from_global(const char *owner_identity) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        fprintf(stderr, "[CONTACTS_DB] Invalid owner_identity for migration\n");
        return -1;
    }

    // Get old global database path
    char old_db_path[512];
#ifdef _WIN32
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to get AppData path\n");
        return -1;
    }
    snprintf(old_db_path, sizeof(old_db_path), "%s\\.dna\\contacts.db", appdata);
#else
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    if (!home) {
        fprintf(stderr, "[CONTACTS_DB] Failed to get home directory\n");
        return -1;
    }
    snprintf(old_db_path, sizeof(old_db_path), "%s/.dna/contacts.db", home);
#endif

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
        printf("[CONTACTS_DB] Per-identity database already exists, skipping migration\n");
        return 0;
    }

    printf("[CONTACTS_DB] Migrating contacts from global database to '%s'\n", owner_identity);

    // Open old database
    sqlite3 *old_db = NULL;
    int rc = sqlite3_open(old_db_path, &old_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to open old database: %s\n", sqlite3_errmsg(old_db));
        if (old_db) sqlite3_close(old_db);
        return -1;
    }

    // Query all contacts from old database
    const char *query = "SELECT identity, added_timestamp, notes FROM contacts;";
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(old_db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to prepare query: %s\n", sqlite3_errmsg(old_db));
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
        fprintf(stderr, "[CONTACTS_DB] Failed to allocate memory for migration\n");
        sqlite3_finalize(stmt);
        sqlite3_close(old_db);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (contact_count >= capacity) {
            capacity *= 2;
            migrate_contact_t *new_contacts = (migrate_contact_t*)realloc(contacts, capacity * sizeof(migrate_contact_t));
            if (!new_contacts) {
                fprintf(stderr, "[CONTACTS_DB] Failed to reallocate memory\n");
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
        printf("[CONTACTS_DB] No contacts to migrate\n");
        free(contacts);
        return 0;
    }

    printf("[CONTACTS_DB] Found %zu contacts to migrate\n", contact_count);

    // Initialize new per-identity database
    if (contacts_db_init(owner_identity) != 0) {
        fprintf(stderr, "[CONTACTS_DB] Failed to initialize new database\n");
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
            fprintf(stderr, "[CONTACTS_DB] Warning: Failed to migrate contact '%s'\n", contacts[i].identity);
        }
    }

    free(contacts);

    printf("[CONTACTS_DB] Migration complete: %zu/%zu contacts migrated\n", migrated, contact_count);

    // Rename old database to backup
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.migrated", old_db_path);
    if (rename(old_db_path, backup_path) == 0) {
        printf("[CONTACTS_DB] Old database backed up to: %s\n", backup_path);
    } else {
        printf("[CONTACTS_DB] Warning: Could not rename old database (you can delete it manually)\n");
    }

    return (int)migrated;
}
