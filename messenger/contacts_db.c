/**
 * Contacts Database Implementation
 * Local SQLite database for contact management
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

// Get database path
static int get_db_path(char *path_out, size_t path_size) {
#ifdef _WIN32
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        fprintf(stderr, "[CONTACTS_DB] Failed to get AppData path\n");
        return -1;
    }
    snprintf(path_out, path_size, "%s\\.dna\\contacts.db", appdata);
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
    snprintf(path_out, path_size, "%s/.dna/contacts.db", home);
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
int contacts_db_init(void) {
    if (g_db) {
        return 0;  // Already initialized
    }

    // Get database path
    char db_path[512];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
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
        return -1;
    }

    printf("[CONTACTS_DB] Initialized: %s\n", db_path);
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
        printf("[CONTACTS_DB] Closed\n");
    }
}
