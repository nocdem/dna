/**
 * Address Book Database Implementation
 * Local SQLite database for wallet address management (per-identity)
 */

#include "addressbook_db.h"
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

#define LOG_TAG "ADDRESSBOOK"

static sqlite3 *g_db = NULL;
static char g_owner_identity[256] = {0};

// Get database path
static int get_db_path(const char *owner_identity, char *path_out, size_t path_size) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid owner_identity\n");
        return -1;
    }

    // Validate owner_identity to prevent path traversal attacks
    size_t identity_len = strlen(owner_identity);
    if (identity_len > 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid identity length: %zu (must be 1-128 chars)\n", identity_len);
        return -1;
    }

    for (size_t i = 0; i < identity_len; i++) {
        char c = owner_identity[i];

        // Block path traversal characters
        if (c == '\\' || c == '/' || c == ':' || c == '.') {
            QGP_LOG_ERROR(LOG_TAG, "Path traversal character blocked: 0x%02X at position %zu\n",
                    (unsigned char)c, i);
            return -1;
        }

        // Whitelist: only allow alphanumeric, dash, underscore
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid character in identity: 0x%02X at position %zu\n",
                    (unsigned char)c, i);
            return -1;
        }
    }

    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // Flat structure: db/addressbook.db
    (void)owner_identity;  // Unused in v0.3.0 flat structure
    snprintf(path_out, path_size, "%s/db/addressbook.db", data_dir);
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

    // Create directories recursively
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir_path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
    }

    p = tmp;
#ifdef _WIN32
    // Skip drive letter on Windows
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
                    QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s\n", tmp);
                    return -1;
                }
            }
            *p = sep;
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
int addressbook_db_init(const char *owner_identity) {
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
        addressbook_db_close();
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

    // Set performance pragmas
    const char *pragmas =
        "PRAGMA synchronous = NORMAL;"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA temp_store = MEMORY;"
        "PRAGMA cache_size = -2000;";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, pragmas, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set pragmas: %s\n", err_msg);
        sqlite3_free(err_msg);
        // Continue anyway - not fatal
    }

    // Create addresses table
    const char *sql_addresses =
        "CREATE TABLE IF NOT EXISTS addresses ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    address TEXT NOT NULL,"
        "    label TEXT NOT NULL,"
        "    network TEXT NOT NULL,"
        "    notes TEXT DEFAULT NULL,"
        "    created_at INTEGER NOT NULL,"
        "    updated_at INTEGER NOT NULL,"
        "    last_used INTEGER DEFAULT 0,"
        "    use_count INTEGER DEFAULT 0,"
        "    UNIQUE(address, network)"
        ");";

    rc = sqlite3_exec(g_db, sql_addresses, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create addresses table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        g_owner_identity[0] = '\0';
        return -1;
    }

    // Create indexes for faster queries
    const char *sql_indexes =
        "CREATE INDEX IF NOT EXISTS idx_addresses_network ON addresses(network);"
        "CREATE INDEX IF NOT EXISTS idx_addresses_label ON addresses(label COLLATE NOCASE);"
        "CREATE INDEX IF NOT EXISTS idx_addresses_last_used ON addresses(last_used DESC);";

    rc = sqlite3_exec(g_db, sql_indexes, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create indexes: %s\n", err_msg);
        sqlite3_free(err_msg);
        // Continue - not fatal
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized for identity '%s': %s\n", owner_identity, db_path);
    return 0;
}

// Add address
int addressbook_db_add(const char *address, const char *label, const char *network, const char *notes) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!address || !label || !network) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters: address, label, and network are required\n");
        return -1;
    }

    // Check if already exists
    if (addressbook_db_exists(address, network)) {
        QGP_LOG_INFO(LOG_TAG, "Address already exists: %.20s... on %s\n", address, network);
        return -2;
    }

    const char *sql = "INSERT INTO addresses (address, label, network, notes, created_at, updated_at) "
                      "VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, network, -1, SQLITE_TRANSIENT);
    if (notes && notes[0]) {
        sqlite3_bind_text(stmt, 4, notes, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 4);
    }
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added address: %s on %s\n", label, network);
    return 0;
}

// Update address
int addressbook_db_update(int id, const char *label, const char *notes) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (id <= 0 || !label) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters: id and label are required\n");
        return -1;
    }

    const char *sql = "UPDATE addresses SET label = ?, notes = ?, updated_at = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_text(stmt, 1, label, -1, SQLITE_TRANSIENT);
    if (notes && notes[0]) {
        sqlite3_bind_text(stmt, 2, notes, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 2);
    }
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 4, id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Updated address id=%d\n", id);
    return 0;
}

// Remove address by ID
int addressbook_db_remove(int id) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (id <= 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid id\n");
        return -1;
    }

    const char *sql = "DELETE FROM addresses WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Removed address id=%d\n", id);
    return 0;
}

// Remove address by address and network
int addressbook_db_remove_by_address(const char *address, const char *network) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!address || !network) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    const char *sql = "DELETE FROM addresses WHERE address = ? AND network = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, network, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Removed address %.20s... on %s\n", address, network);
    return 0;
}

// Check if address exists
bool addressbook_db_exists(const char *address, const char *network) {
    if (!g_db || !address || !network) {
        return false;
    }

    const char *sql = "SELECT COUNT(*) FROM addresses WHERE address = ? AND network = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, network, -1, SQLITE_TRANSIENT);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        exists = (count > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

// Helper to fill entry from statement
static void fill_entry_from_stmt(sqlite3_stmt *stmt, addressbook_entry_t *entry) {
    entry->id = sqlite3_column_int(stmt, 0);

    const char *address = (const char*)sqlite3_column_text(stmt, 1);
    const char *label = (const char*)sqlite3_column_text(stmt, 2);
    const char *network = (const char*)sqlite3_column_text(stmt, 3);
    const char *notes = (const char*)sqlite3_column_text(stmt, 4);

    strncpy(entry->address, address ? address : "", sizeof(entry->address) - 1);
    entry->address[sizeof(entry->address) - 1] = '\0';

    strncpy(entry->label, label ? label : "", sizeof(entry->label) - 1);
    entry->label[sizeof(entry->label) - 1] = '\0';

    strncpy(entry->network, network ? network : "", sizeof(entry->network) - 1);
    entry->network[sizeof(entry->network) - 1] = '\0';

    if (notes) {
        strncpy(entry->notes, notes, sizeof(entry->notes) - 1);
        entry->notes[sizeof(entry->notes) - 1] = '\0';
    } else {
        entry->notes[0] = '\0';
    }

    entry->created_at = (uint64_t)sqlite3_column_int64(stmt, 5);
    entry->updated_at = (uint64_t)sqlite3_column_int64(stmt, 6);
    entry->last_used = (uint64_t)sqlite3_column_int64(stmt, 7);
    entry->use_count = (uint32_t)sqlite3_column_int(stmt, 8);
}

// List all addresses
int addressbook_db_list(addressbook_list_t **list_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!list_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid output parameter\n");
        return -1;
    }

    // Count addresses
    int count = addressbook_db_count();
    if (count < 0) {
        return -1;
    }

    // Allocate list
    addressbook_list_t *list = malloc(sizeof(addressbook_list_t));
    if (!list) {
        return -1;
    }

    list->count = count;
    list->entries = NULL;

    if (count == 0) {
        *list_out = list;
        return 0;
    }

    list->entries = calloc(count, sizeof(addressbook_entry_t));
    if (!list->entries) {
        free(list);
        return -1;
    }

    // Query addresses
    const char *sql = "SELECT id, address, label, network, notes, created_at, updated_at, last_used, use_count "
                      "FROM addresses ORDER BY label COLLATE NOCASE;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(list->entries);
        free(list);
        return -1;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        fill_entry_from_stmt(stmt, &list->entries[i]);
        i++;
    }

    list->count = i;
    sqlite3_finalize(stmt);

    *list_out = list;
    return 0;
}

// List addresses by network
int addressbook_db_list_by_network(const char *network, addressbook_list_t **list_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!network || !list_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Count addresses for this network
    const char *count_sql = "SELECT COUNT(*) FROM addresses WHERE network = ?;";
    sqlite3_stmt *count_stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, count_sql, -1, &count_stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(count_stmt, 1, network, -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    // Allocate list
    addressbook_list_t *list = malloc(sizeof(addressbook_list_t));
    if (!list) {
        return -1;
    }

    list->count = count;
    list->entries = NULL;

    if (count == 0) {
        *list_out = list;
        return 0;
    }

    list->entries = calloc(count, sizeof(addressbook_entry_t));
    if (!list->entries) {
        free(list);
        return -1;
    }

    // Query addresses
    const char *sql = "SELECT id, address, label, network, notes, created_at, updated_at, last_used, use_count "
                      "FROM addresses WHERE network = ? ORDER BY label COLLATE NOCASE;";
    sqlite3_stmt *stmt = NULL;

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(list->entries);
        free(list);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, network, -1, SQLITE_TRANSIENT);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        fill_entry_from_stmt(stmt, &list->entries[i]);
        i++;
    }

    list->count = i;
    sqlite3_finalize(stmt);

    *list_out = list;
    return 0;
}

// Get address by address and network
int addressbook_db_get_by_address(const char *address, const char *network, addressbook_entry_t **entry_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!address || !network || !entry_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    const char *sql = "SELECT id, address, label, network, notes, created_at, updated_at, last_used, use_count "
                      "FROM addresses WHERE address = ? AND network = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, network, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        *entry_out = NULL;
        return 1;  // Not found
    }

    addressbook_entry_t *entry = malloc(sizeof(addressbook_entry_t));
    if (!entry) {
        sqlite3_finalize(stmt);
        return -1;
    }

    fill_entry_from_stmt(stmt, entry);
    sqlite3_finalize(stmt);

    *entry_out = entry;
    return 0;
}

// Get address by ID
int addressbook_db_get_by_id(int id, addressbook_entry_t **entry_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (id <= 0 || !entry_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    const char *sql = "SELECT id, address, label, network, notes, created_at, updated_at, last_used, use_count "
                      "FROM addresses WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        *entry_out = NULL;
        return 1;  // Not found
    }

    addressbook_entry_t *entry = malloc(sizeof(addressbook_entry_t));
    if (!entry) {
        sqlite3_finalize(stmt);
        return -1;
    }

    fill_entry_from_stmt(stmt, entry);
    sqlite3_finalize(stmt);

    *entry_out = entry;
    return 0;
}

// Search addresses
int addressbook_db_search(const char *query, addressbook_list_t **list_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!query || !list_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Build search pattern
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "%%%s%%", query);

    // Count matches
    const char *count_sql = "SELECT COUNT(*) FROM addresses WHERE label LIKE ? OR address LIKE ?;";
    sqlite3_stmt *count_stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, count_sql, -1, &count_stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(count_stmt, 1, pattern, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(count_stmt, 2, pattern, -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    // Allocate list
    addressbook_list_t *list = malloc(sizeof(addressbook_list_t));
    if (!list) {
        return -1;
    }

    list->count = count;
    list->entries = NULL;

    if (count == 0) {
        *list_out = list;
        return 0;
    }

    list->entries = calloc(count, sizeof(addressbook_entry_t));
    if (!list->entries) {
        free(list);
        return -1;
    }

    // Query matching addresses
    const char *sql = "SELECT id, address, label, network, notes, created_at, updated_at, last_used, use_count "
                      "FROM addresses WHERE label LIKE ? OR address LIKE ? ORDER BY label COLLATE NOCASE;";
    sqlite3_stmt *stmt = NULL;

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(list->entries);
        free(list);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_TRANSIENT);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        fill_entry_from_stmt(stmt, &list->entries[i]);
        i++;
    }

    list->count = i;
    sqlite3_finalize(stmt);

    *list_out = list;
    return 0;
}

// Get recently used addresses
int addressbook_db_get_recent(int limit, addressbook_list_t **list_out) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (limit <= 0 || !list_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Allocate list
    addressbook_list_t *list = malloc(sizeof(addressbook_list_t));
    if (!list) {
        return -1;
    }

    list->count = 0;
    list->entries = calloc(limit, sizeof(addressbook_entry_t));
    if (!list->entries) {
        free(list);
        return -1;
    }

    // Query recent addresses (only those that have been used)
    const char *sql = "SELECT id, address, label, network, notes, created_at, updated_at, last_used, use_count "
                      "FROM addresses WHERE last_used > 0 ORDER BY last_used DESC LIMIT ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(list->entries);
        free(list);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, limit);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < limit) {
        fill_entry_from_stmt(stmt, &list->entries[i]);
        i++;
    }

    list->count = i;
    sqlite3_finalize(stmt);

    *list_out = list;
    return 0;
}

// Increment usage
int addressbook_db_increment_usage(int id) {
    if (!g_db) {
        return -1;
    }

    if (id <= 0) {
        return -1;
    }

    const char *sql = "UPDATE addresses SET use_count = use_count + 1, last_used = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 2, id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to increment usage: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

// Get address count
int addressbook_db_count(void) {
    if (!g_db) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM addresses;";
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

// Clear all addresses
int addressbook_db_clear_all(void) {
    if (!g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    const char *sql = "DELETE FROM addresses;";
    char *err_msg = NULL;

    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to clear addresses: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Cleared all addresses\n");
    return 0;
}

// Free list
void addressbook_db_free_list(addressbook_list_t *list) {
    if (list) {
        if (list->entries) {
            free(list->entries);
        }
        free(list);
    }
}

// Free entry
void addressbook_db_free_entry(addressbook_entry_t *entry) {
    if (entry) {
        free(entry);
    }
}

// Close database
void addressbook_db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Closed database for identity '%s'\n", g_owner_identity);
        g_owner_identity[0] = '\0';
    }
}
