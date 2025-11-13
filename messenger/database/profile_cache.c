/**
 * Profile Cache Database Implementation
 * Local SQLite cache for user profiles (per-identity)
 *
 * @file profile_cache.c
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#include "profile_cache.h"
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
        fprintf(stderr, "[PROFILE_CACHE] Invalid owner_identity\n");
        return -1;
    }

#ifdef _WIN32
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to get AppData path\n");
        return -1;
    }
    snprintf(path_out, path_size, "%s\\.dna\\%s_profiles.db", appdata, owner_identity);
#else
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    if (!home) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to get home directory\n");
        return -1;
    }

    snprintf(path_out, path_size, "%s/.dna/%s_profiles.db", home, owner_identity);
#endif

    return 0;
}

/**
 * Initialize profile cache
 */
int profile_cache_init(const char *owner_identity) {
    if (!owner_identity || strlen(owner_identity) == 0) {
        fprintf(stderr, "[PROFILE_CACHE] Invalid owner_identity\n");
        return -1;
    }

    // Close existing database if open
    if (g_db) {
        // Check if same owner
        if (strcmp(g_owner_identity, owner_identity) == 0) {
            return 0;  // Already initialized for this owner
        }
        profile_cache_close();
    }

    // Get database path
    char db_path[1024];
    if (get_db_path(owner_identity, db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    printf("[PROFILE_CACHE] Opening database: %s\n", db_path);

    // Open database
    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Create table if it doesn't exist
    const char *sql =
        "CREATE TABLE IF NOT EXISTS profiles ("
        "    user_fingerprint TEXT PRIMARY KEY,"
        "    display_name TEXT NOT NULL,"
        "    bio TEXT,"
        "    avatar_hash TEXT,"
        "    location TEXT,"
        "    website TEXT,"
        "    created_at INTEGER,"
        "    updated_at INTEGER,"
        "    fetched_at INTEGER"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Store owner identity
    strncpy(g_owner_identity, owner_identity, sizeof(g_owner_identity) - 1);
    g_owner_identity[sizeof(g_owner_identity) - 1] = '\0';

    printf("[PROFILE_CACHE] Initialized for owner: %s\n", owner_identity);
    return 0;
}

/**
 * Add or update profile in cache
 */
int profile_cache_add_or_update(const char *user_fingerprint, const dht_profile_t *profile) {
    if (!g_db) {
        fprintf(stderr, "[PROFILE_CACHE] Database not initialized\n");
        return -1;
    }

    if (!user_fingerprint || !profile) {
        fprintf(stderr, "[PROFILE_CACHE] Invalid parameters\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO profiles "
        "(user_fingerprint, display_name, bio, avatar_hash, location, website, "
        " created_at, updated_at, fetched_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, profile->display_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, profile->bio, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, profile->avatar_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, profile->location, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, profile->website, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, profile->created_at);
    sqlite3_bind_int64(stmt, 8, profile->updated_at);
    sqlite3_bind_int64(stmt, 9, now);  // fetched_at = now

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to insert/update: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    printf("[PROFILE_CACHE] Cached profile for: %s\n", user_fingerprint);
    return 0;
}

/**
 * Get profile from cache
 */
int profile_cache_get(const char *user_fingerprint, dht_profile_t *profile_out, uint64_t *fetched_at_out) {
    if (!g_db) {
        fprintf(stderr, "[PROFILE_CACHE] Database not initialized\n");
        return -1;
    }

    if (!user_fingerprint || !profile_out) {
        fprintf(stderr, "[PROFILE_CACHE] Invalid parameters\n");
        return -1;
    }

    const char *sql =
        "SELECT display_name, bio, avatar_hash, location, website, "
        "       created_at, updated_at, fetched_at "
        "FROM profiles WHERE user_fingerprint = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  // Not found
    }

    // Read profile data
    memset(profile_out, 0, sizeof(dht_profile_t));

    const char *display_name = (const char*)sqlite3_column_text(stmt, 0);
    const char *bio = (const char*)sqlite3_column_text(stmt, 1);
    const char *avatar_hash = (const char*)sqlite3_column_text(stmt, 2);
    const char *location = (const char*)sqlite3_column_text(stmt, 3);
    const char *website = (const char*)sqlite3_column_text(stmt, 4);

    if (display_name) strncpy(profile_out->display_name, display_name, sizeof(profile_out->display_name) - 1);
    if (bio) strncpy(profile_out->bio, bio, sizeof(profile_out->bio) - 1);
    if (avatar_hash) strncpy(profile_out->avatar_hash, avatar_hash, sizeof(profile_out->avatar_hash) - 1);
    if (location) strncpy(profile_out->location, location, sizeof(profile_out->location) - 1);
    if (website) strncpy(profile_out->website, website, sizeof(profile_out->website) - 1);

    profile_out->created_at = sqlite3_column_int64(stmt, 5);
    profile_out->updated_at = sqlite3_column_int64(stmt, 6);

    if (fetched_at_out) {
        *fetched_at_out = sqlite3_column_int64(stmt, 7);
    }

    sqlite3_finalize(stmt);
    return 0;
}

/**
 * Check if profile exists in cache
 */
bool profile_cache_exists(const char *user_fingerprint) {
    if (!g_db || !user_fingerprint) {
        return false;
    }

    const char *sql = "SELECT COUNT(*) FROM profiles WHERE user_fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = (sqlite3_column_int(stmt, 0) > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

/**
 * Check if cached profile is expired (>7 days old)
 */
bool profile_cache_is_expired(const char *user_fingerprint) {
    if (!g_db || !user_fingerprint) {
        return true;  // Treat as expired if error
    }

    const char *sql = "SELECT fetched_at FROM profiles WHERE user_fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return true;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    bool expired = true;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t fetched_at = sqlite3_column_int64(stmt, 0);
        uint64_t now = (uint64_t)time(NULL);
        uint64_t age = now - fetched_at;

        expired = (age >= PROFILE_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return expired;
}

/**
 * Delete profile from cache
 */
int profile_cache_delete(const char *user_fingerprint) {
    if (!g_db) {
        fprintf(stderr, "[PROFILE_CACHE] Database not initialized\n");
        return -1;
    }

    if (!user_fingerprint) {
        fprintf(stderr, "[PROFILE_CACHE] Invalid fingerprint\n");
        return -1;
    }

    const char *sql = "DELETE FROM profiles WHERE user_fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to delete: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/**
 * Get list of all expired profiles
 */
int profile_cache_list_expired(char ***fingerprints_out, size_t *count_out) {
    if (!g_db || !fingerprints_out || !count_out) {
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    uint64_t cutoff = now - PROFILE_CACHE_TTL_SECONDS;

    const char *sql = "SELECT user_fingerprint FROM profiles WHERE fetched_at < ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, cutoff);

    // Count results
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        *fingerprints_out = NULL;
        *count_out = 0;
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate array
    char **fingerprints = malloc(count * sizeof(char*));
    if (!fingerprints) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fill array
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        const char *fp = (const char*)sqlite3_column_text(stmt, 0);
        fingerprints[i] = strdup(fp ? fp : "");
        i++;
    }

    sqlite3_finalize(stmt);

    *fingerprints_out = fingerprints;
    *count_out = count;
    return 0;
}

/**
 * Get all cached profiles
 */
int profile_cache_list_all(profile_cache_list_t **list_out) {
    if (!g_db || !list_out) {
        return -1;
    }

    const char *sql =
        "SELECT user_fingerprint, display_name, bio, avatar_hash, location, website, "
        "       created_at, updated_at, fetched_at FROM profiles;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    // Count results
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    // Allocate list
    profile_cache_list_t *list = malloc(sizeof(profile_cache_list_t));
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }

    list->entries = NULL;
    list->count = 0;

    if (count == 0) {
        *list_out = list;
        sqlite3_finalize(stmt);
        return 0;
    }

    list->entries = malloc(count * sizeof(profile_cache_entry_t));
    if (!list->entries) {
        free(list);
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fill entries
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        profile_cache_entry_t *entry = &list->entries[i];
        memset(entry, 0, sizeof(profile_cache_entry_t));

        const char *fp = (const char*)sqlite3_column_text(stmt, 0);
        if (fp) strncpy(entry->user_fingerprint, fp, sizeof(entry->user_fingerprint) - 1);

        const char *dn = (const char*)sqlite3_column_text(stmt, 1);
        if (dn) strncpy(entry->profile.display_name, dn, sizeof(entry->profile.display_name) - 1);

        const char *bio = (const char*)sqlite3_column_text(stmt, 2);
        if (bio) strncpy(entry->profile.bio, bio, sizeof(entry->profile.bio) - 1);

        const char *ah = (const char*)sqlite3_column_text(stmt, 3);
        if (ah) strncpy(entry->profile.avatar_hash, ah, sizeof(entry->profile.avatar_hash) - 1);

        const char *loc = (const char*)sqlite3_column_text(stmt, 4);
        if (loc) strncpy(entry->profile.location, loc, sizeof(entry->profile.location) - 1);

        const char *web = (const char*)sqlite3_column_text(stmt, 5);
        if (web) strncpy(entry->profile.website, web, sizeof(entry->profile.website) - 1);

        entry->profile.created_at = sqlite3_column_int64(stmt, 6);
        entry->profile.updated_at = sqlite3_column_int64(stmt, 7);
        entry->fetched_at = sqlite3_column_int64(stmt, 8);

        i++;
    }

    sqlite3_finalize(stmt);

    list->count = i;
    *list_out = list;
    return 0;
}

/**
 * Get profile count
 */
int profile_cache_count(void) {
    if (!g_db) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM profiles;";
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

/**
 * Clear all cached profiles
 */
int profile_cache_clear_all(void) {
    if (!g_db) {
        fprintf(stderr, "[PROFILE_CACHE] Database not initialized\n");
        return -1;
    }

    const char *sql = "DELETE FROM profiles;";
    char *err_msg = NULL;

    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[PROFILE_CACHE] Failed to clear profiles: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    printf("[PROFILE_CACHE] Cleared all profiles\n");
    return 0;
}

/**
 * Free profile list
 */
void profile_cache_free_list(profile_cache_list_t *list) {
    if (list) {
        if (list->entries) {
            free(list->entries);
        }
        free(list);
    }
}

/**
 * Close profile cache database
 */
void profile_cache_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        g_owner_identity[0] = '\0';
        printf("[PROFILE_CACHE] Closed database\n");
    }
}
