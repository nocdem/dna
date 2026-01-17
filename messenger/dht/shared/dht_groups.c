/**
 * DHT-based Group Management Implementation
 * Phase 3: Decentralized group chat
 *
 * Storage Architecture:
 * - Group metadata stored in DHT (distributed)
 * - Group messages stored in local SQLite (per-user)
 * - Member lists maintained in DHT
 * - Local cache in SQLite for fast lookups
 */

#include "dht_groups.h"
#include "dht_chunked.h"
#include "../core/dht_context.h"
#include "../../crypto/utils/qgp_sha3.h"
#include "../../crypto/utils/qgp_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include "../crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_GROUPS"

// Helper: Escape string for JSON (prevents injection attacks)
// Caller must free() the returned string
static char* json_escape_string(const char *str) {
    if (!str) return strdup("");

    size_t len = strlen(str);
    // Worst case: every char needs escaping (e.g., \n -> \\n = 2 chars)
    char *escaped = malloc(len * 2 + 1);
    if (!escaped) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        switch (c) {
            case '"':
                escaped[j++] = '\\';
                escaped[j++] = '"';
                break;
            case '\\':
                escaped[j++] = '\\';
                escaped[j++] = '\\';
                break;
            case '\n':
                escaped[j++] = '\\';
                escaped[j++] = 'n';
                break;
            case '\r':
                escaped[j++] = '\\';
                escaped[j++] = 'r';
                break;
            case '\t':
                escaped[j++] = '\\';
                escaped[j++] = 't';
                break;
            default:
                // Skip other control characters (< 0x20) for safety
                if (c >= 0x20) {
                    escaped[j++] = c;
                }
                break;
        }
    }
    escaped[j] = '\0';

    return escaped;
}

// Global database connection for group cache
static sqlite3 *g_db = NULL;

// SQL schema for local group cache
static const char *GROUP_CACHE_SCHEMA =
    "CREATE TABLE IF NOT EXISTS dht_group_cache ("
    "    local_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    group_uuid TEXT UNIQUE NOT NULL,"
    "    name TEXT NOT NULL,"
    "    creator TEXT NOT NULL,"
    "    created_at INTEGER NOT NULL,"
    "    last_sync INTEGER DEFAULT 0,"
    "    UNIQUE(group_uuid)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_group_uuid ON dht_group_cache(group_uuid);"
    ""
    "CREATE TABLE IF NOT EXISTS dht_group_members ("
    "    group_uuid TEXT NOT NULL,"
    "    member_identity TEXT NOT NULL,"
    "    added_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "    PRIMARY KEY (group_uuid, member_identity),"
    "    FOREIGN KEY (group_uuid) REFERENCES dht_group_cache(group_uuid) ON DELETE CASCADE"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_member_identity ON dht_group_members(member_identity);";

// Helper: Generate UUID v4
// Returns: 0 on success, -1 on failure
static int generate_uuid_v4(char *uuid_out) {
    // UUID v4 generation using cryptographically secure randomness
    unsigned char bytes[16];

    // Use qgp_randombytes for cryptographically secure random generation
    // This uses getrandom() on Linux or BCryptGenRandom() on Windows
    if (qgp_randombytes(bytes, 16) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate UUID: no secure randomness available\n");
        return -1;
    }

    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  // Version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  // Variant RFC 4122

    snprintf(uuid_out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);

    return 0;  // Success
}

// Helper: Create base key for chunked layer (handles hashing internally)
static void make_base_key(const char *group_uuid, char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "dht:group:%s", group_uuid);
}

// Helper: Serialize metadata to JSON string
static char* serialize_metadata(const dht_group_metadata_t *meta) {
    // Escape user-provided strings to prevent JSON injection
    char *escaped_name = json_escape_string(meta->name);
    char *escaped_desc = json_escape_string(meta->description);
    if (!escaped_name || !escaped_desc) {
        free(escaped_name);
        free(escaped_desc);
        return NULL;
    }

    // Calculate required buffer size with escaped strings
    size_t base_size = 512 + strlen(escaped_name) + strlen(escaped_desc);

    // Calculate actual members size: each member can be up to 128 chars + quotes (2) + comma (1)
    size_t members_size = 0;
    for (uint32_t i = 0; i < meta->member_count; i++) {
        members_size += strlen(meta->members[i]) + 3;  // +3 for quotes and comma
    }
    members_size += 16;  // Extra margin for array brackets and final member

    char *json = malloc(base_size + members_size);
    if (!json) {
        free(escaped_name);
        free(escaped_desc);
        return NULL;
    }

    char *ptr = json;
    ptr += sprintf(ptr, "{\"group_uuid\":\"%s\",", meta->group_uuid);
    ptr += sprintf(ptr, "\"name\":\"%s\",", escaped_name);
    ptr += sprintf(ptr, "\"description\":\"%s\",", escaped_desc);
    ptr += sprintf(ptr, "\"creator\":\"%s\",", meta->creator);
    ptr += sprintf(ptr, "\"created_at\":%lu,", (unsigned long)meta->created_at);
    ptr += sprintf(ptr, "\"version\":%u,", meta->version);
    ptr += sprintf(ptr, "\"gek_version\":%u,", meta->gek_version);
    ptr += sprintf(ptr, "\"member_count\":%u,", meta->member_count);
    ptr += sprintf(ptr, "\"members\":[");

    for (uint32_t i = 0; i < meta->member_count; i++) {
        if (i > 0) ptr += sprintf(ptr, ",");
        ptr += sprintf(ptr, "\"%s\"", meta->members[i]);
    }
    ptr += sprintf(ptr, "]}");

    free(escaped_name);
    free(escaped_desc);

    return json;
}

// Helper: Deserialize metadata from JSON string
static int deserialize_metadata(const char *json, dht_group_metadata_t **meta_out) {
    dht_group_metadata_t *meta = malloc(sizeof(dht_group_metadata_t));
    if (!meta) return -1;

    memset(meta, 0, sizeof(dht_group_metadata_t));

    // Simple JSON parsing (for production, use json-c)
    const char *p = json;

    // Parse group_uuid
    p = strstr(p, "\"group_uuid\":\"");
    if (!p) goto error;
    p += 14;
    sscanf(p, "%36[^\"]", meta->group_uuid);

    // Parse name
    p = strstr(p, "\"name\":\"");
    if (!p) goto error;
    p += 8;
    sscanf(p, "%127[^\"]", meta->name);

    // Parse description
    p = strstr(p, "\"description\":\"");
    if (!p) goto error;
    p += 15;
    sscanf(p, "%511[^\"]", meta->description);

    // Parse creator
    p = strstr(p, "\"creator\":\"");
    if (!p) goto error;
    p += 11;
    sscanf(p, "%128[^\"]", meta->creator);  // Read full 128-char fingerprint

    // Parse timestamps and version
    p = strstr(p, "\"created_at\":");
    if (!p) goto error;
    sscanf(p + 13, "%lu", (unsigned long*)&meta->created_at);

    p = strstr(p, "\"version\":");
    if (!p) goto error;
    sscanf(p + 10, "%u", &meta->version);

    // Parse gek_version (optional for backward compatibility)
    const char *gek_p = strstr(p, "\"gek_version\":");
    if (gek_p) {
        sscanf(gek_p + 14, "%u", &meta->gek_version);
    } else {
        meta->gek_version = 1;  // Default to v1 for old groups
    }

    p = strstr(p, "\"member_count\":");
    if (!p) goto error;
    sscanf(p + 15, "%u", &meta->member_count);

    // Parse members array
    p = strstr(p, "\"members\":[");
    if (!p) goto error;
    p += 11;

    if (meta->member_count > 0) {
        meta->members = calloc(meta->member_count, sizeof(char*));
        if (!meta->members) goto error;

        for (uint32_t i = 0; i < meta->member_count; i++) {
            meta->members[i] = calloc(129, 1);  // 128 chars + null, zero-initialized
            if (!meta->members[i]) goto error;

            p = strchr(p, '"');
            if (!p) {
                QGP_LOG_ERROR(LOG_TAG, "Parse error: no opening quote for member[%u]\n", i);
                goto error;
            }
            p++;
            int chars_read = 0;
            sscanf(p, "%128[^\"]%n", meta->members[i], &chars_read);
            QGP_LOG_DEBUG(LOG_TAG, "Parsed member[%u]: '%s' (read %d chars)\n", i, meta->members[i], chars_read);

            // Validate: fingerprint must be 128 hex chars
            size_t len = strlen(meta->members[i]);
            if (len != 128) {
                QGP_LOG_ERROR(LOG_TAG, "Invalid member[%u] length: %zu (expected 128)\n", i, len);
                goto error;
            }

            p = strchr(p, '"');  // Find closing quote
            if (p) p++;          // Move past it
        }
    }

    *meta_out = meta;
    return 0;

error:
    dht_groups_free_metadata(meta);
    return -1;
}

// Initialize DHT groups subsystem
int dht_groups_init(const char *db_path) {
    if (g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Already initialized\n");
        return 0;
    }

    // Open with FULLMUTEX for thread safety (DHT callbacks + main thread)
    int rc = sqlite3_open_v2(db_path, &g_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Enable foreign keys
    sqlite3_exec(g_db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);

    // Create tables
    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, GROUP_CACHE_SCHEMA, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create tables: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized with database: %s\n", db_path);
    return 0;
}

// Cleanup DHT groups subsystem
void dht_groups_cleanup(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Cleanup complete\n");
    }
}

// Create a new group in DHT
int dht_groups_create(
    dht_context_t *dht_ctx,
    const char *name,
    const char *description,
    const char *creator,
    const char **members,
    size_t member_count,
    char *group_uuid_out
) {
    if (!dht_ctx || !name || !creator || !group_uuid_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to create\n");
        return -1;
    }

    // Generate UUID
    char group_uuid[37];
    if (generate_uuid_v4(group_uuid) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate UUID for group\n");
        return -1;
    }
    strcpy(group_uuid_out, group_uuid);

    // Build metadata
    dht_group_metadata_t meta;
    memset(&meta, 0, sizeof(meta));
    strcpy(meta.group_uuid, group_uuid);
    strncpy(meta.name, name, sizeof(meta.name) - 1);
    if (description) {
        strncpy(meta.description, description, sizeof(meta.description) - 1);
    }
    strncpy(meta.creator, creator, sizeof(meta.creator) - 1);
    meta.created_at = time(NULL);
    meta.version = 1;
    meta.member_count = member_count + 1;  // +1 for creator

    // Allocate members array (creator + provided members)
    meta.members = malloc(sizeof(char*) * meta.member_count);
    if (!meta.members) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate members array\n");
        return -1;
    }

    // Add creator as first member
    meta.members[0] = strdup(creator);

    // Add provided members
    for (size_t i = 0; i < member_count; i++) {
        meta.members[i + 1] = strdup(members[i]);
    }

    // Serialize to JSON
    char *json = serialize_metadata(&meta);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize metadata\n");
        for (uint32_t i = 0; i < meta.member_count; i++) free(meta.members[i]);
        free(meta.members);
        return -1;
    }

    // Create base key for chunked layer
    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    // Store in DHT via chunked layer (30-day TTL for group metadata)
    int ret = dht_chunked_publish(dht_ctx, base_key, (uint8_t*)json, strlen(json), DHT_CHUNK_TTL_30DAY);
    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT: %s\n", dht_chunked_strerror(ret));
        free(json);
        for (uint32_t i = 0; i < meta.member_count; i++) free(meta.members[i]);
        free(meta.members);
        return -1;
    }

    free(json);

    // Add to local cache
    if (g_db) {
        sqlite3_stmt *stmt = NULL;
        const char *sql = "INSERT INTO dht_group_cache (group_uuid, name, creator, created_at, last_sync) "
                         "VALUES (?, ?, ?, ?, ?)";
        sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, creator, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, meta.created_at);
        sqlite3_bind_int64(stmt, 5, time(NULL));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Add members to cache
        for (uint32_t i = 0; i < meta.member_count; i++) {
            const char *member_sql = "INSERT INTO dht_group_members (group_uuid, member_identity) VALUES (?, ?)";
            sqlite3_prepare_v2(g_db, member_sql, -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, meta.members[i], -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // Cleanup
    for (uint32_t i = 0; i < meta.member_count; i++) free(meta.members[i]);
    free(meta.members);

    QGP_LOG_INFO(LOG_TAG, "Created group %s (%s)\n", name, group_uuid);
    return 0;
}

// Get group metadata from DHT
int dht_groups_get(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    dht_group_metadata_t **metadata_out
) {
    if (!dht_ctx || !group_uuid || !metadata_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get\n");
        return -1;
    }

    // Create base key for chunked layer
    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    // Retrieve from DHT via chunked layer
    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);
    if (ret != DHT_CHUNK_OK || !value || value_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Group not found in DHT: %s (%s)\n", group_uuid, dht_chunked_strerror(ret));
        if (value) free(value);
        return -2;  // Not found
    }

    // Null-terminate JSON
    char *json = malloc(value_len + 1);
    if (!json) {
        free(value);
        return -1;
    }
    memcpy(json, value, value_len);
    json[value_len] = '\0';
    free(value);

    // Deserialize
    ret = deserialize_metadata(json, metadata_out);
    free(json);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize metadata\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved group %s from DHT\n", group_uuid);
    return 0;
}

// Update group metadata in DHT
int dht_groups_update(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *new_name,
    const char *new_description,
    const char *updater
) {
    if (!dht_ctx || !group_uuid || !updater) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to update\n");
        return -1;
    }

    // Get current metadata
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return ret;
    }

    // Check authorization (creator or member can update)
    bool authorized = (strcmp(meta->creator, updater) == 0);
    if (!authorized) {
        for (uint32_t i = 0; i < meta->member_count; i++) {
            if (strcmp(meta->members[i], updater) == 0) {
                authorized = true;
                break;
            }
        }
    }

    if (!authorized) {
        QGP_LOG_ERROR(LOG_TAG, "Unauthorized update attempt by %s\n", updater);
        dht_groups_free_metadata(meta);
        return -2;  // Not authorized
    }

    // Update fields
    if (new_name) {
        strncpy(meta->name, new_name, sizeof(meta->name) - 1);
    }
    if (new_description) {
        strncpy(meta->description, new_description, sizeof(meta->description) - 1);
    }
    meta->version++;

    // Serialize and store
    char *json = serialize_metadata(meta);
    if (!json) {
        dht_groups_free_metadata(meta);
        return -1;
    }

    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    ret = dht_chunked_publish(dht_ctx, base_key, (uint8_t*)json, strlen(json), DHT_CHUNK_TTL_30DAY);
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Updated group %s\n", group_uuid);
    return 0;
}

// Add member to group
int dht_groups_add_member(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *new_member,
    const char *adder
) {
    if (!dht_ctx || !group_uuid || !new_member || !adder) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to add_member\n");
        return -1;
    }

    // Get current metadata
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return ret;
    }

    // Check authorization (creator or member can add)
    bool authorized = (strcmp(meta->creator, adder) == 0);
    if (!authorized) {
        for (uint32_t i = 0; i < meta->member_count; i++) {
            if (strcmp(meta->members[i], adder) == 0) {
                authorized = true;
                break;
            }
        }
    }

    if (!authorized) {
        QGP_LOG_ERROR(LOG_TAG, "Unauthorized add_member by %s\n", adder);
        dht_groups_free_metadata(meta);
        return -2;
    }

    // Check if already member
    for (uint32_t i = 0; i < meta->member_count; i++) {
        if (strcmp(meta->members[i], new_member) == 0) {
            QGP_LOG_ERROR(LOG_TAG, "Already a member: %s\n", new_member);
            dht_groups_free_metadata(meta);
            return -3;
        }
    }

    // Add member
    char **new_members = realloc(meta->members, sizeof(char*) * (meta->member_count + 1));
    if (!new_members) {
        dht_groups_free_metadata(meta);
        return -1;
    }
    meta->members = new_members;
    meta->members[meta->member_count] = strdup(new_member);
    meta->member_count++;
    meta->version++;

    // Serialize and store
    char *json = serialize_metadata(meta);
    if (!json) {
        dht_groups_free_metadata(meta);
        return -1;
    }

    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    ret = dht_chunked_publish(dht_ctx, base_key, (uint8_t*)json, strlen(json), DHT_CHUNK_TTL_30DAY);
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add member to DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added member %s to group %s\n", new_member, group_uuid);
    return 0;
}

// Remove member from group
int dht_groups_remove_member(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *member,
    const char *remover
) {
    if (!dht_ctx || !group_uuid || !member || !remover) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to remove_member\n");
        return -1;
    }

    // Get current metadata
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return ret;
    }

    // Check authorization (creator or self can remove)
    bool authorized = (strcmp(meta->creator, remover) == 0) || (strcmp(member, remover) == 0);

    if (!authorized) {
        QGP_LOG_ERROR(LOG_TAG, "Unauthorized remove_member by %s\n", remover);
        dht_groups_free_metadata(meta);
        return -2;
    }

    // Find and remove member
    int found_idx = -1;
    for (uint32_t i = 0; i < meta->member_count; i++) {
        if (strcmp(meta->members[i], member) == 0) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == -1) {
        QGP_LOG_ERROR(LOG_TAG, "Member not found: %s\n", member);
        dht_groups_free_metadata(meta);
        return -1;
    }

    // Remove from array
    free(meta->members[found_idx]);
    for (uint32_t i = found_idx; i < meta->member_count - 1; i++) {
        meta->members[i] = meta->members[i + 1];
    }
    meta->member_count--;
    meta->version++;

    // Serialize and store
    char *json = serialize_metadata(meta);
    if (!json) {
        dht_groups_free_metadata(meta);
        return -1;
    }

    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    ret = dht_chunked_publish(dht_ctx, base_key, (uint8_t*)json, strlen(json), DHT_CHUNK_TTL_30DAY);
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove member from DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Removed member %s from group %s\n", member, group_uuid);
    return 0;
}

// Update GEK version in group metadata
int dht_groups_update_gek_version(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    uint32_t new_gek_version
) {
    if (!dht_ctx || !group_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to update_gek_version\n");
        return -1;
    }

    // Get current metadata
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group metadata for GEK version update\n");
        return ret;
    }

    // Update GEK version
    meta->gek_version = new_gek_version;
    meta->version++;  // Increment metadata version

    // Serialize and store
    char *json = serialize_metadata(meta);
    if (!json) {
        dht_groups_free_metadata(meta);
        return -1;
    }

    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    ret = dht_chunked_publish(dht_ctx, base_key, (uint8_t*)json, strlen(json), DHT_CHUNK_TTL_30DAY);
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update GEK version in DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Updated GEK version to %u for group %s\n", new_gek_version, group_uuid);
    return 0;
}

// Delete group from DHT
int dht_groups_delete(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *deleter
) {
    if (!dht_ctx || !group_uuid || !deleter) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to delete\n");
        return -1;
    }

    // Get current metadata
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return ret;
    }

    // Check authorization (only creator can delete)
    if (strcmp(meta->creator, deleter) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Unauthorized delete attempt by %s\n", deleter);
        dht_groups_free_metadata(meta);
        return -2;
    }

    dht_groups_free_metadata(meta);

    // Delete from DHT via chunked layer
    char base_key[256];
    make_base_key(group_uuid, base_key, sizeof(base_key));

    // Chunked layer has explicit delete
    ret = dht_chunked_delete(dht_ctx, base_key, 0);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete from DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    // Remove from local cache
    if (g_db) {
        sqlite3_stmt *stmt = NULL;
        const char *sql = "DELETE FROM dht_group_cache WHERE group_uuid = ?";
        sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted group %s\n", group_uuid);
    return 0;
}

// List all groups for a specific user (from local cache)
int dht_groups_list_for_user(
    const char *identity,
    dht_group_cache_entry_t **groups_out,
    int *count_out
) {
    if (!identity || !groups_out || !count_out || !g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to list_for_user (identity=%p, groups_out=%p, count_out=%p, g_db=%p)\n",
                (void*)identity, (void*)groups_out, (void*)count_out, (void*)g_db);
        return -1;
    }

    *groups_out = NULL;
    *count_out = 0;

    // Query groups where user is a member
    const char *sql =
        "SELECT DISTINCT c.local_id, c.group_uuid, c.name, c.creator, c.created_at, c.last_sync "
        "FROM dht_group_cache c "
        "INNER JOIN dht_group_members m ON c.group_uuid = m.group_uuid "
        "WHERE m.member_identity = ? "
        "ORDER BY c.created_at DESC";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);

    // Count results first
    int capacity = 16;
    dht_group_cache_entry_t *groups = malloc(sizeof(dht_group_cache_entry_t) * capacity);
    if (!groups) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            capacity *= 2;
            dht_group_cache_entry_t *new_groups = realloc(groups, sizeof(dht_group_cache_entry_t) * capacity);
            if (!new_groups) {
                free(groups);
                sqlite3_finalize(stmt);
                return -1;
            }
            groups = new_groups;
        }

        groups[count].local_id = sqlite3_column_int(stmt, 0);

        const char *db_uuid = (const char*)sqlite3_column_text(stmt, 1);
        const char *db_name = (const char*)sqlite3_column_text(stmt, 2);
        const char *db_creator = (const char*)sqlite3_column_text(stmt, 3);

        QGP_LOG_WARN(LOG_TAG, ">>> ROW[%d]: uuid=%s name=%s creator_len=%zu",
                     count,
                     db_uuid ? db_uuid : "(null)",
                     db_name ? db_name : "(null)",
                     db_creator ? strlen(db_creator) : 0);

        strncpy(groups[count].group_uuid, db_uuid ? db_uuid : "", 36);
        groups[count].group_uuid[36] = '\0';
        strncpy(groups[count].name, db_name ? db_name : "", 127);
        groups[count].name[127] = '\0';
        strncpy(groups[count].creator, db_creator ? db_creator : "", 128);
        groups[count].creator[128] = '\0';
        groups[count].created_at = sqlite3_column_int64(stmt, 4);
        groups[count].last_sync = sqlite3_column_int64(stmt, 5);

        count++;
    }

    sqlite3_finalize(stmt);

    *groups_out = groups;
    *count_out = count;

    QGP_LOG_INFO(LOG_TAG, "Listed %d groups for user %s\n", count, identity);
    return 0;
}

// Get single group cache entry by UUID
int dht_groups_get_cache_entry(
    const char *group_uuid,
    dht_group_cache_entry_t **entry_out
) {
    if (!group_uuid || !entry_out || !g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_cache_entry\n");
        return -1;
    }

    *entry_out = NULL;

    const char *sql =
        "SELECT local_id, group_uuid, name, creator, created_at, last_sync "
        "FROM dht_group_cache WHERE group_uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  // Not found
    }

    dht_group_cache_entry_t *entry = malloc(sizeof(dht_group_cache_entry_t));
    if (!entry) {
        sqlite3_finalize(stmt);
        return -1;
    }

    entry->local_id = sqlite3_column_int(stmt, 0);

    const char *db_uuid = (const char*)sqlite3_column_text(stmt, 1);
    const char *db_name = (const char*)sqlite3_column_text(stmt, 2);
    const char *db_creator = (const char*)sqlite3_column_text(stmt, 3);

    strncpy(entry->group_uuid, db_uuid ? db_uuid : "", 36);
    entry->group_uuid[36] = '\0';
    strncpy(entry->name, db_name ? db_name : "", 127);
    entry->name[127] = '\0';
    strncpy(entry->creator, db_creator ? db_creator : "", 128);
    entry->creator[128] = '\0';
    entry->created_at = sqlite3_column_int64(stmt, 4);
    entry->last_sync = sqlite3_column_int64(stmt, 5);

    sqlite3_finalize(stmt);

    *entry_out = entry;
    return 0;
}

// Get group UUID from local group ID (Phase 6.1)
int dht_groups_get_uuid_by_local_id(
    const char *identity,
    int local_id,
    char *uuid_out
) {
    if (!identity || !uuid_out || !g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_uuid_by_local_id\n");
        return -1;
    }

    // Query local cache for UUID by local_id
    // User must be a member of the group (security check)
    const char *sql =
        "SELECT c.group_uuid "
        "FROM dht_group_cache c "
        "INNER JOIN dht_group_members m ON c.group_uuid = m.group_uuid "
        "WHERE c.local_id = ? AND m.member_identity = ? "
        "LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, local_id);
    sqlite3_bind_text(stmt, 2, identity, -1, SQLITE_STATIC);

    int result = -2;  // Not found by default
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *uuid = (const char*)sqlite3_column_text(stmt, 0);
        if (uuid) {
            strncpy(uuid_out, uuid, 36);
            uuid_out[36] = '\0';
            result = 0;
        }
    }

    sqlite3_finalize(stmt);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Mapped local_id %d to UUID %s for user %s\n", local_id, uuid_out, identity);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "local_id %d not found for user %s\n", local_id, identity);
    }

    return result;
}

// Get local group ID from group UUID (Phase 7 - Group Messages)
int dht_groups_get_local_id_by_uuid(
    const char *identity,
    const char *group_uuid,
    int *local_id_out
) {
    if (!identity || !group_uuid || !local_id_out || !g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_local_id_by_uuid\n");
        return -1;
    }

    // Query local cache for local_id by group_uuid
    // User must be a member of the group (security check)
    const char *sql =
        "SELECT c.local_id "
        "FROM dht_group_cache c "
        "INNER JOIN dht_group_members m ON c.group_uuid = m.group_uuid "
        "WHERE c.group_uuid = ? AND m.member_identity = ? "
        "LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, identity, -1, SQLITE_STATIC);

    int result = -2;  // Not found by default
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *local_id_out = sqlite3_column_int(stmt, 0);
        result = 0;
    }

    sqlite3_finalize(stmt);

    if (result == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "Mapped UUID %s to local_id %d for user %.16s...\n",
                     group_uuid, *local_id_out, identity);
    } else {
        QGP_LOG_WARN(LOG_TAG, "UUID %s not found for user %.16s...\n", group_uuid, identity);
    }

    return result;
}

// Sync group metadata from DHT to local cache
int dht_groups_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *group_uuid
) {
    if (!dht_ctx || !group_uuid || !g_db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sync_from_dht\n");
        return -1;
    }

    // Get from DHT
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return ret;
    }

    // DEBUG: Log parsed metadata before writing to database
    QGP_LOG_WARN(LOG_TAG, "=== SYNC DEBUG: Parsed metadata ===\n");
    QGP_LOG_WARN(LOG_TAG, "  group_uuid: %s\n", meta->group_uuid ? meta->group_uuid : "(null)");
    QGP_LOG_WARN(LOG_TAG, "  name: %s\n", meta->name ? meta->name : "(null)");
    QGP_LOG_WARN(LOG_TAG, "  creator: %.32s...\n", meta->creator ? meta->creator : "(null)");
    QGP_LOG_WARN(LOG_TAG, "  member_count: %u\n", meta->member_count);
    for (uint32_t i = 0; i < meta->member_count && i < 10; i++) {
        if (meta->members && meta->members[i]) {
            size_t len = strlen(meta->members[i]);
            QGP_LOG_WARN(LOG_TAG, "  member[%u]: %.32s... (len=%zu)\n", i, meta->members[i], len);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "  member[%u]: NULL POINTER!\n", i);
        }
    }
    QGP_LOG_WARN(LOG_TAG, "=== END SYNC DEBUG ===\n");

    // Update local cache
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO dht_group_cache (group_uuid, name, creator, created_at, last_sync) "
        "VALUES (?, ?, ?, ?, ?)";

    sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, meta->group_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, meta->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, meta->creator, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, meta->created_at);
    sqlite3_bind_int64(stmt, 5, time(NULL));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Update members
    const char *delete_sql = "DELETE FROM dht_group_members WHERE group_uuid = ?";
    sqlite3_prepare_v2(g_db, delete_sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    for (uint32_t i = 0; i < meta->member_count; i++) {
        // Skip NULL members (defensive - shouldn't happen if parsing succeeded)
        if (!meta->members || !meta->members[i]) {
            QGP_LOG_ERROR(LOG_TAG, "NULL member[%u] - skipping\n", i);
            continue;
        }
        const char *insert_sql = "INSERT INTO dht_group_members (group_uuid, member_identity) VALUES (?, ?)";
        sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, meta->members[i], -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    dht_groups_free_metadata(meta);

    QGP_LOG_INFO(LOG_TAG, "Synced group %s from DHT to local cache\n", group_uuid);
    return 0;
}

// Free group metadata structure
void dht_groups_free_metadata(dht_group_metadata_t *metadata) {
    if (!metadata) return;

    if (metadata->members) {
        for (uint32_t i = 0; i < metadata->member_count; i++) {
            if (metadata->members[i]) {
                free(metadata->members[i]);
            }
        }
        free(metadata->members);
    }

    free(metadata);
}

// Free array of cache entries
void dht_groups_free_cache_entries(dht_group_cache_entry_t *entries, int count) {
    (void)count;
    if (entries) {
        free(entries);
    }
}

// Get member count for a group from local cache
int dht_groups_get_member_count(const char *group_uuid, int *count_out) {
    if (!g_db || !group_uuid || !count_out) {
        return -1;
    }

    *count_out = 0;

    const char *sql = "SELECT COUNT(*) FROM dht_group_members WHERE group_uuid = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *count_out = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return 0;
}

int dht_groups_get_members(const char *group_uuid, char ***members_out, int *count_out) {
    if (!g_db || !group_uuid || !members_out || !count_out) {
        return -1;
    }

    *members_out = NULL;
    *count_out = 0;

    /* First get count */
    int member_count = 0;
    if (dht_groups_get_member_count(group_uuid, &member_count) != 0 || member_count == 0) {
        return 0;  /* No members, not an error */
    }

    /* Allocate array */
    char **members = calloc(member_count, sizeof(char *));
    if (!members) {
        return -1;
    }

    /* Fetch members */
    const char *sql = "SELECT member_identity FROM dht_group_members WHERE group_uuid = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(members);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < member_count) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 0);
        if (fp) {
            members[idx] = strdup(fp);
            if (!members[idx]) {
                /* Cleanup on failure */
                for (int i = 0; i < idx; i++) free(members[i]);
                free(members);
                sqlite3_finalize(stmt);
                return -1;
            }
            idx++;
        }
    }

    sqlite3_finalize(stmt);

    *members_out = members;
    *count_out = idx;
    return 0;
}

void dht_groups_free_members(char **members, int count) {
    if (!members) return;
    for (int i = 0; i < count; i++) {
        free(members[i]);
    }
    free(members);
}
