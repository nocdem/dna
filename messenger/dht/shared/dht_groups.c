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
#include "../core/dht_context.h"
#include "../crypto/utils/qgp_sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <openssl/evp.h>

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
static void generate_uuid_v4(char *uuid_out) {
    // Simple UUID v4 generation (random-based)
    unsigned char bytes[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(bytes, 1, 16, f);
        fclose(f);
    } else {
        // Fallback to rand()
        srand(time(NULL));
        for (int i = 0; i < 16; i++) {
            bytes[i] = rand() & 0xFF;
        }
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
}

// Helper: Compute SHA3-512 hash for DHT key (Category 5)
static void compute_dht_key(const char *group_uuid, char *key_out) {
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)group_uuid, strlen(group_uuid), hash) != 0) {
        // Fallback: clear output
        key_out[0] = '\0';
        return;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[128] = '\0';
}

// Helper: Serialize metadata to JSON string
static char* serialize_metadata(const dht_group_metadata_t *meta) {
    // Calculate required buffer size more accurately
    size_t base_size = 512 + strlen(meta->name) + strlen(meta->description);
    
    // Calculate actual members size: each member can be up to 32 chars + quotes (2) + comma (1) = 35
    size_t members_size = 0;
    for (uint32_t i = 0; i < meta->member_count; i++) {
        members_size += strlen(meta->members[i]) + 3;  // +3 for quotes and comma
    }
    members_size += 16;  // Extra margin for array brackets and final member
    
    char *json = malloc(base_size + members_size);
    if (!json) return NULL;

    char *ptr = json;
    ptr += sprintf(ptr, "{\"group_uuid\":\"%s\",", meta->group_uuid);
    ptr += sprintf(ptr, "\"name\":\"%s\",", meta->name);
    ptr += sprintf(ptr, "\"description\":\"%s\",", meta->description);
    ptr += sprintf(ptr, "\"creator\":\"%s\",", meta->creator);
    ptr += sprintf(ptr, "\"created_at\":%lu,", (unsigned long)meta->created_at);
    ptr += sprintf(ptr, "\"version\":%u,", meta->version);
    ptr += sprintf(ptr, "\"member_count\":%u,", meta->member_count);
    ptr += sprintf(ptr, "\"members\":[");

    for (uint32_t i = 0; i < meta->member_count; i++) {
        if (i > 0) ptr += sprintf(ptr, ",");
        ptr += sprintf(ptr, "\"%s\"", meta->members[i]);
    }
    ptr += sprintf(ptr, "]}");

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
    sscanf(p, "%32[^\"]", meta->creator);

    // Parse timestamps and version
    p = strstr(p, "\"created_at\":");
    if (!p) goto error;
    sscanf(p + 13, "%lu", (unsigned long*)&meta->created_at);

    p = strstr(p, "\"version\":");
    if (!p) goto error;
    sscanf(p + 10, "%u", &meta->version);

    p = strstr(p, "\"member_count\":");
    if (!p) goto error;
    sscanf(p + 15, "%u", &meta->member_count);

    // Parse members array
    p = strstr(p, "\"members\":[");
    if (!p) goto error;
    p += 11;

    if (meta->member_count > 0) {
        meta->members = malloc(sizeof(char*) * meta->member_count);
        if (!meta->members) goto error;

        for (uint32_t i = 0; i < meta->member_count; i++) {
            meta->members[i] = malloc(33);
            if (!meta->members[i]) goto error;

            p = strchr(p, '"');
            if (!p) goto error;
            p++;
            sscanf(p, "%32[^\"]", meta->members[i]);
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
        fprintf(stderr, "[DHT GROUPS] Already initialized\n");
        return 0;
    }

    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DHT GROUPS] Failed to open database: %s\n", sqlite3_errmsg(g_db));
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
        fprintf(stderr, "[DHT GROUPS] Failed to create tables: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    printf("[DHT GROUPS] Initialized with database: %s\n", db_path);
    return 0;
}

// Cleanup DHT groups subsystem
void dht_groups_cleanup(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        printf("[DHT GROUPS] Cleanup complete\n");
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
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to create\n");
        return -1;
    }

    // Generate UUID
    char group_uuid[37];
    generate_uuid_v4(group_uuid);
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
        fprintf(stderr, "[DHT GROUPS] Failed to allocate members array\n");
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
        fprintf(stderr, "[DHT GROUPS] Failed to serialize metadata\n");
        for (uint32_t i = 0; i < meta.member_count; i++) free(meta.members[i]);
        free(meta.members);
        return -1;
    }

    // Compute DHT key
    char dht_key[129];
    compute_dht_key(group_uuid, dht_key);

    // Store in DHT
    int ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), (uint8_t*)json, strlen(json));
    if (ret != 0) {
        fprintf(stderr, "[DHT GROUPS] Failed to store in DHT\n");
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

    printf("[DHT GROUPS] Created group %s (%s)\n", name, group_uuid);
    return 0;
}

// Get group metadata from DHT
int dht_groups_get(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    dht_group_metadata_t **metadata_out
) {
    if (!dht_ctx || !group_uuid || !metadata_out) {
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to get\n");
        return -1;
    }

    // Compute DHT key
    char dht_key[129];
    compute_dht_key(group_uuid, dht_key);

    // Retrieve from DHT
    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &value, &value_len);
    if (ret != 0 || !value || value_len == 0) {
        fprintf(stderr, "[DHT GROUPS] Group not found in DHT: %s\n", group_uuid);
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
        fprintf(stderr, "[DHT GROUPS] Failed to deserialize metadata\n");
        return -1;
    }

    printf("[DHT GROUPS] Retrieved group %s from DHT\n", group_uuid);
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
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to update\n");
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
        fprintf(stderr, "[DHT GROUPS] Unauthorized update attempt by %s\n", updater);
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

    char dht_key[129];
    compute_dht_key(group_uuid, dht_key);

    ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), (uint8_t*)json, strlen(json));
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != 0) {
        fprintf(stderr, "[DHT GROUPS] Failed to update DHT\n");
        return -1;
    }

    printf("[DHT GROUPS] Updated group %s\n", group_uuid);
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
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to add_member\n");
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
        fprintf(stderr, "[DHT GROUPS] Unauthorized add_member by %s\n", adder);
        dht_groups_free_metadata(meta);
        return -2;
    }

    // Check if already member
    for (uint32_t i = 0; i < meta->member_count; i++) {
        if (strcmp(meta->members[i], new_member) == 0) {
            fprintf(stderr, "[DHT GROUPS] Already a member: %s\n", new_member);
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

    char dht_key[129];
    compute_dht_key(group_uuid, dht_key);

    ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), (uint8_t*)json, strlen(json));
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != 0) {
        fprintf(stderr, "[DHT GROUPS] Failed to add member to DHT\n");
        return -1;
    }

    printf("[DHT GROUPS] Added member %s to group %s\n", new_member, group_uuid);
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
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to remove_member\n");
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
        fprintf(stderr, "[DHT GROUPS] Unauthorized remove_member by %s\n", remover);
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
        fprintf(stderr, "[DHT GROUPS] Member not found: %s\n", member);
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

    char dht_key[129];
    compute_dht_key(group_uuid, dht_key);

    ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), (uint8_t*)json, strlen(json));
    free(json);
    dht_groups_free_metadata(meta);

    if (ret != 0) {
        fprintf(stderr, "[DHT GROUPS] Failed to remove member from DHT\n");
        return -1;
    }

    printf("[DHT GROUPS] Removed member %s from group %s\n", member, group_uuid);
    return 0;
}

// Delete group from DHT
int dht_groups_delete(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *deleter
) {
    if (!dht_ctx || !group_uuid || !deleter) {
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to delete\n");
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
        fprintf(stderr, "[DHT GROUPS] Unauthorized delete attempt by %s\n", deleter);
        dht_groups_free_metadata(meta);
        return -2;
    }

    dht_groups_free_metadata(meta);

    // Delete from DHT (store empty value)
    char dht_key[129];
    compute_dht_key(group_uuid, dht_key);

    // OpenDHT doesn't have explicit delete, so store a tombstone
    const char *tombstone = "{\"deleted\":true}";
    ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), (uint8_t*)tombstone, strlen(tombstone));

    if (ret != 0) {
        fprintf(stderr, "[DHT GROUPS] Failed to delete from DHT\n");
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

    printf("[DHT GROUPS] Deleted group %s\n", group_uuid);
    return 0;
}

// List all groups for a specific user (from local cache)
int dht_groups_list_for_user(
    const char *identity,
    dht_group_cache_entry_t **groups_out,
    int *count_out
) {
    if (!identity || !groups_out || !count_out || !g_db) {
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to list_for_user (identity=%p, groups_out=%p, count_out=%p, g_db=%p)\n",
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
        fprintf(stderr, "[DHT GROUPS] Failed to prepare query: %s\n", sqlite3_errmsg(g_db));
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
        strncpy(groups[count].group_uuid, (const char*)sqlite3_column_text(stmt, 1), 36);
        groups[count].group_uuid[36] = '\0';
        strncpy(groups[count].name, (const char*)sqlite3_column_text(stmt, 2), 127);
        groups[count].name[127] = '\0';
        strncpy(groups[count].creator, (const char*)sqlite3_column_text(stmt, 3), 32);
        groups[count].creator[32] = '\0';
        groups[count].created_at = sqlite3_column_int64(stmt, 4);
        groups[count].last_sync = sqlite3_column_int64(stmt, 5);

        count++;
    }

    sqlite3_finalize(stmt);

    *groups_out = groups;
    *count_out = count;

    printf("[DHT GROUPS] Listed %d groups for user %s\n", count, identity);
    return 0;
}

// Get group UUID from local group ID (Phase 6.1)
int dht_groups_get_uuid_by_local_id(
    const char *identity,
    int local_id,
    char *uuid_out
) {
    if (!identity || !uuid_out || !g_db) {
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to get_uuid_by_local_id\n");
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
        fprintf(stderr, "[DHT GROUPS] Failed to prepare query: %s\n", sqlite3_errmsg(g_db));
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
        printf("[DHT GROUPS] Mapped local_id %d to UUID %s for user %s\n", local_id, uuid_out, identity);
    } else {
        fprintf(stderr, "[DHT GROUPS] local_id %d not found for user %s\n", local_id, identity);
    }

    return result;
}

// Sync group metadata from DHT to local cache
int dht_groups_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *group_uuid
) {
    if (!dht_ctx || !group_uuid || !g_db) {
        fprintf(stderr, "[DHT GROUPS] Invalid arguments to sync_from_dht\n");
        return -1;
    }

    // Get from DHT
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return ret;
    }

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
        const char *insert_sql = "INSERT INTO dht_group_members (group_uuid, member_identity) VALUES (?, ?)";
        sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, meta->members[i], -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    dht_groups_free_metadata(meta);

    printf("[DHT GROUPS] Synced group %s from DHT to local cache\n", group_uuid);
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
    if (entries) {
        free(entries);
    }
}
