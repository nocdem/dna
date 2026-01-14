/**
 * DHT-based Group Management
 * Phase 3: Decentralized group chat implementation
 *
 * Architecture:
 * - Group metadata stored in DHT (distributed)
 * - Group messages stored in local SQLite (per-user)
 * - Member lists maintained in DHT
 * - Group updates propagated via DHT put operations
 */

#ifndef DHT_GROUPS_H
#define DHT_GROUPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct dht_context dht_context_t;

/**
 * DHT Group Metadata
 * Stored in DHT at key: hash(group_uuid)
 */
typedef struct {
    char group_uuid[37];           // UUID v4 (36 chars + null)
    char name[128];                 // Group name
    char description[512];          // Group description
    char creator[129];              // Creator DNA fingerprint (128 hex chars + null)
    uint64_t created_at;            // Unix timestamp
    uint32_t version;               // Version number (for updates)
    uint32_t member_count;          // Number of members
    char **members;                 // Array of member identities
} dht_group_metadata_t;

/**
 * Local Group Cache Entry (SQLite)
 * Maps group_uuid to local group_id for efficient lookups
 */
typedef struct {
    int local_id;                   // Local database ID
    char group_uuid[37];            // Global group UUID
    char name[128];                 // Cached group name
    char creator[129];              // Creator fingerprint (128 hex chars + null)
    uint64_t created_at;            // Creation timestamp
    uint64_t last_sync;             // Last DHT sync timestamp
} dht_group_cache_entry_t;

/**
 * Initialize DHT groups subsystem
 * Creates SQLite tables for local group cache
 *
 * @param db_path: Path to SQLite database file
 * @return: 0 on success, -1 on error
 */
int dht_groups_init(const char *db_path);

/**
 * Cleanup DHT groups subsystem
 */
void dht_groups_cleanup(void);

/**
 * Create a new group in DHT
 *
 * @param dht_ctx: DHT context
 * @param name: Group name
 * @param description: Group description (can be NULL)
 * @param creator: Creator identity
 * @param members: Array of initial member identities (excluding creator)
 * @param member_count: Number of initial members
 * @param group_uuid_out: Output buffer for group UUID (37 bytes)
 * @return: 0 on success, -1 on error
 */
int dht_groups_create(
    dht_context_t *dht_ctx,
    const char *name,
    const char *description,
    const char *creator,
    const char **members,
    size_t member_count,
    char *group_uuid_out
);

/**
 * Get group metadata from DHT
 *
 * @param dht_ctx: DHT context
 * @param group_uuid: Group UUID
 * @param metadata_out: Output metadata structure (caller must free with dht_groups_free_metadata)
 * @return: 0 on success, -1 on error, -2 if not found
 */
int dht_groups_get(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    dht_group_metadata_t **metadata_out
);

/**
 * Update group metadata in DHT
 *
 * @param dht_ctx: DHT context
 * @param group_uuid: Group UUID
 * @param new_name: New group name (NULL to keep current)
 * @param new_description: New description (NULL to keep current)
 * @param updater: Identity making the update
 * @return: 0 on success, -1 on error, -2 if not authorized
 */
int dht_groups_update(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *new_name,
    const char *new_description,
    const char *updater
);

/**
 * Add member to group
 *
 * @param dht_ctx: DHT context
 * @param group_uuid: Group UUID
 * @param new_member: Identity to add
 * @param adder: Identity adding the member
 * @return: 0 on success, -1 on error, -2 if not authorized, -3 if already member
 */
int dht_groups_add_member(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *new_member,
    const char *adder
);

/**
 * Remove member from group
 *
 * @param dht_ctx: DHT context
 * @param group_uuid: Group UUID
 * @param member: Identity to remove
 * @param remover: Identity removing the member
 * @return: 0 on success, -1 on error, -2 if not authorized
 */
int dht_groups_remove_member(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *member,
    const char *remover
);

/**
 * Delete group from DHT
 * Only creator can delete
 *
 * @param dht_ctx: DHT context
 * @param group_uuid: Group UUID
 * @param deleter: Identity attempting deletion
 * @return: 0 on success, -1 on error, -2 if not authorized
 */
int dht_groups_delete(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *deleter
);

/**
 * List all groups for a specific user (from local cache)
 *
 * @param identity: User identity
 * @param groups_out: Output array of cache entries (caller must free)
 * @param count_out: Number of groups returned
 * @return: 0 on success, -1 on error
 */
int dht_groups_list_for_user(
    const char *identity,
    dht_group_cache_entry_t **groups_out,
    int *count_out
);

/**
 * Get group UUID from local group ID (Phase 6.1)
 *
 * Helper function to map local_id to group_uuid.
 * Useful for functions that receive local_id from GUI/API.
 *
 * @param identity: User identity (for per-user group cache)
 * @param local_id: Local group ID
 * @param uuid_out: Output buffer for UUID (37 bytes)
 * @return: 0 on success, -1 on error, -2 if not found
 */
int dht_groups_get_uuid_by_local_id(
    const char *identity,
    int local_id,
    char *uuid_out
);

/**
 * Get local group ID from group UUID (Phase 7 - Group Messages)
 *
 * Reverse helper function to map group_uuid to local_id.
 * Useful for functions that receive UUID from DHT/events.
 *
 * @param identity: User identity (for per-user group cache)
 * @param group_uuid: Group UUID (36 chars)
 * @param local_id_out: Output local group ID
 * @return: 0 on success, -1 on error, -2 if not found
 */
int dht_groups_get_local_id_by_uuid(
    const char *identity,
    const char *group_uuid,
    int *local_id_out
);

/**
 * Sync group metadata from DHT to local cache
 *
 * @param dht_ctx: DHT context
 * @param group_uuid: Group UUID
 * @return: 0 on success, -1 on error
 */
int dht_groups_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *group_uuid
);

/**
 * Get member count for a group from local cache
 *
 * Queries dht_group_members table for count.
 * Fast local lookup, no DHT query.
 *
 * @param group_uuid: Group UUID
 * @param count_out: Output member count
 * @return: 0 on success, -1 on error
 */
int dht_groups_get_member_count(
    const char *group_uuid,
    int *count_out
);

/**
 * Get member fingerprints for a group from local cache
 *
 * Queries dht_group_members table for member identities.
 * Fast local lookup, no DHT query.
 *
 * @param group_uuid: Group UUID
 * @param members_out: Output array of fingerprints (caller frees with dht_groups_free_members)
 * @param count_out: Number of members returned
 * @return: 0 on success, -1 on error
 */
int dht_groups_get_members(
    const char *group_uuid,
    char ***members_out,
    int *count_out
);

/**
 * Free member fingerprint array from dht_groups_get_members
 *
 * @param members: Array to free
 * @param count: Number of members
 */
void dht_groups_free_members(char **members, int count);

/**
 * Free group metadata structure
 *
 * @param metadata: Metadata to free
 */
void dht_groups_free_metadata(dht_group_metadata_t *metadata);

/**
 * Free array of cache entries
 *
 * @param entries: Array to free
 * @param count: Number of entries
 */
void dht_groups_free_cache_entries(dht_group_cache_entry_t *entries, int count);

#ifdef __cplusplus
}
#endif

#endif // DHT_GROUPS_H
