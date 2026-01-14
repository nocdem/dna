/**
 * @file groups.h
 * @brief Group Management for GEK System
 *
 * High-level group management functions for the GEK (Group Encryption Key) system.
 * Manages groups, members, and invitations using local database + DHT sync.
 *
 * Part of DNA Messenger - GEK System
 *
 * @date 2026-01-10
 */

#ifndef GROUPS_H
#define GROUPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * TYPES
 * ============================================================================ */

/**
 * Group info structure (from local database)
 */
typedef struct {
    char uuid[37];          // Group UUID (36 + null)
    char name[128];         // Group display name
    uint64_t created_at;    // Creation timestamp (Unix epoch)
    bool is_owner;          // True if we are the group owner
    char owner_fp[129];     // Owner fingerprint (128 hex + null)
} groups_info_t;

/**
 * Group member structure
 */
typedef struct {
    char fingerprint[129];  // Member fingerprint (128 hex + null)
    uint64_t added_at;      // When member was added
} groups_member_t;

/**
 * Pending invitation structure
 */
typedef struct {
    char group_uuid[37];    // Group UUID
    char group_name[128];   // Group display name
    char owner_fp[129];     // Owner fingerprint
    uint64_t received_at;   // When invitation was received
} groups_invitation_t;

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */

/**
 * Initialize groups subsystem
 *
 * @param backup_ctx Message backup context (provides database access)
 * @return 0 on success, -1 on error
 */
int groups_init(void *backup_ctx);

/* ============================================================================
 * GROUP MANAGEMENT
 * ============================================================================ */

/**
 * Create a new group
 *
 * Creates group in local database and generates initial GEK (v0).
 * Caller should then add members and publish to DHT.
 *
 * @param name Group display name
 * @param owner_fp Owner's fingerprint (our identity)
 * @param uuid_out Output buffer for generated UUID (37 bytes)
 * @return 0 on success, -1 on error
 */
int groups_create(const char *name, const char *owner_fp, char *uuid_out);

/**
 * Delete a group
 *
 * Removes group from local database. Only owner can delete.
 *
 * @param group_uuid Group UUID
 * @param my_fp My fingerprint (must match owner)
 * @return 0 on success, -1 on error (not owner, not found)
 */
int groups_delete(const char *group_uuid, const char *my_fp);

/**
 * List all groups user belongs to
 *
 * Returns groups from local database.
 *
 * @param groups_out Output array (allocated by function, caller must free)
 * @param count_out Output for number of groups
 * @return 0 on success, -1 on error
 */
int groups_list(groups_info_t **groups_out, int *count_out);

/**
 * Get group info by UUID
 *
 * @param group_uuid Group UUID
 * @param info_out Output for group info
 * @return 0 on success, -1 on error (not found)
 */
int groups_get_info(const char *group_uuid, groups_info_t *info_out);

/**
 * Free groups array
 *
 * @param groups Array to free
 * @param count Number of elements
 */
void groups_free_list(groups_info_t *groups, int count);

/* ============================================================================
 * MEMBER MANAGEMENT
 * ============================================================================ */

/**
 * Get members of a group
 *
 * @param group_uuid Group UUID
 * @param members_out Output array (allocated by function, caller must free)
 * @param count_out Output for number of members
 * @return 0 on success, -1 on error
 */
int groups_get_members(const char *group_uuid, groups_member_t **members_out, int *count_out);

/**
 * Add member to group
 *
 * Adds member to local database. Triggers GEK rotation.
 * Only owner can add members.
 *
 * @param group_uuid Group UUID
 * @param member_fp Member's fingerprint
 * @param my_fp My fingerprint (must be owner)
 * @return 0 on success, -1 on error
 */
int groups_add_member(const char *group_uuid, const char *member_fp, const char *my_fp);

/**
 * Remove member from group
 *
 * Removes member from local database. Triggers GEK rotation.
 * Only owner can remove members.
 *
 * @param group_uuid Group UUID
 * @param member_fp Member's fingerprint
 * @param my_fp My fingerprint (must be owner)
 * @return 0 on success, -1 on error
 */
int groups_remove_member(const char *group_uuid, const char *member_fp, const char *my_fp);

/**
 * Free members array
 *
 * @param members Array to free
 * @param count Number of elements
 */
void groups_free_members(groups_member_t *members, int count);

/* ============================================================================
 * INVITATIONS
 * ============================================================================ */

/**
 * Save pending invitation
 *
 * Called when receiving a group invitation from DHT.
 *
 * @param group_uuid Group UUID
 * @param group_name Group display name
 * @param owner_fp Owner's fingerprint
 * @return 0 on success, -1 on error
 */
int groups_save_invitation(const char *group_uuid, const char *group_name, const char *owner_fp);

/**
 * List pending invitations
 *
 * @param invites_out Output array (allocated by function, caller must free)
 * @param count_out Output for number of invitations
 * @return 0 on success, -1 on error
 */
int groups_list_invitations(groups_invitation_t **invites_out, int *count_out);

/**
 * Accept invitation
 *
 * Moves invitation to groups table and fetches GEK from DHT.
 *
 * @param group_uuid Group UUID to accept
 * @return 0 on success, -1 on error
 */
int groups_accept_invitation(const char *group_uuid);

/**
 * Reject invitation
 *
 * Removes invitation from pending list.
 *
 * @param group_uuid Group UUID to reject
 * @return 0 on success, -1 on error
 */
int groups_reject_invitation(const char *group_uuid);

/**
 * Free invitations array
 *
 * @param invites Array to free
 * @param count Number of elements
 */
void groups_free_invitations(groups_invitation_t *invites, int count);

/* ============================================================================
 * MESSAGING
 * ============================================================================ */

/**
 * Save decrypted group message to local cache
 *
 * @param group_uuid Group UUID
 * @param message_id Message ID (per-sender sequence)
 * @param sender_fp Sender fingerprint
 * @param timestamp_ms Message timestamp (milliseconds)
 * @param gek_version GEK version used for encryption
 * @param plaintext Decrypted message content
 * @return 0 on success, -1 on error (duplicate)
 */
int groups_save_message(const char *group_uuid, int message_id, const char *sender_fp,
                        uint64_t timestamp_ms, uint32_t gek_version, const char *plaintext);

/**
 * Check if we are a member of a group
 *
 * @param group_uuid Group UUID
 * @param my_fp My fingerprint
 * @return 1 if member, 0 if not, -1 on error
 */
int groups_is_member(const char *group_uuid, const char *my_fp);

/**
 * Check if we are the owner of a group
 *
 * @param group_uuid Group UUID
 * @param my_fp My fingerprint
 * @return 1 if owner, 0 if not, -1 on error
 */
int groups_is_owner(const char *group_uuid, const char *my_fp);

/* ============================================================================
 * BACKUP / RESTORE (Multi-Device Sync)
 * ============================================================================ */

/**
 * Group export entry for backup
 * Contains full group info including members
 */
typedef struct {
    char uuid[37];              // Group UUID
    char name[128];             // Group display name
    char owner_fp[129];         // Owner fingerprint
    bool is_owner;              // True if we are owner
    uint64_t created_at;        // Creation timestamp
    char **members;             // Array of member fingerprints
    int member_count;           // Number of members
} groups_export_entry_t;

/**
 * Export all groups for backup
 *
 * Retrieves all group entries from the database with members.
 *
 * @param entries_out Output array (allocated by function, caller must free with groups_free_export_entries)
 * @param count_out Output for number of entries
 * @return 0 on success, -1 on error
 */
int groups_export_all(groups_export_entry_t **entries_out, size_t *count_out);

/**
 * Import groups from backup
 *
 * Imports group entries into the database.
 * Skips groups that already exist (by UUID).
 *
 * @param entries Array of group entries to import
 * @param count Number of entries
 * @param imported_out Output for number of successfully imported groups (can be NULL)
 * @return 0 on success, -1 on error
 */
int groups_import_all(const groups_export_entry_t *entries, size_t count, int *imported_out);

/**
 * Free exported groups array
 *
 * @param entries Array to free
 * @param count Number of entries
 */
void groups_free_export_entries(groups_export_entry_t *entries, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* GROUPS_H */
