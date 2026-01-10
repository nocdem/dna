/**
 * Messenger Group Functions - DHT Implementation
 * Phase 3: Migrated from PostgreSQL to DHT + SQLite cache
 */

#include "messenger.h"
#include "messenger_p2p.h"  // For messenger_p2p_check_offline_messages
#include "messenger/gek.h"  // GEK rotation
#include "dht/shared/dht_groups.h"
#include "dht/core/dht_context.h"
#include "dht/client/dht_singleton.h"  // For dht_singleton_get
#include "dht/client/dna_group_outbox.h"  // Group outbox (feed pattern)
#include "message_backup.h"  // Phase 5.2
#include "database/group_invitations.h"  // Group invitation management
#include "dna_api.h"  // For dna_decrypt_message_raw
#include "crypto/utils/qgp_types.h"  // For qgp_key_load/free
#include "crypto/utils/qgp_platform.h"  // For qgp_platform_home_dir
// p2p_transport.h no longer needed - Phase 14 uses dht_singleton_get() directly
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_GROUPS"

// Helper: Convert timestamp to string
static char* timestamp_to_string(uint64_t timestamp) {
    char *str = malloc(32);
    if (!str) return NULL;

    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    strftime(str, 32, "%Y-%m-%d %H:%M:%S", tm_info);
    return str;
}

// Helper: Get group UUID from local group_id (Phase 6.1)
static int get_group_uuid_by_id(const char *identity, int group_id, char *uuid_out) {
    if (!identity || !uuid_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_group_uuid_by_id\n");
        return -1;
    }

    // Use dht_groups helper function to map local_id to UUID
    int ret = dht_groups_get_uuid_by_local_id(identity, group_id, uuid_out);
    if (ret != 0) {
        if (ret == -2) {
            QGP_LOG_ERROR(LOG_TAG, "Group ID %d not found or access denied\n", group_id);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Failed to lookup group UUID for ID %d\n", group_id);
        }
        return -1;
    }

    return 0;
}

// ============================================================================
// Group Management - DHT Implementation
// ============================================================================

int messenger_create_group(messenger_context_t *ctx, const char *name, const char *description,
                            const char **members, size_t member_count, int *group_id_out) {
    if (!ctx || !name || !group_id_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to create_group\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    char group_uuid[37];
    int ret = dht_groups_create(
        dht_ctx,
        name,
        description,
        ctx->identity,
        members,
        member_count,
        group_uuid
    );

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create group in DHT\n");
        return -1;
    }

    // Get the local_id from cache
    // We need to query the newly created group from the cache
    dht_group_cache_entry_t *groups = NULL;
    int count = 0;
    ret = dht_groups_list_for_user(ctx->identity, &groups, &count);
    if (ret != 0 || count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to retrieve created group from cache\n");
        return -1;
    }

    // Find the group we just created by UUID
    int local_id = -1;
    for (int i = 0; i < count; i++) {
        if (strcmp(groups[i].group_uuid, group_uuid) == 0) {
            local_id = groups[i].local_id;
            break;
        }
    }

    dht_groups_free_cache_entries(groups, count);

    if (local_id == -1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to find local_id for created group\n");
        return -1;
    }

    *group_id_out = local_id;
    QGP_LOG_INFO(LOG_TAG, "Created group '%s' (local_id=%d, uuid=%s)\n", name, local_id, group_uuid);

    // Phase 13: Create initial GEK (version 0) and publish to DHT
    QGP_LOG_INFO(LOG_TAG, "Creating initial GEK for group %s...\n", group_uuid);
    if (gek_rotate_on_member_add(dht_ctx, group_uuid, ctx->identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Initial GEK creation failed (non-fatal)\n");
        // Continue - group is created, but GEK needs to be created later
    } else {
        QGP_LOG_INFO(LOG_TAG, "Initial GEK created and published to DHT\n");
    }

    // Send invitations to all initial members (not the creator)
    if (member_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Sending invitations to %zu initial members...\n", member_count);
        for (size_t i = 0; i < member_count; i++) {
            ret = messenger_send_group_invitation(ctx, group_uuid, members[i],
                                                   name, (int)(member_count + 1));
            if (ret == 0) {
                QGP_LOG_INFO(LOG_TAG, "Sent invitation to %s\n", members[i]);
            } else {
                QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to send invitation to %s\n", members[i]);
                // Non-fatal - continue with other members
            }
        }
    }

    return 0;
}

int messenger_get_groups(messenger_context_t *ctx, group_info_t **groups_out, int *count_out) {
    if (!ctx || !groups_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_groups\n");
        return -1;
    }

    *groups_out = NULL;
    *count_out = 0;

    // Get groups from local cache
    dht_group_cache_entry_t *cache_entries = NULL;
    int count = 0;
    int ret = dht_groups_list_for_user(ctx->identity, &cache_entries, &count);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to list groups from cache\n");
        return -1;
    }

    if (count == 0) {
        *groups_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Convert cache entries to group_info_t
    group_info_t *groups = malloc(sizeof(group_info_t) * count);
    if (!groups) {
        dht_groups_free_cache_entries(cache_entries, count);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        groups[i].id = cache_entries[i].local_id;
        groups[i].name = strdup(cache_entries[i].name);
        groups[i].description = strdup("");  // Not cached locally
        groups[i].creator = strdup(cache_entries[i].creator);
        groups[i].created_at = timestamp_to_string(cache_entries[i].created_at);
        groups[i].member_count = 0;  // Need to query from DHT for accurate count
    }

    dht_groups_free_cache_entries(cache_entries, count);

    *groups_out = groups;
    *count_out = count;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d groups for user %s\n", count, ctx->identity);
    return 0;
}

int messenger_get_group_info(messenger_context_t *ctx, int group_id, group_info_t *info_out) {
    if (!ctx || !info_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_group_info\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    // Get group UUID from local group_id (Phase 6.1)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        return -1;
    }

    // Get full metadata from DHT
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group metadata from DHT\n");
        return -1;
    }

    // Populate group_info_t
    info_out->id = group_id;
    info_out->name = strdup(meta->name);
    info_out->description = strdup(meta->description);
    info_out->creator = strdup(meta->creator);
    info_out->created_at = timestamp_to_string(meta->created_at);
    info_out->member_count = meta->member_count;

    dht_groups_free_metadata(meta);

    QGP_LOG_INFO(LOG_TAG, "Retrieved info for group %d (%s)\n", group_id, group_uuid);
    return 0;
}

int messenger_get_group_members(messenger_context_t *ctx, int group_id, char ***members_out, int *count_out) {
    if (!ctx || !members_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_group_members\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    *members_out = NULL;
    *count_out = 0;

    // Get group UUID from local group_id (Phase 6.1)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        return -1;
    }

    // Get metadata from DHT
    dht_group_metadata_t *meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret != 0) {
        return -1;
    }

    // Copy members array
    char **members = malloc(sizeof(char*) * meta->member_count);
    if (!members) {
        dht_groups_free_metadata(meta);
        return -1;
    }

    for (uint32_t i = 0; i < meta->member_count; i++) {
        members[i] = strdup(meta->members[i]);
    }

    *members_out = members;
    *count_out = meta->member_count;

    dht_groups_free_metadata(meta);

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d members for group %d\n", *count_out, group_id);
    return 0;
}

int messenger_add_group_member(messenger_context_t *ctx, int group_id, const char *identity) {
    if (!ctx || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to add_group_member\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    // Get group UUID from local group_id (Phase 6.1)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        return -1;
    }

    // Add member in DHT
    int ret = dht_groups_add_member(dht_ctx, group_uuid, identity, ctx->identity);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add member to DHT\n");
        return -1;
    }

    // Sync back to local cache
    dht_groups_sync_from_dht(dht_ctx, group_uuid);

    // Phase 5 (v0.09): Rotate GEK when member is added
    QGP_LOG_INFO(LOG_TAG, "Rotating GEK for group %s after adding member...\n", group_uuid);
    if (gek_rotate_on_member_add(dht_ctx, group_uuid, ctx->identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: GEK rotation failed (non-fatal)\n");
        // Continue - member is still added, but GEK rotation failed
    }

    // Fetch group metadata to get name and member count for invitation
    dht_group_metadata_t *meta = NULL;
    ret = dht_groups_get(dht_ctx, group_uuid, &meta);
    if (ret == 0 && meta) {
        // Send invitation to the new member
        ret = messenger_send_group_invitation(ctx, group_uuid, identity,
                                               meta->name, meta->member_count);
        if (ret == 0) {
            QGP_LOG_INFO(LOG_TAG, "Sent group invitation to %s for group '%s'\n",
                   identity, meta->name);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to send invitation to %s\n", identity);
            // Non-fatal - member is still added to DHT
        }
        dht_groups_free_metadata(meta);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Could not fetch group metadata to send invitation\n");
        // Non-fatal - member is still added to DHT
    }

    QGP_LOG_INFO(LOG_TAG, "Added member %s to group %d\n", identity, group_id);
    return 0;
}

int messenger_remove_group_member(messenger_context_t *ctx, int group_id, const char *identity) {
    if (!ctx || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to remove_group_member\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    // Get group UUID from local group_id (Phase 6.1)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        return -1;
    }

    // Remove member from DHT
    int ret = dht_groups_remove_member(dht_ctx, group_uuid, identity, ctx->identity);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove member from DHT\n");
        return -1;
    }

    // Sync back to local cache
    dht_groups_sync_from_dht(dht_ctx, group_uuid);

    // Phase 5 (v0.09): Rotate GEK when member is removed
    QGP_LOG_INFO(LOG_TAG, "Rotating GEK for group %s after removing member...\n", group_uuid);
    if (gek_rotate_on_member_remove(dht_ctx, group_uuid, ctx->identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: GEK rotation failed (non-fatal)\n");
        // Continue - member is still removed, but GEK rotation failed
    }

    QGP_LOG_INFO(LOG_TAG, "Removed member %s from group %d\n", identity, group_id);
    return 0;
}

int messenger_leave_group(messenger_context_t *ctx, int group_id) {
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to leave_group\n");
        return -1;
    }

    // User leaves group by removing themselves
    return messenger_remove_group_member(ctx, group_id, ctx->identity);
}

int messenger_delete_group(messenger_context_t *ctx, int group_id) {
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to delete_group\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    // Get group UUID from local group_id (Phase 6.1)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        return -1;
    }

    // Delete from DHT (only creator can do this)
    int ret = dht_groups_delete(dht_ctx, group_uuid, ctx->identity);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete group from DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted group %d\n", group_id);
    return 0;
}

int messenger_update_group_info(messenger_context_t *ctx, int group_id, const char *new_name, const char *new_description) {
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to update_group_info\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    // Get group UUID from local group_id (Phase 6.1)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        return -1;
    }

    // Update in DHT
    int ret = dht_groups_update(dht_ctx, group_uuid, new_name, new_description, ctx->identity);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update group in DHT\n");
        return -1;
    }

    // Sync back to local cache
    dht_groups_sync_from_dht(dht_ctx, group_uuid);

    QGP_LOG_INFO(LOG_TAG, "Updated group %d\n", group_id);
    return 0;
}

int messenger_get_group_conversation(messenger_context_t *ctx, int group_id, message_info_t **messages_out, int *count_out) {
    if (!ctx || !messages_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to get_group_conversation\n");
        return -1;
    }

    *messages_out = NULL;
    *count_out = 0;

    // Get messages from message_backup (Phase 5.2)
    // Use fingerprint (canonical) for consistent database path
    const char *db_identity = ctx->fingerprint ? ctx->fingerprint : ctx->identity;
    message_backup_context_t *backup_ctx = message_backup_init(db_identity);
    if (!backup_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init message backup\n");
        return -1;
    }

    backup_message_t *backup_messages = NULL;
    int backup_count = 0;
    int ret = message_backup_get_group_conversation(backup_ctx, group_id, &backup_messages, &backup_count);
    message_backup_close(backup_ctx);

    if (ret != 0 || backup_count == 0) {
        return (ret == 0) ? 0 : -1;
    }

    // Convert backup_message_t to message_info_t
    message_info_t *messages = calloc(backup_count, sizeof(message_info_t));
    if (!messages) {
        message_backup_free_messages(backup_messages, backup_count);
        return -1;
    }

    for (int i = 0; i < backup_count; i++) {
        messages[i].id = backup_messages[i].id;
        messages[i].sender = strdup(backup_messages[i].sender);
        messages[i].recipient = strdup(backup_messages[i].recipient);

        // Convert time_t to timestamp string
        messages[i].timestamp = timestamp_to_string(backup_messages[i].timestamp);

        // Convert status to string
        const char *status_str = (backup_messages[i].status == 0) ? "pending" :
                                  (backup_messages[i].status == 1) ? "sent" : "failed";
        messages[i].status = strdup(status_str);

        // Set delivered_at and read_at (NULL for now, would need actual timestamps)
        messages[i].delivered_at = backup_messages[i].delivered ? strdup("delivered") : NULL;
        messages[i].read_at = backup_messages[i].read ? strdup("read") : NULL;
        messages[i].plaintext = NULL;  // Not decrypted yet

        // Note: encrypted_message is not copied to message_info_t
        // Messages must be decrypted separately via messenger_decrypt_message()
    }

    message_backup_free_messages(backup_messages, backup_count);

    *messages_out = messages;
    *count_out = backup_count;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d group messages (group_id=%d)\n", backup_count, group_id);
    return 0;
}

void messenger_free_groups(group_info_t *groups, int count) {
    if (!groups) return;

    for (int i = 0; i < count; i++) {
        if (groups[i].name) free(groups[i].name);
        if (groups[i].description) free(groups[i].description);
        if (groups[i].creator) free(groups[i].creator);
        if (groups[i].created_at) free(groups[i].created_at);
    }

    free(groups);
}

/**
 * Send group invitation to a user
 *
 * Creates a special invitation message with JSON format:
 * {
 *   "type": "group_invite",
 *   "group_uuid": "...",
 *   "group_name": "...",
 *   "inviter": "...",
 *   "member_count": 5
 * }
 */
int messenger_send_group_invitation(messenger_context_t *ctx, const char *group_uuid,
                                     const char *recipient, const char *group_name,
                                     int member_count) {
    if (!ctx || !group_uuid || !recipient || !group_name) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to send_group_invitation\n");
        return -1;
    }

    // Create invitation JSON
    json_object *j_invite = json_object_new_object();
    json_object_object_add(j_invite, "type", json_object_new_string("group_invite"));
    json_object_object_add(j_invite, "group_uuid", json_object_new_string(group_uuid));
    json_object_object_add(j_invite, "group_name", json_object_new_string(group_name));
    json_object_object_add(j_invite, "inviter", json_object_new_string(ctx->identity));
    json_object_object_add(j_invite, "member_count", json_object_new_int(member_count));

    const char *json_str = json_object_to_json_string_ext(j_invite, JSON_C_TO_STRING_PLAIN);

    // Send as encrypted message (group_id=0, message_type=GROUP_INVITATION)
    int ret = messenger_send_message(ctx, &recipient, 1, json_str, 0, MESSAGE_TYPE_GROUP_INVITATION);

    json_object_put(j_invite);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send group invitation\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Sent group invitation to %s for group '%s' (UUID: %s)\n",
           recipient, group_name, group_uuid);
    return 0;
}

/**
 * Accept a group invitation
 */
int messenger_accept_group_invitation(messenger_context_t *ctx, const char *group_uuid) {
    if (!ctx || !group_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to accept_group_invitation\n");
        return -1;
    }

    // Get invitation details
    group_invitation_t *invitation = NULL;
    int ret = group_invitations_get(group_uuid, &invitation);
    if (ret != 0 || !invitation) {
        QGP_LOG_ERROR(LOG_TAG, "Invitation not found: %s\n", group_uuid);
        return -1;
    }

    // Sync group metadata from DHT
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not initialized\n");
        group_invitations_free(invitation, 1);
        return -1;
    }

    ret = dht_groups_sync_from_dht(dht_ctx, group_uuid);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync group from DHT\n");
        group_invitations_free(invitation, 1);
        return -1;
    }

    // Update invitation status to accepted
    group_invitations_update_status(group_uuid, INVITATION_STATUS_ACCEPTED);

    group_invitations_free(invitation, 1);

    QGP_LOG_INFO(LOG_TAG, "Accepted group invitation: %s\n", group_uuid);
    return 0;
}

/**
 * Reject a group invitation
 */
int messenger_reject_group_invitation(messenger_context_t *ctx, const char *group_uuid) {
    if (!ctx || !group_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to reject_group_invitation\n");
        return -1;
    }

    // Update invitation status to rejected
    int ret = group_invitations_update_status(group_uuid, INVITATION_STATUS_REJECTED);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update invitation status\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Rejected group invitation: %s\n", group_uuid);
    return 0;
}

/**
 * Sync groups from offline messages and DHT
 *
 * This function:
 * 1. Checks for offline messages containing group invitations
 * 2. Scans recent messages for invitation JSON
 * 3. Stores invitations in local database
 * 4. Handles duplicates gracefully
 */
int messenger_sync_groups(messenger_context_t *ctx) {
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context for sync_groups\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing groups and invitations...\n");

    // Step 1: Check for offline messages (which may contain invitations)
    if (ctx->p2p_enabled && ctx->p2p_transport) {
        size_t offline_count = 0;
        messenger_p2p_check_offline_messages(ctx, NULL, &offline_count);
        if (offline_count > 0) {
            QGP_LOG_INFO(LOG_TAG, "Retrieved %zu offline messages (may include invitations)\n", offline_count);
        }
    }

    // Step 2: Scan recent messages for group invitations
    char **contacts = NULL;
    int contact_count = 0;

    int ret = message_backup_get_recent_contacts(ctx->backup_ctx, &contacts, &contact_count);
    if (ret != 0 || contact_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No recent messages to scan for invitations\n");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Scanning %d recent contacts for group invitations...\n", contact_count);

    // Load recipient's private Kyber1024 key from filesystem (for decryption)
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        for (int i = 0; i < contact_count; i++) {
            free(contacts[i]);
        }
        free(contacts);
        return -1;
    }
    // v0.3.0: Flat structure - keys/identity.kem
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key for decryption\n");
        // Free contacts list
        for (int i = 0; i < contact_count; i++) {
            free(contacts[i]);
        }
        free(contacts);
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {  // Kyber1024 secret key size
        QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber key size: %zu (expected 3168)\n",
                kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        // Free contacts list
        for (int i = 0; i < contact_count; i++) {
            free(contacts[i]);
        }
        free(contacts);
        return -1;
    }

    int invitations_found = 0;

    // Step 3: For each contact, get their messages and check for invitations
    for (int i = 0; i < contact_count; i++) {
        backup_message_t *messages = NULL;
        int message_count = 0;

        ret = message_backup_get_conversation(ctx->backup_ctx, contacts[i], &messages, &message_count);
        if (ret != 0 || message_count == 0) {
            continue;
        }

        // Check each message for group invitation JSON
        for (int j = 0; j < message_count; j++) {
            // Skip if already read (already processed)
            if (messages[j].read) {
                continue;
            }

            // Decrypt the message
            uint8_t *plaintext = NULL;
            size_t plaintext_len = 0;
            uint8_t *sender_pubkey = NULL;
            size_t sender_pubkey_len = 0;
            uint8_t *signature = NULL;
            size_t signature_len = 0;
            uint64_t sender_timestamp = 0;

            dna_error_t err = dna_decrypt_message_raw(
                ctx->dna_ctx,
                messages[j].encrypted_message,
                messages[j].encrypted_len,
                kyber_key->private_key,  // Kyber1024 private key
                &plaintext,
                &plaintext_len,
                &sender_pubkey,
                &sender_pubkey_len,
                &signature,
                &signature_len,
                &sender_timestamp  // v0.08: Extract sender's timestamp
            );

            if (err != DNA_OK || !plaintext) {
                if (signature) free(signature);
                continue;  // Skip messages we can't decrypt
            }

            // Ensure null-terminated for JSON parsing
            char *plaintext_str = malloc(plaintext_len + 1);
            if (!plaintext_str) {
                free(plaintext);
                free(sender_pubkey);
                if (signature) free(signature);
                continue;
            }
            memcpy(plaintext_str, plaintext, plaintext_len);
            plaintext_str[plaintext_len] = '\0';
            
            // Try to parse as JSON
            json_object *j_msg = json_tokener_parse(plaintext_str);
            free(plaintext_str);
            if (j_msg) {
                json_object *j_type = json_object_object_get(j_msg, "type");

                if (j_type && strcmp(json_object_get_string(j_type), "group_invite") == 0) {
                    // This is a group invitation!
                    json_object *j_uuid = json_object_object_get(j_msg, "group_uuid");
                    json_object *j_name = json_object_object_get(j_msg, "group_name");
                    json_object *j_inviter = json_object_object_get(j_msg, "inviter");
                    json_object *j_count = json_object_object_get(j_msg, "member_count");

                    if (j_uuid && j_name && j_inviter && j_count) {
                        group_invitation_t invitation = {0};
                        strncpy(invitation.group_uuid, json_object_get_string(j_uuid),
                                sizeof(invitation.group_uuid) - 1);
                        strncpy(invitation.group_name, json_object_get_string(j_name),
                                sizeof(invitation.group_name) - 1);
                        strncpy(invitation.inviter, json_object_get_string(j_inviter),
                                sizeof(invitation.inviter) - 1);
                        invitation.invited_at = messages[j].timestamp;
                        invitation.status = INVITATION_STATUS_PENDING;
                        invitation.member_count = json_object_get_int(j_count);

                        // Store invitation (handles duplicates with return code -2)
                        ret = group_invitations_store(&invitation);
                        if (ret == 0) {
                            QGP_LOG_INFO(LOG_TAG, "Found new group invitation: '%s' from %s\n",
                                   invitation.group_name, invitation.inviter);
                            invitations_found++;
                        } else if (ret == -2) {
                            // Duplicate, ignore silently
                        }

                        // Mark message as read so we don't process it again
                        message_backup_mark_read(ctx->backup_ctx, messages[j].id);
                    }
                }

                json_object_put(j_msg);
            }

            free(plaintext);
            free(sender_pubkey);
            if (signature) free(signature);
        }

        message_backup_free_messages(messages, message_count);
    }

    // Free Kyber key (secure wipe)
    qgp_key_free(kyber_key);

    // Free contacts list
    for (int i = 0; i < contact_count; i++) {
        free(contacts[i]);
    }
    free(contacts);

    if (invitations_found > 0) {
        QGP_LOG_INFO(LOG_TAG, "✓ Sync complete: %d new invitation(s) found\n", invitations_found);
    } else {
        QGP_LOG_INFO(LOG_TAG, "✓ Sync complete: no new invitations\n");
    }

    return 0;
}

// ============================================================================
// GROUP MESSAGING (Feed Pattern via DHT Outbox)
// ============================================================================

/**
 * Send message to a group using feed-pattern outbox
 *
 * NEW IMPLEMENTATION (v0.10+):
 * - Message encrypted ONCE with GEK (AES-256-GCM)
 * - Stored ONCE in DHT (feed pattern)
 * - All members poll via dht_get_all()
 * - Storage: O(message_size) vs O(N * message_size) in old system
 *
 * @param ctx Messenger context
 * @param group_uuid Group UUID (36 chars)
 * @param message Plaintext message
 * @return 0 on success, -1 on error
 */
int messenger_send_group_message(messenger_context_t *ctx, const char *group_uuid, const char *message) {
    if (!ctx || !group_uuid || !message) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Sending message to group %s (feed pattern)\n", group_uuid);

    // Step 1: Get DHT context
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not initialized\n");
        return -1;
    }

    // Step 2: Load Dilithium5 private key for signing
    const char *data_dir2 = qgp_platform_app_data_dir();
    if (!data_dir2) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s-dilithium.pqkey",
             data_dir2, ctx->identity);

    FILE *fp = fopen(dilithium_path, "rb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open Dilithium key: %s\n", dilithium_path);
        return -1;
    }

    uint8_t dilithium_privkey[4896];  // Dilithium5 private key size
    if (fread(dilithium_privkey, 1, 4896, fp) != 4896) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read Dilithium private key\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Step 3: Get sender fingerprint (canonical identifier)
    const char *sender_fingerprint = ctx->fingerprint ? ctx->fingerprint : ctx->identity;

    // Step 4: Send via group outbox (feed pattern)
    char message_id[DNA_GROUP_MSG_ID_SIZE];
    int result = dna_group_outbox_send(
        dht_ctx,
        group_uuid,
        sender_fingerprint,
        message,
        dilithium_privkey,
        message_id
    );

    // Secure wipe private key
    qgp_secure_memzero(dilithium_privkey, sizeof(dilithium_privkey));

    if (result == DNA_GROUP_OUTBOX_OK) {
        QGP_LOG_INFO(LOG_TAG, "Message sent via group outbox: %s\n", message_id);
        return 0;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send group message: %s\n",
                dna_group_outbox_strerror(result));
        return -1;
    }
}

/**
 * Load group conversation messages from group outbox
 *
 * NEW IMPLEMENTATION (v0.10+):
 * Retrieves messages from the group_messages table (feed pattern storage).
 * Messages are already decrypted during sync.
 *
 * @param ctx Messenger context
 * @param group_uuid Group UUID (36 chars)
 * @param messages_out Output array of messages (caller must free)
 * @param count_out Number of messages returned
 * @return 0 on success, -1 on error
 */
int messenger_load_group_messages(messenger_context_t *ctx, const char *group_uuid,
                                   backup_message_t **messages_out, int *count_out) {
    if (!ctx || !group_uuid || !messages_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Loading messages for group %s (from group_messages table)\n", group_uuid);

    // Load from new group_messages table
    dna_group_message_t *group_msgs = NULL;
    size_t group_count = 0;

    int result = dna_group_outbox_db_get_messages(group_uuid, 0, 0, &group_msgs, &group_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load group messages from database\n");
        *messages_out = NULL;
        *count_out = 0;
        return -1;
    }

    if (group_count == 0) {
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Convert dna_group_message_t to backup_message_t for compatibility
    backup_message_t *messages = calloc(group_count, sizeof(backup_message_t));
    if (!messages) {
        dna_group_outbox_free_messages(group_msgs, group_count);
        return -1;
    }

    for (size_t i = 0; i < group_count; i++) {
        messages[i].id = (int)i;  // Use index as ID
        strncpy(messages[i].sender, group_msgs[i].sender_fingerprint, sizeof(messages[i].sender) - 1);
        strncpy(messages[i].recipient, group_uuid, sizeof(messages[i].recipient) - 1);
        messages[i].timestamp = (time_t)(group_msgs[i].timestamp_ms / 1000);
        messages[i].delivered = 1;
        messages[i].read = 0;
        messages[i].status = 1;  // SENT
        messages[i].group_id = 0;  // Not used in new system
        messages[i].message_type = 0;  // CHAT

        // Copy encrypted message (for compatibility)
        if (group_msgs[i].ciphertext && group_msgs[i].ciphertext_len > 0) {
            messages[i].encrypted_message = malloc(group_msgs[i].ciphertext_len);
            if (messages[i].encrypted_message) {
                memcpy(messages[i].encrypted_message, group_msgs[i].ciphertext, group_msgs[i].ciphertext_len);
                messages[i].encrypted_len = group_msgs[i].ciphertext_len;
            }
        }
    }

    dna_group_outbox_free_messages(group_msgs, group_count);

    *messages_out = messages;
    *count_out = (int)group_count;

    QGP_LOG_INFO(LOG_TAG, "Loaded %zu group messages\n", group_count);
    return 0;
}
