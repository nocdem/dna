/**
 * Messenger Group Functions - DHT Implementation
 * Phase 3: Migrated from PostgreSQL to DHT + SQLite cache
 */

#include "messenger.h"
#include "messenger_transport.h"  // For messenger_transport_check_offline_messages
#include "messenger/gek.h"  // GEK rotation
#include "dht/shared/dht_groups.h"
#include "dht/shared/dht_gek_storage.h"  // GEK fetch from DHT
#include "crypto/utils/qgp_sha3.h"  // For fingerprint calculation
#include "dht/core/dht_context.h"
#include "dht/client/dht_singleton.h"  // For dht_singleton_get
#include "dht/client/dna_group_outbox.h"  // Group outbox (feed pattern)
#include "dht/client/dht_grouplist.h"  // Group list DHT sync (v0.5.26+)
#include "messenger/groups.h"  // For groups_export_all
#include "message_backup.h"  // Phase 5.2
#include "database/group_invitations.h"  // Group invitation management
#include "dna_api.h"  // For dna_decrypt_message_raw
#include "crypto/utils/qgp_types.h"  // For qgp_key_load/free
#include "crypto/utils/qgp_platform.h"  // For qgp_platform_home_dir
// transport_ctx.h no longer needed - Phase 14 uses dht_singleton_get() directly
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
                            const char **members, size_t member_count, int *group_id_out,
                            char *uuid_out) {
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
    if (uuid_out) {
        strncpy(uuid_out, group_uuid, 36);
        uuid_out[36] = '\0';
    }
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

    // Sync group list to DHT so it can be restored on other devices
    ret = messenger_sync_groups_to_dht(ctx);
    if (ret != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to sync grouplist to DHT after create (non-fatal)\n");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to add member to DHT (ret=%d)\n", ret);
        return ret;  // Preserve specific error code: -2=unauthorized, -3=already member
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

    // Get group UUID before removing (needed for local cleanup)
    char group_uuid[37] = {0};
    if (get_group_uuid_by_id(ctx->identity, group_id, group_uuid) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group UUID for leave_group\n");
        return -1;
    }

    // Step 1: Remove ourselves from DHT group member list
    int ret = messenger_remove_group_member(ctx, group_id, ctx->identity);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove self from DHT group members\n");
        return -1;
    }

    // Step 2: Delete group from local database (members, geks, messages, group entry)
    ret = groups_leave(group_uuid);
    if (ret != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to delete group from local DB (continuing)\n");
        // Non-fatal - we're already removed from DHT
    }

    // Step 3: Sync grouplist to DHT (update personal grouplist)
    ret = messenger_sync_groups_to_dht(ctx);
    if (ret != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to sync grouplist to DHT after leave (non-fatal)\n");
        // Non-fatal - local state is correct
    }

    QGP_LOG_INFO(LOG_TAG, "Left group %d (uuid=%s)\n", group_id, group_uuid);
    return 0;
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
    int ret = messenger_send_message(ctx, &recipient, 1, json_str, 0, MESSAGE_TYPE_GROUP_INVITATION, 0);

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
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: START uuid=%s <<<\n", group_uuid ? group_uuid : "(null)");

    if (!ctx || !group_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to accept_group_invitation\n");
        return -1;
    }

    // Get invitation details
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: Getting invitation from DB <<<\n");
    group_invitation_t *invitation = NULL;
    int ret = group_invitations_get(group_uuid, &invitation);
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: group_invitations_get returned %d, invitation=%p <<<\n", ret, (void*)invitation);

    if (ret != 0 || !invitation) {
        QGP_LOG_ERROR(LOG_TAG, "Invitation not found: %s\n", group_uuid);
        return -1;
    }

    // Sync group metadata from DHT
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: Getting DHT context <<<\n");
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not initialized\n");
        group_invitations_free(invitation, 1);
        return -1;
    }

    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: Calling dht_groups_sync_from_dht <<<\n");
    ret = dht_groups_sync_from_dht(dht_ctx, group_uuid);
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: dht_groups_sync_from_dht returned %d <<<\n", ret);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync group from DHT\n");
        group_invitations_free(invitation, 1);
        return -1;
    }

    // Fetch GEK (Initial Key Packet) from DHT and store locally
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: Fetching GEK from DHT <<<\n");
    do {
        // Load user's Kyber private key for IKP extraction
        const char *data_dir = qgp_platform_app_data_dir();
        if (!data_dir) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory for GEK fetch\n");
            break;
        }

        // v0.3.0: Flat structure - keys/identity.kem
        char kyber_path[512];
        snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

        qgp_key_t *kyber_key = NULL;
        if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key for GEK extraction\n");
            break;
        }

        if (kyber_key->private_key_size != 3168) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber key size: %zu\n", kyber_key->private_key_size);
            qgp_key_free(kyber_key);
            break;
        }

        // Load Dilithium public key to compute fingerprint
        char dilithium_path[512];
        snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

        qgp_key_t *dilithium_key = NULL;
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0 || !dilithium_key) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key for fingerprint\n");
            qgp_key_free(kyber_key);
            break;
        }

        // Compute fingerprint (SHA3-512 of Dilithium public key)
        uint8_t my_fingerprint[64];
        if (qgp_sha3_512(dilithium_key->public_key, 2592, my_fingerprint) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint\n");
            qgp_key_free(kyber_key);
            qgp_key_free(dilithium_key);
            break;
        }
        qgp_key_free(dilithium_key);

        // Get group metadata to find current GEK version
        dht_group_metadata_t *group_meta = NULL;
        ret = dht_groups_get(dht_ctx, group_uuid, &group_meta);
        if (ret != 0 || !group_meta) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get group metadata for GEK version\n");
            qgp_key_free(kyber_key);
            break;
        }

        uint32_t gek_version = group_meta->gek_version;
        QGP_LOG_INFO(LOG_TAG, "Group metadata indicates GEK version %u\n", gek_version);
        dht_groups_free_metadata(group_meta);

        // Fetch the specific GEK version from metadata
        uint8_t *ikp_packet = NULL;
        size_t ikp_size = 0;
        ret = dht_gek_fetch(dht_ctx, group_uuid, gek_version, &ikp_packet, &ikp_size);

        if (ret != 0 || !ikp_packet || ikp_size == 0) {
            QGP_LOG_WARN(LOG_TAG, "No GEK v%u found in DHT for group %s (may be published later)\n",
                         gek_version, group_uuid);
            qgp_key_free(kyber_key);
            break;
        }

        QGP_LOG_INFO(LOG_TAG, "Found IKP for group %s version %u (%zu bytes)\n",
                     group_uuid, gek_version, ikp_size);

        // Extract GEK from IKP using my fingerprint and Kyber private key
        uint8_t gek[GEK_KEY_SIZE];
        uint32_t extracted_version = 0;
        ret = ikp_extract(ikp_packet, ikp_size, my_fingerprint,
                          kyber_key->private_key, gek, &extracted_version);
        free(ikp_packet);
        qgp_key_free(kyber_key);

        if (ret != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to extract GEK from IKP (not a member?)\n");
            break;
        }

        // Store GEK locally
        ret = gek_store(group_uuid, extracted_version, gek);
        qgp_secure_memzero(gek, GEK_KEY_SIZE);

        if (ret != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to store GEK locally\n");
            break;
        }

        QGP_LOG_INFO(LOG_TAG, "Successfully stored GEK v%u for group %s\n",
                     extracted_version, group_uuid);
    } while (0);

    // Update invitation status to accepted
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: Updating status <<<\n");
    group_invitations_update_status(group_uuid, INVITATION_STATUS_ACCEPTED);

    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: Freeing invitation <<<\n");
    group_invitations_free(invitation, 1);

    // Sync group list to DHT so it can be restored on other devices
    ret = messenger_sync_groups_to_dht(ctx);
    if (ret != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to sync grouplist to DHT after accept (non-fatal)\n");
    }

    QGP_LOG_INFO(LOG_TAG, "Accepted group invitation: %s\n", group_uuid);
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT_INV: DONE <<<\n");
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
 * Sync GEK (Group Encryption Key) from DHT for an existing group
 *
 * Fetches the Initial Key Packet from DHT, extracts the GEK using
 * this user's Kyber private key, and stores it locally.
 *
 * @param group_uuid Group UUID (36 chars)
 * @return 0 on success, -1 on error
 */
int messenger_sync_group_gek(const char *group_uuid) {
    if (!group_uuid || strlen(group_uuid) != 36) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid group_uuid for GEK sync\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing GEK for group %s...\n", group_uuid);

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not initialized\n");
        return -1;
    }

    // Load user's Kyber private key for IKP extraction
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory for GEK sync\n");
        return -1;
    }

    // v0.3.0: Flat structure - keys/identity.kem
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key for GEK sync\n");
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber key size: %zu\n", kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        return -1;
    }

    // Load Dilithium public key to compute fingerprint
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *dilithium_key = NULL;
    if (qgp_key_load(dilithium_path, &dilithium_key) != 0 || !dilithium_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key for fingerprint\n");
        qgp_key_free(kyber_key);
        return -1;
    }

    // Compute fingerprint (SHA3-512 of Dilithium public key)
    uint8_t my_fingerprint[64];
    if (qgp_sha3_512(dilithium_key->public_key, 2592, my_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint\n");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        return -1;
    }
    qgp_key_free(dilithium_key);

    // Get group metadata to find current GEK version
    dht_group_metadata_t *group_meta = NULL;
    int ret = dht_groups_get(dht_ctx, group_uuid, &group_meta);
    if (ret != 0 || !group_meta) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group metadata for GEK sync\n");
        qgp_key_free(kyber_key);
        return -1;
    }

    uint32_t gek_version = group_meta->gek_version;
    QGP_LOG_INFO(LOG_TAG, "Group metadata indicates GEK version %u\n", gek_version);
    dht_groups_free_metadata(group_meta);

    // Fetch the specific GEK version from metadata
    uint8_t *ikp_packet = NULL;
    size_t ikp_size = 0;
    ret = dht_gek_fetch(dht_ctx, group_uuid, gek_version, &ikp_packet, &ikp_size);

    if (ret != 0 || !ikp_packet || ikp_size == 0) {
        QGP_LOG_WARN(LOG_TAG, "No GEK v%u found in DHT for group %s\n", gek_version, group_uuid);
        qgp_key_free(kyber_key);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Found IKP for group %s version %u (%zu bytes)\n",
                 group_uuid, gek_version, ikp_size);

    // Extract GEK from IKP using my fingerprint and Kyber private key
    uint8_t gek[GEK_KEY_SIZE];
    uint32_t extracted_version = 0;
    ret = ikp_extract(ikp_packet, ikp_size, my_fingerprint,
                      kyber_key->private_key, gek, &extracted_version);
    free(ikp_packet);
    qgp_key_free(kyber_key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to extract GEK from IKP (not a member?)\n");
        return -1;
    }

    // Store GEK locally
    ret = gek_store(group_uuid, extracted_version, gek);
    qgp_secure_memzero(gek, GEK_KEY_SIZE);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store GEK locally\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully synced GEK v%u for group %s\n",
                 extracted_version, group_uuid);
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
    if (ctx->transport_enabled && ctx->transport_ctx) {
        size_t offline_count = 0;
        messenger_transport_check_offline_messages(ctx, NULL, true, &offline_count);
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

            // v14: Messages are stored as plaintext - no decryption needed
            const char *plaintext = messages[j].plaintext;
            if (!plaintext || strlen(plaintext) == 0) {
                continue;  // Skip empty messages
            }

            // Try to parse as JSON
            json_object *j_msg = json_tokener_parse(plaintext);
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
            // v14: No signature/plaintext cleanup needed - plaintext is from struct
        }

        message_backup_free_messages(messages, message_count);
    }

    // v14: Kyber key no longer needed for plaintext messages
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

/**
 * Sync groups to DHT (local -> DHT)
 *
 * Publishes the user's group membership list to DHT.
 * Uses dht_grouplist layer for encryption and storage.
 */
int messenger_sync_groups_to_dht(messenger_context_t *ctx) {
    if (!ctx || !ctx->identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context for group DHT sync\n");
        return -1;
    }

    // Get DHT context from singleton
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT singleton not available\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "[GROUPLIST_PUBLISH] messenger_sync_groups_to_dht called for %.16s...\n", ctx->identity);

    // Load user's keys
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // Load Kyber keypair (try encrypted if password available, fallback to unencrypted)
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(kyber_path, ctx->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key\n");
            return -1;
        }
    } else {
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key\n");
            return -1;
        }
    }

    // Load Dilithium keypair
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *dilithium_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, ctx->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    }

    // Get group list from local database using groups_export_all()
    groups_export_entry_t *entries = NULL;
    size_t entry_count = 0;

    int ret = groups_export_all(&entries, &entry_count);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to export groups from local database\n");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        return -1;
    }

    // Extract UUIDs into string array
    const char **group_uuids = NULL;
    if (entry_count > 0) {
        group_uuids = malloc(entry_count * sizeof(char*));
        if (!group_uuids) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate group UUIDs array\n");
            groups_free_export_entries(entries, entry_count);
            qgp_key_free(kyber_key);
            qgp_key_free(dilithium_key);
            return -1;
        }

        for (size_t i = 0; i < entry_count; i++) {
            group_uuids[i] = entries[i].uuid;
            QGP_LOG_DEBUG(LOG_TAG, "Group[%zu]: %s (%s)\n", i, entries[i].uuid, entries[i].name);
        }
    }

    // Publish to DHT
    int result = dht_grouplist_publish(
        dht_ctx,
        ctx->identity,
        group_uuids,
        entry_count,
        kyber_key->public_key,
        kyber_key->private_key,
        dilithium_key->public_key,
        dilithium_key->private_key,
        0  // Use default 7-day TTL
    );

    // Cleanup
    if (group_uuids) free(group_uuids);
    groups_free_export_entries(entries, entry_count);
    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Successfully synced %zu groups to DHT\n", entry_count);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync groups to DHT\n");
    }

    return result;
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
    // v0.3.0: Flat structure - keys/identity.dsa
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir2);

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

// ============================================================================
// GROUP RESTORATION FROM DHT (Android startup fix)
// ============================================================================

/**
 * Restore groups from DHT to local cache
 *
 * On fresh startup (especially Android), the local SQLite cache is empty.
 * This function fetches the user's group list from DHT and syncs each group
 * to the local cache so they appear in the UI.
 *
 * Called during DHT stabilization (after 15-second routing table warmup).
 *
 * @param ctx Messenger context with identity loaded
 * @return Number of groups restored, or -1 on error
 */
int messenger_restore_groups_from_dht(messenger_context_t *ctx) {
    if (!ctx || !ctx->identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context for group restore\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "[RESTORE] Restoring groups from DHT for %.16s...\n", ctx->identity);

    // Get DHT context
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE] DHT not available\n");
        return -1;
    }

    // Load user's keys for decryption/verification
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE] Failed to get data directory\n");
        return -1;
    }

    // Load Kyber private key (for decryption)
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(kyber_path, ctx->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[RESTORE] Failed to load encrypted Kyber key\n");
            return -1;
        }
    } else {
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[RESTORE] Failed to load Kyber key\n");
            return -1;
        }
    }

    // Load Dilithium public key (for signature verification)
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *dilithium_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, ctx->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[RESTORE] Failed to load encrypted Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[RESTORE] Failed to load Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    }

    // Fetch group list from DHT
    char **group_uuids = NULL;
    size_t group_count = 0;

    int ret = dht_grouplist_fetch(
        dht_ctx,
        ctx->identity,
        &group_uuids,
        &group_count,
        kyber_key->private_key,
        dilithium_key->public_key
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (ret == -2) {
        // Not found in DHT - user has no groups yet
        QGP_LOG_INFO(LOG_TAG, "[RESTORE] No group list found in DHT (new user or no groups)\n");
        return 0;
    }

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE] Failed to fetch group list from DHT: %d\n", ret);
        return -1;
    }

    if (group_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "[RESTORE] Group list is empty in DHT\n");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[RESTORE] Found %zu groups in DHT, syncing to local cache...\n", group_count);

    // Sync each group to local cache
    int restored = 0;
    for (size_t i = 0; i < group_count; i++) {
        if (!group_uuids[i]) continue;

        QGP_LOG_DEBUG(LOG_TAG, "[RESTORE] Syncing group %zu/%zu: %s\n", i + 1, group_count, group_uuids[i]);

        ret = dht_groups_sync_from_dht(dht_ctx, group_uuids[i]);
        if (ret == 0) {
            restored++;
            QGP_LOG_INFO(LOG_TAG, "[RESTORE] Synced group: %s\n", group_uuids[i]);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RESTORE] Failed to sync group %s (may not exist in DHT)\n", group_uuids[i]);
        }
    }

    // Free group UUIDs array
    dht_grouplist_free_groups(group_uuids, group_count);

    QGP_LOG_INFO(LOG_TAG, "[RESTORE] Restored %d/%zu groups from DHT\n", restored, group_count);
    return restored;
}
