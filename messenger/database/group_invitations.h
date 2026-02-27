/*
 * DNA Messenger - Group Invitations Database
 *
 * Manages pending group invitations in local SQLite database.
 * Stores invitations until user accepts or rejects them.
 */

#ifndef GROUP_INVITATIONS_H
#define GROUP_INVITATIONS_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Invitation status
typedef enum {
    INVITATION_STATUS_PENDING = 0,
    INVITATION_STATUS_ACCEPTED = 1,
    INVITATION_STATUS_REJECTED = 2
} invitation_status_t;

// Group invitation structure
typedef struct {
    char group_uuid[37];        // UUID v4 (36 chars + null)
    char group_name[256];       // Group display name
    char inviter[256];          // Who invited this user (identity or fingerprint)
    int64_t invited_at;         // Unix timestamp when invited
    invitation_status_t status; // pending/accepted/rejected
    int member_count;           // Number of members in group (for display)
} group_invitation_t;

/**
 * @brief Initialize group invitations database
 *
 * Creates the pending_invitations table if it doesn't exist.
 * Database path: ~/.dna/<identity>_invitations.db (per-identity)
 *
 * @param identity: User's identity (for per-identity database)
 * @return: 0 on success, -1 on error
 */
int group_invitations_init(const char *identity);

/**
 * @brief Store a new group invitation
 *
 * @param invitation: Invitation to store
 * @return: 0 on success, -1 on error, -2 if already exists
 */
int group_invitations_store(const group_invitation_t *invitation);

/**
 * @brief Get all pending invitations
 *
 * @param invitations_out: Output array of invitations (caller must free)
 * @param count_out: Output count of invitations
 * @return: 0 on success, -1 on error
 */
int group_invitations_get_pending(group_invitation_t **invitations_out, int *count_out);

/**
 * @brief Get a specific invitation by group UUID
 *
 * @param group_uuid: UUID of the group
 * @param invitation_out: Output invitation (caller must free if returned)
 * @return: 0 on success, -1 on error, -2 if not found
 */
int group_invitations_get(const char *group_uuid, group_invitation_t **invitation_out);

/**
 * @brief Update invitation status
 *
 * @param group_uuid: UUID of the group
 * @param status: New status (accepted/rejected)
 * @return: 0 on success, -1 on error
 */
int group_invitations_update_status(const char *group_uuid, invitation_status_t status);

/**
 * @brief Delete an invitation
 *
 * @param group_uuid: UUID of the group
 * @return: 0 on success, -1 on error
 */
int group_invitations_delete(const char *group_uuid);

/**
 * @brief Free invitation array
 *
 * @param invitations: Array to free
 * @param count: Number of invitations in array
 */
void group_invitations_free(group_invitation_t *invitations, int count);

/**
 * @brief Cleanup invitations database
 *
 * Closes database connection. Call on app shutdown.
 */
void group_invitations_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // GROUP_INVITATIONS_H
