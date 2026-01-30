/**
 * @file groups.h
 * @brief Group Management - Minimal Interface
 *
 * This header was significantly cleaned up in v0.6.83 to remove dead code.
 *
 * The original groups.c had functions that operated on the 'groups' table
 * in groups.db, but the application actually uses 'dht_group_cache' table
 * in messages.db (via dht/shared/dht_groups.h).
 *
 * For group operations, use:
 * - dht_groups_create(), dht_groups_list_for_user(), etc. (dht/shared/dht_groups.h)
 * - messenger_create_group(), messenger_get_groups(), etc. (messenger.h)
 *
 * Functions retained here:
 * - groups_init(): Initialize database (required by messenger/init.c)
 * - groups_leave(): Clean up GEKs and messages when leaving a group
 * - groups_import_all(): Backward compatibility for old backup restores
 *
 * Part of DNA Messenger - GEK System
 * @date 2026-01-30
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
 * INITIALIZATION
 * ============================================================================ */

/**
 * Initialize groups subsystem
 *
 * @param backup_ctx Unused (legacy parameter)
 * @return 0 on success, -1 on error
 */
int groups_init(void *backup_ctx);

/* ============================================================================
 * GROUP CLEANUP
 * ============================================================================ */

/**
 * Leave a group (non-owner)
 *
 * Removes group from local database including GEKs and cached messages.
 * This is important for security - ensures encryption keys are deleted.
 *
 * @param group_uuid Group UUID
 * @return 0 on success, -1 on error
 */
int groups_leave(const char *group_uuid);

/* ============================================================================
 * BACKUP / RESTORE (Backward Compatibility)
 * ============================================================================ */

/**
 * Group export entry for backup (legacy format)
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
 * Import groups from backup (backward compatibility)
 *
 * Kept for restoring old backups. New backups (v0.6.83+) don't include
 * group data since groups are synced via dht_grouplist.
 *
 * Note: This writes to the 'groups' table which is NOT read by the app
 * (the app uses dht_group_cache). But we keep it for data preservation.
 *
 * @param entries Array of group entries to import
 * @param count Number of entries
 * @param imported_out Output for number of successfully imported groups (can be NULL)
 * @return 0 on success, -1 on error
 */
int groups_import_all(const groups_export_entry_t *entries, size_t count, int *imported_out);

#ifdef __cplusplus
}
#endif

#endif /* GROUPS_H */
