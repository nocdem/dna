/**
 * @file group_database.h
 * @brief Group Database Module - SQLite storage for all group data
 *
 * Separate database for group-related data:
 * - Groups metadata
 * - Group members
 * - Group Encryption Keys (GEK)
 * - Pending invitations
 * - Group messages
 *
 * Database path: ~/.dna/db/groups.db
 *
 * Part of DNA Connect - GEK System
 *
 * @date 2026-01-15
 */

#ifndef GROUP_DATABASE_H
#define GROUP_DATABASE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * TYPES
 * ============================================================================ */

/**
 * Group Database Context (opaque)
 */
typedef struct group_database_context group_database_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

/**
 * Initialize group database
 *
 * Creates ~/.dna/db/groups.db if it doesn't exist.
 * Opens connection to SQLite database.
 * Creates all group-related tables.
 *
 * @param db_key Database encryption key (128-char hex, NULL for unencrypted)
 * @return Database context or NULL on error
 */
group_database_context_t* group_database_init(const char *db_key);

/**
 * Get the global group database instance
 *
 * Returns the singleton instance initialized by group_database_init().
 * Returns NULL if not initialized.
 *
 * @return Global group database context or NULL
 */
group_database_context_t* group_database_get_instance(void);

/**
 * Get raw SQLite database handle
 *
 * Used by modules that need direct database access (e.g., GEK, groups).
 *
 * @param ctx Group database context
 * @return SQLite database handle (sqlite3*) or NULL if ctx is NULL
 */
void* group_database_get_db(group_database_context_t *ctx);

/**
 * Close group database
 *
 * Closes SQLite connection and frees context.
 *
 * @param ctx Group database context
 */
void group_database_close(group_database_context_t *ctx);

/* ============================================================================
 * STATISTICS
 * ============================================================================ */

/**
 * Get group database statistics
 *
 * @param ctx Group database context
 * @param group_count Output for number of groups
 * @param member_count Output for total members across all groups
 * @param message_count Output for total group messages
 * @return 0 on success, -1 on error
 */
int group_database_get_stats(group_database_context_t *ctx,
                              int *group_count,
                              int *member_count,
                              int *message_count);

/* ============================================================================
 * DHT SALT ACCESSORS (CORE-04 — Phase 6 plan 03)
 *
 * Per-group 32-byte DHT key privacy salt. Mirrors the per-contact salt API
 * in database/contacts_db.c (contacts_db_set_salt / contacts_db_get_salt).
 * Plan 04 will use these to hard-cut over the group outbox to salted keys.
 * ============================================================================ */

/**
 * Check whether a group has a DHT salt provisioned.
 *
 * @param group_uuid Group UUID
 * @return 1 if has_dht_salt=1 on the group row, 0 otherwise (including
 *         missing group / uninitialized db / NULL args)
 */
int group_database_has_dht_salt(const char *group_uuid);

/**
 * Read the 32-byte DHT salt for a group.
 *
 * @param group_uuid Group UUID
 * @param salt_out Output buffer, MUST be at least 32 bytes
 * @return 0 on success, -1 if not found or salt not set
 */
int group_database_get_dht_salt(const char *group_uuid, uint8_t *salt_out);

/**
 * Set the 32-byte DHT salt for a group. Marks has_dht_salt=1 on the row.
 *
 * @param group_uuid Group UUID (group row must already exist)
 * @param salt Exactly 32 bytes of salt material
 * @return 0 on success, -1 on error (no such group, db error, NULL args)
 */
int group_database_set_dht_salt(const char *group_uuid, const uint8_t *salt);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_DATABASE_H */
