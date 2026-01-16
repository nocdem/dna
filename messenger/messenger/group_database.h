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
 * Part of DNA Messenger - GEK System
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
 * @return Database context or NULL on error
 */
group_database_context_t* group_database_init(void);

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

#ifdef __cplusplus
}
#endif

#endif /* GROUP_DATABASE_H */
