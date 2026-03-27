/**
 * Following Database
 * Local SQLite database for follow list management (per-identity)
 *
 * Architecture:
 * - Per-identity database: ~/.dna/db/following.db
 * - One-directional follow (no approval needed)
 * - DHT synchronization for multi-device / seed recovery
 * - Private: only the owner can see their follow list
 *
 * Database Schema:
 * CREATE TABLE following (
 *     fingerprint TEXT PRIMARY KEY,
 *     followed_at INTEGER DEFAULT 0
 * );
 *
 * @file following_db.h
 */

#ifndef FOLLOWING_DB_H
#define FOLLOWING_DB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Following entry
 */
typedef struct {
    char fingerprint[129];     /* 128 hex chars + null */
    uint64_t followed_at;      /* Unix timestamp when followed */
} following_entry_t;

/**
 * Following list
 */
typedef struct {
    following_entry_t *entries;
    size_t count;
} following_list_t;

/**
 * Initialize following database
 *
 * @param owner_identity: Identity who owns this follow list
 * @return: 0 on success, -1 on error
 */
int following_db_init(const char *owner_identity);

/**
 * Add a user to following list
 *
 * @param fingerprint: 128-char hex fingerprint to follow
 * @return: 0 on success, -1 on error, -2 if already following
 */
int following_db_add(const char *fingerprint);

/**
 * Remove a user from following list
 *
 * @param fingerprint: 128-char hex fingerprint to unfollow
 * @return: 0 on success, -1 on error
 */
int following_db_remove(const char *fingerprint);

/**
 * Check if following a user
 *
 * @param fingerprint: Fingerprint to check
 * @return: true if following, false otherwise
 */
bool following_db_exists(const char *fingerprint);

/**
 * Get all followed users
 *
 * @param list_out: Output list (caller must free with following_db_free_list)
 * @return: 0 on success, -1 on error
 */
int following_db_list(following_list_t **list_out);

/**
 * Get following count
 *
 * @return: Number of followed users, or -1 on error
 */
int following_db_count(void);

/**
 * Clear all following entries
 * Used for REPLACE sync mode when syncing from DHT
 *
 * @return: 0 on success, -1 on error
 */
int following_db_clear_all(void);

/**
 * Free following list
 *
 * @param list: List to free
 */
void following_db_free_list(following_list_t *list);

/**
 * Close database
 */
void following_db_close(void);

#ifdef __cplusplus
}
#endif

#endif /* FOLLOWING_DB_H */
