/**
 * @file gsk.h
 * @brief Group Symmetric Key (GSK) Manager
 *
 * Manages AES-256 symmetric keys for group messaging encryption.
 * Provides generation, storage, rotation, and retrieval of GSKs.
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#ifndef GSK_H
#define GSK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * GSK key size (AES-256)
 */
#define GSK_KEY_SIZE 32

/**
 * Default GSK expiration (7 days in seconds)
 */
#define GSK_DEFAULT_EXPIRY (7 * 24 * 3600)

/**
 * GSK entry structure (local storage)
 */
typedef struct {
    char group_uuid[37];       // UUID v4 (36 + null terminator)
    uint32_t gsk_version;      // Rotation counter (0, 1, 2, ...)
    uint8_t gsk[GSK_KEY_SIZE]; // AES-256 key
    uint64_t created_at;       // Unix timestamp (seconds)
    uint64_t expires_at;       // created_at + GSK_DEFAULT_EXPIRY
} gsk_entry_t;

/**
 * Generate a new random GSK for a group
 *
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @param version GSK version number (0 for initial, increment on rotation)
 * @param gsk_out Output buffer for generated GSK (32 bytes)
 * @return 0 on success, -1 on error
 */
int gsk_generate(const char *group_uuid, uint32_t version, uint8_t gsk_out[GSK_KEY_SIZE]);

/**
 * Store GSK in local database
 *
 * Stores the GSK in the dht_group_gsks table with expiration timestamp.
 *
 * @param group_uuid Group UUID
 * @param version GSK version number
 * @param gsk GSK to store (32 bytes)
 * @return 0 on success, -1 on error
 */
int gsk_store(const char *group_uuid, uint32_t version, const uint8_t gsk[GSK_KEY_SIZE]);

/**
 * Load GSK from local database by version
 *
 * @param group_uuid Group UUID
 * @param version GSK version to load
 * @param gsk_out Output buffer for loaded GSK (32 bytes)
 * @return 0 on success, -1 on error (not found or expired)
 */
int gsk_load(const char *group_uuid, uint32_t version, uint8_t gsk_out[GSK_KEY_SIZE]);

/**
 * Load active (latest non-expired) GSK from local database
 *
 * Fetches the most recent GSK that hasn't expired yet.
 *
 * @param group_uuid Group UUID
 * @param gsk_out Output buffer for loaded GSK (32 bytes)
 * @param version_out Output for loaded GSK version number (optional, can be NULL)
 * @return 0 on success, -1 on error (no active GSK found)
 */
int gsk_load_active(const char *group_uuid, uint8_t gsk_out[GSK_KEY_SIZE], uint32_t *version_out);

/**
 * Rotate GSK (increment version, generate new key)
 *
 * Generates a new GSK with version = current_version + 1.
 * Does NOT publish to DHT (caller must handle distribution).
 *
 * @param group_uuid Group UUID
 * @param new_version_out Output for new version number
 * @param new_gsk_out Output buffer for new GSK (32 bytes)
 * @return 0 on success, -1 on error
 */
int gsk_rotate(const char *group_uuid, uint32_t *new_version_out, uint8_t new_gsk_out[GSK_KEY_SIZE]);

/**
 * Get current GSK version from local database
 *
 * Returns the highest GSK version number stored locally for a group.
 *
 * @param group_uuid Group UUID
 * @param version_out Output for current version (0 if no GSK exists)
 * @return 0 on success, -1 on error
 */
int gsk_get_current_version(const char *group_uuid, uint32_t *version_out);

/**
 * Delete expired GSKs from database
 *
 * Cleanup function to remove old GSKs that have expired.
 * Should be called periodically (e.g., on startup, daily background task).
 *
 * @return Number of deleted entries, -1 on error
 */
int gsk_cleanup_expired(void);

/**
 * Initialize GSK subsystem
 *
 * Creates dht_group_gsks table if it doesn't exist.
 * Should be called on messenger initialization.
 *
 * @param backup_ctx Message backup context (provides database access)
 * @return 0 on success, -1 on error
 */
int gsk_init(void *backup_ctx);

/**
 * Rotate GSK when a member is added to the group
 *
 * Automatically called by messenger_add_group_member().
 * Generates new GSK, builds Initial Key Packet, publishes to DHT,
 * and notifies all members.
 *
 * @param dht_ctx DHT context for publishing
 * @param group_uuid Group UUID
 * @param owner_identity Owner's identity (for signing)
 * @return 0 on success, -1 on error
 */
int gsk_rotate_on_member_add(void *dht_ctx, const char *group_uuid, const char *owner_identity);

/**
 * Rotate GSK when a member is removed from the group
 *
 * Automatically called by messenger_remove_group_member().
 * Generates new GSK, builds Initial Key Packet, publishes to DHT,
 * and notifies all members.
 *
 * @param dht_ctx DHT context for publishing
 * @param group_uuid Group UUID
 * @param owner_identity Owner's identity (for signing)
 * @return 0 on success, -1 on error
 */
int gsk_rotate_on_member_remove(void *dht_ctx, const char *group_uuid, const char *owner_identity);

#ifdef __cplusplus
}
#endif

#endif // GSK_H
