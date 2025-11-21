/**
 * @file group_ownership.h
 * @brief Group Ownership Manager - Decentralized Ownership Transfer
 *
 * Implements automatic ownership transfer when the owner goes offline.
 * Uses DHT heartbeat mechanism with 7-day liveness check and deterministic
 * fallback algorithm (highest SHA3-512 fingerprint becomes new owner).
 *
 * Architecture:
 * - Owner publishes heartbeat to DHT every 6 hours
 * - Members check heartbeat every 2 minutes (background polling)
 * - If heartbeat expires (7 days), deterministic transfer initiated
 * - New owner selected by: highest SHA3-512(fingerprint) among active members
 * - New owner rotates GSK to revoke old owner's access
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#ifndef GROUP_OWNERSHIP_H
#define GROUP_OWNERSHIP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Heartbeat interval (6 hours in seconds)
 * Owner publishes heartbeat every 6 hours to prove liveness
 */
#define OWNER_HEARTBEAT_INTERVAL (6 * 3600)

/**
 * Liveness timeout (7 days in seconds)
 * If owner hasn't updated heartbeat in 7 days, ownership transfer initiated
 */
#define OWNER_LIVENESS_TIMEOUT (7 * 24 * 3600)

/**
 * Ownership heartbeat entry (DHT storage)
 */
typedef struct {
    char group_uuid[37];          // Group UUID
    char owner_fingerprint[129];  // Owner's fingerprint (128 hex + null)
    uint64_t last_heartbeat;      // Unix timestamp of last heartbeat
    uint32_t heartbeat_version;   // Incremented on each heartbeat
    uint8_t signature[4627];      // Dilithium5 signature (owner proves identity)
} ownership_heartbeat_t;

/**
 * Initialize group ownership subsystem
 *
 * @return 0 on success, -1 on error
 */
int group_ownership_init(void);

/**
 * Publish owner heartbeat to DHT
 *
 * Called by group owner every OWNER_HEARTBEAT_INTERVAL (6 hours).
 * Updates DHT with current timestamp to prove liveness.
 *
 * DHT Key: SHA3-512(group_uuid + ":ownership")
 * TTL: 7 days (OWNER_LIVENESS_TIMEOUT)
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param owner_fingerprint Owner's fingerprint (128 hex chars)
 * @param owner_dilithium_privkey Owner's Dilithium5 private key (for signing)
 * @return 0 on success, -1 on error
 */
int group_ownership_publish_heartbeat(
    void *dht_ctx,
    const char *group_uuid,
    const char *owner_fingerprint,
    const uint8_t *owner_dilithium_privkey
);

/**
 * Check owner liveness from DHT
 *
 * Called by group members every 2 minutes (background polling).
 * Fetches heartbeat from DHT and checks if last_heartbeat is within
 * OWNER_LIVENESS_TIMEOUT (7 days).
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param is_alive_out Output: true if owner is alive, false if timeout
 * @param owner_fingerprint_out Output: Current owner's fingerprint (129 bytes, can be NULL)
 * @return 0 on success, -1 on error (DHT fetch failed)
 */
int group_ownership_check_liveness(
    void *dht_ctx,
    const char *group_uuid,
    bool *is_alive_out,
    char *owner_fingerprint_out
);

/**
 * Initiate ownership transfer (deterministic algorithm)
 *
 * Called when owner liveness check fails.
 * Uses deterministic algorithm to select new owner:
 * - Sort all group members by SHA3-512(fingerprint)
 * - Highest hash becomes new owner
 * - New owner publishes heartbeat and rotates GSK
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param my_fingerprint My fingerprint (128 hex chars)
 * @param my_dilithium_privkey My Dilithium5 private key (if I become owner)
 * @param became_owner_out Output: true if I became new owner, false otherwise
 * @return 0 on success, -1 on error
 */
int group_ownership_transfer(
    void *dht_ctx,
    const char *group_uuid,
    const char *my_fingerprint,
    const uint8_t *my_dilithium_privkey,
    bool *became_owner_out
);

/**
 * Get current owner fingerprint from DHT
 *
 * Simple helper to fetch current owner without liveness check.
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param owner_fingerprint_out Output buffer (129 bytes)
 * @return 0 on success, -1 on error (not found or DHT error)
 */
int group_ownership_get_current_owner(
    void *dht_ctx,
    const char *group_uuid,
    char *owner_fingerprint_out
);

/**
 * Helper: Calculate deterministic owner from member list
 *
 * Returns the member with highest SHA3-512(fingerprint) hash.
 * Used for deterministic ownership transfer.
 *
 * @param member_fingerprints Array of member fingerprints (128 hex chars each)
 * @param member_count Number of members
 * @param new_owner_out Output: Fingerprint of new owner (129 bytes)
 * @return 0 on success, -1 on error
 */
int group_ownership_calculate_new_owner(
    const char **member_fingerprints,
    size_t member_count,
    char *new_owner_out
);

#ifdef __cplusplus
}
#endif

#endif // GROUP_OWNERSHIP_H
