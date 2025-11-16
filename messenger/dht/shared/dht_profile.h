/**
 * DHT Profile Storage
 * Public user profile data stored in DHT
 *
 * Architecture:
 * - DHT Key: SHA3-512(user_fingerprint + ":profile")
 * - Storage: dht_put_signed_permanent(value_id=1) - replacement, not accumulation
 * - Format: Public JSON (no encryption, Dilithium5 signed)
 * - TTL: PERMANENT (never expires)
 * - Updates: Replace old profile (signed put with same value_id)
 *
 * Profile Schema:
 * {
 *     "display_name": "Alice",
 *     "bio": "Post-quantum cryptography enthusiast",
 *     "avatar_hash": "sha3_512_hash_of_avatar_data",
 *     "location": "San Francisco, CA",
 *     "website": "https://alice.example.com",
 *     "created_at": 1731398400,
 *     "updated_at": 1731450000
 * }
 *
 * @file dht_profile.h
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#ifndef DHT_PROFILE_H
#define DHT_PROFILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../core/dht_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum field sizes
 */
#define DHT_PROFILE_MAX_DISPLAY_NAME    128
#define DHT_PROFILE_MAX_BIO             512
#define DHT_PROFILE_MAX_AVATAR_HASH     128
#define DHT_PROFILE_MAX_LOCATION        128
#define DHT_PROFILE_MAX_WEBSITE         256

/**
 * User profile data
 */
typedef struct {
    char display_name[DHT_PROFILE_MAX_DISPLAY_NAME];   // Display name
    char bio[DHT_PROFILE_MAX_BIO];                     // Biography
    char avatar_hash[DHT_PROFILE_MAX_AVATAR_HASH];     // SHA3-512 hash of avatar image
    char location[DHT_PROFILE_MAX_LOCATION];           // Location (optional)
    char website[DHT_PROFILE_MAX_WEBSITE];             // Website URL (optional)
    uint64_t created_at;                                // Profile creation timestamp
    uint64_t updated_at;                                // Last update timestamp
} dht_profile_t;

/**
 * Initialize DHT profile subsystem
 * Call once at startup
 *
 * @return 0 on success, -1 on error
 */
int dht_profile_init(void);

/**
 * Cleanup DHT profile subsystem
 * Call once at shutdown
 */
void dht_profile_cleanup(void);

/**
 * Publish user profile to DHT
 * Uses signed puts with value_id=1 for replacement (no accumulation)
 *
 * @param dht_ctx DHT context
 * @param user_fingerprint User's fingerprint (64-byte hex string)
 * @param profile Profile data to publish
 * @param dilithium_privkey Dilithium5 private key for signing (4896 bytes)
 * @return 0 on success, -1 on error
 */
int dht_profile_publish(
    dht_context_t *dht_ctx,
    const char *user_fingerprint,
    const dht_profile_t *profile,
    const uint8_t *dilithium_privkey
);

/**
 * Fetch user profile from DHT
 *
 * @param dht_ctx DHT context
 * @param user_fingerprint User's fingerprint (64-byte hex string)
 * @param profile_out Output profile data (caller provides buffer)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_profile_fetch(
    dht_context_t *dht_ctx,
    const char *user_fingerprint,
    dht_profile_t *profile_out
);

/**
 * Delete user profile from DHT (best-effort)
 * Note: DHT deletion is not guaranteed. For reliable deletion,
 * publish an empty profile instead.
 *
 * @param dht_ctx DHT context
 * @param user_fingerprint User's fingerprint (64-byte hex string)
 * @return 0 on success, -1 on error
 */
int dht_profile_delete(
    dht_context_t *dht_ctx,
    const char *user_fingerprint
);

/**
 * Validate profile data
 * Checks field sizes and content
 *
 * @param profile Profile to validate
 * @return true if valid, false otherwise
 */
bool dht_profile_validate(const dht_profile_t *profile);

/**
 * Create empty profile
 * Initializes all fields to empty/zero
 *
 * @param profile_out Output profile (caller provides buffer)
 */
void dht_profile_init_empty(dht_profile_t *profile_out);

#ifdef __cplusplus
}
#endif

#endif // DHT_PROFILE_H
