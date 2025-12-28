/**
 * DHT Keyserver - Profile Management
 * Handles profile updates, identity loading, and display names
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "KEYSERVER"

// Update DNA profile data
int dna_update_profile(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dna_profile_data_t *profile,
    const uint8_t *dilithium_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey
) {
    if (!dht_ctx || !fingerprint || !profile || !dilithium_privkey || !dilithium_pubkey || !kyber_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to dna_update_profile\n");
        return -1;
    }

    // Load existing identity
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret != 0) {
        // Create new identity if doesn't exist yet
        identity = dna_identity_create();
        if (!identity) {
            return -1;
        }

        // Set fingerprint and public keys
        strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
        memcpy(identity->dilithium_pubkey, dilithium_pubkey, sizeof(identity->dilithium_pubkey));
        memcpy(identity->kyber_pubkey, kyber_pubkey, sizeof(identity->kyber_pubkey));

        // Initialize name registration fields
        identity->has_registered_name = false;
        memset(identity->registered_name, 0, sizeof(identity->registered_name));
        identity->name_registered_at = 0;
        identity->name_expires_at = 0;
        identity->name_version = 0;

        QGP_LOG_INFO(LOG_TAG, "Created new identity (old profile signature verification failed)\n");
    }

    // Update profile data
    memcpy(&identity->wallets, &profile->wallets, sizeof(identity->wallets));
    memcpy(&identity->socials, &profile->socials, sizeof(identity->socials));
    strncpy(identity->bio, profile->bio, sizeof(identity->bio) - 1);
    strncpy(identity->avatar_base64, profile->avatar_base64, sizeof(identity->avatar_base64) - 1);

    // DEBUG: Log avatar being saved
    size_t avatar_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
    QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] dna_update_profile: saving avatar_base64 length=%zu\n", avatar_len);

    // Update metadata
    identity->timestamp = time(NULL);
    identity->version++;

    // Sign the JSON representation (not struct bytes) for forward compatibility
    // This allows struct changes without breaking signature verification
    char *json_unsigned = dna_identity_to_json_unsigned(identity);
    if (!json_unsigned) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity for signing\n");
        dna_identity_free(identity);
        return -1;
    }

    // Sign with Dilithium5
    size_t siglen = sizeof(identity->signature);
    ret = qgp_dsa87_sign(identity->signature, &siglen,
                         (uint8_t*)json_unsigned, strlen(json_unsigned),
                         dilithium_privkey);
    free(json_unsigned);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign identity profile\n");
        dna_identity_free(identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity profile signed with Dilithium5 (JSON-based)\n");

    // Serialize to JSON (now includes signature)
    char *json = dna_identity_to_json(identity);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity\n");
        dna_identity_free(identity);
        return -1;
    }

    // Create base key for profile (chunked layer handles hashing)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:profile", fingerprint);

    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] dna_update_profile called for %.16s...\n", fingerprint);
    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] Base key: %s\n", base_key);

    // Store in DHT via chunked layer (permanent storage)
    ret = dht_chunked_publish(dht_ctx, base_key,
                              (uint8_t*)json, strlen(json),
                              DHT_CHUNK_TTL_365DAY);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT: %s\n", dht_chunked_strerror(ret));
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    free(json);
    dna_identity_free(identity);

    return 0;
}

// Load complete DNA identity from DHT
int dna_load_identity(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dna_unified_identity_t **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to dna_load_identity\n");
        return -1;
    }

    // Create base key for profile (chunked layer handles hashing)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:profile", fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Loading identity for fingerprint %.16s...\n", fingerprint);
    QGP_LOG_INFO(LOG_TAG, "Base key: %s\n", base_key);

    // Fetch from DHT via chunked layer (single value, chunked handles versioning)
    uint8_t *value = NULL;
    size_t value_len = 0;

    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);
    if (ret != DHT_CHUNK_OK || !value) {
        QGP_LOG_ERROR(LOG_TAG, "Identity not found in DHT: %s\n", dht_chunked_strerror(ret));
        return -2;  // Not found
    }

    QGP_LOG_INFO(LOG_TAG, "Loaded profile (%zu bytes), verifying...\n", value_len);

    // Create null-terminated copy for JSON parsing
    char *json_str = (char*)malloc(value_len + 1);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    // DEBUG: Check if avatar_base64 key exists in raw JSON (must use null-terminated string)
    {
        const char *avatar_key = "\"avatar_base64\"";
        const char *found = strstr(json_str, avatar_key);
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] Raw JSON has avatar_base64 key: %s\n",
                     found ? "YES" : "NO");
    }

    // Parse JSON
    dna_unified_identity_t *identity = NULL;
    if (dna_identity_from_json(json_str, &identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "JSON parse failed\n");
        free(json_str);
        return -1;
    }
    free(json_str);

    // DEBUG: Log avatar data after JSON parse (WARN level to ensure visibility)
    size_t avatar_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
    QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] dna_load_identity: avatar_base64 length=%zu (first 20 chars: %.20s)\n",
                 avatar_len, avatar_len > 0 ? identity->avatar_base64 : "(empty)");

    // Verify signature against JSON representation (for forward compatibility)
    // This allows struct changes without breaking signature verification
    char *json_unsigned = dna_identity_to_json_unsigned(identity);
    if (!json_unsigned) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity for verification\n");
        dna_identity_free(identity);
        return -1;
    }

    // Verify Dilithium5 signature against unsigned JSON
    int sig_result = qgp_dsa87_verify(identity->signature, sizeof(identity->signature),
                                       (uint8_t*)json_unsigned, strlen(json_unsigned),
                                       identity->dilithium_pubkey);

    if (sig_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "✗ Signature verification failed for profile: name=%s, fp=%.16s...\n",
                      identity->has_registered_name ? identity->registered_name : "(none)",
                      identity->fingerprint);
        QGP_LOG_DEBUG(LOG_TAG, "Verification details: json_len=%zu, sig_result=%d, version=%u\n",
                      strlen(json_unsigned), sig_result, identity->version);
        QGP_LOG_DEBUG(LOG_TAG, "Possible causes: 1) Stale profile in DHT, 2) Key rotation, 3) Profile edited after signing\n");
        free(json_unsigned);
        dna_identity_free(identity);
        return -3;  // Verification failed
    }
    free(json_unsigned);

    // Verify fingerprint matches
    char computed_fingerprint[129];
    compute_fingerprint(identity->dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "✗ Fingerprint mismatch\n");
        dna_identity_free(identity);
        return -3;  // Verification failed
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Profile loaded and verified (timestamp=%lu, version=%u)\n",
           identity->timestamp, identity->version);
    if (identity->has_registered_name) {
        QGP_LOG_INFO(LOG_TAG, "Name: %s (expires: %lu)\n",
               identity->registered_name, identity->name_expires_at);
    }

    *identity_out = identity;
    return 0;
}
