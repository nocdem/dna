/*
 * DNA Messenger - Identity Module Implementation
 */

#include "identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_types.h"
#include "../crypto/utils/qgp_log.h"
#include "../dht/core/dht_keyserver.h"
#include "../p2p/p2p_transport.h"

#define LOG_TAG "IDENTITY"

// ============================================================================
// FINGERPRINT UTILITIES (Phase 4: Fingerprint-First Identity)
// ============================================================================

/**
 * Compute fingerprint from Dilithium5 public key in a key file
 */
int messenger_compute_identity_fingerprint(const char *identity, char *fingerprint_out) {
    if (!identity || !fingerprint_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to messenger_compute_identity_fingerprint");
        return -1;
    }

    // Load Dilithium key file
    const char *home = qgp_platform_home_dir();
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s/keys/%s.dsa", home, identity, identity);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key: %s", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->public_key) {
        QGP_LOG_ERROR(LOG_TAG, "Not a Dilithium5 key or missing public key");
        qgp_key_free(key);
        return -1;
    }

    // Compute fingerprint using DHT keyserver function
    dna_compute_fingerprint(key->public_key, fingerprint_out);

    qgp_key_free(key);
    return 0;
}

/**
 * Check if a string is a valid fingerprint (128 hex characters)
 */
bool messenger_is_fingerprint(const char *str) {
    if (!str) return false;

    size_t len = strlen(str);
    if (len != 128) return false;

    // Check all characters are hex
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }

    return true;
}

/**
 * Get display name for an identity (fingerprint or name)
 */
int messenger_get_display_name(messenger_context_t *ctx, const char *identifier, char *display_name_out) {
    if (!ctx || !identifier || !display_name_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to messenger_get_display_name");
        return -1;
    }

    // Check if identifier is a fingerprint
    if (messenger_is_fingerprint(identifier)) {
        // Try to resolve to registered name via DHT (using reverse lookup, not full profile)
        dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
        if (dht_ctx) {
            char *registered_name = NULL;
            int ret = dht_keyserver_reverse_lookup(dht_ctx, identifier, &registered_name);
            if (ret == 0 && registered_name) {
                strncpy(display_name_out, registered_name, 255);
                display_name_out[255] = '\0';
                free(registered_name);
                return 0;
            }
        }

        // No registered name found, return shortened fingerprint (first 5 bytes + ... + last 5 bytes)
        // Fingerprint is 128 hex chars (64 bytes), show first 10 chars + "..." + last 10 chars
        size_t len = strlen(identifier);
        if (len == 128) {
            snprintf(display_name_out, 256, "%.10s...%.10s", identifier, identifier + 118);
        } else {
            // Fallback for non-standard length
            snprintf(display_name_out, 256, "%.10s...", identifier);
        }
        return 0;
    }

    // Not a fingerprint, assume it's already a name
    strncpy(display_name_out, identifier, 255);
    display_name_out[255] = '\0';
    return 0;
}
