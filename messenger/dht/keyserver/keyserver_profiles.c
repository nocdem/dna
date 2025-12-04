/**
 * DHT Keyserver - Profile Management
 * Handles profile updates, identity loading, and display names
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"

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
        fprintf(stderr, "[DNA] Invalid arguments to dna_update_profile\n");
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
        memset(identity->registration_tx_hash, 0, sizeof(identity->registration_tx_hash));
        memset(identity->registration_network, 0, sizeof(identity->registration_network));
        identity->name_version = 0;

        printf("[DNA] Created new identity (old profile signature verification failed)\n");
    }

    // Update profile data
    memcpy(&identity->wallets, &profile->wallets, sizeof(identity->wallets));
    memcpy(&identity->socials, &profile->socials, sizeof(identity->socials));
    strncpy(identity->bio, profile->bio, sizeof(identity->bio) - 1);
    strncpy(identity->avatar_base64, profile->avatar_base64, sizeof(identity->avatar_base64) - 1);

    // Update metadata
    identity->timestamp = time(NULL);
    identity->version++;

    // Sign the updated identity profile with Dilithium5
    size_t msg_len = sizeof(identity->fingerprint) +
                   sizeof(identity->dilithium_pubkey) +
                   sizeof(identity->kyber_pubkey) +
                   sizeof(bool) +
                   sizeof(identity->registered_name) +
                   sizeof(uint64_t) * 2 +
                   sizeof(identity->registration_tx_hash) +
                   sizeof(identity->registration_network) +
                   sizeof(uint32_t) +
                   sizeof(identity->wallets) +
                   sizeof(identity->socials) +
                   sizeof(identity->bio) +
                   sizeof(identity->profile_picture_ipfs) +
                   sizeof(uint64_t) +
                   sizeof(uint32_t);

    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        fprintf(stderr, "[DNA] Failed to allocate message buffer for signing\n");
        dna_identity_free(identity);
        return -1;
    }

    size_t offset = 0;
    memcpy(msg + offset, identity->fingerprint, sizeof(identity->fingerprint));
    offset += sizeof(identity->fingerprint);
    memcpy(msg + offset, identity->dilithium_pubkey, sizeof(identity->dilithium_pubkey));
    offset += sizeof(identity->dilithium_pubkey);
    memcpy(msg + offset, identity->kyber_pubkey, sizeof(identity->kyber_pubkey));
    offset += sizeof(identity->kyber_pubkey);
    memcpy(msg + offset, &identity->has_registered_name, sizeof(bool));
    offset += sizeof(bool);
    memcpy(msg + offset, identity->registered_name, sizeof(identity->registered_name));
    offset += sizeof(identity->registered_name);

    // Network byte order for integers
    uint64_t registered_at_net = htonll(identity->name_registered_at);
    uint64_t expires_at_net = htonll(identity->name_expires_at);
    uint32_t name_version_net = htonl(identity->name_version);
    uint64_t timestamp_net = htonll(identity->timestamp);
    uint32_t version_net = htonl(identity->version);

    memcpy(msg + offset, &registered_at_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, &expires_at_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, identity->registration_tx_hash, sizeof(identity->registration_tx_hash));
    offset += sizeof(identity->registration_tx_hash);
    memcpy(msg + offset, identity->registration_network, sizeof(identity->registration_network));
    offset += sizeof(identity->registration_network);
    memcpy(msg + offset, &name_version_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(msg + offset, &identity->wallets, sizeof(identity->wallets));
    offset += sizeof(identity->wallets);
    memcpy(msg + offset, &identity->socials, sizeof(identity->socials));
    offset += sizeof(identity->socials);
    memcpy(msg + offset, identity->bio, sizeof(identity->bio));
    offset += sizeof(identity->bio);
    memcpy(msg + offset, identity->profile_picture_ipfs, sizeof(identity->profile_picture_ipfs));
    offset += sizeof(identity->profile_picture_ipfs);
    memcpy(msg + offset, &timestamp_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, &version_net, sizeof(uint32_t));

    // Sign with private key
    size_t siglen = sizeof(identity->signature);
    ret = qgp_dsa87_sign(identity->signature, &siglen, msg, msg_len, dilithium_privkey);

    free(msg);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to sign identity profile\n");
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Identity profile signed with Dilithium5\n");

    // Serialize to JSON
    char *json = dna_identity_to_json(identity);
    if (!json) {
        fprintf(stderr, "[DNA] Failed to serialize identity\n");
        dna_identity_free(identity);
        return -1;
    }

    // Create base key for unified identity (chunked layer handles hashing)
    // UNIFIED: Uses :identity key (replaces old :profile)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:identity", fingerprint);

    printf("[DNA] Updating identity for fingerprint %.16s...\n", fingerprint);
    printf("[DNA] Base key: %s (TTL=7 days)\n", base_key);

    // Store in DHT via chunked layer (7-day TTL for death privacy)
    ret = dht_chunked_publish(dht_ctx, base_key,
                              (uint8_t*)json, strlen(json),
                              DHT_CHUNK_TTL_7DAY);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[DNA] Failed to store in DHT: %s\n", dht_chunked_strerror(ret));
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    // Debug: Show what was stored (BEFORE freeing identity!)
    printf("[DNA] ✓ Profile updated successfully\n");
    printf("[DNA] DEBUG Profile Storage:\n");
    printf("[DNA]   Fingerprint: %s\n", fingerprint);
    printf("[DNA]   Base Key: %s\n", base_key);
    printf("[DNA]   Registered Name: %s\n", identity->has_registered_name ? identity->registered_name : "(none)");
    printf("[DNA]   Bio: %s\n", identity->bio[0] ? identity->bio : "(empty)");
    printf("[DNA]   Telegram: %s\n", identity->socials.telegram[0] ? identity->socials.telegram : "(empty)");
    printf("[DNA]   Twitter/X: %s\n", identity->socials.x[0] ? identity->socials.x : "(empty)");
    printf("[DNA]   GitHub: %s\n", identity->socials.github[0] ? identity->socials.github : "(empty)");
    printf("[DNA]   Backbone: %s\n", identity->wallets.backbone[0] ? identity->wallets.backbone : "(empty)");
    printf("[DNA]   Version: %u\n", identity->version);
    printf("[DNA]   Timestamp: %lu\n", (unsigned long)identity->timestamp);

    free(json);
    dna_identity_free(identity);

    return 0;
}

// Load complete DNA identity from DHT
// verify_signature: if true, verifies Dilithium5 signature (use for untrusted data)
//                   if false, skips verification (use for own identity or display-only)
int dna_load_identity_ex(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    bool verify_signature,
    dna_unified_identity_t **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_load_identity\n");
        return -1;
    }

    // Create base key for unified identity (chunked layer handles hashing)
    // UNIFIED: Uses :identity key (replaces old :profile)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:identity", fingerprint);

    printf("[DNA] Loading identity for fingerprint %.16s... (verify=%s)\n",
           fingerprint, verify_signature ? "yes" : "no");

    // Fetch from DHT via chunked layer (single value, chunked handles versioning)
    uint8_t *value = NULL;
    size_t value_len = 0;

    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);
    if (ret != DHT_CHUNK_OK || !value) {
        fprintf(stderr, "[DNA] Identity not found in DHT: %s\n", dht_chunked_strerror(ret));
        return -2;  // Not found
    }

    printf("[DNA] Loaded identity (%zu bytes)\n", value_len);

    // Create null-terminated copy for JSON parsing
    char *json_str = (char*)malloc(value_len + 1);
    if (!json_str) {
        fprintf(stderr, "[DNA] Memory allocation failed\n");
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    // Parse JSON
    dna_unified_identity_t *identity = NULL;
    if (dna_identity_from_json(json_str, &identity) != 0) {
        fprintf(stderr, "[DNA] JSON parse failed\n");
        free(json_str);
        return -1;
    }
    free(json_str);

    // Optional signature verification
    if (verify_signature) {
        // Build message to verify: everything except signature field
        size_t msg_len = sizeof(identity->fingerprint) +
                         sizeof(identity->dilithium_pubkey) +
                         sizeof(identity->kyber_pubkey) +
                         sizeof(bool) +  // has_registered_name
                         sizeof(identity->registered_name) +
                         sizeof(identity->name_registered_at) +
                         sizeof(identity->name_expires_at) +
                         sizeof(identity->registration_tx_hash) +
                         sizeof(identity->registration_network) +
                         sizeof(identity->name_version) +
                         sizeof(identity->wallets) +
                         sizeof(identity->socials) +
                         sizeof(identity->bio) +
                         sizeof(identity->profile_picture_ipfs) +
                         sizeof(identity->timestamp) +
                         sizeof(identity->version);

        uint8_t *msg = malloc(msg_len);
        if (!msg) {
            dna_identity_free(identity);
            return -1;
        }

        // Build message (same order as signing)
        size_t offset = 0;
        memcpy(msg + offset, identity->fingerprint, sizeof(identity->fingerprint));
        offset += sizeof(identity->fingerprint);
        memcpy(msg + offset, identity->dilithium_pubkey, sizeof(identity->dilithium_pubkey));
        offset += sizeof(identity->dilithium_pubkey);
        memcpy(msg + offset, identity->kyber_pubkey, sizeof(identity->kyber_pubkey));
        offset += sizeof(identity->kyber_pubkey);
        memcpy(msg + offset, &identity->has_registered_name, sizeof(bool));
        offset += sizeof(bool);
        memcpy(msg + offset, identity->registered_name, sizeof(identity->registered_name));
        offset += sizeof(identity->registered_name);

        // Network byte order for integers (same as signing)
        uint64_t registered_at_net = htonll(identity->name_registered_at);
        uint64_t expires_at_net = htonll(identity->name_expires_at);
        uint32_t name_version_net = htonl(identity->name_version);
        uint64_t timestamp_net = htonll(identity->timestamp);
        uint32_t version_net = htonl(identity->version);

        memcpy(msg + offset, &registered_at_net, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        memcpy(msg + offset, &expires_at_net, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        memcpy(msg + offset, identity->registration_tx_hash, sizeof(identity->registration_tx_hash));
        offset += sizeof(identity->registration_tx_hash);
        memcpy(msg + offset, identity->registration_network, sizeof(identity->registration_network));
        offset += sizeof(identity->registration_network);
        memcpy(msg + offset, &name_version_net, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(msg + offset, &identity->wallets, sizeof(identity->wallets));
        offset += sizeof(identity->wallets);
        memcpy(msg + offset, &identity->socials, sizeof(identity->socials));
        offset += sizeof(identity->socials);
        memcpy(msg + offset, identity->bio, sizeof(identity->bio));
        offset += sizeof(identity->bio);
        memcpy(msg + offset, identity->profile_picture_ipfs, sizeof(identity->profile_picture_ipfs));
        offset += sizeof(identity->profile_picture_ipfs);
        memcpy(msg + offset, &timestamp_net, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        memcpy(msg + offset, &version_net, sizeof(uint32_t));

        // Verify Dilithium5 signature
        int sig_result = qgp_dsa87_verify(identity->signature, sizeof(identity->signature),
                                           msg, msg_len, identity->dilithium_pubkey);

        free(msg);

        if (sig_result != 0) {
            fprintf(stderr, "[DNA] ✗ Signature verification failed\n");
            dna_identity_free(identity);
            return -3;  // Verification failed
        }

        // Verify fingerprint matches
        char computed_fingerprint[129];
        compute_fingerprint(identity->dilithium_pubkey, computed_fingerprint);

        if (strcmp(computed_fingerprint, fingerprint) != 0) {
            fprintf(stderr, "[DNA] ✗ Fingerprint mismatch\n");
            dna_identity_free(identity);
            return -3;  // Verification failed
        }

        printf("[DNA] ✓ Identity verified\n");
    }

    printf("[DNA] ✓ Identity loaded (timestamp=%lu, version=%u)\n",
           identity->timestamp, identity->version);
    if (identity->has_registered_name) {
        printf("[DNA] Name: %s (expires: %lu)\n",
               identity->registered_name, identity->name_expires_at);
    }

    *identity_out = identity;
    return 0;
}

// Wrapper for backward compatibility - always verifies signature
int dna_load_identity(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dna_unified_identity_t **identity_out
) {
    return dna_load_identity_ex(dht_ctx, fingerprint, true, identity_out);
}

// Get display name for fingerprint
// Note: Uses unverified load since we only need the name, not crypto verification
int dna_get_display_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **display_name_out
) {
    if (!fingerprint || !display_name_out) {
        return -1;
    }

    // Try to load identity from DHT (no signature verification needed for display name)
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity_ex(dht_ctx, fingerprint, false, &identity);

    if (ret == 0 && identity) {
        // Check if name is registered and not expired
        if (identity->has_registered_name && !dna_is_name_expired(identity)) {
            // Return registered name
            char *display = strdup(identity->registered_name);
            dna_identity_free(identity);

            if (!display) {
                return -1;
            }

            *display_name_out = display;
            printf("[DNA] ✓ Display name: %s (from identity)\n", display);
            return 0;
        }

        dna_identity_free(identity);
    }

    // Fallback: Return shortened fingerprint (first 16 chars + "...")
    char *display = malloc(32);
    if (!display) {
        return -1;
    }

    snprintf(display, 32, "%.16s...", fingerprint);
    *display_name_out = display;

    printf("[DNA] Display name: %s (fingerprint fallback)\n", display);
    return 0;
}
