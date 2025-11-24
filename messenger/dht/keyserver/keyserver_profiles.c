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
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !profile || !dilithium_privkey) {
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

        // Set fingerprint and keys (keys must be provided separately)
        strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
        // Note: Keys must be set by caller before calling this function
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

    // Compute DHT key: SHA3-512(fingerprint + ":profile")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        fprintf(stderr, "[DNA] Failed to compute DHT key\n");
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    printf("[DNA] Updating profile for fingerprint %.16s...\n", fingerprint);
    printf("[DNA] DHT key: %.32s...\n", dht_key);

    // Store in DHT (permanent storage, signed with fixed value_id=1 to prevent accumulation)
    ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                    (uint8_t*)json, strlen(json), 1);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store in DHT\n");
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    // Debug: Show what was stored (BEFORE freeing identity!)
    printf("[DNA] ✓ Profile updated successfully\n");
    printf("[DNA] DEBUG Profile Storage:\n");
    printf("[DNA]   Fingerprint: %s\n", fingerprint);
    printf("[DNA]   DHT Key: %s\n", dht_key);
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
int dna_load_identity(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dna_unified_identity_t **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_load_identity\n");
        return -1;
    }

    // Compute DHT key: SHA3-512(fingerprint + ":profile")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        fprintf(stderr, "[DNA] Failed to compute DHT key\n");
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    printf("[DNA] Loading identity for fingerprint %.16s...\n", fingerprint);
    printf("[DNA] DHT key: %.32s...\n", dht_key);

    // Fetch ALL values from DHT (OpenDHT append-only model)
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t value_count = 0;

    if (dht_get_all(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &values, &values_len, &value_count) != 0) {
        fprintf(stderr, "[DNA] Identity not found in DHT\n");
        return -2;  // Not found
    }

    printf("[DNA] Found %zu profile version(s) in DHT\n", value_count);

    // Parse and verify all values, track newest valid one
    dna_unified_identity_t *best_identity = NULL;
    uint64_t best_timestamp = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (!values[i] || values_len[i] == 0) {
            continue;  // Skip empty values
        }

        printf("[DNA] Verifying version %zu/%zu (%zu bytes)...\n", i+1, value_count, values_len[i]);

        // Create null-terminated copy for JSON parsing
        char *json_str = (char*)malloc(values_len[i] + 1);
        if (!json_str) {
            fprintf(stderr, "[DNA] ⚠ Version %zu: Memory allocation failed\n", i+1);
            continue;
        }
        memcpy(json_str, values[i], values_len[i]);
        json_str[values_len[i]] = '\0';

        // Parse JSON
        dna_unified_identity_t *identity = NULL;
        if (dna_identity_from_json(json_str, &identity) != 0) {
            fprintf(stderr, "[DNA] ⚠ Version %zu: JSON parse failed\n", i+1);
            free(json_str);
            continue;
        }
        free(json_str);

        // Verify signature
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

    // DEBUG: Print message length calculation
    printf("[DNA] DEBUG Verification message length: %zu bytes\n", msg_len);
    printf("[DNA] DEBUG Field sizes:\n");
    printf("[DNA]   fingerprint: %zu\n", sizeof(identity->fingerprint));
    printf("[DNA]   dilithium_pubkey: %zu\n", sizeof(identity->dilithium_pubkey));
    printf("[DNA]   kyber_pubkey: %zu\n", sizeof(identity->kyber_pubkey));
    printf("[DNA]   bool: %zu\n", sizeof(bool));
    printf("[DNA]   registered_name: %zu\n", sizeof(identity->registered_name));
    printf("[DNA]   name_registered_at: %zu\n", sizeof(identity->name_registered_at));
    printf("[DNA]   name_expires_at: %zu\n", sizeof(identity->name_expires_at));
    printf("[DNA]   registration_tx_hash: %zu\n", sizeof(identity->registration_tx_hash));
    printf("[DNA]   registration_network: %zu\n", sizeof(identity->registration_network));
    printf("[DNA]   name_version: %zu\n", sizeof(identity->name_version));
    printf("[DNA]   wallets: %zu\n", sizeof(identity->wallets));
    printf("[DNA]   socials: %zu\n", sizeof(identity->socials));
    printf("[DNA]   bio: %zu\n", sizeof(identity->bio));
    printf("[DNA]   profile_picture_ipfs: %zu\n", sizeof(identity->profile_picture_ipfs));
    printf("[DNA]   timestamp: %zu\n", sizeof(identity->timestamp));
    printf("[DNA]   version: %zu\n", sizeof(identity->version));
    printf("[DNA] DEBUG Profile values:\n");
    printf("[DNA]   has_registered_name: %d\n", identity->has_registered_name);
    printf("[DNA]   timestamp: %lu\n", (unsigned long)identity->timestamp);
    printf("[DNA]   version: %u\n", identity->version);

    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        dna_identity_free(identity);
        return -1;
    }

    // Build message (same order as signing in messenger.c)
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
            fprintf(stderr, "[DNA] ✗ Version %zu: Signature verification failed\n", i+1);
            dna_identity_free(identity);
            continue;
        }

        // Verify fingerprint matches
        char computed_fingerprint[129];
        compute_fingerprint(identity->dilithium_pubkey, computed_fingerprint);

        if (strcmp(computed_fingerprint, fingerprint) != 0) {
            fprintf(stderr, "[DNA] ✗ Version %zu: Fingerprint mismatch\n", i+1);
            dna_identity_free(identity);
            continue;
        }

        printf("[DNA] ✓ Version %zu: Valid (timestamp=%lu, version=%u)\n",
               i+1, identity->timestamp, identity->version);

        // Check if this is the newest valid version
        if (identity->timestamp > best_timestamp) {
            // Free previous best if exists
            if (best_identity) {
                dna_identity_free(best_identity);
            }
            best_identity = identity;
            best_timestamp = identity->timestamp;
        } else {
            // This version is older, discard it
            dna_identity_free(identity);
        }
    }

    // Free values array
    for (size_t i = 0; i < value_count; i++) {
        free(values[i]);
    }
    free(values);
    free(values_len);

    // Check if we found any valid identity
    if (!best_identity) {
        fprintf(stderr, "[DNA] No valid identity found (all signatures failed)\n");
        return -3;  // Verification failed
    }

    printf("[DNA] ✓ Loaded newest valid profile (timestamp=%lu, version=%u)\n",
           best_identity->timestamp, best_identity->version);
    if (best_identity->has_registered_name) {
        printf("[DNA] Name: %s (expires: %lu)\n",
               best_identity->registered_name, best_identity->name_expires_at);
    }

    *identity_out = best_identity;
    return 0;
}

// Get display name for fingerprint
int dna_get_display_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **display_name_out
) {
    if (!fingerprint || !display_name_out) {
        return -1;
    }

    // Try to load identity from DHT
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity(dht_ctx, fingerprint, &identity);

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
            printf("[DNA] ✓ Display name: %s (registered)\n", display);
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

    printf("[DNA] Display name: %s (fingerprint)\n", display);
    return 0;
}
