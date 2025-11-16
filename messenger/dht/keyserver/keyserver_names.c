/**
 * DHT Keyserver - DNA Name System
 * Handles name registration, renewal, lookup, and expiration
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"

// Compute fingerprint from Dilithium5 public key (public wrapper)
void dna_compute_fingerprint(
    const uint8_t *dilithium_pubkey,
    char *fingerprint_out
) {
    compute_fingerprint(dilithium_pubkey, fingerprint_out);
}

// Register DNA name for a fingerprint identity
int dna_register_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,
    const char *tx_hash,
    const char *network,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !name || !tx_hash || !network || !dilithium_privkey) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_register_name\n");
        return -1;
    }

    // Validate name format
    if (!dna_validate_name(name)) {
        fprintf(stderr, "[DNA] Invalid name format: %s\n", name);
        return -1;
    }

    // Verify blockchain transaction
    printf("[DNA] Verifying blockchain transaction...\n");
    printf("[DNA] TX: %s on %s\n", tx_hash, network);

    int verify_result = cellframe_verify_registration_tx(tx_hash, network, name);
    if (verify_result != 0) {
        if (verify_result == -2) {
            fprintf(stderr, "[DNA] Transaction validation failed (invalid amount, memo, or recipient)\n");
        } else {
            fprintf(stderr, "[DNA] Transaction verification error (RPC failure or tx not found)\n");
        }
        return -1;
    }

    printf("[DNA] ✓ Transaction verified successfully\n");

    // Check if name is already taken
    char *existing_fp = NULL;
    int ret = dna_lookup_by_name(dht_ctx, name, &existing_fp);
    if (ret == 0) {
        // Name exists - check if it's the same fingerprint
        if (strcmp(existing_fp, fingerprint) != 0) {
            fprintf(stderr, "[DNA] Name '%s' already registered to different fingerprint\n", name);
            free(existing_fp);
            return -2;  // Name taken
        }
        free(existing_fp);
        // Same fingerprint - allow re-registration (renewal)
    }

    // Load or create identity
    dna_unified_identity_t *identity = NULL;
    ret = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret != 0) {
        // Create new identity
        identity = dna_identity_create();
        if (!identity) {
            return -1;
        }
        strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
        // Note: Keys must be set separately
    }

    // Update name registration
    identity->has_registered_name = true;
    strncpy(identity->registered_name, name, sizeof(identity->registered_name) - 1);
    identity->name_registered_at = time(NULL);
    identity->name_expires_at = identity->name_registered_at + (365 * 24 * 60 * 60);  // +365 days
    strncpy(identity->registration_tx_hash, tx_hash, sizeof(identity->registration_tx_hash) - 1);
    strncpy(identity->registration_network, network, sizeof(identity->registration_network) - 1);
    identity->name_version = 1;
    identity->timestamp = time(NULL);
    identity->version++;

    // Store identity to DHT
    char *json = dna_identity_to_json(identity);
    if (!json) {
        dna_identity_free(identity);
        return -1;
    }

    // Compute identity DHT key
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                    (uint8_t*)json, strlen(json), 1);
    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store identity in DHT\n");
        dna_identity_free(identity);
        return -1;
    }

    // Store reverse mapping: name → fingerprint
    // Normalize name to lowercase
    char normalized_name[256];
    strncpy(normalized_name, name, sizeof(normalized_name) - 1);
    normalized_name[sizeof(normalized_name) - 1] = '\0';
    for (char *p = normalized_name; *p; p++) {
        *p = tolower(*p);
    }

    snprintf(key_input, sizeof(key_input), "%s:lookup", normalized_name);
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        dna_identity_free(identity);
        return -1;
    }

    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    unsigned int ttl_365_days = 365 * 24 * 3600;
    ret = dht_put_signed(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                         (uint8_t*)fingerprint, 128, 1, ttl_365_days);  // Store fingerprint (128 hex chars, signed)

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store name mapping in DHT\n");
        dna_identity_free(identity);
        return -1;
    }

    uint64_t expires_at = identity->name_expires_at;
    dna_identity_free(identity);

    printf("[DNA] ✓ Name registered: %s → %.16s...\n", name, fingerprint);
    printf("[DNA] Expires: %lu (365 days)\n", expires_at);
    return 0;
}

// Renew DNA name registration
int dna_renew_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *renewal_tx_hash,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !renewal_tx_hash || !dilithium_privkey) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_renew_name\n");
        return -1;
    }

    // Load existing identity first to get name and network
    dna_unified_identity_t *identity = NULL;
    int ret_load = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret_load != 0) {
        fprintf(stderr, "[DNA] Identity not found\n");
        return -2;
    }

    if (!identity->has_registered_name) {
        fprintf(stderr, "[DNA] No name registered for this fingerprint\n");
        dna_identity_free(identity);
        return -2;
    }

    // Verify blockchain transaction
    printf("[DNA] Verifying renewal transaction...\n");
    printf("[DNA] Renewal TX: %s\n", renewal_tx_hash);

    int verify_result = cellframe_verify_registration_tx(renewal_tx_hash,
                                                         identity->registration_network,
                                                         identity->registered_name);
    if (verify_result != 0) {
        if (verify_result == -2) {
            fprintf(stderr, "[DNA] Renewal transaction validation failed\n");
        } else {
            fprintf(stderr, "[DNA] Renewal transaction verification error\n");
        }
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Renewal transaction verified successfully\n");

    // Update renewal info
    identity->name_expires_at += (365 * 24 * 60 * 60);  // Extend by 365 days
    strncpy(identity->registration_tx_hash, renewal_tx_hash,
            sizeof(identity->registration_tx_hash) - 1);
    identity->name_version++;
    identity->timestamp = time(NULL);
    identity->version++;

    // Store updated identity
    char *json = dna_identity_to_json(identity);
    if (!json) {
        dna_identity_free(identity);
        return -1;
    }

    // Compute DHT key
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    int ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                        (uint8_t*)json, strlen(json), 1);
    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store renewed identity in DHT\n");
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Name renewed: %s\n", identity->registered_name);
    printf("[DNA] New expiration: %lu (+365 days)\n", identity->name_expires_at);

    dna_identity_free(identity);
    return 0;
}

// Lookup fingerprint by DNA name
int dna_lookup_by_name(
    dht_context_t *dht_ctx,
    const char *name,
    char **fingerprint_out
) {
    if (!dht_ctx || !name || !fingerprint_out) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_lookup_by_name\n");
        return -1;
    }

    // Normalize name to lowercase
    char normalized_name[256];
    strncpy(normalized_name, name, sizeof(normalized_name) - 1);
    normalized_name[sizeof(normalized_name) - 1] = '\0';
    for (char *p = normalized_name; *p; p++) {
        *p = tolower(*p);
    }

    // Compute DHT key: SHA3-512(name + ":lookup")
    char key_input[300];
    snprintf(key_input, sizeof(key_input), "%s:lookup", normalized_name);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        fprintf(stderr, "[DNA] Failed to compute DHT key\n");
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    printf("[DNA] Looking up name '%s'\n", normalized_name);
    printf("[DNA] DHT key: %.32s...\n", dht_key);

    // Fetch from DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &value, &value_len) != 0 || !value) {
        fprintf(stderr, "[DNA] Name not found in DHT\n");
        return -2;  // Not found
    }

    // Value is just the fingerprint (128 hex chars)
    if (value_len != 128) {
        fprintf(stderr, "[DNA] Invalid fingerprint length: %zu (expected 128)\n", value_len);
        free(value);
        return -1;
    }

    char *fingerprint = malloc(129);
    if (!fingerprint) {
        free(value);
        return -1;
    }

    memcpy(fingerprint, value, 128);
    fingerprint[128] = '\0';
    free(value);

    printf("[DNA] ✓ Name resolved: %s → %.16s...\n", normalized_name, fingerprint);

    *fingerprint_out = fingerprint;
    return 0;
}

// Check if DNA name has expired
bool dna_is_name_expired(const dna_unified_identity_t *identity) {
    if (!identity || !identity->has_registered_name) {
        return false;  // No name registered = not expired
    }

    uint64_t now = time(NULL);
    return (now >= identity->name_expires_at);
}
