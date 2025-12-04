/**
 * DHT Keyserver - DNA Name System
 * Handles name registration, lookup, and expiration
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
// Simple version - no blockchain verification, free registration
int dna_register_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !name || !dilithium_pubkey || !kyber_pubkey || !dilithium_privkey) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_register_name\n");
        return -1;
    }

    // Validate name format
    if (!dna_validate_name(name)) {
        fprintf(stderr, "[DNA] Invalid name format: %s\n", name);
        return -1;
    }

    printf("[DNA] Registering name '%s' for %.16s...\n", name, fingerprint);

    // Check if name is already taken by someone else
    char *existing_fp = NULL;
    int ret = dna_lookup_by_name(dht_ctx, name, &existing_fp);
    if (ret == 0 && existing_fp) {
        if (strcmp(existing_fp, fingerprint) != 0) {
            fprintf(stderr, "[DNA] Name '%s' already registered to different identity\n", name);
            free(existing_fp);
            return -2;  // Name taken
        }
        free(existing_fp);
        // Same fingerprint - allow re-registration
    }

    // Create identity with name
    dna_unified_identity_t *identity = dna_identity_create();
    if (!identity) {
        return -1;
    }

    // Set identity data
    strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
    memcpy(identity->dilithium_pubkey, dilithium_pubkey, sizeof(identity->dilithium_pubkey));
    memcpy(identity->kyber_pubkey, kyber_pubkey, sizeof(identity->kyber_pubkey));

    // Set name registration
    identity->has_registered_name = true;
    strncpy(identity->registered_name, name, sizeof(identity->registered_name) - 1);
    identity->name_registered_at = time(NULL);
    identity->name_expires_at = identity->name_registered_at + (365 * 24 * 60 * 60);  // +365 days
    identity->name_version = 1;
    identity->timestamp = time(NULL);
    identity->version = 1;

    // Sign the identity with Dilithium5
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
    int sign_ret = qgp_dsa87_sign(identity->signature, &siglen, msg, msg_len, dilithium_privkey);

    free(msg);

    if (sign_ret != 0) {
        fprintf(stderr, "[DNA] Failed to sign identity\n");
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Identity signed with Dilithium5\n");

    // Serialize and store to DHT
    char *json = dna_identity_to_json(identity);
    if (!json) {
        dna_identity_free(identity);
        return -1;
    }

    // Store identity
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:identity", fingerprint);

    ret = dht_chunked_publish(dht_ctx, base_key,
                              (uint8_t*)json, strlen(json),
                              DHT_CHUNK_TTL_7DAY);
    free(json);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[DNA] Failed to store identity in DHT: %s\n", dht_chunked_strerror(ret));
        dna_identity_free(identity);
        return -1;
    }

    // Store name → fingerprint lookup
    char normalized_name[256];
    strncpy(normalized_name, name, sizeof(normalized_name) - 1);
    normalized_name[sizeof(normalized_name) - 1] = '\0';
    for (char *p = normalized_name; *p; p++) {
        *p = tolower(*p);
    }

    char name_base_key[256];
    snprintf(name_base_key, sizeof(name_base_key), "%s:lookup", normalized_name);

    ret = dht_chunked_publish(dht_ctx, name_base_key,
                              (uint8_t*)fingerprint, 128,
                              DHT_CHUNK_TTL_7DAY);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[DNA] Failed to store name lookup in DHT: %s\n", dht_chunked_strerror(ret));
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Name registered: %s → %.16s...\n", name, fingerprint);
    printf("[DNA] ✓ Expires: %lu (365 days)\n", identity->name_expires_at);

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

    char base_key[300];
    snprintf(base_key, sizeof(base_key), "%s:lookup", normalized_name);

    printf("[DNA] Looking up name '%s'\n", normalized_name);

    uint8_t *value = NULL;
    size_t value_len = 0;

    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);
    if (ret != DHT_CHUNK_OK || !value) {
        fprintf(stderr, "[DNA] Name not found in DHT: %s\n", dht_chunked_strerror(ret));
        return -2;  // Not found
    }

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
        return false;
    }

    uint64_t now = time(NULL);
    return (now >= identity->name_expires_at);
}
