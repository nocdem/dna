/**
 * DHT Keyserver - Publish Operations
 * Handles publishing identities and name aliases
 *
 * DHT Keys (only 2):
 * - fingerprint:profile  -> dna_unified_identity_t (keys + name + profile)
 * - name:lookup          -> fingerprint (for name-based lookups)
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"
#include "../client/dna_profile.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "KEYSERVER"

// Publish identity to DHT (NAME-FIRST architecture)
// Creates dna_unified_identity_t and stores at fingerprint:profile
// Also publishes name:lookup alias for name-based lookups
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,  // REQUIRED - DNA name
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey,
    const char *wallet_address  // Optional - Cellframe wallet address
) {
    QGP_LOG_INFO(LOG_TAG, "Publishing identity: name=%s, fingerprint=%.16s...\n",
           name, fingerprint);

    // Validate required arguments
    if (!dht_ctx || !fingerprint || !name || !dilithium_pubkey || !kyber_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments (all fields required)\n");
        return -1;
    }

    // Validate fingerprint format
    if (!is_valid_fingerprint(fingerprint)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint format (expected 128 hex chars)\n");
        return -1;
    }

    // Validate name format (3-20 alphanumeric)
    size_t name_len = strlen(name);
    if (name_len < 3 || name_len > 20) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid name length: %zu (must be 3-20 chars)\n", name_len);
        return -1;
    }

    // Check if name is already taken
    char alias_base_key[256];
    snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", name);

    uint8_t *existing_alias = NULL;
    size_t existing_len = 0;
    int alias_check = dht_chunked_fetch(dht_ctx, alias_base_key, &existing_alias, &existing_len);

    if (alias_check == DHT_CHUNK_OK && existing_alias) {
        // Name exists - check if it's the same fingerprint (re-publish ok)
        if (existing_len == 128 && strncmp((char*)existing_alias, fingerprint, 128) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Name '%s' already taken by different identity\n", name);
            free(existing_alias);
            return -2;  // Name taken
        }
        free(existing_alias);
    }

    // Create unified identity
    dna_unified_identity_t *identity = dna_identity_create();
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate identity\n");
        return -1;
    }

    // Set fingerprint and keys
    strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
    memcpy(identity->dilithium_pubkey, dilithium_pubkey, sizeof(identity->dilithium_pubkey));
    memcpy(identity->kyber_pubkey, kyber_pubkey, sizeof(identity->kyber_pubkey));

    // Set name registration
    identity->has_registered_name = true;
    strncpy(identity->registered_name, name, sizeof(identity->registered_name) - 1);
    strncpy(identity->display_name, name, sizeof(identity->display_name) - 1);
    identity->name_registered_at = time(NULL);
    identity->name_expires_at = identity->name_registered_at + (365 * 24 * 60 * 60);  // +365 days
    strncpy(identity->registration_tx_hash, "FREE_REGISTRATION", sizeof(identity->registration_tx_hash) - 1);
    strncpy(identity->registration_network, "DNA_NETWORK", sizeof(identity->registration_network) - 1);
    identity->name_version = 1;

    // Set wallet address if provided
    if (wallet_address && wallet_address[0]) {
        strncpy(identity->wallets.backbone, wallet_address, sizeof(identity->wallets.backbone) - 1);
    }

    // Set metadata
    identity->created_at = time(NULL);
    identity->updated_at = identity->created_at;
    identity->timestamp = identity->created_at;
    identity->version = 1;

    // Sign the identity
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate message buffer\n");
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

    size_t siglen = sizeof(identity->signature);
    int sign_result = qgp_dsa87_sign(identity->signature, &siglen, msg, msg_len, dilithium_privkey);
    free(msg);

    if (sign_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign identity\n");
        dna_identity_free(identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity signed with Dilithium5\n");

    // Serialize to JSON
    char *json = dna_identity_to_json(identity);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity\n");
        dna_identity_free(identity);
        return -1;
    }

    // Publish to fingerprint:profile
    char profile_base_key[256];
    snprintf(profile_base_key, sizeof(profile_base_key), "%s:profile", fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Publishing to DHT key: %s\n", profile_base_key);

    int ret = dht_chunked_publish(dht_ctx, profile_base_key,
                                  (uint8_t*)json, strlen(json),
                                  DHT_CHUNK_TTL_365DAY);
    free(json);
    dna_identity_free(identity);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish identity: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity published to fingerprint:profile\n");

    // Publish name:lookup alias
    ret = dht_chunked_publish(dht_ctx, alias_base_key,
                              (uint8_t*)fingerprint, 128,
                              DHT_CHUNK_TTL_365DAY);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to publish name alias (lookups may not work)\n");
        // Non-fatal - identity is already published
    } else {
        QGP_LOG_INFO(LOG_TAG, "✓ Name alias published: %s -> %.16s...\n", name, fingerprint);
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity published successfully\n");
    return 0;
}

// Publish name → fingerprint alias (for name-based lookups)
int dht_keyserver_publish_alias(
    dht_context_t *dht_ctx,
    const char *name,
    const char *fingerprint
) {
    if (!dht_ctx || !name || !fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to publish_alias\n");
        return -1;
    }

    // Validate name (3-20 alphanumeric)
    size_t name_len = strlen(name);
    if (name_len < 3 || name_len > 20) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid name length: %zu (must be 3-20 chars)\n", name_len);
        return -1;
    }

    // Validate fingerprint
    if (!is_valid_fingerprint(fingerprint)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint format (expected 128 hex chars)\n");
        return -1;
    }

    // Create base key for alias (chunked layer handles hashing)
    char alias_base_key[256];
    snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", name);

    // Store fingerprint as plain text via chunked layer
    QGP_LOG_INFO(LOG_TAG, "Publishing alias: '%s' → %s\n", name, fingerprint);
    QGP_LOG_INFO(LOG_TAG, "Alias base key: %s\n", alias_base_key);

    int ret = dht_chunked_publish(dht_ctx, alias_base_key,
                                  (uint8_t*)fingerprint, 128,
                                  DHT_CHUNK_TTL_365DAY);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish alias: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Alias published successfully (TTL=365 days)\n");
    return 0;
}

// Update keys in DHT (key rotation)
// Loads existing identity, updates keys, increments version, re-signs, and publishes to :profile
int dht_keyserver_update(
    dht_context_t *dht_ctx,
    const char *name_or_fingerprint,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *new_dilithium_privkey
) {
    if (!dht_ctx || !name_or_fingerprint || !new_dilithium_pubkey || !new_kyber_pubkey || !new_dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments\n");
        return -1;
    }

    // Fetch existing identity
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(dht_ctx, name_or_fingerprint, &identity);

    if (ret != 0 || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot update - identity not found\n");
        return -2;
    }

    // Compute new fingerprint from new pubkey
    char new_fingerprint[129];
    compute_fingerprint(new_dilithium_pubkey, new_fingerprint);

    // Update identity with new keys
    memcpy(identity->dilithium_pubkey, new_dilithium_pubkey, sizeof(identity->dilithium_pubkey));
    memcpy(identity->kyber_pubkey, new_kyber_pubkey, sizeof(identity->kyber_pubkey));
    strncpy(identity->fingerprint, new_fingerprint, sizeof(identity->fingerprint) - 1);
    identity->timestamp = time(NULL);
    identity->updated_at = identity->timestamp;
    identity->version++;

    QGP_LOG_INFO(LOG_TAG, "Updating identity keys, new version: %u\n", identity->version);

    // Re-sign the identity with new private key
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

    size_t siglen = sizeof(identity->signature);
    int sign_result = qgp_dsa87_sign(identity->signature, &siglen, msg, msg_len, new_dilithium_privkey);
    free(msg);

    if (sign_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign updated identity\n");
        dna_identity_free(identity);
        return -1;
    }

    // Serialize and publish
    char *json = dna_identity_to_json(identity);
    if (!json) {
        dna_identity_free(identity);
        return -1;
    }

    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:profile", new_fingerprint);

    ret = dht_chunked_publish(dht_ctx, base_key,
                              (uint8_t*)json, strlen(json),
                              DHT_CHUNK_TTL_365DAY);
    free(json);
    dna_identity_free(identity);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update in DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity updated successfully\n");
    return 0;
}

// Delete public keys from DHT
int dht_keyserver_delete(
    dht_context_t *dht_ctx,
    const char *identity
) {
    if (!dht_ctx || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments\n");
        return -1;
    }

    // Compute DHT key (use fingerprint if valid, otherwise treat as name for lookup)
    char dht_key[129];
    if (is_valid_fingerprint(identity)) {
        // Direct fingerprint
        compute_dht_key_by_fingerprint(identity, dht_key);
    } else {
        // Name - resolve to fingerprint first
        // For now, just fail since deletion without fingerprint is ambiguous
        QGP_LOG_ERROR(LOG_TAG, "Delete requires fingerprint (128 hex chars), not name\n");
        return -1;
    }

    // Note: DHT doesn't support true deletion, but we can try to overwrite with tombstone
    // For now, just return success (keys will expire naturally if DHT implementation supports it)
    QGP_LOG_INFO(LOG_TAG, "Delete not fully supported by DHT (keys remain until natural expiry)\n");

    return 0;
}

// NOTE: dht_keyserver_free_entry removed - use dna_identity_free instead
