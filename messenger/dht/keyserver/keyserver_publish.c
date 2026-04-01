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
#include "dht/shared/nodus_ops.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "database/profile_cache.h"

#define LOG_TAG "KEYSERVER"

// Publish identity to DHT (NAME-FIRST architecture)
// Creates dna_unified_identity_t and stores at fingerprint:profile
// Also publishes name:lookup alias for name-based lookups
int dht_keyserver_publish(
    const char *fingerprint,
    const char *name,  // REQUIRED - DNA name
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey,
    const char *wallet_address,  // Optional - Cellframe wallet address
    const char *eth_address,     // Optional - Ethereum wallet address
    const char *sol_address,     // Optional - Solana wallet address
    const char *trx_address      // Optional - TRON wallet address
) {
    QGP_LOG_INFO(LOG_TAG, "[PROFILE_PUBLISH] dht_keyserver_publish: name=%s, fp=%.16s...\n",
           name, fingerprint);

    // Validate required arguments
    if (!fingerprint || !name || !dilithium_pubkey || !kyber_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments (all fields required)\n");
        return -1;
    }

    // Wait for Nodus to be ready (connected to network)
    if (!nodus_ops_is_ready()) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus not ready - cannot publish identity\n");
        return -3;
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
    int alias_check = nodus_ops_get_str(alias_base_key, &existing_alias, &existing_len);

    if (alias_check == 0 && existing_alias) {
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
    identity->name_registered_at = time(NULL);
    identity->name_expires_at = identity->name_registered_at + (365 * 24 * 60 * 60);  // +365 days
    identity->name_version = 1;

    // Set wallet addresses if provided
    if (wallet_address && wallet_address[0]) {
        strncpy(identity->wallets.backbone, wallet_address, sizeof(identity->wallets.backbone) - 1);
    }
    if (eth_address && eth_address[0]) {
        strncpy(identity->wallets.eth, eth_address, sizeof(identity->wallets.eth) - 1);
    }
    if (sol_address && sol_address[0]) {
        strncpy(identity->wallets.sol, sol_address, sizeof(identity->wallets.sol) - 1);
    }
    if (trx_address && trx_address[0]) {
        strncpy(identity->wallets.trx, trx_address, sizeof(identity->wallets.trx) - 1);
    }

    // Set metadata
    identity->created_at = time(NULL);
    identity->updated_at = identity->created_at;
    identity->timestamp = identity->created_at;
    identity->version = 1;

    // Sign the JSON representation (not struct bytes) for forward compatibility
    // This matches the verification method in keyserver_profiles.c and keyserver_lookup.c
    char *json_unsigned = dna_identity_to_json_unsigned(identity);
    if (!json_unsigned) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity for signing\n");
        dna_identity_free(identity);
        return -1;
    }

    size_t siglen = sizeof(identity->signature);
    int sign_result = qgp_dsa87_sign(identity->signature, &siglen,
                                      (uint8_t*)json_unsigned, strlen(json_unsigned),
                                      dilithium_privkey);
    free(json_unsigned);

    if (sign_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign identity\n");
        dna_identity_free(identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity signed with Dilithium5\n");

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

    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] Publishing to DHT key: %s\n", profile_base_key);

    // Exclusive — first writer owns this key (single-owner profile)
    int ret = nodus_ops_put_str_exclusive(profile_base_key,
                                          (uint8_t*)json, strlen(json),
                                          nodus_ops_value_id());
    free(json);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish identity (ret=%d)\n", ret);
        dna_identity_free(identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity published to fingerprint:profile\n");

    // Cache locally to avoid DHT propagation delay issues
    // This ensures getProfile() returns correct data immediately after publish
    if (profile_cache_add_or_update(fingerprint, identity) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Identity cached locally\n");
    }

    dna_identity_free(identity);

    // Publish name:lookup alias — exclusive (first writer owns)
    ret = nodus_ops_put_str_exclusive(alias_base_key,
                                      (uint8_t*)fingerprint, 128,
                                      nodus_ops_value_id());

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to publish name alias (lookups may not work)\n");
        // Non-fatal - identity is already published
    } else {
        QGP_LOG_INFO(LOG_TAG, "Name alias published: %s -> %.16s...\n", name, fingerprint);
    }

    // Publish reverse mapping: fingerprint:rname → name (for fingerprint→name lookups)
    {
        char rname_key[256];
        snprintf(rname_key, sizeof(rname_key), "%s:rname", fingerprint);
        ret = nodus_ops_put_str_exclusive(rname_key,
                                          (uint8_t*)name, strlen(name),
                                          nodus_ops_value_id());
        if (ret == 0) {
            QGP_LOG_INFO(LOG_TAG, "Reverse name published: %.16s... -> %s\n", fingerprint, name);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Warning: Failed to publish reverse name mapping\n");
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Identity published successfully\n");
    return 0;
}

// Publish name -> fingerprint alias (for name-based lookups)
int dht_keyserver_publish_alias(
    const char *name,
    const char *fingerprint
) {
    if (!name || !fingerprint) {
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

    // Create base key for alias
    char alias_base_key[256];
    snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", name);

    // Store fingerprint as plain text
    QGP_LOG_INFO(LOG_TAG, "Publishing alias: '%s' -> %s\n", name, fingerprint);
    QGP_LOG_INFO(LOG_TAG, "Alias base key: %s\n", alias_base_key);

    // Exclusive — first writer owns name alias
    int ret = nodus_ops_put_str_exclusive(alias_base_key,
                                          (uint8_t*)fingerprint, 128,
                                          nodus_ops_value_id());

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish alias (ret=%d)\n", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Alias published successfully (TTL=PERMANENT)\n");
    return 0;
}

// Update keys in DHT (key rotation)
// Loads existing identity, updates keys, increments version, re-signs, and publishes to :profile
int dht_keyserver_update(
    const char *name_or_fingerprint,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *new_dilithium_privkey
) {
    if (!name_or_fingerprint || !new_dilithium_pubkey || !new_kyber_pubkey || !new_dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments\n");
        return -1;
    }

    // Fetch existing identity
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(name_or_fingerprint, &identity);

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

    // Re-sign the JSON representation with new private key (for forward compatibility)
    char *json_unsigned = dna_identity_to_json_unsigned(identity);
    if (!json_unsigned) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity for signing\n");
        dna_identity_free(identity);
        return -1;
    }

    size_t siglen = sizeof(identity->signature);
    int sign_result = qgp_dsa87_sign(identity->signature, &siglen,
                                      (uint8_t*)json_unsigned, strlen(json_unsigned),
                                      new_dilithium_privkey);
    free(json_unsigned);

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

    // Exclusive — first writer owns profile key
    ret = nodus_ops_put_str_exclusive(base_key,
                                      (uint8_t*)json, strlen(json),
                                      nodus_ops_value_id());
    free(json);
    dna_identity_free(identity);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update in DHT (ret=%d)\n", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity updated successfully (TTL=PERMANENT)\n");
    return 0;
}

// NOTE: dht_keyserver_delete removed - DHT doesn't support deletion (values expire via TTL)
// NOTE: dht_keyserver_free_entry removed - use dna_identity_free instead
