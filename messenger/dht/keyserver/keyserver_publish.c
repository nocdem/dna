/**
 * DHT Keyserver - Publish Operations
 * Handles publishing keys, aliases, updates, and deletes
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"

// Publish public keys to DHT (FINGERPRINT-FIRST architecture)
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *display_name,  // Optional human-readable name
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey
) {
    printf("[DEBUG PUBLISH] dht_keyserver_publish() called for: %.16s... (name: %s)\n",
           fingerprint, display_name ? display_name : "(none)");

    if (!dht_ctx || !fingerprint || !dilithium_pubkey || !kyber_pubkey || !dilithium_privkey) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Validate fingerprint format
    if (!is_valid_fingerprint(fingerprint)) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid fingerprint format (expected 128 hex chars)\n");
        return -1;
    }

    // Build entry
    dht_pubkey_entry_t entry = {0};

    // Store display name (or fingerprint if no name provided)
    if (display_name && strlen(display_name) > 0) {
        strncpy(entry.identity, display_name, sizeof(entry.identity) - 1);
    } else {
        strncpy(entry.identity, fingerprint, sizeof(entry.identity) - 1);
    }

    memcpy(entry.dilithium_pubkey, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(entry.kyber_pubkey, kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    entry.timestamp = time(NULL);
    entry.version = 1;  // Initial version

    // Store fingerprint (should match computed one)
    strncpy(entry.fingerprint, fingerprint, sizeof(entry.fingerprint) - 1);

    // Sign entry
    if (sign_entry(&entry, dilithium_privkey) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to sign entry\n");
        return -1;
    }

    // Serialize to JSON
    char *json = serialize_entry(&entry);
    if (!json) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to serialize entry\n");
        return -1;
    }

    // Create base key for chunked layer (it handles hashing internally)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:pubkey", fingerprint);

    // Store in DHT via chunked layer (permanent storage)
    printf("[DHT_KEYSERVER] Publishing keys for fingerprint '%s' to DHT\n", fingerprint);
    if (display_name && strlen(display_name) > 0) {
        printf("[DHT_KEYSERVER] Display name: %s\n", display_name);
    }
    printf("[DHT_KEYSERVER] Base key: %s\n", base_key);

    int ret = dht_chunked_publish(dht_ctx, base_key,
                                  (uint8_t*)json, strlen(json),
                                  DHT_CHUNK_TTL_365DAY);

    free(json);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to store in DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    // Publish SIGNED reverse mapping (fingerprint → identity) for unknown sender lookup
    // This allows looking up identity from Dilithium pubkey fingerprint
    // Entry is signed to prevent identity spoofing attacks

    printf("[DHT_KEYSERVER_DEBUG] Starting reverse mapping publish\n");

    // Build message to sign: dilithium_pubkey || display_name || timestamp
    // Use display_name for reverse mapping (or fingerprint if no name)
    const char *name_for_reverse = (display_name && strlen(display_name) > 0) ? display_name : fingerprint;
    size_t reverse_msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(name_for_reverse) + sizeof(uint64_t);
    uint8_t *reverse_msg = malloc(reverse_msg_len);
    if (!reverse_msg) {
        fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to allocate reverse mapping message\n");
    } else {
        printf("[DHT_KEYSERVER_DEBUG] Allocated reverse_msg (%zu bytes)\n", reverse_msg_len);
        size_t offset = 0;
        memcpy(reverse_msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
        offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
        memcpy(reverse_msg + offset, name_for_reverse, strlen(name_for_reverse));
        offset += strlen(name_for_reverse);

        // Network byte order for cross-platform compatibility
        uint64_t timestamp_net = htonll(entry.timestamp);
        memcpy(reverse_msg + offset, &timestamp_net, sizeof(timestamp_net));

        // Sign reverse mapping
        uint8_t reverse_signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
        size_t reverse_siglen = DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE;

        printf("[DHT_KEYSERVER_DEBUG] Signing reverse mapping message...\n");
        int sign_result = qgp_dsa87_sign(reverse_signature, &reverse_siglen,
                                      reverse_msg, reverse_msg_len, dilithium_privkey);
        printf("[DHT_KEYSERVER_DEBUG] Signature result: %d, siglen: %zu\n", sign_result, reverse_siglen);

        if (sign_result != 0) {
            fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to sign reverse mapping\n");
            free(reverse_msg);
        } else {
            free(reverse_msg);
            printf("[DHT_KEYSERVER_DEBUG] Reverse mapping signature succeeded, building JSON...\n");

            // Build reverse mapping entry
            json_object *reverse_obj = json_object_new_object();
            if (!reverse_obj) {
                fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to create JSON object for reverse mapping\n");
                return 0;  // Non-critical, forward mapping already published
            }
            printf("[DHT_KEYSERVER_DEBUG] Created JSON object for reverse mapping\n");

            // Store dilithium pubkey (needed for signature verification)
            char dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2 + 1];
            for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE; i++) {
                sprintf(dilithium_hex + (i * 2), "%02x", dilithium_pubkey[i]);
            }
            dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2] = '\0';

            json_object_object_add(reverse_obj, "dilithium_pubkey", json_object_new_string(dilithium_hex));
            json_object_object_add(reverse_obj, "identity", json_object_new_string(name_for_reverse));
            json_object_object_add(reverse_obj, "timestamp", json_object_new_int64(entry.timestamp));
            json_object_object_add(reverse_obj, "fingerprint", json_object_new_string(fingerprint));

            // Store signature
            char sig_hex[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE * 2 + 1];
            for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE; i++) {
                sprintf(sig_hex + (i * 2), "%02x", reverse_signature[i]);
            }
            sig_hex[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE * 2] = '\0';
            json_object_object_add(reverse_obj, "signature", json_object_new_string(sig_hex));

            const char *reverse_json_str = json_object_to_json_string(reverse_obj);
            char *reverse_json = strdup(reverse_json_str);
            json_object_put(reverse_obj);

            // Create base key for reverse lookup (chunked layer handles hashing)
            char reverse_base_key[256];
            snprintf(reverse_base_key, sizeof(reverse_base_key), "%s:reverse", entry.fingerprint);

            printf("[DHT_KEYSERVER] Publishing signed reverse mapping (fingerprint → identity)\n");
            printf("[DHT_KEYSERVER] Reverse base key: %s\n", reverse_base_key);

            ret = dht_chunked_publish(dht_ctx, reverse_base_key,
                                      (uint8_t*)reverse_json, strlen(reverse_json),
                                      DHT_CHUNK_TTL_365DAY);

            free(reverse_json);

            if (ret != DHT_CHUNK_OK) {
                fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to store reverse mapping (non-critical): %s\n",
                        dht_chunked_strerror(ret));
            } else {
                printf("[DHT_KEYSERVER] ✓ Signed reverse mapping published\n");
            }
        }
    }

    printf("[DHT_KEYSERVER] ✓ Keys published successfully\n");
    return 0;
}

// Publish name → fingerprint alias (for name-based lookups)
int dht_keyserver_publish_alias(
    dht_context_t *dht_ctx,
    const char *name,
    const char *fingerprint
) {
    if (!dht_ctx || !name || !fingerprint) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to publish_alias\n");
        return -1;
    }

    // Validate name (3-20 alphanumeric)
    size_t name_len = strlen(name);
    if (name_len < 3 || name_len > 20) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid name length: %zu (must be 3-20 chars)\n", name_len);
        return -1;
    }

    // Validate fingerprint
    if (!is_valid_fingerprint(fingerprint)) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid fingerprint format (expected 128 hex chars)\n");
        return -1;
    }

    // Create base key for alias (chunked layer handles hashing)
    char alias_base_key[256];
    snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", name);

    // Store fingerprint as plain text via chunked layer
    printf("[DHT_KEYSERVER] Publishing alias: '%s' → %s\n", name, fingerprint);
    printf("[DHT_KEYSERVER] Alias base key: %s\n", alias_base_key);

    int ret = dht_chunked_publish(dht_ctx, alias_base_key,
                                  (uint8_t*)fingerprint, 128,
                                  DHT_CHUNK_TTL_365DAY);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to publish alias: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    printf("[DHT_KEYSERVER] ✓ Alias published successfully (TTL=365 days)\n");
    return 0;
}

// Update public keys in DHT
int dht_keyserver_update(
    dht_context_t *dht_ctx,
    const char *identity,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *new_dilithium_privkey
) {
    if (!dht_ctx || !identity || !new_dilithium_pubkey || !new_kyber_pubkey || !new_dilithium_privkey) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Fetch existing entry to get version
    dht_pubkey_entry_t *old_entry = NULL;
    int ret = dht_keyserver_lookup(dht_ctx, identity, &old_entry);

    uint32_t new_version = 1;
    if (ret == 0 && old_entry) {
        // Increment version
        new_version = old_entry->version + 1;
        dht_keyserver_free_entry(old_entry);
    }

    // Build new entry
    dht_pubkey_entry_t entry = {0};
    strncpy(entry.identity, identity, sizeof(entry.identity) - 1);
    memcpy(entry.dilithium_pubkey, new_dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(entry.kyber_pubkey, new_kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    entry.timestamp = time(NULL);
    entry.version = new_version;

    // Compute fingerprint
    compute_fingerprint(new_dilithium_pubkey, entry.fingerprint);

    // Sign with NEW private key
    if (sign_entry(&entry, new_dilithium_privkey) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to sign entry\n");
        return -1;
    }

    // Serialize to JSON
    char *json = serialize_entry(&entry);
    if (!json) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to serialize entry\n");
        return -1;
    }

    // Create base key for chunked layer (fingerprint-first)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:pubkey", entry.fingerprint);

    // Store in DHT via chunked layer
    printf("[DHT_KEYSERVER] Updating keys for fingerprint: %s\n", entry.fingerprint);
    printf("[DHT_KEYSERVER] New version: %u\n", new_version);

    ret = dht_chunked_publish(dht_ctx, base_key,
                              (uint8_t*)json, strlen(json),
                              DHT_CHUNK_TTL_365DAY);

    free(json);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to update in DHT: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    printf("[DHT_KEYSERVER] ✓ Keys updated successfully\n");
    return 0;
}

// Delete public keys from DHT
int dht_keyserver_delete(
    dht_context_t *dht_ctx,
    const char *identity
) {
    if (!dht_ctx || !identity) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
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
        fprintf(stderr, "[DHT_KEYSERVER] Delete requires fingerprint (128 hex chars), not name\n");
        return -1;
    }

    // Note: DHT doesn't support true deletion, but we can try to overwrite with tombstone
    // For now, just return success (keys will expire naturally if DHT implementation supports it)
    printf("[DHT_KEYSERVER] Delete not fully supported by DHT (keys remain until natural expiry)\n");

    return 0;
}

// Free public key entry
void dht_keyserver_free_entry(dht_pubkey_entry_t *entry) {
    if (entry) {
        free(entry);
    }
}
