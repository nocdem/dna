/**
 * DHT Keyserver - Lookup Operations
 * Handles key lookups using unified :identity records.
 * Note: Reverse lookups removed - use dna_load_identity() instead.
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"

// Lookup public keys from DHT (supports both fingerprint and name)
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *identity_or_fingerprint,
    dht_pubkey_entry_t **entry_out
) {
    if (!dht_ctx || !identity_or_fingerprint || !entry_out) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    char fingerprint[129];
    bool is_direct_fingerprint = false;

    // Detect input type: fingerprint (128 hex) or name (3-20 alphanumeric)
    if (is_valid_fingerprint(identity_or_fingerprint)) {
        // Direct fingerprint lookup
        strncpy(fingerprint, identity_or_fingerprint, 128);
        fingerprint[128] = '\0';
        is_direct_fingerprint = true;
        printf("[DHT_KEYSERVER] Direct fingerprint lookup: %s\n", fingerprint);
    } else {
        // Name lookup: first resolve name → fingerprint via alias
        printf("[DHT_KEYSERVER] Name lookup: resolving '%s' to fingerprint\n", identity_or_fingerprint);

        // Create base key for alias lookup (chunked layer handles hashing)
        char alias_base_key[256];
        snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", identity_or_fingerprint);

        uint8_t *alias_data = NULL;
        size_t alias_data_len = 0;
        int alias_ret = dht_chunked_fetch(dht_ctx, alias_base_key, &alias_data, &alias_data_len);

        if (alias_ret != DHT_CHUNK_OK || !alias_data) {
            fprintf(stderr, "[DHT_KEYSERVER] Name '%s' not registered (alias not found): %s\n",
                    identity_or_fingerprint, dht_chunked_strerror(alias_ret));
            return -2;  // Name not found
        }

        // Parse fingerprint from alias (simple text storage)
        if (alias_data_len != 128) {
            fprintf(stderr, "[DHT_KEYSERVER] Invalid alias data length: %zu (expected 128)\n", alias_data_len);
            free(alias_data);
            return -1;
        }

        memcpy(fingerprint, alias_data, 128);
        fingerprint[128] = '\0';
        free(alias_data);

        printf("[DHT_KEYSERVER] ✓ Name resolved to fingerprint: %s\n", fingerprint);
    }

    // Lookup by fingerprint using chunked layer
    // UNIFIED: Uses :identity key (replaces old :pubkey)
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:identity", fingerprint);

    printf("[DHT_KEYSERVER] Fetching identity for fingerprint from DHT\n");
    printf("[DHT_KEYSERVER] Base key: %s\n", base_key);

    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &data, &data_len);

    if (ret != DHT_CHUNK_OK || !data) {
        fprintf(stderr, "[DHT_KEYSERVER] Keys not found in DHT for fingerprint %s: %s\n",
                fingerprint, dht_chunked_strerror(ret));
        return -2;  // Not found
    }

    // Parse JSON (need to null-terminate first as DHT data isn't)
    char *json_str = (char*)malloc(data_len + 1);
    if (!json_str) {
        free(data);
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate memory for JSON string\n");
        return -1;
    }
    memcpy(json_str, data, data_len);
    json_str[data_len] = '\0';
    free(data);

    dht_pubkey_entry_t *entry = malloc(sizeof(dht_pubkey_entry_t));
    if (!entry) {
        free(json_str);
        return -1;
    }

    if (deserialize_entry(json_str, entry) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse entry\n");
        free(json_str);
        free(entry);
        return -1;
    }

    free(json_str);

    // Verify signature
    if (verify_entry(entry) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Signature verification failed\n");
        free(entry);
        return -3;  // Signature verification failed
    }

    printf("[DHT_KEYSERVER] ✓ Keys retrieved and verified\n");
    printf("[DHT_KEYSERVER] Fingerprint: %s\n", entry->fingerprint);
    printf("[DHT_KEYSERVER] Version: %u\n", entry->version);

    *entry_out = entry;
    return 0;
}

// NOTE: dht_keyserver_reverse_lookup() and dht_keyserver_reverse_lookup_async() REMOVED
// The unified :identity record contains all needed data including display name
// Use dna_load_identity() from keyserver_profiles.c instead
