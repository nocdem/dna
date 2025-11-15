/**
 * DHT Keyserver - Lookup Operations
 * Handles key lookups, reverse lookups (sync/async)
 */

#include "keyserver_core.h"
#include "../dht_keyserver.h"

// Async reverse lookup helper structure
typedef struct {
    char fingerprint[129];
    void (*callback)(char *identity, void *userdata);
    void *userdata;
} reverse_lookup_async_ctx_t;

// Static callback for async DHT get
static void reverse_lookup_dht_callback(uint8_t *value, size_t value_len, void *cb_userdata) {
    reverse_lookup_async_ctx_t *ctx = (reverse_lookup_async_ctx_t*)cb_userdata;

    if (!value) {
        printf("[DHT_KEYSERVER] Async reverse mapping not found in DHT\n");
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Parse JSON
    char *json_str = (char*)malloc(value_len + 1);
    if (!json_str) {
        free(value);
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate memory for JSON string\n");
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse reverse mapping JSON\n");
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Extract fields
    json_object *dilithium_obj, *identity_obj, *timestamp_obj, *fingerprint_obj, *signature_obj;

    if (!json_object_object_get_ex(root, "dilithium_pubkey", &dilithium_obj) ||
        !json_object_object_get_ex(root, "identity", &identity_obj) ||
        !json_object_object_get_ex(root, "timestamp", &timestamp_obj) ||
        !json_object_object_get_ex(root, "fingerprint", &fingerprint_obj) ||
        !json_object_object_get_ex(root, "signature", &signature_obj)) {
        fprintf(stderr, "[DHT_KEYSERVER] Reverse mapping missing required fields\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Parse dilithium pubkey
    const char *dilithium_hex = json_object_get_string(dilithium_obj);
    uint8_t dilithium_pubkey[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE];
    if (hex_to_bytes(dilithium_hex, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid dilithium pubkey in reverse mapping\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Verify fingerprint matches
    char computed_fingerprint[129];
    compute_fingerprint(dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, ctx->fingerprint) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Fingerprint mismatch in reverse mapping\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    const char *identity = json_object_get_string(identity_obj);
    uint64_t timestamp = json_object_get_int64(timestamp_obj);

    // Parse signature
    const char *sig_hex = json_object_get_string(signature_obj);
    uint8_t signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
    if (hex_to_bytes(sig_hex, signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid signature in reverse mapping\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Rebuild message to verify
    size_t msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(identity) + sizeof(uint64_t);
    uint8_t *msg = (uint8_t*)malloc(msg_len);
    if (!msg) {
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    size_t offset = 0;
    memcpy(msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    memcpy(msg + offset, identity, strlen(identity));
    offset += strlen(identity);

    uint64_t timestamp_net = htonll(timestamp);
    memcpy(msg + offset, &timestamp_net, sizeof(timestamp_net));

    // Verify signature
    int verify_result = qgp_dsa87_verify(signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                         msg, msg_len, dilithium_pubkey);
    free(msg);

    if (verify_result != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Async reverse mapping signature verification failed\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // All checks passed - return identity
    char *identity_copy = strdup(identity);
    printf("[DHT_KEYSERVER] ✓ Async reverse lookup successful: %s\n", identity);

    json_object_put(root);
    ctx->callback(identity_copy, ctx->userdata);
    free(ctx);
}

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

        char alias_key[129];
        compute_dht_key_by_name(identity_or_fingerprint, alias_key);

        uint8_t *alias_data = NULL;
        size_t alias_data_len = 0;
        int alias_ret = dht_get(dht_ctx, (uint8_t*)alias_key, strlen(alias_key), &alias_data, &alias_data_len);

        if (alias_ret != 0 || !alias_data) {
            fprintf(stderr, "[DHT_KEYSERVER] Name '%s' not registered (alias not found)\n", identity_or_fingerprint);
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

    // Lookup by fingerprint
    char dht_key[129];
    compute_dht_key_by_fingerprint(fingerprint, dht_key);

    printf("[DHT_KEYSERVER] Fetching keys for fingerprint from DHT\n");
    printf("[DHT_KEYSERVER] DHT key: %s\n", dht_key);

    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &data, &data_len);

    if (ret != 0 || !data) {
        fprintf(stderr, "[DHT_KEYSERVER] Keys not found in DHT for fingerprint %s\n", fingerprint);
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

// Reverse lookup: fingerprint → identity (with signature verification)
int dht_keyserver_reverse_lookup(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to reverse_lookup\n");
        return -1;
    }

    *identity_out = NULL;

    // Compute DHT key: SHA3-512(fingerprint + ":reverse")
    char reverse_key_input[256];
    snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", fingerprint);

    unsigned char reverse_hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to compute reverse DHT key\n");
        return -1;
    }

    char reverse_dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
    }
    reverse_dht_key[128] = '\0';

    printf("[DHT_KEYSERVER] Reverse lookup for fingerprint: %s\n", fingerprint);
    printf("[DHT_KEYSERVER] Reverse DHT key: %s\n", reverse_dht_key);

    // Fetch from DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht_ctx, (uint8_t*)reverse_dht_key, strlen(reverse_dht_key),
                &value, &value_len) != 0 || !value) {
        printf("[DHT_KEYSERVER] Reverse mapping not found in DHT\n");
        return -2;  // Not found
    }

    // Parse JSON (need to null-terminate first as DHT data isn't)
    char *json_str = (char*)malloc(value_len + 1);
    if (!json_str) {
        free(value);
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate memory for JSON string\n");
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse reverse mapping JSON\n");
        return -1;
    }

    // Extract fields
    json_object *dilithium_obj, *identity_obj, *timestamp_obj, *fingerprint_obj, *signature_obj;

    if (!json_object_object_get_ex(root, "dilithium_pubkey", &dilithium_obj) ||
        !json_object_object_get_ex(root, "identity", &identity_obj) ||
        !json_object_object_get_ex(root, "timestamp", &timestamp_obj) ||
        !json_object_object_get_ex(root, "fingerprint", &fingerprint_obj) ||
        !json_object_object_get_ex(root, "signature", &signature_obj)) {
        fprintf(stderr, "[DHT_KEYSERVER] Reverse mapping missing required fields\n");
        json_object_put(root);
        return -1;
    }

    // Parse dilithium pubkey
    const char *dilithium_hex = json_object_get_string(dilithium_obj);
    uint8_t dilithium_pubkey[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE];
    if (hex_to_bytes(dilithium_hex, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid dilithium pubkey in reverse mapping\n");
        json_object_put(root);
        return -1;
    }

    // Verify fingerprint matches (prevents pubkey substitution)
    char computed_fingerprint[129];
    compute_fingerprint(dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, fingerprint) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Fingerprint mismatch in reverse mapping\n");
        json_object_put(root);
        return -3;  // Signature verification failed (invalid data)
    }

    const char *identity = json_object_get_string(identity_obj);
    uint64_t timestamp = json_object_get_int64(timestamp_obj);

    // Parse signature
    const char *sig_hex = json_object_get_string(signature_obj);
    uint8_t signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
    if (hex_to_bytes(sig_hex, signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid signature in reverse mapping\n");
        json_object_put(root);
        return -1;
    }

    // Rebuild message to verify: dilithium_pubkey || identity || timestamp
    size_t msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(identity) + sizeof(uint64_t);
    uint8_t *msg = (uint8_t*)malloc(msg_len);
    if (!msg) {
        json_object_put(root);
        return -1;
    }

    size_t offset = 0;
    memcpy(msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    memcpy(msg + offset, identity, strlen(identity));
    offset += strlen(identity);

    // Network byte order
    uint64_t timestamp_net = htonll(timestamp);
    memcpy(msg + offset, &timestamp_net, sizeof(timestamp_net));

    // Verify signature
    int verify_result = qgp_dsa87_verify(signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                               msg, msg_len, dilithium_pubkey);
    free(msg);

    if (verify_result != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Reverse mapping signature verification failed\n");
        json_object_put(root);
        return -3;  // Signature verification failed
    }

    // All checks passed - return identity
    *identity_out = strdup(identity);
    printf("[DHT_KEYSERVER] ✓ Reverse lookup successful: %s\n", identity);

    json_object_put(root);
    return 0;
}

// Async reverse lookup: fingerprint → identity (non-blocking with callback)
void dht_keyserver_reverse_lookup_async(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    void (*callback)(char *identity, void *userdata),
    void *userdata
) {
    if (!dht_ctx || !fingerprint || !callback) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to reverse_lookup_async\n");
        if (callback) callback(NULL, userdata);
        return;
    }

    // Compute DHT key: SHA3-512(fingerprint + ":reverse")
    char reverse_key_input[256];
    snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", fingerprint);

    unsigned char reverse_hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to compute reverse DHT key\n");
        callback(NULL, userdata);
        return;
    }

    char reverse_dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
    }
    reverse_dht_key[128] = '\0';

    printf("[DHT_KEYSERVER] Async reverse lookup for fingerprint: %s\n", fingerprint);
    printf("[DHT_KEYSERVER] Reverse DHT key: %s\n", reverse_dht_key);

    // Create context for callback (need to preserve fingerprint)
    reverse_lookup_async_ctx_t *ctx = (reverse_lookup_async_ctx_t*)malloc(sizeof(reverse_lookup_async_ctx_t));
    if (!ctx) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate async context\n");
        callback(NULL, userdata);
        return;
    }

    strncpy(ctx->fingerprint, fingerprint, 128);
    ctx->fingerprint[128] = '\0';
    ctx->callback = callback;
    ctx->userdata = userdata;

    // Start async DHT get with static callback
    dht_get_async(dht_ctx, (uint8_t*)reverse_dht_key, strlen(reverse_dht_key),
                  reverse_lookup_dht_callback, ctx);
}
