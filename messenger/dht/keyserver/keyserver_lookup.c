/**
 * DHT Keyserver - Lookup Operations
 * Handles key lookups, reverse lookups (sync/async)
 * Now uses dht_chunked layer for all DHT operations.
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"
#include <pthread.h>

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
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:pubkey", fingerprint);

    printf("[DHT_KEYSERVER] Fetching keys for fingerprint from DHT\n");
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

    // Create base key for reverse lookup (chunked layer handles hashing)
    char reverse_base_key[256];
    snprintf(reverse_base_key, sizeof(reverse_base_key), "%s:reverse", fingerprint);

    printf("[DHT_KEYSERVER] Reverse lookup for fingerprint: %s\n", fingerprint);
    printf("[DHT_KEYSERVER] Reverse base key: %s\n", reverse_base_key);

    // Fetch from DHT via chunked layer
    uint8_t *value = NULL;
    size_t value_len = 0;

    int ret = dht_chunked_fetch(dht_ctx, reverse_base_key, &value, &value_len);
    if (ret != DHT_CHUNK_OK || !value) {
        printf("[DHT_KEYSERVER] Reverse mapping not found in DHT: %s\n", dht_chunked_strerror(ret));
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

// Thread context for async reverse lookup
typedef struct {
    dht_context_t *dht_ctx;
    char fingerprint[129];
    void (*callback)(char *identity, void *userdata);
    void *userdata;
} reverse_lookup_async_ctx_t;

// Worker thread for async reverse lookup
static void *reverse_lookup_thread(void *arg) {
    reverse_lookup_async_ctx_t *ctx = (reverse_lookup_async_ctx_t *)arg;

    // Perform synchronous lookup in this thread
    char *identity = NULL;
    int ret = dht_keyserver_reverse_lookup(ctx->dht_ctx, ctx->fingerprint, &identity);

    // Call the callback with the result
    if (ret != 0) {
        ctx->callback(NULL, ctx->userdata);
    } else {
        ctx->callback(identity, ctx->userdata);  // Caller is responsible for freeing identity
    }

    // Free the context
    free(ctx);
    return NULL;
}

// Async reverse lookup: fingerprint → identity (true async using pthread)
// Spawns a detached thread to perform the lookup without blocking the caller
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

    printf("[DHT_KEYSERVER] Async reverse lookup for fingerprint: %s\n", fingerprint);

    // Allocate context for the thread
    reverse_lookup_async_ctx_t *ctx = malloc(sizeof(reverse_lookup_async_ctx_t));
    if (!ctx) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate async context\n");
        callback(NULL, userdata);
        return;
    }

    ctx->dht_ctx = dht_ctx;
    strncpy(ctx->fingerprint, fingerprint, 128);
    ctx->fingerprint[128] = '\0';
    ctx->callback = callback;
    ctx->userdata = userdata;

    // Spawn detached thread
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&thread, &attr, reverse_lookup_thread, ctx) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to create async thread\n");
        free(ctx);
        callback(NULL, userdata);
    }

    pthread_attr_destroy(&attr);
}
