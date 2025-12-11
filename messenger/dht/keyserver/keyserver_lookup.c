/**
 * DHT Keyserver - Lookup Operations
 * Handles identity lookups and reverse lookups (sync/async)
 *
 * DHT Keys (only 2):
 * - fingerprint:profile  -> dna_unified_identity_t (keys + name + profile)
 * - name:lookup          -> fingerprint (for name-based lookups)
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"
#include "../client/dna_profile.h"
#include <pthread.h>
#include <ctype.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "KEYSERVER"

// Lookup identity from DHT (supports both fingerprint and name)
// Returns dna_unified_identity_t from fingerprint:profile
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *name_or_fingerprint,
    dna_unified_identity_t **identity_out
) {
    if (!dht_ctx || !name_or_fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments\n");
        return -1;
    }

    *identity_out = NULL;
    char fingerprint[129];

    // Detect input type: fingerprint (128 hex) or name (3-20 alphanumeric)
    if (is_valid_fingerprint(name_or_fingerprint)) {
        // Direct fingerprint lookup
        strncpy(fingerprint, name_or_fingerprint, 128);
        fingerprint[128] = '\0';
        QGP_LOG_INFO(LOG_TAG, "Direct fingerprint lookup: %.16s...\n", fingerprint);
    } else {
        // Name lookup: first resolve name → fingerprint via name:lookup
        QGP_LOG_INFO(LOG_TAG, "Name lookup: resolving '%s' to fingerprint\n", name_or_fingerprint);

        // Normalize name to lowercase (registration stores lowercase keys)
        char normalized_name[64];
        strncpy(normalized_name, name_or_fingerprint, sizeof(normalized_name) - 1);
        normalized_name[sizeof(normalized_name) - 1] = '\0';
        for (char *p = normalized_name; *p; p++) {
            *p = tolower(*p);
        }

        char alias_base_key[256];
        snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", normalized_name);

        uint8_t *alias_data = NULL;
        size_t alias_data_len = 0;
        int alias_ret = dht_chunked_fetch(dht_ctx, alias_base_key, &alias_data, &alias_data_len);

        if (alias_ret != DHT_CHUNK_OK || !alias_data) {
            QGP_LOG_ERROR(LOG_TAG, "Name '%s' not registered: %s\n",
                    name_or_fingerprint, dht_chunked_strerror(alias_ret));
            return -2;  // Name not found
        }

        if (alias_data_len != 128) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid alias data length: %zu\n", alias_data_len);
            free(alias_data);
            return -1;
        }

        memcpy(fingerprint, alias_data, 128);
        fingerprint[128] = '\0';
        free(alias_data);

        QGP_LOG_INFO(LOG_TAG, "✓ Name resolved to fingerprint: %.16s...\n", fingerprint);
    }

    // Fetch identity from fingerprint:profile
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:profile", fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Fetching identity from: %s\n", base_key);

    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &data, &data_len);

    if (ret != DHT_CHUNK_OK || !data) {
        QGP_LOG_ERROR(LOG_TAG, "Identity not found: %s\n", dht_chunked_strerror(ret));
        return -2;  // Not found
    }

    // Parse JSON
    char *json_str = (char*)malloc(data_len + 1);
    if (!json_str) {
        free(data);
        return -1;
    }
    memcpy(json_str, data, data_len);
    json_str[data_len] = '\0';
    free(data);

    dna_unified_identity_t *identity = NULL;
    if (dna_identity_from_json(json_str, &identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse identity JSON\n");
        free(json_str);
        return -1;
    }
    free(json_str);

    // Verify signature against JSON representation (for forward compatibility)
    // This matches the signing method in keyserver_profiles.c
    char *json_unsigned = dna_identity_to_json_unsigned(identity);
    if (!json_unsigned) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity for verification\n");
        dna_identity_free(identity);
        return -1;
    }

    int sig_result = qgp_dsa87_verify(identity->signature, sizeof(identity->signature),
                                       (uint8_t*)json_unsigned, strlen(json_unsigned),
                                       identity->dilithium_pubkey);
    free(json_unsigned);

    if (sig_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature verification failed\n");
        dna_identity_free(identity);
        return -3;
    }

    // Verify fingerprint matches pubkey
    char computed_fingerprint[129];
    compute_fingerprint(identity->dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Fingerprint mismatch\n");
        dna_identity_free(identity);
        return -3;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity retrieved and verified\n");
    QGP_LOG_INFO(LOG_TAG, "Name: %s, Version: %u\n",
           identity->has_registered_name ? identity->registered_name : "(none)",
           identity->version);

    *identity_out = identity;
    return 0;
}

// Reverse lookup: fingerprint → name
// Fetches from fingerprint:profile and extracts registered_name
int dht_keyserver_reverse_lookup(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to reverse_lookup\n");
        return -1;
    }

    *identity_out = NULL;

    QGP_LOG_INFO(LOG_TAG, "Reverse lookup for fingerprint: %.16s...\n", fingerprint);

    // Use dht_keyserver_lookup to fetch the full identity
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(dht_ctx, fingerprint, &identity);

    if (ret != 0 || !identity) {
        QGP_LOG_INFO(LOG_TAG, "Identity not found for fingerprint\n");
        return ret;
    }

    // Extract registered name
    if (identity->has_registered_name && identity->registered_name[0] != '\0') {
        *identity_out = strdup(identity->registered_name);
        QGP_LOG_INFO(LOG_TAG, "✓ Reverse lookup successful: %s\n", identity->registered_name);
    } else {
        // No registered name - return shortened fingerprint
        char short_fp[32];
        snprintf(short_fp, sizeof(short_fp), "%.16s...", fingerprint);
        *identity_out = strdup(short_fp);
        QGP_LOG_INFO(LOG_TAG, "No registered name, returning fingerprint prefix\n");
    }

    dna_identity_free(identity);
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
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to reverse_lookup_async\n");
        if (callback) callback(NULL, userdata);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Async reverse lookup for fingerprint: %s\n", fingerprint);

    // Allocate context for the thread
    reverse_lookup_async_ctx_t *ctx = malloc(sizeof(reverse_lookup_async_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate async context\n");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to create async thread\n");
        free(ctx);
        callback(NULL, userdata);
    }

    pthread_attr_destroy(&attr);
}
