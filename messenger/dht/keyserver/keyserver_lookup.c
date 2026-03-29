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
#include "dht/shared/nodus_ops.h"
#include "database/keyserver_cache.h"
#include <pthread.h>
#include <ctype.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "KEYSERVER"

// Lookup identity from DHT (supports both fingerprint and name)
// Returns dna_unified_identity_t from fingerprint:profile
int dht_keyserver_lookup(
    const char *name_or_fingerprint,
    dna_unified_identity_t **identity_out
) {
    if (!name_or_fingerprint || !identity_out) {
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
        int alias_ret = nodus_ops_get_str(alias_base_key, &alias_data, &alias_data_len);

        if (alias_ret != 0 || !alias_data) {
            QGP_LOG_ERROR(LOG_TAG, "Name '%s' not registered (ret=%d)\n",
                    name_or_fingerprint, alias_ret);
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
    int ret = nodus_ops_get_str(base_key, &data, &data_len);

    if (ret != 0 || !data) {
        QGP_LOG_ERROR(LOG_TAG, "Identity not found (ret=%d)\n", ret);
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

    if (sig_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature verification failed for identity: name=%s, fp=%.16s...\n",
                      identity->has_registered_name ? identity->registered_name : "(none)",
                      identity->fingerprint);
        QGP_LOG_DEBUG(LOG_TAG, "Verification details: json_len=%zu, sig_result=%d, version=%u\n",
                      strlen(json_unsigned), sig_result, identity->version);
        QGP_LOG_DEBUG(LOG_TAG, "Possible causes: 1) Corrupted data in DHT, 2) Key rotation in progress, 3) Different signing format\n");
        free(json_unsigned);
        dna_identity_free(identity);
        return -3;
    }
    free(json_unsigned);

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
    const char *fingerprint,
    char **identity_out
) {
    if (!fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to reverse_lookup\n");
        return -1;
    }

    *identity_out = NULL;

    QGP_LOG_INFO(LOG_TAG, "Reverse lookup for fingerprint: %.16s...\n", fingerprint);

    // Check name cache first (avoids DHT roundtrip for repeated lookups)
    char cached_name[64] = {0};
    if (keyserver_cache_get_name(fingerprint, cached_name, sizeof(cached_name)) == 0 &&
        cached_name[0] != '\0') {
        *identity_out = strdup(cached_name);
        QGP_LOG_INFO(LOG_TAG, "✓ Reverse lookup (cached): %s\n", cached_name);
        return 0;
    }

    // Use dht_keyserver_lookup to fetch the full identity
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(fingerprint, &identity);

    if (ret != 0 || !identity) {
        QGP_LOG_INFO(LOG_TAG, "Identity not found for fingerprint\n");
        return ret;
    }

    // Name resolution priority (proof of ownership chain):
    // 1. DHT reverse key: fingerprint:rname → candidate name
    // 2. Profile's registered_name as fallback candidate
    // 3. Local cache as last resort candidate
    // ALL candidates verified via: name:lookup → fingerprint (authoritative proof)

    char candidate_name[64] = {0};
    bool found_candidate = false;

    // Step 1: Try DHT reverse mapping (fingerprint:rname → name)
    {
        char rname_key[256];
        snprintf(rname_key, sizeof(rname_key), "%s:rname", fingerprint);
        uint8_t *rname_val = NULL;
        size_t rname_len = 0;
        if (nodus_ops_get_str(rname_key, &rname_val, &rname_len) == 0 &&
            rname_val && rname_len > 0 && rname_len < sizeof(candidate_name)) {
            memcpy(candidate_name, rname_val, rname_len);
            candidate_name[rname_len] = '\0';
            found_candidate = true;
            QGP_LOG_DEBUG(LOG_TAG, "Reverse key candidate: %s\n", candidate_name);
        }
        if (rname_val) free(rname_val);
    }

    // Step 2: Fall back to profile's registered_name
    if (!found_candidate && identity->has_registered_name && identity->registered_name[0] != '\0') {
        strncpy(candidate_name, identity->registered_name, sizeof(candidate_name) - 1);
        found_candidate = true;
        QGP_LOG_DEBUG(LOG_TAG, "Profile candidate: %s\n", candidate_name);
    }

    // Step 3: Fall back to local cache
    if (!found_candidate) {
        char cached_rname[64] = {0};
        if (keyserver_cache_get_name(fingerprint, cached_rname, sizeof(cached_rname)) == 0 &&
            cached_rname[0] != '\0') {
            strncpy(candidate_name, cached_rname, sizeof(candidate_name) - 1);
            found_candidate = true;
            QGP_LOG_DEBUG(LOG_TAG, "Cache candidate: %s\n", candidate_name);
        }
    }

    // Verify candidate against name registry (proof of ownership)
    if (found_candidate && candidate_name[0] != '\0') {
        char verify_key[256];
        snprintf(verify_key, sizeof(verify_key), "%s:lookup", candidate_name);

        uint8_t *lookup_fp = NULL;
        size_t lookup_len = 0;
        int verify_rc = nodus_ops_get_str(verify_key, &lookup_fp, &lookup_len);

        if (verify_rc == 0 && lookup_fp && lookup_len >= 128 &&
            strncmp((char*)lookup_fp, fingerprint, 128) == 0) {
            // ✓ Verified: name registry confirms ownership
            *identity_out = strdup(candidate_name);
            QGP_LOG_INFO(LOG_TAG, "✓ Reverse lookup VERIFIED: %s\n", candidate_name);
            keyserver_cache_put_name(fingerprint, candidate_name, 0);
        } else {
            // ✗ Verification failed — name doesn't belong to this fingerprint
            QGP_LOG_WARN(LOG_TAG, "⚠ Name '%s' failed verification for %.16s...\n",
                        candidate_name, fingerprint);
            char short_fp[32];
            snprintf(short_fp, sizeof(short_fp), "%.16s...", fingerprint);
            *identity_out = strdup(short_fp);
        }

        if (lookup_fp) free(lookup_fp);
    } else {
        // No name candidate found anywhere
        char short_fp[32];
        snprintf(short_fp, sizeof(short_fp), "%.16s...", fingerprint);
        *identity_out = strdup(short_fp);
        QGP_LOG_INFO(LOG_TAG, "No name candidate found for %.16s...\n", fingerprint);
    }

    dna_identity_free(identity);
    return 0;
}

// Thread context for async reverse lookup
typedef struct {
    char fingerprint[129];
    void (*callback)(char *identity, void *userdata);
    void *userdata;
} reverse_lookup_async_ctx_t;

// Worker thread for async reverse lookup
static void *reverse_lookup_thread(void *arg) {
    reverse_lookup_async_ctx_t *ctx = (reverse_lookup_async_ctx_t *)arg;

    // Perform synchronous lookup in this thread
    char *identity = NULL;
    int ret = dht_keyserver_reverse_lookup(ctx->fingerprint, &identity);

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
    const char *fingerprint,
    void (*callback)(char *identity, void *userdata),
    void *userdata
) {
    if (!fingerprint || !callback) {
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
