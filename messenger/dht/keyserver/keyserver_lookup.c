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

// Lookup identity from DHT (supports both fingerprint and name)
// Returns dna_unified_identity_t from fingerprint:profile
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *name_or_fingerprint,
    dna_unified_identity_t **identity_out
) {
    if (!dht_ctx || !name_or_fingerprint || !identity_out) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    *identity_out = NULL;
    char fingerprint[129];

    // Detect input type: fingerprint (128 hex) or name (3-20 alphanumeric)
    if (is_valid_fingerprint(name_or_fingerprint)) {
        // Direct fingerprint lookup
        strncpy(fingerprint, name_or_fingerprint, 128);
        fingerprint[128] = '\0';
        printf("[DHT_KEYSERVER] Direct fingerprint lookup: %.16s...\n", fingerprint);
    } else {
        // Name lookup: first resolve name → fingerprint via name:lookup
        printf("[DHT_KEYSERVER] Name lookup: resolving '%s' to fingerprint\n", name_or_fingerprint);

        char alias_base_key[256];
        snprintf(alias_base_key, sizeof(alias_base_key), "%s:lookup", name_or_fingerprint);

        uint8_t *alias_data = NULL;
        size_t alias_data_len = 0;
        int alias_ret = dht_chunked_fetch(dht_ctx, alias_base_key, &alias_data, &alias_data_len);

        if (alias_ret != DHT_CHUNK_OK || !alias_data) {
            fprintf(stderr, "[DHT_KEYSERVER] Name '%s' not registered: %s\n",
                    name_or_fingerprint, dht_chunked_strerror(alias_ret));
            return -2;  // Name not found
        }

        if (alias_data_len != 128) {
            fprintf(stderr, "[DHT_KEYSERVER] Invalid alias data length: %zu\n", alias_data_len);
            free(alias_data);
            return -1;
        }

        memcpy(fingerprint, alias_data, 128);
        fingerprint[128] = '\0';
        free(alias_data);

        printf("[DHT_KEYSERVER] ✓ Name resolved to fingerprint: %.16s...\n", fingerprint);
    }

    // Fetch identity from fingerprint:profile
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s:profile", fingerprint);

    printf("[DHT_KEYSERVER] Fetching identity from: %s\n", base_key);

    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &data, &data_len);

    if (ret != DHT_CHUNK_OK || !data) {
        fprintf(stderr, "[DHT_KEYSERVER] Identity not found: %s\n", dht_chunked_strerror(ret));
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
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse identity JSON\n");
        free(json_str);
        return -1;
    }
    free(json_str);

    // Verify signature
    size_t msg_len = sizeof(identity->fingerprint) +
                     sizeof(identity->dilithium_pubkey) +
                     sizeof(identity->kyber_pubkey) +
                     sizeof(bool) +
                     sizeof(identity->registered_name) +
                     sizeof(identity->name_registered_at) +
                     sizeof(identity->name_expires_at) +
                     sizeof(identity->registration_tx_hash) +
                     sizeof(identity->registration_network) +
                     sizeof(identity->name_version) +
                     sizeof(identity->wallets) +
                     sizeof(identity->socials) +
                     sizeof(identity->bio) +
                     sizeof(identity->profile_picture_ipfs) +
                     sizeof(identity->timestamp) +
                     sizeof(identity->version);

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

    int sig_result = qgp_dsa87_verify(identity->signature, sizeof(identity->signature),
                                       msg, msg_len, identity->dilithium_pubkey);
    free(msg);

    if (sig_result != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Signature verification failed\n");
        dna_identity_free(identity);
        return -3;
    }

    // Verify fingerprint matches pubkey
    char computed_fingerprint[129];
    compute_fingerprint(identity->dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, fingerprint) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Fingerprint mismatch\n");
        dna_identity_free(identity);
        return -3;
    }

    printf("[DHT_KEYSERVER] ✓ Identity retrieved and verified\n");
    printf("[DHT_KEYSERVER] Name: %s, Version: %u\n",
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
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to reverse_lookup\n");
        return -1;
    }

    *identity_out = NULL;

    printf("[DHT_KEYSERVER] Reverse lookup for fingerprint: %.16s...\n", fingerprint);

    // Use dht_keyserver_lookup to fetch the full identity
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(dht_ctx, fingerprint, &identity);

    if (ret != 0 || !identity) {
        printf("[DHT_KEYSERVER] Identity not found for fingerprint\n");
        return ret;
    }

    // Extract registered name
    if (identity->has_registered_name && identity->registered_name[0] != '\0') {
        *identity_out = strdup(identity->registered_name);
        printf("[DHT_KEYSERVER] ✓ Reverse lookup successful: %s\n", identity->registered_name);
    } else {
        // No registered name - return shortened fingerprint
        char short_fp[32];
        snprintf(short_fp, sizeof(short_fp), "%.16s...", fingerprint);
        *identity_out = strdup(short_fp);
        printf("[DHT_KEYSERVER] No registered name, returning fingerprint prefix\n");
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
