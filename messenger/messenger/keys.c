/*
 * DNA Messenger - Keys Module Implementation
 */

#include "keys.h"
#include "messenger_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#ifdef _WIN32
#define CURL_STATICLIB  // Required for static linking on Windows
#endif
#include <curl/curl.h>
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_types.h"
#include "../dht/core/dht_keyserver.h"
#include "../dht/client/dht_singleton.h"
#include "../database/keyserver_cache.h"
#include "../database/contacts_db.h"
#include "../p2p/p2p_transport.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_KEYS"

// ============================================================================
// CURL HELPERS
// ============================================================================

// Response buffer for curl
struct curl_response_buffer {
    char *data;
    size_t size;
};

// Curl write callback (renamed to avoid conflict with curl.h typedef)
static size_t keys_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response_buffer *buf = (struct curl_response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

// ============================================================================
// PUBLIC KEY MANAGEMENT
// ============================================================================

int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *fingerprint,
    const char *display_name,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
) {
    if (!ctx || !fingerprint || !signing_pubkey || !encryption_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to messenger_store_pubkey");
        return -1;
    }

    // Fingerprint-first DHT publishing
    if (display_name && strlen(display_name) > 0) {
        QGP_LOG_INFO(LOG_TAG, "Publishing public keys for '%s' (fingerprint: %.16s...) to DHT keyserver", display_name, fingerprint);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Publishing public keys for fingerprint '%.16s...' to DHT keyserver", fingerprint);
    }

    // Use global DHT singleton (initialized at app startup)
    // This eliminates the need for temporary DHT contexts
    dht_context_t *dht_ctx = NULL;

    if (ctx->p2p_transport) {
        // Use existing P2P transport's DHT (when logged in)
        dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
        QGP_LOG_INFO(LOG_TAG, "Using P2P transport DHT for key publishing\n");
    } else {
        // Use global DHT singleton (during identity creation, before login)
        dht_ctx = dht_singleton_get();
        if (!dht_ctx) {
            QGP_LOG_ERROR(LOG_TAG, "Global DHT not initialized! Call dht_singleton_init() at app startup.");
            return -1;
        }
        QGP_LOG_INFO(LOG_TAG, "Using global DHT singleton for key publishing\n");
    }

    // Get data directory
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }

    // Find and load private key for signing (searches <data_dir>/*/keys/)
    char key_path[512];
    if (messenger_find_key_path(data_dir, fingerprint, ".dsa", key_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signing key not found for fingerprint: %.16s...", fingerprint);
        return -1;
    }

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key: %s", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->private_key) {
        QGP_LOG_ERROR(LOG_TAG, "Not a Dilithium private key");
        qgp_key_free(key);
        return -1;
    }

    // Publish to DHT (FINGERPRINT-FIRST)
    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] messenger_publish_pubkeys calling dht_keyserver_publish");
    int ret = dht_keyserver_publish(
        dht_ctx,
        fingerprint,
        display_name,  // Optional human-readable name
        signing_pubkey,
        encryption_pubkey,
        key->private_key,
        NULL,  // wallet_address not available here
        NULL,  // eth_address not available here
        NULL,  // sol_address not available here
        NULL   // trx_address not available here
    );

    qgp_key_free(key);

    // No cleanup needed - global DHT singleton persists for app lifetime
    // P2P transport DHT is managed by p2p_transport_free()

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish keys to DHT keyserver");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Public keys published to DHT successfully");
    return 0;
}

int messenger_load_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **signing_pubkey_out,
    size_t *signing_pubkey_len_out,
    uint8_t **encryption_pubkey_out,
    size_t *encryption_pubkey_len_out,
    char *fingerprint_out  // NEW: Output fingerprint (129 bytes), can be NULL
) {
    if (!ctx || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to messenger_load_pubkey");
        return -1;
    }

    // Phase 4: Check keyserver cache first
    keyserver_cache_entry_t *cached = NULL;
    int ret = keyserver_cache_get(identity, &cached);
    if (ret == 0 && cached) {
        // Cache hit!
        *signing_pubkey_out = malloc(cached->dilithium_pubkey_len);
        *encryption_pubkey_out = malloc(cached->kyber_pubkey_len);

        if (!*signing_pubkey_out || !*encryption_pubkey_out) {
            if (*signing_pubkey_out) free(*signing_pubkey_out);
            if (*encryption_pubkey_out) free(*encryption_pubkey_out);
            keyserver_cache_free_entry(cached);
            return -1;
        }

        memcpy(*signing_pubkey_out, cached->dilithium_pubkey, cached->dilithium_pubkey_len);
        memcpy(*encryption_pubkey_out, cached->kyber_pubkey, cached->kyber_pubkey_len);
        *signing_pubkey_len_out = cached->dilithium_pubkey_len;
        *encryption_pubkey_len_out = cached->kyber_pubkey_len;

        // Return fingerprint from cache
        if (fingerprint_out && strlen(cached->identity) == 128) {
            strcpy(fingerprint_out, cached->identity);
        }

        keyserver_cache_free_entry(cached);
        QGP_LOG_DEBUG(LOG_TAG, "Loaded public keys for '%s' from cache", identity);
        return 0;
    }

    // Cache miss - fetch from DHT keyserver
    QGP_LOG_INFO(LOG_TAG, "Fetching public keys for '%s' from DHT keyserver...", identity);

    // Get DHT context - prefer P2P transport, fallback to global singleton
    // Phase 14: DHT-only messaging doesn't require P2P transport
    dht_context_t *dht_ctx = NULL;
    if (ctx->p2p_transport) {
        dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
    }
    if (!dht_ctx) {
        // Fallback to global DHT singleton (Phase 14: DHT-only messaging)
        dht_ctx = dht_singleton_get();
    }
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available (singleton not initialized)");
        return -1;
    }

    // Lookup in DHT
    dna_unified_identity_t *dht_identity = NULL;
    ret = dht_keyserver_lookup(dht_ctx, identity, &dht_identity);

    if (ret != 0) {
        if (ret == -2) {
            QGP_LOG_ERROR(LOG_TAG, "Identity '%s' not found in DHT keyserver", identity);
        } else if (ret == -3) {
            QGP_LOG_ERROR(LOG_TAG, "Signature verification failed for identity '%s'", identity);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Failed to lookup identity in DHT keyserver");
        }
        return -1;
    }

    // Allocate and copy keys
    uint8_t *dil_decoded = malloc(DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    uint8_t *kyber_decoded = malloc(DHT_KEYSERVER_KYBER_PUBKEY_SIZE);

    if (!dil_decoded || !kyber_decoded) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        if (dil_decoded) free(dil_decoded);
        if (kyber_decoded) free(kyber_decoded);
        dna_identity_free(dht_identity);
        return -1;
    }

    memcpy(dil_decoded, dht_identity->dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(kyber_decoded, dht_identity->kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);

    size_t dil_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    size_t kyber_len = DHT_KEYSERVER_KYBER_PUBKEY_SIZE;

    // Store in cache for future lookups (using fingerprint as key)
    keyserver_cache_put(dht_identity->fingerprint, dil_decoded, dil_len, kyber_decoded, kyber_len, 0);

    // Return fingerprint if requested
    if (fingerprint_out) {
        strcpy(fingerprint_out, dht_identity->fingerprint);
    }

    // Free DHT identity
    dna_identity_free(dht_identity);

    // Return keys
    *signing_pubkey_out = dil_decoded;
    *signing_pubkey_len_out = dil_len;
    *encryption_pubkey_out = kyber_decoded;
    *encryption_pubkey_len_out = kyber_len;
    QGP_LOG_INFO(LOG_TAG, "Loaded public keys for '%s' from keyserver", identity);
    return 0;
}

int messenger_list_pubkeys(const messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Fetch from cpunk.io API using libcurl (secure, no command injection)
    const char *url = "https://cpunk.io/api/keyserver/list";

    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize curl");
        return -1;
    }

    // Setup response buffer
    struct curl_response_buffer resp_buf = {0};

    // Configure curl options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, keys_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");  // HTTPS only (curl 7.85.0+)
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);  // 30 second timeout
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // Follow redirects
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);  // Max 3 redirects

    // Perform request
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch identity list from keyserver: %s",
                curl_easy_strerror(res));
        if (resp_buf.data) {
            free(resp_buf.data);
        }
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response from keyserver");
        return -1;
    }

    // Use the response buffer
    char *response = resp_buf.data;
    size_t response_len = resp_buf.size;

    // Trim whitespace
    while (response_len > 0 &&
           (response[response_len-1] == '\n' ||
            response[response_len-1] == '\r' ||
            response[response_len-1] == ' ' ||
            response[response_len-1] == '\t')) {
        response[--response_len] = '\0';
    }

    // Parse JSON response
    struct json_object *root = json_tokener_parse(response);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON response");
        free(response);
        return -1;
    }

    // Check success field
    struct json_object *success_obj = json_object_object_get(root, "success");
    if (!success_obj || !json_object_get_boolean(success_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "API returned failure");
        json_object_put(root);
        free(response);
        return -1;
    }

    // Get total count
    struct json_object *total_obj = json_object_object_get(root, "total");
    int total = total_obj ? json_object_get_int(total_obj) : 0;

    printf("\n=== Keyserver (%d identities) ===\n\n", total);

    // Get identities array
    struct json_object *identities_obj = json_object_object_get(root, "identities");
    if (!identities_obj || !json_object_is_type(identities_obj, json_type_array)) {
        json_object_put(root);
        free(response);
        return 0;
    }

    int count = json_object_array_length(identities_obj);
    for (int i = 0; i < count; i++) {
        struct json_object *identity_obj = json_object_array_get_idx(identities_obj, i);
        if (!identity_obj) continue;

        struct json_object *dna_obj = json_object_object_get(identity_obj, "dna");
        struct json_object *registered_obj = json_object_object_get(identity_obj, "registered_at");

        const char *identity = dna_obj ? json_object_get_string(dna_obj) : "unknown";
        const char *registered_at = registered_obj ? json_object_get_string(registered_obj) : "unknown";

        printf("  %s (added: %s)\n", identity, registered_at);
    }

    printf("\n");
    json_object_put(root);
    free(response);
    return 0;
}

/**
 * Get contact list (from local contacts database)
 * Phase 9.4: Replaced HTTP API with local contacts_db
 */
int messenger_get_contact_list(messenger_context_t *ctx, char ***identities_out, int *count_out) {
    if (!ctx || !identities_out || !count_out) {
        return -1;
    }

    // Initialize contacts database if not already done (per-identity)
    // Use fingerprint (canonical) to ensure consistent database path regardless of login method
    const char *db_identity = ctx->fingerprint ? ctx->fingerprint : ctx->identity;
    if (contacts_db_init(db_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize contacts database for '%s'", db_identity);
        return -1;
    }

    // Migrate from global contacts.db if needed (first time only)
    static bool migration_attempted = false;
    if (!migration_attempted) {
        int migrated = contacts_db_migrate_from_global(db_identity);
        if (migrated > 0) {
            QGP_LOG_INFO(LOG_TAG, "Migrated %d contacts from global database\n", migrated);
        }
        migration_attempted = true;
    }

    // Get contact list from database
    contact_list_t *list = NULL;
    if (contacts_db_list(&list) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get contact list");
        return -1;
    }

    *count_out = list->count;

    if (list->count == 0) {
        *identities_out = NULL;
        contacts_db_free_list(list);
        return 0;
    }

    // Allocate array of string pointers
    char **identities = (char**)malloc(sizeof(char*) * list->count);
    if (!identities) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        contacts_db_free_list(list);
        return -1;
    }

    // Copy each identity string
    for (size_t i = 0; i < list->count; i++) {
        identities[i] = strdup(list->contacts[i].identity);
        if (!identities[i]) {
            // Clean up on failure
            for (size_t j = 0; j < i; j++) {
                free(identities[j]);
            }
            free(identities);
            contacts_db_free_list(list);
            return -1;
        }
    }

    *identities_out = identities;
    contacts_db_free_list(list);
    return 0;
}
