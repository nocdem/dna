/*
 * DNA Messenger - Keys Module Implementation
 */

#include "keys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#ifndef __ANDROID__
#ifdef _WIN32
#define CURL_STATICLIB  // Required for static linking on Windows
#endif
#include <curl/curl.h>
#endif /* __ANDROID__ */
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_types.h"
#include "../dht/core/dht_keyserver.h"
#include "../dht/client/dht_singleton.h"
#include "../database/keyserver_cache.h"
#include "../database/contacts_db.h"
#include "../p2p/p2p_transport.h"

// ============================================================================
// CURL HELPERS (not available on Android)
// ============================================================================

#ifndef __ANDROID__
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
#endif /* __ANDROID__ */

// ============================================================================
// HELPER FUNCTIONS (Base64 encoding/decoding)
// ============================================================================

/**
 * Base64 encode helper
 */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* base64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = base64_chars[(triple >> 6) & 0x3F];
        out[j++] = base64_chars[triple & 0x3F];
    }

    // Add padding
    size_t mod = len % 3;
    if (mod == 1) {
        out[out_len - 2] = '=';
        out[out_len - 1] = '=';
    } else if (mod == 2) {
        out[out_len - 1] = '=';
    }

    out[out_len] = '\0';
    return out;
}

/**
 * Base64 decode helper
 */
static size_t base64_decode(const char *input, uint8_t **output) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    size_t decode_len = (input_len * 3) / 4;

    *output = malloc(decode_len);
    if (!*output) return 0;

    bio = BIO_new_mem_buf(input, input_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_size = BIO_read(bio, *output, decode_len);
    BIO_free_all(bio);

    if (decoded_size < 0) {
        free(*output);
        *output = NULL;
        return 0;
    }

    return decoded_size;
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
        fprintf(stderr, "ERROR: Invalid arguments to messenger_store_pubkey\n");
        return -1;
    }

    // Fingerprint-first DHT publishing
    if (display_name && strlen(display_name) > 0) {
        printf("⟳ Publishing public keys for '%s' (fingerprint: %s) to DHT keyserver...\n", display_name, fingerprint);
    } else {
        printf("⟳ Publishing public keys for fingerprint '%s' to DHT keyserver...\n", fingerprint);
    }

    // Use global DHT singleton (initialized at app startup)
    // This eliminates the need for temporary DHT contexts
    dht_context_t *dht_ctx = NULL;

    if (ctx->p2p_transport) {
        // Use existing P2P transport's DHT (when logged in)
        dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
        printf("[INFO] Using P2P transport DHT for key publishing\n");
    } else {
        // Use global DHT singleton (during identity creation, before login)
        dht_ctx = dht_singleton_get();
        if (!dht_ctx) {
            fprintf(stderr, "ERROR: Global DHT not initialized! Call dht_singleton_init() at app startup.\n");
            return -1;
        }
        printf("[INFO] Using global DHT singleton for key publishing\n");
    }

    // Get dna_dir path
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) {
            fprintf(stderr, "ERROR: HOME environment variable not set\n");
            return -1;
        }
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Load private key for signing (using fingerprint)
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s.dsa", dna_dir, fingerprint);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "ERROR: Failed to load signing key: %s\n", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->private_key) {
        fprintf(stderr, "ERROR: Not a Dilithium private key\n");
        qgp_key_free(key);
        return -1;
    }

    // Publish to DHT (FINGERPRINT-FIRST)
    int ret = dht_keyserver_publish(
        dht_ctx,
        fingerprint,
        display_name,  // Optional human-readable name
        signing_pubkey,
        encryption_pubkey,
        key->private_key
    );

    qgp_key_free(key);

    // No cleanup needed - global DHT singleton persists for app lifetime
    // P2P transport DHT is managed by p2p_transport_free()

    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to publish keys to DHT keyserver\n");
        return -1;
    }

    printf("✓ Public keys published to DHT successfully!\n");
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
        fprintf(stderr, "ERROR: Invalid arguments to messenger_load_pubkey\n");
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
        printf("✓ Loaded public keys for '%s' from cache\n", identity);
        return 0;
    }

    // Cache miss - fetch from DHT keyserver
    printf("⟳ Fetching public keys for '%s' from DHT keyserver...\n", identity);

    // Get DHT context from P2P transport
    if (!ctx->p2p_transport) {
        fprintf(stderr, "ERROR: P2P transport not initialized\n");
        return -1;
    }

    dht_context_t *dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        fprintf(stderr, "ERROR: DHT context not available\n");
        return -1;
    }

    // Lookup in DHT
    dht_pubkey_entry_t *entry = NULL;
    ret = dht_keyserver_lookup(dht_ctx, identity, &entry);

    if (ret != 0) {
        if (ret == -2) {
            fprintf(stderr, "ERROR: Identity '%s' not found in DHT keyserver\n", identity);
        } else if (ret == -3) {
            fprintf(stderr, "ERROR: Signature verification failed for identity '%s'\n", identity);
        } else {
            fprintf(stderr, "ERROR: Failed to lookup identity in DHT keyserver\n");
        }
        return -1;
    }

    // Allocate and copy keys
    uint8_t *dil_decoded = malloc(DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    uint8_t *kyber_decoded = malloc(DHT_KEYSERVER_KYBER_PUBKEY_SIZE);

    if (!dil_decoded || !kyber_decoded) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        if (dil_decoded) free(dil_decoded);
        if (kyber_decoded) free(kyber_decoded);
        dht_keyserver_free_entry(entry);
        return -1;
    }

    memcpy(dil_decoded, entry->dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(kyber_decoded, entry->kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);

    size_t dil_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    size_t kyber_len = DHT_KEYSERVER_KYBER_PUBKEY_SIZE;

    // Store in cache for future lookups (using fingerprint as key)
    keyserver_cache_put(entry->fingerprint, dil_decoded, dil_len, kyber_decoded, kyber_len, 0);

    // Return fingerprint if requested
    if (fingerprint_out) {
        strcpy(fingerprint_out, entry->fingerprint);
    }

    // Free DHT entry
    dht_keyserver_free_entry(entry);

    // Return keys
    *signing_pubkey_out = dil_decoded;
    *signing_pubkey_len_out = dil_len;
    *encryption_pubkey_out = kyber_decoded;
    *encryption_pubkey_len_out = kyber_len;
    printf("✓ Loaded public keys for '%s' from keyserver\n", identity);
    return 0;
}

#ifdef __ANDROID__
/* Android: HTTP API not available (no libcurl), use DHT keyserver instead */
int messenger_list_pubkeys(messenger_context_t *ctx) {
    (void)ctx;
    fprintf(stderr, "[Android] messenger_list_pubkeys: HTTP API not available on Android\n");
    fprintf(stderr, "[Android] Use DHT keyserver lookup instead\n");
    return -1;
}
#else
int messenger_list_pubkeys(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Fetch from cpunk.io API using libcurl (secure, no command injection)
    const char *url = "https://cpunk.io/api/keyserver/list";

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: Failed to initialize curl\n");
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
        fprintf(stderr, "Error: Failed to fetch identity list from keyserver: %s\n",
                curl_easy_strerror(res));
        if (resp_buf.data) {
            free(resp_buf.data);
        }
        return -1;
    }

    if (!resp_buf.data) {
        fprintf(stderr, "Error: Empty response from keyserver\n");
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
        fprintf(stderr, "Error: Failed to parse JSON response\n");
        free(response);
        return -1;
    }

    // Check success field
    struct json_object *success_obj = json_object_object_get(root, "success");
    if (!success_obj || !json_object_get_boolean(success_obj)) {
        fprintf(stderr, "Error: API returned failure\n");
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
#endif /* __ANDROID__ */

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
        fprintf(stderr, "Error: Failed to initialize contacts database for '%s'\n", db_identity);
        return -1;
    }

    // Migrate from global contacts.db if needed (first time only)
    static bool migration_attempted = false;
    if (!migration_attempted) {
        int migrated = contacts_db_migrate_from_global(db_identity);
        if (migrated > 0) {
            printf("[MESSENGER] Migrated %d contacts from global database\n", migrated);
        }
        migration_attempted = true;
    }

    // Get contact list from database
    contact_list_t *list = NULL;
    if (contacts_db_list(&list) != 0) {
        fprintf(stderr, "Error: Failed to get contact list\n");
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
        fprintf(stderr, "Error: Memory allocation failed\n");
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
