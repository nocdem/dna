/**
 * DHT Profile Storage Implementation
 * Public user profile data stored in DHT
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 *
 * @file dht_profile.c
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#include "dht_profile.h"
#include "dht_chunked.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_dilithium.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_PROFILE"
// Windows byte order conversion macros (be64toh, htobe64 not available)
#ifdef _WIN32
#include <winsock2.h>

// 64-bit big-endian conversions for Windows
#define htobe64(x) ( \
    ((uint64_t)(htonl((uint32_t)((x) & 0xFFFFFFFF))) << 32) | \
    ((uint64_t)(htonl((uint32_t)((x) >> 32)))) \
)
#define be64toh(x) htobe64(x)  // Same operation for bidirectional conversion

#else
#include <endian.h>
#endif

// JSON helpers (simple manual serialization - no json-c dependency)

/**
 * Escape JSON string (handle quotes and backslashes)
 */
static char* json_escape(const char *str) {
    if (!str) return strdup("");

    size_t len = strlen(str);
    char *escaped = malloc(len * 2 + 1);  // Worst case: every char needs escaping
    if (!escaped) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '"' || str[i] == '\\') {
            escaped[j++] = '\\';
        }
        escaped[j++] = str[i];
    }
    escaped[j] = '\0';

    return escaped;
}

/**
 * Serialize profile to JSON
 */
static char* serialize_to_json(const dht_profile_t *profile) {
    if (!profile) return NULL;

    // Escape fields
    char *esc_display_name = json_escape(profile->display_name);
    char *esc_bio = json_escape(profile->bio);
    char *esc_avatar_hash = json_escape(profile->avatar_hash);
    char *esc_location = json_escape(profile->location);
    char *esc_website = json_escape(profile->website);

    if (!esc_display_name || !esc_bio || !esc_avatar_hash || !esc_location || !esc_website) {
        free(esc_display_name);
        free(esc_bio);
        free(esc_avatar_hash);
        free(esc_location);
        free(esc_website);
        return NULL;
    }

    // Build JSON (2KB should be plenty for profile data)
    char *json = malloc(2048);
    if (!json) {
        free(esc_display_name);
        free(esc_bio);
        free(esc_avatar_hash);
        free(esc_location);
        free(esc_website);
        return NULL;
    }

    snprintf(json, 2048,
        "{\n"
        "  \"display_name\": \"%s\",\n"
        "  \"bio\": \"%s\",\n"
        "  \"avatar_hash\": \"%s\",\n"
        "  \"location\": \"%s\",\n"
        "  \"website\": \"%s\",\n"
        "  \"created_at\": %lu,\n"
        "  \"updated_at\": %lu\n"
        "}",
        esc_display_name,
        esc_bio,
        esc_avatar_hash,
        esc_location,
        esc_website,
        (unsigned long)profile->created_at,
        (unsigned long)profile->updated_at
    );

    free(esc_display_name);
    free(esc_bio);
    free(esc_avatar_hash);
    free(esc_location);
    free(esc_website);

    return json;
}

/**
 * Simple JSON field extractor (no full parser - just extract quoted strings and numbers)
 */
static bool json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out) return false;

    // Find key
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char *pos = strstr(json, search);
    if (!pos) return false;

    // Skip to value
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;

    if (*pos != '"') return false;
    pos++;  // Skip opening quote

    // Extract value
    size_t i = 0;
    while (*pos && *pos != '"' && i < out_size - 1) {
        if (*pos == '\\' && *(pos + 1)) {
            pos++;  // Skip escape char
        }
        out[i++] = *pos++;
    }
    out[i] = '\0';

    return true;
}

static bool json_get_uint64(const char *json, const char *key, uint64_t *out) {
    if (!json || !key || !out) return false;

    // Find key
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char *pos = strstr(json, search);
    if (!pos) return false;

    // Skip to value
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;

    // Parse number
    *out = strtoull(pos, NULL, 10);
    return true;
}

/**
 * Deserialize JSON to profile
 */
static int deserialize_from_json(const char *json, dht_profile_t *profile_out) {
    if (!json || !profile_out) return -1;

    memset(profile_out, 0, sizeof(dht_profile_t));

    // Extract fields
    if (!json_get_string(json, "display_name", profile_out->display_name, sizeof(profile_out->display_name))) {
        return -1;
    }

    json_get_string(json, "bio", profile_out->bio, sizeof(profile_out->bio));
    json_get_string(json, "avatar_hash", profile_out->avatar_hash, sizeof(profile_out->avatar_hash));
    json_get_string(json, "location", profile_out->location, sizeof(profile_out->location));
    json_get_string(json, "website", profile_out->website, sizeof(profile_out->website));

    if (!json_get_uint64(json, "created_at", &profile_out->created_at)) {
        profile_out->created_at = 0;
    }

    if (!json_get_uint64(json, "updated_at", &profile_out->updated_at)) {
        profile_out->updated_at = 0;
    }

    return 0;
}

/**
 * Generate base key string for profile storage
 * Format: "fingerprint:profile"
 * The dht_chunked layer handles hashing internally
 */
static int make_base_key(const char *user_fingerprint, char *key_out, size_t key_out_size) {
    if (!user_fingerprint || !key_out) return -1;

    // Fingerprint is 64-byte hex string (128 chars)
    size_t fp_len = strlen(user_fingerprint);
    if (fp_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length: %zu (expected 128)\n", fp_len);
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:profile", user_fingerprint);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/**
 * Initialize DHT profile subsystem
 */
int dht_profile_init(void) {
    // Currently nothing to initialize
    QGP_LOG_INFO(LOG_TAG, "Initialized\n");
    return 0;
}

/**
 * Cleanup DHT profile subsystem
 */
void dht_profile_cleanup(void) {
    // Currently nothing to cleanup
    QGP_LOG_INFO(LOG_TAG, "Cleaned up\n");
}

/**
 * Publish user profile to DHT
 */
int dht_profile_publish(
    dht_context_t *dht_ctx,
    const char *user_fingerprint,
    const dht_profile_t *profile,
    const uint8_t *dilithium_privkey)
{
    if (!dht_ctx || !user_fingerprint || !profile || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for publish\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing profile for '%s'\n", user_fingerprint);

    // Validate profile
    if (!dht_profile_validate(profile)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid profile data\n");
        return -1;
    }

    // Serialize to JSON
    char *json = serialize_to_json(profile);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize profile\n");
        return -1;
    }

    size_t json_len = strlen(json);
    QGP_LOG_INFO(LOG_TAG, "JSON size: %zu bytes\n", json_len);

    // Sign JSON data with Dilithium5 (DSA-87)
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];
    size_t siglen = 0;
    if (qgp_dsa87_sign(signature, &siglen, (const uint8_t*)json, json_len, dilithium_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign profile\n");
        free(json);
        return -1;
    }

    // Build binary blob: [json_len (8 bytes)][json][signature_len (8 bytes)][signature]
    size_t blob_size = 8 + json_len + 8 + siglen;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blob\n");
        free(json);
        return -1;
    }

    uint8_t *ptr = blob;

    // Write json_len (network byte order - big endian)
    uint64_t json_len_be = htobe64(json_len);
    memcpy(ptr, &json_len_be, 8);
    ptr += 8;

    // Write JSON
    memcpy(ptr, json, json_len);
    ptr += json_len;

    // Write signature_len (network byte order)
    uint64_t sig_len_be = htobe64(siglen);
    memcpy(ptr, &sig_len_be, 8);
    ptr += 8;

    // Write signature
    memcpy(ptr, signature, siglen);

    free(json);

    QGP_LOG_INFO(LOG_TAG, "Total blob size: %zu bytes\n", blob_size);

    // Generate base key for chunked storage
    char base_key[256];
    if (make_base_key(user_fingerprint, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        free(blob);
        return -1;
    }

    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] dht_profile_publish called for %.16s...\n", user_fingerprint);

    // Store in DHT using chunked layer (handles compression, chunking, signing)
    int result = dht_chunked_publish(dht_ctx, base_key, blob, blob_size, DHT_CHUNK_TTL_365DAY);
    free(blob);

    if (result != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT: %s\n", dht_chunked_strerror(result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published profile\n");
    return 0;
}

/**
 * Fetch user profile from DHT
 */
int dht_profile_fetch(
    dht_context_t *dht_ctx,
    const char *user_fingerprint,
    dht_profile_t *profile_out)
{
    if (!dht_ctx || !user_fingerprint || !profile_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching profile for '%s'\n", user_fingerprint);

    // Generate base key for chunked storage
    char base_key[256];
    if (make_base_key(user_fingerprint, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    // Fetch from DHT using chunked layer (handles decompression, reassembly)
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result != DHT_CHUNK_OK || !blob) {
        QGP_LOG_INFO(LOG_TAG, "Profile not found in DHT: %s\n", dht_chunked_strerror(result));
        return -2;  // Not found
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched blob: %zu bytes\n", blob_size);

    // Parse blob: [json_len][json][sig_len][signature]
    if (blob_size < 16) {  // Minimum: 8 + 0 + 8 + 0
        QGP_LOG_ERROR(LOG_TAG, "Blob too small\n");
        free(blob);
        return -1;
    }

    uint8_t *ptr = blob;

    // Read json_len
    uint64_t json_len_be;
    memcpy(&json_len_be, ptr, 8);
    uint64_t json_len = be64toh(json_len_be);
    ptr += 8;

    if (json_len > blob_size - 16) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid json_len: %lu\n", (unsigned long)json_len);
        free(blob);
        return -1;
    }

    // Read JSON
    char *json = malloc(json_len + 1);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate JSON buffer\n");
        free(blob);
        return -1;
    }
    memcpy(json, ptr, json_len);
    json[json_len] = '\0';
    ptr += json_len;

    // Read signature_len
    uint64_t sig_len_be;
    memcpy(&sig_len_be, ptr, 8);
    uint64_t sig_len = be64toh(sig_len_be);
    ptr += 8;

    if (sig_len > QGP_DSA87_SIGNATURE_BYTES || sig_len > (size_t)(blob + blob_size - ptr)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature length: %lu\n", (unsigned long)sig_len);
        free(json);
        free(blob);
        return -1;
    }

    // Note: We can't verify signature without public key
    // Signature verification should be done by caller if needed
    // For now, we trust DHT (signed puts provide some authenticity)
    // signature starts at ptr, length is sig_len (unused for now)

    QGP_LOG_INFO(LOG_TAG, "Signature present (%lu bytes), skipping verification\n",
           (unsigned long)sig_len);

    // Deserialize JSON
    if (deserialize_from_json(json, profile_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON\n");
        free(json);
        free(blob);
        return -1;
    }

    free(json);
    free(blob);

    QGP_LOG_INFO(LOG_TAG, "Successfully fetched profile\n");
    return 0;
}

/**
 * Delete user profile from DHT
 *
 * Note: DHT doesn't support true deletion. This function publishes
 * empty chunks to overwrite existing data. Chunks will fully expire via TTL.
 */
int dht_profile_delete(
    dht_context_t *dht_ctx,
    const char *user_fingerprint)
{
    if (!dht_ctx || !user_fingerprint) {
        return -1;
    }

    char base_key[256];
    if (make_base_key(user_fingerprint, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    // Note: dht_chunked_delete overwrites with empty chunks
    dht_chunked_delete(dht_ctx, base_key, 0);

    QGP_LOG_INFO(LOG_TAG, "Deleted profile for '%s' (best-effort)\n", user_fingerprint);
    return 0;
}

/**
 * Validate profile data
 */
bool dht_profile_validate(const dht_profile_t *profile) {
    if (!profile) return false;

    // Display name is required
    if (strlen(profile->display_name) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Display name is required\n");
        return false;
    }

    // Check sizes (should be enforced by struct, but double-check)
    if (strlen(profile->display_name) >= DHT_PROFILE_MAX_DISPLAY_NAME ||
        strlen(profile->bio) >= DHT_PROFILE_MAX_BIO ||
        strlen(profile->avatar_hash) >= DHT_PROFILE_MAX_AVATAR_HASH ||
        strlen(profile->location) >= DHT_PROFILE_MAX_LOCATION ||
        strlen(profile->website) >= DHT_PROFILE_MAX_WEBSITE) {
        QGP_LOG_ERROR(LOG_TAG, "Profile field exceeds maximum size\n");
        return false;
    }

    return true;
}

/**
 * Create empty profile
 */
void dht_profile_init_empty(dht_profile_t *profile_out) {
    if (!profile_out) return;

    memset(profile_out, 0, sizeof(dht_profile_t));
    profile_out->created_at = (uint64_t)time(NULL);
    profile_out->updated_at = profile_out->created_at;
}
