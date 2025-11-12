/**
 * DHT Profile Storage Implementation
 * Public user profile data stored in DHT
 *
 * @file dht_profile.c
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#include "dht_profile.h"
#include "../qgp_sha3.h"
#include "../qgp_dilithium.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
 * Compute DHT key for profile
 * Key = SHA3-512(user_fingerprint + ":profile")
 */
static int compute_dht_key(const char *user_fingerprint, uint8_t *key_out) {
    if (!user_fingerprint || !key_out) return -1;

    // Fingerprint is 64-byte hex string (128 chars)
    size_t fp_len = strlen(user_fingerprint);
    if (fp_len != 128) {
        fprintf(stderr, "[DHT_PROFILE] Invalid fingerprint length: %zu (expected 128)\n", fp_len);
        return -1;
    }

    // Construct key string: fingerprint + ":profile"
    char key_str[256];
    snprintf(key_str, sizeof(key_str), "%s:profile", user_fingerprint);

    // Hash with SHA3-512
    if (qgp_sha3_512((const uint8_t*)key_str, strlen(key_str), key_out) != 0) {
        fprintf(stderr, "[DHT_PROFILE] Failed to compute SHA3-512\n");
        return -1;
    }

    return 0;
}

/**
 * Initialize DHT profile subsystem
 */
int dht_profile_init(void) {
    // Currently nothing to initialize
    printf("[DHT_PROFILE] Initialized\n");
    return 0;
}

/**
 * Cleanup DHT profile subsystem
 */
void dht_profile_cleanup(void) {
    // Currently nothing to cleanup
    printf("[DHT_PROFILE] Cleaned up\n");
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
        fprintf(stderr, "[DHT_PROFILE] Invalid parameters for publish\n");
        return -1;
    }

    printf("[DHT_PROFILE] Publishing profile for '%s'\n", user_fingerprint);

    // Validate profile
    if (!dht_profile_validate(profile)) {
        fprintf(stderr, "[DHT_PROFILE] Invalid profile data\n");
        return -1;
    }

    // Serialize to JSON
    char *json = serialize_to_json(profile);
    if (!json) {
        fprintf(stderr, "[DHT_PROFILE] Failed to serialize profile\n");
        return -1;
    }

    size_t json_len = strlen(json);
    printf("[DHT_PROFILE] JSON size: %zu bytes\n", json_len);

    // Sign JSON data with Dilithium5 (DSA-87)
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];
    size_t siglen = 0;
    if (qgp_dsa87_sign(signature, &siglen, (const uint8_t*)json, json_len, dilithium_privkey) != 0) {
        fprintf(stderr, "[DHT_PROFILE] Failed to sign profile\n");
        free(json);
        return -1;
    }

    // Build binary blob: [json_len (8 bytes)][json][signature_len (8 bytes)][signature]
    size_t blob_size = 8 + json_len + 8 + siglen;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        fprintf(stderr, "[DHT_PROFILE] Failed to allocate blob\n");
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

    printf("[DHT_PROFILE] Total blob size: %zu bytes\n", blob_size);

    // Compute DHT key
    uint8_t dht_key[64];
    if (compute_dht_key(user_fingerprint, dht_key) != 0) {
        fprintf(stderr, "[DHT_PROFILE] Failed to compute DHT key\n");
        free(blob);
        return -1;
    }

    // Store in DHT with signed put (value_id=1 for replacement)
    int result = dht_put_signed_permanent(dht_ctx, dht_key, 64, blob, blob_size, 1);
    free(blob);

    if (result != 0) {
        fprintf(stderr, "[DHT_PROFILE] Failed to store in DHT\n");
        return -1;
    }

    printf("[DHT_PROFILE] Successfully published profile (signed, value_id=1)\n");
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
        fprintf(stderr, "[DHT_PROFILE] Invalid parameters for fetch\n");
        return -1;
    }

    printf("[DHT_PROFILE] Fetching profile for '%s'\n", user_fingerprint);

    // Compute DHT key
    uint8_t dht_key[64];
    if (compute_dht_key(user_fingerprint, dht_key) != 0) {
        fprintf(stderr, "[DHT_PROFILE] Failed to compute DHT key\n");
        return -1;
    }

    // Fetch from DHT
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_get(dht_ctx, dht_key, 64, &blob, &blob_size);
    if (result != 0 || !blob) {
        printf("[DHT_PROFILE] Profile not found in DHT\n");
        return -2;  // Not found
    }

    printf("[DHT_PROFILE] Fetched blob: %zu bytes\n", blob_size);

    // Parse blob: [json_len][json][sig_len][signature]
    if (blob_size < 16) {  // Minimum: 8 + 0 + 8 + 0
        fprintf(stderr, "[DHT_PROFILE] Blob too small\n");
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
        fprintf(stderr, "[DHT_PROFILE] Invalid json_len: %lu\n", (unsigned long)json_len);
        free(blob);
        return -1;
    }

    // Read JSON
    char *json = malloc(json_len + 1);
    if (!json) {
        fprintf(stderr, "[DHT_PROFILE] Failed to allocate JSON buffer\n");
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
        fprintf(stderr, "[DHT_PROFILE] Invalid signature length: %lu\n", (unsigned long)sig_len);
        free(json);
        free(blob);
        return -1;
    }

    // Read signature
    uint8_t *signature = ptr;

    // Note: We can't verify signature without public key
    // Signature verification should be done by caller if needed
    // For now, we trust DHT (signed puts provide some authenticity)

    printf("[DHT_PROFILE] Signature present (%lu bytes), skipping verification\n",
           (unsigned long)sig_len);

    // Deserialize JSON
    if (deserialize_from_json(json, profile_out) != 0) {
        fprintf(stderr, "[DHT_PROFILE] Failed to parse JSON\n");
        free(json);
        free(blob);
        return -1;
    }

    free(json);
    free(blob);

    printf("[DHT_PROFILE] Successfully fetched profile\n");
    return 0;
}

/**
 * Delete user profile from DHT
 */
int dht_profile_delete(
    dht_context_t *dht_ctx,
    const char *user_fingerprint)
{
    if (!dht_ctx || !user_fingerprint) {
        return -1;
    }

    uint8_t dht_key[64];
    if (compute_dht_key(user_fingerprint, dht_key) != 0) {
        return -1;
    }

    // Note: DHT deletion is best-effort (not guaranteed)
    dht_delete(dht_ctx, dht_key, 64);

    printf("[DHT_PROFILE] Deleted profile for '%s' (best-effort)\n", user_fingerprint);
    return 0;
}

/**
 * Validate profile data
 */
bool dht_profile_validate(const dht_profile_t *profile) {
    if (!profile) return false;

    // Display name is required
    if (strlen(profile->display_name) == 0) {
        fprintf(stderr, "[DHT_PROFILE] Display name is required\n");
        return false;
    }

    // Check sizes (should be enforced by struct, but double-check)
    if (strlen(profile->display_name) >= DHT_PROFILE_MAX_DISPLAY_NAME ||
        strlen(profile->bio) >= DHT_PROFILE_MAX_BIO ||
        strlen(profile->avatar_hash) >= DHT_PROFILE_MAX_AVATAR_HASH ||
        strlen(profile->location) >= DHT_PROFILE_MAX_LOCATION ||
        strlen(profile->website) >= DHT_PROFILE_MAX_WEBSITE) {
        fprintf(stderr, "[DHT_PROFILE] Profile field exceeds maximum size\n");
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
