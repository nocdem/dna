/**
 * DHT GEK (Group Encryption Key) Synchronization Implementation
 * Per-identity encrypted GEK cache with DHT storage
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 *
 * @file dht_geks.c
 * @date 2026-01-25
 */

#include "dht_geks.h"
#include "../shared/dht_chunked.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../dna_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_GEKS"

#ifdef _WIN32
#include <winsock2.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#endif

// Network byte order functions (may not be available on all systems)
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

// Base64 encoding table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ============================================================================
// BASE64 HELPERS
// ============================================================================

/**
 * Encode binary data to base64
 */
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

        out[j++] = base64_table[(triple >> 18) & 0x3F];
        out[j++] = base64_table[(triple >> 12) & 0x3F];
        out[j++] = base64_table[(triple >> 6) & 0x3F];
        out[j++] = base64_table[triple & 0x3F];
    }

    // Padding
    size_t mod = len % 3;
    if (mod > 0) {
        out[out_len - 1] = '=';
        if (mod == 1) {
            out[out_len - 2] = '=';
        }
    }

    out[out_len] = '\0';
    return out;
}

/**
 * Decode base64 string to binary
 */
static int base64_decode(const char *data, uint8_t *out, size_t *out_len) {
    if (!data || !out || !out_len) return -1;

    size_t len = strlen(data);
    if (len == 0 || len % 4 != 0) return -1;

    size_t decoded_len = len / 4 * 3;
    if (data[len - 1] == '=') decoded_len--;
    if (data[len - 2] == '=') decoded_len--;

    static const int8_t decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        int8_t a = data[i] == '=' ? 0 : decode_table[(unsigned char)data[i]]; i++;
        int8_t b = data[i] == '=' ? 0 : decode_table[(unsigned char)data[i]]; i++;
        int8_t c = data[i] == '=' ? 0 : decode_table[(unsigned char)data[i]]; i++;
        int8_t d = data[i] == '=' ? 0 : decode_table[(unsigned char)data[i]]; i++;

        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;

        uint32_t triple = (a << 18) + (b << 12) + (c << 6) + d;

        if (j < decoded_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < decoded_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < decoded_len) out[j++] = triple & 0xFF;
    }

    *out_len = decoded_len;
    return 0;
}

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * Generate base key string for GEK storage
 * Format: "identity:geks"
 * The dht_chunked layer handles hashing internally
 */
static int make_base_key(const char *identity, char *key_out, size_t key_out_size) {
    if (!identity || !key_out) {
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:geks", identity);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/**
 * Serialize GEK entries to JSON string
 */
static char* serialize_to_json(const char *identity, const dht_gek_entry_t *entries, size_t entry_count, uint64_t timestamp) {
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for JSON serialization\n");
        return NULL;
    }

    // Create JSON object
    json_object *root = json_object_new_object();
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create JSON object\n");
        return NULL;
    }

    // Add fields
    json_object_object_add(root, "identity", json_object_new_string(identity));
    json_object_object_add(root, "version", json_object_new_int(DHT_GEKS_VERSION));
    json_object_object_add(root, "timestamp", json_object_new_int64((int64_t)timestamp));

    // Create groups object (group_uuid -> array of keys)
    json_object *groups_obj = json_object_new_object();
    if (!groups_obj) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create groups object\n");
        json_object_put(root);
        return NULL;
    }

    // Organize entries by group_uuid
    for (size_t i = 0; i < entry_count; i++) {
        const dht_gek_entry_t *entry = &entries[i];

        // Get or create array for this group
        json_object *keys_array = NULL;
        if (!json_object_object_get_ex(groups_obj, entry->group_uuid, &keys_array)) {
            keys_array = json_object_new_array();
            json_object_object_add(groups_obj, entry->group_uuid, keys_array);
        }

        // Create key entry
        json_object *key_obj = json_object_new_object();
        json_object_object_add(key_obj, "v", json_object_new_int64((int64_t)entry->gek_version));

        // Base64 encode the GEK
        char *key_b64 = base64_encode(entry->gek, DHT_GEKS_KEY_SIZE);
        if (key_b64) {
            json_object_object_add(key_obj, "key", json_object_new_string(key_b64));
            free(key_b64);
        }

        json_object_object_add(key_obj, "created", json_object_new_int64((int64_t)entry->created_at));
        json_object_object_add(key_obj, "expires", json_object_new_int64((int64_t)entry->expires_at));

        json_object_array_add(keys_array, key_obj);
    }

    json_object_object_add(root, "groups", groups_obj);

    // Convert to string
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    QGP_LOG_DEBUG(LOG_TAG, "Serialized JSON (first 200 chars): %.200s\n", json_str);
    char *result = strdup(json_str);

    json_object_put(root);  // This frees the entire object tree

    return result;
}

/**
 * Deserialize JSON string to GEK entries
 */
static int deserialize_from_json(const char *json_str, dht_gek_entry_t **entries_out, size_t *count_out, uint64_t *timestamp_out) {
    if (!json_str || !entries_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for JSON deserialization\n");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Deserializing JSON (first 200 chars): %.200s\n", json_str);

    // Parse JSON
    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON\n");
        return -1;
    }

    // Extract timestamp (optional)
    if (timestamp_out) {
        json_object *timestamp_obj = NULL;
        if (json_object_object_get_ex(root, "timestamp", &timestamp_obj)) {
            *timestamp_out = (uint64_t)json_object_get_int64(timestamp_obj);
        } else {
            *timestamp_out = 0;
        }
    }

    // Extract groups object
    json_object *groups_obj = NULL;
    if (!json_object_object_get_ex(root, "groups", &groups_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "No groups object in JSON\n");
        json_object_put(root);
        *entries_out = NULL;
        *count_out = 0;
        return 0;  // Empty is valid
    }

    // Count total entries across all groups
    size_t total_entries = 0;
    json_object_object_foreach(groups_obj, group_uuid, keys_array) {
        (void)group_uuid;
        if (json_object_is_type(keys_array, json_type_array)) {
            total_entries += json_object_array_length(keys_array);
        }
    }

    if (total_entries == 0) {
        *entries_out = NULL;
        *count_out = 0;
        json_object_put(root);
        return 0;
    }

    // Sanity limit
    if (total_entries > DHT_GEKS_MAX_GROUPS * DHT_GEKS_MAX_VERSIONS_PER_GROUP) {
        QGP_LOG_ERROR(LOG_TAG, "Too many GEK entries: %zu\n", total_entries);
        json_object_put(root);
        return -1;
    }

    // Allocate entries array
    dht_gek_entry_t *entries = calloc(total_entries, sizeof(dht_gek_entry_t));
    if (!entries) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate entries array\n");
        json_object_put(root);
        return -1;
    }

    // Parse entries
    size_t idx = 0;
    json_object_object_foreach(groups_obj, group_uuid2, keys_array2) {
        if (!json_object_is_type(keys_array2, json_type_array)) {
            continue;
        }

        size_t arr_len = json_object_array_length(keys_array2);
        for (size_t i = 0; i < arr_len && idx < total_entries; i++) {
            json_object *key_obj = json_object_array_get_idx(keys_array2, i);
            if (!key_obj) continue;

            dht_gek_entry_t *entry = &entries[idx];

            // Copy group UUID
            strncpy(entry->group_uuid, group_uuid2, 36);
            entry->group_uuid[36] = '\0';

            // Get version
            json_object *v_obj = NULL;
            if (json_object_object_get_ex(key_obj, "v", &v_obj)) {
                entry->gek_version = (uint32_t)json_object_get_int64(v_obj);
            }

            // Get key (base64 encoded)
            json_object *key_str_obj = NULL;
            if (json_object_object_get_ex(key_obj, "key", &key_str_obj)) {
                const char *key_b64 = json_object_get_string(key_str_obj);
                if (key_b64) {
                    size_t decoded_len = 0;
                    if (base64_decode(key_b64, entry->gek, &decoded_len) != 0 || decoded_len != DHT_GEKS_KEY_SIZE) {
                        QGP_LOG_WARN(LOG_TAG, "Invalid base64 key at index %zu\n", idx);
                        continue;
                    }
                }
            }

            // Get timestamps
            json_object *created_obj = NULL;
            if (json_object_object_get_ex(key_obj, "created", &created_obj)) {
                entry->created_at = (uint64_t)json_object_get_int64(created_obj);
            }

            json_object *expires_obj = NULL;
            if (json_object_object_get_ex(key_obj, "expires", &expires_obj)) {
                entry->expires_at = (uint64_t)json_object_get_int64(expires_obj);
            }

            idx++;
        }
    }

    *entries_out = entries;
    *count_out = idx;
    json_object_put(root);

    QGP_LOG_INFO(LOG_TAG, "Deserialized %zu GEK entries\n", idx);
    return 0;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * Initialize DHT GEK sync subsystem
 */
int dht_geks_init(void) {
    QGP_LOG_INFO(LOG_TAG, "GEK sync subsystem initialized\n");
    return 0;
}

/**
 * Cleanup DHT GEK sync subsystem
 */
void dht_geks_cleanup(void) {
    // Currently nothing to cleanup
    QGP_LOG_INFO(LOG_TAG, "GEK sync subsystem cleaned up\n");
}

/**
 * Publish GEKs to DHT
 */
int dht_geks_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const dht_gek_entry_t *entries,
    size_t entry_count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds)
{
    if (!dht_ctx || !identity || !kyber_pubkey || !kyber_privkey || !dilithium_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for publish\n");
        return -1;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = DHT_GEKS_DEFAULT_TTL;
    }

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + ttl_seconds;

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu GEK entries for '%.16s...' (TTL=%u)\n",
           entry_count, identity, ttl_seconds);

    // Step 1: Serialize to JSON
    char *json_str = serialize_to_json(identity, entries, entry_count, timestamp);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize to JSON\n");
        return -1;
    }

    size_t json_len = strlen(json_str);
    QGP_LOG_INFO(LOG_TAG, "JSON length: %zu bytes\n", json_len);

    // Step 2: Sign JSON with Dilithium5
    uint8_t signature[DHT_GEKS_DILITHIUM_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (qgp_dsa87_sign(signature, &sig_len, (const uint8_t*)json_str, json_len, dilithium_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign JSON\n");
        free(json_str);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Signature length: %zu bytes\n", sig_len);

    // Step 3: Encrypt JSON with Kyber1024 (self-encryption)
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context\n");
        free(json_str);
        return -1;
    }

    uint8_t *encrypted_data = NULL;
    size_t encrypted_len = 0;

    // Self-encryption: encrypt with own public key, sign with own private key
    uint64_t sync_timestamp = (uint64_t)time(NULL);
    dna_error_t enc_result = dna_encrypt_message_raw(
        dna_ctx,
        (const uint8_t*)json_str,
        json_len,
        kyber_pubkey,           // recipient_enc_pubkey (self)
        dilithium_pubkey,       // sender_sign_pubkey (self)
        dilithium_privkey,      // sender_sign_privkey (self)
        sync_timestamp,         // v0.08: sync timestamp
        &encrypted_data,        // output ciphertext (allocated by function)
        &encrypted_len          // output length
    );

    dna_context_free(dna_ctx);
    free(json_str);

    if (enc_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt JSON: %s\n", dna_error_string(enc_result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Encrypted length: %zu bytes\n", encrypted_len);

    // Step 4: Build binary blob
    // Format: [magic][version][timestamp][expiry][json_len][encrypted_json][sig_len][signature]
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blob\n");
        free(encrypted_data);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = htonl(DHT_GEKS_MAGIC);
    memcpy(blob + offset, &magic, 4);
    offset += 4;

    // Version
    blob[offset++] = DHT_GEKS_VERSION;

    // Timestamp (network byte order)
    uint64_t ts_net = htonll(timestamp);
    memcpy(blob + offset, &ts_net, 8);
    offset += 8;

    // Expiry (network byte order)
    uint64_t exp_net = htonll(expiry);
    memcpy(blob + offset, &exp_net, 8);
    offset += 8;

    // Encrypted JSON length
    uint32_t json_len_net = htonl((uint32_t)encrypted_len);
    memcpy(blob + offset, &json_len_net, 4);
    offset += 4;

    // Encrypted JSON data
    memcpy(blob + offset, encrypted_data, encrypted_len);
    offset += encrypted_len;

    // Signature length
    uint32_t sig_len_net = htonl((uint32_t)sig_len);
    memcpy(blob + offset, &sig_len_net, 4);
    offset += 4;

    // Signature
    memcpy(blob + offset, signature, sig_len);

    free(encrypted_data);

    QGP_LOG_INFO(LOG_TAG, "Total blob size: %zu bytes\n", blob_size);

    // Step 5: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        free(blob);
        return -1;
    }

    // Step 6: Store in DHT using chunked layer (handles compression, chunking, signing)
    int result = dht_chunked_publish(dht_ctx, base_key, blob, blob_size, DHT_CHUNK_TTL_365DAY);
    free(blob);

    if (result != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT: %s\n", dht_chunked_strerror(result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published %zu GEK entries to DHT\n", entry_count);
    return 0;
}

/**
 * Fetch GEKs from DHT
 */
int dht_geks_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    dht_gek_entry_t **entries_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey)
{
    if (!dht_ctx || !identity || !entries_out || !count_out || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching GEKs for '%.16s...'\n", identity);

    // Step 1: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    // Step 2: Fetch from DHT using chunked layer (handles decompression, reassembly)
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result != DHT_CHUNK_OK || !blob) {
        QGP_LOG_INFO(LOG_TAG, "GEKs not found in DHT: %s\n", dht_chunked_strerror(result));
        return -2;  // Not found
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved blob: %zu bytes\n", blob_size);

    // Step 3: Parse blob header
    if (blob_size < 4 + 1 + 8 + 8 + 4 + 4) {
        QGP_LOG_ERROR(LOG_TAG, "Blob too small\n");
        free(blob);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic;
    memcpy(&magic, blob + offset, 4);
    magic = ntohl(magic);
    offset += 4;

    if (magic != DHT_GEKS_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X (expected 0x%08X)\n", magic, DHT_GEKS_MAGIC);
        free(blob);
        return -1;
    }

    // Version
    uint8_t version = blob[offset++];
    if (version != DHT_GEKS_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %d\n", version);
        free(blob);
        return -1;
    }

    // Timestamp
    uint64_t timestamp;
    memcpy(&timestamp, blob + offset, 8);
    timestamp = ntohll(timestamp);
    offset += 8;

    // Expiry
    uint64_t expiry;
    memcpy(&expiry, blob + offset, 8);
    expiry = ntohll(expiry);
    offset += 8;

    // Check expiry
    uint64_t now = (uint64_t)time(NULL);
    if (expiry < now) {
        QGP_LOG_INFO(LOG_TAG, "GEKs expired (expiry=%lu, now=%lu)\n", (unsigned long)expiry, (unsigned long)now);
        free(blob);
        return -2;  // Expired
    }

    // Encrypted JSON length
    uint32_t encrypted_len;
    memcpy(&encrypted_len, blob + offset, 4);
    encrypted_len = ntohl(encrypted_len);
    offset += 4;

    if (offset + encrypted_len + 4 > blob_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted length\n");
        free(blob);
        return -1;
    }

    uint8_t *encrypted_data = blob + offset;
    offset += encrypted_len;

    // Signature length
    uint32_t sig_len;
    memcpy(&sig_len, blob + offset, 4);
    sig_len = ntohl(sig_len);
    offset += 4;

    if (offset + sig_len != blob_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature length\n");
        free(blob);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Parsed header: timestamp=%lu, expiry=%lu, encrypted_len=%u, sig_len=%u\n",
           (unsigned long)timestamp, (unsigned long)expiry, encrypted_len, sig_len);

    // Step 4: Decrypt JSON
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context\n");
        free(blob);
        return -1;
    }

    uint8_t *decrypted_data = NULL;
    size_t decrypted_len = 0;
    uint8_t *sender_pubkey_out = NULL;
    size_t sender_pubkey_len_out = 0;
    uint8_t *signature_out = NULL;
    size_t signature_out_len = 0;
    uint64_t sender_timestamp = 0;

    // Decrypt with own private key (self-decryption)
    dna_error_t dec_result = dna_decrypt_message_raw(
        dna_ctx,
        encrypted_data,
        encrypted_len,
        kyber_privkey,              // recipient_enc_privkey (self)
        &decrypted_data,            // output plaintext (allocated by function)
        &decrypted_len,             // output length
        &sender_pubkey_out,         // v0.07: sender's fingerprint (64 bytes)
        &sender_pubkey_len_out,     // sender fingerprint length
        &signature_out,             // signature bytes (from v0.07 message)
        &signature_out_len,         // signature length
        &sender_timestamp           // v0.08: sender's timestamp
    );

    dna_context_free(dna_ctx);

    if (dec_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt JSON: %s\n", dna_error_string(dec_result));
        free(blob);
        if (signature_out) free(signature_out);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Decrypted JSON: %zu bytes\n", decrypted_len);

    // Null-terminate for JSON parsing
    char *json_str = malloc(decrypted_len + 1);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate JSON buffer\n");
        free(decrypted_data);
        free(sender_pubkey_out);
        if (signature_out) free(signature_out);
        free(blob);
        return -1;
    }
    memcpy(json_str, decrypted_data, decrypted_len);
    json_str[decrypted_len] = '\0';

    // Step 5: Verify sender's public key matches expected (self-verification)
    if (dilithium_pubkey && sender_pubkey_len_out == DHT_GEKS_DILITHIUM_PUBKEY_SIZE) {
        if (memcmp(sender_pubkey_out, dilithium_pubkey, DHT_GEKS_DILITHIUM_PUBKEY_SIZE) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Sender public key mismatch (not self-encrypted)\n");
            free(json_str);
            free(decrypted_data);
            free(sender_pubkey_out);
            if (signature_out) free(signature_out);
            free(blob);
            return -1;
        }
        QGP_LOG_INFO(LOG_TAG, "Sender public key verified (self-encrypted)\n");
    }

    free(decrypted_data);
    free(sender_pubkey_out);
    if (signature_out) free(signature_out);
    free(blob);

    // Step 6: Parse JSON
    uint64_t parsed_timestamp = 0;
    if (deserialize_from_json(json_str, entries_out, count_out, &parsed_timestamp) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON\n");
        free(json_str);
        return -1;
    }

    free(json_str);

    QGP_LOG_INFO(LOG_TAG, "Successfully fetched %zu GEK entries\n", *count_out);
    return 0;
}

/**
 * Free GEK entries array
 */
void dht_geks_free_entries(dht_gek_entry_t *entries, size_t count) {
    (void)count;  // No per-entry cleanup needed
    if (entries) {
        free(entries);
    }
}

/**
 * Free GEK cache structure
 */
void dht_geks_free_cache(dht_geks_cache_t *cache) {
    if (!cache) return;

    if (cache->entries) {
        dht_geks_free_entries(cache->entries, cache->entry_count);
    }
    free(cache);
}

/**
 * Check if GEKs exist in DHT
 */
bool dht_geks_exists(dht_context_t *dht_ctx, const char *identity) {
    if (!dht_ctx || !identity) {
        return false;
    }

    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        return false;
    }

    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result == DHT_CHUNK_OK && blob) {
        free(blob);
        return true;
    }

    return false;
}

/**
 * Get GEKs timestamp from DHT
 */
int dht_geks_get_timestamp(dht_context_t *dht_ctx, const char *identity, uint64_t *timestamp_out) {
    if (!dht_ctx || !identity || !timestamp_out) {
        return -1;
    }

    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result != DHT_CHUNK_OK || !blob) {
        return -2;  // Not found
    }

    // Parse just the timestamp from header
    if (blob_size < 4 + 1 + 8) {
        free(blob);
        return -1;
    }

    size_t offset = 4 + 1;  // Skip magic and version
    uint64_t timestamp;
    memcpy(&timestamp, blob + offset, 8);
    timestamp = ntohll(timestamp);

    *timestamp_out = timestamp;

    free(blob);
    return 0;
}
