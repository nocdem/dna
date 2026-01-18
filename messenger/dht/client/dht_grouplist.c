/**
 * DHT Group List Synchronization Implementation
 * Per-identity encrypted group lists with DHT storage
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 */

#include "dht_grouplist.h"
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

#define LOG_TAG "DHT_GROUPS"

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

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * Generate base key string for group list storage
 * Format: "identity:grouplist"
 * The dht_chunked layer handles hashing internally
 */
static int make_base_key(const char *identity, char *key_out, size_t key_out_size) {
    if (!identity || !key_out) {
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:grouplist", identity);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/**
 * Serialize group list to JSON string
 */
static char* serialize_to_json(const char *identity, const char **groups, size_t group_count, uint64_t timestamp) {
    if (!identity || (!groups && group_count > 0)) {
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
    json_object_object_add(root, "version", json_object_new_int(DHT_GROUPLIST_VERSION));
    json_object_object_add(root, "timestamp", json_object_new_int64(timestamp));

    // Add groups array
    json_object *groups_array = json_object_new_array();
    if (!groups_array) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create groups array\n");
        json_object_put(root);
        return NULL;
    }

    for (size_t i = 0; i < group_count; i++) {
        QGP_LOG_DEBUG(LOG_TAG, "Serializing group[%zu]: '%s'\n", i, groups[i] ? groups[i] : "(null)");
        json_object_array_add(groups_array, json_object_new_string(groups[i]));
    }

    json_object_object_add(root, "groups", groups_array);

    // Convert to string
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    QGP_LOG_DEBUG(LOG_TAG, "Serialized JSON (first 200 chars): %.200s\n", json_str);
    char *result = strdup(json_str);

    json_object_put(root);  // This frees the entire object tree

    return result;
}

/**
 * Deserialize JSON string to group list
 */
static int deserialize_from_json(const char *json_str, char ***groups_out, size_t *count_out, uint64_t *timestamp_out) {
    if (!json_str || !groups_out || !count_out) {
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
            *timestamp_out = json_object_get_int64(timestamp_obj);
        } else {
            *timestamp_out = 0;
        }
    }

    // Extract groups array
    json_object *groups_array = NULL;
    if (!json_object_object_get_ex(root, "groups", &groups_array)) {
        QGP_LOG_ERROR(LOG_TAG, "No groups array in JSON\n");
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(groups_array);
    *count_out = count;

    if (count == 0) {
        *groups_out = NULL;
        json_object_put(root);
        return 0;
    }

    // Allocate groups array
    char **groups = malloc(count * sizeof(char*));
    if (!groups) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate groups array\n");
        json_object_put(root);
        return -1;
    }

    // Extract group strings
    for (size_t i = 0; i < count; i++) {
        json_object *group_obj = json_object_array_get_idx(groups_array, i);
        const char *group_str = json_object_get_string(group_obj);
        QGP_LOG_DEBUG(LOG_TAG, "JSON group[%zu]: '%s'\n", i, group_str ? group_str : "(null)");
        groups[i] = strdup(group_str);
        if (!groups[i]) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                free(groups[j]);
            }
            free(groups);
            json_object_put(root);
            return -1;
        }
    }

    *groups_out = groups;
    json_object_put(root);
    return 0;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * Initialize DHT group list subsystem
 */
int dht_grouplist_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Group list subsystem initialized\n");
    return 0;
}

/**
 * Cleanup DHT group list subsystem
 */
void dht_grouplist_cleanup(void) {
    // Currently nothing to cleanup
    QGP_LOG_INFO(LOG_TAG, "Group list subsystem cleaned up\n");
}

/**
 * Publish group list to DHT
 */
int dht_grouplist_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const char **group_uuids,
    size_t group_count,
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
        ttl_seconds = DHT_GROUPLIST_DEFAULT_TTL;
    }

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + ttl_seconds;

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu groups for '%.16s...' (TTL=%u)\n",
           group_count, identity, ttl_seconds);

    // Step 1: Serialize to JSON
    char *json_str = serialize_to_json(identity, group_uuids, group_count, timestamp);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize to JSON\n");
        return -1;
    }

    size_t json_len = strlen(json_str);
    QGP_LOG_INFO(LOG_TAG, "JSON length: %zu bytes\n", json_len);

    // Step 2: Sign JSON with Dilithium5
    uint8_t signature[DHT_GROUPLIST_DILITHIUM_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (qgp_dsa87_sign(signature, &sig_len, (const uint8_t*)json_str, json_len, dilithium_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign JSON\n");
        free(json_str);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Signature length: %zu bytes\n", sig_len);

    // Step 3: Encrypt JSON with Kyber1024 (self-encryption)
    // For self-encryption: user is both sender (signs) and recipient (encrypts for self)
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
        sync_timestamp,         // v0.08: group list sync timestamp
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
    uint32_t magic = htonl(DHT_GROUPLIST_MAGIC);
    memcpy(blob + offset, &magic, 4);
    offset += 4;

    // Version
    blob[offset++] = DHT_GROUPLIST_VERSION;

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

    QGP_LOG_INFO(LOG_TAG, "Successfully published group list to DHT\n");
    return 0;
}

/**
 * Fetch group list from DHT
 */
int dht_grouplist_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    char ***groups_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey)
{
    if (!dht_ctx || !identity || !groups_out || !count_out || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching group list for '%.16s...'\n", identity);

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
        QGP_LOG_INFO(LOG_TAG, "Group list not found in DHT: %s\n", dht_chunked_strerror(result));
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

    if (magic != DHT_GROUPLIST_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X (expected 0x%08X)\n", magic, DHT_GROUPLIST_MAGIC);
        free(blob);
        return -1;
    }

    // Version
    uint8_t version = blob[offset++];
    if (version != DHT_GROUPLIST_VERSION) {
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
        QGP_LOG_INFO(LOG_TAG, "Group list expired (expiry=%lu, now=%lu)\n", (unsigned long)expiry, (unsigned long)now);
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

    // Note: signature at (blob + offset) is validated during decryption

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

    // Step 5: Verify that sender's public key matches expected (self-verification for self-encryption)
    // The DNA encryption already verified the signature during decryption
    // But we can additionally verify it matches the expected dilithium_pubkey if provided
    if (dilithium_pubkey && sender_pubkey_len_out == DHT_GROUPLIST_DILITHIUM_PUBKEY_SIZE) {
        if (memcmp(sender_pubkey_out, dilithium_pubkey, DHT_GROUPLIST_DILITHIUM_PUBKEY_SIZE) != 0) {
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
    if (deserialize_from_json(json_str, groups_out, count_out, &parsed_timestamp) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON\n");
        free(json_str);
        return -1;
    }

    free(json_str);

    QGP_LOG_INFO(LOG_TAG, "Successfully fetched %zu groups\n", *count_out);

    return 0;
}

/**
 * Free groups array
 */
void dht_grouplist_free_groups(char **groups, size_t count) {
    if (!groups) return;

    for (size_t i = 0; i < count; i++) {
        free(groups[i]);
    }
    free(groups);
}

/**
 * Free group list structure
 */
void dht_grouplist_free(dht_grouplist_t *list) {
    if (!list) return;

    if (list->groups) {
        dht_grouplist_free_groups(list->groups, list->group_count);
    }
    free(list);
}

/**
 * Check if group list exists in DHT
 */
bool dht_grouplist_exists(dht_context_t *dht_ctx, const char *identity) {
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
 * Get group list timestamp from DHT
 */
int dht_grouplist_get_timestamp(dht_context_t *dht_ctx, const char *identity, uint64_t *timestamp_out) {
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
