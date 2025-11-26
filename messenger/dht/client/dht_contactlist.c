/**
 * DHT Contact List Synchronization Implementation
 * Per-identity encrypted contact lists with DHT storage
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 */

#include "dht_contactlist.h"
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

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
// Network byte order functions for Windows
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#else
#include <arpa/inet.h>
// Define htonll/ntohll for Linux (may not be available on all systems)
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif
#endif

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * Generate base key string for contact list storage
 * Format: "identity:contactlist"
 * The dht_chunked layer handles hashing internally
 */
static int make_base_key(const char *identity, char *key_out, size_t key_out_size) {
    if (!identity || !key_out) {
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:contactlist", identity);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        fprintf(stderr, "[DHT_CONTACTLIST] Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/**
 * Serialize contact list to JSON string
 */
static char* serialize_to_json(const char *identity, const char **contacts, size_t contact_count, uint64_t timestamp) {
    if (!identity || (!contacts && contact_count > 0)) {
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid parameters for JSON serialization\n");
        return NULL;
    }

    // Create JSON object
    json_object *root = json_object_new_object();
    if (!root) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to create JSON object\n");
        return NULL;
    }

    // Add fields
    json_object_object_add(root, "identity", json_object_new_string(identity));
    json_object_object_add(root, "version", json_object_new_int(DHT_CONTACTLIST_VERSION));
    json_object_object_add(root, "timestamp", json_object_new_int64(timestamp));

    // Add contacts array
    json_object *contacts_array = json_object_new_array();
    if (!contacts_array) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to create contacts array\n");
        json_object_put(root);
        return NULL;
    }

    for (size_t i = 0; i < contact_count; i++) {
        json_object_array_add(contacts_array, json_object_new_string(contacts[i]));
    }

    json_object_object_add(root, "contacts", contacts_array);

    // Convert to string
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);

    json_object_put(root);  // This frees the entire object tree

    return result;
}

/**
 * Deserialize JSON string to contact list
 */
static int deserialize_from_json(const char *json_str, char ***contacts_out, size_t *count_out, uint64_t *timestamp_out) {
    if (!json_str || !contacts_out || !count_out) {
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid parameters for JSON deserialization\n");
        return -1;
    }

    // Parse JSON
    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to parse JSON\n");
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

    // Extract contacts array
    json_object *contacts_array = NULL;
    if (!json_object_object_get_ex(root, "contacts", &contacts_array)) {
        fprintf(stderr, "[DHT_CONTACTLIST] No contacts array in JSON\n");
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(contacts_array);
    *count_out = count;

    if (count == 0) {
        *contacts_out = NULL;
        json_object_put(root);
        return 0;
    }

    // Allocate contacts array
    char **contacts = malloc(count * sizeof(char*));
    if (!contacts) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to allocate contacts array\n");
        json_object_put(root);
        return -1;
    }

    // Extract contact strings
    for (size_t i = 0; i < count; i++) {
        json_object *contact_obj = json_object_array_get_idx(contacts_array, i);
        const char *contact_str = json_object_get_string(contact_obj);
        contacts[i] = strdup(contact_str);
        if (!contacts[i]) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                free(contacts[j]);
            }
            free(contacts);
            json_object_put(root);
            return -1;
        }
    }

    *contacts_out = contacts;
    json_object_put(root);
    return 0;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * Initialize DHT contact list subsystem
 */
int dht_contactlist_init(void) {
    // Currently nothing to initialize
    // Future: could load caching state, etc.
    printf("[DHT_CONTACTLIST] Initialized\n");
    return 0;
}

/**
 * Cleanup DHT contact list subsystem
 */
void dht_contactlist_cleanup(void) {
    // Currently nothing to cleanup
    printf("[DHT_CONTACTLIST] Cleaned up\n");
}

/**
 * Publish contact list to DHT
 */
int dht_contactlist_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const char **contacts,
    size_t contact_count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds)
{
    if (!dht_ctx || !identity || !kyber_pubkey || !kyber_privkey || !dilithium_pubkey || !dilithium_privkey) {
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid parameters for publish\n");
        return -1;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = DHT_CONTACTLIST_DEFAULT_TTL;
    }

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + ttl_seconds;

    printf("[DHT_CONTACTLIST] Publishing %zu contacts for '%s' (TTL=%u)\n",
           contact_count, identity, ttl_seconds);

    // Step 1: Serialize to JSON
    char *json_str = serialize_to_json(identity, contacts, contact_count, timestamp);
    if (!json_str) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to serialize to JSON\n");
        return -1;
    }

    size_t json_len = strlen(json_str);
    printf("[DHT_CONTACTLIST] JSON length: %zu bytes\n", json_len);

    // Step 2: Sign JSON with Dilithium5
    uint8_t signature[DHT_CONTACTLIST_DILITHIUM_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (qgp_dsa87_sign(signature, &sig_len, (const uint8_t*)json_str, json_len, dilithium_privkey) != 0) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to sign JSON\n");
        free(json_str);
        return -1;
    }

    printf("[DHT_CONTACTLIST] Signature length: %zu bytes\n", sig_len);

    // Step 3: Encrypt JSON with Kyber1024 (self-encryption)
    // For self-encryption: user is both sender (signs) and recipient (encrypts for self)
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to create DNA context\n");
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
        sync_timestamp,         // v0.08: contact list sync timestamp
        &encrypted_data,        // output ciphertext (allocated by function)
        &encrypted_len          // output length
    );

    dna_context_free(dna_ctx);
    free(json_str);

    if (enc_result != DNA_OK) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to encrypt JSON: %s\n", dna_error_string(enc_result));
        return -1;
    }

    printf("[DHT_CONTACTLIST] Encrypted length: %zu bytes\n", encrypted_len);

    // Step 4: Build binary blob
    // Format: [magic][version][timestamp][expiry][json_len][encrypted_json][sig_len][signature]
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to allocate blob\n");
        free(encrypted_data);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = htonl(DHT_CONTACTLIST_MAGIC);
    memcpy(blob + offset, &magic, 4);
    offset += 4;

    // Version
    blob[offset++] = DHT_CONTACTLIST_VERSION;

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
    offset += sig_len;

    free(encrypted_data);

    printf("[DHT_CONTACTLIST] Total blob size: %zu bytes\n", blob_size);

    // Step 5: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to generate base key\n");
        free(blob);
        return -1;
    }

    // Step 6: Store in DHT using chunked layer (handles compression, chunking, signing)
    int result = dht_chunked_publish(dht_ctx, base_key, blob, blob_size, DHT_CHUNK_TTL_365DAY);
    free(blob);

    if (result != DHT_CHUNK_OK) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to store in DHT: %s\n", dht_chunked_strerror(result));
        return -1;
    }

    printf("[DHT_CONTACTLIST] Successfully published contact list to DHT\n");
    return 0;
}

/**
 * Fetch contact list from DHT
 */
int dht_contactlist_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    char ***contacts_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey)
{
    if (!dht_ctx || !identity || !contacts_out || !count_out || !kyber_privkey || !dilithium_pubkey) {
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid parameters for fetch\n");
        return -1;
    }

    printf("[DHT_CONTACTLIST] Fetching contact list for '%s'\n", identity);

    // Step 1: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to generate base key\n");
        return -1;
    }

    // Step 2: Fetch from DHT using chunked layer (handles decompression, reassembly)
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result != DHT_CHUNK_OK || !blob) {
        printf("[DHT_CONTACTLIST] Contact list not found in DHT: %s\n", dht_chunked_strerror(result));
        return -2;  // Not found
    }

    printf("[DHT_CONTACTLIST] Retrieved blob: %zu bytes\n", blob_size);

    // Step 3: Parse blob header
    if (blob_size < 4 + 1 + 8 + 8 + 4 + 4) {
        fprintf(stderr, "[DHT_CONTACTLIST] Blob too small\n");
        free(blob);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic;
    memcpy(&magic, blob + offset, 4);
    magic = ntohl(magic);
    offset += 4;

    if (magic != DHT_CONTACTLIST_MAGIC) {
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid magic: 0x%08X\n", magic);
        free(blob);
        return -1;
    }

    // Version
    uint8_t version = blob[offset++];
    if (version != DHT_CONTACTLIST_VERSION) {
        fprintf(stderr, "[DHT_CONTACTLIST] Unsupported version: %d\n", version);
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
        printf("[DHT_CONTACTLIST] Contact list expired (expiry=%lu, now=%lu)\n", expiry, now);
        free(blob);
        return -2;  // Expired
    }

    // Encrypted JSON length
    uint32_t encrypted_len;
    memcpy(&encrypted_len, blob + offset, 4);
    encrypted_len = ntohl(encrypted_len);
    offset += 4;

    if (offset + encrypted_len + 4 > blob_size) {
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid encrypted length\n");
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
        fprintf(stderr, "[DHT_CONTACTLIST] Invalid signature length\n");
        free(blob);
        return -1;
    }

    uint8_t *signature = blob + offset;

    printf("[DHT_CONTACTLIST] Parsed header: timestamp=%lu, expiry=%lu, encrypted_len=%u, sig_len=%u\n",
           timestamp, expiry, encrypted_len, sig_len);

    // Step 4: Decrypt JSON
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to create DNA context\n");
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
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to decrypt JSON: %s\n", dna_error_string(dec_result));
        free(blob);
        if (signature_out) free(signature_out);
        return -1;
    }

    printf("[DHT_CONTACTLIST] Decrypted JSON: %zu bytes\n", decrypted_len);

    // Null-terminate for JSON parsing
    char *json_str = malloc(decrypted_len + 1);
    if (!json_str) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to allocate JSON buffer\n");
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
    if (dilithium_pubkey && sender_pubkey_len_out == DHT_CONTACTLIST_DILITHIUM_PUBKEY_SIZE) {
        if (memcmp(sender_pubkey_out, dilithium_pubkey, DHT_CONTACTLIST_DILITHIUM_PUBKEY_SIZE) != 0) {
            fprintf(stderr, "[DHT_CONTACTLIST] Sender public key mismatch (not self-encrypted)\n");
            free(json_str);
            free(decrypted_data);
            free(sender_pubkey_out);
            if (signature_out) free(signature_out);
            free(blob);
            return -1;
        }
        printf("[DHT_CONTACTLIST] Sender public key verified (self-encrypted)\n");
    }

    free(decrypted_data);
    free(sender_pubkey_out);
    if (signature_out) free(signature_out);
    free(blob);

    // Step 6: Parse JSON
    uint64_t parsed_timestamp = 0;
    if (deserialize_from_json(json_str, contacts_out, count_out, &parsed_timestamp) != 0) {
        fprintf(stderr, "[DHT_CONTACTLIST] Failed to parse JSON\n");
        free(json_str);
        return -1;
    }

    free(json_str);

    printf("[DHT_CONTACTLIST] Successfully fetched %zu contacts\n", *count_out);
    return 0;
}

/**
 * Clear contact list from DHT (best-effort, not guaranteed)
 *
 * DEPRECATED: With chunked storage, this function publishes empty chunks to overwrite.
 * Use dht_contactlist_publish() with an empty contact array instead, which will
 * replace the old contact list with an empty one.
 *
 * Note: DHT doesn't support true deletion. Chunks will fully expire via TTL.
 */
int dht_contactlist_clear(dht_context_t *dht_ctx, const char *identity) {
    if (!dht_ctx || !identity) {
        return -1;
    }

    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    // Note: dht_chunked_delete overwrites with empty chunks
    // Chunks will fully expire via TTL
    dht_chunked_delete(dht_ctx, base_key, 0);

    printf("[DHT_CONTACTLIST] Attempted to clear contact list for '%s' (best-effort, deprecated)\n", identity);
    printf("[DHT_CONTACTLIST] Recommend using dht_contactlist_publish() with empty array for reliable clearing\n");
    return 0;
}

/**
 * Free contacts array
 */
void dht_contactlist_free_contacts(char **contacts, size_t count) {
    if (!contacts) return;

    for (size_t i = 0; i < count; i++) {
        free(contacts[i]);
    }
    free(contacts);
}

/**
 * Free contact list structure
 */
void dht_contactlist_free(dht_contactlist_t *list) {
    if (!list) return;

    if (list->contacts) {
        dht_contactlist_free_contacts(list->contacts, list->contact_count);
    }
    free(list);
}

/**
 * Check if contact list exists in DHT
 */
bool dht_contactlist_exists(dht_context_t *dht_ctx, const char *identity) {
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
 * Get contact list timestamp from DHT
 */
int dht_contactlist_get_timestamp(dht_context_t *dht_ctx, const char *identity, uint64_t *timestamp_out) {
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
