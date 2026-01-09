/**
 * DHT Address Book Synchronization Implementation
 * Per-identity encrypted address books with DHT storage
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 */

#include "dht_addressbook.h"
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

#define LOG_TAG "DHT_ADDRBOOK"

#ifdef _WIN32
#include <winsock2.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#endif

// Network byte order functions
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
 * Generate base key string for address book storage
 * Format: "identity:addressbook"
 */
static int make_base_key(const char *identity, char *key_out, size_t key_out_size) {
    if (!identity || !key_out) {
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:addressbook", identity);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/**
 * Serialize address book to JSON string
 */
static char* serialize_to_json(const char *identity, const dht_addressbook_entry_t *entries, size_t entry_count, uint64_t timestamp) {
    if (!identity || (!entries && entry_count > 0)) {
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
    json_object_object_add(root, "version", json_object_new_int(DHT_ADDRESSBOOK_VERSION));
    json_object_object_add(root, "timestamp", json_object_new_int64((int64_t)timestamp));

    // Add addresses array
    json_object *addresses_array = json_object_new_array();
    if (!addresses_array) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create addresses array\n");
        json_object_put(root);
        return NULL;
    }

    for (size_t i = 0; i < entry_count; i++) {
        json_object *entry_obj = json_object_new_object();
        if (!entry_obj) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create entry object\n");
            json_object_put(root);
            return NULL;
        }

        json_object_object_add(entry_obj, "address", json_object_new_string(entries[i].address));
        json_object_object_add(entry_obj, "label", json_object_new_string(entries[i].label));
        json_object_object_add(entry_obj, "network", json_object_new_string(entries[i].network));
        json_object_object_add(entry_obj, "notes", json_object_new_string(entries[i].notes));
        json_object_object_add(entry_obj, "created_at", json_object_new_int64((int64_t)entries[i].created_at));
        json_object_object_add(entry_obj, "last_used", json_object_new_int64((int64_t)entries[i].last_used));
        json_object_object_add(entry_obj, "use_count", json_object_new_int((int)entries[i].use_count));

        json_object_array_add(addresses_array, entry_obj);
    }

    json_object_object_add(root, "addresses", addresses_array);

    // Convert to string
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    QGP_LOG_DEBUG(LOG_TAG, "Serialized JSON (first 200 chars): %.200s\n", json_str);
    char *result = strdup(json_str);

    json_object_put(root);  // Frees the entire object tree

    return result;
}

/**
 * Deserialize JSON string to address book entries
 */
static int deserialize_from_json(const char *json_str, dht_addressbook_entry_t **entries_out, size_t *count_out, uint64_t *timestamp_out) {
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

    // Extract addresses array
    json_object *addresses_array = NULL;
    if (!json_object_object_get_ex(root, "addresses", &addresses_array)) {
        QGP_LOG_ERROR(LOG_TAG, "No addresses array in JSON\n");
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(addresses_array);
    *count_out = count;

    if (count == 0) {
        *entries_out = NULL;
        json_object_put(root);
        return 0;
    }

    // Allocate entries array
    dht_addressbook_entry_t *entries = calloc(count, sizeof(dht_addressbook_entry_t));
    if (!entries) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate entries array\n");
        json_object_put(root);
        return -1;
    }

    // Extract entry objects
    for (size_t i = 0; i < count; i++) {
        json_object *entry_obj = json_object_array_get_idx(addresses_array, i);
        if (!entry_obj) {
            continue;
        }

        json_object *field = NULL;

        if (json_object_object_get_ex(entry_obj, "address", &field)) {
            const char *val = json_object_get_string(field);
            if (val) {
                strncpy(entries[i].address, val, sizeof(entries[i].address) - 1);
            }
        }

        if (json_object_object_get_ex(entry_obj, "label", &field)) {
            const char *val = json_object_get_string(field);
            if (val) {
                strncpy(entries[i].label, val, sizeof(entries[i].label) - 1);
            }
        }

        if (json_object_object_get_ex(entry_obj, "network", &field)) {
            const char *val = json_object_get_string(field);
            if (val) {
                strncpy(entries[i].network, val, sizeof(entries[i].network) - 1);
            }
        }

        if (json_object_object_get_ex(entry_obj, "notes", &field)) {
            const char *val = json_object_get_string(field);
            if (val) {
                strncpy(entries[i].notes, val, sizeof(entries[i].notes) - 1);
            }
        }

        if (json_object_object_get_ex(entry_obj, "created_at", &field)) {
            entries[i].created_at = (uint64_t)json_object_get_int64(field);
        }

        if (json_object_object_get_ex(entry_obj, "last_used", &field)) {
            entries[i].last_used = (uint64_t)json_object_get_int64(field);
        }

        if (json_object_object_get_ex(entry_obj, "use_count", &field)) {
            entries[i].use_count = (uint32_t)json_object_get_int(field);
        }
    }

    *entries_out = entries;
    json_object_put(root);
    return 0;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * Initialize DHT address book subsystem
 */
int dht_addressbook_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Initialized\n");
    return 0;
}

/**
 * Cleanup DHT address book subsystem
 */
void dht_addressbook_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "Cleaned up\n");
}

/**
 * Publish address book to DHT
 */
int dht_addressbook_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const dht_addressbook_entry_t *entries,
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
        ttl_seconds = DHT_ADDRESSBOOK_DEFAULT_TTL;
    }

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + ttl_seconds;

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu addresses for '%s' (TTL=%u)\n",
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
    uint8_t signature[DHT_ADDRESSBOOK_DILITHIUM_SIGNATURE_SIZE];
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

    uint64_t sync_timestamp = (uint64_t)time(NULL);
    dna_error_t enc_result = dna_encrypt_message_raw(
        dna_ctx,
        (const uint8_t*)json_str,
        json_len,
        kyber_pubkey,           // recipient_enc_pubkey (self)
        dilithium_pubkey,       // sender_sign_pubkey (self)
        dilithium_privkey,      // sender_sign_privkey (self)
        sync_timestamp,
        &encrypted_data,
        &encrypted_len
    );

    dna_context_free(dna_ctx);
    free(json_str);

    if (enc_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt JSON: %s\n", dna_error_string(enc_result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Encrypted length: %zu bytes\n", encrypted_len);

    // Step 4: Build binary blob
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blob\n");
        free(encrypted_data);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = htonl(DHT_ADDRESSBOOK_MAGIC);
    memcpy(blob + offset, &magic, 4);
    offset += 4;

    // Version
    blob[offset++] = DHT_ADDRESSBOOK_VERSION;

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

    // Step 6: Store in DHT using chunked layer
    int result = dht_chunked_publish(dht_ctx, base_key, blob, blob_size, DHT_CHUNK_TTL_365DAY);
    free(blob);

    if (result != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT: %s\n", dht_chunked_strerror(result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published address book to DHT\n");
    return 0;
}

/**
 * Fetch address book from DHT
 */
int dht_addressbook_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    dht_addressbook_entry_t **entries_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey)
{
    if (!dht_ctx || !identity || !entries_out || !count_out || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching address book for '%s'\n", identity);

    // Step 1: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    // Step 2: Fetch from DHT using chunked layer
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result != DHT_CHUNK_OK || !blob) {
        QGP_LOG_INFO(LOG_TAG, "Address book not found in DHT: %s\n", dht_chunked_strerror(result));
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

    if (magic != DHT_ADDRESSBOOK_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X\n", magic);
        free(blob);
        return -1;
    }

    // Version
    uint8_t version = blob[offset++];
    if (version != DHT_ADDRESSBOOK_VERSION) {
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
        QGP_LOG_INFO(LOG_TAG, "Address book expired (expiry=%llu, now=%llu)\n",
                     (unsigned long long)expiry, (unsigned long long)now);
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

    QGP_LOG_INFO(LOG_TAG, "Parsed header: timestamp=%llu, expiry=%llu, encrypted_len=%u, sig_len=%u\n",
           (unsigned long long)timestamp, (unsigned long long)expiry, encrypted_len, sig_len);

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

    dna_error_t dec_result = dna_decrypt_message_raw(
        dna_ctx,
        encrypted_data,
        encrypted_len,
        kyber_privkey,
        &decrypted_data,
        &decrypted_len,
        &sender_pubkey_out,
        &sender_pubkey_len_out,
        &signature_out,
        &signature_out_len,
        &sender_timestamp
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

    // Step 5: Verify sender's public key matches (self-verification)
    if (dilithium_pubkey && sender_pubkey_len_out == DHT_ADDRESSBOOK_DILITHIUM_PUBKEY_SIZE) {
        if (memcmp(sender_pubkey_out, dilithium_pubkey, DHT_ADDRESSBOOK_DILITHIUM_PUBKEY_SIZE) != 0) {
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

    QGP_LOG_INFO(LOG_TAG, "Successfully fetched %zu addresses\n", *count_out);
    return 0;
}

/**
 * Free address book entries array
 */
void dht_addressbook_free_entries(dht_addressbook_entry_t *entries, size_t count) {
    (void)count;  // Entries are a flat array, no inner allocations
    if (entries) {
        free(entries);
    }
}

/**
 * Free address book structure
 */
void dht_addressbook_free(dht_addressbook_t *addressbook) {
    if (!addressbook) return;

    if (addressbook->entries) {
        dht_addressbook_free_entries(addressbook->entries, addressbook->entry_count);
    }
    free(addressbook);
}

/**
 * Check if address book exists in DHT
 */
bool dht_addressbook_exists(dht_context_t *dht_ctx, const char *identity) {
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
 * Get address book timestamp from DHT
 */
int dht_addressbook_get_timestamp(dht_context_t *dht_ctx, const char *identity, uint64_t *timestamp_out) {
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

/**
 * Convert database entries to DHT entries
 */
dht_addressbook_entry_t* dht_addressbook_from_db_entries(const addressbook_entry_t *db_entries, size_t count) {
    if (!db_entries || count == 0) {
        return NULL;
    }

    dht_addressbook_entry_t *dht_entries = calloc(count, sizeof(dht_addressbook_entry_t));
    if (!dht_entries) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(dht_entries[i].address, db_entries[i].address, sizeof(dht_entries[i].address) - 1);
        strncpy(dht_entries[i].label, db_entries[i].label, sizeof(dht_entries[i].label) - 1);
        strncpy(dht_entries[i].network, db_entries[i].network, sizeof(dht_entries[i].network) - 1);
        strncpy(dht_entries[i].notes, db_entries[i].notes, sizeof(dht_entries[i].notes) - 1);
        dht_entries[i].created_at = db_entries[i].created_at;
        dht_entries[i].last_used = db_entries[i].last_used;
        dht_entries[i].use_count = db_entries[i].use_count;
    }

    return dht_entries;
}

/**
 * Convert DHT entries to database entries
 */
addressbook_entry_t* dht_addressbook_to_db_entries(const dht_addressbook_entry_t *dht_entries, size_t count) {
    if (!dht_entries || count == 0) {
        return NULL;
    }

    addressbook_entry_t *db_entries = calloc(count, sizeof(addressbook_entry_t));
    if (!db_entries) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        db_entries[i].id = 0;  // Will be assigned by database
        strncpy(db_entries[i].address, dht_entries[i].address, sizeof(db_entries[i].address) - 1);
        strncpy(db_entries[i].label, dht_entries[i].label, sizeof(db_entries[i].label) - 1);
        strncpy(db_entries[i].network, dht_entries[i].network, sizeof(db_entries[i].network) - 1);
        strncpy(db_entries[i].notes, dht_entries[i].notes, sizeof(db_entries[i].notes) - 1);
        db_entries[i].created_at = dht_entries[i].created_at;
        db_entries[i].updated_at = dht_entries[i].created_at;  // Use created_at as updated_at
        db_entries[i].last_used = dht_entries[i].last_used;
        db_entries[i].use_count = dht_entries[i].use_count;
    }

    return db_entries;
}
