/**
 * DHT Message Backup/Restore Implementation
 * Per-identity encrypted message backup with DHT storage
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 */

#include "dht_message_backup.h"
#include "../shared/dht_chunked.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../dna_api.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>

#define LOG_TAG "DHT_MSGBACKUP"

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
 * Generate base key string for message backup storage
 * Format: "fingerprint:message_backup"
 * The dht_chunked layer handles hashing internally
 */
static int make_base_key(const char *fingerprint, char *key_out, size_t key_out_size) {
    if (!fingerprint || !key_out) {
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:message_backup", fingerprint);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small");
        return -1;
    }

    return 0;
}

/**
 * Get all messages from SQLite and serialize to JSON
 */
static char* serialize_messages_to_json(
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    uint64_t timestamp,
    int *message_count_out)
{
    if (!msg_ctx || !fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for message serialization");
        return NULL;
    }

    // Get all recent contacts to iterate through conversations
    char **contacts = NULL;
    int contact_count = 0;

    if (message_backup_get_recent_contacts(msg_ctx, &contacts, &contact_count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get recent contacts");
        return NULL;
    }

    // Create JSON object
    json_object *root = json_object_new_object();
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create JSON object");
        if (contacts) {
            for (int i = 0; i < contact_count; i++) free(contacts[i]);
            free(contacts);
        }
        return NULL;
    }

    // Add header fields
    json_object_object_add(root, "version", json_object_new_int(DHT_MSGBACKUP_VERSION));
    json_object_object_add(root, "fingerprint", json_object_new_string(fingerprint));
    json_object_object_add(root, "timestamp", json_object_new_int64(timestamp));

    // Create messages array
    json_object *messages_array = json_object_new_array();
    if (!messages_array) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create messages array");
        json_object_put(root);
        if (contacts) {
            for (int i = 0; i < contact_count; i++) free(contacts[i]);
            free(contacts);
        }
        return NULL;
    }

    int total_messages = 0;

    // Iterate through each contact conversation
    for (int c = 0; c < contact_count; c++) {
        backup_message_t *messages = NULL;
        int msg_count = 0;

        if (message_backup_get_conversation(msg_ctx, contacts[c], &messages, &msg_count) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to get conversation for contact %d", c);
            continue;
        }

        // Add each message to array
        for (int m = 0; m < msg_count; m++) {
            json_object *msg_obj = json_object_new_object();
            if (!msg_obj) continue;

            json_object_object_add(msg_obj, "sender", json_object_new_string(messages[m].sender));
            json_object_object_add(msg_obj, "recipient", json_object_new_string(messages[m].recipient));

            // Base64 encode the encrypted message
            char *enc_b64 = qgp_base64_encode(messages[m].encrypted_message, messages[m].encrypted_len, NULL);
            if (enc_b64) {
                json_object_object_add(msg_obj, "encrypted_message_base64", json_object_new_string(enc_b64));
                free(enc_b64);
            }

            json_object_object_add(msg_obj, "encrypted_len", json_object_new_int64(messages[m].encrypted_len));
            json_object_object_add(msg_obj, "timestamp", json_object_new_int64(messages[m].timestamp));
            json_object_object_add(msg_obj, "is_outgoing", json_object_new_boolean(
                strcmp(messages[m].sender, fingerprint) == 0));
            json_object_object_add(msg_obj, "status", json_object_new_int(messages[m].status));
            json_object_object_add(msg_obj, "group_id", json_object_new_int(messages[m].group_id));
            json_object_object_add(msg_obj, "message_type", json_object_new_int(messages[m].message_type));

            json_object_array_add(messages_array, msg_obj);
            total_messages++;
        }

        message_backup_free_messages(messages, msg_count);
    }

    // Free contacts
    if (contacts) {
        for (int i = 0; i < contact_count; i++) free(contacts[i]);
        free(contacts);
    }

    json_object_object_add(root, "message_count", json_object_new_int(total_messages));
    json_object_object_add(root, "messages", messages_array);

    if (message_count_out) {
        *message_count_out = total_messages;
    }

    // Convert to string
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    QGP_LOG_INFO(LOG_TAG, "Serialized %d messages to JSON (%zu bytes)", total_messages, strlen(json_str));
    char *result = strdup(json_str);

    json_object_put(root);  // This frees the entire object tree

    return result;
}

/**
 * Deserialize JSON and import messages to SQLite (skip duplicates)
 */
static int deserialize_and_import_messages(
    message_backup_context_t *msg_ctx,
    const char *json_str,
    int *restored_count_out,
    int *skipped_count_out)
{
    if (!msg_ctx || !json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for message deserialization");
        return -1;
    }

    // Parse JSON
    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON");
        return -1;
    }

    // Extract messages array
    json_object *messages_array = NULL;
    if (!json_object_object_get_ex(root, "messages", &messages_array)) {
        QGP_LOG_ERROR(LOG_TAG, "No messages array in JSON");
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(messages_array);
    int restored = 0;
    int skipped = 0;

    QGP_LOG_INFO(LOG_TAG, "Processing %zu messages from backup", count);

    // Process each message
    for (size_t i = 0; i < count; i++) {
        json_object *msg_obj = json_object_array_get_idx(messages_array, i);
        if (!msg_obj) continue;

        // Extract fields
        json_object *sender_obj = NULL, *recipient_obj = NULL;
        json_object *enc_b64_obj = NULL, *timestamp_obj = NULL;
        json_object *is_outgoing_obj = NULL, *group_id_obj = NULL;
        json_object *message_type_obj = NULL;

        json_object_object_get_ex(msg_obj, "sender", &sender_obj);
        json_object_object_get_ex(msg_obj, "recipient", &recipient_obj);
        json_object_object_get_ex(msg_obj, "encrypted_message_base64", &enc_b64_obj);
        json_object_object_get_ex(msg_obj, "timestamp", &timestamp_obj);
        json_object_object_get_ex(msg_obj, "is_outgoing", &is_outgoing_obj);
        json_object_object_get_ex(msg_obj, "group_id", &group_id_obj);
        json_object_object_get_ex(msg_obj, "message_type", &message_type_obj);

        if (!sender_obj || !recipient_obj || !enc_b64_obj || !timestamp_obj) {
            QGP_LOG_WARN(LOG_TAG, "Skipping message %zu: missing required fields", i);
            skipped++;
            continue;
        }

        const char *sender = json_object_get_string(sender_obj);
        const char *recipient = json_object_get_string(recipient_obj);
        const char *enc_b64 = json_object_get_string(enc_b64_obj);
        time_t timestamp = (time_t)json_object_get_int64(timestamp_obj);
        bool is_outgoing = is_outgoing_obj ? json_object_get_boolean(is_outgoing_obj) : false;
        int group_id = group_id_obj ? json_object_get_int(group_id_obj) : 0;
        int message_type = message_type_obj ? json_object_get_int(message_type_obj) : 0;

        // Decode base64 encrypted message
        size_t enc_len = 0;
        uint8_t *encrypted_message = qgp_base64_decode(enc_b64, &enc_len);
        if (!encrypted_message || enc_len == 0) {
            QGP_LOG_WARN(LOG_TAG, "Skipping message %zu: failed to decode base64", i);
            if (encrypted_message) free(encrypted_message);
            skipped++;
            continue;
        }

        // Check if message already exists (duplicate check)
        if (message_backup_exists_ciphertext(msg_ctx, encrypted_message, enc_len)) {
            QGP_LOG_DEBUG(LOG_TAG, "Skipping message %zu: duplicate", i);
            free(encrypted_message);
            skipped++;
            continue;
        }

        // Import message to SQLite
        // Legacy backups don't have offline_seq, so pass 0
        int result = message_backup_save(
            msg_ctx,
            sender,
            recipient,
            encrypted_message,
            enc_len,
            timestamp,
            is_outgoing,
            group_id,
            message_type,
            0  // offline_seq = 0 (legacy backup format)
        );

        free(encrypted_message);

        if (result == 0) {
            restored++;
        } else if (result == 1) {
            // Duplicate (already existed)
            skipped++;
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to import message %zu", i);
            skipped++;
        }
    }

    json_object_put(root);

    if (restored_count_out) *restored_count_out = restored;
    if (skipped_count_out) *skipped_count_out = skipped;

    QGP_LOG_INFO(LOG_TAG, "Import complete: %d restored, %d skipped", restored, skipped);

    return 0;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * Initialize DHT message backup subsystem
 */
int dht_message_backup_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Initialized");
    return 0;
}

/**
 * Cleanup DHT message backup subsystem
 */
void dht_message_backup_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "Cleaned up");
}

/**
 * Backup all messages to DHT
 */
int dht_message_backup_publish(
    dht_context_t *dht_ctx,
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    int *message_count_out)
{
    if (!dht_ctx || !msg_ctx || !fingerprint || !kyber_pubkey || !kyber_privkey ||
        !dilithium_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for publish");
        return -1;
    }

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + DHT_MSGBACKUP_DEFAULT_TTL;

    QGP_LOG_INFO(LOG_TAG, "Publishing message backup for '%.20s...' (TTL=%d)",
                 fingerprint, DHT_MSGBACKUP_DEFAULT_TTL);

    // Step 1: Serialize all messages to JSON
    int msg_count = 0;
    char *json_str = serialize_messages_to_json(msg_ctx, fingerprint, timestamp, &msg_count);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize messages to JSON");
        return -1;
    }

    if (message_count_out) {
        *message_count_out = msg_count;
    }

    size_t json_len = strlen(json_str);
    QGP_LOG_INFO(LOG_TAG, "JSON length: %zu bytes (%d messages)", json_len, msg_count);

    // Step 2: Sign JSON with Dilithium5
    uint8_t signature[DHT_MSGBACKUP_DILITHIUM_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (qgp_dsa87_sign(signature, &sig_len, (const uint8_t*)json_str, json_len, dilithium_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign JSON");
        free(json_str);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Signature length: %zu bytes", sig_len);

    // Step 3: Encrypt JSON with Kyber1024 (self-encryption)
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context");
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
        sync_timestamp,
        &encrypted_data,
        &encrypted_len
    );

    dna_context_free(dna_ctx);
    free(json_str);

    if (enc_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt JSON: %s", dna_error_string(enc_result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Encrypted length: %zu bytes", encrypted_len);

    // Step 4: Build binary blob
    // Format: [magic][version][timestamp][expiry][payload_len][encrypted_payload][sig_len][signature]
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blob");
        free(encrypted_data);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = htonl(DHT_MSGBACKUP_MAGIC);
    memcpy(blob + offset, &magic, 4);
    offset += 4;

    // Version
    blob[offset++] = DHT_MSGBACKUP_VERSION;

    // Timestamp (network byte order)
    uint64_t ts_net = htonll(timestamp);
    memcpy(blob + offset, &ts_net, 8);
    offset += 8;

    // Expiry (network byte order)
    uint64_t exp_net = htonll(expiry);
    memcpy(blob + offset, &exp_net, 8);
    offset += 8;

    // Encrypted payload length
    uint32_t enc_len_net = htonl((uint32_t)encrypted_len);
    memcpy(blob + offset, &enc_len_net, 4);
    offset += 4;

    // Encrypted payload
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

    QGP_LOG_INFO(LOG_TAG, "Total blob size: %zu bytes", blob_size);

    // Step 5: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(fingerprint, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key");
        free(blob);
        return -1;
    }

    // Step 6: Store in DHT using chunked layer (handles compression, chunking, signing)
    int result = dht_chunked_publish(dht_ctx, base_key, blob, blob_size, DHT_CHUNK_TTL_7DAY);
    free(blob);

    if (result != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT: %s", dht_chunked_strerror(result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published message backup to DHT (%d messages)", msg_count);
    return 0;
}

/**
 * Restore messages from DHT
 */
int dht_message_backup_restore(
    dht_context_t *dht_ctx,
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    int *restored_count_out,
    int *skipped_count_out)
{
    if (!dht_ctx || !msg_ctx || !fingerprint || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for restore");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Restoring message backup for '%.20s...'", fingerprint);

    // Step 1: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(fingerprint, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key");
        return -1;
    }

    // Step 2: Fetch from DHT using chunked layer
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = dht_chunked_fetch(dht_ctx, base_key, &blob, &blob_size);
    if (result != DHT_CHUNK_OK || !blob) {
        QGP_LOG_INFO(LOG_TAG, "Message backup not found in DHT: %s", dht_chunked_strerror(result));
        return -2;  // Not found
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved blob: %zu bytes", blob_size);

    // Step 3: Parse blob header
    if (blob_size < 4 + 1 + 8 + 8 + 4 + 4) {
        QGP_LOG_ERROR(LOG_TAG, "Blob too small");
        free(blob);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic;
    memcpy(&magic, blob + offset, 4);
    magic = ntohl(magic);
    offset += 4;

    if (magic != DHT_MSGBACKUP_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X", magic);
        free(blob);
        return -1;
    }

    // Version
    uint8_t version = blob[offset++];
    if (version != DHT_MSGBACKUP_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %d", version);
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
        QGP_LOG_INFO(LOG_TAG, "Message backup expired (expiry=%lu, now=%lu)",
                     (unsigned long)expiry, (unsigned long)now);
        free(blob);
        return -2;  // Expired
    }

    // Encrypted payload length
    uint32_t encrypted_len;
    memcpy(&encrypted_len, blob + offset, 4);
    encrypted_len = ntohl(encrypted_len);
    offset += 4;

    if (offset + encrypted_len + 4 > blob_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted length");
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
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature length");
        free(blob);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Parsed header: timestamp=%lu, expiry=%lu, encrypted_len=%u, sig_len=%u",
                 (unsigned long)timestamp, (unsigned long)expiry, encrypted_len, sig_len);

    // Step 4: Decrypt JSON
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt JSON: %s", dna_error_string(dec_result));
        free(blob);
        if (signature_out) free(signature_out);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Decrypted JSON: %zu bytes", decrypted_len);

    // Verify sender public key matches expected (self-verification)
    if (dilithium_pubkey && sender_pubkey_len_out == DHT_MSGBACKUP_DILITHIUM_PUBKEY_SIZE) {
        if (memcmp(sender_pubkey_out, dilithium_pubkey, DHT_MSGBACKUP_DILITHIUM_PUBKEY_SIZE) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Sender public key mismatch (not self-encrypted)");
            free(decrypted_data);
            free(sender_pubkey_out);
            if (signature_out) free(signature_out);
            free(blob);
            return -1;
        }
        QGP_LOG_INFO(LOG_TAG, "Sender public key verified (self-encrypted)");
    }

    free(sender_pubkey_out);
    if (signature_out) free(signature_out);
    free(blob);

    // Null-terminate for JSON parsing
    char *json_str = malloc(decrypted_len + 1);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate JSON buffer");
        free(decrypted_data);
        return -1;
    }
    memcpy(json_str, decrypted_data, decrypted_len);
    json_str[decrypted_len] = '\0';
    free(decrypted_data);

    // Step 5: Parse JSON and import messages
    int restored = 0, skipped = 0;
    if (deserialize_and_import_messages(msg_ctx, json_str, &restored, &skipped) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize and import messages");
        free(json_str);
        return -1;
    }

    free(json_str);

    if (restored_count_out) *restored_count_out = restored;
    if (skipped_count_out) *skipped_count_out = skipped;

    QGP_LOG_INFO(LOG_TAG, "Successfully restored %d messages (%d skipped)", restored, skipped);

    return 0;
}

/**
 * Check if message backup exists in DHT
 */
bool dht_message_backup_exists(dht_context_t *dht_ctx, const char *fingerprint) {
    if (!dht_ctx || !fingerprint) {
        return false;
    }

    char base_key[512];
    if (make_base_key(fingerprint, base_key, sizeof(base_key)) != 0) {
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
 * Get message backup info from DHT
 */
int dht_message_backup_get_info(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    uint64_t *timestamp_out,
    int *message_count_out)
{
    if (!dht_ctx || !fingerprint) {
        return -1;
    }

    char base_key[512];
    if (make_base_key(fingerprint, base_key, sizeof(base_key)) != 0) {
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

    if (timestamp_out) {
        *timestamp_out = timestamp;
    }

    // For message_count, we'd need to decrypt the payload
    // For now, return -1 to indicate unknown
    if (message_count_out) {
        *message_count_out = -1;
    }

    free(blob);
    return 0;
}
