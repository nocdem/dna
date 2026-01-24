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
#include "../../messenger/gek.h"
#include "../../messenger/groups.h"
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
 * Serialize GEKs and groups to JSON for backup
 * v4: Messages removed (fetched from DM outboxes instead)
 */
static char* serialize_messages_to_json(
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    uint64_t timestamp,
    int *message_count_out)
{
    (void)msg_ctx;  // No longer used for messages in v4

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for backup serialization");
        return NULL;
    }

    // Create JSON object
    json_object *root = json_object_new_object();
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create JSON object");
        return NULL;
    }

    // Add header fields
    json_object_object_add(root, "version", json_object_new_int(DHT_MSGBACKUP_VERSION));
    json_object_object_add(root, "fingerprint", json_object_new_string(fingerprint));
    json_object_object_add(root, "timestamp", json_object_new_int64(timestamp));

    // v4: No messages in backup (fetched from DM outboxes)
    json_object_object_add(root, "message_count", json_object_new_int(0));

    if (message_count_out) {
        *message_count_out = 0;
    }

    // === Add GEK data (v2+) ===
    gek_export_entry_t *gek_entries = NULL;
    size_t gek_count = 0;
    if (gek_export_all(&gek_entries, &gek_count) == 0 && gek_count > 0) {
        json_object *geks_array = json_object_new_array();
        for (size_t i = 0; i < gek_count; i++) {
            json_object *gek_obj = json_object_new_object();
            json_object_object_add(gek_obj, "group_uuid",
                json_object_new_string(gek_entries[i].group_uuid));
            json_object_object_add(gek_obj, "gek_version",
                json_object_new_int((int)gek_entries[i].gek_version));

            // Base64 encode the encrypted GEK
            char *gek_b64 = qgp_base64_encode(gek_entries[i].encrypted_gek,
                GEK_ENC_TOTAL_SIZE, NULL);
            if (gek_b64) {
                json_object_object_add(gek_obj, "gek_base64",
                    json_object_new_string(gek_b64));
                free(gek_b64);
            }

            json_object_object_add(gek_obj, "created_at",
                json_object_new_int64((int64_t)gek_entries[i].created_at));
            json_object_object_add(gek_obj, "expires_at",
                json_object_new_int64((int64_t)gek_entries[i].expires_at));
            json_object_array_add(geks_array, gek_obj);
        }
        json_object_object_add(root, "gek_count", json_object_new_int((int)gek_count));
        json_object_object_add(root, "geks", geks_array);
        gek_free_export_entries(gek_entries, gek_count);
        QGP_LOG_INFO(LOG_TAG, "Added %zu GEK entries to backup", gek_count);
    } else {
        json_object_object_add(root, "gek_count", json_object_new_int(0));
    }

    // === Add group data (v2) ===
    groups_export_entry_t *group_entries = NULL;
    size_t group_count = 0;
    if (groups_export_all(&group_entries, &group_count) == 0 && group_count > 0) {
        json_object *groups_array = json_object_new_array();
        for (size_t i = 0; i < group_count; i++) {
            json_object *group_obj = json_object_new_object();
            json_object_object_add(group_obj, "uuid",
                json_object_new_string(group_entries[i].uuid));
            json_object_object_add(group_obj, "name",
                json_object_new_string(group_entries[i].name));
            json_object_object_add(group_obj, "owner_fingerprint",
                json_object_new_string(group_entries[i].owner_fp));
            json_object_object_add(group_obj, "is_owner",
                json_object_new_boolean(group_entries[i].is_owner));
            json_object_object_add(group_obj, "created_at",
                json_object_new_int64((int64_t)group_entries[i].created_at));

            // Add members array
            json_object *members_array = json_object_new_array();
            for (int m = 0; m < group_entries[i].member_count; m++) {
                if (group_entries[i].members && group_entries[i].members[m]) {
                    json_object_array_add(members_array,
                        json_object_new_string(group_entries[i].members[m]));
                }
            }
            json_object_object_add(group_obj, "members", members_array);
            json_object_array_add(groups_array, group_obj);
        }
        json_object_object_add(root, "group_count", json_object_new_int((int)group_count));
        json_object_object_add(root, "groups", groups_array);
        groups_free_export_entries(group_entries, group_count);
        QGP_LOG_INFO(LOG_TAG, "Added %zu groups to backup", group_count);
    } else {
        json_object_object_add(root, "group_count", json_object_new_int(0));
    }

    // Convert to string
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    QGP_LOG_INFO(LOG_TAG, "Serialized backup v4: %zu GEKs, %zu groups to JSON (%zu bytes)",
                 gek_count, group_count, strlen(json_str));
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

    // Extract messages array (optional in v4 - messages come from DM outboxes)
    json_object *messages_array = NULL;
    json_object_object_get_ex(root, "messages", &messages_array);

    size_t count = messages_array ? json_object_array_length(messages_array) : 0;
    int restored = 0;
    int skipped = 0;

    if (count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Processing %zu messages from backup (v3 format)", count);
    } else {
        QGP_LOG_INFO(LOG_TAG, "No messages in backup (v4 format - messages from DM outboxes)");
    }

    // Process each message (v3 backward compatibility)
    for (size_t i = 0; i < count; i++) {
        json_object *msg_obj = json_object_array_get_idx(messages_array, i);
        if (!msg_obj) continue;

        // Extract fields (v3 format: plaintext instead of encrypted_message)
        json_object *sender_obj = NULL, *recipient_obj = NULL;
        json_object *plaintext_obj = NULL, *timestamp_obj = NULL;
        json_object *is_outgoing_obj = NULL, *group_id_obj = NULL;
        json_object *message_type_obj = NULL, *sender_fp_obj = NULL;

        json_object_object_get_ex(msg_obj, "sender", &sender_obj);
        json_object_object_get_ex(msg_obj, "recipient", &recipient_obj);
        json_object_object_get_ex(msg_obj, "plaintext", &plaintext_obj);
        json_object_object_get_ex(msg_obj, "timestamp", &timestamp_obj);
        json_object_object_get_ex(msg_obj, "is_outgoing", &is_outgoing_obj);
        json_object_object_get_ex(msg_obj, "group_id", &group_id_obj);
        json_object_object_get_ex(msg_obj, "message_type", &message_type_obj);
        json_object_object_get_ex(msg_obj, "sender_fingerprint", &sender_fp_obj);

        // v3 requires plaintext field - skip old v2 encrypted format
        if (!sender_obj || !recipient_obj || !plaintext_obj || !timestamp_obj) {
            // Check if this is old v2 encrypted format
            json_object *enc_b64_obj = NULL;
            if (json_object_object_get_ex(msg_obj, "encrypted_message_base64", &enc_b64_obj)) {
                QGP_LOG_WARN(LOG_TAG, "Skipping message %zu: old v2 encrypted format not supported in v3", i);
            } else {
                QGP_LOG_WARN(LOG_TAG, "Skipping message %zu: missing required fields", i);
            }
            skipped++;
            continue;
        }

        const char *sender = json_object_get_string(sender_obj);
        const char *recipient = json_object_get_string(recipient_obj);
        const char *plaintext = json_object_get_string(plaintext_obj);
        time_t timestamp = (time_t)json_object_get_int64(timestamp_obj);
        bool is_outgoing = is_outgoing_obj ? json_object_get_boolean(is_outgoing_obj) : false;
        int group_id = group_id_obj ? json_object_get_int(group_id_obj) : 0;
        int message_type = message_type_obj ? json_object_get_int(message_type_obj) : 0;
        const char *sender_fp = sender_fp_obj ? json_object_get_string(sender_fp_obj) : sender;

        // Check if message already exists (v3: use sender_fp + recipient + timestamp)
        if (message_backup_exists(msg_ctx, sender_fp, recipient, timestamp)) {
            QGP_LOG_DEBUG(LOG_TAG, "Skipping message %zu: duplicate", i);
            skipped++;
            continue;
        }

        // Import message to SQLite (v3 format: plaintext, v15: no offline_seq)
        int result = message_backup_save(
            msg_ctx,
            sender,
            recipient,
            plaintext,      // v3: plaintext message
            sender_fp,      // v3: sender fingerprint
            timestamp,
            is_outgoing,
            group_id,
            message_type
        );

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

    // === Import GEK data (v2) ===
    json_object *geks_array = NULL;
    int gek_imported = 0;
    if (json_object_object_get_ex(root, "geks", &geks_array)) {
        size_t gek_count = json_object_array_length(geks_array);
        if (gek_count > 0) {
            gek_export_entry_t *gek_entries = calloc(gek_count, sizeof(gek_export_entry_t));
            if (gek_entries) {
                for (size_t i = 0; i < gek_count; i++) {
                    json_object *gek_obj = json_object_array_get_idx(geks_array, i);
                    if (!gek_obj) continue;

                    json_object *uuid_obj = NULL, *version_obj = NULL;
                    json_object *gek_b64_obj = NULL, *created_obj = NULL, *expires_obj = NULL;

                    json_object_object_get_ex(gek_obj, "group_uuid", &uuid_obj);
                    json_object_object_get_ex(gek_obj, "gek_version", &version_obj);
                    json_object_object_get_ex(gek_obj, "gek_base64", &gek_b64_obj);
                    json_object_object_get_ex(gek_obj, "created_at", &created_obj);
                    json_object_object_get_ex(gek_obj, "expires_at", &expires_obj);

                    if (uuid_obj && gek_b64_obj) {
                        const char *uuid = json_object_get_string(uuid_obj);
                        const char *gek_b64 = json_object_get_string(gek_b64_obj);

                        if (uuid) {
                            strncpy(gek_entries[i].group_uuid, uuid, 36);
                            gek_entries[i].group_uuid[36] = '\0';
                        }
                        gek_entries[i].gek_version = version_obj ?
                            (uint32_t)json_object_get_int(version_obj) : 0;
                        gek_entries[i].created_at = created_obj ?
                            (uint64_t)json_object_get_int64(created_obj) : 0;
                        gek_entries[i].expires_at = expires_obj ?
                            (uint64_t)json_object_get_int64(expires_obj) : 0;

                        // Decode base64 encrypted GEK
                        size_t dec_len = 0;
                        uint8_t *dec_gek = qgp_base64_decode(gek_b64, &dec_len);
                        if (dec_gek && dec_len == GEK_ENC_TOTAL_SIZE) {
                            memcpy(gek_entries[i].encrypted_gek, dec_gek, GEK_ENC_TOTAL_SIZE);
                        }
                        if (dec_gek) free(dec_gek);
                    }
                }

                gek_import_all(gek_entries, gek_count, &gek_imported);
                free(gek_entries);
            }
        }
        QGP_LOG_INFO(LOG_TAG, "Imported %d GEK entries from backup", gek_imported);
    }

    // === Import group data (v2) ===
    json_object *groups_array_obj = NULL;
    int groups_imported = 0;
    if (json_object_object_get_ex(root, "groups", &groups_array_obj)) {
        size_t group_count = json_object_array_length(groups_array_obj);
        if (group_count > 0) {
            groups_export_entry_t *group_entries = calloc(group_count, sizeof(groups_export_entry_t));
            if (group_entries) {
                for (size_t i = 0; i < group_count; i++) {
                    json_object *group_obj = json_object_array_get_idx(groups_array_obj, i);
                    if (!group_obj) continue;

                    json_object *uuid_obj = NULL, *name_obj = NULL;
                    json_object *owner_obj = NULL, *is_owner_obj = NULL;
                    json_object *created_obj = NULL, *members_obj = NULL;

                    json_object_object_get_ex(group_obj, "uuid", &uuid_obj);
                    json_object_object_get_ex(group_obj, "name", &name_obj);
                    json_object_object_get_ex(group_obj, "owner_fingerprint", &owner_obj);
                    json_object_object_get_ex(group_obj, "is_owner", &is_owner_obj);
                    json_object_object_get_ex(group_obj, "created_at", &created_obj);
                    json_object_object_get_ex(group_obj, "members", &members_obj);

                    if (uuid_obj) {
                        const char *uuid = json_object_get_string(uuid_obj);
                        if (uuid) {
                            strncpy(group_entries[i].uuid, uuid, 36);
                            group_entries[i].uuid[36] = '\0';
                        }
                    }
                    if (name_obj) {
                        const char *name = json_object_get_string(name_obj);
                        if (name) {
                            strncpy(group_entries[i].name, name, 127);
                            group_entries[i].name[127] = '\0';
                        }
                    }
                    if (owner_obj) {
                        const char *owner = json_object_get_string(owner_obj);
                        if (owner) {
                            strncpy(group_entries[i].owner_fp, owner, 128);
                            group_entries[i].owner_fp[128] = '\0';
                        }
                    }
                    group_entries[i].is_owner = is_owner_obj ?
                        json_object_get_boolean(is_owner_obj) : false;
                    group_entries[i].created_at = created_obj ?
                        (uint64_t)json_object_get_int64(created_obj) : 0;

                    // Parse members array
                    group_entries[i].members = NULL;
                    group_entries[i].member_count = 0;
                    if (members_obj) {
                        size_t mem_count = json_object_array_length(members_obj);
                        if (mem_count > 0) {
                            group_entries[i].members = calloc(mem_count, sizeof(char *));
                            if (group_entries[i].members) {
                                for (size_t m = 0; m < mem_count; m++) {
                                    json_object *mem_obj = json_object_array_get_idx(members_obj, m);
                                    if (mem_obj) {
                                        const char *fp = json_object_get_string(mem_obj);
                                        if (fp) {
                                            group_entries[i].members[m] = strdup(fp);
                                            group_entries[i].member_count++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                groups_import_all(group_entries, group_count, &groups_imported);

                // Free group entries
                for (size_t i = 0; i < group_count; i++) {
                    if (group_entries[i].members) {
                        for (int m = 0; m < group_entries[i].member_count; m++) {
                            free(group_entries[i].members[m]);
                        }
                        free(group_entries[i].members);
                    }
                }
                free(group_entries);
            }
        }
        QGP_LOG_INFO(LOG_TAG, "Imported %d groups from backup", groups_imported);
    }

    json_object_put(root);

    if (restored_count_out) *restored_count_out = restored;
    if (skipped_count_out) *skipped_count_out = skipped;

    QGP_LOG_INFO(LOG_TAG, "Import complete: %d messages restored, %d skipped, %d GEKs, %d groups",
                 restored, skipped, gek_imported, groups_imported);

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

    // Version (accept v3 and v4 for backward compatibility)
    uint8_t version = blob[offset++];
    if (version < 3 || version > DHT_MSGBACKUP_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %d (expected 3-%d)", version, DHT_MSGBACKUP_VERSION);
        free(blob);
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "Backup version: %d", version);

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
