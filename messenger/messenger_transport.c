/*
 * DNA Messenger - Transport Integration Layer Implementation
 *
 * Phase 14: DHT-Only Messaging
 */

#include "messenger_transport.h"
#include "messenger.h"
#include "transport/transport.h"
#include "transport/internal/transport_core.h"  // For parse_presence_json
#include "dht/client/dht_singleton.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/shared/dht_chunked.h"
#include "dht/shared/dht_groups.h"
#include "dht/core/dht_keyserver.h"
#include "dht/core/dht_context.h"
#include "dht/core/dht_listen.h"
#include "database/keyserver_cache.h"
#include "database/contacts_db.h"
#include "database/group_invitations.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_types.h"
#include "database/presence_cache.h"
#include "database/profile_manager.h"
#include "database/profile_cache.h"
#include "dna_api.h"
#include "dna_config.h"
#include "dna/dna_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <pthread.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#endif

#define LOG_TAG "TRANSPORT"

// Global config for bootstrap nodes
static dna_config_t g_transport_config = {0};
static bool g_transport_config_loaded = false;

static void ensure_transport_config(void) {
    if (!g_transport_config_loaded) {
        dna_config_load(&g_transport_config);
        g_transport_config_loaded = true;
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static int load_my_dilithium_pubkey(
    messenger_context_t *ctx,
    uint8_t **pubkey_out,
    size_t *pubkey_len_out)
{
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot determine data directory");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open key file: %s", key_path);
        return -1;
    }

    fseek(f, 276, SEEK_SET);

    uint8_t *pubkey = malloc(2592);
    if (!pubkey) {
        fclose(f);
        return -1;
    }

    size_t read = fread(pubkey, 1, 2592, f);
    fclose(f);

    if (read != 2592) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid public key size: %zu (expected 2592)", read);
        free(pubkey);
        return -1;
    }

    *pubkey_out = pubkey;
    *pubkey_len_out = 2592;
    return 0;
}

static int load_pubkey_for_identity(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **pubkey_out,
    size_t *pubkey_len_out)
{
    uint8_t *signing_pubkey = NULL;
    size_t signing_len = 0;
    uint8_t *encryption_pubkey = NULL;
    size_t encryption_len = 0;

    if (messenger_load_pubkey(ctx, identity, &signing_pubkey, &signing_len,
                              &encryption_pubkey, &encryption_len, NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load public key for identity: %s", identity);
        return -1;
    }

    *pubkey_out = signing_pubkey;
    *pubkey_len_out = signing_len;
    free(encryption_pubkey);
    return 0;
}

static int resolve_identity_to_fingerprint(
    messenger_context_t *ctx,
    const char *identity,
    char fingerprint_out[129])
{
    uint8_t *signing_pubkey = NULL;
    size_t signing_len = 0;
    uint8_t *encryption_pubkey = NULL;
    size_t encryption_len = 0;

    if (messenger_load_pubkey(ctx, identity, &signing_pubkey, &signing_len,
                              &encryption_pubkey, &encryption_len, fingerprint_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to resolve identity to fingerprint: %s\n", identity);
        return -1;
    }

    free(signing_pubkey);
    free(encryption_pubkey);
    return 0;
}

static int load_my_privkey(
    messenger_context_t *ctx,
    uint8_t **privkey_out,
    size_t *privkey_len_out)
{
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot determine data directory");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open private key: %s\n", key_path);
        return -1;
    }

    uint8_t *privkey = malloc(4896);
    if (!privkey) {
        fclose(f);
        return -1;
    }

    fseek(f, 276 + 2592, SEEK_SET);
    size_t read = fread(privkey, 1, 4896, f);
    fclose(f);

    if (read != 4896) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid private key size: %zu (expected 4896)\n", read);
        free(privkey);
        return -1;
    }

    *privkey_out = privkey;
    *privkey_len_out = 4896;
    return 0;
}

static int load_my_kyber_key(
    messenger_context_t *ctx,
    uint8_t **kyber_key_out,
    size_t *kyber_key_len_out)
{
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot determine data directory");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.kem", data_dir);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open Kyber key: %s\n", key_path);
        return -1;
    }

    uint8_t *kyber = malloc(3168);
    if (!kyber) {
        fclose(f);
        return -1;
    }

    size_t read = fread(kyber, 1, 3168, f);
    fclose(f);

    if (read != 3168) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber key size: %zu (expected 3168)\n", read);
        free(kyber);
        return -1;
    }

    *kyber_key_out = kyber;
    *kyber_key_len_out = 3168;
    return 0;
}

static char* extract_sender_from_encrypted(
    messenger_context_t *ctx,
    const uint8_t *encrypted_msg,
    size_t msg_len)
{
    if (!ctx || !encrypted_msg || msg_len < 100) {
        return NULL;
    }

    typedef struct {
        char magic[8];
        uint8_t version;
        uint8_t enc_key_type;
        uint8_t recipient_count;
        uint8_t reserved;
        uint32_t encrypted_size;
        uint32_t signature_size;
    } __attribute__((packed)) msg_header_t;

    const msg_header_t *header = (const msg_header_t*)encrypted_msg;
    if (memcmp(header->magic, "PQSIGENC", 8) != 0) {
        return NULL;
    }

    size_t header_size = sizeof(msg_header_t);
    size_t recipient_entry_size = 1568 + 40;
    size_t recipients_size = header->recipient_count * recipient_entry_size;
    size_t nonce_size = 12;
    size_t ciphertext_size = header->encrypted_size;
    size_t tag_size = 16;

    size_t sig_offset = header_size + recipients_size + nonce_size + ciphertext_size + tag_size;

    if (sig_offset + 5 > msg_len) {
        return NULL;
    }

    const uint8_t *sig_data = encrypted_msg + sig_offset;
    uint16_t pkey_size = (sig_data[1] << 8) | sig_data[2];

    if (pkey_size != 2592) {
        return NULL;
    }

    const uint8_t *signing_pubkey = sig_data + 5;

    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts) {
        return NULL;
    }

    for (size_t i = 0; i < contacts->count; i++) {
        const char *identity = contacts->contacts[i].identity;
        keyserver_cache_entry_t *entry = NULL;

        if (keyserver_cache_get(identity, &entry) == 0 && entry) {
            if (memcmp(entry->dilithium_pubkey, signing_pubkey, 2592) == 0) {
                char *result = strdup(identity);
                keyserver_cache_free_entry(entry);
                contacts_db_free_list(contacts);
                return result;
            }
            keyserver_cache_free_entry(entry);
        }
    }

    contacts_db_free_list(contacts);

    unsigned char hash[64];
    qgp_sha3_512(signing_pubkey, 2592, hash);

    char fingerprint[129];
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        return NULL;
    }

    char *identity = NULL;
    int result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &identity);

    if (result == 0 && identity) {
        return identity;
    }

    return NULL;
}

static char* lookup_identity_for_pubkey(
    messenger_context_t *ctx,
    const uint8_t *pubkey,
    size_t pubkey_len)
{
    if (!ctx || !pubkey || pubkey_len != 2592) {
        return NULL;
    }

    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) == 0 && contacts) {
        for (size_t i = 0; i < contacts->count; i++) {
            const char *identity = contacts->contacts[i].identity;
            keyserver_cache_entry_t *entry = NULL;

            if (keyserver_cache_get(identity, &entry) == 0 && entry) {
                if (memcmp(entry->dilithium_pubkey, pubkey, 2592) == 0) {
                    char *result = strdup(identity);
                    keyserver_cache_free_entry(entry);
                    contacts_db_free_list(contacts);
                    return result;
                }
                keyserver_cache_free_entry(entry);
            }
        }
        contacts_db_free_list(contacts);
    }

    unsigned char hash[64];
    qgp_sha3_512(pubkey, 2592, hash);

    char fingerprint[129];
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        return NULL;
    }

    char *identity = NULL;
    int result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &identity);

    if (result == 0 && identity) {
        return identity;
    }

    return NULL;
}

// ============================================================================
// CALLBACKS (Forward declarations)
// ============================================================================

static void transport_message_received_internal(
    const uint8_t *peer_pubkey,
    const char *sender_fingerprint,
    const uint8_t *message,
    size_t message_len,
    void *user_data);

// ============================================================================
// TRANSPORT INITIALIZATION
// ============================================================================

int messenger_transport_init(messenger_context_t *ctx)
{
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid messenger context");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Initializing transport for identity: %s\n", ctx->identity);

    uint8_t *dilithium_privkey = NULL;
    size_t dilithium_privkey_len = 0;
    uint8_t *dilithium_pubkey = NULL;
    size_t dilithium_pubkey_len = 0;
    uint8_t *kyber_key = NULL;
    size_t kyber_key_len = 0;

    if (load_my_privkey(ctx, &dilithium_privkey, &dilithium_privkey_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium private key");
        return -1;
    }

    if (load_my_dilithium_pubkey(ctx, &dilithium_pubkey, &dilithium_pubkey_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium public key");
        free(dilithium_privkey);
        return -1;
    }

    if (load_my_kyber_key(ctx, &kyber_key, &kyber_key_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load KEM-1024 key");
        free(dilithium_privkey);
        free(dilithium_pubkey);
        return -1;
    }

    ensure_transport_config();

    transport_config_t config = {
        .dht_port = 4000,
        .enable_offline_queue = true,
        .offline_ttl_seconds = 604800,
        .bootstrap_count = g_transport_config.bootstrap_count
    };

    snprintf(config.identity, sizeof(config.identity), "%s", ctx->identity);

    for (int i = 0; i < g_transport_config.bootstrap_count && i < 5; i++) {
        snprintf(config.bootstrap_nodes[i], sizeof(config.bootstrap_nodes[i]),
                 "%s", g_transport_config.bootstrap_nodes[i]);
    }

    ctx->transport_ctx = transport_init(
        &config,
        dilithium_privkey,
        dilithium_pubkey,
        kyber_key,
        transport_message_received_internal,
        ctx
    );

    free(dilithium_privkey);
    free(dilithium_pubkey);
    free(kyber_key);

    if (!ctx->transport_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize transport");
        ctx->transport_enabled = false;
        return -1;
    }

    if (transport_start(ctx->transport_ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start transport");
        transport_free(ctx->transport_ctx);
        ctx->transport_ctx = NULL;
        ctx->transport_enabled = false;
        return -1;
    }

    if (transport_register_presence(ctx->transport_ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to register presence in DHT");
        transport_free(ctx->transport_ctx);
        ctx->transport_ctx = NULL;
        ctx->transport_enabled = false;
        return -1;
    }

    ctx->transport_enabled = true;

    if (presence_cache_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to initialize presence cache");
    }

    QGP_LOG_DEBUG(LOG_TAG, "Transport initialized successfully");
    QGP_LOG_DEBUG(LOG_TAG, "DHT port 4000");
    QGP_LOG_DEBUG(LOG_TAG, "Bootstrap nodes: %d configured\n", g_transport_config.bootstrap_count);

    return 0;
}

void messenger_transport_shutdown(messenger_context_t *ctx)
{
    if (!ctx || !ctx->transport_ctx) {
        return;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Shutting down transport for identity: %s\n", ctx->identity);

    transport_free(ctx->transport_ctx);
    ctx->transport_ctx = NULL;
    ctx->transport_enabled = false;

    QGP_LOG_DEBUG(LOG_TAG, "Transport shutdown complete");
}

// ============================================================================
// DHT-ONLY MESSAGING
// ============================================================================

int messenger_queue_to_dht(
    messenger_context_t *ctx,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len,
    uint64_t seq_num)
{
    QGP_LOG_INFO(LOG_TAG, "Queueing message to DHT for %s (len=%zu, seq=%llu)\n",
                 recipient ? recipient : "NULL", encrypted_len, (unsigned long long)seq_num);

    if (!ctx || !recipient || !encrypted_message || encrypted_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "messenger_queue_to_dht: Invalid parameters\n");
        return -1;
    }

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for message queue\n");
        return -1;
    }

    char recipient_fingerprint[129];
    if (resolve_identity_to_fingerprint(ctx, recipient, recipient_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to resolve recipient '%s' to fingerprint\n", recipient);
        return -1;
    }

    int queue_result = dht_queue_message(
        dht_ctx,
        ctx->identity,
        recipient_fingerprint,
        encrypted_message,
        encrypted_len,
        seq_num,
        604800
    );

    if (queue_result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Message queued in DHT for %s (fp: %.20s..., seq=%lu)\n",
               recipient, recipient_fingerprint, (unsigned long)seq_num);
        /* Watermark listener is already running persistently for this contact */
        return 0;
    }

    QGP_LOG_ERROR(LOG_TAG, "Failed to queue message in DHT (result=%d)\n", queue_result);
    return -1;
}

// ============================================================================
// MESSAGE RECEIVE CALLBACK
// ============================================================================

static void transport_message_received_internal(
    const uint8_t *peer_pubkey,
    const char *sender_fingerprint,
    const uint8_t *message,
    size_t message_len,
    void *user_data)
{
    messenger_context_t *ctx = (messenger_context_t*)user_data;
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context in message callback");
        return;
    }

    char *sender_identity = NULL;

    if (sender_fingerprint && strlen(sender_fingerprint) > 0) {
        sender_identity = strdup(sender_fingerprint);
        QGP_LOG_INFO(LOG_TAG, "Identified sender from DHT queue: %.32s...\n", sender_identity);
    } else if (peer_pubkey) {
        sender_identity = lookup_identity_for_pubkey(ctx, peer_pubkey, 2592);
    }

    if (!sender_identity && message && message_len > 0) {
        sender_identity = extract_sender_from_encrypted(ctx, message, message_len);
    }

    if (sender_identity) {
        QGP_LOG_INFO(LOG_TAG, "Received message from %s (%zu bytes)\n", sender_identity, message_len);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Received message from unknown peer (%zu bytes)\n", message_len);
        sender_identity = strdup("unknown");
    }

    uint64_t sender_timestamp = 0;
    int message_type = MESSAGE_TYPE_CHAT;

    const char *app_data = qgp_platform_app_data_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", app_data);

    qgp_key_t *kyber_key = NULL;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    dna_error_t decrypt_result = DNA_ERROR_KEY_LOAD;

    if (qgp_key_load(kyber_path, &kyber_key) == 0 && kyber_key && kyber_key->private_key_size == 3168) {
        uint8_t *sender_fp_from_msg = NULL;
        size_t sender_fp_len = 0;
        uint8_t *signature = NULL;
        size_t signature_len = 0;

        decrypt_result = dna_decrypt_message_raw(
            ctx->dna_ctx,
            message,
            message_len,
            kyber_key->private_key,
            &plaintext,
            &plaintext_len,
            &sender_fp_from_msg,
            &sender_fp_len,
            &signature,
            &signature_len,
            &sender_timestamp
        );

        if (sender_fp_from_msg) free(sender_fp_from_msg);
        if (signature) free(signature);
        qgp_key_free(kyber_key);
    } else {
        if (kyber_key) qgp_key_free(kyber_key);
    }

    if (decrypt_result == DNA_OK && plaintext && plaintext_len > 0) {
        uint8_t *plaintext_z = realloc(plaintext, plaintext_len + 1);
        if (plaintext_z) {
            plaintext = plaintext_z;
            plaintext[plaintext_len] = '\0';
        }

        json_object *j_msg = json_tokener_parse((const char*)plaintext);
        if (j_msg) {
            json_object *j_type = NULL;
            if (json_object_object_get_ex(j_msg, "type", &j_type)) {
                const char *type_str = json_object_get_string(j_type);
                if (type_str && (strcmp(type_str, "group_invite") == 0 ||
                                 strcmp(type_str, "groupinvite") == 0)) {
                    message_type = MESSAGE_TYPE_GROUP_INVITATION;

                    json_object *j_uuid = NULL, *j_name = NULL, *j_inviter = NULL, *j_count = NULL;
                    if (!json_object_object_get_ex(j_msg, "group_uuid", &j_uuid))
                        json_object_object_get_ex(j_msg, "groupuuid", &j_uuid);
                    if (!json_object_object_get_ex(j_msg, "group_name", &j_name))
                        json_object_object_get_ex(j_msg, "groupname", &j_name);
                    json_object_object_get_ex(j_msg, "inviter", &j_inviter);
                    if (!json_object_object_get_ex(j_msg, "member_count", &j_count))
                        json_object_object_get_ex(j_msg, "membercount", &j_count);

                    if (j_uuid && j_name && j_inviter) {
                        group_invitation_t invitation = {0};
                        strncpy(invitation.group_uuid, json_object_get_string(j_uuid), sizeof(invitation.group_uuid) - 1);
                        strncpy(invitation.group_name, json_object_get_string(j_name), sizeof(invitation.group_name) - 1);
                        strncpy(invitation.inviter, json_object_get_string(j_inviter), sizeof(invitation.inviter) - 1);
                        invitation.invited_at = sender_timestamp ? (time_t)sender_timestamp : time(NULL);
                        invitation.status = INVITATION_STATUS_PENDING;
                        invitation.member_count = j_count ? json_object_get_int(j_count) : 0;

                        int store_result = group_invitations_store(&invitation);
                        if (store_result == 0) {
                            QGP_LOG_INFO(LOG_TAG, "Group invitation stored: %s\n", invitation.group_name);

                            dna_engine_t *engine = dna_engine_get_global();
                            if (engine) {
                                dna_event_t event = {0};
                                event.type = DNA_EVENT_GROUP_INVITATION_RECEIVED;
                                dna_dispatch_event(engine, &event);
                            }
                        }
                    }
                }
            }
            json_object_put(j_msg);
        }
        free(plaintext);
    }

    time_t msg_timestamp = sender_timestamp ? (time_t)sender_timestamp : time(NULL);

    int result = message_backup_save(
        ctx->backup_ctx,
        sender_identity,
        ctx->identity,
        message,
        message_len,
        msg_timestamp,
        false,
        0,
        message_type,
        0
    );

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Message from %s stored (type=%d)\n", sender_identity, message_type);

        dna_engine_t *engine = dna_engine_get_global();
        if (engine) {
            dna_event_t event = {0};
            event.type = DNA_EVENT_MESSAGE_RECEIVED;
            strncpy(event.data.message_received.message.sender,
                    sender_identity,
                    sizeof(event.data.message_received.message.sender) - 1);
            strncpy(event.data.message_received.message.recipient,
                    ctx->identity,
                    sizeof(event.data.message_received.message.recipient) - 1);
            event.data.message_received.message.timestamp = (uint64_t)msg_timestamp;
            event.data.message_received.message.is_outgoing = false;
            event.data.message_received.message.message_type = message_type;
            dna_dispatch_event(engine, &event);
        }
    }

    if (profile_cache_is_expired(sender_identity)) {
        dna_unified_identity_t *identity = NULL;
        int profile_result = profile_manager_get_profile(sender_identity, &identity);
        if (profile_result == 0 && identity) {
            dna_identity_free(identity);
        }
    }

    free(sender_identity);
}

void messenger_transport_message_callback(
    const char *identity,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    QGP_LOG_DEBUG(LOG_TAG, "External message callback for %s (%zu bytes)\n", identity, len);
}

// ============================================================================
// PRESENCE & PEER DISCOVERY
// ============================================================================

bool messenger_transport_peer_online(messenger_context_t *ctx, const char *identity)
{
    if (!ctx || !identity) {
        return false;
    }
    return presence_cache_get(identity);
}

int messenger_transport_list_online_peers(
    messenger_context_t *ctx,
    char ***identities_out,
    int *count_out)
{
    if (!ctx || !identities_out || !count_out) {
        return -1;
    }
    *identities_out = NULL;
    *count_out = 0;
    return 0;
}

int messenger_transport_refresh_presence(messenger_context_t *ctx)
{
    if (!ctx) {
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Refreshing presence in DHT for %s", ctx->identity);

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for presence refresh");
        return -1;
    }

    uint8_t *pubkey = NULL;
    size_t pubkey_len = 0;
    if (load_my_dilithium_pubkey(ctx, &pubkey, &pubkey_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load public key for presence refresh");
        return -1;
    }

    char presence_data[512];
    if (create_presence_json(presence_data, sizeof(presence_data)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create presence JSON");
        free(pubkey);
        return -1;
    }

    uint8_t dht_key[64];
    sha3_512_hash(pubkey, pubkey_len, dht_key);
    free(pubkey);

    unsigned int ttl_7days = 7 * 24 * 3600;
    int result = dht_put_signed(dht, dht_key, sizeof(dht_key),
                                (const uint8_t*)presence_data, strlen(presence_data),
                                1, ttl_7days, "presence_heartbeat");

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to register presence in DHT");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Presence refreshed successfully");
    return 0;
}

int messenger_transport_lookup_presence(
    messenger_context_t *ctx,
    const char *fingerprint,
    uint64_t *last_seen_out)
{
    if (!ctx || !fingerprint || !last_seen_out) {
        return -1;
    }

    *last_seen_out = 0;

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for presence lookup");
        return -1;
    }

    size_t fp_len = strlen(fingerprint);
    if (fp_len != 128) {
        return -1;
    }

    uint8_t dht_key[64];
    for (int i = 0; i < 64; i++) {
        unsigned int byte;
        if (sscanf(fingerprint + (i * 2), "%02x", &byte) != 1) {
            return -1;
        }
        dht_key[i] = (uint8_t)byte;
    }

    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
        return -1;
    }

    uint64_t last_seen = 0;
    if (parse_presence_json((const char*)value, &last_seen) != 0) {
        free(value);
        return -1;
    }

    *last_seen_out = last_seen;
    free(value);
    return 0;
}

// ============================================================================
// OFFLINE MESSAGE QUEUE
// ============================================================================

int messenger_transport_check_offline_messages(
    messenger_context_t *ctx,
    const char *sender_fp,
    size_t *messages_received)
{
    if (!ctx || !ctx->transport_enabled || !ctx->transport_ctx) {
        if (messages_received) *messages_received = 0;
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Checking for offline messages in DHT (sender=%s)...",
                  sender_fp ? sender_fp : "ALL");

    size_t count = 0;
    int result = transport_check_offline_messages(ctx->transport_ctx, sender_fp, &count);

    if (result == 0 && count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Retrieved %zu offline messages from DHT\n", count);
    }

    if (messages_received) {
        *messages_received = count;
    }

    return result;
}
