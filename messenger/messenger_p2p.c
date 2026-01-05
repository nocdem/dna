/*
 * DNA Messenger - P2P Integration Layer Implementation
 *
 * Phase 9.1b: Hybrid P2P Transport Integration
 */

#include "messenger_p2p.h"
#include "messenger.h"
#include "p2p/p2p_transport.h"
#include "p2p/transport/transport_core.h"  // For parse_presence_json
#include "dht/client/dht_singleton.h"      // For DHT-only presence lookup
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
#include "database/presence_cache.h"
#include "database/profile_manager.h"
#include "database/profile_cache.h"
#include "dna_api.h"
#include "dna_config.h"
#include "dna/dna_engine.h"  // For event dispatch to Flutter
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <pthread.h>
#include <time.h>

// Platform-specific headers (qgp_platform.h provides cross-platform sleep)
#ifndef _WIN32
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#endif

// Global config for bootstrap nodes
static dna_config_t g_p2p_config = {0};
static bool g_p2p_config_loaded = false;

static void ensure_p2p_config(void) {
    if (!g_p2p_config_loaded) {
        dna_config_load(&g_p2p_config);
        g_p2p_config_loaded = true;
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Load my own Dilithium public key from local file
 * Used during P2P init to avoid circular dependency with keyserver
 *
 * @return: 0 on success, -1 on error
 */
static int load_my_dilithium_pubkey(
    messenger_context_t *ctx,
    uint8_t **pubkey_out,
    size_t *pubkey_len_out
)
{
    // Get data directory using cross-platform API
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR("P2P", "Cannot determine data directory");
        return -1;
    }

    /* v0.3.0: Flat structure - keys/identity.dsa */
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        QGP_LOG_ERROR("P2P", "Failed to open key file: %s", key_path);
        return -1;
    }

    // Skip header (276 bytes) and read public key (2592 bytes)
    // File format: [HEADER: 276 bytes][PUBLIC_KEY: 2592 bytes][PRIVATE_KEY: 4896 bytes]
    fseek(f, 276, SEEK_SET);

    uint8_t *pubkey = malloc(2592);  // Dilithium5 public key size
    if (!pubkey) {
        fclose(f);
        return -1;
    }

    size_t read = fread(pubkey, 1, 2592, f);
    fclose(f);

    if (read != 2592) {
        QGP_LOG_ERROR("P2P", "Invalid public key size: %zu (expected 2592)", read);
        free(pubkey);
        return -1;
    }

    *pubkey_out = pubkey;
    *pubkey_len_out = 2592;  // Dilithium5 public key size
    return 0;
}

/**
 * Load Dilithium public key for an identity from keyserver
 *
 * @return: 0 on success, -1 on error
 */
static int load_pubkey_for_identity(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **pubkey_out,
    size_t *pubkey_len_out
)
{
    uint8_t *signing_pubkey = NULL;
    size_t signing_len = 0;
    uint8_t *encryption_pubkey = NULL;
    size_t encryption_len = 0;

    // Load public keys from keyserver (don't need fingerprint here)
    if (messenger_load_pubkey(ctx, identity, &signing_pubkey, &signing_len,
                              &encryption_pubkey, &encryption_len, NULL) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to load public key for identity: %s", identity);
        return -1;
    }

    // We only need the signing key (Dilithium5) for P2P transport
    *pubkey_out = signing_pubkey;
    *pubkey_len_out = signing_len;

    // Free encryption key (not needed for P2P layer)
    free(encryption_pubkey);

    return 0;
}

/**
 * Resolve identity (name or fingerprint) to fingerprint
 * Uses keyserver lookup to ensure consistent fingerprint for DHT keys
 *
 * @return: 0 on success, -1 on error
 */
static int resolve_identity_to_fingerprint(
    messenger_context_t *ctx,
    const char *identity,
    char fingerprint_out[129]
)
{
    uint8_t *signing_pubkey = NULL;
    size_t signing_len = 0;
    uint8_t *encryption_pubkey = NULL;
    size_t encryption_len = 0;

    // Load public keys and get fingerprint
    if (messenger_load_pubkey(ctx, identity, &signing_pubkey, &signing_len,
                              &encryption_pubkey, &encryption_len, fingerprint_out) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to resolve identity to fingerprint: %s\n", identity);
        return -1;
    }

    // Free keys (we only needed the fingerprint)
    free(signing_pubkey);
    free(encryption_pubkey);

    return 0;
}

/**
 * Load my own Dilithium private key
 *
 * @return: 0 on success, -1 on error
 */
static int load_my_privkey(
    messenger_context_t *ctx,
    uint8_t **privkey_out,
    size_t *privkey_len_out
)
{
    // Get data directory using cross-platform API
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR("P2P", "Cannot determine data directory");
        return -1;
    }

    /* v0.3.0: Flat structure - keys/identity.dsa */
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        QGP_LOG_ERROR("P2P", "Failed to open private key: %s\n", key_path);
        return -1;
    }

    // Dilithium5 private key (ML-DSA-87) is 4896 bytes
    // File format: [HEADER: 276 bytes][PUBLIC_KEY: 2592 bytes][PRIVATE_KEY: 4896 bytes]
    // Private key is at offset 276 + 2592 = 2868
    uint8_t *privkey = malloc(4896);
    if (!privkey) {
        fclose(f);
        return -1;
    }

    // Skip header (276 bytes) and public key (2592 bytes)
    fseek(f, 276 + 2592, SEEK_SET);

    size_t read = fread(privkey, 1, 4896, f);
    fclose(f);

    if (read != 4896) {
        QGP_LOG_ERROR("P2P", "Invalid private key size: %zu (expected 4896 for Dilithium5)\n", read);
        free(privkey);
        return -1;
    }

    *privkey_out = privkey;
    *privkey_len_out = 4896;
    return 0;
}

/**
 * Load my own Kyber1024 private key (ML-KEM-1024)
 *
 * @return: 0 on success, -1 on error
 */
static int load_my_kyber_key(
    messenger_context_t *ctx,
    uint8_t **kyber_key_out,
    size_t *kyber_key_len_out
)
{
    // Get data directory using cross-platform API
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR("P2P", "Cannot determine data directory");
        return -1;
    }

    /* v0.3.0: Flat structure - keys/identity.kem */
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.kem", data_dir);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        QGP_LOG_ERROR("P2P", "Failed to open Kyber key: %s\n", key_path);
        return -1;
    }

    // Kyber1024 private key (ML-KEM-1024) is 3168 bytes
    // NOTE: Legacy keys may be 2400 bytes (Kyber768) - migration needed
    uint8_t *kyber = malloc(3168);
    if (!kyber) {
        fclose(f);
        return -1;
    }

    size_t read = fread(kyber, 1, 3168, f);
    fclose(f);

    if (read != 3168) {
        QGP_LOG_ERROR("P2P", "Invalid Kyber key size: %zu (expected 3168 for Kyber1024)\n", read);
        free(kyber);
        return -1;
    }

    *kyber_key_out = kyber;
    *kyber_key_len_out = 3168;
    return 0;
}

/**
 * Lookup identity for a public key in keyserver
 *
 * This is the reverse mapping: pubkey -> identity
 * Used when receiving P2P messages to find who sent it
 *
 * @return: identity string (caller must free), or NULL if not found
 */
/**
 * Extract sender identity from encrypted message by parsing signature
 * Encrypted format: [header | recipients | nonce | ciphertext | tag | signature]
 * Signature format: [type(1) | pkey_size(2) | sig_size(2) | pubkey | sig_bytes]
 */
static char* extract_sender_from_encrypted(
    messenger_context_t *ctx,
    const uint8_t *encrypted_msg,
    size_t msg_len
)
{
    if (!ctx || !encrypted_msg || msg_len < 100) {
        return NULL;
    }

    // Parse header to get signature offset
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
        return NULL;  // Invalid format
    }

    // Calculate signature offset
    size_t header_size = sizeof(msg_header_t);
    size_t recipient_entry_size = 1568 + 40;  // Kyber1024 ciphertext + wrapped_dek
    size_t recipients_size = header->recipient_count * recipient_entry_size;
    size_t nonce_size = 12;
    size_t ciphertext_size = header->encrypted_size;
    size_t tag_size = 16;

    size_t sig_offset = header_size + recipients_size + nonce_size + ciphertext_size + tag_size;

    if (sig_offset + 5 > msg_len) {
        return NULL;  // Message too short
    }

    // Parse signature header: [type(1) | pkey_size(2) | sig_size(2) | pubkey | sig]
    const uint8_t *sig_data = encrypted_msg + sig_offset;
    uint16_t pkey_size = (sig_data[1] << 8) | sig_data[2];

    if (pkey_size != 2592) {  // Dilithium5 public key size
        return NULL;  // Not Dilithium5
    }

    // Extract signing pubkey
    const uint8_t *signing_pubkey = sig_data + 5;

    // Search keyserver cache for identity with matching Dilithium pubkey
    // We'll use the keyserver cache lookup by iterating through it
    // This is not optimal but works for small contact lists

    // Get contacts list
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts) {
        return NULL;
    }

    // Check each contact's cached pubkey
    for (size_t i = 0; i < contacts->count; i++) {
        const char *identity = contacts->contacts[i].identity;
        keyserver_cache_entry_t *entry = NULL;

        if (keyserver_cache_get(identity, &entry) == 0 && entry) {
            // Compare Dilithium pubkeys
            if (memcmp(entry->dilithium_pubkey, signing_pubkey, 2592) == 0) {  // Dilithium5 public key size
                // Found matching contact!
                char *result = strdup(identity);
                keyserver_cache_free_entry(entry);
                contacts_db_free_list(contacts);
                return result;
            }
            keyserver_cache_free_entry(entry);
        }
    }

    // Free contacts list
    contacts_db_free_list(contacts);

    // Not in contacts - try DHT reverse lookup (fingerprint → identity)
    QGP_LOG_DEBUG("P2P", "Sender not in contacts, querying DHT reverse mapping...");

    // Compute fingerprint as hex string (SHA3-512 of pubkey)
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    qgp_sha3_512(signing_pubkey, 2592, hash);  // Dilithium5 public key size

    char fingerprint[129];  // SHA3-512 hex string = 128 chars + null
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';  // Null-terminate at position 128

    // Phase 14: Use global DHT singleton directly
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_WARN("P2P", "DHT not available for reverse lookup");
        return NULL;
    }

    // Query DHT for reverse mapping (fingerprint → identity)
    char *identity = NULL;
    int result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &identity);

    if (result == 0 && identity) {
        QGP_LOG_INFO("P2P", "DHT reverse lookup found: %s (fingerprint: %.16s...)\n", identity, fingerprint);

        // Cache the identity in contacts for faster lookup next time
        // (User can add them to contacts manually later if they want)
        return identity;  // Caller must free
    } else if (result == -2) {
        QGP_LOG_WARN("P2P", "Identity not found in DHT (fingerprint: %.16s...)\n", fingerprint);
    } else if (result == -3) {
        QGP_LOG_WARN("P2P", "DHT reverse mapping signature verification failed (fingerprint: %.16s...)\n", fingerprint);
    } else {
        QGP_LOG_WARN("P2P", "DHT reverse lookup error (fingerprint: %.16s...)\n", fingerprint);
    }

    return NULL;  // No matching identity found
}

static char* lookup_identity_for_pubkey(
    messenger_context_t *ctx,
    const uint8_t *pubkey,
    size_t pubkey_len
)
{
    if (!ctx || !pubkey || pubkey_len != 2592) {  // Dilithium5 public key size
        return NULL;
    }

    // Phase 6.2: Reverse DHT lookup (pubkey → identity)

    // First, check local contacts/keyserver cache
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) == 0 && contacts) {
        // Check each contact's cached pubkey
        for (size_t i = 0; i < contacts->count; i++) {
            const char *identity = contacts->contacts[i].identity;
            keyserver_cache_entry_t *entry = NULL;

            if (keyserver_cache_get(identity, &entry) == 0 && entry) {
                // Compare Dilithium pubkeys
                if (memcmp(entry->dilithium_pubkey, pubkey, 2592) == 0) {
                    // Found matching contact!
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

    // Not in local cache - try DHT reverse lookup (fingerprint → identity)
    // Compute fingerprint as hex string (SHA3-512 of pubkey)
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    qgp_sha3_512(pubkey, 2592, hash);  // Dilithium5 public key size

    char fingerprint[129];  // SHA3-512 hex string = 128 chars + null
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';  // Null-terminate at position 128

    // Phase 14: Use global DHT singleton directly
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        return NULL;  // DHT not available
    }

    // Query DHT for reverse mapping (fingerprint → identity)
    char *identity = NULL;
    int result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &identity);

    if (result == 0 && identity) {
        // Successfully resolved identity via DHT
        return identity;  // Caller must free
    }

    return NULL;  // No matching identity found
}

// ============================================================================
// P2P CALLBACKS (Forward declarations for init)
// ============================================================================

static void p2p_message_received_internal(
    const uint8_t *peer_pubkey,
    const char *sender_fingerprint,
    const uint8_t *message,
    size_t message_len,
    void *user_data
);

static void p2p_connection_state_changed(
    const uint8_t *peer_pubkey,
    bool is_connected,
    void *user_data
);

// ============================================================================
// P2P INITIALIZATION
// ============================================================================

int messenger_p2p_init(messenger_context_t *ctx)
{
    if (!ctx) {
        QGP_LOG_ERROR("P2P", "Invalid messenger context");
        return -1;
    }

    QGP_LOG_DEBUG("P2P", "Initializing P2P transport for identity: %s\n", ctx->identity);

    // Load my private keys
    uint8_t *dilithium_privkey = NULL;
    size_t dilithium_privkey_len = 0;
    uint8_t *dilithium_pubkey = NULL;
    size_t dilithium_pubkey_len = 0;
    uint8_t *kyber_key = NULL;
    size_t kyber_key_len = 0;

    // Load Dilithium private key
    if (load_my_privkey(ctx, &dilithium_privkey, &dilithium_privkey_len) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to load Dilithium private key");
        return -1;
    }

    // Load Dilithium public key (from local file, not keyserver to avoid circular dependency)
    if (load_my_dilithium_pubkey(ctx, &dilithium_pubkey, &dilithium_pubkey_len) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to load Dilithium public key");
        free(dilithium_privkey);
        return -1;
    }

    // Load Kyber1024 key (ML-KEM-1024)
    if (load_my_kyber_key(ctx, &kyber_key, &kyber_key_len) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to load KEM-1024 key");
        free(dilithium_privkey);
        free(dilithium_pubkey);
        return -1;
    }

    // Load config for bootstrap nodes
    ensure_p2p_config();

    // Configure P2P transport
    p2p_config_t config = {
        .listen_port = 4001,
        .dht_port = 4000,
        .enable_offline_queue = true,   // Phase 9.2: DHT offline message queue
        .offline_ttl_seconds = 604800,  // 7 days (Phase 9.2)
        .bootstrap_count = g_p2p_config.bootstrap_count
    };

    snprintf(config.identity, sizeof(config.identity), "%s", ctx->identity);

    // Add bootstrap nodes from config
    for (int i = 0; i < g_p2p_config.bootstrap_count && i < 16; i++) {
        snprintf(config.bootstrap_nodes[i], sizeof(config.bootstrap_nodes[i]),
                 "%s", g_p2p_config.bootstrap_nodes[i]);
    }

    // Initialize P2P transport
    ctx->p2p_transport = p2p_transport_init(
        &config,
        dilithium_privkey,
        dilithium_pubkey,
        kyber_key,
        p2p_message_received_internal,
        p2p_connection_state_changed,
        ctx  // Pass messenger context as user_data
    );

    // Free keys (they've been copied by p2p_transport_init)
    free(dilithium_privkey);
    free(dilithium_pubkey);
    free(kyber_key);

    if (!ctx->p2p_transport) {
        QGP_LOG_ERROR("P2P", "Failed to initialize P2P transport");
        ctx->p2p_enabled = false;
        return -1;
    }

    // Start P2P transport
    if (p2p_transport_start(ctx->p2p_transport) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to start P2P transport");
        p2p_transport_free(ctx->p2p_transport);
        ctx->p2p_transport = NULL;
        ctx->p2p_enabled = false;
        return -1;
    }

    // Register presence in DHT
    if (p2p_register_presence(ctx->p2p_transport) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to register presence in DHT");
        p2p_transport_free(ctx->p2p_transport);
        ctx->p2p_transport = NULL;
        ctx->p2p_enabled = false;
        return -1;
    }

    ctx->p2p_enabled = true;

    // Initialize presence cache for fast online/offline status
    if (presence_cache_init() != 0) {
        QGP_LOG_ERROR("P2P", "Warning: Failed to initialize presence cache");
    } else {
        QGP_LOG_DEBUG("P2P", "Presence cache initialized");
    }

    QGP_LOG_DEBUG("P2P", "P2P transport initialized successfully");
    QGP_LOG_DEBUG("P2P", "Listening on TCP port 4001");
    QGP_LOG_DEBUG("P2P", "DHT port 4000");
    QGP_LOG_DEBUG("P2P", "Bootstrap nodes: %d configured\n", g_p2p_config.bootstrap_count);

    return 0;
}

void messenger_p2p_shutdown(messenger_context_t *ctx)
{
    if (!ctx || !ctx->p2p_transport) {
        return;
    }

    QGP_LOG_DEBUG("P2P", "Shutting down P2P transport for identity: %s\n", ctx->identity);

    p2p_transport_free(ctx->p2p_transport);
    ctx->p2p_transport = NULL;
    ctx->p2p_enabled = false;

    QGP_LOG_DEBUG("P2P", "P2P transport shutdown complete");
}

// ============================================================================
// P2P MESSAGING (P2P + DHT Offline Queue)
// ============================================================================

int messenger_send_p2p(
    messenger_context_t *ctx,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len)
{
    QGP_LOG_WARN("P2P", ">>> messenger_send_p2p called for %s (len=%zu)\n",
                 recipient ? recipient : "NULL", encrypted_len);

    if (!ctx || !recipient || !encrypted_message || encrypted_len == 0) {
        QGP_LOG_ERROR("P2P", "Invalid parameters");
        return -1;
    }

    QGP_LOG_WARN("P2P", ">>> p2p_enabled=%d, p2p_transport=%p\n",
                 ctx->p2p_enabled, (void*)ctx->p2p_transport);

    // If P2P is not enabled, cannot send message
    if (!ctx->p2p_enabled || !ctx->p2p_transport) {
        QGP_LOG_WARN("P2P", "P2P disabled (enabled=%d, transport=%p), cannot send to %s\n",
                     ctx->p2p_enabled, (void*)ctx->p2p_transport, recipient);
        return -1;  // Cannot send - no transport available
    }

    // Load recipient's public key
    uint8_t *recipient_pubkey = NULL;
    size_t recipient_pubkey_len = 0;

    QGP_LOG_WARN("P2P", ">>> Loading pubkey for %s...\n", recipient);
    if (load_pubkey_for_identity(ctx, recipient, &recipient_pubkey, &recipient_pubkey_len) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to load public key for %s\n", recipient);
        return -1;  // Cannot send without recipient's public key
    }

    QGP_LOG_WARN("P2P", ">>> Calling p2p_send_message (pubkey_len=%zu)...\n", recipient_pubkey_len);

    // Try to send via P2P
    int result = p2p_send_message(
        ctx->p2p_transport,
        recipient_pubkey,
        encrypted_message,
        encrypted_len
    );

    free(recipient_pubkey);

    if (result == 0) {
        QGP_LOG_INFO("P2P", "Message sent to %s via P2P\n", recipient);
        return 0;
    }

    // P2P send failed - try DHT offline queue (Phase 9.2)
    QGP_LOG_WARN("P2P", ">>> P2P send failed (result=%d), trying DHT queue for %s\n", result, recipient);

    // Try to queue in DHT
    if (ctx->p2p_transport) {
        // CRITICAL: Resolve recipient to fingerprint for consistent DHT key
        // Queue key = SHA3-512(recipient_fingerprint + ":offline_queue")
        // Retrieval key = SHA3-512(ctx->identity + ":offline_queue")
        // Both must use fingerprints, not display names!
        char recipient_fingerprint[129];
        if (resolve_identity_to_fingerprint(ctx, recipient, recipient_fingerprint) != 0) {
            QGP_LOG_ERROR("P2P", "Failed to resolve recipient '%s' to fingerprint for DHT queue\n", recipient);
            return -1;
        }

        // Get next sequence number for watermark pruning
        uint64_t seq_num = 1;
        if (ctx->backup_ctx) {
            seq_num = message_backup_get_next_seq(ctx->backup_ctx, recipient_fingerprint);
        }

        int queue_result = p2p_queue_offline_message(
            ctx->p2p_transport,
            ctx->identity,      // sender (should already be fingerprint)
            recipient_fingerprint,  // recipient (NOW using fingerprint!)
            encrypted_message,
            encrypted_len,
            seq_num
        );

        QGP_LOG_WARN("P2P", ">>> p2p_queue_offline_message returned %d (seq=%lu)\n",
               queue_result, (unsigned long)seq_num);
        if (queue_result == 0) {
            QGP_LOG_WARN("P2P", ">>> Message queued in DHT for %s (fingerprint: %.20s..., seq=%lu)\n",
                   recipient, recipient_fingerprint, (unsigned long)seq_num);

            // Start tracking delivery for this recipient (delivery confirmation feature)
            dna_engine_t *engine = dna_engine_get_global();
            if (engine) {
                dna_engine_track_delivery(engine, recipient_fingerprint);
            }

            return 0;  // Success via DHT queue
        } else {
            QGP_LOG_ERROR("P2P", "Failed to queue message in DHT (result=%d)\n", queue_result);
            return -1;  // DHT queue failed - message not delivered
        }
    }

    // No P2P transport available
    QGP_LOG_ERROR("P2P", "No P2P transport available for %s\n", recipient);
    return -1;  // Message not delivered
}

// ============================================================================
// DHT-ONLY MESSAGING (Phase 14)
// ============================================================================

int messenger_queue_to_dht(
    messenger_context_t *ctx,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len)
{
    QGP_LOG_INFO("P2P", "Queueing message to DHT for %s (len=%zu)\n",
                 recipient ? recipient : "NULL", encrypted_len);

    if (!ctx || !recipient || !encrypted_message || encrypted_len == 0) {
        QGP_LOG_ERROR("P2P", "messenger_queue_to_dht: Invalid parameters\n");
        return -1;
    }

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR("P2P", "DHT not available for message queue\n");
        return -1;
    }

    // Resolve recipient to fingerprint for consistent DHT key
    char recipient_fingerprint[129];
    if (resolve_identity_to_fingerprint(ctx, recipient, recipient_fingerprint) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to resolve recipient '%s' to fingerprint for DHT queue\n", recipient);
        return -1;
    }

    // Get next sequence number for watermark pruning
    uint64_t seq_num = 1;
    if (ctx->backup_ctx) {
        seq_num = message_backup_get_next_seq(ctx->backup_ctx, recipient_fingerprint);
    }

    // Queue directly to DHT (Spillway) - call dht_queue_message directly
    // Default TTL: 7 days (604800 seconds)
    int queue_result = dht_queue_message(
        dht_ctx,
        ctx->identity,           // sender (fingerprint)
        recipient_fingerprint,   // recipient (fingerprint)
        encrypted_message,
        encrypted_len,
        seq_num,
        604800  // 7-day TTL
    );

    if (queue_result == 0) {
        QGP_LOG_INFO("P2P", "Message queued in DHT for %s (fp: %.20s..., seq=%lu)\n",
               recipient, recipient_fingerprint, (unsigned long)seq_num);

        // Start tracking delivery for this recipient (delivery confirmation feature)
        dna_engine_t *engine = dna_engine_get_global();
        if (engine) {
            dna_engine_track_delivery(engine, recipient_fingerprint);
        }

        return 0;  // Success
    }

    QGP_LOG_ERROR("P2P", "Failed to queue message in DHT (result=%d)\n", queue_result);
    return -1;
}

int messenger_broadcast_p2p(
    messenger_context_t *ctx,
    const char **recipients,
    size_t recipient_count,
    const uint8_t *encrypted_message,
    size_t encrypted_len)
{
    if (!ctx || !recipients || recipient_count == 0 || !encrypted_message) {
        return -1;
    }

    size_t sent = 0;
    size_t failed = 0;

    for (size_t i = 0; i < recipient_count; i++) {
        if (messenger_send_p2p(ctx, recipients[i], encrypted_message, encrypted_len) == 0) {
            sent++;
        } else {
            failed++;
        }
    }

    QGP_LOG_DEBUG("P2P", "Broadcast complete: %zu sent, %zu failed\n", sent, failed);

    return 0;
}

// ============================================================================
// P2P RECEIVE CALLBACKS
// ============================================================================

static void p2p_message_received_internal(
    const uint8_t *peer_pubkey,
    const char *sender_fingerprint,
    const uint8_t *message,
    size_t message_len,
    void *user_data)
{
    messenger_context_t *ctx = (messenger_context_t*)user_data;
    if (!ctx) {
        QGP_LOG_ERROR("P2P", "Invalid context in message callback");
        return;
    }

    // Determine sender identity from available sources (in priority order):
    // 1. sender_fingerprint (from DHT offline queue - most reliable for offline messages)
    // 2. peer_pubkey lookup (from direct P2P connection)
    // 3. Extract from encrypted message signature (fallback)
    char *sender_identity = NULL;

    if (sender_fingerprint && strlen(sender_fingerprint) > 0) {
        // DHT offline message - sender_fingerprint is the fingerprint directly
        sender_identity = strdup(sender_fingerprint);
        QGP_LOG_INFO("P2P", "Identified sender from DHT queue: %.32s...\n", sender_identity);
    } else if (peer_pubkey) {
        // Direct P2P - lookup identity from pubkey
        sender_identity = lookup_identity_for_pubkey(ctx, peer_pubkey, 2592);
    }

    // If not found via fingerprint or pubkey, try extracting from encrypted message signature
    if (!sender_identity && message && message_len > 0) {
        sender_identity = extract_sender_from_encrypted(ctx, message, message_len);
        if (sender_identity) {
            QGP_LOG_INFO("P2P", "Identified sender from message signature: %s\n", sender_identity);
        }
    }

    if (sender_identity) {
        QGP_LOG_INFO("P2P", "Received P2P message from %s (%zu bytes)\n", sender_identity, message_len);

        // NOTE: Do NOT update presence here. In DHT-only messaging (Phase 14),
        // receiving a queued message does NOT mean sender is online - they may
        // have sent it hours/days ago. Presence comes only from DHT presence
        // listeners and explicit lookups.
    } else {
        QGP_LOG_INFO("P2P", "Received P2P message from unknown peer (%zu bytes)\n", message_len);
        QGP_LOG_DEBUG("P2P", "Hint: Add sender as contact to see their identity");
        sender_identity = strdup("unknown");
    }

    // Store in SQLite local database so messenger_list_messages() can retrieve it
    // The message is already encrypted at this point
    time_t now = time(NULL);

    // Phase 6.2: Detect group invitations by decrypting and checking JSON
    int message_type = MESSAGE_TYPE_CHAT;  // default

    // Try to decrypt message to check if it's an invitation
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    if (dna_decrypt_message(ctx->dna_ctx, message, message_len, ctx->identity,
                            &plaintext, &plaintext_len, NULL, NULL) == DNA_OK && plaintext) {
        // Check if it's JSON with "type": "group_invite"
        json_object *j_msg = json_tokener_parse((const char*)plaintext);
        if (j_msg) {
            json_object *j_type = NULL;
            if (json_object_object_get_ex(j_msg, "type", &j_type)) {
                const char *type_str = json_object_get_string(j_type);
                if (type_str && strcmp(type_str, "group_invite") == 0) {
                    // It's a group invitation!
                    message_type = MESSAGE_TYPE_GROUP_INVITATION;

                    // Extract invitation details
                    json_object *j_uuid = NULL, *j_name = NULL, *j_inviter = NULL, *j_count = NULL;
                    json_object_object_get_ex(j_msg, "group_uuid", &j_uuid);
                    json_object_object_get_ex(j_msg, "group_name", &j_name);
                    json_object_object_get_ex(j_msg, "inviter", &j_inviter);
                    json_object_object_get_ex(j_msg, "member_count", &j_count);

                    if (j_uuid && j_name && j_inviter) {
                        // Store in group_invitations database
                        group_invitation_t invitation = {0};
                        strncpy(invitation.group_uuid, json_object_get_string(j_uuid), sizeof(invitation.group_uuid) - 1);
                        strncpy(invitation.group_name, json_object_get_string(j_name), sizeof(invitation.group_name) - 1);
                        strncpy(invitation.inviter, json_object_get_string(j_inviter), sizeof(invitation.inviter) - 1);
                        invitation.invited_at = now;
                        invitation.status = INVITATION_STATUS_PENDING;
                        invitation.member_count = j_count ? json_object_get_int(j_count) : 0;

                        int store_result = group_invitations_store(&invitation);
                        if (store_result == 0) {
                            QGP_LOG_INFO("P2P", "Group invitation stored: %s (from %s)\n",
                                   invitation.group_name, invitation.inviter);
                        } else if (store_result == -2) {
                            QGP_LOG_DEBUG("P2P", "Group invitation already exists: %s\n", invitation.group_name);
                        } else {
                            QGP_LOG_ERROR("P2P", "Failed to store group invitation");
                        }
                    }
                }
            }
            json_object_put(j_msg);
        }
        free(plaintext);
    }

    int result = message_backup_save(
        ctx->backup_ctx,
        sender_identity,    // sender
        ctx->identity,      // recipient (us)
        message,            // encrypted message
        message_len,        // encrypted length
        now,                // timestamp
        false,              // is_outgoing = false (we're receiving)
        0,                  // group_id = 0 (direct messages for invitations)
        message_type        // message_type (chat or invitation)
    );

    if (result < 0) {
        QGP_LOG_ERROR("P2P", "Failed to store received message in SQLite");
    } else if (result == 0) {
        QGP_LOG_INFO("P2P", "Message from %s stored in SQLite (type=%d)\n", sender_identity, message_type);

        // Emit DNA_EVENT_MESSAGE_RECEIVED to notify Flutter UI
        dna_engine_t *engine = dna_engine_get_global();
        if (engine) {
            dna_event_t event = {0};
            event.type = DNA_EVENT_MESSAGE_RECEIVED;
            // Populate message struct with available info
            strncpy(event.data.message_received.message.sender,
                    sender_identity,
                    sizeof(event.data.message_received.message.sender) - 1);
            strncpy(event.data.message_received.message.recipient,
                    ctx->identity,
                    sizeof(event.data.message_received.message.recipient) - 1);
            event.data.message_received.message.timestamp = (uint64_t)now;
            event.data.message_received.message.is_outgoing = false;
            event.data.message_received.message.message_type = message_type;
            // plaintext is NULL (stored encrypted, decrypted on demand)
            dna_dispatch_event(engine, &event);
            QGP_LOG_DEBUG("P2P", "Dispatched MESSAGE_RECEIVED event for %s\n", sender_identity);
        }
    }
    // result == 1 means duplicate (already exists), not an error

    // Fetch sender profile for caching (only if expired or missing) - Phase 5: Unified Identity
    if (profile_cache_is_expired(sender_identity)) {
        QGP_LOG_DEBUG("P2P", "Fetching profile for sender: %s\n", sender_identity);
        dna_unified_identity_t *identity = NULL;
        int profile_result = profile_manager_get_profile(sender_identity, &identity);
        if (profile_result == 0 && identity) {
            QGP_LOG_INFO("P2P", "Identity cached: %s\n", identity->display_name[0] ? identity->display_name : sender_identity);
            dna_identity_free(identity);
        } else if (profile_result == -2) {
            QGP_LOG_DEBUG("P2P", "Profile not found for sender: %s\n", sender_identity);
        } else {
            QGP_LOG_ERROR("P2P", "Failed to fetch profile for sender: %s\n", sender_identity);
        }
    }

    free(sender_identity);
}

static void p2p_connection_state_changed(
    const uint8_t *peer_pubkey,
    bool is_connected,
    void *user_data)
{
    messenger_context_t *ctx = (messenger_context_t*)user_data;
    if (!ctx) {
        return;
    }

    char *peer_identity = lookup_identity_for_pubkey(ctx, peer_pubkey, 2592);  // Dilithium5 public key size
    if (peer_identity) {
        QGP_LOG_DEBUG("P2P", "%s %s\n", peer_identity, is_connected ? "CONNECTED" : "DISCONNECTED");

        // Update presence cache on connection state change
        presence_cache_update(peer_identity, is_connected, time(NULL));

        free(peer_identity);
    } else {
        QGP_LOG_DEBUG("P2P", "Unknown peer %s\n", is_connected ? "CONNECTED" : "DISCONNECTED");
    }
}

void messenger_p2p_message_callback(
    const char *identity,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    // This is the external wrapper for messenger_p2p.h
    // The actual callback used internally is p2p_message_received_internal
    // which uses pubkeys instead of identities
    QGP_LOG_DEBUG("P2P", "External message callback for %s (%zu bytes)\n", identity, len);
}

// ============================================================================
// PRESENCE & PEER DISCOVERY
// ============================================================================

bool messenger_p2p_peer_online(messenger_context_t *ctx, const char *identity)
{
    if (!ctx || !identity) {
        return false;
    }

    // Use presence cache for fast O(1) lookup (no DHT query!)
    // Cache is passively updated when:
    // - Message received from peer (online)
    // - P2P connection established (online)
    // - P2P connection lost (offline)
    // - Cache entry expires after 5 minutes (assume offline)
    return presence_cache_get(identity);
}

int messenger_p2p_list_online_peers(
    messenger_context_t *ctx,
    char ***identities_out,
    int *count_out)
{
    if (!ctx || !identities_out || !count_out) {
        return -1;
    }

    // This requires iterating through the keyserver and checking each identity
    // For now, return empty list (can be implemented later if needed)
    *identities_out = NULL;
    *count_out = 0;
    return 0;
}

int messenger_p2p_refresh_presence(messenger_context_t *ctx)
{
    if (!ctx) {
        return -1;
    }

    // Phase 14: DHT-only messaging - P2P transport reserved for voice/video only
    QGP_LOG_DEBUG("P2P", "Refreshing presence in DHT for %s", ctx->identity);

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR("P2P", "DHT not available for presence refresh");
        return -1;
    }

    // Load my Dilithium public key to compute DHT key
    uint8_t *pubkey = NULL;
    size_t pubkey_len = 0;
    if (load_my_dilithium_pubkey(ctx, &pubkey, &pubkey_len) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to load public key for presence refresh");
        return -1;
    }

    // Get public IP via STUN
    char my_ip[64] = {0};
    if (stun_get_public_ip(my_ip, sizeof(my_ip)) != 0) {
        QGP_LOG_ERROR("P2P", "STUN query failed - cannot register presence without public IP");
        free(pubkey);
        return -1;
    }
    QGP_LOG_DEBUG("P2P", "STUN discovered public IP: %s", my_ip);

    // Create presence JSON (port=0 since we're not listening for P2P connections)
    char presence_data[512];
    if (create_presence_json(my_ip, 0, presence_data, sizeof(presence_data)) != 0) {
        QGP_LOG_ERROR("P2P", "Failed to create presence JSON");
        free(pubkey);
        return -1;
    }

    // Compute DHT key: SHA3-512(public_key)
    uint8_t dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(pubkey, pubkey_len, dht_key);
    free(pubkey);

    QGP_LOG_DEBUG("P2P", "Registering presence in DHT");
    QGP_LOG_DEBUG("P2P", "DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);

    // Store in DHT (signed, 7-day TTL, value_id=1 for replacement)
    unsigned int ttl_7days = 7 * 24 * 3600;  // 604800 seconds
    int result = dht_put_signed(dht, dht_key, sizeof(dht_key),
                                (const uint8_t*)presence_data, strlen(presence_data),
                                1, ttl_7days);

    if (result != 0) {
        QGP_LOG_ERROR("P2P", "Failed to register presence in DHT");
        return -1;
    }

    QGP_LOG_DEBUG("P2P", "Presence refreshed successfully");
    return 0;
}

int messenger_p2p_lookup_presence(
    messenger_context_t *ctx,
    const char *fingerprint,
    uint64_t *last_seen_out)
{
    if (!ctx || !fingerprint || !last_seen_out) {
        return -1;
    }

    *last_seen_out = 0;

    // Use DHT singleton for presence lookup - doesn't require P2P transport
    // This allows presence to work even when P2P is disabled (Phase 14: DHT-only messaging)
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR("P2P", "DHT not available for presence lookup");
        return -1;
    }

    // Validate fingerprint length (128 hex chars)
    size_t fp_len = strlen(fingerprint);
    if (fp_len != 128) {
        QGP_LOG_DEBUG("P2P", "Invalid fingerprint length: %zu (expected 128)", fp_len);
        return -1;
    }

    // Convert hex fingerprint to binary DHT key (64 bytes)
    uint8_t dht_key[64];
    for (int i = 0; i < 64; i++) {
        unsigned int byte;
        if (sscanf(fingerprint + (i * 2), "%02x", &byte) != 1) {
            QGP_LOG_DEBUG("P2P", "Invalid fingerprint hex at position %d", i * 2);
            return -1;
        }
        dht_key[i] = (uint8_t)byte;
    }

    QGP_LOG_DEBUG("P2P", "Looking up presence for: %.16s...", fingerprint);

    // Query DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
        QGP_LOG_DEBUG("P2P", "Presence not found in DHT for %.16s...", fingerprint);
        return -1;
    }

    // Parse JSON to extract timestamp
    peer_info_t peer_info;
    memset(&peer_info, 0, sizeof(peer_info));

    if (parse_presence_json((const char*)value, &peer_info) != 0) {
        QGP_LOG_DEBUG("P2P", "Failed to parse presence JSON");
        free(value);
        return -1;
    }

    *last_seen_out = peer_info.last_seen;
    free(value);

    QGP_LOG_DEBUG("P2P", "Presence lookup successful: last_seen=%lu", (unsigned long)*last_seen_out);
    return 0;
}

// ============================================================================
// OFFLINE MESSAGE QUEUE (Phase 9.2)
// ============================================================================

int messenger_p2p_check_offline_messages(
    messenger_context_t *ctx,
    size_t *messages_received)
{
    if (!ctx || !ctx->p2p_enabled || !ctx->p2p_transport) {
        if (messages_received) *messages_received = 0;
        return -1;
    }

    QGP_LOG_DEBUG("P2P", "Checking for offline messages in DHT...");

    size_t count = 0;
    int result = p2p_check_offline_messages(ctx->p2p_transport, &count);

    if (result == 0 && count > 0) {
        QGP_LOG_INFO("P2P", "Retrieved %zu offline messages from DHT\n", count);
        // Messages are automatically delivered via p2p_message_received_internal()
        // which stores them in SQLite for GUI retrieval
        // Note: Group sync is handled separately by messenger_sync_groups() which
        // calls this function internally to avoid circular dependencies
    } else if (result == 0 && count == 0) {
        QGP_LOG_DEBUG("P2P", "No offline messages in DHT");
    } else {
        QGP_LOG_ERROR("P2P", "Failed to check offline messages");
    }

    if (messages_received) {
        *messages_received = count;
    }

    return result;
}
