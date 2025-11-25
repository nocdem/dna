/*
 * DNA Messenger - P2P Integration Layer Implementation
 *
 * Phase 9.1b: Hybrid P2P Transport Integration
 */

#include "messenger_p2p.h"
#include "messenger.h"
#include "p2p/p2p_transport.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/shared/dht_groups.h"
#include "dht/core/dht_keyserver.h"
#include "dht/core/dht_context.h"
#include "dht/core/dht_listen.h"
#include "database/keyserver_cache.h"
#include "database/contacts_db.h"
#include "database/group_invitations.h"
#include "crypto/utils/qgp_sha3.h"
#include "database/presence_cache.h"
#include "database/profile_manager.h"
#include "database/profile_cache.h"
#include "dna_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <pthread.h>

// Platform-specific headers for home directory detection
#ifndef _WIN32
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#endif

// Bootstrap nodes (hardcoded from Phase 9.1 deployment)
static const char *BOOTSTRAP_NODES[] = {
    "154.38.182.161:4000",    // dna-bootstrap-us-1
    "164.68.105.227:4000",    // dna-bootstrap-eu-1
    "164.68.116.180:4000"     // dna-bootstrap-eu-2
};
#define BOOTSTRAP_COUNT 3

// ============================================================================
// PUSH NOTIFICATION SUBSCRIPTION MANAGEMENT (Phase 10.1)
// ============================================================================

// Subscription entry for tracking DHT listen() tokens
typedef struct {
    char *contact_fingerprint;  // Contact whose outbox we're watching
    size_t listen_token;         // DHT listen() token
} subscription_entry_t;

// Global subscription manager
typedef struct {
    subscription_entry_t *subscriptions;
    size_t count;
    size_t capacity;
    pthread_mutex_t mutex;
    messenger_context_t *messenger_ctx;  // Context for message delivery
} subscription_manager_t;

static subscription_manager_t g_subscription_manager = {
    .subscriptions = NULL,
    .count = 0,
    .capacity = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .messenger_ctx = NULL
};

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
    // Get home directory
    const char *home = NULL;

#ifdef _WIN32
    home = getenv("USERPROFILE");
    if (!home) {
        static char win_home[512];
        const char *homedrive = getenv("HOMEDRIVE");
        const char *homepath = getenv("HOMEPATH");
        if (homedrive && homepath) {
            snprintf(win_home, sizeof(win_home), "%s%s", homedrive, homepath);
            home = win_home;
        }
    }
#else
    home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
#endif

    if (!home) {
        fprintf(stderr, "[P2P] Cannot determine home directory\n");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa",
             home, ctx->identity);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "[P2P] Failed to open key file: %s\n", key_path);
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
        fprintf(stderr, "[P2P] Invalid public key size: %zu (expected 2592)\n", read);
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
        fprintf(stderr, "[P2P] Failed to load public key for identity: %s\n", identity);
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
        fprintf(stderr, "[P2P] Failed to resolve identity to fingerprint: %s\n", identity);
        return -1;
    }

    // Free keys (we only needed the fingerprint)
    free(signing_pubkey);
    free(encryption_pubkey);

    return 0;
}

/**
 * Load my own Dilithium private key from ~/.dna/
 *
 * @return: 0 on success, -1 on error
 */
static int load_my_privkey(
    messenger_context_t *ctx,
    uint8_t **privkey_out,
    size_t *privkey_len_out
)
{
    // Get home directory (platform-specific)
    const char *home = NULL;

#ifdef _WIN32
    // Windows: Try USERPROFILE first, then HOMEDRIVE+HOMEPATH
    home = getenv("USERPROFILE");
    if (!home) {
        static char win_home[512];
        const char *homedrive = getenv("HOMEDRIVE");
        const char *homepath = getenv("HOMEPATH");
        if (homedrive && homepath) {
            snprintf(win_home, sizeof(win_home), "%s%s", homedrive, homepath);
            home = win_home;
        }
    }
#else
    // Linux/POSIX: Try HOME first, then getpwuid() fallback
    home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
#endif

    if (!home) {
        fprintf(stderr, "[P2P] Cannot determine home directory\n");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa",
             home, ctx->identity);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "[P2P] Failed to open private key: %s\n", key_path);
        return -1;
    }

    // Dilithium5 private key (ML-DSA-87) is 4896 bytes
    // NOTE: Legacy keys may be 4016 bytes (Dilithium3) - migration needed
    uint8_t *privkey = malloc(4896);
    if (!privkey) {
        fclose(f);
        return -1;
    }

    size_t read = fread(privkey, 1, 4896, f);
    fclose(f);

    if (read != 4896) {
        fprintf(stderr, "[P2P] Invalid private key size: %zu (expected 4896 for Dilithium5)\n", read);
        free(privkey);
        return -1;
    }

    *privkey_out = privkey;
    *privkey_len_out = 4896;
    return 0;
}

/**
 * Load my own Kyber1024 private key (ML-KEM-1024) from ~/.dna/
 *
 * @return: 0 on success, -1 on error
 */
static int load_my_kyber_key(
    messenger_context_t *ctx,
    uint8_t **kyber_key_out,
    size_t *kyber_key_len_out
)
{
    // Get home directory (platform-specific)
    const char *home = NULL;

#ifdef _WIN32
    // Windows: Try USERPROFILE first, then HOMEDRIVE+HOMEPATH
    home = getenv("USERPROFILE");
    if (!home) {
        static char win_home[512];
        const char *homedrive = getenv("HOMEDRIVE");
        const char *homepath = getenv("HOMEPATH");
        if (homedrive && homepath) {
            snprintf(win_home, sizeof(win_home), "%s%s", homedrive, homepath);
            home = win_home;
        }
    }
#else
    // Linux/POSIX: Try HOME first, then getpwuid() fallback
    home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
#endif

    if (!home) {
        fprintf(stderr, "[P2P] Cannot determine home directory\n");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.kem",
             home, ctx->identity);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "[P2P] Failed to open Kyber key: %s\n", key_path);
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
        fprintf(stderr, "[P2P] Invalid Kyber key size: %zu (expected 3168 for Kyber1024)\n", read);
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
    printf("[P2P] Sender not in contacts, querying DHT reverse mapping...\n");

    // Compute fingerprint as hex string (SHA3-512 of pubkey)
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    qgp_sha3_512(signing_pubkey, 2592, hash);  // Dilithium5 public key size

    char fingerprint[129];  // SHA3-512 hex string = 128 chars + null
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';  // Null-terminate at position 128

    // Get DHT context from P2P transport
    dht_context_t *dht_ctx = ctx->p2p_transport ? p2p_transport_get_dht_context(ctx->p2p_transport) : NULL;
    if (!dht_ctx) {
        printf("[P2P] ✗ No DHT context available for reverse lookup\n");
        return NULL;
    }

    // Query DHT for reverse mapping (fingerprint → identity)
    char *identity = NULL;
    int result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &identity);

    if (result == 0 && identity) {
        printf("[P2P] ✓ DHT reverse lookup found: %s (fingerprint: %.16s...)\n", identity, fingerprint);

        // Cache the identity in contacts for faster lookup next time
        // (User can add them to contacts manually later if they want)
        return identity;  // Caller must free
    } else if (result == -2) {
        printf("[P2P] ✗ Identity not found in DHT (fingerprint: %.16s...)\n", fingerprint);
    } else if (result == -3) {
        printf("[P2P] ✗ DHT reverse mapping signature verification failed (fingerprint: %.16s...)\n", fingerprint);
    } else {
        printf("[P2P] ✗ DHT reverse lookup error (fingerprint: %.16s...)\n", fingerprint);
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

    // Get DHT context from P2P transport
    dht_context_t *dht_ctx = ctx->p2p_transport ? p2p_transport_get_dht_context(ctx->p2p_transport) : NULL;
    if (!dht_ctx) {
        return NULL;  // No DHT context
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
        fprintf(stderr, "[P2P] Invalid messenger context\n");
        return -1;
    }

    printf("[P2P] Initializing P2P transport for identity: %s\n", ctx->identity);

    // Load my private keys
    uint8_t *dilithium_privkey = NULL;
    size_t dilithium_privkey_len = 0;
    uint8_t *dilithium_pubkey = NULL;
    size_t dilithium_pubkey_len = 0;
    uint8_t *kyber_key = NULL;
    size_t kyber_key_len = 0;

    // Load Dilithium private key
    if (load_my_privkey(ctx, &dilithium_privkey, &dilithium_privkey_len) != 0) {
        fprintf(stderr, "[P2P] Failed to load Dilithium private key\n");
        return -1;
    }

    // Load Dilithium public key (from local file, not keyserver to avoid circular dependency)
    if (load_my_dilithium_pubkey(ctx, &dilithium_pubkey, &dilithium_pubkey_len) != 0) {
        fprintf(stderr, "[P2P] Failed to load Dilithium public key\n");
        free(dilithium_privkey);
        return -1;
    }

    // Load Kyber1024 key (ML-KEM-1024)
    if (load_my_kyber_key(ctx, &kyber_key, &kyber_key_len) != 0) {
        fprintf(stderr, "[P2P] Failed to load KEM-1024 key\n");
        free(dilithium_privkey);
        free(dilithium_pubkey);
        return -1;
    }

    // Configure P2P transport
    p2p_config_t config = {
        .listen_port = 4001,
        .dht_port = 4000,
        .enable_offline_queue = true,   // Phase 9.2: DHT offline message queue
        .offline_ttl_seconds = 604800,  // 7 days (Phase 9.2)
        .bootstrap_count = BOOTSTRAP_COUNT
    };

    snprintf(config.identity, sizeof(config.identity), "%s", ctx->identity);

    // Add bootstrap nodes
    for (size_t i = 0; i < BOOTSTRAP_COUNT; i++) {
        snprintf(config.bootstrap_nodes[i], sizeof(config.bootstrap_nodes[i]),
                 "%s", BOOTSTRAP_NODES[i]);
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
        fprintf(stderr, "[P2P] Failed to initialize P2P transport\n");
        ctx->p2p_enabled = false;
        return -1;
    }

    // Start P2P transport
    if (p2p_transport_start(ctx->p2p_transport) != 0) {
        fprintf(stderr, "[P2P] Failed to start P2P transport\n");
        p2p_transport_free(ctx->p2p_transport);
        ctx->p2p_transport = NULL;
        ctx->p2p_enabled = false;
        return -1;
    }

    // Register presence in DHT
    if (p2p_register_presence(ctx->p2p_transport) != 0) {
        fprintf(stderr, "[P2P] Failed to register presence in DHT\n");
        p2p_transport_free(ctx->p2p_transport);
        ctx->p2p_transport = NULL;
        ctx->p2p_enabled = false;
        return -1;
    }

    ctx->p2p_enabled = true;

    // Initialize presence cache for fast online/offline status
    if (presence_cache_init() != 0) {
        fprintf(stderr, "[P2P] Warning: Failed to initialize presence cache\n");
    } else {
        printf("[P2P] Presence cache initialized\n");
    }

    printf("[P2P] P2P transport initialized successfully\n");
    printf("[P2P] Listening on TCP port 4001\n");
    printf("[P2P] DHT port 4000\n");
    printf("[P2P] Bootstrap nodes: %zu configured\n", BOOTSTRAP_COUNT);

    return 0;
}

void messenger_p2p_shutdown(messenger_context_t *ctx)
{
    if (!ctx || !ctx->p2p_transport) {
        return;
    }

    printf("[P2P] Shutting down P2P transport for identity: %s\n", ctx->identity);

    // Cancel all push notification subscriptions
    messenger_p2p_unsubscribe_all(ctx);

    p2p_transport_free(ctx->p2p_transport);
    ctx->p2p_transport = NULL;
    ctx->p2p_enabled = false;

    printf("[P2P] P2P transport shutdown complete\n");
}

// ============================================================================
// HYBRID MESSAGING (P2P + PostgreSQL Fallback)
// ============================================================================

int messenger_send_p2p(
    messenger_context_t *ctx,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len)
{
    if (!ctx || !recipient || !encrypted_message || encrypted_len == 0) {
        fprintf(stderr, "[P2P] Invalid parameters\n");
        return -1;
    }

    // If P2P is not enabled, fall back to PostgreSQL immediately
    if (!ctx->p2p_enabled || !ctx->p2p_transport) {
        printf("[P2P] P2P disabled, using PostgreSQL fallback for %s\n", recipient);
        // Fallback to PostgreSQL will be handled by caller
        return -1;  // Signal to use PostgreSQL
    }

    // Load recipient's public key
    uint8_t *recipient_pubkey = NULL;
    size_t recipient_pubkey_len = 0;

    if (load_pubkey_for_identity(ctx, recipient, &recipient_pubkey, &recipient_pubkey_len) != 0) {
        fprintf(stderr, "[P2P] Failed to load public key for %s, using PostgreSQL fallback\n", recipient);
        return -1;  // Fallback to PostgreSQL
    }

    printf("[P2P] Attempting to send message to %s via P2P...\n", recipient);

    // Try to send via P2P
    int result = p2p_send_message(
        ctx->p2p_transport,
        recipient_pubkey,
        encrypted_message,
        encrypted_len
    );

    free(recipient_pubkey);

    if (result == 0) {
        printf("[P2P] ✓ Message sent to %s via P2P\n", recipient);
        return 0;
    }

    // P2P send failed - try DHT offline queue (Phase 9.2)
    printf("[P2P] P2P send failed for %s\n", recipient);

    // Try to queue in DHT
    if (ctx->p2p_transport) {
        // CRITICAL: Resolve recipient to fingerprint for consistent DHT key
        // Queue key = SHA3-512(recipient_fingerprint + ":offline_queue")
        // Retrieval key = SHA3-512(ctx->identity + ":offline_queue")
        // Both must use fingerprints, not display names!
        char recipient_fingerprint[129];
        if (resolve_identity_to_fingerprint(ctx, recipient, recipient_fingerprint) != 0) {
            fprintf(stderr, "[P2P] Failed to resolve recipient '%s' to fingerprint for DHT queue\n", recipient);
            return -1;
        }

        printf("[P2P] Resolved '%s' → fingerprint for DHT queue\n", recipient);

        int queue_result = p2p_queue_offline_message(
            ctx->p2p_transport,
            ctx->identity,      // sender (should already be fingerprint)
            recipient_fingerprint,  // recipient (NOW using fingerprint!)
            encrypted_message,
            encrypted_len
        );

        if (queue_result == 0) {
            printf("[P2P] ✓ Message queued in DHT for %s (fingerprint: %.20s...)\n",
                   recipient, recipient_fingerprint);
            return 0;  // Success via DHT queue
        } else {
            fprintf(stderr, "[P2P] Failed to queue in DHT, using PostgreSQL fallback\n");
        }
    }

    // Fall back to PostgreSQL
    printf("[P2P] Using PostgreSQL fallback for %s\n", recipient);
    return -1;  // Signal to use PostgreSQL fallback
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

    size_t p2p_sent = 0;
    size_t pg_fallback = 0;

    for (size_t i = 0; i < recipient_count; i++) {
        if (messenger_send_p2p(ctx, recipients[i], encrypted_message, encrypted_len) == 0) {
            p2p_sent++;
        } else {
            pg_fallback++;
            // Caller should handle PostgreSQL insertion for failed sends
        }
    }

    printf("[P2P] Broadcast complete: %zu via P2P, %zu via PostgreSQL\n",
           p2p_sent, pg_fallback);

    return 0;
}

// ============================================================================
// P2P RECEIVE CALLBACKS
// ============================================================================

static void p2p_message_received_internal(
    const uint8_t *peer_pubkey,
    const uint8_t *message,
    size_t message_len,
    void *user_data)
{
    messenger_context_t *ctx = (messenger_context_t*)user_data;
    if (!ctx) {
        fprintf(stderr, "[P2P] Invalid context in message callback\n");
        return;
    }

    // Lookup identity for this pubkey (may be NULL if no handshake yet)
    char *sender_identity = NULL;
    if (peer_pubkey) {
        sender_identity = lookup_identity_for_pubkey(ctx, peer_pubkey, 2592);  // Dilithium5 public key size
    }

    // If not found via pubkey, try extracting from encrypted message signature
    if (!sender_identity && message && message_len > 0) {
        sender_identity = extract_sender_from_encrypted(ctx, message, message_len);
        if (sender_identity) {
            printf("[P2P] ✓ Identified sender from message signature: %s\n", sender_identity);
        }
    }

    if (sender_identity) {
        printf("[P2P] ✓ Received P2P message from %s (%zu bytes)\n", sender_identity, message_len);

        // Passive presence detection: message received = sender online
        presence_cache_update(sender_identity, true, time(NULL));
    } else {
        printf("[P2P] ✓ Received P2P message from unknown peer (%zu bytes)\n", message_len);
        printf("[P2P] Hint: Add sender as contact to see their identity\n");
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
                            printf("[P2P] ✓ Group invitation stored: %s (from %s)\n",
                                   invitation.group_name, invitation.inviter);
                        } else if (store_result == -2) {
                            printf("[P2P] Group invitation already exists: %s\n", invitation.group_name);
                        } else {
                            fprintf(stderr, "[P2P] Failed to store group invitation\n");
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

    if (result != 0) {
        fprintf(stderr, "[P2P] Failed to store received message in SQLite\n");
    } else {
        printf("[P2P] ✓ Message from %s stored in SQLite (type=%d)\n", sender_identity, message_type);
    }

    // Fetch sender profile for caching (only if expired or missing) - Phase 5: Unified Identity
    if (profile_cache_is_expired(sender_identity)) {
        printf("[P2P] Fetching profile for sender: %s\n", sender_identity);
        dna_unified_identity_t *identity = NULL;
        int profile_result = profile_manager_get_profile(sender_identity, &identity);
        if (profile_result == 0 && identity) {
            printf("[P2P] ✓ Identity cached: %s\n", identity->display_name[0] ? identity->display_name : sender_identity);
            dna_identity_free(identity);
        } else if (profile_result == -2) {
            printf("[P2P] Profile not found for sender: %s\n", sender_identity);
        } else {
            fprintf(stderr, "[P2P] Failed to fetch profile for sender: %s\n", sender_identity);
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
        printf("[P2P] %s %s\n", peer_identity, is_connected ? "CONNECTED" : "DISCONNECTED");

        // Update presence cache on connection state change
        presence_cache_update(peer_identity, is_connected, time(NULL));

        free(peer_identity);
    } else {
        printf("[P2P] Unknown peer %s\n", is_connected ? "CONNECTED" : "DISCONNECTED");
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
    printf("[P2P] External message callback for %s (%zu bytes)\n", identity, len);
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
    if (!ctx || !ctx->p2p_enabled || !ctx->p2p_transport) {
        return -1;
    }

    printf("[P2P] Refreshing presence in DHT for %s\n", ctx->identity);

    if (p2p_register_presence(ctx->p2p_transport) != 0) {
        fprintf(stderr, "[P2P] Failed to refresh presence\n");
        return -1;
    }

    printf("[P2P] Presence refreshed successfully\n");
    return 0;
}

// ============================================================================
// PUSH NOTIFICATION CALLBACKS (Phase 10.1)
// ============================================================================

/**
 * Push notification callback - invoked when DHT listen() receives values
 * Runs on DHT worker thread, must be thread-safe
 */
static bool messenger_push_notification_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    messenger_context_t *ctx = (messenger_context_t*)user_data;

    if (expired) {
        printf("[P2P Push] Received expiration notification\n");
        return true;  // Continue listening
    }

    if (!value || value_len == 0) {
        return true;  // Continue listening
    }

    printf("[P2P Push] Received notification (%zu bytes)\n", value_len);

    // Deserialize offline messages
    dht_offline_message_t *messages = NULL;
    size_t count = 0;
    int result = dht_deserialize_messages(value, value_len, &messages, &count);

    if (result != 0 || count == 0) {
        fprintf(stderr, "[P2P Push] Failed to deserialize messages\n");
        return true;  // Continue listening despite error
    }

    printf("[P2P Push] Deserialized %zu message(s)\n", count);

    // Deliver each message via P2P callback (same path as polling)
    if (ctx->p2p_transport) {
        for (size_t i = 0; i < count; i++) {
            dht_offline_message_t *msg = &messages[i];

            printf("[P2P Push] Delivering message %zu/%zu from %s (%zu bytes)\n",
                   i + 1, count, msg->sender, msg->ciphertext_len);

            p2p_transport_deliver_message(
                ctx->p2p_transport,
                NULL,  // peer_pubkey (unknown for offline messages)
                msg->ciphertext,
                msg->ciphertext_len
            );
        }
    }

    dht_offline_messages_free(messages, count);
    return true;  // Continue listening
}

/**
 * Subscribe to a single contact's outbox for push notifications
 */
int messenger_p2p_subscribe_to_contact(
    messenger_context_t *ctx,
    const char *contact_fingerprint)
{
    if (!ctx || !contact_fingerprint) {
        return -1;
    }

    // Generate outbox key
    uint8_t outbox_key[64];
    dht_generate_outbox_key(contact_fingerprint, ctx->fingerprint, outbox_key);

    // Start listening
    dht_context_t *dht = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht) {
        fprintf(stderr, "[P2P Push] Failed to get DHT context\n");
        return -1;
    }

    size_t token = dht_listen(
        dht,
        outbox_key,
        64,
        messenger_push_notification_callback,
        ctx
    );

    if (token == 0) {
        fprintf(stderr, "[P2P Push] Failed to subscribe to %s\n", contact_fingerprint);
        return -1;
    }

    // Add to subscription manager
    pthread_mutex_lock(&g_subscription_manager.mutex);

    // Expand array if needed
    if (g_subscription_manager.count >= g_subscription_manager.capacity) {
        size_t new_capacity = g_subscription_manager.capacity == 0 ? 16 : g_subscription_manager.capacity * 2;
        subscription_entry_t *new_subs = (subscription_entry_t*)realloc(
            g_subscription_manager.subscriptions,
            new_capacity * sizeof(subscription_entry_t)
        );

        if (!new_subs) {
            pthread_mutex_unlock(&g_subscription_manager.mutex);
            dht_cancel_listen(dht, token);
            return -1;
        }

        g_subscription_manager.subscriptions = new_subs;
        g_subscription_manager.capacity = new_capacity;
    }

    // Add entry
    subscription_entry_t *entry = &g_subscription_manager.subscriptions[g_subscription_manager.count];
    entry->contact_fingerprint = strdup(contact_fingerprint);
    entry->listen_token = token;
    g_subscription_manager.count++;

    pthread_mutex_unlock(&g_subscription_manager.mutex);

    printf("[P2P Push] ✓ Subscribed to %s (token: %zu)\n", contact_fingerprint, token);
    return 0;
}

/**
 * Subscribe to all contacts' outboxes for push notifications
 */
int messenger_p2p_subscribe_to_contacts(messenger_context_t *ctx)
{
    if (!ctx || !ctx->p2p_enabled || !ctx->p2p_transport) {
        fprintf(stderr, "[P2P Push] P2P not enabled\n");
        return -1;
    }

    printf("[P2P Push] Subscribing to all contacts' outboxes...\n");

    // Store messenger context for callback
    pthread_mutex_lock(&g_subscription_manager.mutex);
    g_subscription_manager.messenger_ctx = ctx;
    pthread_mutex_unlock(&g_subscription_manager.mutex);

    // Load contacts from database
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts || contacts->count == 0) {
        printf("[P2P Push] No contacts in database, nothing to subscribe to\n");
        return 0;
    }

    printf("[P2P Push] Found %zu contacts\n", contacts->count);

    // Subscribe to each contact
    size_t success_count = 0;
    for (size_t i = 0; i < contacts->count; i++) {
        const char *contact_fp = contacts->contacts[i].identity;

        if (messenger_p2p_subscribe_to_contact(ctx, contact_fp) == 0) {
            success_count++;
        }
    }

    contacts_db_free_list(contacts);

    printf("[P2P Push] ✓ Subscribed to %zu/%zu contacts\n", success_count, contacts->count);
    return 0;
}

/**
 * Unsubscribe from a single contact's outbox
 */
int messenger_p2p_unsubscribe_from_contact(
    messenger_context_t *ctx,
    const char *contact_fingerprint)
{
    if (!ctx || !contact_fingerprint) {
        return -1;
    }

    pthread_mutex_lock(&g_subscription_manager.mutex);

    // Find subscription
    size_t found_index = (size_t)-1;
    for (size_t i = 0; i < g_subscription_manager.count; i++) {
        if (strcmp(g_subscription_manager.subscriptions[i].contact_fingerprint, contact_fingerprint) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index == (size_t)-1) {
        pthread_mutex_unlock(&g_subscription_manager.mutex);
        printf("[P2P Push] No subscription found for %s\n", contact_fingerprint);
        return -1;
    }

    // Cancel DHT subscription
    subscription_entry_t *entry = &g_subscription_manager.subscriptions[found_index];
    dht_context_t *dht = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (dht) {
        dht_cancel_listen(dht, entry->listen_token);
    }

    // Free resources
    free(entry->contact_fingerprint);

    // Remove from array (swap with last element)
    if (found_index < g_subscription_manager.count - 1) {
        g_subscription_manager.subscriptions[found_index] =
            g_subscription_manager.subscriptions[g_subscription_manager.count - 1];
    }
    g_subscription_manager.count--;

    pthread_mutex_unlock(&g_subscription_manager.mutex);

    printf("[P2P Push] ✓ Unsubscribed from %s\n", contact_fingerprint);
    return 0;
}

/**
 * Unsubscribe from all contacts' outboxes
 */
void messenger_p2p_unsubscribe_all(messenger_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    pthread_mutex_lock(&g_subscription_manager.mutex);

    printf("[P2P Push] Unsubscribing from %zu contacts...\n", g_subscription_manager.count);

    if (ctx->p2p_transport) {
        dht_context_t *dht = p2p_transport_get_dht_context(ctx->p2p_transport);

        // Cancel all subscriptions
        for (size_t i = 0; i < g_subscription_manager.count; i++) {
            subscription_entry_t *entry = &g_subscription_manager.subscriptions[i];
            if (dht) {
                dht_cancel_listen(dht, entry->listen_token);
            }
            free(entry->contact_fingerprint);
        }
    }

    // Free array
    free(g_subscription_manager.subscriptions);
    g_subscription_manager.subscriptions = NULL;
    g_subscription_manager.count = 0;
    g_subscription_manager.capacity = 0;
    g_subscription_manager.messenger_ctx = NULL;

    pthread_mutex_unlock(&g_subscription_manager.mutex);

    printf("[P2P Push] ✓ All subscriptions cancelled\n");
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

    printf("[P2P] Checking for offline messages in DHT...\n");

    size_t count = 0;
    int result = p2p_check_offline_messages(ctx->p2p_transport, &count);

    if (result == 0 && count > 0) {
        printf("[P2P] ✓ Retrieved %zu offline messages from DHT\n", count);
        // Messages are automatically delivered via p2p_message_received_internal()
        // which stores them in SQLite for GUI retrieval
        // Note: Group sync is handled separately by messenger_sync_groups() which
        // calls this function internally to avoid circular dependencies
    } else if (result == 0 && count == 0) {
        printf("[P2P] No offline messages in DHT\n");
    } else {
        fprintf(stderr, "[P2P] Failed to check offline messages\n");
    }

    if (messages_received) {
        *messages_received = count;
    }

    return result;
}
