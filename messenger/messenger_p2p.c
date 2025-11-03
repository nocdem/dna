/*
 * DNA Messenger - P2P Integration Layer Implementation
 *
 * Phase 9.1b: Hybrid P2P Transport Integration
 */

#include "messenger_p2p.h"
#include "messenger.h"
#include "p2p/p2p_transport.h"
#include "dht/dht_offline_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s-dilithium3.pqkey",
             home, ctx->identity);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "[P2P] Failed to open key file: %s\n", key_path);
        return -1;
    }

    // Skip private key part (4016 bytes) and read public key (1952 bytes)
    fseek(f, 4016, SEEK_SET);

    uint8_t *pubkey = malloc(1952);
    if (!pubkey) {
        fclose(f);
        return -1;
    }

    size_t read = fread(pubkey, 1, 1952, f);
    fclose(f);

    if (read != 1952) {
        fprintf(stderr, "[P2P] Invalid public key size: %zu (expected 1952)\n", read);
        free(pubkey);
        return -1;
    }

    *pubkey_out = pubkey;
    *pubkey_len_out = 1952;
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

    // Load public keys from keyserver
    if (messenger_load_pubkey(ctx, identity, &signing_pubkey, &signing_len,
                              &encryption_pubkey, &encryption_len) != 0) {
        fprintf(stderr, "[P2P] Failed to load public key for identity: %s\n", identity);
        return -1;
    }

    // We only need the signing key (Dilithium3) for P2P transport
    *pubkey_out = signing_pubkey;
    *pubkey_len_out = signing_len;

    // Free encryption key (not needed for P2P layer)
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
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s-dilithium3.pqkey",
             home, ctx->identity);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "[P2P] Failed to open private key: %s\n", key_path);
        return -1;
    }

    // Dilithium3 private key is 4016 bytes
    uint8_t *privkey = malloc(4016);
    if (!privkey) {
        fclose(f);
        return -1;
    }

    size_t read = fread(privkey, 1, 4016, f);
    fclose(f);

    if (read != 4016) {
        fprintf(stderr, "[P2P] Invalid private key size: %zu (expected 4016)\n", read);
        free(privkey);
        return -1;
    }

    *privkey_out = privkey;
    *privkey_len_out = 4016;
    return 0;
}

/**
 * Load my own Kyber512 private key from ~/.dna/
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
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s-kyber512.pqkey",
             home, ctx->identity);

    FILE *f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "[P2P] Failed to open Kyber key: %s\n", key_path);
        return -1;
    }

    // Kyber512 private key is 2400 bytes
    uint8_t *kyber = malloc(2400);
    if (!kyber) {
        fclose(f);
        return -1;
    }

    size_t read = fread(kyber, 1, 2400, f);
    fclose(f);

    if (read != 2400) {
        fprintf(stderr, "[P2P] Invalid Kyber key size: %zu (expected 2400)\n", read);
        free(kyber);
        return -1;
    }

    *kyber_key_out = kyber;
    *kyber_key_len_out = 2400;
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
static char* lookup_identity_for_pubkey(
    messenger_context_t *ctx,
    const uint8_t *pubkey,
    size_t pubkey_len
)
{
    if (!ctx || !pubkey || pubkey_len != 1952) {
        return NULL;
    }

    // TODO: Implement DHT keyserver lookup (Phase 2/4)
    // For now, return NULL - identity will be extracted from decrypted message
    // This is okay because the encrypted message contains the sender's signing pubkey
    // which can be verified against the DHT keyserver after decryption
    return NULL;
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

    // Load Kyber512 key
    if (load_my_kyber_key(ctx, &kyber_key, &kyber_key_len) != 0) {
        fprintf(stderr, "[P2P] Failed to load Kyber512 key\n");
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
        int queue_result = p2p_queue_offline_message(
            ctx->p2p_transport,
            ctx->identity,      // sender
            recipient,          // recipient
            encrypted_message,
            encrypted_len
        );

        if (queue_result == 0) {
            printf("[P2P] ✓ Message queued in DHT for %s\n", recipient);
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
        sender_identity = lookup_identity_for_pubkey(ctx, peer_pubkey, 1952);
    }

    if (sender_identity) {
        printf("[P2P] ✓ Received P2P message from %s (%zu bytes)\n", sender_identity, message_len);
    } else {
        printf("[P2P] ✓ Received P2P message from unknown peer (%zu bytes)\n", message_len);
        // We'll try to identify sender from the decrypted message content later
        sender_identity = strdup("unknown");
    }

    // Store in SQLite local database so messenger_list_messages() can retrieve it
    // The message is already encrypted at this point
    time_t now = time(NULL);

    int result = message_backup_save(
        ctx->backup_ctx,
        sender_identity,    // sender
        ctx->identity,      // recipient (us)
        message,            // encrypted message
        message_len,        // encrypted length
        now,                // timestamp
        false               // is_outgoing = false (we're receiving)
    );

    if (result != 0) {
        fprintf(stderr, "[P2P] Failed to store received message in SQLite\n");
    } else {
        printf("[P2P] ✓ Message from %s stored in SQLite\n", sender_identity);
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

    char *peer_identity = lookup_identity_for_pubkey(ctx, peer_pubkey, 1952);
    if (peer_identity) {
        printf("[P2P] %s %s\n", peer_identity, is_connected ? "CONNECTED" : "DISCONNECTED");
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
    if (!ctx || !identity || !ctx->p2p_enabled || !ctx->p2p_transport) {
        return false;
    }

    // Load peer's public key
    uint8_t *peer_pubkey = NULL;
    size_t peer_pubkey_len = 0;

    if (load_pubkey_for_identity(ctx, identity, &peer_pubkey, &peer_pubkey_len) != 0) {
        return false;
    }

    // Lookup peer in DHT
    peer_info_t peer_info;
    int result = p2p_lookup_peer(ctx->p2p_transport, peer_pubkey, &peer_info);
    free(peer_pubkey);

    return (result == 0 && peer_info.is_online);
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
        // which stores them in PostgreSQL for GUI retrieval
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
