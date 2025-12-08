/*
 * DNA Messenger Engine - Public API
 *
 * Unified async C API for DNA Messenger core functionality.
 * Provides clean separation between engine and UI layers.
 *
 * Features:
 * - Async operations with callbacks (non-blocking)
 * - Engine-managed threading (DHT, P2P, RPC)
 * - Event system for pushed notifications
 * - Post-quantum cryptography (Kyber1024, Dilithium5)
 * - Cellframe blockchain wallet integration
 *
 * Version: 1.0.0
 */

#ifndef DNA_ENGINE_H
#define DNA_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VERSION
 * ============================================================================ */

#define DNA_ENGINE_VERSION_MAJOR 1
#define DNA_ENGINE_VERSION_MINOR 0
#define DNA_ENGINE_VERSION_PATCH 0
#define DNA_ENGINE_VERSION_STRING "1.0.0"

/* ============================================================================
 * OPAQUE TYPES
 * ============================================================================ */

typedef struct dna_engine dna_engine_t;
typedef uint64_t dna_request_id_t;

/* ============================================================================
 * ERROR CODES (Engine-specific additions to base dna_error_t)
 *
 * Base error codes are in dna_api.h (DNA_OK, DNA_ERROR_CRYPTO, etc.)
 * These engine-specific codes extend the base enum with negative values
 * that don't conflict with the base codes (-1 to -99 reserved by dna_api.h)
 * ============================================================================ */

/* Engine-specific error codes (start at -100 to avoid conflicts) */
#define DNA_ENGINE_ERROR_INIT           (-100)
#define DNA_ENGINE_ERROR_NOT_INITIALIZED (-101)
#define DNA_ENGINE_ERROR_NETWORK        (-102)
#define DNA_ENGINE_ERROR_DATABASE       (-103)
#define DNA_ENGINE_ERROR_TIMEOUT        (-104)
#define DNA_ENGINE_ERROR_BUSY           (-105)
#define DNA_ENGINE_ERROR_NO_IDENTITY    (-106)
#define DNA_ENGINE_ERROR_ALREADY_EXISTS (-107)
#define DNA_ENGINE_ERROR_PERMISSION     (-108)

/**
 * Get human-readable error message for engine errors
 */
const char* dna_engine_error_string(int error);

/* ============================================================================
 * PUBLIC DATA TYPES
 * ============================================================================ */

/**
 * Contact information
 */
typedef struct {
    char fingerprint[129];      /* 128 hex chars + null */
    char display_name[256];     /* Registered name or shortened fingerprint */
    bool is_online;             /* Current online status */
    uint64_t last_seen;         /* Unix timestamp of last activity */
} dna_contact_t;

/**
 * Message information
 */
typedef struct {
    int id;                     /* Local message ID */
    char sender[129];           /* Sender fingerprint */
    char recipient[129];        /* Recipient fingerprint */
    char *plaintext;            /* Decrypted message text (caller must free via dna_free_messages) */
    uint64_t timestamp;         /* Unix timestamp */
    bool is_outgoing;           /* true if sent by current identity */
    int status;                 /* 0=pending, 1=sent, 2=delivered, 3=read */
    int message_type;           /* 0=chat, 1=group_invitation */
} dna_message_t;

/**
 * Group information
 */
typedef struct {
    char uuid[37];              /* UUID v4 string */
    char name[256];             /* Group name */
    char creator[129];          /* Creator fingerprint */
    int member_count;           /* Number of members */
    uint64_t created_at;        /* Unix timestamp */
} dna_group_t;

/**
 * Group invitation
 */
typedef struct {
    char group_uuid[37];        /* Group UUID */
    char group_name[256];       /* Group name */
    char inviter[129];          /* Inviter fingerprint */
    int member_count;           /* Current member count */
    uint64_t invited_at;        /* Unix timestamp */
} dna_invitation_t;

/**
 * Wallet information (Cellframe)
 */
typedef struct {
    char name[256];             /* Wallet name */
    char address[120];          /* Primary address */
    int sig_type;               /* 0=Dilithium, 1=Picnic, 2=Bliss, 3=Tesla */
    bool is_protected;          /* Password protected */
} dna_wallet_t;

/**
 * Token balance
 */
typedef struct {
    char token[32];             /* Token ticker (CPUNK, CELL, KEL) */
    char balance[64];           /* Formatted balance string */
    char network[64];           /* Network name (Backbone, KelVPN) */
} dna_balance_t;

/**
 * Transaction record
 */
typedef struct {
    char tx_hash[128];          /* Transaction hash */
    char direction[16];         /* "sent" or "received" */
    char amount[64];            /* Formatted amount */
    char token[32];             /* Token ticker */
    char other_address[120];    /* Other party's address */
    char timestamp[32];         /* Formatted timestamp */
    char status[32];            /* ACCEPTED, DECLINED, PENDING */
} dna_transaction_t;

/**
 * Feed channel information (simplified for async API)
 */
typedef struct {
    char channel_id[65];        /* SHA256 hex of channel name (64 + null) */
    char name[64];              /* Display name */
    char description[512];      /* Channel description */
    char creator_fingerprint[129]; /* Creator's SHA3-512 fingerprint */
    uint64_t created_at;        /* Unix timestamp */
    int post_count;             /* Approximate post count */
    int subscriber_count;       /* Approximate subscriber count */
    uint64_t last_activity;     /* Timestamp of last post */
} dna_channel_info_t;

/**
 * Feed post information (simplified for async API)
 */
typedef struct {
    char post_id[200];          /* <fingerprint>_<timestamp_ms>_<random> */
    char channel_id[65];        /* Channel this post belongs to */
    char author_fingerprint[129]; /* Author's SHA3-512 fingerprint */
    char *text;                 /* Post content (caller frees via dna_free_feed_posts) */
    uint64_t timestamp;         /* Unix timestamp (milliseconds) */
    uint64_t updated;           /* Last activity timestamp (comment added) */
    int comment_count;          /* Cached comment count */
    int upvotes;                /* Upvote count */
    int downvotes;              /* Downvote count */
    int user_vote;              /* Current user's vote: +1, -1, or 0 */
    bool verified;              /* Signature verified */
} dna_post_info_t;

/**
 * Feed comment info (flat comments, no nesting)
 */
typedef struct {
    char comment_id[200];       /* <fingerprint>_<timestamp_ms>_<random> */
    char post_id[200];          /* Parent post ID */
    char author_fingerprint[129]; /* Author's SHA3-512 fingerprint */
    char *text;                 /* Comment content (caller frees via dna_free_feed_comments) */
    uint64_t timestamp;         /* Unix timestamp (milliseconds) */
    int upvotes;                /* Upvote count */
    int downvotes;              /* Downvote count */
    int user_vote;              /* Current user's vote: +1, -1, or 0 */
    bool verified;              /* Signature verified */
} dna_comment_info_t;

/**
 * User profile information (wallet addresses, socials, bio, avatar)
 */
typedef struct {
    /* Cellframe wallet addresses */
    char backbone[120];
    char kelvpn[120];
    char subzero[120];
    char cpunk_testnet[120];

    /* External wallet addresses */
    char btc[128];
    char eth[128];
    char sol[128];

    /* Social links */
    char telegram[128];
    char twitter[128];          /* X (Twitter) handle */
    char github[128];

    /* Bio and avatar */
    char bio[512];
    char avatar_base64[20484];  /* Base64-encoded 64x64 PNG/JPEG (~20KB max) */
} dna_profile_t;

/* ============================================================================
 * ASYNC CALLBACK TYPES
 * ============================================================================ */

/**
 * Generic completion callback (success/error only)
 * Error is 0 (DNA_OK) on success, negative on error
 */
typedef void (*dna_completion_cb)(
    dna_request_id_t request_id,
    int error,
    void *user_data
);

/**
 * Identity list callback
 */
typedef void (*dna_identities_cb)(
    dna_request_id_t request_id,
    int error,
    char **fingerprints,        /* Array of fingerprint strings */
    int count,
    void *user_data
);

/**
 * Identity created callback
 */
typedef void (*dna_identity_created_cb)(
    dna_request_id_t request_id,
    int error,
    const char *fingerprint,    /* New identity fingerprint (129 chars) */
    void *user_data
);

/**
 * Display name callback
 */
typedef void (*dna_display_name_cb)(
    dna_request_id_t request_id,
    int error,
    const char *display_name,
    void *user_data
);

/**
 * Contacts list callback
 */
typedef void (*dna_contacts_cb)(
    dna_request_id_t request_id,
    int error,
    dna_contact_t *contacts,
    int count,
    void *user_data
);

/**
 * Messages callback
 */
typedef void (*dna_messages_cb)(
    dna_request_id_t request_id,
    int error,
    dna_message_t *messages,
    int count,
    void *user_data
);

/**
 * Groups callback
 */
typedef void (*dna_groups_cb)(
    dna_request_id_t request_id,
    int error,
    dna_group_t *groups,
    int count,
    void *user_data
);

/**
 * Group created callback
 */
typedef void (*dna_group_created_cb)(
    dna_request_id_t request_id,
    int error,
    const char *group_uuid,     /* New group UUID (37 chars) */
    void *user_data
);

/**
 * Invitations callback
 */
typedef void (*dna_invitations_cb)(
    dna_request_id_t request_id,
    int error,
    dna_invitation_t *invitations,
    int count,
    void *user_data
);

/**
 * Wallets callback
 */
typedef void (*dna_wallets_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wallet_t *wallets,
    int count,
    void *user_data
);

/**
 * Balances callback
 */
typedef void (*dna_balances_cb)(
    dna_request_id_t request_id,
    int error,
    dna_balance_t *balances,
    int count,
    void *user_data
);

/**
 * Transactions callback
 */
typedef void (*dna_transactions_cb)(
    dna_request_id_t request_id,
    int error,
    dna_transaction_t *transactions,
    int count,
    void *user_data
);

/**
 * Presence lookup callback
 * Returns last_seen timestamp from DHT (0 if not found or error)
 */
typedef void (*dna_presence_cb)(
    dna_request_id_t request_id,
    int error,
    uint64_t last_seen,     /* Unix timestamp when peer last registered presence */
    void *user_data
);

/**
 * Feed channels callback
 */
typedef void (*dna_feed_channels_cb)(
    dna_request_id_t request_id,
    int error,
    dna_channel_info_t *channels,
    int count,
    void *user_data
);

/**
 * Feed channel created callback
 */
typedef void (*dna_feed_channel_cb)(
    dna_request_id_t request_id,
    int error,
    dna_channel_info_t *channel,
    void *user_data
);

/**
 * Feed posts callback
 */
typedef void (*dna_feed_posts_cb)(
    dna_request_id_t request_id,
    int error,
    dna_post_info_t *posts,
    int count,
    void *user_data
);

/**
 * Feed post created callback
 */
typedef void (*dna_feed_post_cb)(
    dna_request_id_t request_id,
    int error,
    dna_post_info_t *post,
    void *user_data
);

/**
 * Feed comments callback
 */
typedef void (*dna_feed_comments_cb)(
    dna_request_id_t request_id,
    int error,
    dna_comment_info_t *comments,
    int count,
    void *user_data
);

/**
 * Feed comment created callback
 */
typedef void (*dna_feed_comment_cb)(
    dna_request_id_t request_id,
    int error,
    dna_comment_info_t *comment,
    void *user_data
);

/**
 * Profile callback
 */
typedef void (*dna_profile_cb)(
    dna_request_id_t request_id,
    int error,
    dna_profile_t *profile,
    void *user_data
);

/* ============================================================================
 * EVENT TYPES (pushed by engine)
 * ============================================================================ */

typedef enum {
    DNA_EVENT_DHT_CONNECTED,
    DNA_EVENT_DHT_DISCONNECTED,
    DNA_EVENT_MESSAGE_RECEIVED,
    DNA_EVENT_MESSAGE_SENT,
    DNA_EVENT_MESSAGE_DELIVERED,
    DNA_EVENT_MESSAGE_READ,
    DNA_EVENT_CONTACT_ONLINE,
    DNA_EVENT_CONTACT_OFFLINE,
    DNA_EVENT_GROUP_INVITATION_RECEIVED,
    DNA_EVENT_GROUP_MEMBER_JOINED,
    DNA_EVENT_GROUP_MEMBER_LEFT,
    DNA_EVENT_IDENTITY_LOADED,
    DNA_EVENT_ERROR
} dna_event_type_t;

/**
 * Event data structure
 */
typedef struct {
    dna_event_type_t type;
    union {
        struct {
            dna_message_t message;
        } message_received;
        struct {
            int message_id;
            int new_status;
        } message_status;
        struct {
            char fingerprint[129];
        } contact_status;
        struct {
            dna_invitation_t invitation;
        } group_invitation;
        struct {
            char group_uuid[37];
            char member[129];
        } group_member;
        struct {
            char fingerprint[129];
        } identity_loaded;
        struct {
            int code;
            char message[256];
        } error;
    } data;
} dna_event_t;

/**
 * Event callback (called from engine thread, must be thread-safe)
 */
typedef void (*dna_event_cb)(const dna_event_t *event, void *user_data);

/* ============================================================================
 * 1. LIFECYCLE (4 functions)
 * ============================================================================ */

/**
 * Create DNA engine instance
 *
 * Initializes engine and spawns internal worker threads for:
 * - DHT network operations
 * - P2P transport
 * - Offline message polling
 * - RPC queries
 *
 * @param data_dir  Path to data directory (NULL for default ~/.dna)
 * @return          Engine instance or NULL on error
 */
dna_engine_t* dna_engine_create(const char *data_dir);

/**
 * Set event callback for pushed events
 *
 * Events are called from engine thread - callback must be thread-safe.
 * Only one callback can be active at a time.
 *
 * @param engine    Engine instance
 * @param callback  Event callback function (NULL to disable)
 * @param user_data User data passed to callback
 */
void dna_engine_set_event_callback(
    dna_engine_t *engine,
    dna_event_cb callback,
    void *user_data
);

/**
 * Destroy engine and release all resources
 *
 * Stops all worker threads, closes network connections,
 * and frees all allocated memory.
 *
 * @param engine    Engine instance (can be NULL)
 */
void dna_engine_destroy(dna_engine_t *engine);

/**
 * Get current identity fingerprint
 *
 * @param engine    Engine instance
 * @return          Fingerprint string (128 hex chars) or NULL if no identity loaded
 */
const char* dna_engine_get_fingerprint(dna_engine_t *engine);

/* ============================================================================
 * 2. IDENTITY (5 async functions)
 * ============================================================================ */

/**
 * List available identities
 *
 * Scans ~/.dna for .dsa key files and returns fingerprints.
 *
 * @param engine    Engine instance
 * @param callback  Called with list of fingerprints
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_list_identities(
    dna_engine_t *engine,
    dna_identities_cb callback,
    void *user_data
);

/**
 * Create new identity from BIP39 seeds
 *
 * Generates Dilithium5 + Kyber1024 keypairs deterministically
 * from provided seeds. Saves keys to ~/.dna/<name>/keys/
 *
 * @param engine          Engine instance
 * @param name            Identity name (required, used for directory structure)
 * @param signing_seed    32-byte seed for Dilithium5
 * @param encryption_seed 32-byte seed for Kyber1024
 * @param wallet_seed     32-byte seed for Cellframe wallet (can be NULL)
 * @param callback        Called with new fingerprint
 * @param user_data       User data for callback
 * @return                Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t *wallet_seed,
    dna_identity_created_cb callback,
    void *user_data
);

/**
 * Create new identity from BIP39 seeds (synchronous)
 *
 * Same as dna_engine_create_identity but blocks and returns result directly.
 * Useful for FFI bindings where async callbacks are problematic.
 *
 * @param engine          Engine instance (can be NULL for keygen-only)
 * @param name            Identity name (required, used for directory structure)
 * @param signing_seed    32-byte seed for Dilithium5
 * @param encryption_seed 32-byte seed for Kyber1024
 * @param wallet_seed     32-byte seed for Cellframe wallet (can be NULL)
 * @param master_seed     64-byte BIP39 master seed for multi-chain wallets (can be NULL)
 * @param fingerprint_out Output buffer for fingerprint (129 bytes min)
 * @return                0 on success, error code on failure
 */
int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t wallet_seed[32],
    const uint8_t master_seed[64],
    char fingerprint_out[129]
);

/**
 * Load and activate identity
 *
 * Loads keypairs, bootstraps DHT, registers presence,
 * starts P2P listener, and subscribes to contacts.
 *
 * @param engine      Engine instance
 * @param fingerprint Identity fingerprint (128 hex chars)
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Register human-readable name in DHT
 *
 * Associates a name with current identity's fingerprint.
 * Name must be 3-20 chars, alphanumeric + underscore.
 *
 * @param engine    Engine instance
 * @param name      Desired name
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_register_name(
    dna_engine_t *engine,
    const char *name,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Lookup display name for fingerprint
 *
 * Checks DHT for registered name, returns shortened
 * fingerprint if no name registered.
 *
 * @param engine      Engine instance
 * @param fingerprint Identity fingerprint
 * @param callback    Called with display name
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_display_name(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,
    void *user_data
);

/**
 * Get avatar for fingerprint
 *
 * Returns cached avatar or fetches from DHT if not cached.
 * Avatar is base64 encoded.
 *
 * @param engine      Engine instance
 * @param fingerprint Identity fingerprint
 * @param callback    Called with avatar base64 (NULL if no avatar)
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_avatar(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,
    void *user_data
);

/**
 * Lookup name availability (name -> fingerprint)
 *
 * Checks if a name is already registered in DHT.
 * Returns fingerprint if name is taken, empty string if available.
 *
 * @param engine    Engine instance
 * @param name      Name to lookup (3-20 chars, alphanumeric + underscore)
 * @param callback  Called with fingerprint (empty if available)
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_lookup_name(
    dna_engine_t *engine,
    const char *name,
    dna_display_name_cb callback,
    void *user_data
);

/**
 * Get current identity's profile from DHT
 *
 * Loads wallet addresses, social links, bio, and avatar.
 *
 * @param engine    Engine instance
 * @param callback  Called with profile data
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_profile(
    dna_engine_t *engine,
    dna_profile_cb callback,
    void *user_data
);

/**
 * Update current identity's profile in DHT
 *
 * Saves wallet addresses, social links, bio, and avatar.
 * Signs with Dilithium5 before publishing.
 *
 * @param engine    Engine instance
 * @param profile   Profile data to save
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_update_profile(
    dna_engine_t *engine,
    const dna_profile_t *profile,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * 3. CONTACTS (3 async functions)
 * ============================================================================ */

/**
 * Get contact list
 *
 * Returns contacts from local database.
 *
 * @param engine    Engine instance
 * @param callback  Called with contacts array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_contacts(
    dna_engine_t *engine,
    dna_contacts_cb callback,
    void *user_data
);

/**
 * Add contact by fingerprint or registered name
 *
 * Looks up public keys in DHT if needed.
 *
 * @param engine     Engine instance
 * @param identifier Fingerprint or registered name
 * @param callback   Called on completion
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_add_contact(
    dna_engine_t *engine,
    const char *identifier,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Remove contact
 *
 * @param engine      Engine instance
 * @param fingerprint Contact fingerprint
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_remove_contact(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * 4. MESSAGING (3 async functions)
 * ============================================================================ */

/**
 * Send message to contact
 *
 * Encrypts with Kyber1024 + AES-256-GCM, signs with Dilithium5.
 * Tries P2P delivery first, falls back to DHT offline queue.
 *
 * @param engine               Engine instance
 * @param recipient_fingerprint Recipient fingerprint
 * @param message              Message text
 * @param callback             Called on completion
 * @param user_data            User data for callback
 * @return                     Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_send_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Queue message for async sending (returns immediately)
 *
 * Adds message to internal send queue for background delivery.
 * Messages are sent in order via worker threads. Use this for
 * fire-and-forget messaging with optimistic UI.
 *
 * @param engine               Engine instance
 * @param recipient_fingerprint Recipient fingerprint
 * @param message              Message text
 * @return                     >= 0: queue slot ID (success)
 *                             -1: queue full (DNA_ENGINE_ERROR_BUSY)
 *                             -2: invalid args (DNA_ENGINE_ERROR_NOT_INITIALIZED)
 */
int dna_engine_queue_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message
);

/**
 * Get message queue capacity
 *
 * @param engine Engine instance
 * @return       Maximum number of messages that can be queued
 */
int dna_engine_get_message_queue_capacity(dna_engine_t *engine);

/**
 * Get current message queue size
 *
 * @param engine Engine instance
 * @return       Number of messages currently in queue
 */
int dna_engine_get_message_queue_size(dna_engine_t *engine);

/**
 * Set message queue capacity (default: 20)
 *
 * @param engine   Engine instance
 * @param capacity New capacity (1-100)
 * @return         0 on success, -1 on invalid capacity
 */
int dna_engine_set_message_queue_capacity(dna_engine_t *engine, int capacity);

/**
 * Get conversation with contact
 *
 * Returns all messages exchanged with contact.
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact fingerprint
 * @param callback            Called with messages array
 * @param user_data           User data for callback
 * @return                    Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_conversation(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_messages_cb callback,
    void *user_data
);

/**
 * Force check for offline messages
 *
 * Normally automatic - only needed if you want immediate check.
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_check_offline_messages(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * 5. GROUPS (6 async functions)
 * ============================================================================ */

/**
 * Get groups current identity belongs to
 *
 * @param engine    Engine instance
 * @param callback  Called with groups array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_groups(
    dna_engine_t *engine,
    dna_groups_cb callback,
    void *user_data
);

/**
 * Create new group
 *
 * Creates group with GSK (Group Symmetric Key) encryption.
 *
 * @param engine              Engine instance
 * @param name                Group name
 * @param member_fingerprints Array of member fingerprints
 * @param member_count        Number of members
 * @param callback            Called with new group UUID
 * @param user_data           User data for callback
 * @return                    Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_create_group(
    dna_engine_t *engine,
    const char *name,
    const char **member_fingerprints,
    int member_count,
    dna_group_created_cb callback,
    void *user_data
);

/**
 * Send message to group
 *
 * Encrypts with GSK (AES-256-GCM), signs with Dilithium5.
 *
 * @param engine     Engine instance
 * @param group_uuid Group UUID
 * @param message    Message text
 * @param callback   Called on completion
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_send_group_message(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *message,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get pending group invitations
 *
 * @param engine    Engine instance
 * @param callback  Called with invitations array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_invitations(
    dna_engine_t *engine,
    dna_invitations_cb callback,
    void *user_data
);

/**
 * Accept group invitation
 *
 * @param engine     Engine instance
 * @param group_uuid Group UUID
 * @param callback   Called on completion
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_accept_invitation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Reject group invitation
 *
 * @param engine     Engine instance
 * @param group_uuid Group UUID
 * @param callback   Called on completion
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_reject_invitation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * 6. WALLET (4 async functions) - Cellframe /opt/cellframe-node
 * ============================================================================ */

/**
 * List Cellframe wallets
 *
 * Scans /opt/cellframe-node/var/lib/wallet for .dwallet files.
 *
 * @param engine    Engine instance
 * @param callback  Called with wallets array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_list_wallets(
    dna_engine_t *engine,
    dna_wallets_cb callback,
    void *user_data
);

/**
 * Get token balances for wallet
 *
 * Queries Cellframe RPC for balance info.
 *
 * @param engine       Engine instance
 * @param wallet_index Index from list_wallets result
 * @param callback     Called with balances array
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
);

/**
 * Gas speed presets for ETH transactions
 */
typedef enum {
    DNA_GAS_SLOW   = 0,  /* 0.8x network price - cheaper, slower */
    DNA_GAS_NORMAL = 1,  /* 1.0x network price - balanced */
    DNA_GAS_FAST   = 2   /* 1.5x network price - faster confirmation */
} dna_gas_speed_t;

/**
 * Send tokens
 *
 * Builds transaction, signs with Dilithium, submits via RPC.
 *
 * @param engine            Engine instance
 * @param wallet_index      Source wallet index
 * @param recipient_address Destination address
 * @param amount            Amount to send (string)
 * @param token             Token ticker (CPUNK, CELL, KEL, ETH)
 * @param network           Network name (Backbone, KelVPN, or empty for ETH)
 * @param gas_speed         Gas speed preset (ETH only, ignored for Cellframe)
 * @param callback          Called on completion
 * @param user_data         User data for callback
 * @return                  Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_send_tokens(
    dna_engine_t *engine,
    int wallet_index,
    const char *recipient_address,
    const char *amount,
    const char *token,
    const char *network,
    int gas_speed,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get transaction history
 *
 * @param engine       Engine instance
 * @param wallet_index Wallet index
 * @param network      Network name
 * @param callback     Called with transactions array
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_transactions(
    dna_engine_t *engine,
    int wallet_index,
    const char *network,
    dna_transactions_cb callback,
    void *user_data
);

/* ============================================================================
 * 7. P2P & PRESENCE (4 async functions)
 * ============================================================================ */

/**
 * Refresh presence in DHT (announce we're online)
 *
 * Call periodically to maintain online status visibility.
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_refresh_presence(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Check if a peer is online
 *
 * @param engine      Engine instance
 * @param fingerprint Peer fingerprint
 * @return            true if peer is online, false otherwise
 */
bool dna_engine_is_peer_online(dna_engine_t *engine, const char *fingerprint);

/**
 * Lookup peer presence from DHT
 *
 * Queries DHT for peer's presence record and returns the timestamp
 * when they last registered their presence (i.e., when they were last online).
 *
 * @param engine      Engine instance
 * @param fingerprint Peer fingerprint (128 hex chars)
 * @param callback    Called with last_seen timestamp (0 if not found)
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_lookup_presence(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_presence_cb callback,
    void *user_data
);

/**
 * Sync contacts to DHT (publish local contacts)
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_sync_contacts_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Sync contacts from DHT (merge with local)
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_sync_contacts_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Sync groups from DHT
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_sync_groups(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Subscribe to contacts for push notifications
 *
 * Enables real-time message delivery via DHT.
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_subscribe_to_contacts(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get registered name for current identity
 *
 * Performs DHT reverse lookup (fingerprint -> name).
 *
 * @param engine    Engine instance
 * @param callback  Called with display name (or empty if not registered)
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_registered_name(
    dna_engine_t *engine,
    dna_display_name_cb callback,
    void *user_data
);

/* ============================================================================
 * 8. FEED (8 async functions) - Public social feed via DHT
 * ============================================================================ */

/**
 * Get all feed channels from DHT registry
 *
 * @param engine    Engine instance
 * @param callback  Called with channels array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_feed_channels(
    dna_engine_t *engine,
    dna_feed_channels_cb callback,
    void *user_data
);

/**
 * Create a new feed channel
 *
 * Creates channel metadata and adds to global registry.
 * Requires active identity for signing.
 *
 * @param engine      Engine instance
 * @param name        Channel name (max 64 chars)
 * @param description Channel description (max 512 chars)
 * @param callback    Called with created channel
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_create_feed_channel(
    dna_engine_t *engine,
    const char *name,
    const char *description,
    dna_feed_channel_cb callback,
    void *user_data
);

/**
 * Initialize default feed channels
 *
 * Creates #general, #announcements, #help, #random if they don't exist.
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_init_default_channels(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get posts for a feed channel
 *
 * Returns posts for specified date (or today if NULL).
 *
 * @param engine     Engine instance
 * @param channel_id Channel ID (SHA256 of channel name)
 * @param date       Date string (YYYYMMDD) or NULL for today
 * @param callback   Called with posts array
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_feed_posts(
    dna_engine_t *engine,
    const char *channel_id,
    const char *date,
    dna_feed_posts_cb callback,
    void *user_data
);

/**
 * Create a new feed post
 *
 * Posts are signed with Dilithium5.
 * Use dna_engine_add_feed_comment() for comments.
 *
 * @param engine     Engine instance
 * @param channel_id Channel ID
 * @param text       Post content (max 2048 chars)
 * @param callback   Called with created post
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_create_feed_post(
    dna_engine_t *engine,
    const char *channel_id,
    const char *text,
    dna_feed_post_cb callback,
    void *user_data
);

/**
 * Add a comment to a post
 *
 * Comments are flat (no nesting). Signed with Dilithium5.
 * Also refreshes parent post TTL (engagement-TTL).
 *
 * @param engine    Engine instance
 * @param post_id   Post ID to comment on
 * @param text      Comment content (max 2048 chars)
 * @param callback  Called with created comment
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_add_feed_comment(
    dna_engine_t *engine,
    const char *post_id,
    const char *text,
    dna_feed_comment_cb callback,
    void *user_data
);

/**
 * Get all comments for a post
 *
 * @param engine    Engine instance
 * @param post_id   Post ID
 * @param callback  Called with comments array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_feed_comments(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_comments_cb callback,
    void *user_data
);

/**
 * Cast a vote on a feed post
 *
 * Votes are permanent (cannot be changed once cast).
 * Signed with Dilithium5.
 *
 * @param engine     Engine instance
 * @param post_id    Post ID to vote on
 * @param vote_value +1 for upvote, -1 for downvote
 * @param callback   Called on completion
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_cast_feed_vote(
    dna_engine_t *engine,
    const char *post_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get vote counts and user's vote for a post
 *
 * Returns updated upvotes/downvotes/user_vote in the post struct.
 *
 * @param engine    Engine instance
 * @param post_id   Post ID
 * @param callback  Called with post containing vote data
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_feed_votes(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_post_cb callback,
    void *user_data
);

/**
 * Cast a vote on a feed comment
 *
 * Votes are permanent (cannot be changed once cast).
 * Signed with Dilithium5.
 *
 * @param engine      Engine instance
 * @param comment_id  Comment ID to vote on
 * @param vote_value  +1 for upvote, -1 for downvote
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_cast_comment_vote(
    dna_engine_t *engine,
    const char *comment_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get vote counts and user's vote for a comment
 *
 * Returns updated upvotes/downvotes/user_vote in the comment struct.
 *
 * @param engine      Engine instance
 * @param comment_id  Comment ID
 * @param callback    Called with comment containing vote data
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
dna_request_id_t dna_engine_get_comment_votes(
    dna_engine_t *engine,
    const char *comment_id,
    dna_feed_comment_cb callback,
    void *user_data
);

/* ============================================================================
 * 9. BACKWARD COMPATIBILITY (for gradual GUI migration)
 * ============================================================================ */

/**
 * Get underlying messenger context
 *
 * For backward compatibility during GUI migration.
 * Returns NULL if no identity loaded.
 *
 * WARNING: Use sparingly - prefer engine API functions.
 *
 * @param engine    Engine instance
 * @return          messenger_context_t* (opaque, cast as needed)
 */
void* dna_engine_get_messenger_context(dna_engine_t *engine);

/**
 * Get DHT context
 *
 * For backward compatibility during GUI migration.
 * Returns NULL if DHT not initialized.
 *
 * WARNING: Use sparingly - prefer engine API functions.
 *
 * @param engine    Engine instance
 * @return          dht_context_t* (opaque, cast as needed)
 */
void* dna_engine_get_dht_context(dna_engine_t *engine);

/* ============================================================================
 * LOG CONFIGURATION
 * ============================================================================ */

/**
 * Get current log level
 *
 * @return Log level string: "DEBUG", "INFO", "WARN", "ERROR", or "NONE"
 */
const char* dna_engine_get_log_level(void);

/**
 * Set log level
 *
 * @param level  Log level: "DEBUG", "INFO", "WARN", "ERROR", or "NONE"
 * @return       0 on success, -1 on error
 */
int dna_engine_set_log_level(const char *level);

/**
 * Get current log tags filter
 *
 * @return Comma-separated tags string (empty = show all)
 */
const char* dna_engine_get_log_tags(void);

/**
 * Set log tags filter
 *
 * @param tags  Comma-separated tags to show (empty = show all)
 * @return      0 on success, -1 on error
 */
int dna_engine_set_log_tags(const char *tags);

/* ============================================================================
 * MEMORY MANAGEMENT
 * ============================================================================ */

/**
 * Free string array returned by callbacks
 */
void dna_free_strings(char **strings, int count);

/**
 * Free contacts array returned by callbacks
 */
void dna_free_contacts(dna_contact_t *contacts, int count);

/**
 * Free messages array returned by callbacks
 */
void dna_free_messages(dna_message_t *messages, int count);

/**
 * Free groups array returned by callbacks
 */
void dna_free_groups(dna_group_t *groups, int count);

/**
 * Free invitations array returned by callbacks
 */
void dna_free_invitations(dna_invitation_t *invitations, int count);

/**
 * Free wallets array returned by callbacks
 */
void dna_free_wallets(dna_wallet_t *wallets, int count);

/**
 * Free balances array returned by callbacks
 */
void dna_free_balances(dna_balance_t *balances, int count);

/**
 * Free transactions array returned by callbacks
 */
void dna_free_transactions(dna_transaction_t *transactions, int count);

/**
 * Free feed channels array returned by callbacks
 */
void dna_free_feed_channels(dna_channel_info_t *channels, int count);

/**
 * Free feed posts array returned by callbacks
 */
void dna_free_feed_posts(dna_post_info_t *posts, int count);

/**
 * Free single feed post returned by callbacks
 */
void dna_free_feed_post(dna_post_info_t *post);

/**
 * Free feed comments array returned by callbacks
 */
void dna_free_feed_comments(dna_comment_info_t *comments, int count);

/**
 * Free single feed comment returned by callbacks
 */
void dna_free_feed_comment(dna_comment_info_t *comment);

/**
 * Free profile returned by callbacks
 */
void dna_free_profile(dna_profile_t *profile);

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_H */
