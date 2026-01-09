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

/* DLL Export/Import macros for Windows */
#ifdef _WIN32
    #ifdef DNA_LIB_EXPORTS
        #define DNA_API __declspec(dllexport)
    #else
        #define DNA_API __declspec(dllimport)
    #endif
#else
    #define DNA_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VERSION (from version.h - single source of truth)
 * ============================================================================ */

#include "version.h"

/**
 * Get DNA Messenger version string
 *
 * @return Version string (e.g., "0.2.5") - do not free
 */
DNA_API const char* dna_engine_get_version(void);

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
#define DNA_ENGINE_ERROR_NO_IDENTITY    (-106)
#define DNA_ENGINE_ERROR_ALREADY_EXISTS (-107)
#define DNA_ENGINE_ERROR_PERMISSION     (-108)
#define DNA_ENGINE_ERROR_INVALID_PARAM  (-109)
#define DNA_ENGINE_ERROR_NOT_FOUND      (-110)
#define DNA_ENGINE_ERROR_PASSWORD_REQUIRED (-111)
#define DNA_ENGINE_ERROR_WRONG_PASSWORD (-112)
#define DNA_ENGINE_ERROR_INVALID_SIGNATURE (-113)  /* DHT profile signature verification failed */
#define DNA_ENGINE_ERROR_INSUFFICIENT_BALANCE (-114)  /* Insufficient token balance for transaction */
#define DNA_ENGINE_ERROR_RENT_MINIMUM (-115)  /* Solana: amount below rent-exempt minimum for new account */

/**
 * Get human-readable error message for engine errors
 */
DNA_API const char* dna_engine_error_string(int error);

/* ============================================================================
 * PUBLIC DATA TYPES
 * ============================================================================ */

/**
 * Contact information
 */
typedef struct {
    char fingerprint[129];      /* 128 hex chars + null */
    char display_name[256];     /* Resolved name (nickname > DHT name > fingerprint) */
    char nickname[64];          /* Local nickname override (empty if not set) */
    bool is_online;             /* Current online status */
    uint64_t last_seen;         /* Unix timestamp of last activity */
} dna_contact_t;

/**
 * Contact request information (ICQ-style request)
 */
typedef struct {
    char fingerprint[129];      /* Requester's fingerprint (128 hex + null) */
    char display_name[64];      /* Requester's display name */
    char message[256];          /* Optional request message */
    uint64_t requested_at;      /* Unix timestamp when request was sent */
    int status;                 /* 0=pending, 1=approved, 2=denied */
} dna_contact_request_t;

/**
 * Blocked user information
 */
typedef struct {
    char fingerprint[129];      /* Blocked user's fingerprint */
    uint64_t blocked_at;        /* Unix timestamp when blocked */
    char reason[256];           /* Optional reason for blocking */
} dna_blocked_user_t;

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
 * Address book entry (wallet address storage)
 */
typedef struct {
    int id;                     /* Database row ID */
    char address[128];          /* Wallet address */
    char label[64];             /* User-defined label */
    char network[32];           /* Network: backbone, ethereum, solana, tron */
    char notes[256];            /* Optional notes */
    uint64_t created_at;        /* When address was added */
    uint64_t updated_at;        /* When address was last modified */
    uint64_t last_used;         /* When address was last used for sending */
    uint32_t use_count;         /* Number of times used for sending */
} dna_addressbook_entry_t;

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
 * Synced with DHT dna_unified_identity_t structure
 */
typedef struct {
    /* Cellframe wallet addresses */
    char backbone[120];
    char alvin[120];            /* Alvin (cpunk mainnet) */

    /* External wallet addresses */
    char eth[128];              /* Also works for BSC, Polygon, etc. */
    char sol[128];
    char trx[128];              /* TRON address (T...) */

    /* Social links */
    char telegram[128];
    char twitter[128];          /* X (Twitter) handle */
    char github[128];
    char facebook[128];
    char instagram[128];
    char linkedin[128];
    char google[128];

    /* Profile info */
    char display_name[128];
    char bio[512];
    char location[128];
    char website[256];
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
 * Send tokens callback (returns tx hash on success)
 * Error is 0 (DNA_OK) on success, negative on error
 * tx_hash is NULL on error, valid string on success
 */
typedef void (*dna_send_tokens_cb)(
    dna_request_id_t request_id,
    int error,
    const char *tx_hash,
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
 * Contact requests callback (ICQ-style incoming requests)
 */
typedef void (*dna_contact_requests_cb)(
    dna_request_id_t request_id,
    int error,
    dna_contact_request_t *requests,
    int count,
    void *user_data
);

/**
 * Blocked users callback
 */
typedef void (*dna_blocked_users_cb)(
    dna_request_id_t request_id,
    int error,
    dna_blocked_user_t *blocked,
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
 * Address book callback
 */
typedef void (*dna_addressbook_cb)(
    dna_request_id_t request_id,
    int error,
    dna_addressbook_entry_t *entries,
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
    DNA_EVENT_CONTACT_REQUEST_RECEIVED,  /* New contact request from DHT */
    DNA_EVENT_OUTBOX_UPDATED,            /* Contact's outbox has new messages */
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
            dna_contact_request_t request;
        } contact_request_received;
        struct {
            char contact_fingerprint[129];  /* Contact whose outbox was updated */
        } outbox_updated;
        struct {
            char recipient[129];            /* Recipient fingerprint */
            uint64_t seq_num;               /* Watermark value (messages up to this are delivered) */
            uint64_t timestamp;             /* When delivery was confirmed */
        } message_delivered;
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

/**
 * Free a heap-allocated event after processing
 *
 * Events passed to the event callback are heap-allocated to ensure they
 * remain valid when Dart's NativeCallable.listener processes them
 * asynchronously. Call this function after processing the event.
 *
 * @param event Event to free (can be NULL)
 */
DNA_API void dna_free_event(dna_event_t *event);

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
DNA_API dna_engine_t* dna_engine_create(const char *data_dir);

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
DNA_API void dna_engine_set_event_callback(
    dna_engine_t *engine,
    dna_event_cb callback,
    void *user_data
);

/**
 * Android notification callback type
 *
 * Called when a contact's outbox has new messages (for showing Android notifications).
 * This is separate from the main event callback and is NOT affected by Flutter lifecycle.
 *
 * @param contact_fingerprint  Fingerprint of contact who sent the message
 * @param display_name         Display name of contact (from profile/registered name) or NULL
 * @param user_data           User data passed when setting callback
 */
typedef void (*dna_android_notification_cb)(const char *contact_fingerprint, const char *display_name, void *user_data);

/**
 * Set Android notification callback
 *
 * This callback is called when DNA_EVENT_OUTBOX_UPDATED fires, allowing Android
 * to show native notifications even when Flutter's event callback is detached.
 *
 * @param callback  Notification callback function (NULL to disable)
 * @param user_data User data passed to callback
 */
DNA_API void dna_engine_set_android_notification_callback(
    dna_android_notification_cb callback,
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
DNA_API void dna_engine_destroy(dna_engine_t *engine);

/**
 * Get current identity fingerprint
 *
 * @param engine    Engine instance
 * @return          Fingerprint string (128 hex chars) or NULL if no identity loaded
 */
DNA_API const char* dna_engine_get_fingerprint(dna_engine_t *engine);

/* ============================================================================
 * 2. IDENTITY (v0.3.0: single-user model)
 * ============================================================================ */

/* v0.3.0: dna_engine_list_identities() removed - use dna_engine_has_identity() */

/**
 * Create new identity from BIP39 seeds
 *
 * Generates Dilithium5 + Kyber1024 keypairs deterministically
 * from provided seeds. v0.3.0: Saves keys to ~/.dna/keys/identity.{dsa,kem}
 *
 * @param engine          Engine instance
 * @param name            Identity name (required, used for directory structure)
 * @param signing_seed    32-byte seed for Dilithium5
 * @param encryption_seed 32-byte seed for Kyber1024
 * @param callback        Called with new fingerprint
 * @param user_data       User data for callback
 * @return                Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
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
 * @param master_seed     64-byte BIP39 master seed for multi-chain wallets (can be NULL)
 * @param mnemonic        Space-separated BIP39 mnemonic (for Cellframe wallet, can be NULL)
 * @param fingerprint_out Output buffer for fingerprint (129 bytes min)
 * @return                0 on success, error code on failure
 */
DNA_API int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
);

/**
 * Restore identity from BIP39 seeds (synchronous)
 *
 * Creates keys and wallets locally without DHT name registration.
 * Use this when restoring an existing identity from seed phrase.
 * The identity's name/profile can be looked up from DHT after restore.
 *
 * @param engine          Engine instance
 * @param signing_seed    32-byte seed for Dilithium5
 * @param encryption_seed 32-byte seed for Kyber1024
 * @param master_seed     64-byte BIP39 master seed for multi-chain wallets (can be NULL)
 * @param mnemonic        Space-separated BIP39 mnemonic (for Cellframe wallet, can be NULL)
 * @param fingerprint_out Output buffer for fingerprint (129 bytes min)
 * @return                0 on success, error code on failure
 */
DNA_API int dna_engine_restore_identity_sync(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
);

/**
 * Delete identity and all associated local data (synchronous)
 *
 * v0.3.0 flat structure - Deletes all local files:
 * - Keys directory: <data_dir>/keys/
 * - Wallets directory: <data_dir>/wallets/
 * - Database directory: <data_dir>/db/
 * - Mnemonic file: <data_dir>/mnemonic.enc
 * - DHT identity: <data_dir>/dht_identity.bin
 *
 * WARNING: This operation is irreversible! The identity cannot be
 * recovered unless the user has backed up their seed phrase.
 *
 * Note: This does NOT delete data from the DHT network (name registration,
 * profile, etc.). The identity can be restored from seed phrase.
 *
 * @param engine      Engine instance
 * @param fingerprint Identity fingerprint to delete (128 hex chars)
 * @return            0 on success, error code on failure
 */
DNA_API int dna_engine_delete_identity_sync(
    dna_engine_t *engine,
    const char *fingerprint
);

/**
 * Check if an identity exists (v0.3.0 single-user model)
 *
 * Checks if keys/identity.dsa exists in the data directory.
 * Use this to determine if onboarding is needed.
 *
 * @param engine Engine instance
 * @return       true if identity exists, false otherwise
 */
DNA_API bool dna_engine_has_identity(dna_engine_t *engine);

/**
 * Prepare DHT connection from mnemonic (before identity creation)
 *
 * v0.3.0+: Call this when user enters seed phrase and presses "Next".
 * Starts DHT connection early so it's ready when identity is created.
 *
 * Flow:
 * 1. User enters seed → presses Next
 * 2. Call prepareDhtFromMnemonic() → DHT starts connecting
 * 3. User enters nickname (DHT connects in background)
 * 4. User presses Create → DHT is ready → name registration succeeds
 *
 * @param engine   Engine instance
 * @param mnemonic BIP39 mnemonic (24 words, space-separated)
 * @return         0 on success, -1 on error
 */
DNA_API int dna_engine_prepare_dht_from_mnemonic(dna_engine_t *engine, const char *mnemonic);

/**
 * Load and activate identity
 *
 * Loads keypairs, bootstraps DHT, registers presence,
 * starts P2P listener, and subscribes to contacts.
 *
 * @param engine      Engine instance
 * @param fingerprint Identity fingerprint (128 hex chars)
 * @param password    Password for encrypted keys (NULL if keys are unencrypted)
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
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
DNA_API dna_request_id_t dna_engine_register_name(
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
DNA_API dna_request_id_t dna_engine_get_display_name(
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
DNA_API dna_request_id_t dna_engine_get_avatar(
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
DNA_API dna_request_id_t dna_engine_lookup_name(
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
DNA_API dna_request_id_t dna_engine_get_profile(
    dna_engine_t *engine,
    dna_profile_cb callback,
    void *user_data
);

/**
 * Lookup any user's profile by fingerprint
 *
 * Fetches profile from cache (if fresh) or DHT.
 * Use this to resolve a fingerprint to wallet address for sending tokens.
 *
 * @param engine      Engine instance
 * @param fingerprint User's fingerprint (128 hex chars)
 * @param callback    Called with profile data (NULL if not found)
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_lookup_profile(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_profile_cb callback,
    void *user_data
);

/**
 * Refresh contact's profile from DHT (force, bypass cache)
 *
 * Forces a fresh fetch from DHT, ignoring cached data.
 * Use this when viewing a contact's profile to ensure up-to-date data.
 *
 * @param engine      Engine instance
 * @param fingerprint Contact's fingerprint (128 hex chars)
 * @param callback    Called with profile data (NULL if not found)
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_refresh_contact_profile(
    dna_engine_t *engine,
    const char *fingerprint,
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
DNA_API dna_request_id_t dna_engine_update_profile(
    dna_engine_t *engine,
    const dna_profile_t *profile,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get encrypted mnemonic (recovery phrase)
 *
 * Loads and decrypts the stored BIP39 mnemonic phrase using the
 * identity's Kyber1024 private key. This allows users to view
 * their recovery phrase in settings.
 *
 * v0.3.0 flat structure: mnemonic stored at ~/.dna/mnemonic.enc
 * and can only be decrypted with the identity's private key.
 *
 * @param engine        Engine instance
 * @param mnemonic_out  Output buffer (at least 256 bytes)
 * @param mnemonic_size Size of output buffer
 * @return              0 on success, negative error code on failure
 *                      Returns DNA_ENGINE_ERROR_NOT_FOUND if mnemonic not stored
 *                      (identities created before this feature won't have it)
 */
DNA_API int dna_engine_get_mnemonic(
    dna_engine_t *engine,
    char *mnemonic_out,
    size_t mnemonic_size
);

/**
 * Change password for identity keys
 *
 * Changes the password used to encrypt the identity's private keys
 * (.dsa, .kem) and mnemonic file. All files are re-encrypted with
 * the new password atomically.
 *
 * Requirements:
 * - Identity must be loaded
 * - Old password must be correct (or NULL if keys are unencrypted)
 * - New password should be strong (recommended: 12+ characters)
 *
 * v0.3.0 flat structure - Files updated:
 * - ~/.dna/keys/identity.dsa
 * - ~/.dna/keys/identity.kem
 * - ~/.dna/mnemonic.enc
 *
 * @param engine        Engine instance
 * @param old_password  Current password (NULL if keys are unencrypted)
 * @param new_password  New password (NULL to remove encryption - not recommended)
 * @return              0 on success, negative error code on failure
 *                      DNA_ENGINE_ERROR_WRONG_PASSWORD if old password is incorrect
 *                      DNA_ENGINE_ERROR_NOT_INITIALIZED if no identity loaded
 */
DNA_API int dna_engine_change_password_sync(
    dna_engine_t *engine,
    const char *old_password,
    const char *new_password
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
DNA_API dna_request_id_t dna_engine_get_contacts(
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
DNA_API dna_request_id_t dna_engine_add_contact(
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
DNA_API dna_request_id_t dna_engine_remove_contact(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Set local nickname for a contact (synchronous)
 *
 * Sets a custom local nickname that overrides the DHT display name.
 * This is local-only and NOT synced to the network.
 *
 * @param engine      Engine instance
 * @param fingerprint Contact fingerprint (128 hex chars)
 * @param nickname    Nickname to set (NULL or empty to clear)
 * @return            0 on success, negative error code on failure
 */
DNA_API int dna_engine_set_contact_nickname_sync(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *nickname
);

/* ============================================================================
 * 3.5 CONTACT REQUESTS (ICQ-style mutual approval)
 * ============================================================================ */

/**
 * Send contact request to another user
 *
 * Creates a signed contact request and publishes it to the recipient's
 * DHT inbox at SHA3-512(recipient_fingerprint + ":requests").
 * The recipient will see this as a pending request.
 *
 * @param engine               Engine instance
 * @param recipient_fingerprint Recipient's fingerprint (128 hex chars)
 * @param message              Optional message (can be NULL, max 255 chars)
 * @param callback             Called on completion
 * @param user_data            User data for callback
 * @return                     Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_send_contact_request(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get pending incoming contact requests
 *
 * Fetches both locally stored requests and new requests from DHT inbox.
 * Filters out blocked users and already-processed requests.
 *
 * @param engine    Engine instance
 * @param callback  Called with array of pending requests
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_contact_requests(
    dna_engine_t *engine,
    dna_contact_requests_cb callback,
    void *user_data
);

/**
 * Get count of pending incoming contact requests
 *
 * Synchronous function for badge display.
 *
 * @param engine Engine instance
 * @return       Number of pending requests, or -1 on error
 */
DNA_API int dna_engine_get_contact_request_count(dna_engine_t *engine);

/**
 * Approve a contact request (makes mutual contact)
 *
 * Moves the request to approved status and adds the requester
 * to contacts list. Also sends a reciprocal request so the
 * requester knows their request was accepted.
 *
 * @param engine      Engine instance
 * @param fingerprint Requester's fingerprint
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_approve_contact_request(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Deny a contact request (ignorable, can retry later)
 *
 * Marks request as denied. The requester is not blocked and
 * can send another request in the future.
 *
 * @param engine      Engine instance
 * @param fingerprint Requester's fingerprint
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_deny_contact_request(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Block a user permanently
 *
 * Adds user to blocklist. They cannot send messages or requests.
 * Any pending requests from this user are automatically removed.
 *
 * @param engine      Engine instance
 * @param fingerprint User's fingerprint to block
 * @param reason      Optional reason (can be NULL)
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_block_user(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *reason,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Unblock a user
 *
 * Removes user from blocklist. They can send requests again.
 *
 * @param engine      Engine instance
 * @param fingerprint User's fingerprint to unblock
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_unblock_user(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get list of blocked users
 *
 * @param engine    Engine instance
 * @param callback  Called with array of blocked users
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_blocked_users(
    dna_engine_t *engine,
    dna_blocked_users_cb callback,
    void *user_data
);

/**
 * Check if a user is blocked
 *
 * Synchronous function for quick checks.
 *
 * @param engine      Engine instance
 * @param fingerprint Fingerprint to check
 * @return            true if blocked, false otherwise
 */
DNA_API bool dna_engine_is_user_blocked(dna_engine_t *engine, const char *fingerprint);

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
DNA_API dna_request_id_t dna_engine_send_message(
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
 *                             -1: queue full
 *                             -2: invalid args (DNA_ENGINE_ERROR_NOT_INITIALIZED)
 */
DNA_API int dna_engine_queue_message(
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
DNA_API int dna_engine_get_message_queue_capacity(dna_engine_t *engine);

/**
 * Get current message queue size
 *
 * @param engine Engine instance
 * @return       Number of messages currently in queue
 */
DNA_API int dna_engine_get_message_queue_size(dna_engine_t *engine);

/**
 * Set message queue capacity (default: 20)
 *
 * @param engine   Engine instance
 * @param capacity New capacity (1-100)
 * @return         0 on success, -1 on invalid capacity
 */
DNA_API int dna_engine_set_message_queue_capacity(dna_engine_t *engine, int capacity);

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
DNA_API dna_request_id_t dna_engine_get_conversation(
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
DNA_API dna_request_id_t dna_engine_check_offline_messages(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get unread message count for a contact (synchronous)
 *
 * Returns number of unread incoming messages from the specified contact.
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact fingerprint
 * @return                    Unread count (>=0), or -1 on error
 */
DNA_API int dna_engine_get_unread_count(
    dna_engine_t *engine,
    const char *contact_fingerprint
);

/**
 * Mark all messages from contact as read
 *
 * Call when user opens conversation to clear unread badge.
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact fingerprint
 * @param callback            Called on completion
 * @param user_data           User data for callback
 * @return                    Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_mark_conversation_read(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Delete a message from local database
 *
 * Deletes a message by ID from the local message backup database.
 * This is a local-only operation - does not affect the recipient's copy.
 *
 * @param engine     Engine instance
 * @param message_id Message ID to delete
 * @return           0 on success, -1 on error
 */
DNA_API int dna_engine_delete_message_sync(
    dna_engine_t *engine,
    int message_id
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
DNA_API dna_request_id_t dna_engine_get_groups(
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
DNA_API dna_request_id_t dna_engine_create_group(
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
DNA_API dna_request_id_t dna_engine_send_group_message(
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
DNA_API dna_request_id_t dna_engine_get_invitations(
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
DNA_API dna_request_id_t dna_engine_accept_invitation(
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
DNA_API dna_request_id_t dna_engine_reject_invitation(
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
DNA_API dna_request_id_t dna_engine_list_wallets(
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
DNA_API dna_request_id_t dna_engine_get_balances(
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
 * Gas estimate result
 */
typedef struct {
    char fee_eth[32];       /* Fee in ETH (e.g., "0.000042") */
    uint64_t gas_price;     /* Gas price in wei */
    uint64_t gas_limit;     /* Gas limit (21000 for ETH transfer) */
} dna_gas_estimate_t;

/**
 * Get gas fee estimate for ETH transaction
 *
 * Synchronous call - queries current network gas price.
 *
 * @param gas_speed     Gas speed preset (0=slow, 1=normal, 2=fast)
 * @param estimate_out  Output: gas estimate
 * @return              0 on success, -1 on error
 */
DNA_API int dna_engine_estimate_eth_gas(int gas_speed, dna_gas_estimate_t *estimate_out);

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
 * @param callback          Called on completion with tx_hash
 * @param user_data         User data for callback
 * @return                  Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_send_tokens(
    dna_engine_t *engine,
    int wallet_index,
    const char *recipient_address,
    const char *amount,
    const char *token,
    const char *network,
    int gas_speed,
    dna_send_tokens_cb callback,
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
DNA_API dna_request_id_t dna_engine_get_transactions(
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
DNA_API dna_request_id_t dna_engine_refresh_presence(
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
DNA_API bool dna_engine_is_peer_online(dna_engine_t *engine, const char *fingerprint);

/**
 * Pause presence heartbeat (for background/inactive state)
 *
 * Call when app goes to background (Android onPause/onStop).
 * Stops announcing presence so we appear offline to others.
 *
 * @param engine    Engine instance
 */
DNA_API void dna_engine_pause_presence(dna_engine_t *engine);

/**
 * Resume presence heartbeat (for foreground/active state)
 *
 * Call when app returns to foreground (Android onResume).
 * Resumes announcing presence so we appear online to others.
 *
 * @param engine    Engine instance
 */
DNA_API void dna_engine_resume_presence(dna_engine_t *engine);

/**
 * Handle network connectivity change
 *
 * Call when network connectivity changes (e.g., WiFi to cellular switch on mobile).
 * This reinitializes the DHT connection with a fresh socket bound to the new IP.
 *
 * On Android, call this from ConnectivityManager.NetworkCallback when:
 * - onAvailable() is called (new network connected)
 * - onLost() followed by onAvailable() (network switch)
 *
 * The function:
 * 1. Cancels all DHT listeners
 * 2. Stops the current DHT connection
 * 3. Creates a new DHT connection with the same identity
 * 4. Resubscribes all listeners
 * 5. Fires DNA_EVENT_DHT_CONNECTED when reconnected
 *
 * @param engine    Engine instance
 * @return          0 on success, -1 on error
 */
DNA_API int dna_engine_network_changed(dna_engine_t *engine);

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
DNA_API dna_request_id_t dna_engine_lookup_presence(
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
DNA_API dna_request_id_t dna_engine_sync_contacts_to_dht(
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
DNA_API dna_request_id_t dna_engine_sync_contacts_from_dht(
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
DNA_API dna_request_id_t dna_engine_sync_groups(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Request TURN relay credentials from DNA Nodus
 *
 * Forces a TURN credential request even if not needed for current NAT type.
 * Useful for testing and pre-caching credentials.
 *
 * @param engine      Engine instance
 * @param timeout_ms  Timeout in milliseconds (0 for default 10s)
 * @return            0 on success, negative on error
 */
DNA_API int dna_engine_request_turn_credentials(dna_engine_t *engine, int timeout_ms);

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
DNA_API dna_request_id_t dna_engine_get_registered_name(
    dna_engine_t *engine,
    dna_display_name_cb callback,
    void *user_data
);

/* ============================================================================
 * 7.5 OUTBOX LISTENERS (Real-time offline message notifications)
 * ============================================================================ */

/**
 * Start listening for updates to a contact's outbox
 *
 * Subscribes to DHT notifications when the contact publishes new offline
 * messages to their outbox (addressed to us). When updates are detected,
 * fires DNA_EVENT_OUTBOX_UPDATED event.
 *
 * The outbox key is computed as: SHA3-512(contact_fp + ":outbox:" + my_fp)
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact's fingerprint (128 hex chars)
 * @return                    Listener token (> 0 on success, 0 on failure)
 */
DNA_API size_t dna_engine_listen_outbox(
    dna_engine_t *engine,
    const char *contact_fingerprint
);

/**
 * Cancel an active outbox listener
 *
 * Stops receiving notifications for the specified contact's outbox.
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact's fingerprint
 */
DNA_API void dna_engine_cancel_outbox_listener(
    dna_engine_t *engine,
    const char *contact_fingerprint
);

/**
 * Start listeners for all contacts' outboxes
 *
 * Convenience function that starts outbox listeners for all contacts
 * in the local database. Call after loading identity.
 *
 * @param engine    Engine instance
 * @return          Number of listeners started
 */
DNA_API int dna_engine_listen_all_contacts(
    dna_engine_t *engine
);

/**
 * Cancel all active outbox listeners
 *
 * @param engine    Engine instance
 */
DNA_API void dna_engine_cancel_all_outbox_listeners(
    dna_engine_t *engine
);

/**
 * Refresh all listeners (cancel stale and restart)
 *
 * Clears engine-level listener tracking arrays and restarts listeners
 * for all contacts. Use after network changes when DHT is reconnected
 * to ensure listeners are properly resubscribed.
 *
 * @param engine    Engine instance
 * @return          Number of listeners started, or -1 on error
 */
DNA_API int dna_engine_refresh_listeners(
    dna_engine_t *engine
);

/* ============================================================================
 * 7.6 DELIVERY TRACKERS (Message delivery confirmation)
 * ============================================================================ */

/**
 * Start tracking delivery status for a recipient
 *
 * Listens for watermark updates from the recipient. When they retrieve
 * messages and publish their watermark, this fires DNA_EVENT_MESSAGE_DELIVERED
 * and updates message status in the local database.
 *
 * Call this after sending an offline message to start tracking delivery.
 * Duplicate calls for the same recipient are ignored (idempotent).
 *
 * @param engine               Engine instance
 * @param recipient_fingerprint Recipient's fingerprint (128 hex chars)
 * @return                     0 on success, negative on error
 */
DNA_API int dna_engine_track_delivery(
    dna_engine_t *engine,
    const char *recipient_fingerprint
);

/**
 * Stop tracking delivery for a recipient
 *
 * Cancels the watermark listener for the specified recipient.
 *
 * @param engine               Engine instance
 * @param recipient_fingerprint Recipient's fingerprint
 */
DNA_API void dna_engine_untrack_delivery(
    dna_engine_t *engine,
    const char *recipient_fingerprint
);

/**
 * Cancel all active delivery trackers
 *
 * @param engine    Engine instance
 */
DNA_API void dna_engine_cancel_all_delivery_trackers(
    dna_engine_t *engine
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
DNA_API dna_request_id_t dna_engine_get_feed_channels(
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
DNA_API dna_request_id_t dna_engine_create_feed_channel(
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
DNA_API dna_request_id_t dna_engine_init_default_channels(
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
DNA_API dna_request_id_t dna_engine_get_feed_posts(
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
DNA_API dna_request_id_t dna_engine_create_feed_post(
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
DNA_API dna_request_id_t dna_engine_add_feed_comment(
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
DNA_API dna_request_id_t dna_engine_get_feed_comments(
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
DNA_API dna_request_id_t dna_engine_cast_feed_vote(
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
DNA_API dna_request_id_t dna_engine_get_feed_votes(
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
DNA_API dna_request_id_t dna_engine_cast_comment_vote(
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
DNA_API dna_request_id_t dna_engine_get_comment_votes(
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

/**
 * Check if DHT is connected
 *
 * Returns the current DHT connection status. Use this to query status
 * for UI indicators when the event-based status may have been missed.
 *
 * @param engine    Engine instance
 * @return          1 if connected, 0 if not connected
 */
DNA_API int dna_engine_is_dht_connected(dna_engine_t *engine);

/* ============================================================================
 * LOG CONFIGURATION
 * ============================================================================ */

/**
 * Get current log level
 *
 * @return Log level string: "DEBUG", "INFO", "WARN", "ERROR", or "NONE"
 */
DNA_API const char* dna_engine_get_log_level(void);

/**
 * Set log level
 *
 * @param level  Log level: "DEBUG", "INFO", "WARN", "ERROR", or "NONE"
 * @return       0 on success, -1 on error
 */
DNA_API int dna_engine_set_log_level(const char *level);

/**
 * Get current log tags filter
 *
 * @return Comma-separated tags string (empty = show all)
 */
DNA_API const char* dna_engine_get_log_tags(void);

/**
 * Set log tags filter
 *
 * @param tags  Comma-separated tags to show (empty = show all)
 * @return      0 on success, -1 on error
 */
DNA_API int dna_engine_set_log_tags(const char *tags);

/* ============================================================================
 * MEMORY MANAGEMENT
 * ============================================================================ */

/**
 * Free string array returned by callbacks
 */
DNA_API void dna_free_strings(char **strings, int count);

/**
 * Free contacts array returned by callbacks
 */
DNA_API void dna_free_contacts(dna_contact_t *contacts, int count);

/**
 * Free messages array returned by callbacks
 */
DNA_API void dna_free_messages(dna_message_t *messages, int count);

/**
 * Free groups array returned by callbacks
 */
DNA_API void dna_free_groups(dna_group_t *groups, int count);

/**
 * Free invitations array returned by callbacks
 */
DNA_API void dna_free_invitations(dna_invitation_t *invitations, int count);

/**
 * Free contact requests array returned by callbacks
 */
DNA_API void dna_free_contact_requests(dna_contact_request_t *requests, int count);

/**
 * Free blocked users array returned by callbacks
 */
DNA_API void dna_free_blocked_users(dna_blocked_user_t *blocked, int count);

/**
 * Free wallets array returned by callbacks
 */
DNA_API void dna_free_wallets(dna_wallet_t *wallets, int count);

/**
 * Free balances array returned by callbacks
 */
DNA_API void dna_free_balances(dna_balance_t *balances, int count);

/**
 * Free transactions array returned by callbacks
 */
DNA_API void dna_free_transactions(dna_transaction_t *transactions, int count);

/**
 * Free feed channels array returned by callbacks
 */
DNA_API void dna_free_feed_channels(dna_channel_info_t *channels, int count);

/**
 * Free feed posts array returned by callbacks
 */
DNA_API void dna_free_feed_posts(dna_post_info_t *posts, int count);

/**
 * Free single feed post returned by callbacks
 */
DNA_API void dna_free_feed_post(dna_post_info_t *post);

/**
 * Free feed comments array returned by callbacks
 */
DNA_API void dna_free_feed_comments(dna_comment_info_t *comments, int count);

/**
 * Free single feed comment returned by callbacks
 */
DNA_API void dna_free_feed_comment(dna_comment_info_t *comment);

/**
 * Free profile returned by callbacks
 */
DNA_API void dna_free_profile(dna_profile_t *profile);

/**
 * Free address book entries array returned by callbacks
 */
DNA_API void dna_free_addressbook_entries(dna_addressbook_entry_t *entries, int count);

/* ============================================================================
 * ADDRESS BOOK (wallet address storage)
 * ============================================================================ */

/**
 * Get all address book entries
 *
 * @param engine        Engine instance
 * @param callback      Result callback
 * @param user_data     User data for callback
 * @return              Request ID
 */
DNA_API dna_request_id_t dna_engine_get_addressbook(
    dna_engine_t *engine,
    dna_addressbook_cb callback,
    void *user_data
);

/**
 * Get address book entries by network
 *
 * @param engine        Engine instance
 * @param network       Network name (backbone, ethereum, solana, tron)
 * @param callback      Result callback
 * @param user_data     User data for callback
 * @return              Request ID
 */
DNA_API dna_request_id_t dna_engine_get_addressbook_by_network(
    dna_engine_t *engine,
    const char *network,
    dna_addressbook_cb callback,
    void *user_data
);

/**
 * Add address to address book (synchronous)
 *
 * @param engine        Engine instance
 * @param address       Wallet address
 * @param label         User-defined label
 * @param network       Network name
 * @param notes         Optional notes (can be NULL)
 * @return              0 on success, -1 on error, -2 if already exists
 */
DNA_API int dna_engine_add_address(
    dna_engine_t *engine,
    const char *address,
    const char *label,
    const char *network,
    const char *notes
);

/**
 * Update address in address book (synchronous)
 *
 * @param engine        Engine instance
 * @param id            Database row ID
 * @param label         New label
 * @param notes         New notes (can be NULL to clear)
 * @return              0 on success, -1 on error
 */
DNA_API int dna_engine_update_address(
    dna_engine_t *engine,
    int id,
    const char *label,
    const char *notes
);

/**
 * Remove address from address book (synchronous)
 *
 * @param engine        Engine instance
 * @param id            Database row ID
 * @return              0 on success, -1 on error
 */
DNA_API int dna_engine_remove_address(
    dna_engine_t *engine,
    int id
);

/**
 * Check if address exists in address book (synchronous)
 *
 * @param engine        Engine instance
 * @param address       Wallet address
 * @param network       Network name
 * @return              true if exists, false otherwise
 */
DNA_API bool dna_engine_address_exists(
    dna_engine_t *engine,
    const char *address,
    const char *network
);

/**
 * Lookup address by address string (synchronous)
 *
 * @param engine        Engine instance
 * @param address       Wallet address
 * @param network       Network name
 * @param entry_out     Output entry (caller must free with dna_free_addressbook_entries)
 * @return              0 on success, -1 on error, 1 if not found
 */
DNA_API int dna_engine_lookup_address(
    dna_engine_t *engine,
    const char *address,
    const char *network,
    dna_addressbook_entry_t *entry_out
);

/**
 * Increment address usage count (call after sending to address)
 *
 * @param engine        Engine instance
 * @param id            Database row ID
 * @return              0 on success, -1 on error
 */
DNA_API int dna_engine_increment_address_usage(
    dna_engine_t *engine,
    int id
);

/**
 * Get recently used addresses
 *
 * @param engine        Engine instance
 * @param limit         Maximum number of addresses to return
 * @param callback      Result callback
 * @param user_data     User data for callback
 * @return              Request ID
 */
DNA_API dna_request_id_t dna_engine_get_recent_addresses(
    dna_engine_t *engine,
    int limit,
    dna_addressbook_cb callback,
    void *user_data
);

/**
 * Sync address book to DHT
 *
 * @param engine        Engine instance
 * @param callback      Completion callback
 * @param user_data     User data for callback
 * @return              Request ID
 */
DNA_API dna_request_id_t dna_engine_sync_addressbook_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Sync address book from DHT (replace local)
 *
 * @param engine        Engine instance
 * @param callback      Completion callback
 * @param user_data     User data for callback
 * @return              Request ID
 */
DNA_API dna_request_id_t dna_engine_sync_addressbook_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * GLOBAL ENGINE ACCESS (for event dispatch from messenger layer)
 * ============================================================================ */

/**
 * Set the global engine instance
 *
 * Called by dna_engine_create() to make the engine accessible
 * from lower layers (e.g., messenger_p2p.c) for event dispatch.
 *
 * @param engine    Engine instance (or NULL to clear)
 */
DNA_API void dna_engine_set_global(dna_engine_t *engine);

/**
 * Get the global engine instance
 *
 * Returns the currently active engine for event dispatch.
 *
 * @return          Engine instance, or NULL if not set
 */
DNA_API dna_engine_t* dna_engine_get_global(void);

/**
 * Dispatch an event to Flutter/GUI layer
 *
 * Wrapper for internal dna_dispatch_event() that can be called
 * from messenger layer when new messages are received.
 *
 * @param engine    Engine instance
 * @param event     Event to dispatch
 */
void dna_dispatch_event(dna_engine_t *engine, const dna_event_t *event);

/* ============================================================================
 * DEBUG LOG API - In-app log viewing for mobile debugging
 * ============================================================================ */

/**
 * Debug log entry structure (matches qgp_log_entry_t)
 */
typedef struct {
    uint64_t timestamp_ms;      /* Unix timestamp in milliseconds */
    int level;                  /* 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR */
    char tag[32];               /* Module/tag name */
    char message[256];          /* Log message */
} dna_debug_log_entry_t;

/**
 * Enable/disable debug log ring buffer
 *
 * When enabled, logs are captured to an in-memory ring buffer
 * that can be viewed in the app. Disabled by default for performance.
 *
 * @param enabled   true to enable, false to disable
 */
DNA_API void dna_engine_debug_log_enable(bool enabled);

/**
 * Check if debug logging is enabled
 *
 * @return true if debug log ring buffer is active
 */
DNA_API bool dna_engine_debug_log_is_enabled(void);

/**
 * Get debug log entries from ring buffer
 *
 * Returns up to max_entries log entries in chronological order.
 * Caller must allocate the entries array.
 *
 * @param entries       Array to fill with log entries
 * @param max_entries   Maximum entries to return
 * @return              Number of entries actually filled
 */
DNA_API int dna_engine_debug_log_get_entries(dna_debug_log_entry_t *entries, int max_entries);

/**
 * Get number of entries in debug log buffer
 *
 * @return Number of log entries currently stored
 */
DNA_API int dna_engine_debug_log_count(void);

/**
 * Clear all debug log entries
 */
DNA_API void dna_engine_debug_log_clear(void);

/**
 * Add a log message from external code (e.g., Dart/Flutter)
 * @param tag Log tag (e.g., "FLUTTER")
 * @param message Log message
 */
DNA_API void dna_engine_debug_log_message(const char *tag, const char *message);

/**
 * Add a log message with explicit level from external code
 * @param tag Log tag (e.g., "FLUTTER")
 * @param message Log message
 * @param level Log level: 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
 */
DNA_API void dna_engine_debug_log_message_level(const char *tag, const char *message, int level);

/**
 * Export debug logs to a file
 * @param filepath Path to write log file
 * @return 0 on success, -1 on error
 */
DNA_API int dna_engine_debug_log_export(const char *filepath);

/* ============================================================================
 * MESSAGE BACKUP/RESTORE API
 * ============================================================================ */

/**
 * Backup result callback
 *
 * Called when backup or restore operation completes.
 *
 * @param request_id     Request ID from original call
 * @param error          0 on success, negative on error, -2 if not found (restore)
 * @param processed_count Number of messages backed up or restored
 * @param skipped_count   Number of duplicates skipped (restore only, 0 for backup)
 * @param user_data      User data from original call
 */
typedef void (*dna_backup_result_cb)(
    dna_request_id_t request_id,
    int error,
    int processed_count,
    int skipped_count,
    void *user_data
);

/**
 * Backup all messages to DHT
 *
 * Uploads all messages from SQLite to DHT with 7-day TTL.
 * Messages are encrypted with self-encryption (only owner can decrypt).
 *
 * @param engine     Engine instance
 * @param callback   Called on completion with message count
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_backup_messages(
    dna_engine_t *engine,
    dna_backup_result_cb callback,
    void *user_data
);

/**
 * Restore messages from DHT
 *
 * Downloads messages from DHT and imports to SQLite.
 * Duplicate messages are automatically skipped.
 *
 * @param engine     Engine instance
 * @param callback   Called on completion with restored/skipped counts
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_restore_messages(
    dna_engine_t *engine,
    dna_backup_result_cb callback,
    void *user_data
);

/* ============================================================================
 * VERSION CHECK API - DHT-based version announcements
 * ============================================================================ */

/**
 * Version information from DHT
 */
typedef struct {
    char library_current[32];   /* Latest library version (e.g., "0.3.90") */
    char library_minimum[32];   /* Minimum supported library version */
    char app_current[32];       /* Latest app version (e.g., "0.99.29") */
    char app_minimum[32];       /* Minimum supported app version */
    char nodus_current[32];     /* Latest nodus version (e.g., "0.4.3") */
    char nodus_minimum[32];     /* Minimum supported nodus version */
    uint64_t published_at;      /* Unix timestamp when published */
    char publisher[129];        /* Fingerprint of publisher */
} dna_version_info_t;

/**
 * Version check result
 */
typedef struct {
    bool library_update_available;  /* true if library_current > local version */
    bool app_update_available;      /* true if app_current > local version */
    bool nodus_update_available;    /* true if nodus_current > local version */
    dna_version_info_t info;        /* Version info from DHT */
} dna_version_check_result_t;

/**
 * Publish version info to DHT (signed with loaded identity)
 *
 * Publishes version information to a well-known DHT key. The first publisher
 * "owns" the key - only the same identity can update it (signed PUT).
 *
 * DHT Key: SHA3-512("dna:system:version")
 *
 * @param engine          Engine instance (must have identity loaded)
 * @param library_version Current library version (e.g., "0.3.90")
 * @param library_minimum Minimum supported library version
 * @param app_version     Current app version (e.g., "0.99.29")
 * @param app_minimum     Minimum supported app version
 * @param nodus_version   Current nodus version (e.g., "0.4.3")
 * @param nodus_minimum   Minimum supported nodus version
 * @return                0 on success, negative on error
 */
DNA_API int dna_engine_publish_version(
    dna_engine_t *engine,
    const char *library_version,
    const char *library_minimum,
    const char *app_version,
    const char *app_minimum,
    const char *nodus_version,
    const char *nodus_minimum
);

/**
 * Check version info from DHT
 *
 * Fetches version information from DHT and compares against local versions.
 * Sets update_available flags if newer versions exist.
 *
 * @param engine     Engine instance
 * @param result_out Output: version check result (caller provides buffer)
 * @return           0 on success, -1 on error, -2 if not found
 */
DNA_API int dna_engine_check_version_dht(
    dna_engine_t *engine,
    dna_version_check_result_t *result_out
);

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_H */
