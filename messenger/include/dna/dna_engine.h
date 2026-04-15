/*
 * DNA Connect Engine - Public API
 *
 * Unified async C API for DNA Connect core functionality.
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
 * Get DNA Connect version string
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
#define DNA_ENGINE_ERROR_NOT_CONNECTED  (-104)  /* DHT not connected (race: operation before bootstrap complete) */
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
#define DNA_ENGINE_ERROR_KEY_UNAVAILABLE (-116)  /* Recipient public key not cached and DHT lookup failed */
#define DNA_ENGINE_ERROR_IDENTITY_LOCKED (-117)  /* v0.6.0+: Identity lock held by another process (Flutter/Service) */
#define DNA_ENGINE_ERROR_LIMIT_REACHED (-118)   /* v0.9.52+: Maximum limit reached (e.g., max likes per post) */
#define DNA_ENGINE_ERROR_TEE_FAILED (-119)  /* TEE/hardware keystore key unavailable — restore from mnemonic */

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
 * Following entry (one-directional follow)
 */
typedef struct {
    char fingerprint[129];      /* Followed user's fingerprint */
    uint64_t followed_at;       /* Unix timestamp when followed */
} dna_following_t;

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
    int status;                 /* 0=pending, 1=sent, 2=received, 3=failed */
    int message_type;           /* 0=chat, 1=group_invitation, 2=cpunkTransfer, 3=reaction */
    bool deleted_by_sender;     /* true if sender deleted this message (v17) */
    char content_hash[65];      /* SHA3-256 hex (64 chars + null), empty if unavailable (v0.9.194) */
} dna_message_t;

/**
 * Reaction entry (one reactor applying one emoji to one target message)
 */
typedef struct {
    char reactor_fp[129];       /* Reactor fingerprint (128 hex + null) */
    char emoji[8];              /* UTF-8 emoji, max 4 bytes + null */
    uint64_t timestamp;         /* Unix timestamp when reaction was applied */
} dna_reaction_t;

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
 * Group member information
 */
typedef struct {
    char fingerprint[129];      /* Member fingerprint */
    uint64_t added_at;          /* When member was added (Unix timestamp) */
    bool is_owner;              /* True if this member is the group owner */
} dna_group_member_t;

/**
 * Extended group information (includes GEK version)
 */
typedef struct {
    char uuid[37];              /* UUID v4 string */
    char name[256];             /* Group name */
    char creator[129];          /* Creator fingerprint */
    int member_count;           /* Number of members */
    uint64_t created_at;        /* Unix timestamp */
    bool is_owner;              /* True if we are the owner */
    uint32_t gek_version;       /* Current GEK version */
} dna_group_info_t;

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
 * Wall: Post information (for async API callbacks)
 */
typedef struct {
    char uuid[37];                      /* UUID v4 */
    char author_fingerprint[129];       /* Author's SHA3-512 fingerprint */
    char author_name[65];              /* Resolved display name (empty if unknown) */
    char text[2048];                    /* Post content */
    char *image_json;                   /* Heap-allocated image JSON, NULL if no image (v0.7.0+) */
    uint64_t timestamp;                 /* Unix timestamp (seconds) */
    bool verified;                      /* Signature verified */
    bool is_boosted;                    /* Post is boosted (v0.9.98+) */
} dna_wall_post_info_t;

/**
 * Wall: Comment information (v0.7.0+, single-level threaded)
 */
typedef struct {
    char comment_uuid[37];          /* UUID v4 */
    char post_uuid[37];             /* Parent post UUID */
    char parent_comment_uuid[37];   /* Reply-to comment UUID (empty = top-level) */
    char author_fingerprint[129];   /* Author's SHA3-512 fingerprint */
    char author_name[65];           /* Resolved display name */
    char body[2001];                /* Comment content */
    uint64_t created_at;            /* Unix timestamp */
    bool verified;                  /* Signature verified */
    uint32_t comment_type;          /* 0=text, 1=tip */
} dna_wall_comment_info_t;

/**
 * Wall: Like information (v0.9.52+)
 */
typedef struct {
    char author_fingerprint[129];   /* Liker's SHA3-512 fingerprint */
    char author_name[65];           /* Resolved display name */
    uint64_t timestamp;             /* Unix timestamp (seconds) */
    bool verified;                  /* Signature verified */
} dna_wall_like_info_t;

/**
 * Wall: Per-post engagement data (v0.9.123+ batch)
 */
typedef struct {
    char post_uuid[37];
    dna_wall_comment_info_t *comments;
    int comment_count;
    int like_count;
    bool is_liked_by_me;
} dna_wall_engagement_t;

/* =====================================================
 * Channel System (RSS-like channels)
 * ===================================================== */

/**
 * Channel information (simplified for async API)
 */
typedef struct {
    char channel_uuid[37];          /* UUID v4 */
    char name[101];                 /* Channel name (max 100 chars) */
    char *description;              /* Optional description (caller frees, max 500 chars) */
    char creator_fingerprint[129];  /* Creator's SHA3-512 fingerprint */
    uint64_t created_at;            /* Unix timestamp */
    bool is_public;                 /* Listed on public DHT index */
    bool deleted;                   /* Soft delete flag */
    uint64_t deleted_at;            /* When deleted (0 if not deleted) */
    bool verified;                  /* Dilithium5 signature verified */
} dna_channel_info_t;

/**
 * Channel post (flat text entry in a channel)
 */
typedef struct {
    char post_uuid[37];             /* UUID v4 */
    char channel_uuid[37];          /* Parent channel UUID */
    char author_fingerprint[129];   /* Author's SHA3-512 fingerprint */
    char *body;                     /* Post text content (caller frees, max 4000 chars) */
    uint64_t created_at;            /* Unix timestamp */
    bool verified;                  /* Dilithium5 signature verified */
} dna_channel_post_info_t;

/**
 * Channel subscription (local + DHT sync)
 */
typedef struct {
    char channel_uuid[37];          /* UUID v4 of subscribed channel */
    uint64_t subscribed_at;         /* Unix timestamp when subscribed */
    uint64_t last_synced;           /* Unix timestamp of last DHT sync */
    uint64_t last_read_at;          /* For unread tracking */
} dna_channel_subscription_info_t;

/* Default channel constants */
#define DNA_DEFAULT_CHANNEL_COUNT 7
extern const char *DNA_DEFAULT_CHANNEL_UUIDS[DNA_DEFAULT_CHANNEL_COUNT];
extern const char *DNA_DEFAULT_CHANNEL_NAMES[DNA_DEFAULT_CHANNEL_COUNT];
extern const char *DNA_DEFAULT_CHANNEL_DESCRIPTIONS[DNA_DEFAULT_CHANNEL_COUNT];

/**
 * User profile information (wallet addresses, socials, bio, avatar)
 * Synced with DHT dna_unified_identity_t structure
 */
typedef struct {
    /* Cellframe wallet addresses */
    char backbone[120];
    char alvin[120];            /* Alvin (cpunk mainnet) */

    /* External wallet addresses */
    char eth[128];              /* Ethereum address */
    char sol[128];
    char trx[128];              /* TRON address (T...) */
    char bsc[128];              /* BSC address (EVM-compatible) */

    /* Social links */
    char telegram[128];
    char twitter[128];          /* X (Twitter) handle */
    char github[128];
    char facebook[128];
    char instagram[128];
    char linkedin[128];
    char google[128];

    /* Profile info */
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
 * Transaction status callback
 * status: 0=pending, 1=verified, 2=denied
 * tx_hash echoed back for matching
 */
typedef void (*dna_tx_status_cb)(
    dna_request_id_t request_id,
    const char *error,
    const char *tx_hash,
    int status,
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
 * Following list callback
 * Caller takes ownership of @p following - free with dna_free_following()
 */
typedef void (*dna_following_cb)(
    dna_request_id_t request_id,
    int error,
    dna_following_t *following,
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
 * Messages page callback (with total count for pagination)
 */
typedef void (*dna_messages_page_cb)(
    dna_request_id_t request_id,
    int error,
    dna_message_t *messages,
    int count,
    int total,
    void *user_data
);

/**
 * Reactions callback
 *
 * @param request_id Request ID
 * @param error      0 on success, error code otherwise
 * @param reactions  Array of reactions (caller must free via dna_free_reactions)
 * @param count      Number of reactions
 * @param user_data  User data
 */
typedef void (*dna_reactions_cb)(
    dna_request_id_t request_id,
    int error,
    dna_reaction_t *reactions,
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
 * Group info callback (extended info with GEK version)
 */
typedef void (*dna_group_info_cb)(
    dna_request_id_t request_id,
    int error,
    dna_group_info_t *info,
    void *user_data
);

/**
 * Group members callback
 */
typedef void (*dna_group_members_cb)(
    dna_request_id_t request_id,
    int error,
    dna_group_member_t *members,
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

/* Channel callbacks */
typedef void (*dna_channel_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_info_t *channel, void *user_data);

typedef void (*dna_channels_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_info_t *channels, int count, void *user_data);

typedef void (*dna_channel_post_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_post_info_t *post, void *user_data);

typedef void (*dna_channel_posts_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_post_info_t *posts, int count, void *user_data);

typedef void (*dna_channel_subscriptions_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_subscription_info_t *subscriptions, int count, void *user_data);

/**
 * Wall: Single post callback (for post creation)
 * Caller takes ownership of @p post - free with dna_free_wall_posts(post, 1)
 */
typedef void (*dna_wall_post_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_post_info_t *post,    /* caller-owned, free with dna_free_wall_posts */
    void *user_data
);

/**
 * Wall: Posts list callback (for wall load and timeline)
 * Caller takes ownership of @p posts - free with dna_free_wall_posts(posts, count)
 */
typedef void (*dna_wall_posts_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_post_info_t *posts,   /* caller-owned, free with dna_free_wall_posts */
    int count,
    void *user_data
);

/**
 * Wall: Single comment callback (v0.7.0+)
 * Caller takes ownership - free with dna_free_wall_comments(comment, 1)
 */
typedef void (*dna_wall_comment_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_comment_info_t *comment,
    void *user_data
);

/**
 * Wall: Comments list callback (v0.7.0+)
 * Caller takes ownership - free with dna_free_wall_comments(comments, count)
 */
typedef void (*dna_wall_comments_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_comment_info_t *comments,
    int count,
    void *user_data
);

/**
 * Wall: Likes list callback (v0.9.52+)
 * Caller takes ownership - free with dna_free_wall_likes(likes, count)
 */
typedef void (*dna_wall_likes_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_like_info_t *likes,
    int count,
    void *user_data
);

/**
 * Wall: Batch engagement callback (v0.9.123+)
 * Returns engagement data for multiple posts in one call.
 * Caller takes ownership - free with dna_free_wall_engagement(engagements, count)
 */
typedef void (*dna_wall_engagement_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_engagement_t *engagements,
    int count,
    void *user_data
);

/**
 * Wall: Image fetch callback (v0.9.142+)
 * Returns image JSON for a single post from local cache.
 */
typedef void (*dna_wall_image_cb)(
    dna_request_id_t request_id,
    int error,
    const char *image_json,
    void *user_data
);

/**
 * Media: Upload callback (v0.9.146+)
 * Called when media upload completes. content_hash is the SHA3-512 of the uploaded data.
 */
typedef void (*dna_media_upload_cb)(
    dna_request_id_t request_id,
    int error,
    const uint8_t content_hash[64],
    void *user_data
);

/**
 * Media: Download callback (v0.9.146+)
 * Called with the downloaded data. Caller must copy data if needed beyond callback scope.
 */
typedef void (*dna_media_download_cb)(
    dna_request_id_t request_id,
    int error,
    const uint8_t *data,
    size_t data_len,
    void *user_data
);

/**
 * Media: Exists callback (v0.9.146+)
 * Called with whether the media exists (complete upload) on DHT.
 */
typedef void (*dna_media_exists_cb)(
    dna_request_id_t request_id,
    int error,
    bool exists,
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
    DNA_EVENT_GROUP_MESSAGE_RECEIVED,    /* New group messages via DHT listen */
    DNA_EVENT_GROUPS_SYNCED,             /* Groups restored from DHT to local cache */
    DNA_EVENT_CONTACTS_SYNCED,           /* Contacts restored from DHT to local cache */
    DNA_EVENT_GEKS_SYNCED,               /* GEKs restored from DHT to local cache */
    DNA_EVENT_DHT_PUBLISH_COMPLETE,      /* Async DHT publish completed successfully (v0.6.80+) */
    DNA_EVENT_DHT_PUBLISH_FAILED,        /* Async DHT publish failed after retries (v0.6.80+) */
    DNA_EVENT_WALL_NEW_POST,             /* New wall post from a contact (v0.6.135+) */
    DNA_EVENT_CHANNEL_NEW_POST,          /* New post in subscribed channel */
    DNA_EVENT_CHANNEL_SUBS_SYNCED,       /* Channel subscriptions synced from DHT */
    DNA_EVENT_MEDIA_UPLOAD_PROGRESS,     /* Media upload byte progress (v0.9.151+) */
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
            char recipient[129];  /* Recipient fingerprint (v0.6.126+) */
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
            char group_uuid[37];            /* Group UUID */
            int new_count;                  /* Number of new messages received */
        } group_message;
        struct {
            int groups_restored;            /* Number of groups restored from DHT */
        } groups_synced;
        struct {
            int contacts_synced;            /* Number of contacts synced from DHT */
        } contacts_synced;
        struct {
            int geks_synced;                /* Number of GEKs synced from DHT (0=none, 1=success) */
        } geks_synced;
        struct {
            uint64_t request_id;            /* Request ID from dht_chunked_publish_async() */
            char base_key[256];             /* DHT key that was published */
            int error_code;                 /* DHT_CHUNK_* error code (0 on success) */
        } dht_publish;
        struct {
            char author_fingerprint[129];   /* Post author's fingerprint */
            char post_uuid[37];             /* New post UUID */
        } wall_new_post;
        struct {
            char channel_uuid[37];
            char post_uuid[37];
            char author_fingerprint[129];
        } channel_new_post;
        struct {
            int subscriptions_synced;
        } channel_subs_synced;
        struct {
            uint64_t bytes_sent;
            uint64_t total_bytes;
            uint64_t request_id;            /* Matches the upload request ID */
        } media_upload_progress;
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
 * Create DNA engine instance (synchronous)
 *
 * Initializes engine and spawns internal worker threads for:
 * - DHT network operations
 * - P2P transport
 * - Offline message polling
 * - RPC queries
 *
 * WARNING: This blocks the calling thread. On mobile platforms, prefer
 * dna_engine_create_async() to avoid blocking the UI thread.
 *
 * @param data_dir  Path to data directory (NULL for default ~/.dna)
 * @return          Engine instance or NULL on error
 */
DNA_API dna_engine_t* dna_engine_create(const char *data_dir);

/**
 * Engine creation completion callback
 *
 * Called when async engine creation completes.
 *
 * @param engine    Created engine instance (or NULL on error)
 * @param error     0 on success, error code on failure
 * @param user_data User data passed to create function
 */
typedef void (*dna_engine_created_cb)(dna_engine_t *engine, int error, void *user_data);

/**
 * Create DNA engine instance (asynchronous)
 *
 * Non-blocking engine creation that runs initialization on a background thread.
 * The callback is called when initialization completes.
 *
 * This avoids blocking the UI thread on mobile platforms.
 *
 * @param data_dir  Path to data directory (NULL for default ~/.dna)
 * @param callback  Called when engine is ready (from background thread)
 * @param user_data User data passed to callback
 * @param cancelled Pointer to atomic bool - set to true to cancel (callback won't fire)
 *                  Caller owns this memory and must keep it valid until callback fires or cancelled.
 */
DNA_API void dna_engine_create_async(
    const char *data_dir,
    dna_engine_created_cb callback,
    void *user_data,
    _Atomic bool *cancelled
);

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

/* Android notification/service callbacks removed in v0.9.7 */

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
 * Request engine shutdown without destroying (v0.6.115+)
 *
 * Sets the shutdown_requested flag which causes all ongoing operations
 * to abort early. Unlike dna_engine_destroy(), this does NOT free resources
 * or wait for threads - it just signals them to stop.
 *
 * Use case: Android service calling this BEFORE acquiring engine lock,
 * so that ongoing DHT operations abort quickly and release locks.
 *
 * After calling this, the engine should be destroyed with dna_engine_destroy().
 *
 * @param engine    Engine instance (can be NULL, does nothing)
 */
DNA_API void dna_engine_request_shutdown(dna_engine_t *engine);

/**
 * Check if shutdown was requested (v0.6.116+)
 *
 * @param engine    Engine instance (can be NULL)
 * @return          true if shutdown was requested, false otherwise
 */
DNA_API bool dna_engine_is_shutdown_requested(dna_engine_t *engine);

/**
 * Pause engine for background mode (v0.6.50+)
 *
 * Suspends DHT listeners and presence heartbeat while keeping the engine
 * alive. This allows fast resume (<500ms) when the app returns to foreground,
 * avoiding the expensive full reinitialization (2-40 seconds).
 *
 * What happens during pause:
 * - DHT listeners are suspended (not destroyed)
 * - Presence heartbeat is paused (stops marking us as online)
 * - DHT connection stays alive
 * - Identity lock is kept
 * - Databases remain open
 * - Worker threads keep running (but idle)
 *
 * Use dna_engine_resume() to reactivate the engine.
 *
 * @param engine    Engine instance
 * @return          0 on success, negative error code on failure
 */
DNA_API int dna_engine_pause(dna_engine_t *engine);

/**
 * Resume engine from background mode (v0.6.50+)
 *
 * Reactivates a paused engine by resubscribing DHT listeners and
 * resuming presence heartbeat. This is much faster than destroying
 * and recreating the engine.
 *
 * What happens during resume:
 * - DHT listeners are resubscribed
 * - Presence heartbeat is resumed (marks us as online again)
 * - Immediate presence refresh
 *
 * @param engine    Engine instance
 * @return          0 on success, negative error code on failure
 */
DNA_API int dna_engine_resume(dna_engine_t *engine);

/**
 * Check if engine is in paused state (v0.6.50+)
 *
 * @param engine    Engine instance
 * @return          true if engine is paused, false otherwise
 */
DNA_API bool dna_engine_is_paused(dna_engine_t *engine);

/**
 * Get current identity fingerprint
 *
 * @param engine    Engine instance
 * @return          Fingerprint string (128 hex chars) or NULL if no identity loaded
 */
DNA_API const char* dna_engine_get_fingerprint(dna_engine_t *engine);

/**
 * @brief Get the engine's data directory path
 * @param engine Engine instance
 * @return Data directory path (e.g., "/data/data/app/.dna" on Android, "~/.dna" on desktop)
 */
DNA_API const char* dna_engine_get_data_dir(dna_engine_t *engine);

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
 * Load identity with minimal initialization (v0.5.24+, v0.6.15+)
 *
 * Used by Android background service (DnaMessengerService) when starting
 * without Flutter UI. Performs minimal initialization to save resources:
 * - Initializes DHT connection
 * - Starts offline message polling
 * - Does NOT start transport layer
 * - Does NOT start presence heartbeat
 * - Does NOT retry pending messages
 *
 * @param engine      Engine instance
 * @param fingerprint Identity fingerprint (128 hex chars)
 * @param password    Password for encrypted keys (NULL if unencrypted)
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_load_identity_minimal(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Check if identity is loaded
 *
 * @param engine    Engine instance
 * @return          true if identity is loaded, false otherwise
 */
DNA_API bool dna_engine_is_identity_loaded(dna_engine_t *engine);

/**
 * Check if transport layer is initialized
 *
 * Returns false if identity was loaded in minimal mode (DHT only).
 * When false, offline message fetching won't work - need to reload identity in full mode.
 *
 * @param engine    Engine instance
 * @return          true if transport is ready, false otherwise
 */
DNA_API bool dna_engine_is_transport_ready(dna_engine_t *engine);

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
 * Send a reaction to a message (async)
 *
 * @param engine                Engine instance
 * @param recipient_fingerprint Target recipient fingerprint (128 hex + null)
 * @param target_content_hash   content_hash of the message being reacted to (64 hex chars)
 * @param emoji                 UTF-8 emoji (must be one of the allowed 8)
 * @param op                    "add" or "remove"
 * @param callback              Called on completion
 * @param user_data             User data for callback
 * @return                      Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_send_reaction(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *target_content_hash,
    const char *emoji,
    const char *op,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get the live reaction list for a target message (async, DB-only)
 *
 * Scans local message backup for message_type=3 rows matching
 * target_content_hash and replays add/remove ops in timestamp order.
 *
 * @param engine               Engine instance
 * @param target_content_hash  64-hex hash of the target message
 * @param callback             Called with the reactions array (owned by caller)
 * @param user_data            User data for callback
 * @return                     Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_reactions(
    dna_engine_t *engine,
    const char *target_content_hash,
    dna_reactions_cb callback,
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
 * Get conversation page with contact (paginated)
 *
 * Returns a page of messages for efficient chat loading.
 * Messages ordered by timestamp DESC (newest first).
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact fingerprint
 * @param limit               Max messages to return (page size)
 * @param offset              Messages to skip (for pagination)
 * @param callback            Called with messages array and total count
 * @param user_data           User data for callback
 * @return                    Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_conversation_page(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    int limit,
    int offset,
    dna_messages_page_cb callback,
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
 * Check for offline messages without publishing watermarks (background caching)
 *
 * Same as dna_engine_check_offline_messages() but does NOT notify senders
 * that messages were received. Use for background polling where user hasn't
 * actually read the messages yet.
 *
 * This function emits DNA_EVENT_OUTBOX_UPDATED for each contact with new
 * messages, triggering Android notifications when Flutter is not attached.
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_check_offline_messages_cached(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Force check for offline messages from a specific contact
 *
 * Queries only the specified contact's outbox instead of all contacts.
 * Use this when entering a chat to get immediate updates from that contact.
 *
 * @param engine              Engine instance
 * @param contact_fingerprint Contact fingerprint to check
 * @param callback            Called on completion
 * @param user_data           User data for callback
 * @return                    Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_check_offline_messages_from(
    dna_engine_t *engine,
    const char *contact_fingerprint,
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

/**
 * Delete a message with full pipeline (local + DHT + notices)
 */
DNA_API dna_request_id_t dna_engine_delete_message(
    dna_engine_t *engine, int message_id, bool send_notices,
    dna_completion_cb callback, void *user_data);

/**
 * Delete all messages with a contact (purge conversation)
 */
DNA_API dna_request_id_t dna_engine_delete_conversation(
    dna_engine_t *engine, const char *contact_fingerprint, bool send_notices,
    dna_completion_cb callback, void *user_data);

/**
 * Delete all messages (purge everything)
 */
DNA_API dna_request_id_t dna_engine_delete_all_messages(
    dna_engine_t *engine, bool send_notices,
    dna_completion_cb callback, void *user_data);

/**
 * Retry all pending/failed messages
 *
 * Queries local database for messages with status PENDING(0) or FAILED(3)
 * and attempts to re-queue them to DHT. Called automatically on:
 * - Identity load (app startup)
 * - DHT reconnect (network change)
 *
 * Messages that exceed max_retries (10) are skipped and remain as FAILED.
 *
 * @param engine     Engine instance
 * @return           Number of messages successfully retried, or -1 on error
 */
DNA_API int dna_engine_retry_pending_messages(dna_engine_t *engine);

/**
 * Retry a single failed message by ID
 *
 * Attempts to re-send a specific message. Use this for manual retry
 * (e.g., user taps retry button on failed message).
 *
 * @param engine     Engine instance
 * @param message_id Message ID from local database
 * @return           0 on success, -1 on error (not found or not retryable)
 */
DNA_API int dna_engine_retry_message(dna_engine_t *engine, int message_id);

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
 * Get extended group info (includes GEK version)
 *
 * @param engine     Engine instance
 * @param group_uuid Group UUID
 * @param callback   Called with group info
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_group_info(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_group_info_cb callback,
    void *user_data
);

/**
 * Get group members
 *
 * @param engine     Engine instance
 * @param group_uuid Group UUID
 * @param callback   Called with members array
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_group_members(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_group_members_cb callback,
    void *user_data
);

/**
 * Create new group
 *
 * Creates group with GEK (Group Encryption Key) encryption.
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
 * Encrypts with GEK (AES-256-GCM), signs with Dilithium5.
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
 * Queue group message for async sending (fire-and-forget)
 *
 * Same as dna_engine_send_group_message but returns immediately.
 * Message is queued and sent in background. Use for optimistic UI.
 *
 * @param engine     Engine instance
 * @param group_uuid Group UUID
 * @param message    Message text
 * @return           >= 0: queue slot ID (success)
 *                   -1: queue full
 *                   -2: invalid args or not initialized
 */
DNA_API int dna_engine_queue_group_message(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *message
);

/**
 * Get group conversation messages
 *
 * Retrieves all messages from a group, decrypted with GEK.
 * Messages are returned in chronological order (oldest first).
 *
 * @param engine      Engine instance
 * @param group_uuid  Group UUID
 * @param callback    Called with messages array
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_group_conversation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_messages_cb callback,
    void *user_data
);

/**
 * Add member to group
 *
 * Adds member to group in DHT, rotates GEK, sends invitation.
 * Only group owner can add members.
 *
 * @param engine      Engine instance
 * @param group_uuid  Group UUID
 * @param fingerprint Member fingerprint to add
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_add_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Remove member from group
 *
 * Removes member from group in DHT and rotates GEK for forward secrecy.
 * Only group owner can remove members.
 *
 * @param engine      Engine instance
 * @param group_uuid  Group UUID
 * @param fingerprint Member fingerprint to remove
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_remove_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
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
 * Get cached balances from SQLite (instant, no network calls)
 * Returns previously fetched balances from local cache.
 * Use for stale-while-revalidate: show cached data instantly,
 * then call dna_engine_get_balances() for live update.
 * Returns empty (count=0) if no cache exists yet.
 */
DNA_API dna_request_id_t dna_engine_get_cached_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
);

/**
 * Gas estimate result
 */
typedef struct {
    char fee_eth[32];       /* Fee in ETH (e.g., "0.000042") */
    uint64_t gas_price;     /* Gas price in wei */
    uint64_t gas_limit;     /* Gas limit (21000 for ETH transfer) */
} dna_gas_estimate_t;

/**
 * Gas estimates for all speeds (single RPC call)
 */
typedef struct {
    dna_gas_estimate_t slow;    /* 0.8x base gas price */
    dna_gas_estimate_t normal;  /* 1.0x base gas price */
    dna_gas_estimate_t fast;    /* 1.5x base gas price */
} dna_gas_estimates_t;

/**
 * Gas estimates callback (all 3 speeds from single RPC call)
 * Error is 0 (DNA_OK) on success, negative on error
 * estimates is NULL on error
 */
typedef void (*dna_gas_estimates_cb)(
    dna_request_id_t request_id,
    int error,
    const dna_gas_estimates_t *estimates,
    void *user_data
);

/**
 * Get gas fee estimate for ETH transaction (DEPRECATED - use dna_engine_estimate_gas_async)
 *
 * Synchronous call - queries current network gas price.
 *
 * @param gas_speed     Gas speed preset (0=slow, 1=normal, 2=fast)
 * @param estimate_out  Output: gas estimate
 * @return              0 on success, -1 on error
 */
DNA_API int dna_engine_estimate_eth_gas(int gas_speed, dna_gas_estimate_t *estimate_out);

/**
 * Estimate ETH gas fees asynchronously (all 3 speeds in one RPC call)
 *
 * @param engine       Engine instance
 * @param callback     Called on completion with all 3 gas estimates
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_estimate_gas_async(
    dna_engine_t *engine,
    dna_gas_estimates_cb callback,
    void *user_data
);

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
 * Get transaction verification status from blockchain
 *
 * Checks cache first. If cached as final (verified/denied), returns immediately.
 * If pending or uncached, queries blockchain via the chain's get_tx_status op.
 *
 * @param engine    Engine instance
 * @param tx_hash   Transaction hash to verify
 * @param chain     Blockchain name ("cellframe", "ethereum", "solana", "tron")
 * @param callback  Called with status result
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_tx_status(
    dna_engine_t *engine,
    const char *tx_hash,
    const char *chain,
    dna_tx_status_cb callback,
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

/**
 * Get cached transactions from SQLite (instant, no network calls)
 * Returns previously fetched transactions from local cache.
 * Use for stale-while-revalidate: show cached data instantly,
 * then call dna_engine_get_transactions() for live update.
 * Returns empty (count=0) if no cache exists yet.
 */
DNA_API dna_request_id_t dna_engine_get_cached_transactions(
    dna_engine_t *engine,
    int wallet_index,
    const char *network,
    dna_transactions_cb callback,
    void *user_data
);

/* ============================================================================
 * 6b. DEX (Decentralized Exchange)
 * ============================================================================ */

/**
 * DEX quote result
 */
typedef struct {
    char from_token[16];        /* Input token symbol */
    char to_token[16];          /* Output token symbol */
    char amount_in[64];         /* Input amount (decimal string) */
    char amount_out[64];        /* Output amount (decimal string) */
    char price[64];             /* Spot price (1 from = X to) */
    char price_impact[16];      /* Price impact percentage */
    char fee[64];               /* Fee in input token */
    char pool_address[48];      /* Pool address used */
    char dex_name[32];          /* DEX name (e.g. "Raydium AMM v4", "Uniswap v2") */
    char chain[8];              /* Chain identifier ("SOL", "ETH", "CELL") */
    char warning[128];          /* Warning message (empty if none) */
} dna_dex_quote_t;

/**
 * DEX quote callback
 *
 * Returns an array of quotes from all matching DEXes (or filtered by dex_filter).
 */
typedef void (*dna_dex_quote_cb)(
    dna_request_id_t request_id,
    int error,
    const dna_dex_quote_t *quotes,
    int count,
    void *user_data
);

/**
 * DEX pairs callback
 */
typedef void (*dna_dex_pairs_cb)(
    dna_request_id_t request_id,
    int error,
    const char **pairs,
    int count,
    void *user_data
);

/**
 * Get DEX swap quotes
 *
 * Fetches on-chain quotes from all matching DEXes and returns them all.
 * If dex_filter is set, only quotes from that DEX are returned.
 *
 * @param engine       Engine instance
 * @param from_token   Input token symbol (e.g., "SOL")
 * @param to_token     Output token symbol (e.g., "USDT")
 * @param amount_in    Input amount as decimal string (e.g., "1.5")
 * @param dex_filter   DEX name filter (NULL=all, e.g. "uniswap-v3", "raydium")
 * @param callback     Called with array of quote results
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_dex_quote(
    dna_engine_t *engine,
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    dna_dex_quote_cb callback,
    void *user_data
);

/**
 * List available DEX swap pairs
 *
 * @param engine       Engine instance
 * @param callback     Called with pairs array
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_dex_list_pairs(
    dna_engine_t *engine,
    dna_dex_pairs_cb callback,
    void *user_data
);

/**
 * DEX swap result
 */
typedef struct {
    char tx_signature[128];     /* Transaction signature (base58) */
    char amount_in[64];         /* Input amount (decimal string) */
    char amount_out[64];        /* Expected output amount (decimal string) */
    char from_token[16];        /* Input token symbol */
    char to_token[16];          /* Output token symbol */
    char dex_name[32];          /* DEX name from route */
    char price_impact[16];      /* Price impact percentage */
} dna_dex_swap_result_t;

/**
 * DEX swap callback
 */
typedef void (*dna_dex_swap_cb)(
    dna_request_id_t request_id,
    int error,
    const dna_dex_swap_result_t *result,
    void *user_data
);

/**
 * Execute DEX swap (Solana only)
 *
 * Fetches quote, builds swap TX via Jupiter, signs locally, submits to Solana.
 * Private key never leaves the device.
 *
 * @param engine       Engine instance
 * @param wallet_index Wallet index (unused, Solana wallet auto-selected)
 * @param from_token   Input token symbol (e.g., "SOL")
 * @param to_token     Output token symbol (e.g., "USDC")
 * @param amount_in    Input amount as decimal string (e.g., "0.01")
 * @param callback     Called with swap result (tx signature)
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_dex_swap(
    dna_engine_t *engine,
    int wallet_index,
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    dna_dex_swap_cb callback,
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
 * Sync groups to DHT (publish local group list)
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_sync_groups_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Restore groups from DHT grouplist to local cache
 *
 * Fetches user's personal group list from DHT and restores
 * group metadata to local database. Used for multi-device sync.
 *
 * @param engine    Engine instance
 * @param callback  Called on completion
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_restore_groups_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Sync a specific group from DHT to local cache
 *
 * Uses the group UUID to fetch metadata from DHT and update local database.
 * Useful for recovering groups after database reset.
 *
 * @param engine      Engine instance
 * @param group_uuid  Group UUID (36 chars)
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_sync_group_by_uuid(
    dna_engine_t *engine,
    const char *group_uuid,
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

/* NOTE: dna_engine_listen_all_contacts_minimal() removed in v0.6.15
 * Android service now uses polling (dna_engine_check_offline_messages)
 * instead of listeners for better battery efficiency. */

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
 * Free reactions array returned by callbacks
 */
DNA_API void dna_free_reactions(dna_reaction_t *reactions, int count);

/**
 * Free groups array returned by callbacks
 */
DNA_API void dna_free_groups(dna_group_t *groups, int count);

/**
 * Free group info returned by callbacks
 */
DNA_API void dna_free_group_info(dna_group_info_t *info);

/**
 * Free group members array returned by callbacks
 */
DNA_API void dna_free_group_members(dna_group_member_t *members, int count);

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
 * Free single channel info returned by callbacks
 */
DNA_API void dna_free_channel_info(dna_channel_info_t *channel);

/**
 * Free channel infos array returned by callbacks
 */
DNA_API void dna_free_channel_infos(dna_channel_info_t *channels, int count);

/**
 * Free single channel post returned by callbacks
 */
DNA_API void dna_free_channel_post(dna_channel_post_info_t *post);

/**
 * Free channel posts array returned by callbacks
 */
DNA_API void dna_free_channel_posts(dna_channel_post_info_t *posts, int count);

/**
 * Free channel subscriptions array returned by callbacks
 */
DNA_API void dna_free_channel_subscriptions(dna_channel_subscription_info_t *subs, int count);

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
 * from lower layers (e.g., messenger_transport.c) for event dispatch.
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

/**
 * Backup info structure for check_backup_exists
 * NOTE: Explicit padding for cross-platform FFI compatibility (32-bit vs 64-bit)
 */
typedef struct {
    bool exists;              /* True if backup found in DHT */
    uint8_t _padding[7];      /* Explicit padding for 8-byte alignment */
    uint64_t timestamp;       /* Backup timestamp (Unix epoch) */
    int32_t message_count;    /* Number of messages (-1 if unknown) */
} dna_backup_info_t;

/**
 * Callback for backup info check
 *
 * @param request_id  Request ID from the call
 * @param error       0 on success, -1 on error
 * @param info        Backup info (only valid if error == 0)
 * @param user_data   User data from the call
 */
typedef void (*dna_backup_info_cb)(
    int request_id,
    int error,
    const dna_backup_info_t *info,
    void *user_data
);

/**
 * Check if message backup exists in DHT
 *
 * Useful for new device setup - check if user has existing backup
 * before prompting to restore.
 *
 * @param engine     Engine instance
 * @param callback   Called on completion with backup info
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_check_backup_exists(
    dna_engine_t *engine,
    dna_backup_info_cb callback,
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
    bool library_below_minimum;     /* true if local version < library_minimum (BLOCKS APP) */
    bool app_below_minimum;         /* true if local app version < app_minimum (BLOCKS APP) */
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

/* ============================================================================
 * WALL (personal wall posts, v0.6.135+)
 * ============================================================================ */

/**
 * Post a message to own wall
 *
 * @param engine    Engine instance
 * @param text      Post text (max 2047 chars, will be truncated)
 * @param callback  Called with created post info
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_post(
    dna_engine_t *engine,
    const char *text,
    dna_wall_post_cb callback,
    void *user_data
);

/**
 * Post a message with image to own wall (v0.7.0+)
 *
 * @param engine      Engine instance
 * @param text        Post text (max 2047 chars, will be truncated)
 * @param image_json  JSON string with image data (base64 + metadata), NULL for text-only
 * @param callback    Called with created post info
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_post_with_image(
    dna_engine_t *engine,
    const char *text,
    const char *image_json,
    dna_wall_post_cb callback,
    void *user_data
);

/**
 * Delete own wall post
 *
 * @param engine     Engine instance
 * @param post_uuid  UUID of post to delete
 * @param callback   Called when complete
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_delete(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Load a user's wall posts
 *
 * @param engine       Engine instance
 * @param fingerprint  Wall owner's fingerprint
 * @param callback     Called with posts array
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_load(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Load timeline (all contacts' wall posts merged)
 *
 * Returns posts from all contacts sorted by timestamp descending.
 * Also includes own posts.
 *
 * @param engine    Engine instance
 * @param callback  Called with merged posts array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Get wall timeline from local cache only (no identity/DHT required).
 * Returns cached posts for own + contacts' walls without network access.
 * Use at startup to show content immediately before identity is fully loaded.
 *
 * @param engine      Engine instance
 * @param fingerprint Owner's 128-char hex fingerprint (for contacts lookup)
 * @param callback    Called with cached posts array
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_timeline_cached(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Free wall posts array returned by callbacks
 */
DNA_API void dna_free_wall_posts(dna_wall_post_info_t *posts, int count);

/* ── Wall Comments (v0.7.0+) ── */

/**
 * Add a comment to a wall post
 *
 * @param engine               Engine instance
 * @param post_uuid            UUID of the wall post to comment on
 * @param parent_comment_uuid  Parent comment UUID for replies (NULL = top-level)
 * @param body                 Comment text (max 2000 chars)
 * @param callback             Called with created comment info
 * @param user_data            User data for callback
 * @return                     Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_add_comment(
    dna_engine_t *engine,
    const char *post_uuid,
    const char *parent_comment_uuid,
    const char *body,
    dna_wall_comment_cb callback,
    void *user_data
);

/**
 * Add a tip comment to a wall post (comment_type=1)
 *
 * @param engine     Engine instance
 * @param post_uuid  UUID of the wall post to tip on
 * @param body       JSON body: {"amount":N,"token":"CPUNK","txHash":"...","chain":"cellframe"}
 * @param callback   Called with created comment info
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_add_tip_comment(
    dna_engine_t *engine,
    const char *post_uuid,
    const char *body,
    dna_wall_comment_cb callback,
    void *user_data
);

/**
 * Get all comments for a wall post
 *
 * @param engine     Engine instance
 * @param post_uuid  UUID of the wall post
 * @param callback   Called with comments array
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_get_comments(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_comments_cb callback,
    void *user_data
);

/**
 * Free wall comments array returned by callbacks
 */
DNA_API void dna_free_wall_comments(dna_wall_comment_info_t *comments, int count);

/* ── Wall Likes (v0.9.52+) ── */

/**
 * Like a wall post
 *
 * Signs post_uuid with Dilithium5 and publishes to DHT.
 * Returns error -3 if already liked, -4 if max likes reached.
 *
 * @param engine     Engine instance
 * @param post_uuid  UUID of the post to like
 * @param callback   Likes list callback (returns updated likes)
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_like(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_likes_cb callback,
    void *user_data
);

/**
 * Get likes for a wall post
 *
 * @param engine     Engine instance
 * @param post_uuid  UUID of the post
 * @param callback   Likes list callback
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_get_likes(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_likes_cb callback,
    void *user_data
);

/**
 * Free wall likes array returned by callbacks
 */
DNA_API void dna_free_wall_likes(dna_wall_like_info_t *likes, int count);

/* ── Wall Engagement Batch (v0.9.123+) ── */

/**
 * Batch fetch engagement (comments + like count) for multiple posts.
 * Uses get_batch for comments (full data) and count_batch for likes (count only).
 * Reduces N*2 DHT requests to 2 batch requests.
 *
 * @param post_uuids  Array of post UUID strings (max 32)
 * @param post_count  Number of posts
 */
DNA_API dna_request_id_t dna_engine_wall_get_engagement(
    dna_engine_t *engine,
    const char **post_uuids,
    int post_count,
    dna_wall_engagement_cb callback,
    void *user_data
);

/**
 * Wall Engagement Batch — cache-only variant (v0.10.7+)
 *
 * Returns cached comment/like counts immediately (SQLite only, no DHT).
 * Completes in ~ms even for large batches. Use for first paint; follow up
 * with dna_engine_wall_get_engagement() to refresh stale entries from DHT.
 */
DNA_API dna_request_id_t dna_engine_wall_get_engagement_cached(
    dna_engine_t *engine,
    const char **post_uuids,
    int post_count,
    dna_wall_engagement_cb callback,
    void *user_data
);

/** Free engagement array returned by callback */
DNA_API void dna_free_wall_engagement(dna_wall_engagement_t *engagements, int count);

/* ============================================================================
 * WALL BOOST (v0.9.71+ — Global boosted posts)
 *
 * Boosted posts are published to a daily multi-owner DHT key visible to all
 * users. The boost key contains lightweight pointers; actual post data is
 * resolved from the author's wall.
 *
 * DHT Key: SHA3-512("dna:boost:YYYY-MM-DD"), TTL 7 days
 * ============================================================================ */

/**
 * Create a wall post AND boost it (publish pointer to daily boost key).
 * Returns the created post via the callback (same as dna_engine_wall_post).
 */
DNA_API dna_request_id_t dna_engine_wall_boost_post(
    dna_engine_t *engine,
    const char *text,
    dna_wall_post_cb callback,
    void *user_data
);

/**
 * Create a wall post with image AND boost it.
 */
DNA_API dna_request_id_t dna_engine_wall_boost_post_with_image(
    dna_engine_t *engine,
    const char *text,
    const char *image_json,
    dna_wall_post_cb callback,
    void *user_data
);

/**
 * Fetch all boosted posts from the last 7 days.
 * Resolves post data from each author's wall (cache-first).
 * Returns via wall_posts callback (same as dna_engine_wall_timeline).
 */
DNA_API dna_request_id_t dna_engine_wall_boost_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Load a single day's wall bucket from DHT (v0.9.141+).
 * Used for lazy-loading older days on scroll.
 *
 * @param fingerprint  Wall owner's fingerprint
 * @param date_str     Day string "YYYY-MM-DD"
 */
DNA_API dna_request_id_t dna_engine_wall_load_day(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *date_str,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Fetch image JSON for a wall post from local cache (v0.9.142+).
 * Returns the image data via callback (no DHT access).
 *
 * @param post_uuid  UUID of the post
 */
DNA_API dna_request_id_t dna_engine_wall_get_image(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_image_cb callback,
    void *user_data
);

/* ============================================================================
 * CHANNELS (RSS-like public channels via DHT)
 * ============================================================================ */

/* Channel CRUD */
DNA_API dna_request_id_t dna_engine_channel_create(dna_engine_t *engine,
    const char *name, const char *description, bool is_public,
    dna_channel_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_get(dna_engine_t *engine,
    const char *uuid, dna_channel_cb callback, void *user_data);

/**
 * Batch fetch channel metadata for multiple UUIDs.
 * Cache-first: fresh cached channels returned immediately, only stale/miss
 * channels are fetched via single DHT batch request.
 * @param uuids Array of UUID strings (copied internally)
 * @param count Number of UUIDs
 * @return Request ID, or -1 on error
 */
DNA_API dna_request_id_t dna_engine_channel_get_batch(dna_engine_t *engine,
    const char **uuids, int count, dna_channels_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_delete(dna_engine_t *engine,
    const char *uuid, dna_completion_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_discover(dna_engine_t *engine,
    int days_back, dna_channels_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_search(dna_engine_t *engine,
    const char *query, int offset, int limit,
    dna_channels_cb callback, void *user_data);

/* Channel posts */
DNA_API dna_request_id_t dna_engine_channel_post(dna_engine_t *engine,
    const char *channel_uuid, const char *body,
    dna_channel_post_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_get_posts(dna_engine_t *engine,
    const char *channel_uuid, int days_back,
    dna_channel_posts_cb callback, void *user_data);

/* Channel subscriptions (synchronous) */
DNA_API int  dna_engine_channel_subscribe(dna_engine_t *engine, const char *channel_uuid);
DNA_API int  dna_engine_channel_unsubscribe(dna_engine_t *engine, const char *channel_uuid);
DNA_API bool dna_engine_channel_is_subscribed(dna_engine_t *engine, const char *channel_uuid);
DNA_API int  dna_engine_channel_mark_read(dna_engine_t *engine, const char *channel_uuid);

/* Channel subscriptions (async) */
DNA_API dna_request_id_t dna_engine_channel_get_subscriptions(dna_engine_t *engine,
    dna_channel_subscriptions_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_sync_subs_to_dht(dna_engine_t *engine,
    dna_completion_cb callback, void *user_data);

DNA_API dna_request_id_t dna_engine_channel_sync_subs_from_dht(dna_engine_t *engine,
    dna_completion_cb callback, void *user_data);

/* ============================================================================
 * FOLLOWING (one-directional follow, v0.9.126+)
 * ============================================================================ */

/**
 * Follow a user (one-directional, no approval needed)
 *
 * @param engine     Engine instance
 * @param fingerprint 128-char hex fingerprint of user to follow
 * @param callback   Completion callback
 * @param user_data  User data for callback
 */
DNA_API dna_request_id_t dna_engine_follow(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Unfollow a user
 *
 * @param engine     Engine instance
 * @param fingerprint 128-char hex fingerprint of user to unfollow
 * @param callback   Completion callback
 * @param user_data  User data for callback
 */
DNA_API dna_request_id_t dna_engine_unfollow(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get list of followed users
 * Caller takes ownership of the result — free with dna_free_following()
 *
 * @param engine     Engine instance
 * @param callback   Following list callback
 * @param user_data  User data for callback
 */
DNA_API dna_request_id_t dna_engine_get_following(
    dna_engine_t *engine,
    dna_following_cb callback,
    void *user_data
);

/**
 * Free following list returned by dna_engine_get_following
 */
DNA_API void dna_free_following(dna_following_t *following, int count);

/**
 * Check if following a user (synchronous, local DB check)
 *
 * @param engine      Engine instance
 * @param fingerprint 128-char hex fingerprint to check
 * @return            true if following, false otherwise
 */
DNA_API bool dna_engine_is_following(dna_engine_t *engine, const char *fingerprint);

/**
 * Sync follow list to DHT (encrypted, private)
 */
DNA_API dna_request_id_t dna_engine_sync_following_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Sync follow list from DHT (restore from backup)
 */
DNA_API dna_request_id_t dna_engine_sync_following_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * MEDIA OPERATIONS (v0.9.146+)
 * ============================================================================ */

/**
 * Upload media to DHT. Data is chunked and uploaded automatically.
 * content_hash must be pre-computed SHA3-512 of the data.
 * The engine takes ownership of data (will be freed after upload).
 *
 * @param engine        Engine instance
 * @param data          Media data (engine copies internally)
 * @param data_len      Data length in bytes
 * @param content_hash  SHA3-512 hash of the data (64 bytes)
 * @param media_type    0=image, 1=video, 2=audio
 * @param encrypted     Whether data is pre-encrypted
 * @param ttl           TTL in seconds (0 = permanent)
 * @param callback      Called on completion
 * @param user_data     User data for callback
 * @return              Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_media_upload(
    dna_engine_t *engine,
    const uint8_t *data, size_t data_len,
    const uint8_t content_hash[64],
    uint8_t media_type, bool encrypted, uint32_t ttl,
    uint32_t start_chunk,
    dna_media_upload_cb callback, void *user_data);

/**
 * Download media from DHT. Fetches all chunks and reassembles.
 * Callback receives the complete data (caller must copy if needed).
 *
 * @param engine        Engine instance
 * @param content_hash  SHA3-512 hash identifying the media (64 bytes)
 * @param callback      Called with downloaded data
 * @param user_data     User data for callback
 * @return              Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_media_download(
    dna_engine_t *engine,
    const uint8_t content_hash[64],
    dna_media_download_cb callback, void *user_data);

/**
 * Check if media exists (complete) on DHT.
 *
 * @param engine        Engine instance
 * @param content_hash  SHA3-512 hash identifying the media (64 bytes)
 * @param callback      Called with exists result
 * @param user_data     User data for callback
 * @return              Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_media_exists(
    dna_engine_t *engine,
    const uint8_t content_hash[64],
    dna_media_exists_cb callback, void *user_data);

/* ============================================================================
 * SIGNING (for QR Auth and external authentication)
 * ============================================================================ */

/**
 * Sign arbitrary data with the loaded identity's Dilithium5 key
 *
 * Creates a detached signature over the provided data using the current
 * identity's private signing key. Used for QR-based authentication flows
 * where the app needs to prove identity to external services.
 *
 * @param engine         Engine instance (must have identity loaded)
 * @param data           Data to sign
 * @param data_len       Length of data in bytes
 * @param signature_out  Output buffer for signature (must be at least 4627 bytes)
 * @param sig_len_out    Output: actual signature length
 * @return               0 on success, negative on error:
 *                       DNA_ENGINE_ERROR_NO_IDENTITY - no identity loaded
 *                       DNA_ERROR_INVALID_ARG - null parameters
 *                       DNA_ERROR_CRYPTO - signing failed
 */
DNA_API int dna_engine_sign_data(
    dna_engine_t *engine,
    const uint8_t *data,
    size_t data_len,
    uint8_t *signature_out,
    size_t *sig_len_out
);

/**
 * Get the loaded identity's Dilithium5 signing public key
 *
 * Copies the raw public key bytes into the provided buffer.
 * Dilithium5 public key size is 2592 bytes.
 *
 * @param engine         Engine instance
 * @param pubkey_out     Output buffer for public key (must be at least 2592 bytes)
 * @param pubkey_out_len Size of output buffer
 * @return               Number of bytes written (2592) on success, negative on error:
 *                       DNA_ENGINE_ERROR_NO_IDENTITY - no identity loaded
 *                       DNA_ERROR_INVALID_ARG - null parameters or buffer too small
 */
DNA_API int dna_engine_get_signing_public_key(
    dna_engine_t *engine,
    uint8_t *pubkey_out,
    size_t pubkey_out_len
);

/* ============================================================================
 * DEBUG LOG INBOX (v0.9.164+)
 * ============================================================================ */

/**
 * Send an encrypted debug log blob to a receiver's DHT inbox.
 *
 * The log body is encrypted with Kyber1024 + AES-256-GCM using the receiver's
 * Kyber public key (fetched from DHT/profile cache), then PUT to the receiver's
 * debug inbox DHT key (SHA3-512("dna-debug-inbox" || receiver_fp_raw_64)).
 *
 * Max log size: 3 MB. Hint is an optional short user-visible label (max 128 B).
 *
 * @param engine            Engine instance (must have identity loaded)
 * @param receiver_fp_hex   128-char hex Dilithium5 fingerprint of the receiver
 * @param log_body          Raw log bytes (plaintext)
 * @param log_len           Length of log body (1 .. DNA_DEBUG_LOG_MAX_BODY_LEN)
 * @param hint              Optional short label (NUL-terminated, may be NULL)
 * @param callback          Completion callback (error == 0 on success)
 * @param user_data         User data for callback
 * @return                  Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_debug_log_send(
    dna_engine_t *engine,
    const char *receiver_fp_hex,
    const uint8_t *log_body,
    size_t log_len,
    const char *hint,
    dna_completion_cb callback,
    void *user_data
);

/* ============================================================================
 * DNAC - DIGITAL CASH (v0.9.173+)
 * ============================================================================ */

/**
 * DNAC balance information
 * Amounts are in raw units (1 token = 100,000,000 raw)
 */
typedef struct {
    uint64_t confirmed;         /**< Confirmed spendable balance */
    uint64_t pending;           /**< Pending incoming */
    uint64_t locked;            /**< Locked in pending spends */
    int utxo_count;             /**< Number of UTXOs */
} dna_dnac_balance_t;

/**
 * DNAC transaction history entry
 */
typedef struct {
    uint8_t tx_hash[64];        /**< Transaction hash (SHA3-512) */
    int type;                   /**< 0=genesis, 1=spend, 2=burn */
    char counterparty[129];     /**< Other party fingerprint (if known) */
    int64_t amount_delta;       /**< Change in balance (+/-) in raw units */
    uint64_t fee;               /**< Fee paid (if sender) */
    uint64_t timestamp;         /**< Unix timestamp */
    char memo[256];             /**< Memo (if any) */
    uint8_t token_id[64];       /**< Token ID (zeros = native DNAC) */
} dna_dnac_history_t;

/**
 * DNAC UTXO entry
 */
typedef struct {
    uint8_t tx_hash[64];        /**< Transaction that created this UTXO */
    uint32_t output_index;      /**< Index within transaction */
    uint64_t amount;            /**< Amount in raw units */
    int status;                 /**< 0=unspent, 1=pending, 2=spent */
    uint64_t received_at;       /**< Unix timestamp when received */
} dna_dnac_utxo_t;

/**
 * DNAC balance callback
 */
typedef void (*dna_dnac_balance_cb)(
    dna_request_id_t request_id,
    int error,
    const dna_dnac_balance_t *balance,
    void *user_data
);

/**
 * DNAC transaction history callback
 */
typedef void (*dna_dnac_history_cb)(
    dna_request_id_t request_id,
    int error,
    const dna_dnac_history_t *history,
    int count,
    void *user_data
);

/**
 * DNAC UTXO list callback
 */
typedef void (*dna_dnac_utxos_cb)(
    dna_request_id_t request_id,
    int error,
    const dna_dnac_utxo_t *utxos,
    int count,
    void *user_data
);

/**
 * DNAC fee estimate callback
 */
typedef void (*dna_dnac_fee_cb)(
    dna_request_id_t request_id,
    int error,
    uint64_t fee,
    void *user_data
);

/**
 * Get DNAC wallet balance
 * Lazy-initializes DNAC context on first call.
 */
DNA_API dna_request_id_t dna_engine_dnac_get_balance(
    dna_engine_t *engine,
    dna_dnac_balance_cb callback,
    void *user_data
);

/**
 * Send DNAC payment (native or custom token)
 *
 * @param recipient_fingerprint  128-char hex fingerprint
 * @param amount                 Amount in raw units (1 token = 100,000,000 raw)
 * @param memo                   Optional memo (NULL for none)
 * @param token_id               Token ID (64 bytes) for custom token send,
 *                               or NULL for native DNAC. Fee (0.1%) is
 *                               calculated in the same token.
 */
DNA_API dna_request_id_t dna_engine_dnac_send(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    uint64_t amount,
    const char *memo,
    const uint8_t *token_id,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Phase 13 / Task 13.5 — fetch the witness receipt of the most recent
 * dnac_send. Synchronous: callable from any thread after the send
 * completion callback has fired. Returns 0 on success, non-zero if no
 * send has completed yet on this engine.
 *
 * tx_hash_out must point at a 64-byte buffer (DNAC tx hash size).
 */
DNA_API int dna_engine_dnac_last_send_receipt(
    dna_engine_t *engine,
    uint64_t *block_height_out,
    uint32_t *tx_index_out,
    uint8_t *tx_hash_out
);

/**
 * Sync DNAC wallet from witnesses
 */
DNA_API dna_request_id_t dna_engine_dnac_sync(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);

/**
 * Get DNAC transaction history from witnesses (authoritative, blocking).
 * Also persists each entry into the local DB cache as a side effect so
 * that subsequent dna_engine_dnac_get_history_local calls see incoming
 * TXs that were previously only visible on the network.
 */
DNA_API dna_request_id_t dna_engine_dnac_get_history(
    dna_engine_t *engine,
    dna_dnac_history_cb callback,
    void *user_data
);

/**
 * Get DNAC transaction history from the local DB cache only.
 *
 * Fast and non-blocking — returns whatever the local DB currently has.
 * Intended for stale-while-revalidate UI patterns: call this first to
 * paint the history screen immediately, then fire
 * dna_engine_dnac_get_history in the background to refresh from
 * witnesses (which will also persist any newly seen incoming TXs into
 * the local cache).
 */
DNA_API dna_request_id_t dna_engine_dnac_get_history_local(
    dna_engine_t *engine,
    dna_dnac_history_cb callback,
    void *user_data
);

/**
 * Get DNAC UTXO list
 */
DNA_API dna_request_id_t dna_engine_dnac_get_utxos(
    dna_engine_t *engine,
    dna_dnac_utxos_cb callback,
    void *user_data
);

/**
 * Estimate fee for DNAC transaction
 *
 * @param amount  Amount to send (raw units)
 */
DNA_API dna_request_id_t dna_engine_dnac_estimate_fee(
    dna_engine_t *engine,
    uint64_t amount,
    dna_dnac_fee_cb callback,
    void *user_data
);

/**
 * Free DNAC history array returned by callback
 */
DNA_API void dna_engine_dnac_free_history(dna_dnac_history_t *history, int count);

/**
 * Free DNAC UTXO array returned by callback
 */
DNA_API void dna_engine_dnac_free_utxos(dna_dnac_utxo_t *utxos, int count);

/* DNAC Multi-Token (v0.9.188+) */
typedef struct {
    uint8_t  token_id[64];
    char     name[33];
    char     symbol[9];
    uint8_t  decimals;
    int64_t  supply;
    char     creator_fp[129];
} dna_dnac_token_t;

typedef void (*dna_dnac_token_list_cb)(dna_request_id_t request_id, int error,
    const dna_dnac_token_t *tokens, int count, void *user_data);

DNA_API dna_request_id_t dna_engine_dnac_token_list(dna_engine_t *engine,
    dna_dnac_token_list_cb callback, void *user_data);
DNA_API dna_request_id_t dna_engine_dnac_token_create(dna_engine_t *engine,
    const char *name, const char *symbol, uint8_t decimals, uint64_t supply,
    dna_completion_cb callback, void *user_data);
DNA_API dna_request_id_t dna_engine_dnac_token_balance(dna_engine_t *engine,
    const uint8_t *token_id, dna_dnac_balance_cb callback, void *user_data);
DNA_API void dna_engine_dnac_free_tokens(dna_dnac_token_t *tokens, int count);

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_H */
