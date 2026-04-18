/*
 * DNA Engine - Internal Header
 *
 * Private implementation details for dna_engine.
 * NOT part of public API - do not include in external code.
 */

#ifndef DNA_ENGINE_INTERNAL_H
#define DNA_ENGINE_INTERNAL_H

#include "dna/dna_engine.h"
#include "messenger.h"
#include "cellframe_wallet.h"
#include "cellframe_rpc.h"
#include "blockchain/blockchain_wallet.h"
#include "database/contacts_db.h"
#include "database/group_invitations.h"
#include "dht/shared/dht_groups.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/shared/dht_dm_outbox.h"  /* Daily bucket DM outbox (v0.4.81+) */
#include "dht/shared/dht_contact_request.h"
#include "dht/client/dna_group_outbox.h"
/* dht_context.h removed — using nodus_init.h directly */
#include "crypto/utils/qgp_types.h" /* For qgp_key_t */

#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

#define DNA_TASK_QUEUE_SIZE 256
#define DNA_WORKER_THREAD_MIN 4      /* Minimum workers (low-end devices) */
#define DNA_WORKER_THREAD_MAX 24     /* Maximum workers (diminishing returns beyond) */
/* NOTE: DNA_PARALLEL_MIN/MAX removed - using threadpool_optimal_size() now */
#define DNA_REQUEST_ID_INVALID 0
#define DNA_MESSAGE_QUEUE_DEFAULT_CAPACITY 20
#define DNA_MESSAGE_QUEUE_MAX_CAPACITY 100

/* ============================================================================
 * ENGINE STATE (v0.6.50+: Pause/Resume lifecycle)
 * ============================================================================ */

/**
 * Engine lifecycle state for Android pause/resume optimization.
 * Allows keeping engine alive in background to avoid expensive reinitialization.
 */
typedef enum {
    DNA_ENGINE_STATE_UNLOADED,  /* No identity loaded */
    DNA_ENGINE_STATE_ACTIVE     /* Full mode, all listeners active */
} dna_engine_state_t;

/* ============================================================================
 * TASK TYPES
 * ============================================================================ */

typedef enum {
    /* Identity (v0.3.0: TASK_LIST_IDENTITIES removed - single-user model) */
    TASK_CREATE_IDENTITY,
    TASK_LOAD_IDENTITY,
    TASK_REGISTER_NAME,
    TASK_GET_DISPLAY_NAME,
    TASK_GET_AVATAR,
    TASK_LOOKUP_NAME,
    TASK_GET_PROFILE,
    TASK_LOOKUP_PROFILE,
    TASK_REFRESH_CONTACT_PROFILE,
    TASK_UPDATE_PROFILE,

    /* Contacts */
    TASK_GET_CONTACTS,
    TASK_ADD_CONTACT,
    TASK_REMOVE_CONTACT,

    /* Contact Requests (ICQ-style) */
    TASK_SEND_CONTACT_REQUEST,
    TASK_GET_CONTACT_REQUESTS,
    TASK_APPROVE_CONTACT_REQUEST,
    TASK_DENY_CONTACT_REQUEST,
    TASK_BLOCK_USER,
    TASK_UNBLOCK_USER,
    TASK_GET_BLOCKED_USERS,

    /* Messaging */
    TASK_SEND_MESSAGE,
    TASK_GET_CONVERSATION,
    TASK_GET_CONVERSATION_PAGE,
    TASK_CHECK_OFFLINE_MESSAGES,
    TASK_CHECK_OFFLINE_MESSAGES_FROM,

    /* Message deletion (v17) */
    TASK_DELETE_MESSAGE,
    TASK_DELETE_CONVERSATION,
    TASK_DELETE_ALL_MESSAGES,

    /* Groups */
    TASK_GET_GROUPS,
    TASK_GET_GROUP_INFO,
    TASK_GET_GROUP_MEMBERS,
    TASK_CREATE_GROUP,
    TASK_SEND_GROUP_MESSAGE,
    TASK_GET_GROUP_CONVERSATION,
    TASK_ADD_GROUP_MEMBER,
    TASK_REMOVE_GROUP_MEMBER,
    TASK_GET_INVITATIONS,
    TASK_ACCEPT_INVITATION,
    TASK_REJECT_INVITATION,

    /* Wallet */
    TASK_LIST_WALLETS,
    TASK_GET_BALANCES,
    TASK_GET_CACHED_BALANCES,
    TASK_SEND_TOKENS,
    TASK_GET_TRANSACTIONS,
    TASK_GET_CACHED_TRANSACTIONS,
    TASK_GET_TX_STATUS,
    TASK_ESTIMATE_GAS,
    TASK_DEX_QUOTE,
    TASK_DEX_LIST_PAIRS,
    TASK_DEX_SWAP,

    /* P2P & Presence */
    TASK_REFRESH_PRESENCE,
    TASK_LOOKUP_PRESENCE,
    TASK_SYNC_CONTACTS_TO_DHT,
    TASK_SYNC_CONTACTS_FROM_DHT,
    TASK_SYNC_GROUPS,
    TASK_SYNC_GROUPS_TO_DHT,
    TASK_RESTORE_GROUPS_FROM_DHT,
    TASK_SYNC_GROUP_BY_UUID,
    TASK_GET_REGISTERED_NAME,

    /* Wall (personal wall posts, v0.6.135+) */
    TASK_WALL_POST,
    TASK_WALL_DELETE,
    TASK_WALL_LOAD,
    TASK_WALL_TIMELINE,
    TASK_WALL_TIMELINE_CACHED,

    /* Wall Comments (v0.7.0+) */
    TASK_WALL_ADD_COMMENT,
    TASK_WALL_GET_COMMENTS,

    /* Wall Likes (v0.9.52+) */
    TASK_WALL_LIKE,
    TASK_WALL_GET_LIKES,

    /* Wall Engagement Batch (v0.9.123+) */
    TASK_WALL_GET_ENGAGEMENT,

    /* Wall Boost (v0.9.71+) */
    TASK_WALL_BOOST_POST,
    TASK_WALL_BOOST_TIMELINE,

    /* Wall Daily Bucket (v0.9.141+) */
    TASK_WALL_LOAD_DAY,

    /* Wall Image Fetch (v0.9.142+) */
    TASK_WALL_GET_IMAGE,

    /* Channel system (RSS-like channels) */
    TASK_CHANNEL_CREATE,
    TASK_CHANNEL_GET,
    TASK_CHANNEL_DELETE,
    TASK_CHANNEL_DISCOVER,
    TASK_CHANNEL_SEARCH,
    TASK_CHANNEL_POST,
    TASK_CHANNEL_GET_POSTS,
    TASK_CHANNEL_GET_SUBSCRIPTIONS,
    TASK_CHANNEL_SYNC_SUBS_TO_DHT,
    TASK_CHANNEL_SYNC_SUBS_FROM_DHT,
    TASK_CHANNEL_GET_BATCH,

    /* Follow system (v0.9.126+) */
    TASK_FOLLOW,
    TASK_UNFOLLOW,
    TASK_GET_FOLLOWING,
    TASK_SYNC_FOLLOWING_TO_DHT,
    TASK_SYNC_FOLLOWING_FROM_DHT,

    /* Media operations (v0.9.146+) */
    TASK_MEDIA_UPLOAD,
    TASK_MEDIA_DOWNLOAD,
    TASK_MEDIA_EXISTS,

    /* Debug log inbox (v0.9.164+) */
    TASK_DEBUG_LOG_SEND,

    /* DNAC digital cash (v0.9.173+) */
    TASK_DNAC_GET_BALANCE,
    TASK_DNAC_SEND,
    TASK_DNAC_SYNC,
    TASK_DNAC_GET_HISTORY,
    TASK_DNAC_GET_HISTORY_LOCAL,
    TASK_DNAC_GET_UTXOS,
    TASK_DNAC_ESTIMATE_FEE,
    TASK_DNAC_TOKEN_LIST,
    TASK_DNAC_TOKEN_CREATE,
    TASK_DNAC_TOKEN_BALANCE,

    /* DNAC stake & delegation (v1.0.0-rc221+) — Phase 16 Task 71 */
    TASK_DNAC_STAKE,
    TASK_DNAC_UNSTAKE,
    TASK_DNAC_DELEGATE,
    TASK_DNAC_UNDELEGATE,
    TASK_DNAC_CLAIM_REWARD,
    TASK_DNAC_VALIDATOR_UPDATE,
    TASK_DNAC_GET_PENDING_REWARDS,
    TASK_DNAC_VALIDATOR_LIST,
    TASK_DNAC_GET_COMMITTEE,

    TASK_SEND_REACTION,
    TASK_GET_REACTIONS
} dna_task_type_t;

/* ============================================================================
 * TASK STRUCTURES
 * ============================================================================ */

/**
 * Task parameters union
 */
typedef union {
    /* Create identity */
    struct {
        char name[256];        /* Required: identity name for directory structure */
        uint8_t signing_seed[32];
        uint8_t encryption_seed[32];
        uint8_t *master_seed;  /* Optional: 64-byte BIP39 master seed for multi-chain wallets (ETH, SOL) */
        char *mnemonic;        /* Optional: space-separated BIP39 mnemonic (for Cellframe wallet) */
        char *password;        /* Optional: password to encrypt keys (NULL for no encryption) */
    } create_identity;

    /* Load identity */
    struct {
        char fingerprint[129];
        char *password;          /* Password for encrypted keys (NULL if unencrypted) */
        bool minimal;            /* true = DHT+listeners only, skip transport/presence/wallet */
    } load_identity;

    /* Register name */
    struct {
        char name[256];
    } register_name;

    /* Get display name */
    struct {
        char fingerprint[129];
    } get_display_name;

    /* Get avatar */
    struct {
        char fingerprint[129];
    } get_avatar;

    /* Lookup name */
    struct {
        char name[256];
    } lookup_name;

    /* Lookup profile */
    struct {
        char fingerprint[129];
    } lookup_profile;

    /* Add contact */
    struct {
        char identifier[256];
    } add_contact;

    /* Remove contact */
    struct {
        char fingerprint[129];
    } remove_contact;

    /* Send contact request */
    struct {
        char recipient[129];
        char message[256];
    } send_contact_request;

    /* Approve/deny contact request */
    struct {
        char fingerprint[129];
    } contact_request;

    /* Block user */
    struct {
        char fingerprint[129];
        char reason[256];
    } block_user;

    /* Unblock user */
    struct {
        char fingerprint[129];
    } unblock_user;

    /* Send message */
    struct {
        char recipient[129];
        char *message;  /* Heap allocated, task owns */
        time_t queued_at;  /* Timestamp when user sent (for ordering) */
    } send_message;

    /* Send reaction */
    struct {
        char recipient[129];
        char target_content_hash[65];
        char emoji[8];
        char op[8];
    } send_reaction;

    /* Get reactions for a target message */
    struct {
        char target_content_hash[65];
    } get_reactions;

    /* Get conversation */
    struct {
        char contact[129];
    } get_conversation;

    /* Get conversation page (paginated) */
    struct {
        char contact[129];
        int limit;
        int offset;
    } get_conversation_page;

    /* Check offline messages */
    struct {
        bool publish_watermarks;  /* false for background caching */
    } check_offline_messages;

    /* Check offline messages from specific contact (async) */
    struct {
        char contact_fingerprint[129];
    } check_offline_messages_from;

    /* Delete message */
    struct {
        int message_id;
        bool send_notices;
    } delete_message;

    /* Delete conversation */
    struct {
        char contact[129];
        bool send_notices;
    } delete_conversation;

    /* Delete all messages */
    struct {
        bool send_notices;
    } delete_all_messages;

    /* Create group */
    struct {
        char name[256];
        char **members;  /* Heap allocated array, task owns */
        int member_count;
    } create_group;

    /* Get group info */
    struct {
        char group_uuid[37];
    } get_group_info;

    /* Get group members */
    struct {
        char group_uuid[37];
    } get_group_members;

    /* Send group message */
    struct {
        char group_uuid[37];
        char *message;  /* Heap allocated, task owns */
    } send_group_message;

    /* Get group conversation */
    struct {
        char group_uuid[37];
    } get_group_conversation;

    /* Add group member */
    struct {
        char group_uuid[37];
        char fingerprint[129];
    } add_group_member;

    /* Accept/reject invitation */
    struct {
        char group_uuid[37];
    } invitation;

    /* Get balances */
    struct {
        int wallet_index;
    } get_balances;

    /* Send tokens */
    struct {
        int wallet_index;
        char recipient[120];
        char amount[64];
        char token[32];
        char network[64];
        int gas_speed;  /* 0=slow (0.8x), 1=normal (1x), 2=fast (1.5x) */
    } send_tokens;

    /* Get transactions */
    struct {
        int wallet_index;
        char network[64];
    } get_transactions;

    /* Get TX status */
    struct {
        char tx_hash[256];
        char chain[32];
    } get_tx_status;

    /* Update profile */
    struct {
        dna_profile_t profile;
    } update_profile;

    /* Lookup presence */
    struct {
        char fingerprint[129];
    } lookup_presence;

    /* Sync group by UUID */
    struct {
        char group_uuid[37];
    } sync_group_by_uuid;

    /* Wall: Post message (with optional image v0.7.0+) */
    struct {
        char *text;                     /* Heap allocated, task owns (max 2048 chars) */
        char *image_json;              /* Heap allocated, task owns; NULL = text-only */
    } wall_post;

    /* Wall: Delete post */
    struct {
        char uuid[37];                  /* Post UUID to delete */
    } wall_delete;

    /* Wall: Load one user's wall */
    struct {
        char fingerprint[129];          /* Wall owner's fingerprint */
    } wall_load;

    /* Wall: Timeline has no extra params (uses engine->contacts list) */

    /* Wall: Timeline cached (cache-only, no identity required) */
    struct {
        char fingerprint[129];          /* Owner fingerprint for contacts_db lookup */
    } wall_timeline_cached;

    /* Wall: Add comment (v0.7.0+) */
    struct {
        char post_uuid[37];             /* Post UUID to comment on */
        char parent_comment_uuid[37];   /* Parent comment for replies (empty = top-level) */
        char *body;                     /* Heap allocated, task owns */
        uint32_t comment_type;          /* 0=text, 1=tip */
    } wall_add_comment;

    /* Wall: Get comments (v0.7.0+) */
    struct {
        char post_uuid[37];             /* Post UUID */
    } wall_get_comments;

    /* Wall: Like a post (v0.9.52+) */
    struct {
        char post_uuid[37];             /* Post UUID to like */
    } wall_like;

    /* Wall: Get likes (v0.9.52+) */
    struct {
        char post_uuid[37];             /* Post UUID */
    } wall_get_likes;

    /* Wall: Engagement batch (v0.9.123+) */
    struct {
        char **post_uuids;              /* Heap array of UUID strings (task owns) */
        int post_count;
        bool cache_only;                /* v0.10.7+: skip DHT phase, return cached counts only */
    } wall_get_engagement;

    /* Wall: Boost post (v0.9.71+) */
    struct {
        char *text;                     /* Heap allocated, task owns */
        char *image_json;              /* Heap allocated, task owns; NULL = text-only */
    } wall_boost_post;

    /* Wall: Boost timeline has no extra params */

    /* Wall: Load day bucket (v0.9.141+) */
    struct {
        char fingerprint[129];
        char date_str[11];              /* "YYYY-MM-DD" */
    } wall_load_day;

    /* Wall: Get image (v0.9.142+) */
    struct {
        char post_uuid[37];
    } wall_get_image;

    /* Channel: create */
    struct {
        char name[101];
        char *description;       /* Heap allocated, task owns */
        bool is_public;
    } channel_create;

    /* Channel: get / delete */
    struct {
        char uuid[37];
    } channel_by_uuid;

    /* Channel: get_batch (v0.9.127+) */
    struct {
        char **uuids;       /* Heap-allocated array of UUID strings (freed after handler) */
        int count;
    } channel_get_batch;

    /* Channel: get_posts */
    struct {
        char uuid[37];
        int days_back;
    } channel_get_posts;

    /* Channel: discover */
    struct {
        int days_back;
    } channel_discover;

    /* Channel: search */
    struct {
        char *query;     /* Heap allocated, task owns */
        int offset;
        int limit;
    } channel_search;

    /* Channel: post */
    struct {
        char channel_uuid[37];
        char *body;              /* Heap allocated, task owns */
    } channel_post;

    /* DEX: quote */
    struct {
        char from_token[16];
        char to_token[16];
        char amount_in[64];
        char dex_filter[32];    /* "" = all DEXes, e.g. "uniswap-v3" */
    } dex_quote;

    /* DEX: swap */
    struct {
        int wallet_index;
        char from_token[16];
        char to_token[16];
        char amount_in[64];
    } dex_swap;

    /* Follow/Unfollow */
    struct {
        char fingerprint[129];          /* User to follow/unfollow */
    } follow;

    /* Media: Upload (v0.9.146+) */
    struct {
        uint8_t  *data;             /* Heap allocated, task owns */
        size_t    data_len;
        uint8_t   content_hash[64]; /* SHA3-512 computed by caller */
        uint8_t   media_type;       /* 0=image, 1=video, 2=audio */
        bool      encrypted;
        uint32_t  ttl;
        uint32_t  start_chunk;      /* Resume: skip chunks before this (0=all) */
    } media_upload;

    /* Media: Download (v0.9.146+) */
    struct {
        uint8_t   content_hash[64];
    } media_download;

    /* Media: Exists check (v0.9.146+) */
    struct {
        uint8_t   content_hash[64];
    } media_exists;

    /* Debug log: Send encrypted log to receiver inbox (v0.9.164+) */
    struct {
        char      receiver_fp_hex[129];     /* 128 hex chars + NUL */
        uint8_t  *log_body;                 /* Heap, task owns */
        size_t    log_len;
        char      hint[129];                /* Optional short label */
    } debug_log_send;

    /* DNAC: Send payment (v0.9.173+) */
    struct {
        char recipient_fingerprint[129];    /* 128 hex chars + NUL */
        uint64_t amount;                    /* Amount in raw units */
        char memo[256];                     /* Optional memo */
        uint8_t token_id[64];               /* Token ID (zeros = native DNAC) */
        bool has_token_id;                  /* True if custom token send */
    } dnac_send;

    /* DNAC: Estimate fee (v0.9.173+) */
    struct {
        uint64_t amount;                    /* Amount in raw units */
    } dnac_estimate_fee;

    struct {
        char name[33];
        char symbol[9];
        uint8_t decimals;
        uint64_t supply;
    } dnac_token_create;

    struct {
        uint8_t token_id[64];
    } dnac_token_balance;

    /* DNAC stake & delegation (v1.0.0-rc221+) — Phase 16 */
    struct {
        uint16_t commission_bps;
        char     unstake_destination_fp[129];  /* 128 hex + NUL */
    } dnac_stake;

    struct {
        uint8_t  validator_pubkey[2592];       /* Dilithium5 pubkey */
        uint64_t amount;                       /* raw units */
    } dnac_delegate;

    struct {
        uint8_t  validator_pubkey[2592];
        uint64_t amount;                       /* raw units */
    } dnac_undelegate;

    struct {
        uint8_t  target_validator_pubkey[2592];
        uint64_t max_pending_amount;
        uint64_t valid_before_block;
    } dnac_claim_reward;

    struct {
        uint16_t new_commission_bps;
        uint64_t signed_at_block;
    } dnac_validator_update;

    struct {
        uint8_t  claimant_pubkey[2592];
        bool     has_claimant_pubkey;          /* false == use caller's own */
    } dnac_pending_rewards;

    struct {
        int filter_status;                     /* -1 for all */
    } dnac_validator_list;

} dna_task_params_t;

/**
 * Task callback union
 */
typedef union {
    dna_completion_cb completion;
    dna_send_tokens_cb send_tokens;
    dna_identity_created_cb identity_created;
    dna_display_name_cb display_name;
    dna_contacts_cb contacts;
    dna_contact_requests_cb contact_requests;
    dna_blocked_users_cb blocked_users;
    dna_messages_cb messages;
    dna_messages_page_cb messages_page;
    dna_reactions_cb reactions;
    dna_groups_cb groups;
    dna_group_info_cb group_info;
    dna_group_members_cb group_members;
    dna_group_created_cb group_created;
    dna_invitations_cb invitations;
    dna_wallets_cb wallets;
    dna_balances_cb balances;
    dna_transactions_cb transactions;
    dna_profile_cb profile;
    dna_presence_cb presence;
    dna_gas_estimates_cb gas_estimates;
    dna_wall_post_cb wall_post;
    dna_wall_posts_cb wall_posts;
    dna_wall_comment_cb wall_comment;
    dna_wall_comments_cb wall_comments;
    dna_wall_likes_cb wall_likes;
    dna_wall_engagement_cb wall_engagement;
    dna_wall_image_cb wall_image;
    dna_channel_cb channel;
    dna_channels_cb channels;
    dna_channel_post_cb channel_post_cb;
    dna_channel_posts_cb channel_posts;
    dna_channel_subscriptions_cb channel_subscriptions;
    dna_dex_quote_cb dex_quote;
    dna_dex_pairs_cb dex_pairs;
    dna_dex_swap_cb dex_swap;
    dna_tx_status_cb tx_status;
    dna_following_cb following;
    dna_media_upload_cb media_upload;
    dna_media_download_cb media_download;
    dna_media_exists_cb media_exists;
    dna_dnac_balance_cb dnac_balance;
    dna_dnac_history_cb dnac_history;
    dna_dnac_utxos_cb dnac_utxos;
    dna_dnac_fee_cb dnac_fee;
    dna_dnac_token_list_cb dnac_token_list;
    dna_dnac_validator_list_cb dnac_validator_list;
} dna_task_callback_t;

/**
 * Async task
 */
typedef struct {
    dna_request_id_t request_id;
    dna_task_type_t type;
    dna_task_params_t params;
    dna_task_callback_t callback;
    void *user_data;
    bool cancelled;
} dna_task_t;

/* ============================================================================
 * TASK QUEUE (Lock-free MPSC)
 * ============================================================================ */

typedef struct {
    dna_task_t tasks[DNA_TASK_QUEUE_SIZE];
    atomic_size_t head;  /* Producer writes here */
    atomic_size_t tail;  /* Consumer reads from here */
#ifndef NDEBUG
    /* THR-03 — Task Queue Concurrency Contract (CONCURRENCY.md L1 cluster).
     *
     * The MPSC-via-task_mutex contract requires every call to
     * dna_task_queue_push to happen while engine->task_mutex is held.
     * dna_submit_task sets this field to pthread_self() immediately after
     * locking task_mutex; dna_task_queue_push asserts via pthread_equal
     * that the current thread matches. A future caller that bypasses
     * dna_submit_task and pushes directly will either trip the assert
     * (owner is a different thread) or trip it on first push (owner is
     * zero-initialized). Zero cost in release builds — the field and the
     * assert are both #ifndef NDEBUG-gated.
     *
     * Portable POSIX: pthread_t + pthread_self() + pthread_equal() are
     * available on pthreads-w32 / llvm-mingw winpthreads and Android NDK. */
    pthread_t task_mutex_owner;
#endif
} dna_task_queue_t;

/* ============================================================================
 * ENGINE STRUCTURE
 * ============================================================================ */

/**
 * Identity name cache entry
 */
#define DNA_NAME_CACHE_MAX 32

typedef struct {
    char fingerprint[129];
    char display_name[64];
} dna_name_cache_entry_t;

/**
 * Message queue entry for async sending (DM and Group messages)
 */
typedef struct {
    char recipient[129];     /* DM recipient fingerprint (empty if group message) */
    char group_uuid[37];     /* Group UUID (empty if DM message) */
    char *message;           /* Heap allocated, queue owns */
    int slot_id;             /* Unique slot ID for tracking */
    bool in_use;             /* True if slot contains valid message */
    time_t queued_at;        /* Timestamp when message was queued (for ordering) */
} dna_message_queue_entry_t;

/**
 * Message send queue (for fire-and-forget messaging)
 */
typedef struct {
    dna_message_queue_entry_t *entries;  /* Dynamic array */
    int capacity;                         /* Current capacity */
    int size;                             /* Number of messages in queue */
    int next_slot_id;                     /* Next slot ID to assign */
    pthread_mutex_t mutex;                /* Thread safety */
} dna_message_queue_t;

/**
 * Outbox listener entry (for real-time offline message notifications)
 */
#define DNA_MAX_OUTBOX_LISTENERS 128

typedef struct {
    char contact_fingerprint[129];      /* Contact we're listening to */
    size_t dht_token;                   /* Token from dht_listen() */
    bool active;                        /* True if listener is active */
    dht_dm_listen_ctx_t *dm_listen_ctx; /* Daily bucket context (v0.4.81+, day rotation) */
} dna_outbox_listener_t;

/* v0.9.0: Presence listeners removed — batch query via Nodus server.
 * dna_presence_listener_t and DNA_MAX_PRESENCE_LISTENERS deleted. */

/**
 * Contact request listener (for real-time contact request notifications)
 * Only one listener needed - listens to our own inbox key
 */
typedef struct {
    size_t dht_token;               /* Token from dht_listen_ex() */
    bool active;                    /* True if listener is active */
} dna_contact_request_listener_t;

/**
 * Simple ACK listener entry (v15: replaced watermarks)
 *
 * ACK listeners are persistent - one per contact, stays active for the
 * session lifetime. When a recipient fetches messages and publishes an ACK,
 * we mark ALL pending messages to them as RECEIVED.
 */
#define DNA_MAX_ACK_LISTENERS 128

typedef struct {
    char contact_fingerprint[129];  /* Contact we're tracking ACKs from */
    uint64_t last_known_ack;        /* Last ACK timestamp received */
    size_t dht_token;               /* Token from dht_listen_ack() */
    bool active;                    /* True if listener is active */
} dna_ack_listener_t;

/**
 * Channel listener entry (for real-time channel post notifications)
 */
#define DNA_MAX_CHANNEL_LISTENERS 64

typedef struct {
    char channel_uuid[37];          /* Channel UUID we're listening to */
    char current_date[12];          /* YYYYMMDD for daily bucket rotation */
    size_t dht_token;               /* Token from dht_listen_ex() */
    bool active;                    /* True if listener is active */
} dna_channel_listener_t;

/**
 * DNA Engine internal state
 */
struct dna_engine {
    /* Configuration */
    char *data_dir;              /* Data directory path (owned) */

    /* Engine state (v0.6.50+: pause/resume lifecycle for Android) */
    dna_engine_state_t state;    /* Current lifecycle state */

    /* DHT: engine uses nodus singleton (no engine-owned context) */

    /* Identity lock (prevents multiple engines from loading same identity) */
    intptr_t identity_lock_fd;   /* File lock descriptor (-1 if not held) */

    /* Messenger backend */
    messenger_context_t *messenger;  /* Core messenger context */
    char fingerprint[129];           /* Current identity fingerprint */
    bool identity_loaded;            /* True if identity is active */
    bool listeners_starting;         /* True if listener setup in progress (race prevention) */
    bool dm_full_sync_done;          /* True after first full DM sync (prevents double sync on startup) */
    time_t profile_published_at;     /* Timestamp when profile was last published (0 = never) */

    /* DNAC digital cash (lazy init on first wallet access) */
    void *dnac_ctx;                  /* dnac_context_t* (NULL until first use) */

    /* Password protection (session state) */
    char *session_password;          /* Password for current session (NULL if unprotected) */
    bool keys_encrypted;             /* True if identity keys are password-protected */

    /* Database encryption (SQLCipher) */
    char db_encryption_key[129];     /* SHA3-512 hex key for SQLCipher (128 hex + null) */

    /* Wallet */
    // NOTE: wallet_list removed in v0.3.150 - was never assigned (dead code)
    blockchain_wallet_list_t *blockchain_wallets;  /* Multi-chain wallet list */
    bool wallets_loaded;             /* True if wallets have been scanned */

    /* Identity name cache (fingerprint -> display name) */
    dna_name_cache_entry_t name_cache[DNA_NAME_CACHE_MAX];
    int name_cache_count;
    pthread_mutex_t name_cache_mutex;

    /* Message send queue (for async fire-and-forget messaging) */
    dna_message_queue_t message_queue;

    /* Outbox listeners (for real-time offline message notifications) */
    dna_outbox_listener_t outbox_listeners[DNA_MAX_OUTBOX_LISTENERS];
    int outbox_listener_count;
    pthread_mutex_t outbox_listeners_mutex;

    /* v0.9.0: Presence listeners removed — batch query via Nodus server */

    /* Contact request listener (for real-time contact request notifications) */
    dna_contact_request_listener_t contact_request_listener;
    pthread_mutex_t contact_request_listener_mutex;

    /* Simple ACK listeners (v15: for message delivery confirmation) */
    dna_ack_listener_t ack_listeners[DNA_MAX_ACK_LISTENERS];
    int ack_listener_count;
    pthread_mutex_t ack_listeners_mutex;

    /* Wall poll timer (v0.9.142+ replaces wall listeners) */
    pthread_t wall_poll_thread;
    bool wall_poll_active;

    /* Channel listeners (for real-time channel post notifications) */
    dna_channel_listener_t channel_listeners[DNA_MAX_CHANNEL_LISTENERS];
    int channel_listener_count;
    pthread_mutex_t channel_listeners_mutex;

    /* Group outbox listeners (for real-time group message notifications) */
    #define DNA_MAX_GROUP_LISTENERS 64
    dna_group_listen_ctx_t *group_listen_contexts[DNA_MAX_GROUP_LISTENERS];
    int group_listen_count;
    pthread_mutex_t group_listen_mutex;

    /* Event callback */
    dna_event_cb event_callback;
    void *event_user_data;
    bool callback_disposing;     /* Set when callback is being cleared (prevents race) */
    pthread_mutex_t event_mutex;

    /* Threading */
    pthread_t *worker_threads;       /* Dynamically allocated based on CPU cores */
    int worker_count;                /* Actual number of worker threads */
    dna_task_queue_t task_queue;
    atomic_bool shutdown_requested;
    pthread_mutex_t task_mutex;
    pthread_cond_t task_cond;

    /* Presence heartbeat (announces our presence every 4 minutes) */
    pthread_t presence_heartbeat_thread;
    bool presence_heartbeat_started;  /* v0.6.0+: Track if thread was started */
    atomic_bool presence_active;  /* false when app in background (Android) */

    /* Background task threads (v0.6.0+: tracked for clean shutdown) */
    pthread_t setup_listeners_thread;      /* Listener setup thread handle */
    pthread_t stabilization_retry_thread;  /* Stabilization retry thread handle */
    bool setup_listeners_running;          /* True while thread is active */
    bool stabilization_retry_running;      /* True while thread is active */
    _Atomic bool initial_connect_handled;  /* True after first stabilization completes */
    pthread_mutex_t background_threads_mutex;  /* Protects running flags */
    pthread_cond_t background_thread_exit_cond;  /* v0.6.113: Signaled when background thread exits */

    /* HIGH-8: Track backup/restore threads for clean shutdown */
    /* SEC-05 (Phase 02-02): running flags are _Atomic bool — the destroy path
     * reads them without holding any engine mutex, and the backup/restore
     * threads write them from their own pthread. Plain bool is a data race. */
    pthread_t backup_thread;
    _Atomic bool backup_thread_running;  /* SEC-05: atomic for destroy-path read race */
    pthread_t restore_thread;
    _Atomic bool restore_thread_running;  /* SEC-05: atomic for destroy-path read race */

    /* v0.6.107+: State synchronization */
    pthread_mutex_t state_mutex;           /* Protects engine state transitions */

    /* Request ID generation */
    atomic_uint_fast64_t next_request_id;
};

/* ============================================================================
 * INTERNAL FUNCTIONS - Task Queue
 * ============================================================================ */

/**
 * Initialize task queue
 */
void dna_task_queue_init(dna_task_queue_t *queue);

/**
 * Push task to queue
 * @return true on success, false if queue full
 */
bool dna_task_queue_push(dna_task_queue_t *queue, const dna_task_t *task);

/**
 * Pop task from queue
 * @return true on success, false if queue empty
 */
bool dna_task_queue_pop(dna_task_queue_t *queue, dna_task_t *task_out);

/**
 * Check if queue is empty
 */
bool dna_task_queue_empty(dna_task_queue_t *queue);

/* ============================================================================
 * INTERNAL FUNCTIONS - Threading
 * ============================================================================ */

/**
 * Start worker threads
 */
int dna_start_workers(dna_engine_t *engine);

/**
 * Stop worker threads
 */
void dna_stop_workers(dna_engine_t *engine);

/**
 * Worker thread entry point
 */
void* dna_worker_thread(void *arg);

/* ============================================================================
 * INTERNAL FUNCTIONS - Task Execution
 * ============================================================================ */

/**
 * Execute a task (called by worker thread)
 */
void dna_execute_task(dna_engine_t *engine, dna_task_t *task);

/**
 * Generate next request ID
 */
dna_request_id_t dna_next_request_id(dna_engine_t *engine);

/**
 * Submit task to queue
 */
dna_request_id_t dna_submit_task(
    dna_engine_t *engine,
    dna_task_type_t type,
    const dna_task_params_t *params,
    dna_task_callback_t callback,
    void *user_data
);

/* ============================================================================
 * INTERNAL FUNCTIONS - Event Dispatch
 * ============================================================================ */

/**
 * Dispatch event to callback (thread-safe)
 */
void dna_dispatch_event(dna_engine_t *engine, const dna_event_t *event);

/* ============================================================================
 * INTERNAL FUNCTIONS - Task Handlers
 * ============================================================================ */

/* Identity (v0.3.0: dna_handle_list_identities removed - single-user model) */
void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task);
void dna_handle_load_identity(dna_engine_t *engine, dna_task_t *task);
void dna_handle_register_name(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_display_name(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_avatar(dna_engine_t *engine, dna_task_t *task);
void dna_handle_lookup_name(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_profile(dna_engine_t *engine, dna_task_t *task);
void dna_handle_lookup_profile(dna_engine_t *engine, dna_task_t *task);
void dna_handle_update_profile(dna_engine_t *engine, dna_task_t *task);
void dna_auto_republish_own_profile(dna_engine_t *engine);

/* Contacts */
void dna_handle_get_contacts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_add_contact(dna_engine_t *engine, dna_task_t *task);
void dna_handle_remove_contact(dna_engine_t *engine, dna_task_t *task);

/* Contact Requests (ICQ-style) */
void dna_handle_send_contact_request(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_contact_requests(dna_engine_t *engine, dna_task_t *task);
void dna_handle_approve_contact_request(dna_engine_t *engine, dna_task_t *task);
void dna_handle_deny_contact_request(dna_engine_t *engine, dna_task_t *task);
void dna_handle_block_user(dna_engine_t *engine, dna_task_t *task);
void dna_handle_unblock_user(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_blocked_users(dna_engine_t *engine, dna_task_t *task);

/* Messaging */
void dna_handle_send_message(dna_engine_t *engine, dna_task_t *task);
void dna_handle_send_reaction(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_reactions(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_conversation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_conversation_page(dna_engine_t *engine, dna_task_t *task);
void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task);
void dna_handle_check_offline_messages_from(dna_engine_t *engine, dna_task_t *task);
void dna_handle_delete_message(dna_engine_t *engine, dna_task_t *task);
void dna_handle_delete_conversation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_delete_all_messages(dna_engine_t *engine, dna_task_t *task);

/* Groups */
void dna_handle_get_groups(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_group_info(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_group_members(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task);
void dna_handle_send_group_message(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_group_conversation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_add_group_member(dna_engine_t *engine, dna_task_t *task);
void dna_handle_remove_group_member(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_invitations(dna_engine_t *engine, dna_task_t *task);
void dna_handle_accept_invitation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_reject_invitation(dna_engine_t *engine, dna_task_t *task);

/* Wallet */
void dna_handle_list_wallets(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_balances(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_cached_balances(dna_engine_t *engine, dna_task_t *task);
void dna_handle_send_tokens(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_transactions(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_cached_transactions(dna_engine_t *engine, dna_task_t *task);
void dna_handle_estimate_gas(dna_engine_t *engine, dna_task_t *task);
void dna_handle_dex_quote(dna_engine_t *engine, dna_task_t *task);
void dna_handle_dex_list_pairs(dna_engine_t *engine, dna_task_t *task);
void dna_handle_dex_swap(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_tx_status(dna_engine_t *engine, dna_task_t *task);

/* P2P & Presence */
void dna_handle_refresh_presence(dna_engine_t *engine, dna_task_t *task);
void dna_handle_lookup_presence(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_contacts_to_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_contacts_from_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_groups(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_groups_to_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_group_by_uuid(dna_engine_t *engine, dna_task_t *task);
void dna_handle_subscribe_to_contacts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_registered_name(dna_engine_t *engine, dna_task_t *task);

/* Wall (personal wall posts, v0.6.135+) */
void dna_handle_wall_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_delete(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_load(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_timeline(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_timeline_cached(dna_engine_t *engine, dna_task_t *task);

/* Wall Comments (v0.7.0+) */
void dna_handle_wall_add_comment(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_get_comments(dna_engine_t *engine, dna_task_t *task);

/* Wall Likes (v0.9.52+) */
void dna_handle_wall_like(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_get_likes(dna_engine_t *engine, dna_task_t *task);

/* Wall Engagement Batch (v0.9.123+) */
void dna_handle_wall_get_engagement(dna_engine_t *engine, dna_task_t *task);

/* Wall Boost (v0.9.71+) */
void dna_handle_wall_boost_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_boost_timeline(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_load_day(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_get_image(dna_engine_t *engine, dna_task_t *task);

/* Channel handlers (dna_engine_channels.c) */
void dna_handle_channel_create(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get_batch(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_delete(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_discover(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_search(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get_posts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get_subscriptions(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_sync_subs_to_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_sync_subs_from_dht(dna_engine_t *engine, dna_task_t *task);

/* Media handlers (dna_engine_media.c) */
void dna_handle_media_upload(dna_engine_t *engine, dna_task_t *task);
void dna_handle_media_download(dna_engine_t *engine, dna_task_t *task);
void dna_handle_media_exists(dna_engine_t *engine, dna_task_t *task);

/* Follow handlers (dna_engine_follow.c) */
void dna_handle_follow(dna_engine_t *engine, dna_task_t *task);
void dna_handle_unfollow(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_following(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_following_to_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_following_from_dht(dna_engine_t *engine, dna_task_t *task);

/* Debug log handlers (dna_engine_debug_log.c) */
void dna_handle_debug_log_send(dna_engine_t *engine, dna_task_t *task);

/* ============================================================================
 * INTERNAL FUNCTIONS - Helpers
 * ============================================================================ */

/* v0.3.0: dna_scan_identities() removed - single-user model
 * Use dna_engine_has_identity() instead */

/**
 * Free task parameters (heap-allocated parts)
 */
void dna_free_task_params(dna_task_t *task);

/* ============================================================================
 * INTERNAL FUNCTIONS - Group Messaging
 * ============================================================================ */

/**
 * Subscribe to all groups (internal)
 * Called at engine init after DHT connects. Sets up listeners for all groups
 * the user is a member of. Also performs full sync of last 7 days.
 *
 * @param engine    Engine instance
 * @return Number of groups subscribed to
 */
int dna_engine_subscribe_all_groups(dna_engine_t *engine);

/**
 * Unsubscribe from all groups (internal)
 * Called at engine shutdown or DHT disconnection.
 *
 * @param engine    Engine instance
 */
void dna_engine_unsubscribe_all_groups(dna_engine_t *engine);

/**
 * Check day rotation for all group listeners (internal)
 * Called periodically (e.g., every 60 seconds) to rotate listeners at midnight UTC.
 *
 * @param engine    Engine instance
 * @return Number of groups that rotated
 */
int dna_engine_check_group_day_rotation(dna_engine_t *engine);

/**
 * @brief Check and rotate 1-1 DM outbox listeners at day boundary
 *
 * Called from heartbeat thread every 4 minutes. Actual rotation only happens
 * at midnight UTC when the day bucket number changes (v0.4.81+).
 *
 * @param engine    Engine instance
 * @return Number of DM outbox listeners that rotated
 */
int dna_engine_check_outbox_day_rotation(dna_engine_t *engine);

/**
 * Check and rotate channel post listeners at midnight UTC.
 * @return Number of channel listeners that rotated
 */
int dna_engine_check_channel_day_rotation(dna_engine_t *engine);

/* ============================================================================
 * HELPER FUNCTIONS (from dna_engine_helpers.c)
 * ============================================================================ */

/* dna_get_dht_ctx() removed — use nodus_ops_is_ready() directly */
qgp_key_t* dna_load_private_key(dna_engine_t *engine);
qgp_key_t* dna_load_encryption_key(dna_engine_t *engine);
bool dht_wait_for_stabilization(dna_engine_t *engine);

/* ============================================================================
 * PRESENCE FUNCTIONS (from dna_engine_presence.c)
 * ============================================================================ */

int dna_start_presence_heartbeat(dna_engine_t *engine);
void dna_stop_presence_heartbeat(dna_engine_t *engine);
int dna_engine_network_changed(dna_engine_t *engine);

/* ============================================================================
 * WORKER FUNCTIONS (from dna_engine_workers.c)
 * ============================================================================ */

void* dna_worker_thread(void *arg);
int dna_start_workers(dna_engine_t *engine);
void dna_stop_workers(dna_engine_t *engine);

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_INTERNAL_H */
