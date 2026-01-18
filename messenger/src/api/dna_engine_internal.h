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
#define DNA_REQUEST_ID_INVALID 0
#define DNA_MESSAGE_QUEUE_DEFAULT_CAPACITY 20
#define DNA_MESSAGE_QUEUE_MAX_CAPACITY 100

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

    /* Groups */
    TASK_GET_GROUPS,
    TASK_GET_GROUP_INFO,
    TASK_GET_GROUP_MEMBERS,
    TASK_CREATE_GROUP,
    TASK_SEND_GROUP_MESSAGE,
    TASK_GET_GROUP_CONVERSATION,
    TASK_ADD_GROUP_MEMBER,
    TASK_GET_INVITATIONS,
    TASK_ACCEPT_INVITATION,
    TASK_REJECT_INVITATION,

    /* Wallet */
    TASK_LIST_WALLETS,
    TASK_GET_BALANCES,
    TASK_SEND_TOKENS,
    TASK_GET_TRANSACTIONS,

    /* P2P & Presence */
    TASK_REFRESH_PRESENCE,
    TASK_LOOKUP_PRESENCE,
    TASK_SYNC_CONTACTS_TO_DHT,
    TASK_SYNC_CONTACTS_FROM_DHT,
    TASK_SYNC_GROUPS,
    TASK_SYNC_GROUPS_TO_DHT,
    TASK_SYNC_GROUP_BY_UUID,
    TASK_GET_REGISTERED_NAME,

    /* Feed */
    TASK_GET_FEED_CHANNELS,
    TASK_CREATE_FEED_CHANNEL,
    TASK_INIT_DEFAULT_CHANNELS,
    TASK_GET_FEED_POSTS,
    TASK_CREATE_FEED_POST,
    TASK_ADD_FEED_COMMENT,
    TASK_GET_FEED_COMMENTS,
    TASK_CAST_FEED_VOTE,
    TASK_GET_FEED_VOTES,
    TASK_CAST_COMMENT_VOTE,
    TASK_GET_COMMENT_VOTES
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

    /* Create feed channel */
    struct {
        char name[64];
        char description[512];
    } create_feed_channel;

    /* Get feed posts */
    struct {
        char channel_id[65];
        char date[12];  /* YYYYMMDD or empty for today */
    } get_feed_posts;

    /* Create feed post */
    struct {
        char channel_id[65];
        char *text;  /* Heap allocated, task owns */
    } create_feed_post;

    /* Add feed comment */
    struct {
        char post_id[200];
        char *text;  /* Heap allocated, task owns */
    } add_feed_comment;

    /* Get feed comments */
    struct {
        char post_id[200];
    } get_feed_comments;

    /* Cast feed vote */
    struct {
        char post_id[200];
        int8_t vote_value;
    } cast_feed_vote;

    /* Get feed votes */
    struct {
        char post_id[200];
    } get_feed_votes;

    /* Cast comment vote */
    struct {
        char comment_id[200];
        int8_t vote_value;
    } cast_comment_vote;

    /* Get comment votes */
    struct {
        char comment_id[200];
    } get_comment_votes;

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

} dna_task_params_t;

/**
 * Task callback union
 */
typedef union {
    dna_completion_cb completion;
    dna_send_tokens_cb send_tokens;
    dna_identities_cb identities;
    dna_identity_created_cb identity_created;
    dna_display_name_cb display_name;
    dna_contacts_cb contacts;
    dna_contact_requests_cb contact_requests;
    dna_blocked_users_cb blocked_users;
    dna_messages_cb messages;
    dna_messages_page_cb messages_page;
    dna_groups_cb groups;
    dna_group_info_cb group_info;
    dna_group_members_cb group_members;
    dna_group_created_cb group_created;
    dna_invitations_cb invitations;
    dna_wallets_cb wallets;
    dna_balances_cb balances;
    dna_transactions_cb transactions;
    dna_feed_channels_cb feed_channels;
    dna_feed_channel_cb feed_channel;
    dna_feed_posts_cb feed_posts;
    dna_feed_post_cb feed_post;
    dna_feed_comments_cb feed_comments;
    dna_feed_comment_cb feed_comment;
    dna_profile_cb profile;
    dna_presence_cb presence;
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
 * Message queue entry for async sending
 */
typedef struct {
    char recipient[129];
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

/**
 * Presence listener entry (for real-time contact online status)
 */
#define DNA_MAX_PRESENCE_LISTENERS 128

typedef struct {
    char contact_fingerprint[129];  /* Contact we're listening to */
    size_t dht_token;               /* Token from dht_listen() */
    bool active;                    /* True if listener is active */
} dna_presence_listener_t;

/**
 * Contact request listener (for real-time contact request notifications)
 * Only one listener needed - listens to our own inbox key
 */
typedef struct {
    size_t dht_token;               /* Token from dht_listen_ex() */
    bool active;                    /* True if listener is active */
} dna_contact_request_listener_t;

/**
 * Persistent watermark listener entry (for delivery confirmation)
 *
 * Watermark listeners are persistent - one per contact, stays active for the
 * session lifetime. They receive watermark updates and update message delivery
 * status in bulk (all messages with seq <= watermark become DELIVERED).
 */
#define DNA_MAX_WATERMARK_LISTENERS 128

typedef struct {
    char contact_fingerprint[129];  /* Contact we're tracking watermarks from */
    uint64_t last_known_watermark;  /* Last watermark value received */
    size_t dht_token;               /* Token from dht_listen_watermark() */
    bool active;                    /* True if listener is active */
} dna_watermark_listener_t;

/**
 * DNA Engine internal state
 */
struct dna_engine {
    /* Configuration */
    char *data_dir;              /* Data directory path (owned) */

    /* Messenger backend */
    messenger_context_t *messenger;  /* Core messenger context */
    char fingerprint[129];           /* Current identity fingerprint */
    bool identity_loaded;            /* True if identity is active */
    bool listeners_starting;         /* True if listener setup in progress (race prevention) */
    time_t profile_published_at;     /* Timestamp when profile was last published (0 = never) */

    /* Password protection (session state) */
    char *session_password;          /* Password for current session (NULL if unprotected) */
    bool keys_encrypted;             /* True if identity keys are password-protected */

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

    /* Presence listeners (for real-time contact online status) */
    dna_presence_listener_t presence_listeners[DNA_MAX_PRESENCE_LISTENERS];
    int presence_listener_count;
    pthread_mutex_t presence_listeners_mutex;

    /* Contact request listener (for real-time contact request notifications) */
    dna_contact_request_listener_t contact_request_listener;
    pthread_mutex_t contact_request_listener_mutex;

    /* Persistent watermark listeners (for message delivery confirmation) */
    dna_watermark_listener_t watermark_listeners[DNA_MAX_WATERMARK_LISTENERS];
    int watermark_listener_count;
    pthread_mutex_t watermark_listeners_mutex;

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
    atomic_bool presence_active;  /* false when app in background (Android) */

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
void dna_handle_get_conversation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_conversation_page(dna_engine_t *engine, dna_task_t *task);
void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task);

/* Groups */
void dna_handle_get_groups(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_group_info(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_group_members(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task);
void dna_handle_send_group_message(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_group_conversation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_invitations(dna_engine_t *engine, dna_task_t *task);
void dna_handle_accept_invitation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_reject_invitation(dna_engine_t *engine, dna_task_t *task);

/* Wallet */
void dna_handle_list_wallets(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_balances(dna_engine_t *engine, dna_task_t *task);
void dna_handle_send_tokens(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_transactions(dna_engine_t *engine, dna_task_t *task);

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

/* Feed */
void dna_handle_get_feed_channels(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_feed_channel(dna_engine_t *engine, dna_task_t *task);
void dna_handle_init_default_channels(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_feed_posts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_feed_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_add_feed_comment(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_feed_comments(dna_engine_t *engine, dna_task_t *task);
void dna_handle_cast_feed_vote(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_feed_votes(dna_engine_t *engine, dna_task_t *task);
void dna_handle_cast_comment_vote(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_comment_votes(dna_engine_t *engine, dna_task_t *task);

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
 * Fire Android callback for group messages (internal helper)
 * Called from group outbox subscribe callback when new messages arrive.
 *
 * @param group_uuid    UUID of the group
 * @param group_name    Display name of the group (may be NULL)
 * @param new_count     Number of new messages
 */
void dna_engine_fire_group_message_callback(
    const char *group_uuid,
    const char *group_name,
    size_t new_count
);

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

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_INTERNAL_H */
