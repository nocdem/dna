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
#include "blockchain/wallet.h"
#include "blockchain/blockchain_rpc.h"
#include "database/contacts_db.h"
#include "database/group_invitations.h"
#include "dht/shared/dht_groups.h"
#include "dht/shared/dht_offline_queue.h"

#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

#define DNA_TASK_QUEUE_SIZE 256
#define DNA_WORKER_THREAD_COUNT 4
#define DNA_REQUEST_ID_INVALID 0

/* ============================================================================
 * TASK TYPES
 * ============================================================================ */

typedef enum {
    /* Identity */
    TASK_LIST_IDENTITIES,
    TASK_CREATE_IDENTITY,
    TASK_LOAD_IDENTITY,
    TASK_REGISTER_NAME,
    TASK_GET_DISPLAY_NAME,
    TASK_LOOKUP_NAME,

    /* Contacts */
    TASK_GET_CONTACTS,
    TASK_ADD_CONTACT,
    TASK_REMOVE_CONTACT,

    /* Messaging */
    TASK_SEND_MESSAGE,
    TASK_GET_CONVERSATION,
    TASK_CHECK_OFFLINE_MESSAGES,

    /* Groups */
    TASK_GET_GROUPS,
    TASK_CREATE_GROUP,
    TASK_SEND_GROUP_MESSAGE,
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
    TASK_SYNC_CONTACTS_TO_DHT,
    TASK_SYNC_CONTACTS_FROM_DHT,
    TASK_SYNC_GROUPS,
    TASK_SUBSCRIBE_TO_CONTACTS,
    TASK_GET_REGISTERED_NAME,

    /* Feed */
    TASK_GET_FEED_CHANNELS,
    TASK_CREATE_FEED_CHANNEL,
    TASK_INIT_DEFAULT_CHANNELS,
    TASK_GET_FEED_POSTS,
    TASK_CREATE_FEED_POST,
    TASK_GET_FEED_POST_REPLIES,
    TASK_CAST_FEED_VOTE,
    TASK_GET_FEED_VOTES
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
        uint8_t signing_seed[32];
        uint8_t encryption_seed[32];
    } create_identity;

    /* Load identity */
    struct {
        char fingerprint[129];
    } load_identity;

    /* Register name */
    struct {
        char name[256];
    } register_name;

    /* Get display name */
    struct {
        char fingerprint[129];
    } get_display_name;

    /* Lookup name */
    struct {
        char name[256];
    } lookup_name;

    /* Add contact */
    struct {
        char identifier[256];
    } add_contact;

    /* Remove contact */
    struct {
        char fingerprint[129];
    } remove_contact;

    /* Send message */
    struct {
        char recipient[129];
        char *message;  /* Heap allocated, task owns */
    } send_message;

    /* Get conversation */
    struct {
        char contact[129];
    } get_conversation;

    /* Create group */
    struct {
        char name[256];
        char **members;  /* Heap allocated array, task owns */
        int member_count;
    } create_group;

    /* Send group message */
    struct {
        char group_uuid[37];
        char *message;  /* Heap allocated, task owns */
    } send_group_message;

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
        char reply_to[200];
    } create_feed_post;

    /* Get feed post replies */
    struct {
        char post_id[200];
    } get_feed_post_replies;

    /* Cast feed vote */
    struct {
        char post_id[200];
        int8_t vote_value;
    } cast_feed_vote;

    /* Get feed votes */
    struct {
        char post_id[200];
    } get_feed_votes;

} dna_task_params_t;

/**
 * Task callback union
 */
typedef union {
    dna_completion_cb completion;
    dna_identities_cb identities;
    dna_identity_created_cb identity_created;
    dna_display_name_cb display_name;
    dna_contacts_cb contacts;
    dna_messages_cb messages;
    dna_groups_cb groups;
    dna_group_created_cb group_created;
    dna_invitations_cb invitations;
    dna_wallets_cb wallets;
    dna_balances_cb balances;
    dna_transactions_cb transactions;
    dna_feed_channels_cb feed_channels;
    dna_feed_channel_cb feed_channel;
    dna_feed_posts_cb feed_posts;
    dna_feed_post_cb feed_post;
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
 * DNA Engine internal state
 */
struct dna_engine {
    /* Configuration */
    char *data_dir;              /* Data directory path (owned) */

    /* Messenger backend */
    messenger_context_t *messenger;  /* Core messenger context */
    char fingerprint[129];           /* Current identity fingerprint */
    bool identity_loaded;            /* True if identity is active */

    /* Wallet */
    wallet_list_t *wallet_list;      /* Cached wallet list */
    bool wallets_loaded;             /* True if wallets have been scanned */

    /* Identity name cache (fingerprint -> display name) */
    dna_name_cache_entry_t name_cache[DNA_NAME_CACHE_MAX];
    int name_cache_count;
    pthread_mutex_t name_cache_mutex;

    /* Event callback */
    dna_event_cb event_callback;
    void *event_user_data;
    pthread_mutex_t event_mutex;

    /* Threading */
    pthread_t worker_threads[DNA_WORKER_THREAD_COUNT];
    dna_task_queue_t task_queue;
    atomic_bool shutdown_requested;
    pthread_mutex_t task_mutex;
    pthread_cond_t task_cond;

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

/* Identity */
void dna_handle_list_identities(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task);
void dna_handle_load_identity(dna_engine_t *engine, dna_task_t *task);
void dna_handle_register_name(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_display_name(dna_engine_t *engine, dna_task_t *task);
void dna_handle_lookup_name(dna_engine_t *engine, dna_task_t *task);

/* Contacts */
void dna_handle_get_contacts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_add_contact(dna_engine_t *engine, dna_task_t *task);
void dna_handle_remove_contact(dna_engine_t *engine, dna_task_t *task);

/* Messaging */
void dna_handle_send_message(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_conversation(dna_engine_t *engine, dna_task_t *task);
void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task);

/* Groups */
void dna_handle_get_groups(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task);
void dna_handle_send_group_message(dna_engine_t *engine, dna_task_t *task);
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
void dna_handle_sync_contacts_to_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_contacts_from_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_sync_groups(dna_engine_t *engine, dna_task_t *task);
void dna_handle_subscribe_to_contacts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_registered_name(dna_engine_t *engine, dna_task_t *task);

/* Feed */
void dna_handle_get_feed_channels(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_feed_channel(dna_engine_t *engine, dna_task_t *task);
void dna_handle_init_default_channels(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_feed_posts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_create_feed_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_feed_post_replies(dna_engine_t *engine, dna_task_t *task);
void dna_handle_cast_feed_vote(dna_engine_t *engine, dna_task_t *task);
void dna_handle_get_feed_votes(dna_engine_t *engine, dna_task_t *task);

/* ============================================================================
 * INTERNAL FUNCTIONS - Helpers
 * ============================================================================ */

/**
 * Scan ~/.dna for identity files
 * @param data_dir Data directory path
 * @param fingerprints_out Output array of fingerprints (caller frees)
 * @param count_out Number of fingerprints found
 * @return 0 on success, -1 on error
 */
int dna_scan_identities(const char *data_dir, char ***fingerprints_out, int *count_out);

/**
 * Free task parameters (heap-allocated parts)
 */
void dna_free_task_params(dna_task_t *task);

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_INTERNAL_H */
