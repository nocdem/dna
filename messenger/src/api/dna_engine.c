/*
 * DNA Engine - Implementation
 *
 * Core engine implementation providing async API for DNA Messenger.
 */

#define _XOPEN_SOURCE 700  /* For strptime */

#ifdef _WIN32
#include <direct.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define platform_mkdir(path, mode) _mkdir(path)

/* Windows doesn't have strndup */
static char* win_strndup(const char* s, size_t n) {
    size_t len = strlen(s);
    if (len > n) len = n;
    char* result = (char*)malloc(len + 1);
    if (result) {
        memcpy(result, s, len);
        result[len] = '\0';
    }
    return result;
}
#define strndup win_strndup

/* Windows doesn't have strcasecmp */
#define strcasecmp _stricmp

/* Windows doesn't have strptime - simple parser for YYYY-MM-DD HH:MM:SS */
static char* win_strptime(const char* s, const char* format, struct tm* tm) {
    (void)format; /* We only support one format */
    int year, month, day, hour, min, sec;
    if (sscanf(s, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &min, &sec) == 6) {
        tm->tm_year = year - 1900;
        tm->tm_mon = month - 1;
        tm->tm_mday = day;
        tm->tm_hour = hour;
        tm->tm_min = min;
        tm->tm_sec = sec;
        tm->tm_isdst = -1;
        return (char*)(s + 19); /* Return pointer past parsed string */
    }
    return NULL;
}
#define strptime win_strptime

#else
#include <strings.h>  /* For strcasecmp */
#define platform_mkdir(path, mode) mkdir(path, mode)
#endif

#include "dna_engine_internal.h"
#include "dna_api.h"
#include "messenger_p2p.h"
#include "message_backup.h"
#include "messenger/status.h"
#include "dht/client/dht_singleton.h"
#include "dht/core/dht_keyserver.h"
#include "dht/core/dht_listen.h"
#include "dht/client/dht_contactlist.h"
#include "dht/client/dht_message_backup.h"
#include "dht/client/dna_feed.h"
#include "dht/client/dna_profile.h"
#include "dht/shared/dht_chunked.h"
#include "p2p/p2p_transport.h"
#include "p2p/transport/turn_credentials.h"
#include "database/presence_cache.h"
#include "database/keyserver_cache.h"
#include "database/profile_cache.h"
#include "database/profile_manager.h"
#include "database/contacts_db.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/key_encryption.h"

/* Blockchain/Wallet includes for send_tokens */
#include "cellframe_wallet.h"
#include "cellframe_rpc.h"
#include "cellframe_tx_builder.h"
#include "cellframe_sign.h"
#include "cellframe_json.h"
#include "crypto/utils/base58.h"
#include "blockchain/ethereum/eth_wallet.h"
#include "blockchain/ethereum/eth_erc20.h"
#include "blockchain/solana/sol_wallet.h"
#include "blockchain/solana/sol_rpc.h"
#include "blockchain/solana/sol_spl.h"
#include "blockchain/tron/trx_wallet.h"
#include "blockchain/tron/trx_rpc.h"
#include "blockchain/tron/trx_trc20.h"
#include "blockchain/blockchain_wallet.h"
#include "blockchain/cellframe/cellframe_addr.h"
#include "crypto/utils/seed_storage.h"
#include "crypto/bip39/bip39.h"
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"
#include "dna_config.h"

#define LOG_TAG "DNA_ENGINE"
/* Use engine-specific error codes */
#define DNA_OK 0

/* Forward declarations for static helpers */
static dht_context_t* dna_get_dht_ctx(dna_engine_t *engine);
static qgp_key_t* dna_load_private_key(dna_engine_t *engine);
static qgp_key_t* dna_load_encryption_key(dna_engine_t *engine);
static void init_log_config(void);

/* Global engine pointer for DHT status callback and event dispatch from lower layers
 * Set during create, cleared during destroy. Used by messenger_p2p.c to emit events. */
static dna_engine_t *g_dht_callback_engine = NULL;

/* Global engine accessors (for messenger layer event dispatch) */
void dna_engine_set_global(dna_engine_t *engine) {
    g_dht_callback_engine = engine;
}

dna_engine_t* dna_engine_get_global(void) {
    return g_dht_callback_engine;
}

/**
 * DHT status change callback - dispatches DHT_CONNECTED/DHT_DISCONNECTED events
 * Called from OpenDHT's internal thread when connection status changes.
 */
static void dna_dht_status_callback(bool is_connected, void *user_data) {
    (void)user_data;  /* Using global engine pointer instead */

    dna_engine_t *engine = g_dht_callback_engine;
    if (!engine) return;

    dna_event_t event = {0};
    if (is_connected) {
        QGP_LOG_WARN(LOG_TAG, "DHT connected (bootstrap complete, ready for operations)");
        event.type = DNA_EVENT_DHT_CONNECTED;

        /* Prefetch profiles for local identities (for identity selection screen) */
        if (engine->data_dir) {
            profile_manager_prefetch_local_identities(engine->data_dir);
        }

        /* Restart outbox listeners on DHT connect (handles reconnection)
         * Listeners fire DNA_EVENT_OUTBOX_UPDATED -> Flutter polls + refreshes UI */
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT connected, identity_loaded=%d", engine->identity_loaded);
        if (engine->identity_loaded) {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Starting outbox listeners from DHT callback...");
            int count = dna_engine_listen_all_contacts(engine);
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT callback: started %d listeners", count);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Skipping listeners (no identity loaded yet)");
        }
    } else {
        /* DHT disconnection can happen during:
         * 1. Initial bootstrap (network not ready yet)
         * 2. Network interface changes (WiFi->mobile, etc.)
         * 3. All bootstrap nodes unreachable
         * The DHT will automatically attempt to reconnect */
        QGP_LOG_WARN(LOG_TAG, "DHT disconnected (will auto-reconnect when network available)");
        event.type = DNA_EVENT_DHT_DISCONNECTED;
    }
    dna_dispatch_event(engine, &event);
}

/* ============================================================================
 * ERROR STRINGS
 * ============================================================================ */

const char* dna_engine_error_string(int error) {
    if (error == 0) return "Success";
    if (error == DNA_ENGINE_ERROR_INIT) return "Initialization failed";
    if (error == DNA_ENGINE_ERROR_NOT_INITIALIZED) return "Not initialized";
    if (error == DNA_ENGINE_ERROR_NETWORK) return "Network error";
    if (error == DNA_ENGINE_ERROR_DATABASE) return "Database error";
    if (error == DNA_ENGINE_ERROR_TIMEOUT) return "Operation timed out";
    if (error == DNA_ENGINE_ERROR_BUSY) return "Engine busy";
    if (error == DNA_ENGINE_ERROR_NO_IDENTITY) return "No identity loaded";
    if (error == DNA_ENGINE_ERROR_ALREADY_EXISTS) return "Already exists";
    if (error == DNA_ENGINE_ERROR_PERMISSION) return "Permission denied";
    if (error == DNA_ENGINE_ERROR_PASSWORD_REQUIRED) return "Password required for encrypted keys";
    if (error == DNA_ENGINE_ERROR_WRONG_PASSWORD) return "Incorrect password";
    if (error == DNA_ENGINE_ERROR_INVALID_SIGNATURE) return "Profile signature verification failed (corrupted or stale DHT data)";
    /* Fall back to base dna_api.h error strings */
    if (error == DNA_ERROR_INVALID_ARG) return "Invalid argument";
    if (error == DNA_ERROR_NOT_FOUND) return "Not found";
    if (error == DNA_ERROR_CRYPTO) return "Cryptographic error";
    if (error == DNA_ERROR_INTERNAL) return "Internal error";
    return "Unknown error";
}

/* ============================================================================
 * TASK QUEUE IMPLEMENTATION
 * ============================================================================ */

void dna_task_queue_init(dna_task_queue_t *queue) {
    memset(queue->tasks, 0, sizeof(queue->tasks));
    atomic_store(&queue->head, 0);
    atomic_store(&queue->tail, 0);
}

bool dna_task_queue_push(dna_task_queue_t *queue, const dna_task_t *task) {
    size_t head = atomic_load(&queue->head);
    size_t next_head = (head + 1) % DNA_TASK_QUEUE_SIZE;

    /* Check if full */
    if (next_head == atomic_load(&queue->tail)) {
        return false;
    }

    queue->tasks[head] = *task;
    atomic_store(&queue->head, next_head);
    return true;
}

bool dna_task_queue_pop(dna_task_queue_t *queue, dna_task_t *task_out) {
    size_t tail = atomic_load(&queue->tail);

    /* Check if empty */
    if (tail == atomic_load(&queue->head)) {
        return false;
    }

    *task_out = queue->tasks[tail];
    atomic_store(&queue->tail, (tail + 1) % DNA_TASK_QUEUE_SIZE);
    return true;
}

bool dna_task_queue_empty(dna_task_queue_t *queue) {
    return atomic_load(&queue->head) == atomic_load(&queue->tail);
}

/* ============================================================================
 * REQUEST ID GENERATION
 * ============================================================================ */

dna_request_id_t dna_next_request_id(dna_engine_t *engine) {
    dna_request_id_t id = atomic_fetch_add(&engine->next_request_id, 1) + 1;
    /* Ensure never returns 0 (invalid) */
    if (id == DNA_REQUEST_ID_INVALID) {
        id = atomic_fetch_add(&engine->next_request_id, 1) + 1;
    }
    return id;
}

/* ============================================================================
 * TASK SUBMISSION
 * ============================================================================ */

dna_request_id_t dna_submit_task(
    dna_engine_t *engine,
    dna_task_type_t type,
    const dna_task_params_t *params,
    dna_task_callback_t callback,
    void *user_data
) {
    if (!engine) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_t task = {0};
    task.request_id = dna_next_request_id(engine);
    task.type = type;
    if (params) {
        task.params = *params;
    }
    task.callback = callback;
    task.user_data = user_data;
    task.cancelled = false;

    pthread_mutex_lock(&engine->task_mutex);
    bool pushed = dna_task_queue_push(&engine->task_queue, &task);
    if (pushed) {
        pthread_cond_signal(&engine->task_cond);
    }
    pthread_mutex_unlock(&engine->task_mutex);

    return pushed ? task.request_id : DNA_REQUEST_ID_INVALID;
}

/* ============================================================================
 * TASK PARAMETER CLEANUP
 * ============================================================================ */

void dna_free_task_params(dna_task_t *task) {
    switch (task->type) {
        case TASK_CREATE_IDENTITY:
            if (task->params.create_identity.password) {
                /* Secure clear password before freeing */
                memset(task->params.create_identity.password, 0,
                       strlen(task->params.create_identity.password));
                free(task->params.create_identity.password);
            }
            break;
        case TASK_LOAD_IDENTITY:
            if (task->params.load_identity.password) {
                /* Secure clear password before freeing */
                memset(task->params.load_identity.password, 0,
                       strlen(task->params.load_identity.password));
                free(task->params.load_identity.password);
            }
            break;
        case TASK_SEND_MESSAGE:
            free(task->params.send_message.message);
            break;
        case TASK_CREATE_GROUP:
            if (task->params.create_group.members) {
                for (int i = 0; i < task->params.create_group.member_count; i++) {
                    free(task->params.create_group.members[i]);
                }
                free(task->params.create_group.members);
            }
            break;
        case TASK_SEND_GROUP_MESSAGE:
            free(task->params.send_group_message.message);
            break;
        case TASK_CREATE_FEED_POST:
            free(task->params.create_feed_post.text);
            break;
        default:
            break;
    }
}

/* ============================================================================
 * WORKER THREAD
 * ============================================================================ */

void* dna_worker_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t*)arg;

    while (!atomic_load(&engine->shutdown_requested)) {
        dna_task_t task;
        bool has_task = false;

        pthread_mutex_lock(&engine->task_mutex);
        while (dna_task_queue_empty(&engine->task_queue) &&
               !atomic_load(&engine->shutdown_requested)) {
            pthread_cond_wait(&engine->task_cond, &engine->task_mutex);
        }

        if (!atomic_load(&engine->shutdown_requested)) {
            has_task = dna_task_queue_pop(&engine->task_queue, &task);
        }
        pthread_mutex_unlock(&engine->task_mutex);

        if (has_task && !task.cancelled) {
            dna_execute_task(engine, &task);
            dna_free_task_params(&task);
        }
    }

    return NULL;
}

int dna_start_workers(dna_engine_t *engine) {
    atomic_store(&engine->shutdown_requested, false);

    for (int i = 0; i < DNA_WORKER_THREAD_COUNT; i++) {
        int rc = pthread_create(&engine->worker_threads[i], NULL, dna_worker_thread, engine);
        if (rc != 0) {
            /* Stop already-started threads */
            atomic_store(&engine->shutdown_requested, true);
            pthread_cond_broadcast(&engine->task_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(engine->worker_threads[j], NULL);
            }
            return -1;
        }
    }
    return 0;
}

void dna_stop_workers(dna_engine_t *engine) {
    atomic_store(&engine->shutdown_requested, true);

    pthread_mutex_lock(&engine->task_mutex);
    pthread_cond_broadcast(&engine->task_cond);
    pthread_mutex_unlock(&engine->task_mutex);

    for (int i = 0; i < DNA_WORKER_THREAD_COUNT; i++) {
        pthread_join(engine->worker_threads[i], NULL);
    }
}

/* ============================================================================
 * EVENT DISPATCH
 * ============================================================================ */

void dna_dispatch_event(dna_engine_t *engine, const dna_event_t *event) {
    pthread_mutex_lock(&engine->event_mutex);
    dna_event_cb callback = engine->event_callback;
    void *user_data = engine->event_user_data;
    pthread_mutex_unlock(&engine->event_mutex);

    if (callback) {
        callback(event, user_data);
    }
}

/* ============================================================================
 * TASK EXECUTION DISPATCH
 * ============================================================================ */

void dna_execute_task(dna_engine_t *engine, dna_task_t *task) {
    switch (task->type) {
        /* Identity */
        case TASK_LIST_IDENTITIES:
            dna_handle_list_identities(engine, task);
            break;
        case TASK_CREATE_IDENTITY:
            dna_handle_create_identity(engine, task);
            break;
        case TASK_LOAD_IDENTITY:
            dna_handle_load_identity(engine, task);
            break;
        case TASK_REGISTER_NAME:
            dna_handle_register_name(engine, task);
            break;
        case TASK_GET_DISPLAY_NAME:
            dna_handle_get_display_name(engine, task);
            break;
        case TASK_GET_AVATAR:
            dna_handle_get_avatar(engine, task);
            break;
        case TASK_LOOKUP_NAME:
            dna_handle_lookup_name(engine, task);
            break;
        case TASK_GET_PROFILE:
            dna_handle_get_profile(engine, task);
            break;
        case TASK_LOOKUP_PROFILE:
            dna_handle_lookup_profile(engine, task);
            break;
        case TASK_UPDATE_PROFILE:
            dna_handle_update_profile(engine, task);
            break;

        /* Contacts */
        case TASK_GET_CONTACTS:
            dna_handle_get_contacts(engine, task);
            break;
        case TASK_ADD_CONTACT:
            dna_handle_add_contact(engine, task);
            break;
        case TASK_REMOVE_CONTACT:
            dna_handle_remove_contact(engine, task);
            break;

        /* Contact Requests (ICQ-style) */
        case TASK_SEND_CONTACT_REQUEST:
            dna_handle_send_contact_request(engine, task);
            break;
        case TASK_GET_CONTACT_REQUESTS:
            dna_handle_get_contact_requests(engine, task);
            break;
        case TASK_APPROVE_CONTACT_REQUEST:
            dna_handle_approve_contact_request(engine, task);
            break;
        case TASK_DENY_CONTACT_REQUEST:
            dna_handle_deny_contact_request(engine, task);
            break;
        case TASK_BLOCK_USER:
            dna_handle_block_user(engine, task);
            break;
        case TASK_UNBLOCK_USER:
            dna_handle_unblock_user(engine, task);
            break;
        case TASK_GET_BLOCKED_USERS:
            dna_handle_get_blocked_users(engine, task);
            break;

        /* Messaging */
        case TASK_SEND_MESSAGE:
            dna_handle_send_message(engine, task);
            break;
        case TASK_GET_CONVERSATION:
            dna_handle_get_conversation(engine, task);
            break;
        case TASK_CHECK_OFFLINE_MESSAGES:
            dna_handle_check_offline_messages(engine, task);
            break;

        /* Groups */
        case TASK_GET_GROUPS:
            dna_handle_get_groups(engine, task);
            break;
        case TASK_CREATE_GROUP:
            dna_handle_create_group(engine, task);
            break;
        case TASK_SEND_GROUP_MESSAGE:
            dna_handle_send_group_message(engine, task);
            break;
        case TASK_GET_INVITATIONS:
            dna_handle_get_invitations(engine, task);
            break;
        case TASK_ACCEPT_INVITATION:
            dna_handle_accept_invitation(engine, task);
            break;
        case TASK_REJECT_INVITATION:
            dna_handle_reject_invitation(engine, task);
            break;

        /* Wallet */
        case TASK_LIST_WALLETS:
            dna_handle_list_wallets(engine, task);
            break;
        case TASK_GET_BALANCES:
            dna_handle_get_balances(engine, task);
            break;
        case TASK_SEND_TOKENS:
            dna_handle_send_tokens(engine, task);
            break;
        case TASK_GET_TRANSACTIONS:
            dna_handle_get_transactions(engine, task);
            break;

        /* P2P & Presence */
        case TASK_REFRESH_PRESENCE:
            dna_handle_refresh_presence(engine, task);
            break;
        case TASK_LOOKUP_PRESENCE:
            dna_handle_lookup_presence(engine, task);
            break;
        case TASK_SYNC_CONTACTS_TO_DHT:
            dna_handle_sync_contacts_to_dht(engine, task);
            break;
        case TASK_SYNC_CONTACTS_FROM_DHT:
            dna_handle_sync_contacts_from_dht(engine, task);
            break;
        case TASK_SYNC_GROUPS:
            dna_handle_sync_groups(engine, task);
            break;
        case TASK_GET_REGISTERED_NAME:
            dna_handle_get_registered_name(engine, task);
            break;

        /* Feed */
        case TASK_GET_FEED_CHANNELS:
            dna_handle_get_feed_channels(engine, task);
            break;
        case TASK_CREATE_FEED_CHANNEL:
            dna_handle_create_feed_channel(engine, task);
            break;
        case TASK_INIT_DEFAULT_CHANNELS:
            dna_handle_init_default_channels(engine, task);
            break;
        case TASK_GET_FEED_POSTS:
            dna_handle_get_feed_posts(engine, task);
            break;
        case TASK_CREATE_FEED_POST:
            dna_handle_create_feed_post(engine, task);
            break;
        case TASK_ADD_FEED_COMMENT:
            dna_handle_add_feed_comment(engine, task);
            break;
        case TASK_GET_FEED_COMMENTS:
            dna_handle_get_feed_comments(engine, task);
            break;
        case TASK_CAST_FEED_VOTE:
            dna_handle_cast_feed_vote(engine, task);
            break;
        case TASK_GET_FEED_VOTES:
            dna_handle_get_feed_votes(engine, task);
            break;
        case TASK_CAST_COMMENT_VOTE:
            dna_handle_cast_comment_vote(engine, task);
            break;
        case TASK_GET_COMMENT_VOTES:
            dna_handle_get_comment_votes(engine, task);
            break;
    }
}

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================ */

dna_engine_t* dna_engine_create(const char *data_dir) {
    dna_engine_t *engine = calloc(1, sizeof(dna_engine_t));
    if (!engine) {
        return NULL;
    }

    /* Set data directory using cross-platform API */
    if (data_dir) {
        /* Mobile: use provided data_dir directly */
        qgp_platform_set_app_dirs(data_dir, NULL);
        engine->data_dir = strdup(data_dir);
    } else {
        /* Desktop: qgp_platform_app_data_dir() returns ~/.dna */
        const char *app_dir = qgp_platform_app_data_dir();
        if (app_dir) {
            engine->data_dir = strdup(app_dir);
        }
    }

    if (!engine->data_dir) {
        free(engine);
        return NULL;
    }

    /* Load config and apply log settings BEFORE any logging */
    dna_config_t config;
    memset(&config, 0, sizeof(config));
    dna_config_load(&config);
    dna_config_apply_log_settings(&config);
    init_log_config();  /* Populate global buffers for get functions */

    /* Enable debug ring buffer by default for in-app log viewing */
    qgp_log_ring_enable(true);

    /* Initialize synchronization */
    pthread_mutex_init(&engine->event_mutex, NULL);
    pthread_mutex_init(&engine->task_mutex, NULL);
    pthread_mutex_init(&engine->name_cache_mutex, NULL);
    pthread_cond_init(&engine->task_cond, NULL);

    /* Initialize name cache */
    engine->name_cache_count = 0;

    /* Initialize message send queue */
    pthread_mutex_init(&engine->message_queue.mutex, NULL);
    engine->message_queue.capacity = DNA_MESSAGE_QUEUE_DEFAULT_CAPACITY;
    engine->message_queue.entries = calloc(engine->message_queue.capacity,
                                           sizeof(dna_message_queue_entry_t));
    engine->message_queue.size = 0;
    engine->message_queue.next_slot_id = 1;

    /* Initialize outbox listeners */
    pthread_mutex_init(&engine->outbox_listeners_mutex, NULL);
    engine->outbox_listener_count = 0;
    memset(engine->outbox_listeners, 0, sizeof(engine->outbox_listeners));

    /* Initialize delivery trackers */
    pthread_mutex_init(&engine->delivery_trackers_mutex, NULL);
    engine->delivery_tracker_count = 0;
    memset(engine->delivery_trackers, 0, sizeof(engine->delivery_trackers));

    /* Initialize task queue */
    dna_task_queue_init(&engine->task_queue);

    /* Initialize request ID counter */
    atomic_store(&engine->next_request_id, 0);

    /* Initialize DHT singleton */
    dht_singleton_init();

    /* Initialize global keyserver cache (for display names before login) */
    keyserver_cache_init(NULL);

    /* Initialize global profile cache + manager (for profile prefetching)
     * DHT context is obtained dynamically via dht_singleton_get() to handle reinit
     * MUST be before status callback registration - callback triggers prefetch */
    profile_manager_init();

    /* Register DHT status callback to emit events on connection changes
     * This waits for DHT connection and fires callback which triggers prefetch */
    g_dht_callback_engine = engine;
    dht_singleton_set_status_callback(dna_dht_status_callback, NULL);

    /* Start worker threads */
    if (dna_start_workers(engine) != 0) {
        g_dht_callback_engine = NULL;
        dht_singleton_set_status_callback(NULL, NULL);
        pthread_mutex_destroy(&engine->event_mutex);
        pthread_mutex_destroy(&engine->task_mutex);
        pthread_cond_destroy(&engine->task_cond);
        free(engine->data_dir);
        free(engine);
        return NULL;
    }

    return engine;
}

void dna_engine_set_event_callback(
    dna_engine_t *engine,
    dna_event_cb callback,
    void *user_data
) {
    if (!engine) return;

    pthread_mutex_lock(&engine->event_mutex);
    engine->event_callback = callback;
    engine->event_user_data = user_data;
    pthread_mutex_unlock(&engine->event_mutex);
}

void dna_engine_destroy(dna_engine_t *engine) {
    if (!engine) return;

    /* Clear DHT status callback before stopping anything */
    if (g_dht_callback_engine == engine) {
        dht_singleton_set_status_callback(NULL, NULL);
        g_dht_callback_engine = NULL;
    }

    /* Stop worker threads */
    dna_stop_workers(engine);

    /* Free messenger context */
    if (engine->messenger) {
        messenger_free(engine->messenger);
    }

    /* Free wallet lists */
    if (engine->wallet_list) {
        wallet_list_free(engine->wallet_list);
    }
    if (engine->blockchain_wallets) {
        blockchain_wallet_list_free(engine->blockchain_wallets);
    }

    /* Cancel all outbox listeners */
    dna_engine_cancel_all_outbox_listeners(engine);
    pthread_mutex_destroy(&engine->outbox_listeners_mutex);

    /* Cancel all delivery trackers */
    dna_engine_cancel_all_delivery_trackers(engine);
    pthread_mutex_destroy(&engine->delivery_trackers_mutex);

    /* Free message queue */
    pthread_mutex_lock(&engine->message_queue.mutex);
    for (int i = 0; i < engine->message_queue.capacity; i++) {
        if (engine->message_queue.entries[i].in_use) {
            free(engine->message_queue.entries[i].message);
        }
    }
    free(engine->message_queue.entries);
    pthread_mutex_unlock(&engine->message_queue.mutex);
    pthread_mutex_destroy(&engine->message_queue.mutex);

    /* Cleanup synchronization */
    pthread_mutex_destroy(&engine->event_mutex);
    pthread_mutex_destroy(&engine->task_mutex);
    pthread_mutex_destroy(&engine->name_cache_mutex);
    pthread_cond_destroy(&engine->task_cond);

    /* Cleanup global caches */
    profile_manager_close();
    keyserver_cache_cleanup();

    /* Securely clear session password */
    if (engine->session_password) {
        memset(engine->session_password, 0, strlen(engine->session_password));
        free(engine->session_password);
        engine->session_password = NULL;
    }

    /* Free data directory */
    free(engine->data_dir);

    free(engine);
}

const char* dna_engine_get_fingerprint(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }
    return engine->fingerprint;
}

/* ============================================================================
 * IDENTITY SCAN HELPER
 * Scans <data_dir>/<name>/keys/ directories for identity key files
 * ============================================================================ */

/* Helper to check if filename is a valid fingerprint.dsa */
static bool is_valid_fingerprint_dsa(const char *filename) {
    size_t len = strlen(filename);
    if (len != 132 || strcmp(filename + 128, ".dsa") != 0) {
        return false;
    }
    /* Check first 128 chars are hex */
    for (int i = 0; i < 128; i++) {
        char c = filename[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

int dna_scan_identities(const char *data_dir, char ***fingerprints_out, int *count_out) {
    DIR *base_dir = opendir(data_dir);
    if (!base_dir) {
        *fingerprints_out = NULL;
        *count_out = 0;
        return 0; /* Empty result, not an error */
    }

    /* Dynamic array for fingerprints */
    int capacity = 16;
    int count = 0;
    char **fingerprints = calloc(capacity, sizeof(char*));
    if (!fingerprints) {
        closedir(base_dir);
        return -1;
    }

    /* Scan each subdirectory in <data_dir>/ */
    struct dirent *identity_entry;
    while ((identity_entry = readdir(base_dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(identity_entry->d_name, ".") == 0 ||
            strcmp(identity_entry->d_name, "..") == 0) {
            continue;
        }

        /* Build path to keys directory: <data_dir>/<name>/keys/ */
        char keys_path[512];
        snprintf(keys_path, sizeof(keys_path), "%s/%s/keys", data_dir, identity_entry->d_name);

        DIR *keys_dir = opendir(keys_path);
        if (!keys_dir) {
            continue; /* No keys directory, skip */
        }

        /* Scan for .dsa files in keys directory */
        struct dirent *key_entry;
        while ((key_entry = readdir(keys_dir)) != NULL) {
            if (is_valid_fingerprint_dsa(key_entry->d_name)) {
                /* Expand array if needed */
                if (count >= capacity) {
                    capacity *= 2;
                    char **new_fps = realloc(fingerprints, capacity * sizeof(char*));
                    if (!new_fps) {
                        for (int i = 0; i < count; i++) free(fingerprints[i]);
                        free(fingerprints);
                        closedir(keys_dir);
                        closedir(base_dir);
                        return -1;
                    }
                    fingerprints = new_fps;
                }

                /* Extract fingerprint (first 128 chars of filename) */
                fingerprints[count] = strndup(key_entry->d_name, 128);
                if (!fingerprints[count]) {
                    for (int i = 0; i < count; i++) free(fingerprints[i]);
                    free(fingerprints);
                    closedir(keys_dir);
                    closedir(base_dir);
                    return -1;
                }
                count++;
            }
        }
        closedir(keys_dir);
    }

    closedir(base_dir);

    if (count == 0) {
        free(fingerprints);
        *fingerprints_out = NULL;
        *count_out = 0;
        return 0;
    }

    *fingerprints_out = fingerprints;
    *count_out = count;
    return 0;
}

/* ============================================================================
 * IDENTITY TASK HANDLERS
 * ============================================================================ */

void dna_handle_list_identities(dna_engine_t *engine, dna_task_t *task) {
    char **fingerprints = NULL;
    int count = 0;

    int rc = dna_scan_identities(engine->data_dir, &fingerprints, &count);

    /* Prefetch and cache display names for all identities */
    if (rc == 0 && count > 0) {
        dht_context_t *dht = dna_get_dht_ctx(engine);
        if (dht) {
            pthread_mutex_lock(&engine->name_cache_mutex);

            for (int i = 0; i < count && i < DNA_NAME_CACHE_MAX; i++) {
                /* Check if already cached */
                bool found = false;
                for (int j = 0; j < engine->name_cache_count; j++) {
                    if (strcmp(engine->name_cache[j].fingerprint, fingerprints[i]) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    /* Fetch from DHT and cache */
                    char *display_name = NULL;
                    if (dna_get_display_name(dht, fingerprints[i], &display_name) == 0 && display_name) {
                        /* Only cache if it's a real name (not just shortened fingerprint) */
                        if (strlen(display_name) < 20 || strstr(display_name, "...") == NULL) {
                            if (engine->name_cache_count < DNA_NAME_CACHE_MAX) {
                                strncpy(engine->name_cache[engine->name_cache_count].fingerprint,
                                        fingerprints[i], 128);
                                strncpy(engine->name_cache[engine->name_cache_count].display_name,
                                        display_name, 63);
                                engine->name_cache_count++;
                                QGP_LOG_INFO(LOG_TAG, "Cached name: %s -> %s\n",
                                       fingerprints[i], display_name);
                            }
                        }
                        free(display_name);
                    }
                }
            }

            pthread_mutex_unlock(&engine->name_cache_mutex);
        }
    }

    int error = (rc == 0) ? DNA_OK : DNA_ENGINE_ERROR_DATABASE;
    task->callback.identities(task->request_id, error, fingerprints, count, task->user_data);

    /* Caller is responsible for freeing via dna_free_strings */
}

void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task) {
    char fingerprint_buf[129] = {0};

    int rc = messenger_generate_keys_from_seeds(
        task->params.create_identity.name,
        task->params.create_identity.signing_seed,
        task->params.create_identity.encryption_seed,
        task->params.create_identity.wallet_seed,  /* wallet_seed - DEPRECATED */
        task->params.create_identity.master_seed,  /* master_seed - for ETH/SOL wallets */
        task->params.create_identity.mnemonic,     /* mnemonic - for Cellframe wallet */
        engine->data_dir,
        task->params.create_identity.password,     /* password for key encryption */
        fingerprint_buf
    );

    int error = DNA_OK;
    char *fingerprint = NULL;
    if (rc != 0) {
        error = DNA_ERROR_CRYPTO;
    } else {
        /* Allocate on heap - caller must free via dna_free_string */
        fingerprint = strdup(fingerprint_buf);
    }

    task->callback.identity_created(
        task->request_id,
        error,
        fingerprint,
        task->user_data
    );
}

void dna_handle_load_identity(dna_engine_t *engine, dna_task_t *task) {
    const char *fingerprint = task->params.load_identity.fingerprint;
    const char *password = task->params.load_identity.password;
    int error = DNA_OK;

    /* Free existing session password if any */
    if (engine->session_password) {
        /* Secure clear before freeing */
        memset(engine->session_password, 0, strlen(engine->session_password));
        free(engine->session_password);
        engine->session_password = NULL;
    }
    engine->keys_encrypted = false;

    /* Free existing messenger context if any */
    if (engine->messenger) {
        messenger_free(engine->messenger);
        engine->messenger = NULL;
        engine->identity_loaded = false;
    }

    /* Check if keys are encrypted and validate password */
    {
        char kem_path[512];
        snprintf(kem_path, sizeof(kem_path), "%s/%s/keys/%s.kem",
                 engine->data_dir, fingerprint, fingerprint);

        bool is_encrypted = qgp_key_file_is_encrypted(kem_path);
        engine->keys_encrypted = is_encrypted;

        if (is_encrypted) {
            if (!password) {
                QGP_LOG_ERROR(LOG_TAG, "Identity keys are encrypted but no password provided");
                error = DNA_ENGINE_ERROR_PASSWORD_REQUIRED;
                goto done;
            }

            /* Verify password by attempting to load key */
            qgp_key_t *test_key = NULL;
            int load_rc = qgp_key_load_encrypted(kem_path, password, &test_key);
            if (load_rc != 0 || !test_key) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt keys - incorrect password");
                error = DNA_ENGINE_ERROR_WRONG_PASSWORD;
                goto done;
            }
            qgp_key_free(test_key);

            /* Store password for session (needed for sensitive operations) */
            engine->session_password = strdup(password);
            QGP_LOG_INFO(LOG_TAG, "Loaded password-protected identity");
        } else {
            QGP_LOG_INFO(LOG_TAG, "Loaded unprotected identity");
        }
    }

    /* Initialize messenger with fingerprint */
    engine->messenger = messenger_init(fingerprint);
    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_INIT;
        goto done;
    }

    /* Pass session password to messenger for encrypted key operations (v0.2.17+) */
    if (engine->keys_encrypted && engine->session_password) {
        messenger_set_session_password(engine->messenger, engine->session_password);
    }

    /* Copy fingerprint */
    strncpy(engine->fingerprint, fingerprint, 128);
    engine->fingerprint[128] = '\0';

    /* Load DHT identity */
    messenger_load_dht_identity(fingerprint);

    /* Initialize contacts database BEFORE P2P/offline message check
     * This is required because offline message check queries contacts' outboxes */
    if (contacts_db_init(fingerprint) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize contacts database\n");
        /* Non-fatal - continue, contacts will be initialized on first access */
    }

    /* Profile cache is now global - initialized in dna_engine_create() */

    /* Sync contacts from DHT (restore on new device)
     * This must happen BEFORE subscribing to contacts for push notifications.
     * If DHT has a newer contact list, it will be merged into local SQLite. */
    if (engine->messenger) {
        int sync_result = messenger_sync_contacts_from_dht(engine->messenger);
        if (sync_result == 0) {
            QGP_LOG_INFO(LOG_TAG, "Synced contacts from DHT");
        } else if (sync_result == -2) {
            QGP_LOG_INFO(LOG_TAG, "No contact list in DHT (new identity or first device)");
        } else {
            QGP_LOG_INFO(LOG_TAG, "Warning: Failed to sync contacts from DHT");
        }
    }

    /* Initialize P2P transport for DHT and messaging */
    if (messenger_p2p_init(engine->messenger) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize P2P transport\n");
        /* Non-fatal - continue without P2P, DHT operations will still work via singleton */
    } else {
        /* P2P initialized successfully - complete P2P setup */
        /* Note: Presence already registered in messenger_p2p_init() */

        /* 1. Check for offline messages (Spillway: query contacts' outboxes) */
        size_t offline_count = 0;
        if (messenger_p2p_check_offline_messages(engine->messenger, &offline_count) == 0) {
            if (offline_count > 0) {
                QGP_LOG_INFO(LOG_TAG, "Received %zu offline messages\n", offline_count);
            } else {
                QGP_LOG_INFO(LOG_TAG, "No offline messages found\n");
            }
        } else {
            QGP_LOG_INFO(LOG_TAG, "Warning: Failed to check offline messages\n");
        }

        /* 2. Start outbox listeners for Flutter events (DNA_EVENT_OUTBOX_UPDATED)
         * When DHT value changes, fires event -> Flutter polls + refreshes UI */
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: starting outbox listeners...");
        int listener_count = dna_engine_listen_all_contacts(engine);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: started %d listeners", listener_count);
    }

    engine->identity_loaded = true;
    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity loaded, identity_loaded flag set to true");

    /* Silent background: Create any missing blockchain wallets
     * This uses the encrypted seed stored during identity creation.
     * Non-fatal if seed doesn't exist or wallet creation fails. */
    {
        char kyber_path[512];
        snprintf(kyber_path, sizeof(kyber_path), "%s/%s/keys/%s.kem",
                 engine->data_dir, fingerprint, fingerprint);

        qgp_key_t *kem_key = NULL;
        int load_rc;
        if (engine->keys_encrypted && engine->session_password) {
            load_rc = qgp_key_load_encrypted(kyber_path, engine->session_password, &kem_key);
        } else {
            load_rc = qgp_key_load(kyber_path, &kem_key);
        }

        if (load_rc == 0 && kem_key &&
            kem_key->private_key && kem_key->private_key_size == 3168) {

            int wallets_created = 0;
            if (blockchain_create_missing_wallets(fingerprint, kem_key->private_key, &wallets_created) == 0) {
                if (wallets_created > 0) {
                    QGP_LOG_INFO(LOG_TAG, "Auto-created %d missing blockchain wallets", wallets_created);
                }
            }
            qgp_key_free(kem_key);
        }
    }

    /* Check if DHT profile exists and has wallet addresses - auto-republish if needed */
    /* Track if we already published to avoid redundant PUTs */
    bool profile_published = false;
    {
        dht_context_t *dht = dna_get_dht_ctx(engine);
        if (dht) {
            /* Lookup own profile from DHT */
            dna_unified_identity_t *identity = NULL;
            int lookup_rc = dht_keyserver_lookup(dht, fingerprint, &identity);

            if (lookup_rc != 0 || !identity) {
                /* Profile NOT found in DHT - this is the bug we're fixing!
                 * Identity was created locally but never published to DHT.
                 * Try to republish using cached name. */
                char cached_name[64] = {0};
                if (keyserver_cache_get_name(fingerprint, cached_name, sizeof(cached_name)) == 0 &&
                    cached_name[0] != '\0') {
                    QGP_LOG_WARN(LOG_TAG, "Profile not found in DHT - republishing for '%s'", cached_name);

                    /* Load keys for republishing */
                    qgp_key_t *sign_key = dna_load_private_key(engine);
                    if (sign_key) {
                        qgp_key_t *enc_key = dna_load_encryption_key(engine);
                        if (enc_key) {
                            /* Get wallet addresses for republish */
                            char cf_addr[128] = {0}, eth_addr[48] = {0}, sol_addr[48] = {0};
                            blockchain_wallet_list_t *bc_wallets = NULL;
                            if (blockchain_list_wallets(fingerprint, &bc_wallets) == 0 && bc_wallets) {
                                for (size_t i = 0; i < bc_wallets->count; i++) {
                                    blockchain_wallet_info_t *w = &bc_wallets->wallets[i];
                                    switch (w->type) {
                                        case BLOCKCHAIN_ETHEREUM:
                                            strncpy(eth_addr, w->address, sizeof(eth_addr) - 1);
                                            break;
                                        case BLOCKCHAIN_SOLANA:
                                            strncpy(sol_addr, w->address, sizeof(sol_addr) - 1);
                                            break;
                                        case BLOCKCHAIN_CELLFRAME:
                                            strncpy(cf_addr, w->address, sizeof(cf_addr) - 1);
                                            break;
                                        default:
                                            break;
                                    }
                                }
                                blockchain_wallet_list_free(bc_wallets);
                            }

                            /* Republish identity to DHT */
                            QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] load_identity: profile NOT in DHT, republishing");
                            int publish_rc = dht_keyserver_publish(dht, fingerprint, cached_name,
                                sign_key->public_key, enc_key->public_key, sign_key->private_key,
                                cf_addr[0] ? cf_addr : NULL,
                                eth_addr[0] ? eth_addr : NULL,
                                sol_addr[0] ? sol_addr : NULL);

                            if (publish_rc == 0) {
                                QGP_LOG_INFO(LOG_TAG, "Profile republished to DHT successfully");
                                profile_published = true;
                            } else if (publish_rc == -2) {
                                QGP_LOG_WARN(LOG_TAG, "Name '%s' already taken by another user", cached_name);
                            } else if (publish_rc == -3) {
                                QGP_LOG_WARN(LOG_TAG, "DHT not ready - will retry on next login");
                            } else {
                                QGP_LOG_WARN(LOG_TAG, "Failed to republish profile to DHT: %d", publish_rc);
                            }
                            qgp_key_free(enc_key);
                        }
                        qgp_key_free(sign_key);
                    }
                } else {
                    QGP_LOG_WARN(LOG_TAG, "Profile not in DHT and no cached name - cannot republish");
                }
            } else {
                /* Profile found in DHT - check if wallet addresses need updating */
                blockchain_wallet_list_t *bc_wallets = NULL;
                if (blockchain_list_wallets(fingerprint, &bc_wallets) == 0 && bc_wallets && bc_wallets->count > 0) {
                    bool need_publish = false;
                    char eth_addr[48] = {0}, sol_addr[48] = {0}, trx_addr[48] = {0}, cf_addr[128] = {0};

                    for (size_t i = 0; i < bc_wallets->count; i++) {
                        blockchain_wallet_info_t *w = &bc_wallets->wallets[i];
                        switch (w->type) {
                            case BLOCKCHAIN_ETHEREUM:
                                strncpy(eth_addr, w->address, sizeof(eth_addr) - 1);
                                if (identity->wallets.eth[0] == '\0' && w->address[0]) need_publish = true;
                                break;
                            case BLOCKCHAIN_SOLANA:
                                strncpy(sol_addr, w->address, sizeof(sol_addr) - 1);
                                if (identity->wallets.sol[0] == '\0' && w->address[0]) need_publish = true;
                                break;
                            case BLOCKCHAIN_TRON:
                                strncpy(trx_addr, w->address, sizeof(trx_addr) - 1);
                                if (identity->wallets.trx[0] == '\0' && w->address[0]) need_publish = true;
                                break;
                            case BLOCKCHAIN_CELLFRAME:
                                strncpy(cf_addr, w->address, sizeof(cf_addr) - 1);
                                if (identity->wallets.backbone[0] == '\0' && w->address[0]) need_publish = true;
                                break;
                            default:
                                break;
                        }
                    }

                    if (need_publish && !profile_published) {
                        QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] load_identity: DHT profile has empty wallet addresses");

                        /* Load keys for signing */
                        qgp_key_t *sign_key = dna_load_private_key(engine);
                        if (sign_key) {
                            qgp_key_t *enc_key = dna_load_encryption_key(engine);
                            if (enc_key) {
                                /* Build profile data with wallet addresses */
                                dna_profile_data_t profile_data = {0};
                                strncpy(profile_data.wallets.backbone, cf_addr[0] ? cf_addr : identity->wallets.backbone, sizeof(profile_data.wallets.backbone) - 1);
                                strncpy(profile_data.wallets.eth, eth_addr[0] ? eth_addr : identity->wallets.eth, sizeof(profile_data.wallets.eth) - 1);
                                strncpy(profile_data.wallets.sol, sol_addr[0] ? sol_addr : identity->wallets.sol, sizeof(profile_data.wallets.sol) - 1);
                                strncpy(profile_data.wallets.trx, trx_addr[0] ? trx_addr : identity->wallets.trx, sizeof(profile_data.wallets.trx) - 1);
                                strncpy(profile_data.socials.telegram, identity->socials.telegram, sizeof(profile_data.socials.telegram) - 1);
                                strncpy(profile_data.socials.x, identity->socials.x, sizeof(profile_data.socials.x) - 1);
                                strncpy(profile_data.socials.github, identity->socials.github, sizeof(profile_data.socials.github) - 1);
                                strncpy(profile_data.bio, identity->bio, sizeof(profile_data.bio) - 1);
                                strncpy(profile_data.avatar_base64, identity->avatar_base64, sizeof(profile_data.avatar_base64) - 1);

                                int update_rc = dna_update_profile(dht, fingerprint, &profile_data,
                                                                   sign_key->private_key, sign_key->public_key,
                                                                   enc_key->public_key);
                                if (update_rc == 0) {
                                    QGP_LOG_INFO(LOG_TAG, "Profile auto-published with wallet addresses on login");
                                    profile_published = true;
                                } else {
                                    QGP_LOG_WARN(LOG_TAG, "Failed to auto-publish profile on login: %d", update_rc);
                                }
                                qgp_key_free(enc_key);
                            }
                            qgp_key_free(sign_key);
                        }
                    }
                    blockchain_wallet_list_free(bc_wallets);
                }
                dna_identity_free(identity);
            }
        }
    }

    /* Dispatch identity loaded event */
    dna_event_t event = {0};
    event.type = DNA_EVENT_IDENTITY_LOADED;
    strncpy(event.data.identity_loaded.fingerprint, fingerprint, 128);
    dna_dispatch_event(engine, &event);

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_register_name(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_register_name(
        engine->messenger,
        engine->fingerprint,
        task->params.register_name.name
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Cache the registered name to SQLite for identity selector */
        keyserver_cache_put_name(engine->fingerprint, task->params.register_name.name, 0);
        QGP_LOG_INFO(LOG_TAG, "Name registered and cached: %.16s... -> %s\n",
               engine->fingerprint, task->params.register_name.name);
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_display_name(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    char display_name_buf[256] = {0};
    int error = DNA_OK;
    char *display_name = NULL;
    const char *fingerprint = task->params.get_display_name.fingerprint;

    /* Use profile_manager (cache first, then DHT) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fingerprint, &identity);

    if (rc == 0 && identity) {
        if (identity->display_name[0] != '\0') {
            strncpy(display_name_buf, identity->display_name, sizeof(display_name_buf) - 1);
        } else {
            /* No display name - use shortened fingerprint */
            snprintf(display_name_buf, sizeof(display_name_buf), "%.16s...", fingerprint);
        }
        dna_identity_free(identity);
    } else {
        /* Profile not found - use shortened fingerprint */
        snprintf(display_name_buf, sizeof(display_name_buf), "%.16s...", fingerprint);
    }

    /* Allocate on heap for thread-safe callback - caller frees via dna_free_string */
    display_name = strdup(display_name_buf);
    task->callback.display_name(task->request_id, error, display_name, task->user_data);
}

void dna_handle_get_avatar(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    int error = DNA_OK;
    char *avatar = NULL;
    const char *fingerprint = task->params.get_avatar.fingerprint;

    /* Use profile_manager (cache first, then DHT) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fingerprint, &identity);

    if (rc == 0 && identity) {
        if (identity->avatar_base64[0] != '\0') {
            avatar = strdup(identity->avatar_base64);
        }
        dna_identity_free(identity);
    }

    /* avatar may be NULL if no avatar set - that's OK */
    task->callback.display_name(task->request_id, error, avatar, task->user_data);
}

void dna_handle_lookup_name(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;  /* Not needed for DHT lookup */
    char fingerprint_buf[129] = {0};
    int error = DNA_OK;
    char *fingerprint = NULL;

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    char *fp_out = NULL;
    int rc = dna_lookup_by_name(dht, task->params.lookup_name.name, &fp_out);

    if (rc == 0 && fp_out) {
        /* Name is taken - return the fingerprint of who owns it */
        strncpy(fingerprint_buf, fp_out, sizeof(fingerprint_buf) - 1);
        free(fp_out);
    } else if (rc == -2) {
        /* Name not found = available, return empty string */
        fingerprint_buf[0] = '\0';
    } else {
        /* Other error */
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    /* Allocate on heap for thread-safe callback - caller frees via dna_free_string */
    fingerprint = strdup(fingerprint_buf);
    task->callback.display_name(task->request_id, error, fingerprint, task->user_data);
}

void dna_handle_get_profile(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_profile_t *profile = NULL;

    QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] dna_handle_get_profile called\n");

    if (!engine->identity_loaded || !engine->messenger) {
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile: no identity loaded\n");
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get DHT context (needed for auto-publish later if wallet changed) */
    dht_context_t *dht = dna_get_dht_ctx(engine);

    /* Get own identity (cache first, then DHT via profile_manager) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(engine->fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            /* No profile yet - create empty profile, will auto-populate wallets below */
            profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
            if (!profile) {
                error = DNA_ERROR_INTERNAL;
                goto done;
            }
            goto populate_wallets;
        } else {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }
    }

    /* Copy identity data to profile struct */
    profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
    if (!profile) {
        error = DNA_ERROR_INTERNAL;
        dna_identity_free(identity);
        goto done;
    }

    /* Wallets - copy from DHT identity */
    strncpy(profile->backbone, identity->wallets.backbone, sizeof(profile->backbone) - 1);
    strncpy(profile->btc, identity->wallets.btc, sizeof(profile->btc) - 1);
    strncpy(profile->eth, identity->wallets.eth, sizeof(profile->eth) - 1);
    strncpy(profile->sol, identity->wallets.sol, sizeof(profile->sol) - 1);
    strncpy(profile->trx, identity->wallets.trx, sizeof(profile->trx) - 1);

    /* Socials */
    strncpy(profile->telegram, identity->socials.telegram, sizeof(profile->telegram) - 1);
    strncpy(profile->twitter, identity->socials.x, sizeof(profile->twitter) - 1);
    strncpy(profile->github, identity->socials.github, sizeof(profile->github) - 1);

    /* Bio and avatar */
    strncpy(profile->bio, identity->bio, sizeof(profile->bio) - 1);
    strncpy(profile->avatar_base64, identity->avatar_base64, sizeof(profile->avatar_base64) - 1);

    /* DEBUG: Log avatar data after copy to profile (WARN level to ensure visibility) */
    {
        size_t src_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
        size_t dst_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile: src_len=%zu, dst_len=%zu (first 20: %.20s)\n",
                     src_len, dst_len, dst_len > 0 ? profile->avatar_base64 : "(empty)");
    }

    dna_identity_free(identity);

populate_wallets:
    /* Auto-populate empty wallet fields from actual wallet files */
    {
        bool wallets_changed = false;
        blockchain_wallet_list_t *bc_wallets = NULL;
        if (blockchain_list_wallets(engine->fingerprint, &bc_wallets) == 0 && bc_wallets) {
            for (size_t i = 0; i < bc_wallets->count; i++) {
                blockchain_wallet_info_t *w = &bc_wallets->wallets[i];
                switch (w->type) {
                    case BLOCKCHAIN_CELLFRAME:
                        if (profile->backbone[0] == '\0' && w->address[0]) {
                            strncpy(profile->backbone, w->address, sizeof(profile->backbone) - 1);
                            wallets_changed = true;
                        }
                        break;
                    case BLOCKCHAIN_ETHEREUM:
                        if (profile->eth[0] == '\0' && w->address[0]) {
                            strncpy(profile->eth, w->address, sizeof(profile->eth) - 1);
                            wallets_changed = true;
                        }
                        break;
                    case BLOCKCHAIN_SOLANA:
                        if (profile->sol[0] == '\0' && w->address[0]) {
                            strncpy(profile->sol, w->address, sizeof(profile->sol) - 1);
                            wallets_changed = true;
                        }
                        break;
                    case BLOCKCHAIN_TRON:
                        if (profile->trx[0] == '\0' && w->address[0]) {
                            strncpy(profile->trx, w->address, sizeof(profile->trx) - 1);
                            wallets_changed = true;
                        }
                        break;
                    default:
                        break;
                }
            }
            blockchain_wallet_list_free(bc_wallets);
        }

        /* Auto-publish profile if wallets were populated */
        if (wallets_changed) {
            QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] get_profile: wallets changed, auto-publishing");

            /* Load keys for signing */
            qgp_key_t *sign_key = dna_load_private_key(engine);
            if (sign_key) {
                qgp_key_t *enc_key = dna_load_encryption_key(engine);
                if (enc_key) {
                    /* Build profile data */
                    dna_profile_data_t profile_data = {0};
                    strncpy(profile_data.wallets.backbone, profile->backbone, sizeof(profile_data.wallets.backbone) - 1);
                    strncpy(profile_data.wallets.btc, profile->btc, sizeof(profile_data.wallets.btc) - 1);
                    strncpy(profile_data.wallets.eth, profile->eth, sizeof(profile_data.wallets.eth) - 1);
                    strncpy(profile_data.wallets.sol, profile->sol, sizeof(profile_data.wallets.sol) - 1);
                    strncpy(profile_data.wallets.trx, profile->trx, sizeof(profile_data.wallets.trx) - 1);
                    strncpy(profile_data.socials.telegram, profile->telegram, sizeof(profile_data.socials.telegram) - 1);
                    strncpy(profile_data.socials.x, profile->twitter, sizeof(profile_data.socials.x) - 1);
                    strncpy(profile_data.socials.github, profile->github, sizeof(profile_data.socials.github) - 1);
                    strncpy(profile_data.bio, profile->bio, sizeof(profile_data.bio) - 1);
                    strncpy(profile_data.avatar_base64, profile->avatar_base64, sizeof(profile_data.avatar_base64) - 1);

                    /* Update profile in DHT */
                    int update_rc = dna_update_profile(dht, engine->fingerprint, &profile_data,
                                                       sign_key->private_key, sign_key->public_key,
                                                       enc_key->public_key);
                    if (update_rc == 0) {
                        QGP_LOG_INFO(LOG_TAG, "Profile auto-published with wallet addresses");
                    } else {
                        QGP_LOG_WARN(LOG_TAG, "Failed to auto-publish profile: %d", update_rc);
                    }
                    qgp_key_free(enc_key);
                }
                qgp_key_free(sign_key);
            }
        }
    }

done:
    /* DEBUG: Log before callback */
    if (profile) {
        size_t avatar_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile CALLBACK: error=%d, avatar_len=%zu\n", error, avatar_len);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile CALLBACK: error=%d, profile=NULL\n", error);
    }
    task->callback.profile(task->request_id, error, profile, task->user_data);
}

void dna_handle_lookup_profile(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_profile_t *profile = NULL;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    const char *fingerprint = task->params.lookup_profile.fingerprint;
    if (!fingerprint || strlen(fingerprint) != 128) {
        error = DNA_ENGINE_ERROR_INVALID_PARAM;
        goto done;
    }

    /* Get identity (cache first, then DHT via profile_manager) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            /* Profile not found */
            error = DNA_ENGINE_ERROR_NOT_FOUND;
        } else if (rc == -3) {
            /* Signature verification failed - corrupted or stale DHT data
             * Auto-remove this contact since their profile is invalid */
            QGP_LOG_WARN(LOG_TAG, "Invalid signature for %.16s... - auto-removing from contacts", fingerprint);
            contacts_db_remove(fingerprint);
            error = DNA_ENGINE_ERROR_INVALID_SIGNATURE;
        } else {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
        goto done;
    }

    /* Copy identity data to profile struct */
    profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
    if (!profile) {
        error = DNA_ERROR_INTERNAL;
        dna_identity_free(identity);
        goto done;
    }

    /* Wallets */
    strncpy(profile->backbone, identity->wallets.backbone, sizeof(profile->backbone) - 1);

    /* Derive backbone address from Dilithium pubkey if not in profile */
    if (profile->backbone[0] == '\0' && identity->dilithium_pubkey[0] != 0) {
        /* Cellframe address is derived from SHA3-256 hash of serialized Dilithium pubkey
         * The pubkey in identity is raw 2592 bytes, but we need the serialized format
         * that includes length prefix (8 bytes) + kind (4 bytes) + key data.
         * For now, we build the serialized format matching wallet file structure. */
        uint8_t serialized[2604];  /* 8 + 4 + 2592 */
        uint64_t total_len = 2592 + 4;  /* key + kind */
        memcpy(serialized, &total_len, 8);  /* Little-endian length */
        uint32_t kind = 0x0102;  /* Dilithium signature type */
        memcpy(serialized + 8, &kind, 4);
        memcpy(serialized + 12, identity->dilithium_pubkey, 2592);

        char derived_addr[128] = {0};
        if (cellframe_addr_from_pubkey(serialized, sizeof(serialized),
                                       CELLFRAME_NET_BACKBONE, derived_addr) == 0) {
            strncpy(profile->backbone, derived_addr, sizeof(profile->backbone) - 1);
            QGP_LOG_INFO(LOG_TAG, "Derived backbone address from pubkey: %.20s...", derived_addr);
        }
    }

    strncpy(profile->btc, identity->wallets.btc, sizeof(profile->btc) - 1);
    strncpy(profile->eth, identity->wallets.eth, sizeof(profile->eth) - 1);
    strncpy(profile->sol, identity->wallets.sol, sizeof(profile->sol) - 1);
    strncpy(profile->trx, identity->wallets.trx, sizeof(profile->trx) - 1);

    /* Socials */
    strncpy(profile->telegram, identity->socials.telegram, sizeof(profile->telegram) - 1);
    strncpy(profile->twitter, identity->socials.x, sizeof(profile->twitter) - 1);
    strncpy(profile->github, identity->socials.github, sizeof(profile->github) - 1);

    /* Bio and avatar */
    strncpy(profile->bio, identity->bio, sizeof(profile->bio) - 1);
    strncpy(profile->avatar_base64, identity->avatar_base64, sizeof(profile->avatar_base64) - 1);

    /* DEBUG: Log avatar data after copy to profile (WARN level to ensure visibility) */
    {
        size_t src_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
        size_t dst_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] lookup_profile: src_len=%zu, dst_len=%zu (first 20: %.20s)\n",
                     src_len, dst_len, dst_len > 0 ? profile->avatar_base64 : "(empty)");
    }

    /* Display name */
    strncpy(profile->display_name, identity->display_name, sizeof(profile->display_name) - 1);

    dna_identity_free(identity);

done:
    task->callback.profile(task->request_id, error, profile, task->user_data);
}

void dna_handle_update_profile(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Load private keys for signing */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        error = DNA_ENGINE_ERROR_PERMISSION;
        goto done;
    }

    /* Load encryption key for kyber pubkey */
    qgp_key_t *enc_key = dna_load_encryption_key(engine);
    if (!enc_key) {
        error = DNA_ENGINE_ERROR_PERMISSION;
        qgp_key_free(sign_key);
        goto done;
    }

    /* Build profile data structure */
    dna_profile_data_t profile_data = {0};
    const dna_profile_t *p = &task->params.update_profile.profile;

    /* Wallets */
    strncpy(profile_data.wallets.backbone, p->backbone, sizeof(profile_data.wallets.backbone) - 1);
    strncpy(profile_data.wallets.btc, p->btc, sizeof(profile_data.wallets.btc) - 1);
    strncpy(profile_data.wallets.eth, p->eth, sizeof(profile_data.wallets.eth) - 1);
    strncpy(profile_data.wallets.sol, p->sol, sizeof(profile_data.wallets.sol) - 1);
    strncpy(profile_data.wallets.trx, p->trx, sizeof(profile_data.wallets.trx) - 1);

    /* Socials */
    strncpy(profile_data.socials.telegram, p->telegram, sizeof(profile_data.socials.telegram) - 1);
    strncpy(profile_data.socials.x, p->twitter, sizeof(profile_data.socials.x) - 1);
    strncpy(profile_data.socials.github, p->github, sizeof(profile_data.socials.github) - 1);

    /* Bio and avatar */
    strncpy(profile_data.bio, p->bio, sizeof(profile_data.bio) - 1);
    strncpy(profile_data.avatar_base64, p->avatar_base64, sizeof(profile_data.avatar_base64) - 1);

    /* DEBUG: Log avatar being saved */
    size_t src_len = p->avatar_base64[0] ? strlen(p->avatar_base64) : 0;
    size_t dst_len = profile_data.avatar_base64[0] ? strlen(profile_data.avatar_base64) : 0;
    QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] update_profile: src_len=%zu, dst_len=%zu\n", src_len, dst_len);

    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] update_profile: user-initiated save");

    /* Update profile in DHT */
    int rc = dna_update_profile(dht, engine->fingerprint, &profile_data,
                                 sign_key->private_key, sign_key->public_key,
                                 enc_key->public_key);

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Refresh profile cache with the updated profile from DHT
         * This ensures the cache has the signed profile data */
        profile_manager_refresh_profile(engine->fingerprint, NULL);
        QGP_LOG_INFO(LOG_TAG, "Profile cached after DHT update: %.16s...\n", engine->fingerprint);
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * CONTACTS TASK HANDLERS
 * ============================================================================ */

void dna_handle_get_contacts(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_contact_t *contacts = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get contact list from local database */
    contact_list_t *list = NULL;
    if (contacts_db_list(&list) != 0 || !list) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (list->count > 0) {
        contacts = calloc(list->count, sizeof(dna_contact_t));
        if (!contacts) {
            contacts_db_free_list(list);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (size_t i = 0; i < list->count; i++) {
            strncpy(contacts[i].fingerprint, list->contacts[i].identity, 128);

            /* Get display name from profile cache */
            dna_unified_identity_t *identity = NULL;
            if (profile_manager_get_profile(list->contacts[i].identity, &identity) == 0 && identity) {
                if (identity->display_name[0] != '\0') {
                    strncpy(contacts[i].display_name, identity->display_name, sizeof(contacts[i].display_name) - 1);
                } else {
                    snprintf(contacts[i].display_name, sizeof(contacts[i].display_name),
                             "%.16s...", list->contacts[i].identity);
                }
                dna_identity_free(identity);
            } else {
                snprintf(contacts[i].display_name, sizeof(contacts[i].display_name),
                         "%.16s...", list->contacts[i].identity);
            }

            /* Check presence cache for online status and last seen */
            contacts[i].is_online = presence_cache_get(list->contacts[i].identity);
            contacts[i].last_seen = (uint64_t)presence_cache_last_seen(list->contacts[i].identity);
        }
        count = (int)list->count;
    }

    contacts_db_free_list(list);

done:
    task->callback.contacts(task->request_id, error, contacts, count, task->user_data);
}

void dna_handle_add_contact(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    char fingerprint[129] = {0};

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *identifier = task->params.add_contact.identifier;

    /* Check if it's already a fingerprint (128 hex chars) */
    bool is_fingerprint = (strlen(identifier) == 128);
    if (is_fingerprint) {
        for (int i = 0; i < 128 && is_fingerprint; i++) {
            char c = identifier[i];
            is_fingerprint = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
    }

    if (is_fingerprint) {
        strncpy(fingerprint, identifier, 128);
    } else {
        /* Lookup name in DHT */
        dht_context_t *dht = dht_singleton_get();
        if (!dht) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        char *fp_out = NULL;
        if (dna_lookup_by_name(dht, identifier, &fp_out) != 0 || !fp_out) {
            error = DNA_ERROR_NOT_FOUND;
            goto done;
        }
        strncpy(fingerprint, fp_out, 128);
        free(fp_out);
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Add to local contacts database */
    int rc = contacts_db_add(fingerprint, NULL);
    if (rc == -2) {
        error = DNA_ENGINE_ERROR_ALREADY_EXISTS;
        goto done;
    } else if (rc != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Sync to DHT */
    QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] add_contact: calling sync");
    messenger_sync_contacts_to_dht(engine->messenger);

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_remove_contact(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    const char *fp = task->params.remove_contact.fingerprint;

    QGP_LOG_INFO(LOG_TAG, "REMOVE_CONTACT: Request to remove %.16s...\n", fp ? fp : "(null)");

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int db_result = contacts_db_remove(fp);
    if (db_result != 0) {
        QGP_LOG_WARN(LOG_TAG, "REMOVE_CONTACT: contacts_db_remove failed (rc=%d) for %.16s...\n", db_result, fp);
        error = DNA_ERROR_NOT_FOUND;
    } else {
        QGP_LOG_INFO(LOG_TAG, "REMOVE_CONTACT: Successfully removed %.16s... from local DB\n", fp);
    }

    /* Sync to DHT */
    if (error == DNA_OK) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] remove_contact: calling sync");
        int sync_result = messenger_sync_contacts_to_dht(engine->messenger);
        if (sync_result != 0) {
            QGP_LOG_WARN(LOG_TAG, "REMOVE_CONTACT: DHT sync failed (rc=%d) - contact may reappear on next sync!\n", sync_result);
        } else {
            QGP_LOG_INFO(LOG_TAG, "REMOVE_CONTACT: DHT sync successful\n");
        }
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * CONTACT REQUEST TASK HANDLERS (ICQ-style)
 * ============================================================================ */

void dna_handle_send_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    QGP_LOG_INFO("DNA_ENGINE", "dna_handle_send_contact_request called for recipient: %.20s...",
                 task->params.send_contact_request.recipient);

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR("DNA_ENGINE", "No identity loaded");
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Get sender keys */
    qgp_key_t *privkey = dna_load_private_key(engine);
    if (!privkey) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get our display name from cache (optional) */
    char *display_name = NULL;
    pthread_mutex_lock(&engine->name_cache_mutex);
    for (int i = 0; i < engine->name_cache_count; i++) {
        if (strcmp(engine->name_cache[i].fingerprint, engine->fingerprint) == 0) {
            display_name = engine->name_cache[i].display_name;
            break;
        }
    }
    pthread_mutex_unlock(&engine->name_cache_mutex);

    /* Send the contact request via DHT */
    int rc = dht_send_contact_request(
        dht_ctx,
        engine->fingerprint,
        display_name,
        privkey->public_key,
        privkey->private_key,
        task->params.send_contact_request.recipient,
        task->params.send_contact_request.message[0] ? task->params.send_contact_request.message : NULL
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }
    /* Contact will be added when the recipient approves and we approve their reciprocal request */

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_contact_requests(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_contact_request_t *requests = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* First, fetch new requests from DHT and store them */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    bool contacts_changed = false;  /* Track if we need to sync */
    if (dht_ctx) {
        dht_contact_request_t *dht_requests = NULL;
        size_t dht_count = 0;

        if (dht_fetch_contact_requests(dht_ctx, engine->fingerprint, &dht_requests, &dht_count) == 0) {
            /* Store new requests in local database */
            for (size_t i = 0; i < dht_count; i++) {
                /* Skip if blocked */
                if (contacts_db_is_blocked(dht_requests[i].sender_fingerprint)) {
                    continue;
                }

                /* Auto-approve reciprocal requests (they accepted our request) */
                if (dht_requests[i].message &&
                    strcmp(dht_requests[i].message, "Contact request accepted") == 0) {
                    QGP_LOG_INFO(LOG_TAG, "Auto-approving reciprocal request from %.20s...",
                                 dht_requests[i].sender_fingerprint);
                    /* Add directly as contact (notes = display name) */
                    contacts_db_add(
                        dht_requests[i].sender_fingerprint,
                        dht_requests[i].sender_name
                    );
                    contacts_changed = true;  /* Mark for sync AFTER loop */
                } else {
                    /* Regular request - add to pending */
                    contacts_db_add_incoming_request(
                        dht_requests[i].sender_fingerprint,
                        dht_requests[i].sender_name,
                        dht_requests[i].message,
                        dht_requests[i].timestamp
                    );
                }
            }
            dht_contact_requests_free(dht_requests, dht_count);
        }
    }

    /* Sync contacts to DHT ONCE after processing all requests */
    if (contacts_changed && engine->messenger) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] auto_accept_requests: syncing ONCE after loop");
        messenger_sync_contacts_to_dht(engine->messenger);
    }

    /* Get all pending requests from database */
    incoming_request_t *db_requests = NULL;
    int db_count = 0;
    if (contacts_db_get_incoming_requests(&db_requests, &db_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Convert to dna_contact_request_t */
    if (db_count > 0) {
        requests = (dna_contact_request_t*)calloc(db_count, sizeof(dna_contact_request_t));
        if (!requests) {
            contacts_db_free_requests(db_requests, db_count);
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }

        for (int i = 0; i < db_count; i++) {
            strncpy(requests[i].fingerprint, db_requests[i].fingerprint, 128);
            requests[i].fingerprint[128] = '\0';
            strncpy(requests[i].display_name, db_requests[i].display_name, 63);
            requests[i].display_name[63] = '\0';
            strncpy(requests[i].message, db_requests[i].message, 255);
            requests[i].message[255] = '\0';
            requests[i].requested_at = db_requests[i].requested_at;
            requests[i].status = db_requests[i].status;
            QGP_LOG_INFO("DNA_ENGINE", "get_requests[%d]: fp='%.40s...' len=%zu name='%s'",
                         i, requests[i].fingerprint, strlen(requests[i].fingerprint), requests[i].display_name);
        }
        count = db_count;
    }

    contacts_db_free_requests(db_requests, db_count);

done:
    if (task->callback.contact_requests) {
        if (requests && count > 0) {
            QGP_LOG_INFO("DNA_ENGINE", "callback: ptr=%p, count=%d, first_fp='%.40s...'",
                         (void*)requests, count, requests[0].fingerprint);
        }
        task->callback.contact_requests(task->request_id, error, requests, count, task->user_data);
    }
    /* NOTE: Memory is freed by caller (Dart FFI) via dna_free_contact_requests() */
}

void dna_handle_approve_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    QGP_LOG_INFO("DNA_ENGINE", "handle_approve called: task fp='%.40s...' len=%zu",
                 task->params.contact_request.fingerprint,
                 strlen(task->params.contact_request.fingerprint));

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Approve the request in database */
    QGP_LOG_INFO("DNA_ENGINE", "Calling contacts_db_approve_request with fp='%.40s...'",
                 task->params.contact_request.fingerprint);
    if (contacts_db_approve_request(task->params.contact_request.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
        goto done;
    }

    /* Send a reciprocal request so they know we approved */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx) {
        qgp_key_t *privkey = dna_load_private_key(engine);
        if (privkey) {
            /* Get our display name from cache (optional) */
            char *display_name = NULL;
            pthread_mutex_lock(&engine->name_cache_mutex);
            for (int i = 0; i < engine->name_cache_count; i++) {
                if (strcmp(engine->name_cache[i].fingerprint, engine->fingerprint) == 0) {
                    display_name = engine->name_cache[i].display_name;
                    break;
                }
            }
            pthread_mutex_unlock(&engine->name_cache_mutex);

            dht_send_contact_request(
                dht_ctx,
                engine->fingerprint,
                display_name,
                privkey->public_key,
                privkey->private_key,
                task->params.contact_request.fingerprint,
                "Contact request accepted"
            );
        }
    }

    /* Sync contacts to DHT */
    if (engine->messenger) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] accept_contact_request: calling sync");
        messenger_sync_contacts_to_dht(engine->messenger);
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_deny_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (contacts_db_deny_request(task->params.contact_request.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_block_user(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int rc = contacts_db_block_user(
        task->params.block_user.fingerprint,
        task->params.block_user.reason[0] ? task->params.block_user.reason : NULL
    );

    if (rc == -2) {
        error = DNA_ENGINE_ERROR_ALREADY_EXISTS;
    } else if (rc != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_unblock_user(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (contacts_db_unblock_user(task->params.unblock_user.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_blocked_users(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_blocked_user_t *blocked = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    blocked_user_t *db_blocked = NULL;
    int db_count = 0;
    if (contacts_db_get_blocked_users(&db_blocked, &db_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Convert to dna_blocked_user_t */
    if (db_count > 0) {
        blocked = (dna_blocked_user_t*)calloc(db_count, sizeof(dna_blocked_user_t));
        if (!blocked) {
            contacts_db_free_blocked(db_blocked, db_count);
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }

        for (int i = 0; i < db_count; i++) {
            strncpy(blocked[i].fingerprint, db_blocked[i].fingerprint, 128);
            blocked[i].fingerprint[128] = '\0';
            blocked[i].blocked_at = db_blocked[i].blocked_at;
            strncpy(blocked[i].reason, db_blocked[i].reason, 255);
            blocked[i].reason[255] = '\0';
        }
        count = db_count;
    }

    contacts_db_free_blocked(db_blocked, db_count);

done:
    if (task->callback.blocked_users) {
        task->callback.blocked_users(task->request_id, error, blocked, count, task->user_data);
    }
    /* NOTE: Memory is freed by caller (Dart FFI) via dna_free_blocked_users() */
}

/* ============================================================================
 * MESSAGING TASK HANDLERS
 * ============================================================================ */

void dna_handle_send_message(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *recipients[1] = { task->params.send_message.recipient };

    int rc = messenger_send_message(
        engine->messenger,
        recipients,
        1,
        task->params.send_message.message,
        0,  /* group_id = 0 for direct messages */
        0   /* message_type = chat */
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Emit MESSAGE_SENT event so UI can update spinner */
        dna_event_t event = {0};
        event.type = DNA_EVENT_MESSAGE_SENT;
        event.data.message_status.message_id = 0;  /* ID not available here */
        event.data.message_status.new_status = 1;  /* SENT */
        dna_dispatch_event(engine, &event);
    }

    /* Clear message queue slot if this was a queued message */
    intptr_t slot_id = (intptr_t)task->user_data;
    if (slot_id > 0) {
        pthread_mutex_lock(&engine->message_queue.mutex);
        for (int i = 0; i < engine->message_queue.capacity; i++) {
            if (engine->message_queue.entries[i].in_use &&
                engine->message_queue.entries[i].slot_id == slot_id) {
                free(engine->message_queue.entries[i].message);
                engine->message_queue.entries[i].message = NULL;
                engine->message_queue.entries[i].in_use = false;
                engine->message_queue.size--;
                break;
            }
        }
        pthread_mutex_unlock(&engine->message_queue.mutex);
    }

done:
    /* Only call callback if one was provided (not for queued messages) */
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_conversation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_message_t *messages = NULL;
    int count = 0;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    message_info_t *msg_infos = NULL;
    int msg_count = 0;

    int rc = messenger_get_conversation(
        engine->messenger,
        task->params.get_conversation.contact,
        &msg_infos,
        &msg_count
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (msg_count > 0) {
        messages = calloc(msg_count, sizeof(dna_message_t));
        if (!messages) {
            messenger_free_messages(msg_infos, msg_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < msg_count; i++) {
            messages[i].id = msg_infos[i].id;
            strncpy(messages[i].sender, msg_infos[i].sender ? msg_infos[i].sender : "", 128);
            strncpy(messages[i].recipient, msg_infos[i].recipient ? msg_infos[i].recipient : "", 128);

            /* Decrypt message */
            char *plaintext = NULL;
            size_t plaintext_len = 0;
            if (messenger_decrypt_message(engine->messenger, msg_infos[i].id, &plaintext, &plaintext_len) == 0) {
                messages[i].plaintext = plaintext;
            } else {
                messages[i].plaintext = strdup("[Decryption failed]");
            }

            /* Parse timestamp string (format: YYYY-MM-DD HH:MM:SS) */
            if (msg_infos[i].timestamp) {
                struct tm tm = {0};
                if (strptime(msg_infos[i].timestamp, "%Y-%m-%d %H:%M:%S", &tm) != NULL) {
                    messages[i].timestamp = (uint64_t)mktime(&tm);
                } else {
                    messages[i].timestamp = (uint64_t)time(NULL);
                }
            } else {
                messages[i].timestamp = (uint64_t)time(NULL);
            }

            /* Determine if outgoing */
            messages[i].is_outgoing = (msg_infos[i].sender &&
                strcmp(msg_infos[i].sender, engine->fingerprint) == 0);

            /* Map status string to int: 0=pending, 1=sent, 2=failed, 3=delivered, 4=read */
            if (msg_infos[i].status) {
                if (strcmp(msg_infos[i].status, "read") == 0) {
                    messages[i].status = 4;
                } else if (strcmp(msg_infos[i].status, "delivered") == 0) {
                    messages[i].status = 3;
                } else if (strcmp(msg_infos[i].status, "failed") == 0) {
                    messages[i].status = 2;
                } else if (strcmp(msg_infos[i].status, "sent") == 0) {
                    messages[i].status = 1;
                } else if (strcmp(msg_infos[i].status, "pending") == 0) {
                    messages[i].status = 0;
                } else {
                    messages[i].status = 1;  /* default to sent for old messages */
                }
            } else {
                messages[i].status = 1;  /* default to sent if no status */
            }

            messages[i].message_type = msg_infos[i].message_type;
        }
        count = msg_count;

        messenger_free_messages(msg_infos, msg_count);
    }

done:
    task->callback.messages(task->request_id, error, messages, count, task->user_data);
}

void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Check DHT offline queue for messages from contacts */
    size_t offline_count = 0;
    int rc = messenger_p2p_check_offline_messages(engine->messenger, &offline_count);
    if (rc == 0 && offline_count > 0) {
        QGP_LOG_INFO("DNA_ENGINE", "Retrieved %zu offline messages from DHT\n", offline_count);
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * GROUPS TASK HANDLERS
 * ============================================================================ */

void dna_handle_get_groups(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_group_t *groups = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get groups from local cache via DHT groups API */
    dht_group_cache_entry_t *entries = NULL;
    int entry_count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (entry_count > 0) {
        groups = calloc(entry_count, sizeof(dna_group_t));
        if (!groups) {
            dht_groups_free_cache_entries(entries, entry_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < entry_count; i++) {
            strncpy(groups[i].uuid, entries[i].group_uuid, 36);
            strncpy(groups[i].name, entries[i].name, sizeof(groups[i].name) - 1);
            strncpy(groups[i].creator, entries[i].creator, 128);
            groups[i].member_count = 0; /* Cache doesn't store member count */
            groups[i].created_at = entries[i].created_at;
        }
        count = entry_count;

        dht_groups_free_cache_entries(entries, entry_count);
    }

done:
    task->callback.groups(task->request_id, error, groups, count, task->user_data);
}

void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    char group_uuid[37] = {0};

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int group_id = 0;
    int rc = messenger_create_group(
        engine->messenger,
        task->params.create_group.name,
        NULL, /* description */
        (const char**)task->params.create_group.members,
        task->params.create_group.member_count,
        &group_id
    );

    if (rc != 0) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Get UUID from group ID - simplified, actual impl would query database */
    snprintf(group_uuid, sizeof(group_uuid), "%08x-0000-0000-0000-000000000000", group_id);

done:
    task->callback.group_created(task->request_id, error,
                                  (error == DNA_OK) ? group_uuid : NULL,
                                  task->user_data);
}

void dna_handle_send_group_message(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_send_group_message(
        engine->messenger,
        task->params.send_group_message.group_uuid,
        task->params.send_group_message.message
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_invitations(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_invitation_t *invitations = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize invitations database for this identity */
    if (group_invitations_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    group_invitation_t *entries = NULL;
    int entry_count = 0;
    if (group_invitations_get_pending(&entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (entry_count > 0) {
        invitations = calloc(entry_count, sizeof(dna_invitation_t));
        if (!invitations) {
            group_invitations_free(entries, entry_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < entry_count; i++) {
            strncpy(invitations[i].group_uuid, entries[i].group_uuid, 36);
            strncpy(invitations[i].group_name, entries[i].group_name, sizeof(invitations[i].group_name) - 1);
            strncpy(invitations[i].inviter, entries[i].inviter, 128);
            invitations[i].member_count = entries[i].member_count;
            invitations[i].invited_at = (uint64_t)entries[i].invited_at;
        }
        count = entry_count;

        group_invitations_free(entries, entry_count);
    }

done:
    task->callback.invitations(task->request_id, error, invitations, count, task->user_data);
}

void dna_handle_accept_invitation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_accept_group_invitation(
        engine->messenger,
        task->params.invitation.group_uuid
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_reject_invitation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_reject_group_invitation(
        engine->messenger,
        task->params.invitation.group_uuid
    );

    if (rc != 0) {
        error = DNA_ERROR_INTERNAL;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * WALLET TASK HANDLERS
 * ============================================================================ */

void dna_handle_list_wallets(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_wallet_t *wallets = NULL;
    int count = 0;

    /* Free existing blockchain wallet list */
    if (engine->blockchain_wallets) {
        blockchain_wallet_list_free(engine->blockchain_wallets);
        engine->blockchain_wallets = NULL;
    }

    /* Try to load wallets from wallet files first */
    int rc = blockchain_list_wallets(engine->fingerprint, &engine->blockchain_wallets);

    /* If no wallet files found, derive wallets on-demand from mnemonic */
    if (rc == 0 && engine->blockchain_wallets && engine->blockchain_wallets->count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No wallet files found, deriving wallets on-demand from mnemonic");

        /* Free the empty list */
        blockchain_wallet_list_free(engine->blockchain_wallets);
        engine->blockchain_wallets = NULL;

        /* Load and decrypt mnemonic */
        char mnemonic[512] = {0};
        if (dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic)) != DNA_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get mnemonic for wallet derivation");
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        /* Convert mnemonic to 64-byte master seed */
        uint8_t master_seed[64];
        if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive master seed from mnemonic");
            memset(mnemonic, 0, sizeof(mnemonic));
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        /* Derive wallet addresses from master seed and mnemonic
         * Note: Cellframe needs the mnemonic (SHA3-256 hash), ETH/SOL/TRX use master seed
         */
        rc = blockchain_derive_wallets_from_seed(master_seed, mnemonic, engine->fingerprint, &engine->blockchain_wallets);

        /* Clear sensitive data from memory */
        memset(mnemonic, 0, sizeof(mnemonic));
        memset(master_seed, 0, sizeof(master_seed));

        if (rc != 0 || !engine->blockchain_wallets) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive wallets from seed");
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }
    } else if (rc != 0 || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    blockchain_wallet_list_t *list = engine->blockchain_wallets;
    if (list->count > 0) {
        wallets = calloc(list->count, sizeof(dna_wallet_t));
        if (!wallets) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (size_t i = 0; i < list->count; i++) {
            strncpy(wallets[i].name, list->wallets[i].name, sizeof(wallets[i].name) - 1);
            strncpy(wallets[i].address, list->wallets[i].address, sizeof(wallets[i].address) - 1);
            /* Map blockchain type to sig_type for UI display */
            if (list->wallets[i].type == BLOCKCHAIN_ETHEREUM) {
                wallets[i].sig_type = 100;  /* Use 100 for ETH (secp256k1) */
            } else if (list->wallets[i].type == BLOCKCHAIN_SOLANA) {
                wallets[i].sig_type = 101;  /* Use 101 for SOL (Ed25519) */
            } else if (list->wallets[i].type == BLOCKCHAIN_TRON) {
                wallets[i].sig_type = 102;  /* Use 102 for TRX (secp256k1) */
            } else {
                wallets[i].sig_type = 4;    /* Dilithium for Cellframe */
            }
            wallets[i].is_protected = list->wallets[i].is_encrypted;
        }
        count = (int)list->count;
    }

    engine->wallets_loaded = true;

done:
    task->callback.wallets(task->request_id, error, wallets, count, task->user_data);
}

void dna_handle_get_balances(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_balance_t *balances = NULL;
    int count = 0;

    if (!engine->wallets_loaded || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    blockchain_wallet_list_t *list = engine->blockchain_wallets;
    int idx = task->params.get_balances.wallet_index;

    if (idx < 0 || idx >= (int)list->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    blockchain_wallet_info_t *wallet_info = &list->wallets[idx];

    /* Handle non-Cellframe blockchains via modular interface */
    if (wallet_info->type == BLOCKCHAIN_ETHEREUM) {
        /* Ethereum: ETH + USDT (ERC-20) */
        balances = calloc(2, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 2;

        /* Native ETH balance */
        strncpy(balances[0].token, "ETH", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Ethereum", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (ERC-20) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Ethereum", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0.0");

        char usdt_balance[64] = {0};
        if (eth_erc20_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        goto done;
    }

    if (wallet_info->type == BLOCKCHAIN_TRON) {
        /* TRON: TRX + USDT (TRC-20) */
        balances = calloc(2, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 2;

        /* Native TRX balance */
        strncpy(balances[0].token, "TRX", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Tron", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (TRC-20) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Tron", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0.0");

        char usdt_balance[64] = {0};
        if (trx_trc20_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        goto done;
    }

    if (wallet_info->type == BLOCKCHAIN_SOLANA) {
        /* Solana: SOL + USDT (SPL) */
        balances = calloc(2, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 2;

        /* Native SOL balance */
        strncpy(balances[0].token, "SOL", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Solana", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (SPL) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Solana", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0");

        char usdt_balance[64] = {0};
        if (sol_spl_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        goto done;
    }

    /* Cellframe wallet - existing logic */
    char address[120] = {0};
    strncpy(address, wallet_info->address, sizeof(address) - 1);

    /* Pre-allocate balances for CF20 tokens: CPUNK, CELL, NYS, KEL, QEVM */
    balances = calloc(5, sizeof(dna_balance_t));
    if (!balances) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Initialize with defaults */
    strncpy(balances[0].token, "CPUNK", sizeof(balances[0].token) - 1);
    strncpy(balances[0].network, "Backbone", sizeof(balances[0].network) - 1);
    strcpy(balances[0].balance, "0.0");

    strncpy(balances[1].token, "CELL", sizeof(balances[1].token) - 1);
    strncpy(balances[1].network, "Backbone", sizeof(balances[1].network) - 1);
    strcpy(balances[1].balance, "0.0");

    strncpy(balances[2].token, "NYS", sizeof(balances[2].token) - 1);
    strncpy(balances[2].network, "Backbone", sizeof(balances[2].network) - 1);
    strcpy(balances[2].balance, "0.0");

    strncpy(balances[3].token, "KEL", sizeof(balances[3].token) - 1);
    strncpy(balances[3].network, "Backbone", sizeof(balances[3].network) - 1);
    strcpy(balances[3].balance, "0.0");

    strncpy(balances[4].token, "QEVM", sizeof(balances[4].token) - 1);
    strncpy(balances[4].network, "Backbone", sizeof(balances[4].network) - 1);
    strcpy(balances[4].balance, "0.0");

    count = 5;

    /* Query balance via RPC - response contains all tokens for address */
    cellframe_rpc_response_t *response = NULL;
    int rc = cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response);

    if (rc == 0 && response && response->result) {
        json_object *jresult = response->result;

        /* Parse response format: result[0][0]["tokens"][i] */
        if (json_object_is_type(jresult, json_type_array) &&
            json_object_array_length(jresult) > 0) {

            json_object *first = json_object_array_get_idx(jresult, 0);
            if (first && json_object_is_type(first, json_type_array) &&
                json_object_array_length(first) > 0) {

                json_object *wallet_obj = json_object_array_get_idx(first, 0);
                json_object *tokens_obj = NULL;

                if (wallet_obj && json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                    int token_count = json_object_array_length(tokens_obj);

                    for (int i = 0; i < token_count; i++) {
                        json_object *token_entry = json_object_array_get_idx(tokens_obj, i);
                        json_object *token_info_obj = NULL;
                        json_object *coins_obj = NULL;

                        if (!json_object_object_get_ex(token_entry, "coins", &coins_obj)) {
                            continue;
                        }

                        if (!json_object_object_get_ex(token_entry, "token", &token_info_obj)) {
                            continue;
                        }

                        json_object *ticker_obj = NULL;
                        if (json_object_object_get_ex(token_info_obj, "ticker", &ticker_obj)) {
                            const char *ticker = json_object_get_string(ticker_obj);
                            const char *coins = json_object_get_string(coins_obj);

                            /* Match ticker to our balance slots */
                            if (ticker && coins) {
                                if (strcmp(ticker, "CPUNK") == 0) {
                                    strncpy(balances[0].balance, coins, sizeof(balances[0].balance) - 1);
                                } else if (strcmp(ticker, "CELL") == 0) {
                                    strncpy(balances[1].balance, coins, sizeof(balances[1].balance) - 1);
                                } else if (strcmp(ticker, "NYS") == 0) {
                                    strncpy(balances[2].balance, coins, sizeof(balances[2].balance) - 1);
                                } else if (strcmp(ticker, "KEL") == 0) {
                                    strncpy(balances[3].balance, coins, sizeof(balances[3].balance) - 1);
                                } else if (strcmp(ticker, "QEVM") == 0) {
                                    strncpy(balances[4].balance, coins, sizeof(balances[4].balance) - 1);
                                }
                            }
                        }
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    }

done:
    task->callback.balances(task->request_id, error, balances, count, task->user_data);
}

void dna_handle_send_tokens(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->wallets_loaded || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* Get task parameters */
    int wallet_index = task->params.send_tokens.wallet_index;
    const char *recipient = task->params.send_tokens.recipient;
    const char *amount_str = task->params.send_tokens.amount;
    const char *token = task->params.send_tokens.token;
    const char *network = task->params.send_tokens.network;
    int gas_speed = task->params.send_tokens.gas_speed;

    /* Determine blockchain type from network parameter */
    blockchain_type_t bc_type;
    const char *chain_name;
    if (strcmp(network, "Ethereum") == 0) {
        bc_type = BLOCKCHAIN_ETHEREUM;
        chain_name = "Ethereum";
    } else if (strcmp(network, "Solana") == 0) {
        bc_type = BLOCKCHAIN_SOLANA;
        chain_name = "Solana";
    } else if (strcasecmp(network, "Tron") == 0) {
        bc_type = BLOCKCHAIN_TRON;
        chain_name = "TRON";
    } else {
        /* Default: Backbone = Cellframe */
        bc_type = BLOCKCHAIN_CELLFRAME;
        chain_name = "Cellframe";
    }

    /* Find wallet for this blockchain type */
    blockchain_wallet_list_t *bc_wallets = engine->blockchain_wallets;
    blockchain_wallet_info_t *bc_wallet_info = NULL;
    for (size_t i = 0; i < bc_wallets->count; i++) {
        if (bc_wallets->wallets[i].type == bc_type) {
            bc_wallet_info = &bc_wallets->wallets[i];
            break;
        }
    }

    if (!bc_wallet_info) {
        QGP_LOG_ERROR(LOG_TAG, "No wallet found for network: %s", network);
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    (void)wallet_index; /* wallet_index no longer used - network determines wallet */

    char tx_hash[128] = {0};

    QGP_LOG_INFO(LOG_TAG, "Sending %s: %s %s to %s (gas_speed=%d)",
                 chain_name, amount_str, token ? token : "(native)", recipient, gas_speed);

    /* Check if wallet has a file (legacy) or needs on-demand derivation */
    if (bc_wallet_info->file_path[0] != '\0') {
        /* Legacy: use wallet file */
        if (blockchain_send_tokens(
                bc_type,
                bc_wallet_info->file_path,
                recipient,
                amount_str,
                token,
                gas_speed,
                tx_hash) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed (wallet file)", chain_name);
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }
    } else {
        /* On-demand derivation: derive wallet from mnemonic */
        QGP_LOG_INFO(LOG_TAG, "Using on-demand wallet derivation for %s", chain_name);

        /* Load and decrypt mnemonic */
        char mnemonic[512] = {0};
        if (dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic)) != DNA_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get mnemonic for send operation");
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        /* Convert mnemonic to 64-byte master seed */
        uint8_t master_seed[64];
        if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive master seed from mnemonic");
            memset(mnemonic, 0, sizeof(mnemonic));
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        /* Send using on-demand derived wallet
         * Note: mnemonic is passed for Cellframe (which uses SHA3-256 hash of mnemonic)
         * It will be cleared after this call completes */
        int send_rc = blockchain_send_tokens_with_seed(
            bc_type,
            master_seed,
            mnemonic,  /* For Cellframe - uses SHA3-256(mnemonic) instead of BIP39 seed */
            recipient,
            amount_str,
            token,
            gas_speed,
            tx_hash
        );

        /* Clear sensitive data from memory */
        memset(mnemonic, 0, sizeof(mnemonic));
        memset(master_seed, 0, sizeof(master_seed));

        if (send_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed (on-demand)", chain_name);
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "%s tx sent: %s", chain_name, tx_hash);
    error = DNA_OK;

done:
    task->callback.send_tokens(task->request_id, error,
                               error == DNA_OK ? tx_hash : NULL,
                               task->user_data);
}

/* Network fee collector address for filtering transactions */
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"

void dna_handle_get_transactions(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_transaction_t *transactions = NULL;
    int count = 0;
    cellframe_rpc_response_t *resp = NULL;

    if (!engine->wallets_loaded || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* Get wallet address */
    int wallet_index = task->params.get_transactions.wallet_index;
    const char *network = task->params.get_transactions.network;

    blockchain_wallet_list_t *wallets = engine->blockchain_wallets;
    if (wallet_index < 0 || wallet_index >= (int)wallets->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    blockchain_wallet_info_t *wallet_info = &wallets->wallets[wallet_index];

    if (wallet_info->address[0] == '\0') {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* ETH transactions via Etherscan API */
    if (wallet_info->type == BLOCKCHAIN_ETHEREUM) {
        eth_transaction_t *eth_txs = NULL;
        int eth_count = 0;

        if (eth_rpc_get_transactions(wallet_info->address, &eth_txs, &eth_count) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        if (eth_count > 0 && eth_txs) {
            transactions = calloc(eth_count, sizeof(dna_transaction_t));
            if (!transactions) {
                eth_rpc_free_transactions(eth_txs, eth_count);
                error = DNA_ERROR_INTERNAL;
                goto done;
            }

            for (int i = 0; i < eth_count; i++) {
                strncpy(transactions[i].tx_hash, eth_txs[i].tx_hash,
                        sizeof(transactions[i].tx_hash) - 1);
                strncpy(transactions[i].token, "ETH", sizeof(transactions[i].token) - 1);
                strncpy(transactions[i].amount, eth_txs[i].value,
                        sizeof(transactions[i].amount) - 1);
                snprintf(transactions[i].timestamp, sizeof(transactions[i].timestamp),
                        "%llu", (unsigned long long)eth_txs[i].timestamp);

                if (eth_txs[i].is_outgoing) {
                    strncpy(transactions[i].direction, "sent",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, eth_txs[i].to,
                            sizeof(transactions[i].other_address) - 1);
                } else {
                    strncpy(transactions[i].direction, "received",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, eth_txs[i].from,
                            sizeof(transactions[i].other_address) - 1);
                }

                strncpy(transactions[i].status,
                        eth_txs[i].is_confirmed ? "CONFIRMED" : "FAILED",
                        sizeof(transactions[i].status) - 1);
            }
            count = eth_count;
            eth_rpc_free_transactions(eth_txs, eth_count);
        }
        goto done;
    }

    /* TRON transactions via TronGrid API */
    if (wallet_info->type == BLOCKCHAIN_TRON) {
        trx_transaction_t *trx_txs = NULL;
        int trx_count = 0;

        if (trx_rpc_get_transactions(wallet_info->address, &trx_txs, &trx_count) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        if (trx_count > 0 && trx_txs) {
            transactions = calloc(trx_count, sizeof(dna_transaction_t));
            if (!transactions) {
                trx_rpc_free_transactions(trx_txs, trx_count);
                error = DNA_ERROR_INTERNAL;
                goto done;
            }

            for (int i = 0; i < trx_count; i++) {
                strncpy(transactions[i].tx_hash, trx_txs[i].tx_hash,
                        sizeof(transactions[i].tx_hash) - 1);
                strncpy(transactions[i].token, "TRX", sizeof(transactions[i].token) - 1);
                strncpy(transactions[i].amount, trx_txs[i].value,
                        sizeof(transactions[i].amount) - 1);
                snprintf(transactions[i].timestamp, sizeof(transactions[i].timestamp),
                        "%llu", (unsigned long long)(trx_txs[i].timestamp / 1000)); /* ms to sec */

                if (trx_txs[i].is_outgoing) {
                    strncpy(transactions[i].direction, "sent",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, trx_txs[i].to,
                            sizeof(transactions[i].other_address) - 1);
                } else {
                    strncpy(transactions[i].direction, "received",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, trx_txs[i].from,
                            sizeof(transactions[i].other_address) - 1);
                }

                strncpy(transactions[i].status,
                        trx_txs[i].is_confirmed ? "CONFIRMED" : "PENDING",
                        sizeof(transactions[i].status) - 1);
            }
            count = trx_count;
            trx_rpc_free_transactions(trx_txs, trx_count);
        }
        goto done;
    }

    /* Solana transactions via Solana RPC */
    if (wallet_info->type == BLOCKCHAIN_SOLANA) {
        sol_transaction_t *sol_txs = NULL;
        int sol_count = 0;

        if (sol_rpc_get_transactions(wallet_info->address, &sol_txs, &sol_count) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        if (sol_count > 0 && sol_txs) {
            transactions = calloc(sol_count, sizeof(dna_transaction_t));
            if (!transactions) {
                sol_rpc_free_transactions(sol_txs, sol_count);
                error = DNA_ERROR_INTERNAL;
                goto done;
            }

            for (int i = 0; i < sol_count; i++) {
                strncpy(transactions[i].tx_hash, sol_txs[i].signature,
                        sizeof(transactions[i].tx_hash) - 1);
                strncpy(transactions[i].token, "SOL", sizeof(transactions[i].token) - 1);

                /* Convert lamports to SOL */
                if (sol_txs[i].lamports > 0) {
                    double sol_amount = (double)sol_txs[i].lamports / 1000000000.0;
                    snprintf(transactions[i].amount, sizeof(transactions[i].amount),
                            "%.9f", sol_amount);
                    /* Trim trailing zeros */
                    char *dot = strchr(transactions[i].amount, '.');
                    if (dot) {
                        char *end = transactions[i].amount + strlen(transactions[i].amount) - 1;
                        while (end > dot && *end == '0') {
                            *end-- = '\0';
                        }
                        if (end == dot) {
                            strcpy(dot, ".0");
                        }
                    }
                } else {
                    strncpy(transactions[i].amount, "0", sizeof(transactions[i].amount) - 1);
                }

                snprintf(transactions[i].timestamp, sizeof(transactions[i].timestamp),
                        "%lld", (long long)sol_txs[i].block_time);

                /* Set direction and other address */
                if (sol_txs[i].is_outgoing) {
                    strncpy(transactions[i].direction, "sent",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, sol_txs[i].to,
                            sizeof(transactions[i].other_address) - 1);
                } else {
                    strncpy(transactions[i].direction, "received",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, sol_txs[i].from,
                            sizeof(transactions[i].other_address) - 1);
                }

                strncpy(transactions[i].status,
                        sol_txs[i].success ? "CONFIRMED" : "FAILED",
                        sizeof(transactions[i].status) - 1);
            }
            count = sol_count;
            sol_rpc_free_transactions(sol_txs, sol_count);
        }
        goto done;
    }

    /* Query transaction history from RPC (Cellframe) */
    if (cellframe_rpc_get_tx_history(network, wallet_info->address, &resp) != 0 || !resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to query tx history from RPC\n");
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    if (!resp->result) {
        /* No transactions - return empty list */
        goto done;
    }

    /* Parse response: result[0] = {addr, limit}, result[1..n] = transactions */
    if (!json_object_is_type(resp->result, json_type_array)) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* First element is array with addr/limit, skip it */
    /* Count actual transaction objects (starting from index 1) */
    int array_len = json_object_array_length(resp->result);
    if (array_len <= 1) {
        /* Only header, no transactions */
        goto done;
    }

    /* First array element contains addr and limit objects */
    json_object *first_elem = json_object_array_get_idx(resp->result, 0);
    if (!first_elem || !json_object_is_type(first_elem, json_type_array)) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Get transactions array - it's inside first_elem starting at index 2 */
    int tx_array_len = json_object_array_length(first_elem);
    int tx_count = tx_array_len - 2;  /* Skip addr and limit objects */

    if (tx_count <= 0) {
        goto done;
    }

    /* Allocate transactions array */
    transactions = calloc(tx_count, sizeof(dna_transaction_t));
    if (!transactions) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Parse each transaction */
    for (int i = 0; i < tx_count; i++) {
        json_object *tx_obj = json_object_array_get_idx(first_elem, i + 2);
        if (!tx_obj) continue;

        json_object *jhash = NULL, *jstatus = NULL, *jtx_created = NULL, *jdata = NULL;

        json_object_object_get_ex(tx_obj, "hash", &jhash);
        json_object_object_get_ex(tx_obj, "status", &jstatus);
        json_object_object_get_ex(tx_obj, "tx_created", &jtx_created);
        json_object_object_get_ex(tx_obj, "data", &jdata);

        /* Copy hash */
        if (jhash) {
            strncpy(transactions[count].tx_hash, json_object_get_string(jhash),
                    sizeof(transactions[count].tx_hash) - 1);
        }

        /* Copy status */
        if (jstatus) {
            strncpy(transactions[count].status, json_object_get_string(jstatus),
                    sizeof(transactions[count].status) - 1);
        }

        /* Copy timestamp */
        if (jtx_created) {
            strncpy(transactions[count].timestamp, json_object_get_string(jtx_created),
                    sizeof(transactions[count].timestamp) - 1);
        }

        /* Parse data - can be array (old format) or object (new format) */
        if (jdata) {
            json_object *jtx_type = NULL, *jtoken = NULL;
            json_object *jrecv_coins = NULL, *jsend_coins = NULL;
            json_object *jsrc_addr = NULL, *jdst_addr = NULL;
            json_object *jaddr_from = NULL, *jaddrs_to = NULL;

            if (json_object_is_type(jdata, json_type_array)) {
                /* Old format: data is array, use first item */
                if (json_object_array_length(jdata) > 0) {
                    json_object *data_item = json_object_array_get_idx(jdata, 0);
                    if (data_item) {
                        json_object_object_get_ex(data_item, "tx_type", &jtx_type);
                        json_object_object_get_ex(data_item, "token", &jtoken);
                        json_object_object_get_ex(data_item, "recv_coins", &jrecv_coins);
                        json_object_object_get_ex(data_item, "send_coins", &jsend_coins);
                        json_object_object_get_ex(data_item, "source_address", &jsrc_addr);
                        json_object_object_get_ex(data_item, "destination_address", &jdst_addr);
                    }
                }
            } else if (json_object_is_type(jdata, json_type_object)) {
                /* New format: data is object with address_from, addresses_to */
                json_object_object_get_ex(jdata, "ticker", &jtoken);
                json_object_object_get_ex(jdata, "address_from", &jaddr_from);
                json_object_object_get_ex(jdata, "addresses_to", &jaddrs_to);
            }

            /* Determine direction and parse addresses */
            if (jtx_type) {
                /* Old format with tx_type */
                const char *tx_type = json_object_get_string(jtx_type);
                if (strcmp(tx_type, "recv") == 0) {
                    strncpy(transactions[count].direction, "received",
                            sizeof(transactions[count].direction) - 1);
                    if (jrecv_coins) {
                        strncpy(transactions[count].amount, json_object_get_string(jrecv_coins),
                                sizeof(transactions[count].amount) - 1);
                    }
                    if (jsrc_addr) {
                        strncpy(transactions[count].other_address, json_object_get_string(jsrc_addr),
                                sizeof(transactions[count].other_address) - 1);
                    }
                } else if (strcmp(tx_type, "send") == 0) {
                    strncpy(transactions[count].direction, "sent",
                            sizeof(transactions[count].direction) - 1);
                    if (jsend_coins) {
                        strncpy(transactions[count].amount, json_object_get_string(jsend_coins),
                                sizeof(transactions[count].amount) - 1);
                    }
                    /* For destination, skip network fee collector address */
                    if (jdst_addr) {
                        const char *dst = json_object_get_string(jdst_addr);
                        if (dst && strcmp(dst, NETWORK_FEE_COLLECTOR) != 0 &&
                            strstr(dst, "DAP_CHAIN") == NULL) {
                            strncpy(transactions[count].other_address, dst,
                                    sizeof(transactions[count].other_address) - 1);
                        }
                    }
                }
            } else if (jaddr_from && jaddrs_to) {
                /* New format: determine direction by comparing wallet address */
                const char *from_addr = json_object_get_string(jaddr_from);

                /* Check if we sent this (our address is sender) */
                if (from_addr && strcmp(from_addr, wallet_info->address) == 0) {
                    strncpy(transactions[count].direction, "sent",
                            sizeof(transactions[count].direction) - 1);

                    /* Find recipient (first non-fee address in addresses_to) */
                    if (json_object_is_type(jaddrs_to, json_type_array)) {
                        int addrs_len = json_object_array_length(jaddrs_to);
                        for (int k = 0; k < addrs_len; k++) {
                            json_object *addr_entry = json_object_array_get_idx(jaddrs_to, k);
                            if (!addr_entry) continue;

                            json_object *jaddr = NULL, *jval = NULL;
                            json_object_object_get_ex(addr_entry, "address", &jaddr);
                            json_object_object_get_ex(addr_entry, "value", &jval);

                            if (jaddr) {
                                const char *addr = json_object_get_string(jaddr);
                                /* Skip fee collector and change addresses (back to sender) */
                                if (addr && strcmp(addr, NETWORK_FEE_COLLECTOR) != 0 &&
                                    strcmp(addr, from_addr) != 0) {
                                    strncpy(transactions[count].other_address, addr,
                                            sizeof(transactions[count].other_address) - 1);
                                    if (jval) {
                                        strncpy(transactions[count].amount, json_object_get_string(jval),
                                                sizeof(transactions[count].amount) - 1);
                                    }
                                    break;  /* Use first valid recipient */
                                }
                            }
                        }
                    }
                } else {
                    /* We received this */
                    strncpy(transactions[count].direction, "received",
                            sizeof(transactions[count].direction) - 1);
                    if (from_addr) {
                        strncpy(transactions[count].other_address, from_addr,
                                sizeof(transactions[count].other_address) - 1);
                    }

                    /* Find amount sent to us */
                    if (json_object_is_type(jaddrs_to, json_type_array)) {
                        int addrs_len = json_object_array_length(jaddrs_to);
                        for (int k = 0; k < addrs_len; k++) {
                            json_object *addr_entry = json_object_array_get_idx(jaddrs_to, k);
                            if (!addr_entry) continue;

                            json_object *jaddr = NULL, *jval = NULL;
                            json_object_object_get_ex(addr_entry, "address", &jaddr);
                            json_object_object_get_ex(addr_entry, "value", &jval);

                            if (jaddr) {
                                const char *addr = json_object_get_string(jaddr);
                                if (addr && strcmp(addr, wallet_info->address) == 0 && jval) {
                                    strncpy(transactions[count].amount, json_object_get_string(jval),
                                            sizeof(transactions[count].amount) - 1);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (jtoken) {
                strncpy(transactions[count].token, json_object_get_string(jtoken),
                        sizeof(transactions[count].token) - 1);
            }
        }

        count++;
    }

done:
    if (resp) cellframe_rpc_response_free(resp);
    task->callback.transactions(task->request_id, error, transactions, count, task->user_data);
}

/* ============================================================================
 * PUBLIC API FUNCTIONS
 * ============================================================================ */

/* Identity */
dna_request_id_t dna_engine_list_identities(
    dna_engine_t *engine,
    dna_identities_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .identities = callback };
    return dna_submit_task(engine, TASK_LIST_IDENTITIES, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t *wallet_seed,
    dna_identity_created_cb callback,
    void *user_data
) {
    if (!engine || !name || !signing_seed || !encryption_seed || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.create_identity.name, name, sizeof(params.create_identity.name) - 1);
    memcpy(params.create_identity.signing_seed, signing_seed, 32);
    memcpy(params.create_identity.encryption_seed, encryption_seed, 32);
    if (wallet_seed) {
        params.create_identity.wallet_seed = malloc(32);
        if (params.create_identity.wallet_seed) {
            memcpy(params.create_identity.wallet_seed, wallet_seed, 32);
        }
    }

    dna_task_callback_t cb = { .identity_created = callback };
    return dna_submit_task(engine, TASK_CREATE_IDENTITY, &params, cb, user_data);
}

int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t wallet_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
) {
    if (!engine || !name || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Step 1: Create keys locally */
    int rc = messenger_generate_keys_from_seeds(name, signing_seed, encryption_seed,
                                                 wallet_seed, master_seed, mnemonic,
                                                 engine->data_dir, NULL, fingerprint_out);
    if (rc != 0) {
        return DNA_ERROR_CRYPTO;
    }

    /* Step 2: Create temporary messenger context for registration */
    messenger_context_t *temp_ctx = messenger_init(fingerprint_out);
    if (!temp_ctx) {
        /* Cleanup: delete created identity directory */
        char identity_dir[512];
        snprintf(identity_dir, sizeof(identity_dir), "%s/%s", engine->data_dir, fingerprint_out);
        qgp_platform_rmdir_recursive(identity_dir);
        QGP_LOG_ERROR(LOG_TAG, "Failed to create messenger context for identity registration");
        return DNA_ERROR_INTERNAL;
    }

    /* Step 3: Load DHT identity for signing */
    messenger_load_dht_identity(fingerprint_out);

    /* Step 4: Register name on DHT (atomic - if this fails, cleanup) */
    rc = messenger_register_name(temp_ctx, fingerprint_out, name);
    messenger_free(temp_ctx);

    if (rc != 0) {
        /* Cleanup: delete created identity directory */
        char identity_dir[512];
        snprintf(identity_dir, sizeof(identity_dir), "%s/%s", engine->data_dir, fingerprint_out);
        qgp_platform_rmdir_recursive(identity_dir);
        QGP_LOG_ERROR(LOG_TAG, "Name registration failed for '%s', identity rolled back", name);
        return DNA_ENGINE_ERROR_NETWORK;
    }

    /* Step 5: Cache the registered name locally */
    keyserver_cache_put_name(fingerprint_out, name, 0);
    QGP_LOG_INFO(LOG_TAG, "Identity created and registered: %s -> %.16s...", name, fingerprint_out);

    return DNA_OK;
}

int dna_engine_restore_identity_sync(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t wallet_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
) {
    if (!engine || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Step 1: Create keys locally (uses fingerprint as directory name) */
    int rc = messenger_generate_keys_from_seeds(NULL, signing_seed, encryption_seed,
                                                 wallet_seed, master_seed, mnemonic,
                                                 engine->data_dir, NULL, fingerprint_out);
    if (rc != 0) {
        return DNA_ERROR_CRYPTO;
    }

    /* Step 2: Load DHT identity for later operations */
    messenger_load_dht_identity(fingerprint_out);

    QGP_LOG_INFO(LOG_TAG, "Identity restored from seed: %.16s...", fingerprint_out);

    return DNA_OK;
}

int dna_engine_delete_identity_sync(
    dna_engine_t *engine,
    const char *fingerprint
) {
    if (!engine || !fingerprint) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Validate fingerprint format (128 hex chars) */
    size_t fp_len = strlen(fingerprint);
    if (fp_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length: %zu (expected 128)", fp_len);
        return DNA_ERROR_INVALID_ARG;
    }

    /* Check that fingerprint contains only hex characters */
    for (size_t i = 0; i < fp_len; i++) {
        char c = fingerprint[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid character in fingerprint at position %zu", i);
            return DNA_ERROR_INVALID_ARG;
        }
    }

    /* If deleting the currently loaded identity, unload it first */
    if (engine->identity_loaded && engine->fingerprint[0] != '\0' &&
        strcmp(engine->fingerprint, fingerprint) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Unloading current identity before deletion");

        /* Free messenger context */
        if (engine->messenger) {
            messenger_free(engine->messenger);
            engine->messenger = NULL;
        }

        /* Clear identity state */
        engine->identity_loaded = false;
        memset(engine->fingerprint, 0, sizeof(engine->fingerprint));
    }

    const char *data_dir = engine->data_dir;
    int errors = 0;

    QGP_LOG_INFO(LOG_TAG, "Deleting identity: %.16s...", fingerprint);

    /* 1. Delete identity directory: <data_dir>/<fingerprint>/ */
    char *identity_dir = qgp_platform_join_path(data_dir, fingerprint);
    if (identity_dir) {
        if (qgp_platform_file_exists(identity_dir)) {
            if (qgp_platform_rmdir_recursive(identity_dir) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to delete identity directory: %s", identity_dir);
                errors++;
            } else {
                QGP_LOG_DEBUG(LOG_TAG, "Deleted identity directory: %s", identity_dir);
            }
        }
        free(identity_dir);
    }

    /* 2. Delete contacts database: <data_dir>/<fingerprint>_contacts.db */
    char contacts_db[512];
    snprintf(contacts_db, sizeof(contacts_db), "%s/%s_contacts.db", data_dir, fingerprint);
    if (qgp_platform_file_exists(contacts_db)) {
        if (remove(contacts_db) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete contacts database: %s", contacts_db);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted contacts database: %s", contacts_db);
        }
    }

    /* 3. Delete profiles cache: <data_dir>/<fingerprint>_profiles.db */
    char profiles_db[512];
    snprintf(profiles_db, sizeof(profiles_db), "%s/%s_profiles.db", data_dir, fingerprint);
    if (qgp_platform_file_exists(profiles_db)) {
        if (remove(profiles_db) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete profiles cache: %s", profiles_db);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted profiles cache: %s", profiles_db);
        }
    }

    /* 4. Delete groups database: <data_dir>/<fingerprint>_groups.db */
    char groups_db[512];
    snprintf(groups_db, sizeof(groups_db), "%s/%s_groups.db", data_dir, fingerprint);
    if (qgp_platform_file_exists(groups_db)) {
        if (remove(groups_db) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete groups database: %s", groups_db);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted groups database: %s", groups_db);
        }
    }

    if (errors > 0) {
        QGP_LOG_WARN(LOG_TAG, "Identity deletion completed with %d errors", errors);
        return DNA_ERROR_INTERNAL;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity deleted successfully: %.16s...", fingerprint);
    return DNA_OK;
}

dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.load_identity.fingerprint, fingerprint, 128);
    params.load_identity.password = password ? strdup(password) : NULL;

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_LOAD_IDENTITY, &params, cb, user_data);
}

dna_request_id_t dna_engine_register_name(
    dna_engine_t *engine,
    const char *name,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.register_name.name, name, sizeof(params.register_name.name) - 1);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REGISTER_NAME, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_display_name(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_display_name.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_DISPLAY_NAME, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_avatar(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,  /* Reuses display_name callback (returns string) */
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_avatar.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_AVATAR, &params, cb, user_data);
}

dna_request_id_t dna_engine_lookup_name(
    dna_engine_t *engine,
    const char *name,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.lookup_name.name, name, sizeof(params.lookup_name.name) - 1);

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_LOOKUP_NAME, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_profile(
    dna_engine_t *engine,
    dna_profile_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .profile = callback };
    return dna_submit_task(engine, TASK_GET_PROFILE, NULL, cb, user_data);
}

dna_request_id_t dna_engine_lookup_profile(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_profile_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded) return DNA_REQUEST_ID_INVALID;
    if (strlen(fingerprint) != 128) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.lookup_profile.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .profile = callback };
    return dna_submit_task(engine, TASK_LOOKUP_PROFILE, &params, cb, user_data);
}

dna_request_id_t dna_engine_update_profile(
    dna_engine_t *engine,
    const dna_profile_t *profile,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !profile || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.update_profile.profile = *profile;

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_UPDATE_PROFILE, &params, cb, user_data);
}

int dna_engine_get_mnemonic(
    dna_engine_t *engine,
    char *mnemonic_out,
    size_t mnemonic_size
) {
    if (!engine || !mnemonic_out || mnemonic_size < 256) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }
    if (!engine->identity_loaded) {
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Build paths to identity directory and Kyber private key */
    char identity_dir[512];
    char kyber_path[512];
    snprintf(identity_dir, sizeof(identity_dir), "%s/%s",
             engine->data_dir, engine->fingerprint);
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/%s.kem",
             identity_dir, engine->fingerprint);

    /* Check if mnemonic file exists */
    if (!mnemonic_storage_exists(identity_dir)) {
        QGP_LOG_DEBUG(LOG_TAG, "Mnemonic file not found for identity %s",
                      engine->fingerprint);
        return DNA_ENGINE_ERROR_NOT_FOUND;
    }

    /* Load Kyber private key (use password if keys are encrypted) */
    qgp_key_t *kem_key = NULL;
    int load_rc;
    if (engine->keys_encrypted && engine->session_password) {
        load_rc = qgp_key_load_encrypted(kyber_path, engine->session_password, &kem_key);
    } else {
        load_rc = qgp_key_load(kyber_path, &kem_key);
    }
    if (load_rc != 0 || !kem_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber private key");
        return DNA_ERROR_CRYPTO;
    }

    if (!kem_key->private_key || kem_key->private_key_size != 3168) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber private key size");
        qgp_key_free(kem_key);
        return DNA_ERROR_CRYPTO;
    }

    /* Decrypt and load mnemonic */
    int result = mnemonic_storage_load(mnemonic_out, mnemonic_size,
                                       kem_key->private_key, identity_dir);

    qgp_key_free(kem_key);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt mnemonic");
        return DNA_ERROR_CRYPTO;
    }

    QGP_LOG_INFO(LOG_TAG, "Mnemonic retrieved successfully");
    return DNA_OK;
}

int dna_engine_change_password_sync(
    dna_engine_t *engine,
    const char *old_password,
    const char *new_password
) {
    if (!engine) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }
    if (!engine->identity_loaded) {
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Build paths to key files */
    char dsa_path[512];
    char kem_path[512];
    char mnemonic_path[512];

    snprintf(dsa_path, sizeof(dsa_path), "%s/%s/keys/%s.dsa",
             engine->data_dir, engine->fingerprint, engine->fingerprint);
    snprintf(kem_path, sizeof(kem_path), "%s/%s/keys/%s.kem",
             engine->data_dir, engine->fingerprint, engine->fingerprint);
    snprintf(mnemonic_path, sizeof(mnemonic_path), "%s/%s/mnemonic.enc",
             engine->data_dir, engine->fingerprint);

    /* Verify old password is correct by trying to load a key */
    if (engine->keys_encrypted || old_password) {
        if (key_verify_password(dsa_path, old_password) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Old password is incorrect");
            return DNA_ENGINE_ERROR_WRONG_PASSWORD;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Changing password for identity %s", engine->fingerprint);

    /* Change password on DSA key */
    if (key_change_password(dsa_path, old_password, new_password) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to change password on DSA key");
        return DNA_ERROR_CRYPTO;
    }

    /* Change password on KEM key */
    if (key_change_password(kem_path, old_password, new_password) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to change password on KEM key");
        /* Try to rollback DSA key */
        key_change_password(dsa_path, new_password, old_password);
        return DNA_ERROR_CRYPTO;
    }

    /* Change password on mnemonic file if it exists */
    if (qgp_platform_file_exists(mnemonic_path)) {
        if (key_change_password(mnemonic_path, old_password, new_password) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to change password on mnemonic file");
            /* Try to rollback DSA and KEM keys */
            key_change_password(dsa_path, new_password, old_password);
            key_change_password(kem_path, new_password, old_password);
            return DNA_ERROR_CRYPTO;
        }
    }

    /* Update session password and encryption state */
    if (engine->session_password) {
        free(engine->session_password);
        engine->session_password = NULL;
    }

    if (new_password && new_password[0] != '\0') {
        engine->session_password = strdup(new_password);
        engine->keys_encrypted = true;
    } else {
        engine->keys_encrypted = false;
    }

    QGP_LOG_INFO(LOG_TAG, "Password changed successfully for identity %s", engine->fingerprint);
    return DNA_OK;
}

/* Contacts */
dna_request_id_t dna_engine_get_contacts(
    dna_engine_t *engine,
    dna_contacts_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .contacts = callback };
    return dna_submit_task(engine, TASK_GET_CONTACTS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_add_contact(
    dna_engine_t *engine,
    const char *identifier,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !identifier || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.add_contact.identifier, identifier, sizeof(params.add_contact.identifier) - 1);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_ADD_CONTACT, &params, cb, user_data);
}

dna_request_id_t dna_engine_remove_contact(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.remove_contact.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REMOVE_CONTACT, &params, cb, user_data);
}

/* Contact Requests (ICQ-style) */
dna_request_id_t dna_engine_send_contact_request(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,
    dna_completion_cb callback,
    void *user_data
) {
    QGP_LOG_INFO("DNA_ENGINE", "dna_engine_send_contact_request called: recipient=%.20s...",
                 recipient_fingerprint ? recipient_fingerprint : "(null)");

    if (!engine || !recipient_fingerprint || !callback) {
        QGP_LOG_ERROR("DNA_ENGINE", "Invalid params: engine=%p, recipient=%p, callback=%p",
                      (void*)engine, (void*)recipient_fingerprint, (void*)callback);
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.send_contact_request.recipient, recipient_fingerprint, 128);
    if (message) {
        strncpy(params.send_contact_request.message, message, 255);
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_CONTACT_REQUEST, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_contact_requests(
    dna_engine_t *engine,
    dna_contact_requests_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .contact_requests = callback };
    return dna_submit_task(engine, TASK_GET_CONTACT_REQUESTS, NULL, cb, user_data);
}

int dna_engine_get_contact_request_count(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) return -1;

    if (contacts_db_init(engine->fingerprint) != 0) {
        return -1;
    }

    return contacts_db_pending_request_count();
}

dna_request_id_t dna_engine_approve_contact_request(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    QGP_LOG_INFO("DNA_ENGINE", "approve_contact_request API called: fp='%.40s...' len=%zu",
                 fingerprint ? fingerprint : "(null)",
                 fingerprint ? strlen(fingerprint) : 0);

    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.contact_request.fingerprint, fingerprint, 128);
    QGP_LOG_INFO("DNA_ENGINE", "approve params.fingerprint='%.40s...'",
                 params.contact_request.fingerprint);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_APPROVE_CONTACT_REQUEST, &params, cb, user_data);
}

dna_request_id_t dna_engine_deny_contact_request(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.contact_request.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_DENY_CONTACT_REQUEST, &params, cb, user_data);
}

dna_request_id_t dna_engine_block_user(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *reason,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.block_user.fingerprint, fingerprint, 128);
    if (reason) {
        strncpy(params.block_user.reason, reason, 255);
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_BLOCK_USER, &params, cb, user_data);
}

dna_request_id_t dna_engine_unblock_user(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.unblock_user.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_UNBLOCK_USER, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_blocked_users(
    dna_engine_t *engine,
    dna_blocked_users_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .blocked_users = callback };
    return dna_submit_task(engine, TASK_GET_BLOCKED_USERS, NULL, cb, user_data);
}

bool dna_engine_is_user_blocked(dna_engine_t *engine, const char *fingerprint) {
    if (!engine || !fingerprint || !engine->identity_loaded) return false;

    if (contacts_db_init(engine->fingerprint) != 0) {
        return false;
    }

    return contacts_db_is_blocked(fingerprint);
}

/* Messaging */
dna_request_id_t dna_engine_send_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !recipient_fingerprint || !message || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.send_message.recipient, recipient_fingerprint, 128);
    params.send_message.message = strdup(message);
    if (!params.send_message.message) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_MESSAGE, &params, cb, user_data);
}

int dna_engine_queue_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message
) {
    if (!engine || !recipient_fingerprint || !message) {
        return -2; /* Invalid args */
    }
    if (!engine->identity_loaded) {
        return -2; /* No identity loaded */
    }

    pthread_mutex_lock(&engine->message_queue.mutex);

    /* Check if queue is full */
    if (engine->message_queue.size >= engine->message_queue.capacity) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -1; /* Queue full */
    }

    /* Find empty slot */
    int slot_index = -1;
    for (int i = 0; i < engine->message_queue.capacity; i++) {
        if (!engine->message_queue.entries[i].in_use) {
            slot_index = i;
            break;
        }
    }

    if (slot_index < 0) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -1; /* No slot available */
    }

    /* Fill the slot */
    dna_message_queue_entry_t *entry = &engine->message_queue.entries[slot_index];
    strncpy(entry->recipient, recipient_fingerprint, 128);
    entry->recipient[128] = '\0';
    entry->message = strdup(message);
    if (!entry->message) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -2; /* Memory error */
    }
    entry->slot_id = engine->message_queue.next_slot_id++;
    entry->in_use = true;
    engine->message_queue.size++;

    int slot_id = entry->slot_id;
    pthread_mutex_unlock(&engine->message_queue.mutex);

    /* Submit task to worker queue (fire-and-forget, no callback) */
    dna_task_params_t params = {0};
    strncpy(params.send_message.recipient, recipient_fingerprint, 128);
    params.send_message.message = strdup(message);
    if (params.send_message.message) {
        dna_task_callback_t cb = { .completion = NULL };
        dna_submit_task(engine, TASK_SEND_MESSAGE, &params, cb, (void*)(intptr_t)slot_id);
    }

    return slot_id;
}

int dna_engine_get_message_queue_capacity(dna_engine_t *engine) {
    if (!engine) return 0;
    return engine->message_queue.capacity;
}

int dna_engine_get_message_queue_size(dna_engine_t *engine) {
    if (!engine) return 0;

    pthread_mutex_lock(&engine->message_queue.mutex);
    int size = engine->message_queue.size;
    pthread_mutex_unlock(&engine->message_queue.mutex);

    return size;
}

int dna_engine_set_message_queue_capacity(dna_engine_t *engine, int capacity) {
    if (!engine || capacity < 1 || capacity > DNA_MESSAGE_QUEUE_MAX_CAPACITY) {
        return -1;
    }

    pthread_mutex_lock(&engine->message_queue.mutex);

    /* Can't shrink below current size */
    if (capacity < engine->message_queue.size) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -1;
    }

    /* Reallocate if needed */
    if (capacity != engine->message_queue.capacity) {
        dna_message_queue_entry_t *new_entries = realloc(
            engine->message_queue.entries,
            capacity * sizeof(dna_message_queue_entry_t)
        );
        if (!new_entries) {
            pthread_mutex_unlock(&engine->message_queue.mutex);
            return -1;
        }
        /* Initialize new slots */
        for (int i = engine->message_queue.capacity; i < capacity; i++) {
            memset(&new_entries[i], 0, sizeof(dna_message_queue_entry_t));
        }
        engine->message_queue.entries = new_entries;
        engine->message_queue.capacity = capacity;
    }

    pthread_mutex_unlock(&engine->message_queue.mutex);
    return 0;
}

dna_request_id_t dna_engine_get_conversation(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_messages_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_conversation.contact, contact_fingerprint, 128);

    dna_task_callback_t cb = { .messages = callback };
    return dna_submit_task(engine, TASK_GET_CONVERSATION, &params, cb, user_data);
}

dna_request_id_t dna_engine_check_offline_messages(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_CHECK_OFFLINE_MESSAGES, NULL, cb, user_data);
}

int dna_engine_get_unread_count(
    dna_engine_t *engine,
    const char *contact_fingerprint
) {
    if (!engine || !contact_fingerprint) return -1;
    if (!engine->messenger) return -1;

    return messenger_get_unread_count(engine->messenger, contact_fingerprint);
}

dna_request_id_t dna_engine_mark_conversation_read(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    /* Mark as read synchronously since it's a fast local DB operation */
    int result = -1;
    if (engine->messenger) {
        result = messenger_mark_conversation_read(engine->messenger, contact_fingerprint);
    }

    /* Call callback immediately with result (0=success, negative=error) */
    callback(1, result == 0 ? 0 : -1, user_data);
    return 1; /* Return valid request ID */
}

/* Groups */
dna_request_id_t dna_engine_get_groups(
    dna_engine_t *engine,
    dna_groups_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .groups = callback };
    return dna_submit_task(engine, TASK_GET_GROUPS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_group(
    dna_engine_t *engine,
    const char *name,
    const char **member_fingerprints,
    int member_count,
    dna_group_created_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;
    if (member_count > 0 && !member_fingerprints) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_group.name, name, sizeof(params.create_group.name) - 1);
    params.create_group.member_count = member_count;

    if (member_count > 0) {
        params.create_group.members = calloc(member_count, sizeof(char*));
        if (!params.create_group.members) {
            return DNA_REQUEST_ID_INVALID;
        }
        for (int i = 0; i < member_count; i++) {
            params.create_group.members[i] = strdup(member_fingerprints[i]);
            if (!params.create_group.members[i]) {
                for (int j = 0; j < i; j++) {
                    free(params.create_group.members[j]);
                }
                free(params.create_group.members);
                return DNA_REQUEST_ID_INVALID;
            }
        }
    }

    dna_task_callback_t cb = { .group_created = callback };
    return dna_submit_task(engine, TASK_CREATE_GROUP, &params, cb, user_data);
}

dna_request_id_t dna_engine_send_group_message(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *message,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !message || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.send_group_message.group_uuid, group_uuid, 36);
    params.send_group_message.message = strdup(message);
    if (!params.send_group_message.message) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_GROUP_MESSAGE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_invitations(
    dna_engine_t *engine,
    dna_invitations_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .invitations = callback };
    return dna_submit_task(engine, TASK_GET_INVITATIONS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_accept_invitation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.invitation.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_ACCEPT_INVITATION, &params, cb, user_data);
}

dna_request_id_t dna_engine_reject_invitation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.invitation.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REJECT_INVITATION, &params, cb, user_data);
}

/* Wallet */
dna_request_id_t dna_engine_list_wallets(
    dna_engine_t *engine,
    dna_wallets_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .wallets = callback };
    return dna_submit_task(engine, TASK_LIST_WALLETS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
) {
    if (!engine || !callback || wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.get_balances.wallet_index = wallet_index;

    dna_task_callback_t cb = { .balances = callback };
    return dna_submit_task(engine, TASK_GET_BALANCES, &params, cb, user_data);
}

int dna_engine_estimate_eth_gas(int gas_speed, dna_gas_estimate_t *estimate_out) {
    if (!estimate_out) return -1;
    if (gas_speed < 0 || gas_speed > 2) gas_speed = 1;

    blockchain_gas_estimate_t bc_estimate;
    if (blockchain_estimate_eth_gas(gas_speed, &bc_estimate) != 0) {
        return -1;
    }

    /* Copy to public struct */
    strncpy(estimate_out->fee_eth, bc_estimate.fee_eth, sizeof(estimate_out->fee_eth) - 1);
    estimate_out->gas_price = bc_estimate.gas_price;
    estimate_out->gas_limit = bc_estimate.gas_limit;

    return 0;
}

dna_request_id_t dna_engine_send_tokens(
    dna_engine_t *engine,
    int wallet_index,
    const char *recipient_address,
    const char *amount,
    const char *token,
    const char *network,
    int gas_speed,
    dna_send_tokens_cb callback,
    void *user_data
) {
    QGP_LOG_INFO(LOG_TAG, "send_tokens: wallet=%d to=%s amount=%s token=%s network=%s gas=%d",
            wallet_index, recipient_address ? recipient_address : "NULL",
            amount ? amount : "NULL", token ? token : "NULL",
            network ? network : "NULL", gas_speed);

    if (!engine || !recipient_address || !amount || !token || !network || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "send_tokens: invalid params");
        return DNA_REQUEST_ID_INVALID;
    }
    if (wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.send_tokens.wallet_index = wallet_index;
    strncpy(params.send_tokens.recipient, recipient_address, sizeof(params.send_tokens.recipient) - 1);
    strncpy(params.send_tokens.amount, amount, sizeof(params.send_tokens.amount) - 1);
    strncpy(params.send_tokens.token, token, sizeof(params.send_tokens.token) - 1);
    strncpy(params.send_tokens.network, network, sizeof(params.send_tokens.network) - 1);
    params.send_tokens.gas_speed = gas_speed;

    dna_task_callback_t cb = { .send_tokens = callback };
    return dna_submit_task(engine, TASK_SEND_TOKENS, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_transactions(
    dna_engine_t *engine,
    int wallet_index,
    const char *network,
    dna_transactions_cb callback,
    void *user_data
) {
    if (!engine || !network || !callback || wallet_index < 0) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    params.get_transactions.wallet_index = wallet_index;
    strncpy(params.get_transactions.network, network, sizeof(params.get_transactions.network) - 1);

    dna_task_callback_t cb = { .transactions = callback };
    return dna_submit_task(engine, TASK_GET_TRANSACTIONS, &params, cb, user_data);
}

/* ============================================================================
 * P2P & PRESENCE PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_refresh_presence(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REFRESH_PRESENCE, NULL, cb, user_data);
}

bool dna_engine_is_peer_online(dna_engine_t *engine, const char *fingerprint) {
    if (!engine || !fingerprint || !engine->messenger) {
        return false;
    }

    return messenger_p2p_peer_online(engine->messenger, fingerprint);
}

int dna_engine_request_turn_credentials(dna_engine_t *engine, int timeout_ms) {
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or no identity loaded");
        return -1;
    }

    if (timeout_ms <= 0) {
        timeout_ms = 10000;  // Default 10 seconds
    }

    // Get data directory
    const char *data_dir = engine->data_dir;
    if (!data_dir) {
        data_dir = qgp_platform_app_data_dir();
    }
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }

    // Build path to signing key
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s/keys/%s.dsa",
             data_dir, engine->fingerprint, engine->fingerprint);

    // Load signing key (handle encrypted keys)
    qgp_key_t *sign_key = NULL;
    int load_rc;
    if (engine->keys_encrypted && engine->session_password) {
        load_rc = qgp_key_load_encrypted(key_path, engine->session_password, &sign_key);
    } else {
        load_rc = qgp_key_load(key_path, &sign_key);
    }

    if (load_rc != 0 || !sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key: %s", key_path);
        return -1;
    }

    if (!sign_key->public_key || !sign_key->private_key) {
        QGP_LOG_ERROR(LOG_TAG, "Signing key missing public or private component");
        qgp_key_free(sign_key);
        return -1;
    }

    // Initialize TURN credential system
    turn_credentials_init();

    // Request credentials
    turn_credentials_t creds;
    memset(&creds, 0, sizeof(creds));

    QGP_LOG_INFO(LOG_TAG, "Requesting TURN credentials (timeout: %dms)...", timeout_ms);

    int result = turn_credentials_request(
        engine->fingerprint,
        sign_key->public_key,
        sign_key->private_key,
        &creds,
        timeout_ms
    );

    qgp_key_free(sign_key);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to obtain TURN credentials");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully obtained TURN credentials (%zu servers)", creds.server_count);
    return 0;
}

dna_request_id_t dna_engine_lookup_presence(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_presence_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.lookup_presence.fingerprint, sizeof(params.lookup_presence.fingerprint),
             "%s", fingerprint);

    dna_task_callback_t cb = { .presence = callback };
    return dna_submit_task(engine, TASK_LOOKUP_PRESENCE, &params, cb, user_data);
}

dna_request_id_t dna_engine_sync_contacts_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_CONTACTS_TO_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_contacts_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_CONTACTS_FROM_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_groups(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUPS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_registered_name(
    dna_engine_t *engine,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_REGISTERED_NAME, NULL, cb, user_data);
}

/* ============================================================================
 * OUTBOX LISTENERS (Real-time offline message notifications)
 * ============================================================================ */

/**
 * Context passed to DHT listen callback
 */
typedef struct {
    dna_engine_t *engine;
    char contact_fingerprint[129];
} outbox_listener_ctx_t;

/**
 * DHT listen callback - fires DNA_EVENT_OUTBOX_UPDATED when contact's outbox changes
 *
 * Called from DHT worker thread when:
 * - New value published to contact's outbox
 * - Existing value updated (content changed + seq incremented)
 * - Value expired/removed
 */
static bool outbox_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] >>> CALLBACK FIRED! value=%p, len=%zu, expired=%d",
                 (void*)value, value_len, expired);

    outbox_listener_ctx_t *ctx = (outbox_listener_ctx_t *)user_data;
    if (!ctx || !ctx->engine) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN-CB] Invalid context, stopping listener");
        return false;  /* Stop listening */
    }

    QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Contact: %.32s...", ctx->contact_fingerprint);

    /* Only fire event for new/updated values, not expirations */
    if (!expired && value && value_len > 0) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] ✓ NEW VALUE! Firing DNA_EVENT_OUTBOX_UPDATED");

        /* Fire DNA_EVENT_OUTBOX_UPDATED event */
        dna_event_t event = {0};
        event.type = DNA_EVENT_OUTBOX_UPDATED;
        strncpy(event.data.outbox_updated.contact_fingerprint,
                ctx->contact_fingerprint,
                sizeof(event.data.outbox_updated.contact_fingerprint) - 1);

        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Dispatching event to Flutter...");
        dna_dispatch_event(ctx->engine, &event);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Event dispatched successfully");
    } else if (expired) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Value expired (ignoring)");
    } else {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Empty value received (ignoring)");
    }

    return true;  /* Continue listening */
}

size_t dna_engine_listen_outbox(
    dna_engine_t *engine,
    const char *contact_fingerprint)
{
    size_t fp_len = contact_fingerprint ? strlen(contact_fingerprint) : 0;

    if (!engine || !contact_fingerprint || fp_len < 64) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Invalid params: engine=%p, fp=%p, fp_len=%zu",
                      (void*)engine, (void*)contact_fingerprint, fp_len);
        return 0;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Cannot listen: identity not loaded");
        return 0;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Cannot listen: DHT context is NULL");
        return 0;
    }

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Setting up listener for %.32s... (len=%zu)",
                 contact_fingerprint, fp_len);

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    /* Check if already listening to this contact */
    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            strcmp(engine->outbox_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Already listening (existing token=%zu)",
                         engine->outbox_listeners[i].dht_token);
            pthread_mutex_unlock(&engine->outbox_listeners_mutex);
            return engine->outbox_listeners[i].dht_token;
        }
    }

    /* Check capacity */
    if (engine->outbox_listener_count >= DNA_MAX_OUTBOX_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Max listeners reached (%d)", DNA_MAX_OUTBOX_LISTENERS);
        pthread_mutex_unlock(&engine->outbox_listeners_mutex);
        return 0;
    }

    /* Generate chunk[0] key for contact's outbox to me.
     * Chunked storage uses: SHA3-512(base_key + ":chunk:0")[0:32]
     * Base key format: contact_fp + ":outbox:" + my_fp */
    char base_key[512];
    snprintf(base_key, sizeof(base_key), "%s:outbox:%s",
             contact_fingerprint, engine->fingerprint);

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] base_key=%s", base_key);

    uint8_t chunk0_key[DHT_CHUNK_KEY_SIZE];  /* 32 bytes */
    if (dht_chunked_make_key(base_key, 0, chunk0_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to generate chunk key");
        pthread_mutex_unlock(&engine->outbox_listeners_mutex);
        return 0;
    }

    /* Create callback context (will be freed when listener is cancelled) */
    outbox_listener_ctx_t *ctx = malloc(sizeof(outbox_listener_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to allocate context");
        pthread_mutex_unlock(&engine->outbox_listeners_mutex);
        return 0;
    }
    ctx->engine = engine;
    strncpy(ctx->contact_fingerprint, contact_fingerprint, sizeof(ctx->contact_fingerprint) - 1);
    ctx->contact_fingerprint[sizeof(ctx->contact_fingerprint) - 1] = '\0';

    /* Start DHT listen on chunk[0] key */
    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Calling dht_listen()...");
    size_t token = dht_listen(dht_ctx, chunk0_key, DHT_CHUNK_KEY_SIZE, outbox_listen_callback, ctx);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] dht_listen() returned 0 (failed)");
        free(ctx);
        pthread_mutex_unlock(&engine->outbox_listeners_mutex);
        return 0;
    }

    /* Store listener info */
    int idx = engine->outbox_listener_count++;
    strncpy(engine->outbox_listeners[idx].contact_fingerprint, contact_fingerprint,
            sizeof(engine->outbox_listeners[idx].contact_fingerprint) - 1);
    engine->outbox_listeners[idx].contact_fingerprint[
        sizeof(engine->outbox_listeners[idx].contact_fingerprint) - 1] = '\0';
    engine->outbox_listeners[idx].dht_token = token;
    engine->outbox_listeners[idx].active = true;

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] ✓ DHT listener active: token=%zu, total_listeners=%d",
                 token, engine->outbox_listener_count);

    pthread_mutex_unlock(&engine->outbox_listeners_mutex);
    return token;
}

void dna_engine_cancel_outbox_listener(
    dna_engine_t *engine,
    const char *contact_fingerprint)
{
    if (!engine || !contact_fingerprint) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            strcmp(engine->outbox_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {

            /* Cancel DHT listener */
            if (dht_ctx) {
                dht_cancel_listen(dht_ctx, engine->outbox_listeners[i].dht_token);
            }

            QGP_LOG_INFO(LOG_TAG, "Cancelled outbox listener for %s... (token=%zu)",
                         contact_fingerprint, engine->outbox_listeners[i].dht_token);

            /* Mark as inactive (compact later) */
            engine->outbox_listeners[i].active = false;

            /* Compact array by moving last element here */
            if (i < engine->outbox_listener_count - 1) {
                engine->outbox_listeners[i] = engine->outbox_listeners[engine->outbox_listener_count - 1];
            }
            engine->outbox_listener_count--;
            break;
        }
    }

    pthread_mutex_unlock(&engine->outbox_listeners_mutex);
}

int dna_engine_listen_all_contacts(dna_engine_t *engine)
{
    QGP_LOG_WARN(LOG_TAG, "[LISTEN] dna_engine_listen_all_contacts() called");

    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] engine is NULL");
        return 0;
    }
    if (!engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] identity not loaded yet");
        return 0;
    }

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] identity=%s", engine->fingerprint);

    /* Initialize contacts database for current identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to initialize contacts database");
        return 0;
    }

    /* Get all contacts */
    contact_list_t *list = NULL;
    int db_result = contacts_db_list(&list);
    if (db_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] contacts_db_list failed: %d", db_result);
        if (list) contacts_db_free_list(list);
        return 0;
    }
    if (!list || list->count == 0) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] No contacts in database (count=%zu)", list ? list->count : 0);
        if (list) contacts_db_free_list(list);
        return 0;
    }

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Found %zu contacts in database", list->count);

    /* Start listener for each contact */
    int started = 0;
    size_t count = list->count;
    for (size_t i = 0; i < count; i++) {
        const char *contact_id = list->contacts[i].identity;
        size_t id_len = contact_id ? strlen(contact_id) : 0;
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Contact[%zu]: %.32s... (len=%zu)",
                     i, contact_id ? contact_id : "(null)", id_len);

        size_t token = dna_engine_listen_outbox(engine, contact_id);
        if (token > 0) {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] ✓ Listener started for contact[%zu], token=%zu", i, token);
            started++;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "[LISTEN] ✗ Failed to start listener for contact[%zu]", i);
        }
    }

    /* Cleanup */
    contacts_db_free_list(list);

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] RESULT: Started %d/%zu outbox listeners", started, count);
    return started;
}

void dna_engine_cancel_all_outbox_listeners(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active && dht_ctx) {
            dht_cancel_listen(dht_ctx, engine->outbox_listeners[i].dht_token);
            QGP_LOG_DEBUG(LOG_TAG, "Cancelled outbox listener for %s...",
                          engine->outbox_listeners[i].contact_fingerprint);
        }
        engine->outbox_listeners[i].active = false;
    }

    engine->outbox_listener_count = 0;
    QGP_LOG_INFO(LOG_TAG, "Cancelled all outbox listeners");

    pthread_mutex_unlock(&engine->outbox_listeners_mutex);
}

/* ============================================================================
 * DELIVERY TRACKERS (Message delivery confirmation)
 * ============================================================================ */

/**
 * Callback context for delivery tracker
 */
typedef struct {
    dna_engine_t *engine;
    char recipient[129];
} delivery_tracker_ctx_t;

/**
 * Internal callback for watermark updates
 * Updates message status and dispatches DNA_EVENT_MESSAGE_DELIVERED
 */
static void delivery_watermark_callback(
    const char *sender,
    const char *recipient,
    uint64_t seq_num,
    void *user_data
) {
    delivery_tracker_ctx_t *ctx = (delivery_tracker_ctx_t *)user_data;
    if (!ctx || !ctx->engine) {
        return;
    }

    dna_engine_t *engine = ctx->engine;

    QGP_LOG_INFO(LOG_TAG, "Delivery confirmed: %.20s... → %.20s... seq=%lu",
                 sender, recipient, (unsigned long)seq_num);

    /* Update tracker's last known watermark */
    pthread_mutex_lock(&engine->delivery_trackers_mutex);
    for (int i = 0; i < engine->delivery_tracker_count; i++) {
        if (engine->delivery_trackers[i].active &&
            strcmp(engine->delivery_trackers[i].recipient, recipient) == 0) {
            engine->delivery_trackers[i].last_known_watermark = seq_num;
            break;
        }
    }
    pthread_mutex_unlock(&engine->delivery_trackers_mutex);

    /* Update message status in database (all messages with seq <= seq_num are delivered) */
    if (engine->messenger && engine->messenger->backup_ctx) {
        int updated = message_backup_mark_delivered_up_to_seq(
            engine->messenger->backup_ctx,
            sender,      /* My fingerprint - I sent the messages */
            recipient,   /* Contact fingerprint - they received */
            seq_num
        );
        if (updated > 0) {
            QGP_LOG_INFO(LOG_TAG, "Updated %d messages to DELIVERED status", updated);
        }
    }

    /* Dispatch DNA_EVENT_MESSAGE_DELIVERED event */
    dna_event_t event = {0};
    event.type = DNA_EVENT_MESSAGE_DELIVERED;
    strncpy(event.data.message_delivered.recipient, recipient,
            sizeof(event.data.message_delivered.recipient) - 1);
    event.data.message_delivered.seq_num = seq_num;
    event.data.message_delivered.timestamp = (uint64_t)time(NULL);

    dna_dispatch_event(engine, &event);
}

int dna_engine_track_delivery(
    dna_engine_t *engine,
    const char *recipient_fingerprint
) {
    if (!engine || !recipient_fingerprint || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot track delivery: invalid params or no identity");
        return -1;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot track delivery: DHT not available");
        return -1;
    }

    pthread_mutex_lock(&engine->delivery_trackers_mutex);

    /* Check if already tracking this recipient */
    for (int i = 0; i < engine->delivery_tracker_count; i++) {
        if (engine->delivery_trackers[i].active &&
            strcmp(engine->delivery_trackers[i].recipient, recipient_fingerprint) == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "Already tracking delivery for %s...", recipient_fingerprint);
            pthread_mutex_unlock(&engine->delivery_trackers_mutex);
            return 0;  /* Already tracking - success */
        }
    }

    /* Check capacity */
    if (engine->delivery_tracker_count >= DNA_MAX_DELIVERY_TRACKERS) {
        QGP_LOG_ERROR(LOG_TAG, "Maximum delivery trackers reached (%d)", DNA_MAX_DELIVERY_TRACKERS);
        pthread_mutex_unlock(&engine->delivery_trackers_mutex);
        return -1;
    }

    /* Create callback context */
    delivery_tracker_ctx_t *ctx = malloc(sizeof(delivery_tracker_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate delivery tracker context");
        pthread_mutex_unlock(&engine->delivery_trackers_mutex);
        return -1;
    }
    ctx->engine = engine;
    strncpy(ctx->recipient, recipient_fingerprint, sizeof(ctx->recipient) - 1);
    ctx->recipient[sizeof(ctx->recipient) - 1] = '\0';

    /* Start watermark listener
     * Key: SHA3-512(recipient + ":watermark:" + sender)
     * sender = my fingerprint, recipient = contact */
    size_t token = dht_listen_watermark(dht_ctx,
                                        engine->fingerprint,
                                        recipient_fingerprint,
                                        delivery_watermark_callback,
                                        ctx);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start watermark listener for %s...", recipient_fingerprint);
        free(ctx);
        pthread_mutex_unlock(&engine->delivery_trackers_mutex);
        return -1;
    }

    /* Store tracker info */
    int idx = engine->delivery_tracker_count++;
    strncpy(engine->delivery_trackers[idx].recipient, recipient_fingerprint,
            sizeof(engine->delivery_trackers[idx].recipient) - 1);
    engine->delivery_trackers[idx].recipient[sizeof(engine->delivery_trackers[idx].recipient) - 1] = '\0';
    engine->delivery_trackers[idx].listener_token = token;
    engine->delivery_trackers[idx].last_known_watermark = 0;
    engine->delivery_trackers[idx].active = true;

    QGP_LOG_INFO(LOG_TAG, "Started delivery tracker for %s... (token=%zu)",
                 recipient_fingerprint, token);

    pthread_mutex_unlock(&engine->delivery_trackers_mutex);
    return 0;
}

void dna_engine_untrack_delivery(
    dna_engine_t *engine,
    const char *recipient_fingerprint
) {
    if (!engine || !recipient_fingerprint) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->delivery_trackers_mutex);

    for (int i = 0; i < engine->delivery_tracker_count; i++) {
        if (engine->delivery_trackers[i].active &&
            strcmp(engine->delivery_trackers[i].recipient, recipient_fingerprint) == 0) {

            /* Cancel the watermark listener */
            if (dht_ctx) {
                dht_cancel_watermark_listener(dht_ctx, engine->delivery_trackers[i].listener_token);
            }

            QGP_LOG_INFO(LOG_TAG, "Cancelled delivery tracker for %s...",
                         recipient_fingerprint);

            /* Remove by swapping with last element */
            if (i < engine->delivery_tracker_count - 1) {
                engine->delivery_trackers[i] = engine->delivery_trackers[engine->delivery_tracker_count - 1];
            }
            engine->delivery_tracker_count--;
            break;
        }
    }

    pthread_mutex_unlock(&engine->delivery_trackers_mutex);
}

void dna_engine_cancel_all_delivery_trackers(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->delivery_trackers_mutex);

    for (int i = 0; i < engine->delivery_tracker_count; i++) {
        if (engine->delivery_trackers[i].active && dht_ctx) {
            dht_cancel_watermark_listener(dht_ctx, engine->delivery_trackers[i].listener_token);
            QGP_LOG_DEBUG(LOG_TAG, "Cancelled delivery tracker for %s...",
                          engine->delivery_trackers[i].recipient);
        }
        engine->delivery_trackers[i].active = false;
    }

    engine->delivery_tracker_count = 0;
    QGP_LOG_INFO(LOG_TAG, "Cancelled all delivery trackers");

    pthread_mutex_unlock(&engine->delivery_trackers_mutex);
}

/* ============================================================================
 * P2P & PRESENCE HANDLERS
 * ============================================================================ */

void dna_handle_refresh_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_p2p_refresh_presence(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_lookup_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    uint64_t last_seen = 0;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_p2p_lookup_presence(engine->messenger,
                task->params.lookup_presence.fingerprint,
                &last_seen) != 0) {
            /* Not found is not an error - just return 0 timestamp */
            last_seen = 0;
        }
    }

    if (task->callback.presence) {
        task->callback.presence(task->request_id, error, last_seen, task->user_data);
    }
}

void dna_handle_sync_contacts_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] sync_contacts_to_dht handler: calling sync");
        if (messenger_sync_contacts_to_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_contacts_from_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_contacts_from_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_groups(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_groups(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_registered_name(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    char *name = NULL;

    if (!engine->messenger || !engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            char *registered_name = NULL;
            int ret = dht_keyserver_reverse_lookup(dht_ctx, engine->fingerprint, &registered_name);
            if (ret == 0 && registered_name) {
                name = registered_name; /* Transfer ownership */
            }
            /* Not found is not an error - just returns NULL name */
        }
    }

    if (task->callback.display_name) {
        /* Caller frees via dna_free_string - don't free here due to async callback */
        task->callback.display_name(task->request_id, error, name, task->user_data);
    }
}

/* ============================================================================
 * BACKWARD COMPATIBILITY
 * ============================================================================ */

void* dna_engine_get_messenger_context(dna_engine_t *engine) {
    if (!engine) return NULL;
    return engine->messenger;
}

void* dna_engine_get_dht_context(dna_engine_t *engine) {
    (void)engine; /* DHT is global singleton */
    return dht_singleton_get();
}

int dna_engine_is_dht_connected(dna_engine_t *engine) {
    (void)engine; /* DHT is global singleton */
    return dht_singleton_is_ready() ? 1 : 0;
}

/* ============================================================================
 * VERSION
 * ============================================================================ */

const char* dna_engine_get_version(void) {
    return DNA_VERSION_STRING;
}

/* ============================================================================
 * LOG CONFIGURATION
 * ============================================================================ */

/* Static buffers for current log config (loaded from <data_dir>/config) */
static char g_log_level[16] = "WARN";
static char g_log_tags[512] = "";

const char* dna_engine_get_log_level(void) {
    return g_log_level;
}

int dna_engine_set_log_level(const char *level) {
    if (!level) return -1;

    /* Validate level */
    if (strcmp(level, "DEBUG") != 0 && strcmp(level, "INFO") != 0 &&
        strcmp(level, "WARN") != 0 && strcmp(level, "ERROR") != 0 &&
        strcmp(level, "NONE") != 0) {
        return -1;
    }

    /* Update in-memory config */
    strncpy(g_log_level, level, sizeof(g_log_level) - 1);
    g_log_level[sizeof(g_log_level) - 1] = '\0';

    /* Apply to log system */
    qgp_log_level_t log_level = QGP_LOG_LEVEL_WARN;
    if (strcmp(level, "DEBUG") == 0) log_level = QGP_LOG_LEVEL_DEBUG;
    else if (strcmp(level, "INFO") == 0) log_level = QGP_LOG_LEVEL_INFO;
    else if (strcmp(level, "WARN") == 0) log_level = QGP_LOG_LEVEL_WARN;
    else if (strcmp(level, "ERROR") == 0) log_level = QGP_LOG_LEVEL_ERROR;
    else if (strcmp(level, "NONE") == 0) log_level = QGP_LOG_LEVEL_NONE;
    qgp_log_set_level(log_level);

    /* Save to config file */
    dna_config_t config;
    dna_config_load(&config);
    strncpy(config.log_level, level, sizeof(config.log_level) - 1);
    dna_config_save(&config);

    return 0;
}

const char* dna_engine_get_log_tags(void) {
    return g_log_tags;
}

int dna_engine_set_log_tags(const char *tags) {
    if (!tags) tags = "";

    /* Update in-memory config */
    strncpy(g_log_tags, tags, sizeof(g_log_tags) - 1);
    g_log_tags[sizeof(g_log_tags) - 1] = '\0';

    /* Apply to log system */
    if (tags[0] == '\0') {
        /* Empty = show all (blacklist mode) */
        qgp_log_set_filter_mode(QGP_LOG_FILTER_BLACKLIST);
        qgp_log_clear_filters();
    } else {
        /* Whitelist mode - only show specified tags */
        qgp_log_set_filter_mode(QGP_LOG_FILTER_WHITELIST);
        qgp_log_clear_filters();

        /* Parse comma-separated tags */
        char tags_copy[512];
        strncpy(tags_copy, tags, sizeof(tags_copy) - 1);
        tags_copy[sizeof(tags_copy) - 1] = '\0';

        char *token = strtok(tags_copy, ",");
        while (token != NULL) {
            /* Trim whitespace */
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            if (*token != '\0') {
                qgp_log_enable_tag(token);
            }
            token = strtok(NULL, ",");
        }
    }

    /* Save to config file */
    dna_config_t config;
    dna_config_load(&config);
    strncpy(config.log_tags, tags, sizeof(config.log_tags) - 1);
    dna_config_save(&config);

    return 0;
}

/* Initialize log config from file (called during engine startup) */
static void init_log_config(void) {
    dna_config_t config;
    if (dna_config_load(&config) == 0) {
        strncpy(g_log_level, config.log_level, sizeof(g_log_level) - 1);
        strncpy(g_log_tags, config.log_tags, sizeof(g_log_tags) - 1);
    }
}

/* ============================================================================
 * MEMORY MANAGEMENT
 * ============================================================================ */

void dna_free_strings(char **strings, int count) {
    if (!strings) return;
    for (int i = 0; i < count; i++) {
        free(strings[i]);
    }
    free(strings);
}

void dna_free_contacts(dna_contact_t *contacts, int count) {
    (void)count;
    free(contacts);
}

void dna_free_messages(dna_message_t *messages, int count) {
    if (!messages) return;
    for (int i = 0; i < count; i++) {
        free(messages[i].plaintext);
    }
    free(messages);
}

void dna_free_groups(dna_group_t *groups, int count) {
    (void)count;
    free(groups);
}

void dna_free_invitations(dna_invitation_t *invitations, int count) {
    (void)count;
    free(invitations);
}

void dna_free_contact_requests(dna_contact_request_t *requests, int count) {
    (void)count;
    free(requests);
}

void dna_free_blocked_users(dna_blocked_user_t *blocked, int count) {
    (void)count;
    free(blocked);
}

void dna_free_wallets(dna_wallet_t *wallets, int count) {
    (void)count;
    free(wallets);
}

void dna_free_balances(dna_balance_t *balances, int count) {
    (void)count;
    free(balances);
}

void dna_free_transactions(dna_transaction_t *transactions, int count) {
    (void)count;
    free(transactions);
}

void dna_free_feed_channels(dna_channel_info_t *channels, int count) {
    (void)count;
    free(channels);
}

void dna_free_feed_posts(dna_post_info_t *posts, int count) {
    if (!posts) return;
    for (int i = 0; i < count; i++) {
        free(posts[i].text);
    }
    free(posts);
}

void dna_free_feed_post(dna_post_info_t *post) {
    if (!post) return;
    free(post->text);
    free(post);
}

void dna_free_feed_comments(dna_comment_info_t *comments, int count) {
    if (!comments) return;
    for (int i = 0; i < count; i++) {
        free(comments[i].text);
    }
    free(comments);
}

void dna_free_feed_comment(dna_comment_info_t *comment) {
    if (!comment) return;
    free(comment->text);
    free(comment);
}

void dna_free_profile(dna_profile_t *profile) {
    if (!profile) return;
    free(profile);
}

/* ============================================================================
 * FEED HANDLERS
 * ============================================================================ */

/* Helper: Get DHT context (uses singleton - P2P transport reserved for voice/video) */
static dht_context_t* dna_get_dht_ctx(dna_engine_t *engine) {
    (void)engine;  /* Unused until voice/video P2P */
    return dht_singleton_get();
}

/* Helper: Get private key for signing (caller frees with qgp_key_free) */
static qgp_key_t* dna_load_private_key(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s/keys/%s.dsa",
             engine->data_dir, engine->fingerprint, engine->fingerprint);

    qgp_key_t *key = NULL;
    int load_rc;
    if (engine->keys_encrypted && engine->session_password) {
        load_rc = qgp_key_load_encrypted(key_path, engine->session_password, &key);
    } else {
        load_rc = qgp_key_load(key_path, &key);
    }
    if (load_rc != 0 || !key) {
        return NULL;
    }
    return key;
}

/* Helper: Get encryption key (caller frees with qgp_key_free) */
static qgp_key_t* dna_load_encryption_key(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s/keys/%s.kem",
             engine->data_dir, engine->fingerprint, engine->fingerprint);

    qgp_key_t *key = NULL;
    int load_rc;
    if (engine->keys_encrypted && engine->session_password) {
        load_rc = qgp_key_load_encrypted(key_path, engine->session_password, &key);
    } else {
        load_rc = qgp_key_load(key_path, &key);
    }
    if (load_rc != 0 || !key) {
        return NULL;
    }
    return key;
}

void dna_handle_get_feed_channels(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_channels(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_registry_t *registry = NULL;
    int ret = dna_feed_registry_get(dht, &registry);

    if (ret == 0 && registry && registry->channel_count > 0) {
        /* Convert to engine format */
        dna_channel_info_t *channels = calloc(registry->channel_count, sizeof(dna_channel_info_t));
        if (channels) {
            for (size_t i = 0; i < registry->channel_count; i++) {
                strncpy(channels[i].channel_id, registry->channels[i].channel_id, 64);
                strncpy(channels[i].name, registry->channels[i].name, 63);
                strncpy(channels[i].description, registry->channels[i].description, 511);
                strncpy(channels[i].creator_fingerprint, registry->channels[i].creator_fingerprint, 128);
                channels[i].created_at = registry->channels[i].created_at;
                channels[i].subscriber_count = registry->channels[i].subscriber_count;
                channels[i].last_activity = registry->channels[i].last_activity;

                /* Count posts from last 7 days */
                int post_count = 0;
                time_t now = time(NULL);
                for (int day = 0; day < 7; day++) {
                    time_t t = now - (day * 86400);
                    struct tm *tm = gmtime(&t);
                    char date[12];
                    snprintf(date, sizeof(date), "%04d%02d%02d",
                             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

                    dna_feed_post_t *posts = NULL;
                    size_t count = 0;
                    if (dna_feed_posts_get_by_channel(dht, channels[i].channel_id, date, &posts, &count) == 0) {
                        post_count += (int)count;
                        free(posts);
                    }
                }
                channels[i].post_count = post_count;
            }
            task->callback.feed_channels(task->request_id, DNA_OK,
                                         channels, (int)registry->channel_count, task->user_data);
        } else {
            task->callback.feed_channels(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
        }
        dna_feed_registry_free(registry);
    } else if (ret == -2) {
        /* No registry - return empty */
        task->callback.feed_channels(task->request_id, DNA_OK, NULL, 0, task->user_data);
    } else {
        task->callback.feed_channels(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        if (registry) dna_feed_registry_free(registry);
    }
}

void dna_handle_create_feed_channel(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_channel(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_channel_t *new_channel = NULL;
    int ret = dna_feed_channel_create(dht,
                                       task->params.create_feed_channel.name,
                                       task->params.create_feed_channel.description,
                                       engine->fingerprint,
                                       key->private_key,
                                       &new_channel);
    qgp_key_free(key);

    if (ret == 0 && new_channel) {
        dna_channel_info_t *channel = calloc(1, sizeof(dna_channel_info_t));
        if (channel) {
            strncpy(channel->channel_id, new_channel->channel_id, 64);
            strncpy(channel->name, new_channel->name, 63);
            strncpy(channel->description, new_channel->description, 511);
            strncpy(channel->creator_fingerprint, new_channel->creator_fingerprint, 128);
            channel->created_at = new_channel->created_at;
            channel->subscriber_count = 1;
            channel->last_activity = new_channel->created_at;
        }
        dna_feed_channel_free(new_channel);
        task->callback.feed_channel(task->request_id, DNA_OK, channel, task->user_data);
    } else if (ret == -2) {
        task->callback.feed_channel(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS,
                                    NULL, task->user_data);
    } else {
        task->callback.feed_channel(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
    }
}

void dna_handle_init_default_channels(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int created = dna_feed_init_default_channels(dht, engine->fingerprint, key->private_key);
    qgp_key_free(key);

    task->callback.completion(task->request_id, created >= 0 ? DNA_OK : DNA_ERROR_INTERNAL,
                              task->user_data);
}

void dna_handle_get_feed_posts(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_posts(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, 0, task->user_data);
        return;
    }

    const char *date = task->params.get_feed_posts.date[0] ? task->params.get_feed_posts.date : NULL;

    dna_feed_post_t *posts = NULL;
    size_t count = 0;
    int ret = dna_feed_posts_get_by_channel(dht, task->params.get_feed_posts.channel_id,
                                            date, &posts, &count);

    if (ret == 0 && posts && count > 0) {
        /* Convert to engine format */
        dna_post_info_t *out_posts = calloc(count, sizeof(dna_post_info_t));
        if (out_posts) {
            for (size_t i = 0; i < count; i++) {
                strncpy(out_posts[i].post_id, posts[i].post_id, 199);
                strncpy(out_posts[i].channel_id, posts[i].channel_id, 64);
                strncpy(out_posts[i].author_fingerprint, posts[i].author_fingerprint, 128);
                out_posts[i].text = strdup(posts[i].text);
                out_posts[i].timestamp = posts[i].timestamp;
                out_posts[i].updated = posts[i].updated;

                /* Fetch actual comment count from DHT */
                dna_feed_comment_t *comments = NULL;
                size_t comment_count = 0;
                if (dna_feed_comments_get(dht, posts[i].post_id, &comments, &comment_count) == 0) {
                    out_posts[i].comment_count = (int)comment_count;
                    dna_feed_comments_free(comments, comment_count);
                } else {
                    out_posts[i].comment_count = 0;
                }

                out_posts[i].upvotes = posts[i].upvotes;
                out_posts[i].downvotes = posts[i].downvotes;
                out_posts[i].user_vote = posts[i].user_vote;
                out_posts[i].verified = (posts[i].signature_len > 0);
            }
            task->callback.feed_posts(task->request_id, DNA_OK,
                                      out_posts, (int)count, task->user_data);
        } else {
            task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        }
        free(posts);
    } else if (ret == -2) {
        /* No posts - return empty */
        task->callback.feed_posts(task->request_id, DNA_OK, NULL, 0, task->user_data);
    } else {
        task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        if (posts) free(posts);
    }
}

void dna_handle_create_feed_post(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_post(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                 NULL, task->user_data);
        return;
    }

    dna_feed_post_t *new_post = NULL;
    int ret = dna_feed_post_create(dht,
                                    task->params.create_feed_post.channel_id,
                                    engine->fingerprint,
                                    task->params.create_feed_post.text,
                                    key->private_key,
                                    &new_post);
    qgp_key_free(key);

    if (ret == 0 && new_post) {
        dna_post_info_t *post = calloc(1, sizeof(dna_post_info_t));
        if (post) {
            strncpy(post->post_id, new_post->post_id, 199);
            strncpy(post->channel_id, new_post->channel_id, 64);
            strncpy(post->author_fingerprint, new_post->author_fingerprint, 128);
            post->text = strdup(new_post->text);
            post->timestamp = new_post->timestamp;
            post->updated = new_post->updated;
            post->comment_count = new_post->comment_count;
            post->upvotes = 0;
            post->downvotes = 0;
            post->user_vote = 0;
            post->verified = true;
        }
        dna_feed_post_free(new_post);
        task->callback.feed_post(task->request_id, DNA_OK, post, task->user_data);
    } else {
        task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, task->user_data);
    }
}

void dna_handle_add_feed_comment(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_comment_t *new_comment = NULL;
    int ret = dna_feed_comment_add(dht,
                                    task->params.add_feed_comment.post_id,
                                    engine->fingerprint,
                                    task->params.add_feed_comment.text,
                                    key->private_key,
                                    &new_comment);
    qgp_key_free(key);

    if (ret == 0 && new_comment) {
        dna_comment_info_t *comment = calloc(1, sizeof(dna_comment_info_t));
        if (comment) {
            strncpy(comment->comment_id, new_comment->comment_id, 199);
            strncpy(comment->post_id, new_comment->post_id, 199);
            strncpy(comment->author_fingerprint, new_comment->author_fingerprint, 128);
            comment->text = strdup(new_comment->text);
            comment->timestamp = new_comment->timestamp;
            comment->upvotes = 0;
            comment->downvotes = 0;
            comment->user_vote = 0;
            comment->verified = true;
        }
        dna_feed_comment_free(new_comment);
        task->callback.feed_comment(task->request_id, DNA_OK, comment, task->user_data);
    } else {
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
    }
}

void dna_handle_get_feed_comments(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comments(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_feed_comments_get(dht, task->params.get_feed_comments.post_id,
                                     &comments, &count);

    if (ret == 0 && comments && count > 0) {
        dna_comment_info_t *out_comments = calloc(count, sizeof(dna_comment_info_t));
        if (out_comments) {
            for (size_t i = 0; i < count; i++) {
                strncpy(out_comments[i].comment_id, comments[i].comment_id, 199);
                strncpy(out_comments[i].post_id, comments[i].post_id, 199);
                strncpy(out_comments[i].author_fingerprint, comments[i].author_fingerprint, 128);
                out_comments[i].text = strdup(comments[i].text);
                out_comments[i].timestamp = comments[i].timestamp;
                out_comments[i].upvotes = comments[i].upvotes;
                out_comments[i].downvotes = comments[i].downvotes;
                out_comments[i].user_vote = comments[i].user_vote;
                out_comments[i].verified = (comments[i].signature_len > 0);
            }
            task->callback.feed_comments(task->request_id, DNA_OK,
                                         out_comments, (int)count, task->user_data);
        } else {
            task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
        }
        dna_feed_comments_free(comments, count);
    } else {
        task->callback.feed_comments(task->request_id, DNA_OK, NULL, 0, task->user_data);
        if (comments) dna_feed_comments_free(comments, count);
    }
}

void dna_handle_cast_feed_vote(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int ret = dna_feed_vote_cast(dht,
                                  task->params.cast_feed_vote.post_id,
                                  engine->fingerprint,
                                  task->params.cast_feed_vote.vote_value,
                                  key->private_key);
    qgp_key_free(key);

    if (ret == 0) {
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
    } else if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS, task->user_data);
    } else {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
    }
}

void dna_handle_get_feed_votes(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_post(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                 NULL, task->user_data);
        return;
    }

    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_votes_get(dht, task->params.get_feed_votes.post_id, &votes);

    dna_post_info_t *post = calloc(1, sizeof(dna_post_info_t));
    if (post) {
        strncpy(post->post_id, task->params.get_feed_votes.post_id, 199);
        if (ret == 0 && votes) {
            post->upvotes = votes->upvote_count;
            post->downvotes = votes->downvote_count;
            post->user_vote = engine->identity_loaded ?
                              dna_feed_get_user_vote(votes, engine->fingerprint) : 0;
            dna_feed_votes_free(votes);
        }
        task->callback.feed_post(task->request_id, DNA_OK, post, task->user_data);
    } else {
        if (votes) dna_feed_votes_free(votes);
        task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
    }
}

void dna_handle_cast_comment_vote(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int ret = dna_feed_comment_vote_cast(dht,
                                          task->params.cast_comment_vote.comment_id,
                                          engine->fingerprint,
                                          task->params.cast_comment_vote.vote_value,
                                          key->private_key);
    qgp_key_free(key);

    if (ret == 0) {
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
    } else if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS, task->user_data);
    } else {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
    }
}

void dna_handle_get_comment_votes(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_comment_votes_get(dht, task->params.get_comment_votes.comment_id, &votes);

    dna_comment_info_t *comment = calloc(1, sizeof(dna_comment_info_t));
    if (comment) {
        strncpy(comment->comment_id, task->params.get_comment_votes.comment_id, 199);
        if (ret == 0 && votes) {
            comment->upvotes = votes->upvote_count;
            comment->downvotes = votes->downvote_count;
            comment->user_vote = engine->identity_loaded ?
                                 dna_feed_get_user_vote(votes, engine->fingerprint) : 0;
            dna_feed_votes_free(votes);
        }
        task->callback.feed_comment(task->request_id, DNA_OK, comment, task->user_data);
    } else {
        if (votes) dna_feed_votes_free(votes);
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
    }
}

/* ============================================================================
 * FEED PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_get_feed_channels(
    dna_engine_t *engine,
    dna_feed_channels_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_channels = callback;
    return dna_submit_task(engine, TASK_GET_FEED_CHANNELS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_feed_channel(
    dna_engine_t *engine,
    const char *name,
    const char *description,
    dna_feed_channel_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_feed_channel.name, name, 63);
    if (description) {
        strncpy(params.create_feed_channel.description, description, 511);
    }

    dna_task_callback_t cb = {0};
    cb.feed_channel = callback;
    return dna_submit_task(engine, TASK_CREATE_FEED_CHANNEL, &params, cb, user_data);
}

dna_request_id_t dna_engine_init_default_channels(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_INIT_DEFAULT_CHANNELS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_posts(
    dna_engine_t *engine,
    const char *channel_id,
    const char *date,
    dna_feed_posts_cb callback,
    void *user_data
) {
    if (!engine || !channel_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_posts.channel_id, channel_id, 64);
    if (date) {
        strncpy(params.get_feed_posts.date, date, 11);
    }

    dna_task_callback_t cb = {0};
    cb.feed_posts = callback;
    return dna_submit_task(engine, TASK_GET_FEED_POSTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_create_feed_post(
    dna_engine_t *engine,
    const char *channel_id,
    const char *text,
    dna_feed_post_cb callback,
    void *user_data
) {
    if (!engine || !channel_id || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_feed_post.channel_id, channel_id, 64);
    params.create_feed_post.text = strdup(text);
    if (!params.create_feed_post.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_post = callback;
    return dna_submit_task(engine, TASK_CREATE_FEED_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_add_feed_comment(
    dna_engine_t *engine,
    const char *post_id,
    const char *text,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.add_feed_comment.post_id, post_id, 199);
    params.add_feed_comment.text = strdup(text);
    if (!params.add_feed_comment.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_ADD_FEED_COMMENT, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_comments(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_comments_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_comments.post_id, post_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_comments = callback;
    return dna_submit_task(engine, TASK_GET_FEED_COMMENTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_cast_feed_vote(
    dna_engine_t *engine,
    const char *post_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;
    if (vote_value != 1 && vote_value != -1) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.cast_feed_vote.post_id, post_id, 199);
    params.cast_feed_vote.vote_value = vote_value;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CAST_FEED_VOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_votes(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_post_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_votes.post_id, post_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_post = callback;
    return dna_submit_task(engine, TASK_GET_FEED_VOTES, &params, cb, user_data);
}

dna_request_id_t dna_engine_cast_comment_vote(
    dna_engine_t *engine,
    const char *comment_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !comment_id || !callback) return DNA_REQUEST_ID_INVALID;
    if (vote_value != 1 && vote_value != -1) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.cast_comment_vote.comment_id, comment_id, 199);
    params.cast_comment_vote.vote_value = vote_value;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CAST_COMMENT_VOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_comment_votes(
    dna_engine_t *engine,
    const char *comment_id,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !comment_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_comment_votes.comment_id, comment_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_GET_COMMENT_VOTES, &params, cb, user_data);
}


/* ============================================================================
 * DEBUG LOG API - In-app log viewing for mobile debugging
 * ============================================================================ */

void dna_engine_debug_log_enable(bool enabled) {
    qgp_log_ring_enable(enabled);
}

bool dna_engine_debug_log_is_enabled(void) {
    return qgp_log_ring_is_enabled();
}

int dna_engine_debug_log_get_entries(dna_debug_log_entry_t *entries, int max_entries) {
    if (!entries || max_entries <= 0) {
        return 0;
    }

    /* Allocate temp buffer for qgp entries */
    qgp_log_entry_t *qgp_entries = calloc(max_entries, sizeof(qgp_log_entry_t));
    if (!qgp_entries) {
        return 0;
    }

    int count = qgp_log_ring_get_entries(qgp_entries, max_entries);

    /* Convert to dna_debug_log_entry_t (same structure, just copy) */
    for (int i = 0; i < count; i++) {
        entries[i].timestamp_ms = qgp_entries[i].timestamp_ms;
        entries[i].level = (int)qgp_entries[i].level;
        memcpy(entries[i].tag, qgp_entries[i].tag, sizeof(entries[i].tag));
        memcpy(entries[i].message, qgp_entries[i].message, sizeof(entries[i].message));
    }

    free(qgp_entries);
    return count;
}

int dna_engine_debug_log_count(void) {
    return qgp_log_ring_count();
}

void dna_engine_debug_log_clear(void) {
    qgp_log_ring_clear();
}

void dna_engine_debug_log_message(const char *tag, const char *message) {
    if (!tag || !message) return;
    qgp_log_ring_add(QGP_LOG_LEVEL_WARN, tag, "%s", message);
}

int dna_engine_debug_log_export(const char *filepath) {
    if (!filepath) return -1;
    return qgp_log_export_to_file(filepath);
}

/* ============================================================================
 * MESSAGE BACKUP/RESTORE IMPLEMENTATION
 * ============================================================================ */

dna_request_id_t dna_engine_backup_messages(
    dna_engine_t *engine,
    dna_backup_result_cb callback,
    void *user_data)
{
    if (!engine || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for backup_messages");
        return 0;
    }

    if (!engine->identity_loaded || !engine->messenger) {
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded for backup");
        callback(0, -1, 0, 0, user_data);
        return 0;
    }

    dna_request_id_t request_id = dna_next_request_id(engine);

    // Get DHT context
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for backup");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    // Get message backup context
    message_backup_context_t *msg_ctx = engine->messenger->backup_ctx;
    if (!msg_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Message backup context not available");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    // Load keys (same pattern as messenger_sync_contacts_to_dht)
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    // Load Kyber keypair
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s/keys/%s.kem",
             data_dir, engine->fingerprint, engine->fingerprint);

    qgp_key_t *kyber_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(kyber_path, engine->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    // Load Dilithium keypair
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s/keys/%s.dsa",
             data_dir, engine->fingerprint, engine->fingerprint);

    qgp_key_t *dilithium_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, engine->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    // Perform backup
    int message_count = 0;
    int result = dht_message_backup_publish(
        dht_ctx,
        msg_ctx,
        engine->fingerprint,
        kyber_key->public_key,
        kyber_key->private_key,
        dilithium_key->public_key,
        dilithium_key->private_key,
        &message_count
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Message backup completed: %d messages", message_count);
        callback(request_id, 0, message_count, 0, user_data);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Message backup failed: %d", result);
        callback(request_id, result, 0, 0, user_data);
    }

    return request_id;
}

dna_request_id_t dna_engine_restore_messages(
    dna_engine_t *engine,
    dna_backup_result_cb callback,
    void *user_data)
{
    if (!engine || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for restore_messages");
        return 0;
    }

    if (!engine->identity_loaded || !engine->messenger) {
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded for restore");
        callback(0, -1, 0, 0, user_data);
        return 0;
    }

    dna_request_id_t request_id = dna_next_request_id(engine);

    // Get DHT context
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for restore");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    // Get message backup context
    message_backup_context_t *msg_ctx = engine->messenger->backup_ctx;
    if (!msg_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Message backup context not available");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    // Load keys
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    // Load Kyber keypair (only need private key for decryption)
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s/keys/%s.kem",
             data_dir, engine->fingerprint, engine->fingerprint);

    qgp_key_t *kyber_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(kyber_path, engine->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    // Load Dilithium keypair (only need public key for signature verification)
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s/keys/%s.dsa",
             data_dir, engine->fingerprint, engine->fingerprint);

    qgp_key_t *dilithium_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, engine->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    // Perform restore
    int restored_count = 0;
    int skipped_count = 0;
    int result = dht_message_backup_restore(
        dht_ctx,
        msg_ctx,
        engine->fingerprint,
        kyber_key->private_key,
        dilithium_key->public_key,
        &restored_count,
        &skipped_count
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Message restore completed: %d restored, %d skipped",
                     restored_count, skipped_count);
        callback(request_id, 0, restored_count, skipped_count, user_data);
    } else if (result == -2) {
        QGP_LOG_INFO(LOG_TAG, "No message backup found in DHT");
        callback(request_id, -2, 0, 0, user_data);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Message restore failed: %d", result);
        callback(request_id, result, 0, 0, user_data);
    }

    return request_id;
}
