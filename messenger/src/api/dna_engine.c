/*
 * DNA Engine - Implementation
 *
 * Core engine implementation providing async API for DNA Messenger.
 */

#define _XOPEN_SOURCE 700  /* For strptime */

/* Standard library includes (all platforms) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
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
#include "messenger/init.h"
#include "messenger/messages.h"
#include "messenger/groups.h"
#include "messenger_transport.h"
#include "message_backup.h"
#include "messenger/status.h"
#include "dht/client/dht_singleton.h"
#include "dht/core/dht_keyserver.h"
#include "dht/core/dht_listen.h"
#include "dht/client/dht_contactlist.h"
#include "dht/client/dht_message_backup.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/client/dna_feed.h"
#include "dht/client/dna_profile.h"
#include "dht/shared/dht_chunked.h"
#include "dht/shared/dht_contact_request.h"
#include "dht/shared/dht_groups.h"
#include "dht/client/dna_group_outbox.h"
#include "transport/transport.h"
#include "transport/internal/transport_core.h"  /* For parse_presence_json */
/* TURN credentials removed in v0.4.61 for privacy */
#include "database/presence_cache.h"
#include "database/keyserver_cache.h"
#include "database/profile_cache.h"
#include "database/profile_manager.h"
#include "database/contacts_db.h"
#include "database/addressbook_db.h"
#include "database/group_invitations.h"
#include "dht/client/dht_addressbook.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/key_encryption.h"
#include "crypto/utils/qgp_dilithium.h"

/* Blockchain/Wallet includes for send_tokens */
#include "cellframe_wallet.h"

/* JSON and SHA3 for version check API */
#include <json-c/json.h>
#include "crypto/utils/qgp_sha3.h"
#include "cellframe_wallet_create.h"
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
#include "messenger/gek.h"
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"
#include "dna_config.h"

#define LOG_TAG "DNA_ENGINE"
/* Use engine-specific error codes */
#define DNA_OK 0

/* DHT stabilization delay - wait for routing table to fill after bootstrap */
#define DHT_STABILIZATION_SECONDS 15

/* Forward declarations for static helpers */
static dht_context_t* dna_get_dht_ctx(dna_engine_t *engine);
static qgp_key_t* dna_load_private_key(dna_engine_t *engine);
static qgp_key_t* dna_load_encryption_key(dna_engine_t *engine);
static void init_log_config(void);

/* Forward declarations for listener management */
void dna_engine_cancel_all_outbox_listeners(dna_engine_t *engine);
void dna_engine_cancel_all_presence_listeners(dna_engine_t *engine);
void dna_engine_cancel_contact_request_listener(dna_engine_t *engine);
size_t dna_engine_start_contact_request_listener(dna_engine_t *engine);
void dna_engine_cancel_watermark_listener(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_listen_outbox(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_presence_listener(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_watermark_listener(dna_engine_t *engine, const char *contact_fingerprint);

/* Parallel listener setup for mobile performance optimization */
typedef struct {
    dna_engine_t *engine;
    char fingerprint[129];
} parallel_listener_ctx_t;

/* Full listener worker - starts outbox + presence + watermark (for Flutter) */
static void *parallel_listener_worker(void *arg) {
    parallel_listener_ctx_t *ctx = (parallel_listener_ctx_t *)arg;
    if (!ctx || !ctx->engine) return NULL;

    dna_engine_listen_outbox(ctx->engine, ctx->fingerprint);
    dna_engine_start_presence_listener(ctx->engine, ctx->fingerprint);
    dna_engine_start_watermark_listener(ctx->engine, ctx->fingerprint);

    return NULL;
}

/* Minimal listener worker - outbox only (for Android service/JNI notifications) */
static void *parallel_listener_worker_minimal(void *arg) {
    parallel_listener_ctx_t *ctx = (parallel_listener_ctx_t *)arg;
    if (!ctx || !ctx->engine) return NULL;

    /* Only outbox listener - presence/watermark not needed for notifications */
    dna_engine_listen_outbox(ctx->engine, ctx->fingerprint);

    return NULL;
}

/**
 * Validate identity name - must be lowercase only
 * Allowed: a-z, 0-9, underscore, hyphen
 * Not allowed: uppercase letters, spaces, special chars
 */
static int is_valid_identity_name(const char *name) {
    if (!name || !*name) return 0;
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') return 0;  /* Reject uppercase */
        if (c >= 'a' && c <= 'z') continue;  /* Allow lowercase */
        if (c >= '0' && c <= '9') continue;  /* Allow digits */
        if (c == '_' || c == '-') continue;  /* Allow underscore/hyphen */
        return 0;  /* Reject other chars */
    }
    return 1;
}
size_t dna_engine_start_presence_listener(dna_engine_t *engine, const char *contact_fingerprint);

/* Global engine pointer for DHT status callback and event dispatch from lower layers
 * Set during create, cleared during destroy. Used by messenger_transport.c to emit events. */
static dna_engine_t *g_dht_callback_engine = NULL;

/* Android notification callback - separate from Flutter's event callback.
 * This is called when DNA_EVENT_MESSAGE_RECEIVED fires for incoming messages,
 * allowing Android to show native notifications even when Flutter is detached. */
static dna_android_notification_cb g_android_notification_cb = NULL;
static void *g_android_notification_data = NULL;

/* Android group message notification callback.
 * Called when new group messages arrive via DHT listen. */
static dna_android_group_message_cb g_android_group_message_cb = NULL;
static void *g_android_group_message_data = NULL;

/* Android contact request notification callback.
 * Called when new contact requests arrive via DHT listen. */
static dna_android_contact_request_cb g_android_contact_request_cb = NULL;
static void *g_android_contact_request_data = NULL;

/* Global engine accessors (for messenger layer event dispatch) */
void dna_engine_set_global(dna_engine_t *engine) {
    g_dht_callback_engine = engine;
}

dna_engine_t* dna_engine_get_global(void) {
    return g_dht_callback_engine;
}

/**
 * Background thread for listener setup
 * Runs on separate thread to avoid blocking OpenDHT's callback thread.
 */
static void *dna_engine_setup_listeners_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t *)arg;
    if (!engine) return NULL;

    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Background thread: starting listener setup...");

    /* v0.6.0+: Check shutdown before each major operation */
    if (atomic_load(&engine->shutdown_requested)) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Shutdown requested, aborting listener setup");
        goto cleanup;
    }

    /* Cancel stale engine-level listener tracking before creating new ones.
     * After network change + DHT reinit, global listeners are suspended but
     * engine-level arrays still show active=true, blocking new listener creation. */
    dna_engine_cancel_all_outbox_listeners(engine);
    dna_engine_cancel_all_presence_listeners(engine);
    dna_engine_cancel_contact_request_listener(engine);

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    int count = dna_engine_listen_all_contacts(engine);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Background thread: started %d listeners", count);

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* Subscribe to all groups for real-time notifications */
    int group_count = dna_engine_subscribe_all_groups(engine);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Background thread: subscribed to %d groups", group_count);

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* Retry pending/failed messages after DHT reconnect
     * Messages may have failed during the previous session or network outage.
     * Now that DHT is reconnected, retry them. */
    int retried = dna_engine_retry_pending_messages(engine);
    if (retried > 0) {
        QGP_LOG_INFO(LOG_TAG, "[RETRY] DHT reconnect: retried %d pending messages", retried);
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* Check for missed incoming messages after reconnect.
     * Android: Skip auto-fetch - Flutter handles fetching when app resumes.
     *          This prevents watermarks being published while app is backgrounded,
     *          which would mark messages as "delivered" before user sees them.
     * Desktop: Fetch immediately since there's no background service. */
#ifndef __ANDROID__
    if (engine->messenger && engine->messenger->transport_ctx) {
        QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: checking for missed messages");
        size_t received = 0;
        transport_check_offline_messages(engine->messenger->transport_ctx, NULL, &received);
        if (received > 0) {
            QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: received %zu missed messages", received);
        }
    }
#else
    QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: skipping auto-fetch (Android - Flutter handles on resume)");
#endif

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* Wait for DHT routing table to stabilize after reconnect, then retry again.
     * The immediate retry above may fail if routing table is still sparse.
     * Sleep in 1-second intervals to check shutdown flag. */
    QGP_LOG_INFO(LOG_TAG, "[RETRY] Listener thread: waiting %d seconds for stabilization...",
                 DHT_STABILIZATION_SECONDS);
    for (int i = 0; i < DHT_STABILIZATION_SECONDS; i++) {
        if (atomic_load(&engine->shutdown_requested)) goto cleanup;
        qgp_platform_sleep_ms(1000);
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    int retried_post_stable = dna_engine_retry_pending_messages(engine);
    if (retried_post_stable > 0) {
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Reconnect post-stabilization: retried %d messages", retried_post_stable);
    }

cleanup:
    /* v0.6.0+: Mark thread as not running before exit */
    pthread_mutex_lock(&engine->background_threads_mutex);
    engine->setup_listeners_running = false;
    pthread_mutex_unlock(&engine->background_threads_mutex);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Background thread: exiting");
    return NULL;
}

/**
 * Post-stabilization retry thread
 * Waits for DHT routing table to fill, then retries pending messages.
 * Spawned from identity load to handle the common case where DHT connects
 * before identity is loaded (callback's listener thread doesn't spawn).
 */
static void *dna_engine_stabilization_retry_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t *)arg;

    /* Diagnostic: log immediately so we know thread started */
    QGP_LOG_WARN(LOG_TAG, "[RETRY] >>> STABILIZATION THREAD STARTED (engine=%p) <<<", (void*)engine);

    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "[RETRY] Stabilization thread: engine is NULL, aborting");
        return NULL;
    }

    /* v0.6.0+: Check shutdown before starting */
    if (atomic_load(&engine->shutdown_requested)) {
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Shutdown requested, aborting stabilization");
        goto cleanup;
    }

    /* Wait for DHT routing table to stabilize.
     * Early retries fail with nodes_tried=0 because routing table only has
     * bootstrap nodes. After 15 seconds, routing table is populated with
     * nodes discovered through DHT crawling.
     * Sleep in 1-second intervals to check shutdown flag. */
    QGP_LOG_WARN(LOG_TAG, "[RETRY] Stabilization thread: waiting %d seconds for routing table...",
                 DHT_STABILIZATION_SECONDS);
    for (int i = 0; i < DHT_STABILIZATION_SECONDS; i++) {
        if (atomic_load(&engine->shutdown_requested)) goto cleanup;
        qgp_platform_sleep_ms(1000);
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    QGP_LOG_WARN(LOG_TAG, "[RETRY] Stabilization thread: woke up, starting retries...");

    /* 1. Re-register presence - initial registration during identity load often fails
     * with nodes_tried=0 because routing table only has bootstrap nodes */
    if (engine->messenger) {
        int presence_rc = messenger_transport_refresh_presence(engine->messenger);
        if (presence_rc == 0) {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: presence re-registered");
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: presence registration failed: %d", presence_rc);
        }
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 1b. Restore groups from DHT to local cache (Android startup fix)
     * On fresh startup, local SQLite cache is empty. Fetch group list from DHT
     * and sync each group to local cache so they appear in the UI. */
    if (engine->messenger) {
        int restored = messenger_restore_groups_from_dht(engine->messenger);
        if (restored > 0) {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: restored %d groups from DHT", restored);
        } else if (restored == 0) {
            QGP_LOG_INFO(LOG_TAG, "[RETRY] Post-stabilization: no groups to restore from DHT");
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: group restore failed: %d", restored);
        }
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 2. Sync any pending outboxes (messages that failed to publish earlier) */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        int synced = dht_offline_queue_sync_pending(dht_ctx);
        if (synced > 0) {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: synced %d pending outboxes", synced);
        }
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 3. Retry pending messages from backup database */
    int retried = dna_engine_retry_pending_messages(engine);
    if (retried > 0) {
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: retried %d pending messages", retried);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: no pending messages to retry");
    }

    QGP_LOG_WARN(LOG_TAG, "[RETRY] >>> STABILIZATION THREAD COMPLETE <<<");

cleanup:
    /* v0.6.0+: Mark thread as not running before exit */
    pthread_mutex_lock(&engine->background_threads_mutex);
    engine->stabilization_retry_running = false;
    pthread_mutex_unlock(&engine->background_threads_mutex);
    return NULL;
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
         * Listeners fire DNA_EVENT_OUTBOX_UPDATED -> Flutter polls + refreshes UI
         *
         * IMPORTANT: Run listener setup on a background thread!
         * This callback runs on OpenDHT's internal thread. If we block here with
         * dht_listen_ex()'s future.get(), we deadlock (OpenDHT needs this thread). */
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT connected, identity_loaded=%d", engine->identity_loaded);
        if (engine->identity_loaded) {
            /* v0.6.0+: Track thread for clean shutdown (no detach) */
            pthread_mutex_lock(&engine->background_threads_mutex);
            if (engine->setup_listeners_running) {
                /* Previous thread still running - skip (it will handle everything) */
                pthread_mutex_unlock(&engine->background_threads_mutex);
                QGP_LOG_INFO(LOG_TAG, "[LISTEN] Listener setup thread already running, skipping");
            } else {
                /* Spawn new thread and track it */
                engine->setup_listeners_running = true;
                pthread_mutex_unlock(&engine->background_threads_mutex);
                if (pthread_create(&engine->setup_listeners_thread, NULL,
                                   dna_engine_setup_listeners_thread, engine) == 0) {
                    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Spawned background thread for listener setup");
                } else {
                    pthread_mutex_lock(&engine->background_threads_mutex);
                    engine->setup_listeners_running = false;
                    pthread_mutex_unlock(&engine->background_threads_mutex);
                    QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to spawn listener setup thread");
                }
            }
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
    if (error == DNA_ENGINE_ERROR_NO_IDENTITY) return "No identity loaded";
    if (error == DNA_ENGINE_ERROR_ALREADY_EXISTS) return "Already exists";
    if (error == DNA_ENGINE_ERROR_PERMISSION) return "Permission denied";
    if (error == DNA_ENGINE_ERROR_PASSWORD_REQUIRED) return "Password required for encrypted keys";
    if (error == DNA_ENGINE_ERROR_WRONG_PASSWORD) return "Incorrect password";
    if (error == DNA_ENGINE_ERROR_INVALID_SIGNATURE) return "Profile signature verification failed (corrupted or stale DHT data)";
    if (error == DNA_ENGINE_ERROR_INSUFFICIENT_BALANCE) return "Insufficient balance";
    if (error == DNA_ENGINE_ERROR_RENT_MINIMUM) return "Amount too small - Solana requires minimum ~0.00089 SOL for new accounts";
    if (error == DNA_ENGINE_ERROR_IDENTITY_LOCKED) return "Identity locked by another process (close the GUI app first)";
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
    if (!engine) return DNA_REQUEST_ID_INVALID;
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
    if (!task) return;
    switch (task->type) {
        case TASK_CREATE_IDENTITY:
            if (task->params.create_identity.password) {
                /* Secure clear password before freeing */
                qgp_secure_memzero(task->params.create_identity.password,
                       strlen(task->params.create_identity.password));
                free(task->params.create_identity.password);
            }
            break;
        case TASK_LOAD_IDENTITY:
            if (task->params.load_identity.password) {
                /* Secure clear password before freeing */
                qgp_secure_memzero(task->params.load_identity.password,
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

/**
 * Get optimal worker thread count based on CPU cores.
 * Returns: cores + 4 (for I/O bound work), clamped to min/max bounds.
 */
static int dna_get_optimal_worker_count(void) {
    int cores = qgp_platform_cpu_count();

    /* For I/O bound work (network, disk), more threads than cores is beneficial */
    int workers = cores + 4;

    /* Clamp to bounds */
    if (workers < DNA_WORKER_THREAD_MIN) workers = DNA_WORKER_THREAD_MIN;
    if (workers > DNA_WORKER_THREAD_MAX) workers = DNA_WORKER_THREAD_MAX;

    return workers;
}

int dna_start_workers(dna_engine_t *engine) {
    if (!engine) return -1;
    atomic_store(&engine->shutdown_requested, false);

    /* Calculate optimal thread count based on CPU cores */
    engine->worker_count = dna_get_optimal_worker_count();
    engine->worker_threads = calloc(engine->worker_count, sizeof(pthread_t));
    if (!engine->worker_threads) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate worker threads array");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Starting %d worker threads (based on CPU cores)", engine->worker_count);

    for (int i = 0; i < engine->worker_count; i++) {
        int rc = pthread_create(&engine->worker_threads[i], NULL, dna_worker_thread, engine);
        if (rc != 0) {
            /* Stop already-started threads */
            atomic_store(&engine->shutdown_requested, true);
            pthread_cond_broadcast(&engine->task_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(engine->worker_threads[j], NULL);
            }
            free(engine->worker_threads);
            engine->worker_threads = NULL;
            engine->worker_count = 0;
            return -1;
        }
    }
    return 0;
}

void dna_stop_workers(dna_engine_t *engine) {
    if (!engine || !engine->worker_threads) return;
    atomic_store(&engine->shutdown_requested, true);

    pthread_mutex_lock(&engine->task_mutex);
    pthread_cond_broadcast(&engine->task_cond);
    pthread_mutex_unlock(&engine->task_mutex);

    for (int i = 0; i < engine->worker_count; i++) {
        pthread_join(engine->worker_threads[i], NULL);
    }

    free(engine->worker_threads);
    engine->worker_threads = NULL;
    engine->worker_count = 0;
}

/* ============================================================================
 * PRESENCE HEARTBEAT (announces our presence every 4 minutes)
 * ============================================================================ */

#define PRESENCE_HEARTBEAT_INTERVAL_SECONDS 240  /* 4 minutes */

static void* presence_heartbeat_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t*)arg;

    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat thread started");

    while (!atomic_load(&engine->shutdown_requested)) {
        /* Sleep in short intervals to respond quickly to shutdown */
        for (int i = 0; i < PRESENCE_HEARTBEAT_INTERVAL_SECONDS; i++) {
            if (atomic_load(&engine->shutdown_requested)) {
                break;
            }
            qgp_platform_sleep(1);
        }

        if (atomic_load(&engine->shutdown_requested)) {
            break;
        }

        /* Only announce presence if active (foreground) */
        if (atomic_load(&engine->presence_active) && engine->messenger) {
            QGP_LOG_DEBUG(LOG_TAG, "Heartbeat: refreshing presence");
            messenger_transport_refresh_presence(engine->messenger);
        }

        /* Check for day rotation on group listeners (runs every 4 min, actual
         * rotation only happens at midnight UTC when day bucket changes) */
        dna_engine_check_group_day_rotation(engine);

        /* Check for day rotation on 1-1 DM outbox listeners (v0.4.81+) */
        dna_engine_check_outbox_day_rotation(engine);
    }

    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat thread stopped");
    return NULL;
}

static int dna_start_presence_heartbeat(dna_engine_t *engine) {
    int rc = pthread_create(&engine->presence_heartbeat_thread, NULL,
                           presence_heartbeat_thread, engine);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start presence heartbeat thread");
        return -1;
    }
    engine->presence_heartbeat_started = true;
    return 0;
}

static void dna_stop_presence_heartbeat(dna_engine_t *engine) {
    /* v0.6.0+: Only join if thread was started (prevents crash on early failure) */
    if (!engine->presence_heartbeat_started) {
        return;
    }
    /* Thread will exit when shutdown_requested is true */
    pthread_join(engine->presence_heartbeat_thread, NULL);
    engine->presence_heartbeat_started = false;
}

void dna_engine_pause_presence(dna_engine_t *engine) {
    if (!engine) return;
    atomic_store(&engine->presence_active, false);
    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat paused (app in background)");
}

void dna_engine_resume_presence(dna_engine_t *engine) {
    if (!engine) return;
    atomic_store(&engine->presence_active, true);
    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat resumed (app in foreground)");

    /* Immediately refresh presence on resume */
    if (engine->messenger) {
        messenger_transport_refresh_presence(engine->messenger);
    }
}

int dna_engine_network_changed(dna_engine_t *engine) {
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "network_changed: NULL engine");
        return -1;
    }

    QGP_LOG_WARN(LOG_TAG, "Network change detected - reinitializing DHT connection");

    /* CRITICAL: Cancel engine-level listeners BEFORE DHT reinit.
     * The listener tokens were issued by the OLD DHT context. We must cancel
     * them while that context still exists, otherwise dht_cancel_listen()
     * silently fails (token not found in new context's map). */
    if (engine->identity_loaded) {
        QGP_LOG_INFO(LOG_TAG, "Cancelling listeners before DHT reinit");
        dna_engine_cancel_all_outbox_listeners(engine);
        dna_engine_cancel_all_presence_listeners(engine);
        dna_engine_cancel_contact_request_listener(engine);
    }

    /* Reinitialize DHT singleton with stored identity.
     * On success, dht_singleton_reinit() fires the status callback which spawns
     * dna_engine_setup_listeners_thread(). That thread handles:
     * - Starting fresh listeners for all contacts
     * - Retrying pending messages
     * - Fetching missed incoming messages
     * - Refreshing presence
     * NO NEED to duplicate that work here - just reinit and let callback handle the rest. */
    int result = dht_singleton_reinit();
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT reinit failed");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "DHT reinit successful - status callback will restart listeners");
    return 0;
}

/* ============================================================================
 * EVENT DISPATCH
 * ============================================================================ */

/* Context for background fetch thread */
typedef struct {
    dna_engine_t *engine;
    char sender_fp[129];  /* Contact fingerprint to fetch from (empty = all) */
} fetch_thread_ctx_t;

/* Background thread for non-blocking message fetch.
 * Called when OUTBOX_UPDATED fires - fetches only from the specific contact.
 * Runs on detached thread so it doesn't block DHT callback thread. */
static void *background_fetch_thread(void *arg) {
    fetch_thread_ctx_t *ctx = (fetch_thread_ctx_t *)arg;
    if (!ctx) return NULL;

    dna_engine_t *engine = ctx->engine;
    const char *sender_fp = ctx->sender_fp[0] ? ctx->sender_fp : NULL;

    /* Delay to let DHT propagate data to more nodes.
     * 100ms was too short - occasionally caused 0 messages due to
     * querying nodes that hadn't received the data yet. */
    qgp_platform_sleep_ms(300);

    if (!engine || !engine->messenger || !engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "[BACKGROUND-THREAD] Engine not ready, aborting fetch");
        free(ctx);
        return NULL;
    }

    /* Retry loop with exponential backoff for DHT propagation delays */
    size_t offline_count = 0;
    int max_retries = 3;
    int delay_ms = 500;  /* Start with 500ms between retries */

    for (int attempt = 0; attempt < max_retries; attempt++) {
        QGP_LOG_INFO(LOG_TAG, "[BACKGROUND-THREAD] Fetching from %s... (attempt %d/%d)",
                     sender_fp ? sender_fp : "ALL contacts", attempt + 1, max_retries);

        messenger_transport_check_offline_messages(engine->messenger, sender_fp, &offline_count);

        if (offline_count > 0) {
            QGP_LOG_INFO(LOG_TAG, "[BACKGROUND-THREAD] Fetch complete: %zu messages", offline_count);
            break;
        }

        /* No messages found - wait and retry (DHT propagation delay) */
        if (attempt < max_retries - 1) {
            QGP_LOG_WARN(LOG_TAG, "[BACKGROUND-THREAD] No messages found, retrying in %dms...", delay_ms);
            qgp_platform_sleep_ms(delay_ms);
            delay_ms *= 2;  /* Exponential backoff: 500, 1000, 2000... */
        } else {
            QGP_LOG_INFO(LOG_TAG, "[BACKGROUND-THREAD] Fetch complete: 0 messages after %d attempts", max_retries);
        }
    }

    free(ctx);
    return NULL;
}

void dna_dispatch_event(dna_engine_t *engine, const dna_event_t *event) {
    pthread_mutex_lock(&engine->event_mutex);
    dna_event_cb callback = engine->event_callback;
    void *user_data = engine->event_user_data;
    bool disposing = engine->callback_disposing;
    pthread_mutex_unlock(&engine->event_mutex);

    /* Don't invoke callback if it's being disposed (prevents crash when
     * Dart NativeCallable is closed while C still holds the pointer) */
    bool flutter_attached = (callback && !disposing);

    /* Debug logging for MESSAGE_SENT event dispatch */
    if (event->type == DNA_EVENT_MESSAGE_SENT) {
        QGP_LOG_WARN(LOG_TAG, "[EVENT] MESSAGE_SENT dispatch: callback=%p, disposing=%d, attached=%d, status=%d",
                     (void*)callback, disposing, flutter_attached, event->data.message_status.new_status);
    }

    /* Debug logging for GROUP_MESSAGE_RECEIVED event dispatch */
    if (event->type == DNA_EVENT_GROUP_MESSAGE_RECEIVED) {
        QGP_LOG_INFO(LOG_TAG, "[EVENT] GROUP_MESSAGE dispatch: callback=%p, disposing=%d, attached=%d",
                     (void*)callback, disposing, flutter_attached);
    }

    if (flutter_attached) {
        /* Heap-allocate a copy for async callbacks (Dart NativeCallable.listener)
         * The caller (Dart) must call dna_free_event() after processing */
        dna_event_t *heap_event = calloc(1, sizeof(dna_event_t));
        if (heap_event) {
            memcpy(heap_event, event, sizeof(dna_event_t));
            callback(heap_event, user_data);
            if (event->type == DNA_EVENT_MESSAGE_SENT) {
                QGP_LOG_WARN(LOG_TAG, "[EVENT] MESSAGE_SENT callback invoked");
            }
            if (event->type == DNA_EVENT_GROUP_MESSAGE_RECEIVED) {
                QGP_LOG_INFO(LOG_TAG, "[EVENT] GROUP_MESSAGE callback invoked");
            }
        }
    }

#ifdef __ANDROID__
    /* Android: When OUTBOX_UPDATED fires and Flutter is NOT attached, just show notification.
     * Don't fetch - let Flutter handle fetching when user opens app.
     * This avoids race conditions between C auto-fetch and Flutter fetch. */
    if (event->type == DNA_EVENT_OUTBOX_UPDATED) {
        QGP_LOG_INFO(LOG_TAG, "[ANDROID-NOTIFY] OUTBOX_UPDATED: cb=%p flutter_attached=%d",
                     (void*)g_android_notification_cb, flutter_attached);
    }
    if (event->type == DNA_EVENT_OUTBOX_UPDATED && g_android_notification_cb && !flutter_attached) {
        const char *contact_fp = event->data.outbox_updated.contact_fingerprint;
        const char *display_name = NULL;
        char name_buf[256] = {0};

        /* Try to get display name from profile cache */
        dna_unified_identity_t *cached = NULL;
        uint64_t cached_at = 0;
        if (profile_cache_get(contact_fp, &cached, &cached_at) == 0 && cached) {
            if (cached->display_name[0]) {
                strncpy(name_buf, cached->display_name, sizeof(name_buf) - 1);
                display_name = name_buf;
            } else if (cached->registered_name[0]) {
                strncpy(name_buf, cached->registered_name, sizeof(name_buf) - 1);
                display_name = name_buf;
            }
            dna_identity_free(cached);
        }

        QGP_LOG_INFO(LOG_TAG, "[ANDROID-NOTIFY] Flutter detached, notifying: fp=%.16s... name=%s",
                     contact_fp, display_name ? display_name : "(unknown)");
        g_android_notification_cb(contact_fp, display_name, g_android_notification_data);
    }
#endif

    /* Android notification callback - called for MESSAGE_RECEIVED events
     * (incoming messages only). This allows Android to show native
     * notifications when app is backgrounded. */
    if (event->type == DNA_EVENT_MESSAGE_RECEIVED && g_android_notification_cb) {
        /* Only notify for incoming messages, not our own sent messages */
        if (!event->data.message_received.message.is_outgoing) {
            const char *fp = event->data.message_received.message.sender;
            const char *display_name = NULL;
            char name_buf[256] = {0};

            /* Try to get display name from profile cache */
            dna_unified_identity_t *cached = NULL;
            uint64_t cached_at = 0;
            if (profile_cache_get(fp, &cached, &cached_at) == 0 && cached) {
                if (cached->display_name[0]) {
                    strncpy(name_buf, cached->display_name, sizeof(name_buf) - 1);
                    display_name = name_buf;
                } else if (cached->registered_name[0]) {
                    strncpy(name_buf, cached->registered_name, sizeof(name_buf) - 1);
                    display_name = name_buf;
                }
                dna_identity_free(cached);
            }

            QGP_LOG_INFO(LOG_TAG, "[ANDROID-NOTIFY] Calling callback: fp=%.16s... name=%s",
                         fp, display_name ? display_name : "(unknown)");
            g_android_notification_cb(fp, display_name, g_android_notification_data);
        }
    }

#ifdef __ANDROID__
    /* Android: Contact request notification - show notification when request arrives */
    if (event->type == DNA_EVENT_CONTACT_REQUEST_RECEIVED && g_android_contact_request_cb) {
        const char *user_fingerprint = event->data.contact_request_received.request.fingerprint;
        const char *user_display_name = event->data.contact_request_received.request.display_name;

        QGP_LOG_INFO(LOG_TAG, "[ANDROID-CONTACT-REQ] Contact request from %.16s... name=%s",
                     user_fingerprint, user_display_name[0] ? user_display_name : "(unknown)");
        g_android_contact_request_cb(user_fingerprint,
                                     user_display_name[0] ? user_display_name : NULL,
                                     g_android_contact_request_data);
    }
#endif
}

void dna_free_event(dna_event_t *event) {
    if (event) {
        free(event);
    }
}

/* ============================================================================
 * TASK EXECUTION DISPATCH
 * ============================================================================ */

/* Forward declarations for handlers defined later */
void dna_handle_refresh_contact_profile(dna_engine_t *engine, dna_task_t *task);
void dna_handle_add_group_member(dna_engine_t *engine, dna_task_t *task);

void dna_execute_task(dna_engine_t *engine, dna_task_t *task) {
    switch (task->type) {
        /* Identity */
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
        case TASK_REFRESH_CONTACT_PROFILE:
            dna_handle_refresh_contact_profile(engine, task);
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
        case TASK_GET_CONVERSATION_PAGE:
            dna_handle_get_conversation_page(engine, task);
            break;
        case TASK_CHECK_OFFLINE_MESSAGES:
            dna_handle_check_offline_messages(engine, task);
            break;

        /* Groups */
        case TASK_GET_GROUPS:
            dna_handle_get_groups(engine, task);
            break;
        case TASK_GET_GROUP_INFO:
            dna_handle_get_group_info(engine, task);
            break;
        case TASK_GET_GROUP_MEMBERS:
            dna_handle_get_group_members(engine, task);
            break;
        case TASK_CREATE_GROUP:
            dna_handle_create_group(engine, task);
            break;
        case TASK_SEND_GROUP_MESSAGE:
            dna_handle_send_group_message(engine, task);
            break;
        case TASK_GET_GROUP_CONVERSATION:
            dna_handle_get_group_conversation(engine, task);
            break;
        case TASK_ADD_GROUP_MEMBER:
            dna_handle_add_group_member(engine, task);
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
        case TASK_SYNC_GROUPS_TO_DHT:
            dna_handle_sync_groups_to_dht(engine, task);
            break;
        case TASK_SYNC_GROUP_BY_UUID:
            dna_handle_sync_group_by_uuid(engine, task);
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

    /* v0.6.0+: Initialize DHT context and identity lock (will be set during identity load) */
    engine->dht_ctx = NULL;
    engine->identity_lock_fd = -1;

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
    engine->callback_disposing = false;  /* Explicit init for callback race protection */
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

    /* Initialize presence listeners */
    pthread_mutex_init(&engine->presence_listeners_mutex, NULL);
    engine->presence_listener_count = 0;
    memset(engine->presence_listeners, 0, sizeof(engine->presence_listeners));

    /* Initialize contact request listener */
    pthread_mutex_init(&engine->contact_request_listener_mutex, NULL);
    engine->contact_request_listener.dht_token = 0;
    engine->contact_request_listener.active = false;

    /* Initialize delivery trackers */
    pthread_mutex_init(&engine->watermark_listeners_mutex, NULL);
    engine->watermark_listener_count = 0;
    memset(engine->watermark_listeners, 0, sizeof(engine->watermark_listeners));

    /* Initialize group outbox listeners */
    pthread_mutex_init(&engine->group_listen_mutex, NULL);
    engine->group_listen_count = 0;
    memset(engine->group_listen_contexts, 0, sizeof(engine->group_listen_contexts));

    /* v0.6.0+: Initialize background thread tracking */
    pthread_mutex_init(&engine->background_threads_mutex, NULL);
    engine->setup_listeners_running = false;
    engine->stabilization_retry_running = false;

    /* Initialize task queue */
    dna_task_queue_init(&engine->task_queue);

    /* Initialize request ID counter */
    atomic_store(&engine->next_request_id, 0);

    /* Initialize presence heartbeat as active (will start thread after identity load) */
    atomic_store(&engine->presence_active, true);

    /* DHT is NOT initialized here - only after identity is created/restored
     * via dht_singleton_init_with_identity() in messenger/init.c */

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
    /* If clearing the callback, set disposing flag FIRST to prevent races
     * where another thread copies the callback before we clear it */
    if (callback == NULL && engine->event_callback != NULL) {
        engine->callback_disposing = true;
    } else {
        engine->callback_disposing = false;
    }
    engine->event_callback = callback;
    engine->event_user_data = user_data;
    pthread_mutex_unlock(&engine->event_mutex);
}

void dna_engine_set_android_notification_callback(
    dna_android_notification_cb callback,
    void *user_data
) {
    g_android_notification_cb = callback;
    g_android_notification_data = user_data;
    QGP_LOG_INFO(LOG_TAG, "Android notification callback %s",
                 callback ? "registered" : "cleared");
}

void dna_engine_set_android_group_message_callback(
    dna_android_group_message_cb callback,
    void *user_data
) {
    g_android_group_message_cb = callback;
    g_android_group_message_data = user_data;
    QGP_LOG_INFO(LOG_TAG, "Android group message callback %s",
                 callback ? "registered" : "cleared");
}

void dna_engine_set_android_contact_request_callback(
    dna_android_contact_request_cb callback,
    void *user_data
) {
    g_android_contact_request_cb = callback;
    g_android_contact_request_data = user_data;
    QGP_LOG_INFO(LOG_TAG, "Android contact request callback %s",
                 callback ? "registered" : "cleared");
}

/* Internal helper to fire Android group message callback.
 * Called from group outbox subscribe on_new_message callback. */
void dna_engine_fire_group_message_callback(
    const char *group_uuid,
    const char *group_name,
    size_t new_count
) {
    if (g_android_group_message_cb && new_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Firing group message callback: group=%s count=%zu",
                     group_uuid, new_count);
        g_android_group_message_cb(group_uuid, group_name, new_count,
                                   g_android_group_message_data);
    }
}

/* Callback for group message notifications from dna_group_outbox_subscribe() */
static void on_group_new_message(const char *group_uuid, size_t new_count, void *user_data) {
    (void)user_data;
    QGP_LOG_INFO(LOG_TAG, "[GROUP] New messages: group=%s count=%zu", group_uuid, new_count);

    /* Get group name from local database for notification */
    char group_name[256] = "";
    groups_info_t group_info;
    if (groups_get_info(group_uuid, &group_info) == 0) {
        strncpy(group_name, group_info.name, sizeof(group_name) - 1);
    }

    /* Fire Android callback */
    dna_engine_fire_group_message_callback(group_uuid,
        group_name[0] ? group_name : NULL, new_count);

    /* Fire DNA event */
    dna_engine_t *engine = dna_engine_get_global();
    if (engine) {
        dna_event_t event = {0};
        event.type = DNA_EVENT_GROUP_MESSAGE_RECEIVED;
        strncpy(event.data.group_message.group_uuid, group_uuid,
                sizeof(event.data.group_message.group_uuid) - 1);
        event.data.group_message.new_count = (int)new_count;
        dna_dispatch_event(engine, &event);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "[GROUP] Cannot dispatch - engine is NULL!");
    }
}

int dna_engine_subscribe_all_groups(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Cannot subscribe - no identity loaded");
        return 0;
    }

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Cannot subscribe - DHT not available");
        return 0;
    }

    /* Get all groups user is member of */
    dht_group_cache_entry_t *groups = NULL;
    int group_count = 0;
    QGP_LOG_WARN(LOG_TAG, "[GROUP] Subscribing for identity %.16s...", engine->fingerprint);
    int ret = dht_groups_list_for_user(engine->fingerprint, &groups, &group_count);
    QGP_LOG_WARN(LOG_TAG, "[GROUP] dht_groups_list_for_user returned %d, count=%d", ret, group_count);
    if (ret != 0 || group_count == 0) {
        QGP_LOG_WARN(LOG_TAG, "[GROUP] No groups to subscribe to (ret=%d, count=%d)", ret, group_count);
        if (groups) {
            dht_groups_free_cache_entries(groups, group_count);
        }
        return 0;
    }

    int subscribed = 0;
    pthread_mutex_lock(&engine->group_listen_mutex);
    QGP_LOG_WARN(LOG_TAG, "[GROUP] Loop start: group_count=%d, listen_count=%d, max=%d",
                 group_count, engine->group_listen_count, DNA_MAX_GROUP_LISTENERS);

    for (int i = 0; i < group_count && engine->group_listen_count < DNA_MAX_GROUP_LISTENERS; i++) {
        const char *group_uuid = groups[i].group_uuid;
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Processing group[%d]: %s", i, group_uuid);

        /* Check if already subscribed */
        bool already_subscribed = false;
        for (int j = 0; j < engine->group_listen_count; j++) {
            if (engine->group_listen_contexts[j] &&
                strcmp(engine->group_listen_contexts[j]->group_uuid, group_uuid) == 0) {
                already_subscribed = true;
                QGP_LOG_WARN(LOG_TAG, "[GROUP] Already subscribed to %s (slot %d)", group_uuid, j);
                break;
            }
        }
        if (already_subscribed) continue;

        /* Single-key architecture: No need to get members for subscription.
         * All members write to the same key with different value_id.
         * Single dht_listen() on the shared key catches ALL member updates.
         */

        /* Full sync before subscribing (catch up on last 7 days) */
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Syncing group %s...", group_uuid);
        size_t sync_count = 0;
        dna_group_outbox_sync(dht_ctx, group_uuid, &sync_count);
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Sync done: %zu messages", sync_count);

        /* Subscribe for real-time updates - single listener per group */
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Subscribing to group %s...", group_uuid);
        dna_group_listen_ctx_t *ctx = NULL;
        ret = dna_group_outbox_subscribe(dht_ctx, group_uuid,
                                          on_group_new_message, NULL, &ctx);
        if (ret == 0 && ctx) {
            engine->group_listen_contexts[engine->group_listen_count++] = ctx;
            subscribed++;
            QGP_LOG_WARN(LOG_TAG, "[GROUP] ✓ Subscribed to group %s (slot %d)",
                         group_uuid, engine->group_listen_count - 1);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "[GROUP] ✗ Failed to subscribe to group %s: ret=%d ctx=%p",
                          group_uuid, ret, (void*)ctx);
        }
    }

    pthread_mutex_unlock(&engine->group_listen_mutex);
    dht_groups_free_cache_entries(groups, group_count);

    QGP_LOG_WARN(LOG_TAG, "[GROUP] Subscribe complete: %d groups subscribed", subscribed);
    return subscribed;
}

void dna_engine_unsubscribe_all_groups(dna_engine_t *engine) {
    if (!engine) return;

    dht_context_t *dht_ctx = dht_singleton_get();

    pthread_mutex_lock(&engine->group_listen_mutex);

    for (int i = 0; i < engine->group_listen_count; i++) {
        if (engine->group_listen_contexts[i]) {
            dna_group_outbox_unsubscribe(dht_ctx, engine->group_listen_contexts[i]);
            engine->group_listen_contexts[i] = NULL;
        }
    }
    engine->group_listen_count = 0;

    pthread_mutex_unlock(&engine->group_listen_mutex);

    QGP_LOG_INFO(LOG_TAG, "[GROUP] Unsubscribed from all groups");
}

int dna_engine_check_group_day_rotation(dna_engine_t *engine) {
    if (!engine) return 0;

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) return 0;

    int rotated = 0;
    pthread_mutex_lock(&engine->group_listen_mutex);

    for (int i = 0; i < engine->group_listen_count; i++) {
        if (engine->group_listen_contexts[i]) {
            int result = dna_group_outbox_check_day_rotation(
                dht_ctx, engine->group_listen_contexts[i]);
            if (result > 0) {
                rotated++;
                QGP_LOG_INFO(LOG_TAG, "[GROUP] Day rotation for group %s",
                             engine->group_listen_contexts[i]->group_uuid);
            }
        }
    }

    pthread_mutex_unlock(&engine->group_listen_mutex);

    if (rotated > 0) {
        QGP_LOG_INFO(LOG_TAG, "[GROUP] Day rotation completed for %d groups", rotated);
    }
    return rotated;
}

/**
 * @brief Check and rotate day bucket for 1-1 DM outbox listeners
 *
 * Called from heartbeat thread every 4 minutes. Actual rotation only happens
 * at midnight UTC when the day bucket number changes.
 *
 * Flow:
 * 1. Get current day bucket
 * 2. For each active listener, check if day changed
 * 3. If changed: cancel old listener, subscribe to new day, sync yesterday
 *
 * @param engine Engine instance
 * @return Number of listeners rotated (0 if no change)
 */
int dna_engine_check_outbox_day_rotation(dna_engine_t *engine) {
    if (!engine) return 0;

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) return 0;

    int rotated = 0;
    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            engine->outbox_listeners[i].dm_listen_ctx) {

            int result = dht_dm_outbox_check_day_rotation(
                dht_ctx, engine->outbox_listeners[i].dm_listen_ctx);

            if (result > 0) {
                rotated++;
                QGP_LOG_INFO(LOG_TAG, "[DM-OUTBOX] Day rotation for contact %.32s...",
                             engine->outbox_listeners[i].contact_fingerprint);
            }
        }
    }

    pthread_mutex_unlock(&engine->outbox_listeners_mutex);

    if (rotated > 0) {
        QGP_LOG_INFO(LOG_TAG, "[DM-OUTBOX] Day rotation completed for %d contacts", rotated);
    }
    return rotated;
}

void dna_engine_destroy(dna_engine_t *engine) {
    if (!engine) return;

#ifdef __ANDROID__
    /* ANDROID: Release identity lock FIRST before any cleanup.
     * This allows ForegroundService to take over DHT immediately.
     * If destroy crashes later due to callback races, lock is already released.
     * The OS will clean up leaked memory when process dies. */
    if (engine->identity_lock_fd >= 0) {
        QGP_LOG_INFO(LOG_TAG, "Android: Releasing identity lock early (fd=%d)",
                     engine->identity_lock_fd);
        qgp_platform_release_identity_lock(engine->identity_lock_fd);
        engine->identity_lock_fd = -1;
    }
#endif

    /* Clear DHT status callback before stopping anything */
    if (g_dht_callback_engine == engine) {
        dht_singleton_set_status_callback(NULL, NULL);
        g_dht_callback_engine = NULL;
    }

    /* Stop worker threads (also sets shutdown_requested = true) */
    dna_stop_workers(engine);

    /* v0.6.0+: Wait for background threads to exit (they check shutdown_requested) */
    pthread_mutex_lock(&engine->background_threads_mutex);
    bool join_setup = engine->setup_listeners_running;
    bool join_stab = engine->stabilization_retry_running;
    pthread_mutex_unlock(&engine->background_threads_mutex);

    if (join_setup) {
        QGP_LOG_INFO(LOG_TAG, "Waiting for setup_listeners thread to exit...");
        pthread_join(engine->setup_listeners_thread, NULL);
        QGP_LOG_INFO(LOG_TAG, "setup_listeners thread exited");
    }
    if (join_stab) {
        QGP_LOG_INFO(LOG_TAG, "Waiting for stabilization_retry thread to exit...");
        pthread_join(engine->stabilization_retry_thread, NULL);
        QGP_LOG_INFO(LOG_TAG, "stabilization_retry thread exited");
    }
    pthread_mutex_destroy(&engine->background_threads_mutex);

    /* Stop presence heartbeat thread */
    dna_stop_presence_heartbeat(engine);

    /* Clear GEK KEM keys (H3 security fix) */
    gek_clear_kem_keys();

    /* Free messenger context */
    if (engine->messenger) {
        messenger_free(engine->messenger);
    }

    /* Free wallet list */
    // NOTE: engine->wallet_list removed in v0.3.150 - was never assigned (dead code)
    if (engine->blockchain_wallets) {
        blockchain_wallet_list_free(engine->blockchain_wallets);
    }

    /* Cancel all outbox listeners */
    dna_engine_cancel_all_outbox_listeners(engine);
    pthread_mutex_destroy(&engine->outbox_listeners_mutex);

    /* Cancel all presence listeners */
    dna_engine_cancel_all_presence_listeners(engine);
    pthread_mutex_destroy(&engine->presence_listeners_mutex);

    /* Cancel contact request listener */
    dna_engine_cancel_contact_request_listener(engine);
    pthread_mutex_destroy(&engine->contact_request_listener_mutex);

    /* Cancel all watermark listeners */
    dna_engine_cancel_all_watermark_listeners(engine);
    pthread_mutex_destroy(&engine->watermark_listeners_mutex);

    /* Unsubscribe from all groups */
    dna_engine_unsubscribe_all_groups(engine);
    pthread_mutex_destroy(&engine->group_listen_mutex);

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

    /* v0.6.0+: Cleanup engine-owned DHT context */
    if (engine->dht_ctx) {
        QGP_LOG_INFO(LOG_TAG, "Cleaning up engine-owned DHT context");
        /* Clear borrowed context from singleton FIRST (prevents use-after-free) */
        dht_singleton_set_borrowed_context(NULL);
        /* Now safe to free the context */
        dht_context_stop(engine->dht_ctx);
        dht_context_free(engine->dht_ctx);
        engine->dht_ctx = NULL;
    }

    /* v0.6.0+: Release identity lock */
    if (engine->identity_lock_fd >= 0) {
        QGP_LOG_INFO(LOG_TAG, "Releasing identity lock (fd=%d)", engine->identity_lock_fd);
        qgp_platform_release_identity_lock(engine->identity_lock_fd);
        engine->identity_lock_fd = -1;
    }

    /* Securely clear session password */
    if (engine->session_password) {
        qgp_secure_memzero(engine->session_password, strlen(engine->session_password));
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
 * IDENTITY TASK HANDLERS
 * ============================================================================ */

/* v0.3.0: dna_scan_identities() and dna_handle_list_identities() removed
 * Single-user model - use dna_engine_has_identity() instead */

void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task) {
    char fingerprint_buf[129] = {0};

    int rc = messenger_generate_keys_from_seeds(
        task->params.create_identity.name,
        task->params.create_identity.signing_seed,
        task->params.create_identity.encryption_seed,
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
        /* Mark profile as just published - skip DHT verification in load_identity */
        engine->profile_published_at = time(NULL);
    }

    task->callback.identity_created(
        task->request_id,
        error,
        fingerprint,
        task->user_data
    );
}

void dna_handle_load_identity(dna_engine_t *engine, dna_task_t *task) {
    const char *password = task->params.load_identity.password;
    int error = DNA_OK;

    /* v0.3.0: Compute fingerprint from flat key file if not provided */
    char fingerprint_buf[129] = {0};
    const char *fingerprint = task->params.load_identity.fingerprint;
    if (!fingerprint || fingerprint[0] == '\0' || strlen(fingerprint) != 128) {
        /* Compute from identity.dsa */
        if (messenger_compute_identity_fingerprint(NULL, fingerprint_buf) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "No identity found - cannot compute fingerprint");
            error = DNA_ENGINE_ERROR_NO_IDENTITY;
            goto done;
        }
        fingerprint = fingerprint_buf;
        QGP_LOG_INFO(LOG_TAG, "v0.3.0: Computed fingerprint from flat key file");
    }

    /* v0.6.0+: Acquire identity lock (single-owner model)
     * Prevents Flutter and ForegroundService from running simultaneously */
    if (engine->identity_lock_fd < 0) {
        engine->identity_lock_fd = qgp_platform_acquire_identity_lock(engine->data_dir);
        if (engine->identity_lock_fd < 0) {
            QGP_LOG_WARN(LOG_TAG, "Identity lock held by another process - cannot load");
            error = DNA_ENGINE_ERROR_IDENTITY_LOCKED;
            goto done;
        }
        QGP_LOG_INFO(LOG_TAG, "v0.6.0+: Identity lock acquired (fd=%d)", engine->identity_lock_fd);
    }

    /* Free existing session password if any */
    if (engine->session_password) {
        /* Secure clear before freeing */
        qgp_secure_memzero(engine->session_password, strlen(engine->session_password));
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
    /* v0.3.0: Flat structure - keys/identity.kem */
    {
        char kem_path[512];
        snprintf(kem_path, sizeof(kem_path), "%s/keys/identity.kem", engine->data_dir);

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

    /* v0.6.0+: Load DHT identity and create engine-owned context */
    if (messenger_load_dht_identity_for_engine(fingerprint, &engine->dht_ctx) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Engine-owned DHT context created");
        /* Lend context to singleton for backwards compatibility with code that
         * still uses dht_singleton_get() directly */
        dht_singleton_set_borrowed_context(engine->dht_ctx);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Failed to create engine DHT context (falling back to singleton)");
        /* Fallback: try singleton-based load for compatibility */
        messenger_load_dht_identity(fingerprint);
    }

    /* Load KEM keys for GEK encryption (H3 security fix) */
    {
        char kem_path[512];
        snprintf(kem_path, sizeof(kem_path), "%s/keys/identity.kem", engine->data_dir);

        qgp_key_t *kem_key = NULL;
        int load_rc;
        if (engine->keys_encrypted && engine->session_password) {
            load_rc = qgp_key_load_encrypted(kem_path, engine->session_password, &kem_key);
        } else {
            load_rc = qgp_key_load(kem_path, &kem_key);
        }

        if (load_rc == 0 && kem_key && kem_key->public_key && kem_key->private_key) {
            if (gek_set_kem_keys(kem_key->public_key, kem_key->private_key) == 0) {
                QGP_LOG_INFO(LOG_TAG, "GEK KEM keys set successfully");
            } else {
                QGP_LOG_WARN(LOG_TAG, "Warning: Failed to set GEK KEM keys");
            }
            qgp_key_free(kem_key);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Warning: Failed to load KEM keys for GEK encryption");
            if (kem_key) qgp_key_free(kem_key);
        }
    }

    /* Initialize contacts database BEFORE P2P/offline message check
     * This is required because offline message check queries contacts' outboxes */
    if (contacts_db_init(fingerprint) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize contacts database\n");
        /* Non-fatal - continue, contacts will be initialized on first access */
    }

    /* Initialize group invitations database BEFORE P2P message processing
     * Required for storing incoming group invitations from P2P messages */
    if (group_invitations_init(fingerprint) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize group invitations database\n");
        /* Non-fatal - continue, invitations will be initialized on first access */
    }

    /* Profile cache is now global - initialized in dna_engine_create() */

    /* Check if minimal mode (background service) - skip heavy initialization */
    bool minimal_mode = task->params.load_identity.minimal;
    if (minimal_mode) {
        QGP_LOG_INFO(LOG_TAG, "Minimal mode: skipping transport, presence, wallet init");
    }

    /* Full mode only: Sync contacts from DHT (restore on new device)
     * This must happen BEFORE subscribing to contacts for push notifications.
     * If DHT has a newer contact list, it will be merged into local SQLite. */
    if (!minimal_mode && engine->messenger) {
        int sync_result = messenger_sync_contacts_from_dht(engine->messenger);
        if (sync_result == 0) {
            QGP_LOG_INFO(LOG_TAG, "Synced contacts from DHT");
        } else if (sync_result == -2) {
            QGP_LOG_INFO(LOG_TAG, "No contact list in DHT (new identity or first device)");
        } else {
            QGP_LOG_INFO(LOG_TAG, "Warning: Failed to sync contacts from DHT");
        }
    }

    /* Full mode only: Initialize P2P transport for DHT and messaging */
    if (!minimal_mode) {
        if (messenger_transport_init(engine->messenger) != 0) {
            QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize P2P transport\n");
            /* Non-fatal - continue without P2P, DHT operations will still work via singleton */
        } else {
            /* P2P initialized successfully - complete P2P setup */
            /* Note: Presence already registered in messenger_transport_init() */

            /* PERF: Skip full offline sync on startup - lazy sync when user opens chat.
             * Listeners will catch NEW messages. Old messages sync via checkContactOffline(). */
            QGP_LOG_INFO(LOG_TAG, "Skipping offline sync (lazy loading enabled)\n");

            /* Start presence heartbeat thread (announces our presence every 4 minutes) */
            if (dna_start_presence_heartbeat(engine) != 0) {
                QGP_LOG_WARN(LOG_TAG, "Warning: Failed to start presence heartbeat");
            }
        }
    }

    /* Mark identity as loaded BEFORE starting listeners (they check this flag) */
    engine->identity_loaded = true;
    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity loaded, identity_loaded flag set to true");

    /* PERF: Skip automatic listener setup - Flutter uses lazy loading,
     * Service calls listen_all_contacts explicitly after identity load.
     * Contact request listener is lightweight, always start it.
     * Groups still need subscription for real-time messages. */
    if (engine->messenger) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Identity load: skipping auto-listeners (lazy loading)");
        dna_engine_start_contact_request_listener(engine);

        /* Subscribe to group outboxes for real-time group messages.
         * This is critical: DHT usually connects before identity loads, so the
         * background thread (dna_engine_setup_listeners_thread) never runs.
         * We must subscribe to groups here after identity loads. */
        int group_count = dna_engine_subscribe_all_groups(engine);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: subscribed to %d groups", group_count);

        /* Full mode only: Retry pending messages and spawn stabilization thread */
        if (!minimal_mode) {
            /* 3. Retry any pending/failed messages from previous sessions
             * Messages may have been queued while offline or failed to send.
             * Now that DHT is connected, retry them. */
            int retried = dna_engine_retry_pending_messages(engine);
            if (retried > 0) {
                QGP_LOG_INFO(LOG_TAG, "[RETRY] Identity load: retried %d pending messages", retried);
            }

            /* Spawn post-stabilization retry thread.
             * DHT callback's listener thread only spawns if identity_loaded was true
             * when callback fired. In the common case (DHT connects before identity
             * loads), we need this dedicated thread to retry after routing table fills.
             * v0.6.0+: Track thread for clean shutdown (no detach) */
            QGP_LOG_WARN(LOG_TAG, "[RETRY] About to spawn stabilization thread (engine=%p, messenger=%p)",
                         (void*)engine, (void*)engine->messenger);
            pthread_mutex_lock(&engine->background_threads_mutex);
            if (engine->stabilization_retry_running) {
                /* Previous thread still running - skip */
                pthread_mutex_unlock(&engine->background_threads_mutex);
                QGP_LOG_WARN(LOG_TAG, "[RETRY] Stabilization thread already running, skipping");
            } else {
                engine->stabilization_retry_running = true;
                pthread_mutex_unlock(&engine->background_threads_mutex);
                int spawn_rc = pthread_create(&engine->stabilization_retry_thread, NULL,
                                              dna_engine_stabilization_retry_thread, engine);
                QGP_LOG_WARN(LOG_TAG, "[RETRY] pthread_create returned %d", spawn_rc);
                if (spawn_rc == 0) {
                    QGP_LOG_WARN(LOG_TAG, "[RETRY] Stabilization thread spawned successfully");
                } else {
                    pthread_mutex_lock(&engine->background_threads_mutex);
                    engine->stabilization_retry_running = false;
                    pthread_mutex_unlock(&engine->background_threads_mutex);
                    QGP_LOG_ERROR(LOG_TAG, "[RETRY] FAILED to spawn stabilization thread: rc=%d", spawn_rc);
                }
            }
        }

        /* Note: Delivery confirmation is now handled by persistent watermark listeners
         * started in dna_engine_listen_all_contacts() for each contact. */
    }

    /* Full mode only: Create any missing blockchain wallets
     * This uses the encrypted seed stored during identity creation.
     * Non-fatal if seed doesn't exist or wallet creation fails.
     * v0.3.0: Flat structure - keys/identity.kem */
    if (!minimal_mode) {
        char kyber_path[512];
        snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", engine->data_dir);

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

    /* NOTE: Removed blocking DHT profile verification (v0.3.141)
     *
     * Previously, this code did a blocking 30-second DHT lookup of OUR OWN
     * profile to verify it exists and has wallet addresses. This caused the
     * app to hang for 30 seconds on startup if the profile wasn't in DHT.
     *
     * Profile is now published on:
     * - Account creation (keygen)
     * - Name registration
     * - Profile edit
     *
     * If the profile is missing from DHT, user can re-register name or
     * edit profile to republish. No need for blocking verification on startup.
     */
    (void)0;  /* Empty statement to satisfy compiler */

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

    /* Display name - fallback to registered_name if display_name is empty */
    if (identity->display_name[0] != '\0') {
        strncpy(profile->display_name, identity->display_name, sizeof(profile->display_name) - 1);
    } else if (identity->registered_name[0] != '\0') {
        strncpy(profile->display_name, identity->registered_name, sizeof(profile->display_name) - 1);
    }

    /* Location and website */
    strncpy(profile->location, identity->location, sizeof(profile->location) - 1);
    strncpy(profile->website, identity->website, sizeof(profile->website) - 1);

    /* DEBUG: Log avatar data after copy to profile (WARN level to ensure visibility) */
    {
        size_t src_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
        size_t dst_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        (void)src_len; (void)dst_len;  // Used only in debug builds
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
                    /* Update profile in DHT - profile is already a dna_profile_t* */
                    int update_rc = dna_update_profile(dht, engine->fingerprint, profile,
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
        (void)avatar_len;  // Used only in debug builds
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
        (void)src_len; (void)dst_len;  // Used only in debug builds
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] lookup_profile: src_len=%zu, dst_len=%zu (first 20: %.20s)\n",
                     src_len, dst_len, dst_len > 0 ? profile->avatar_base64 : "(empty)");
    }

    /* Display name - fallback to registered_name if display_name is empty */
    if (identity->display_name[0] != '\0') {
        strncpy(profile->display_name, identity->display_name, sizeof(profile->display_name) - 1);
    } else if (identity->registered_name[0] != '\0') {
        strncpy(profile->display_name, identity->registered_name, sizeof(profile->display_name) - 1);
    }

    dna_identity_free(identity);

done:
    task->callback.profile(task->request_id, error, profile, task->user_data);
}

void dna_handle_refresh_contact_profile(dna_engine_t *engine, dna_task_t *task) {
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

    QGP_LOG_INFO(LOG_TAG, "Force refresh contact profile: %.16s...\n", fingerprint);

    /* Force refresh from DHT (bypass cache) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_refresh_profile(fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            error = DNA_ENGINE_ERROR_NOT_FOUND;
        } else if (rc == -3) {
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

    QGP_LOG_INFO(LOG_TAG, "Refreshed profile avatar: %zu bytes\n",
                 identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0);

    /* Display name */
    if (identity->display_name[0] != '\0') {
        strncpy(profile->display_name, identity->display_name, sizeof(profile->display_name) - 1);
    } else if (identity->registered_name[0] != '\0') {
        strncpy(profile->display_name, identity->registered_name, sizeof(profile->display_name) - 1);
    }

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

    /* Pass profile directly to DHT update (no more dna_profile_data_t conversion) */
    const dna_profile_t *p = &task->params.update_profile.profile;

    size_t avatar_len = p->avatar_base64[0] ? strlen(p->avatar_base64) : 0;
    QGP_LOG_INFO(LOG_TAG, "update_profile: avatar=%zu bytes, location='%s', website='%s'\n",
                 avatar_len, p->location, p->website);

    /* Update profile in DHT */
    int rc = dna_update_profile(dht, engine->fingerprint, p,
                                 sign_key->private_key, sign_key->public_key,
                                 enc_key->public_key);

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Update local cache directly (don't fetch from DHT - propagation delay) */
        dna_unified_identity_t *cached = NULL;
        uint64_t cached_at = 0;
        int cache_rc = profile_cache_get(engine->fingerprint, &cached, &cached_at);

        if (cache_rc != 0 || !cached) {
            /* No cached profile - create one */
            cached = (dna_unified_identity_t*)calloc(1, sizeof(dna_unified_identity_t));
            if (cached) {
                strncpy(cached->fingerprint, engine->fingerprint, sizeof(cached->fingerprint) - 1);
                cached->created_at = (uint64_t)time(NULL);
            }
        }

        if (cached) {
            /* Update all profile fields in cache */
            strncpy(cached->wallets.backbone, p->backbone, sizeof(cached->wallets.backbone) - 1);
            strncpy(cached->wallets.alvin, p->alvin, sizeof(cached->wallets.alvin) - 1);
            strncpy(cached->wallets.eth, p->eth, sizeof(cached->wallets.eth) - 1);
            strncpy(cached->wallets.sol, p->sol, sizeof(cached->wallets.sol) - 1);
            strncpy(cached->wallets.trx, p->trx, sizeof(cached->wallets.trx) - 1);

            strncpy(cached->socials.telegram, p->telegram, sizeof(cached->socials.telegram) - 1);
            strncpy(cached->socials.x, p->twitter, sizeof(cached->socials.x) - 1);
            strncpy(cached->socials.github, p->github, sizeof(cached->socials.github) - 1);
            strncpy(cached->socials.facebook, p->facebook, sizeof(cached->socials.facebook) - 1);
            strncpy(cached->socials.instagram, p->instagram, sizeof(cached->socials.instagram) - 1);
            strncpy(cached->socials.linkedin, p->linkedin, sizeof(cached->socials.linkedin) - 1);
            strncpy(cached->socials.google, p->google, sizeof(cached->socials.google) - 1);

            strncpy(cached->display_name, p->display_name, sizeof(cached->display_name) - 1);
            strncpy(cached->bio, p->bio, sizeof(cached->bio) - 1);
            strncpy(cached->location, p->location, sizeof(cached->location) - 1);
            strncpy(cached->website, p->website, sizeof(cached->website) - 1);
            strncpy(cached->avatar_base64, p->avatar_base64, sizeof(cached->avatar_base64) - 1);
            cached->updated_at = (uint64_t)time(NULL);

            profile_cache_add_or_update(engine->fingerprint, cached);
            QGP_LOG_INFO(LOG_TAG, "Profile cache updated: %.16s... avatar=%zu bytes\n",
                        engine->fingerprint, strlen(cached->avatar_base64));
            dna_identity_free(cached);
        }
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

            /* Copy local nickname to contact struct (for Flutter to access) */
            if (list->contacts[i].nickname[0] != '\0') {
                strncpy(contacts[i].nickname, list->contacts[i].nickname, sizeof(contacts[i].nickname) - 1);
                contacts[i].nickname[sizeof(contacts[i].nickname) - 1] = '\0';
            } else {
                contacts[i].nickname[0] = '\0';
            }

            /* Get display name with fallback chain:
             * 0. Local nickname (NEW - highest priority)
             * 1. DHT profile (profile_manager)
             * 2. Registered name (keyserver_cache)
             * 3. Stored notes from contact request
             * 4. Fingerprint prefix as last resort */
            bool name_found = false;

            /* Try 0: Local nickname (highest priority) */
            if (list->contacts[i].nickname[0] != '\0') {
                strncpy(contacts[i].display_name, list->contacts[i].nickname, sizeof(contacts[i].display_name) - 1);
                name_found = true;
            }

            /* Try 1: DHT profile (display_name first, then registered_name) */
            if (!name_found) {
                dna_unified_identity_t *identity = NULL;
                if (profile_manager_get_profile(list->contacts[i].identity, &identity) == 0 && identity) {
                    if (identity->display_name[0] != '\0') {
                        strncpy(contacts[i].display_name, identity->display_name, sizeof(contacts[i].display_name) - 1);
                        name_found = true;
                    } else if (identity->registered_name[0] != '\0') {
                        strncpy(contacts[i].display_name, identity->registered_name, sizeof(contacts[i].display_name) - 1);
                        name_found = true;
                    }
                    dna_identity_free(identity);
                }
            }

            /* Try 2: Registered name from keyserver cache */
            if (!name_found) {
                char cached_name[64] = {0};
                if (keyserver_cache_get_name(list->contacts[i].identity, cached_name, sizeof(cached_name)) == 0 &&
                    cached_name[0] != '\0') {
                    strncpy(contacts[i].display_name, cached_name, sizeof(contacts[i].display_name) - 1);
                    name_found = true;
                }
            }

            /* Try 3: Notes field (stored display name from contact request) */
            if (!name_found && list->contacts[i].notes[0] != '\0') {
                strncpy(contacts[i].display_name, list->contacts[i].notes, sizeof(contacts[i].display_name) - 1);
                name_found = true;
            }

            /* Fallback: fingerprint prefix */
            if (!name_found) {
                snprintf(contacts[i].display_name, sizeof(contacts[i].display_name),
                         "%.16s...", list->contacts[i].identity);
            }

            /* Check presence cache for online status and last seen */
            contacts[i].is_online = presence_cache_get(list->contacts[i].identity);

            /* Get last_seen: prefer cache (recent activity), fallback to database (persistent) */
            time_t cache_last_seen = presence_cache_last_seen(list->contacts[i].identity);
            if (cache_last_seen > 0) {
                contacts[i].last_seen = (uint64_t)cache_last_seen;
            } else {
                /* Use database value (persisted from previous sessions) */
                contacts[i].last_seen = list->contacts[i].last_seen;
            }
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

        /* Cancel watermark listener for this contact */
        dna_engine_cancel_watermark_listener(engine, fp);
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
 * CONTACT NICKNAME (synchronous API)
 * ============================================================================ */

int dna_engine_set_contact_nickname_sync(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *nickname
) {
    if (!engine) {
        return DNA_ENGINE_ERROR_NOT_INITIALIZED;
    }
    if (!fingerprint || strlen(fingerprint) != 128) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }
    if (!engine->identity_loaded) {
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Initialize contacts DB if needed */
    if (contacts_db_init(engine->fingerprint) != 0) {
        return DNA_ENGINE_ERROR_DATABASE;
    }

    /* Check if contact exists */
    if (!contacts_db_exists(fingerprint)) {
        return DNA_ERROR_NOT_FOUND;
    }

    /* Update nickname in database */
    int result = contacts_db_update_nickname(fingerprint, nickname);
    if (result != 0) {
        return DNA_ENGINE_ERROR_DATABASE;
    }

    QGP_LOG_INFO(LOG_TAG, "Set nickname for %.16s... to '%s'\n",
                 fingerprint, nickname ? nickname : "(cleared)");
    return DNA_OK;
}

/* ============================================================================
 * CONTACT REQUEST TASK HANDLERS (ICQ-style)
 * ============================================================================ */

void dna_handle_send_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    qgp_key_t *privkey = NULL;

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
    privkey = dna_load_private_key(engine);
    if (!privkey) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get our registered display name from keyserver cache */
    char display_name_buf[64] = {0};
    char *display_name = NULL;
    if (keyserver_cache_get_name(engine->fingerprint, display_name_buf, sizeof(display_name_buf)) == 0 &&
        display_name_buf[0] != '\0') {
        display_name = display_name_buf;
    }

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
    if (privkey) {
        qgp_key_free(privkey);
    }
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

                /* Skip if already a contact or already pending (avoids DHT lookups for old requests) */
                if (contacts_db_exists(dht_requests[i].sender_fingerprint) ||
                    contacts_db_request_exists(dht_requests[i].sender_fingerprint)) {
                    continue;
                }

                /* If sender_name is empty, lookup from DHT profile (reverse lookup) */
                char *looked_up_name = NULL;
                const char *sender_name = dht_requests[i].sender_name;
                if (sender_name[0] == '\0') {
                    QGP_LOG_INFO(LOG_TAG, "Sender name empty, doing reverse lookup for %.20s...",
                                 dht_requests[i].sender_fingerprint);
                    if (dht_keyserver_reverse_lookup(dht_ctx, dht_requests[i].sender_fingerprint,
                                                     &looked_up_name) == 0 && looked_up_name) {
                        sender_name = looked_up_name;
                        /* Cache the name for future use */
                        keyserver_cache_put_name(dht_requests[i].sender_fingerprint, looked_up_name, 0);
                        QGP_LOG_INFO(LOG_TAG, "Reverse lookup found: %s", looked_up_name);
                    }
                }

                /* Auto-approve reciprocal requests (they accepted our request) */
                if (dht_requests[i].message[0] &&
                    strcmp(dht_requests[i].message, "Contact request accepted") == 0) {
                    QGP_LOG_INFO(LOG_TAG, "Auto-approving reciprocal request from %.20s...",
                                 dht_requests[i].sender_fingerprint);
                    /* Add directly as contact (notes = display name) */
                    contacts_db_add(
                        dht_requests[i].sender_fingerprint,
                        sender_name
                    );
                    contacts_changed = true;  /* Mark for sync AFTER loop */
                } else {
                    /* Regular request - add to pending */
                    contacts_db_add_incoming_request(
                        dht_requests[i].sender_fingerprint,
                        sender_name,
                        dht_requests[i].message,
                        dht_requests[i].timestamp
                    );
                }

                /* Free looked up name if allocated */
                if (looked_up_name) {
                    free(looked_up_name);
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

            /* If display_name is empty, try reverse lookup from DHT */
            if (db_requests[i].display_name[0] == '\0' && dht_ctx) {
                char *looked_up_name = NULL;
                QGP_LOG_INFO("DNA_ENGINE", "DB request[%d] has empty name, doing reverse lookup", i);
                if (dht_keyserver_reverse_lookup(dht_ctx, db_requests[i].fingerprint,
                                                 &looked_up_name) == 0 && looked_up_name) {
                    strncpy(requests[i].display_name, looked_up_name, 63);
                    requests[i].display_name[63] = '\0';
                    /* Update the database for future retrievals */
                    contacts_db_update_request_name(db_requests[i].fingerprint, looked_up_name);
                    /* Cache for future use */
                    keyserver_cache_put_name(db_requests[i].fingerprint, looked_up_name, 0);
                    QGP_LOG_INFO("DNA_ENGINE", "Reverse lookup found: %s", looked_up_name);
                    free(looked_up_name);
                } else {
                    requests[i].display_name[0] = '\0';
                }
            } else {
                strncpy(requests[i].display_name, db_requests[i].display_name, 63);
                requests[i].display_name[63] = '\0';
            }

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

    /* Start listeners for new contact (outbox, presence, watermark) */
    dna_engine_listen_outbox(engine, task->params.contact_request.fingerprint);
    dna_engine_start_presence_listener(engine, task->params.contact_request.fingerprint);
    dna_engine_start_watermark_listener(engine, task->params.contact_request.fingerprint);

    /* Send a reciprocal request so they know we approved */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx) {
        qgp_key_t *privkey = dna_load_private_key(engine);
        if (privkey) {
            /* Get our registered display name from keyserver cache */
            char display_name_buf[64] = {0};
            char *display_name = NULL;
            if (keyserver_cache_get_name(engine->fingerprint, display_name_buf, sizeof(display_name_buf)) == 0 &&
                display_name_buf[0] != '\0') {
                display_name = display_name_buf;
            }

            dht_send_contact_request(
                dht_ctx,
                engine->fingerprint,
                display_name,
                privkey->public_key,
                privkey->private_key,
                task->params.contact_request.fingerprint,
                "Contact request accepted"
            );
            qgp_key_free(privkey);
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
        0,  /* message_type = chat */
        task->params.send_message.queued_at
    );

    if (rc != 0) {
        /* Determine error type based on return code */
        if (rc == -3) {
            /* KEY_UNAVAILABLE: recipient key not cached and DHT lookup failed */
            error = DNA_ENGINE_ERROR_KEY_UNAVAILABLE;
            QGP_LOG_WARN(LOG_TAG, "[SEND] Key unavailable for recipient - message not saved (cannot encrypt)");
        } else {
            /* Network or other error */
            error = DNA_ENGINE_ERROR_NETWORK;
            QGP_LOG_WARN(LOG_TAG, "[SEND] Message send failed (rc=%d) - DHT queue unsuccessful", rc);
        }
        /* Emit MESSAGE_SENT event with FAILED status so UI can update spinner */
        dna_event_t event = {0};
        event.type = DNA_EVENT_MESSAGE_SENT;
        event.data.message_status.message_id = 0;  /* ID not available here */
        event.data.message_status.new_status = 2;  /* FAILED */
        dna_dispatch_event(engine, &event);
    } else {
        /* Emit MESSAGE_SENT event so UI can update (triggers refresh)
         * Status is SENT (1) - DHT PUT succeeded, single tick in UI.
         * Will become DELIVERED (3) via watermark confirmation → double tick. */
        QGP_LOG_INFO(LOG_TAG, "[SEND] Message stored on DHT (status=SENT, single tick)");
        dna_event_t event = {0};
        event.type = DNA_EVENT_MESSAGE_SENT;
        event.data.message_status.message_id = 0;  /* ID not available here */
        event.data.message_status.new_status = 1;  /* SENT - DHT PUT succeeded */
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

            /* Use pre-decrypted plaintext from messenger_get_conversation */
            /* (Kyber key loaded once, not per-message - massive speedup) */
            if (msg_infos[i].plaintext) {
                messages[i].plaintext = strdup(msg_infos[i].plaintext);
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

void dna_handle_get_conversation_page(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_message_t *messages = NULL;
    int count = 0;
    int total = 0;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    message_info_t *msg_infos = NULL;
    int msg_count = 0;

    int rc = messenger_get_conversation_page(
        engine->messenger,
        task->params.get_conversation_page.contact,
        task->params.get_conversation_page.limit,
        task->params.get_conversation_page.offset,
        &msg_infos,
        &msg_count,
        &total
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

            if (msg_infos[i].plaintext) {
                messages[i].plaintext = strdup(msg_infos[i].plaintext);
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

            messages[i].is_outgoing = (msg_infos[i].sender &&
                strcmp(msg_infos[i].sender, engine->fingerprint) == 0);

            /* Map status string to int */
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
                    messages[i].status = 1;
                }
            } else {
                messages[i].status = 1;
            }

            messages[i].message_type = msg_infos[i].message_type;
        }
        count = msg_count;

        messenger_free_messages(msg_infos, msg_count);
    }

done:
    task->callback.messages_page(task->request_id, error, messages, count, total, task->user_data);
}

void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* First, sync any pending outboxes (our messages that failed to publish earlier) */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        int synced = dht_offline_queue_sync_pending(dht_ctx);
        if (synced > 0) {
            QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Synced %d pending outboxes to DHT", synced);
        }
    }

    /* Check DHT offline queue for messages from contacts */
    size_t offline_count = 0;
    int rc = messenger_transport_check_offline_messages(engine->messenger, NULL, &offline_count);
    if (rc == 0) {
        QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Direct messages check complete: %zu new", offline_count);
    } else {
        QGP_LOG_WARN("DNA_ENGINE", "[OFFLINE] Direct messages check failed with rc=%d", rc);
    }

    /* Also sync group messages from DHT */
    if (dht_ctx) {
        size_t group_msg_count = 0;
        rc = dna_group_outbox_sync_all(dht_ctx, engine->fingerprint, &group_msg_count);
        if (rc == 0) {
            QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Group messages sync complete: %zu new", group_msg_count);
        } else if (rc != DNA_GROUP_OUTBOX_ERR_NULL_PARAM) {
            /* NULL_PARAM just means no groups, not an error */
            QGP_LOG_WARN("DNA_ENGINE", "[OFFLINE] Group messages sync failed with rc=%d", rc);
        }
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
        /* Sync all groups from DHT first to get latest data */
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            for (int i = 0; i < entry_count; i++) {
                dht_groups_sync_from_dht(dht_ctx, entries[i].group_uuid);
            }
        }

        /* Re-fetch after sync to get updated data */
        dht_groups_free_cache_entries(entries, entry_count);
        entries = NULL;
        entry_count = 0;
        if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }

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
            groups[i].created_at = entries[i].created_at;

            /* Get member count from dht_group_members table */
            int member_count = 0;
            if (dht_groups_get_member_count(entries[i].group_uuid, &member_count) == 0) {
                groups[i].member_count = member_count;
            } else {
                groups[i].member_count = 0;
            }
        }
        count = entry_count;

        dht_groups_free_cache_entries(entries, entry_count);
    }

done:
    task->callback.groups(task->request_id, error, groups, count, task->user_data);
    /* Note: caller (Flutter) owns the memory and frees via dna_free_groups() */
}

void dna_handle_get_group_info(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_group_info_t *info = NULL;
    dht_group_cache_entry_t *cache_entry = NULL;
    const char *group_uuid = task->params.get_group_info.group_uuid;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Sync from DHT first to get latest member list */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        dht_groups_sync_from_dht(dht_ctx, group_uuid);
    }

    /* Get group from local cache (now up-to-date) */
    int rc = dht_groups_get_cache_entry(group_uuid, &cache_entry);
    if (rc != 0) {
        error = (rc == -2) ? DNA_ENGINE_ERROR_NOT_FOUND : DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    info = calloc(1, sizeof(dna_group_info_t));
    if (!info) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    strncpy(info->uuid, cache_entry->group_uuid, 36);
    strncpy(info->name, cache_entry->name, sizeof(info->name) - 1);
    strncpy(info->creator, cache_entry->creator, 128);
    info->created_at = cache_entry->created_at;

    /* Check if current user is the owner */
    info->is_owner = (strcmp(engine->fingerprint, cache_entry->creator) == 0);

    /* Get member count */
    int member_count = 0;
    dht_groups_get_member_count(group_uuid, &member_count);
    info->member_count = member_count;

    /* Get active GEK version */
    uint8_t gek[32];
    uint32_t gek_version = 0;
    if (gek_load_active(group_uuid, gek, &gek_version) == 0) {
        info->gek_version = gek_version;
        qgp_secure_memzero(gek, 32);
    }

done:
    if (cache_entry) free(cache_entry);
    task->callback.group_info(task->request_id, error, info, task->user_data);
}

void dna_handle_get_group_members(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_group_member_t *members = NULL;
    int count = 0;
    dht_group_cache_entry_t *cache_entry = NULL;
    char **dht_members = NULL;
    int dht_member_count = 0;
    const char *group_uuid = task->params.get_group_members.group_uuid;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Sync from DHT first to get latest member list */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        dht_groups_sync_from_dht(dht_ctx, group_uuid);
    }

    /* Get group from local cache (now up-to-date) */
    int rc = dht_groups_get_cache_entry(group_uuid, &cache_entry);
    if (rc != 0) {
        error = (rc == -2) ? DNA_ENGINE_ERROR_NOT_FOUND : DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get members from DHT group_members table */
    if (dht_groups_get_members(group_uuid, &dht_members, &dht_member_count) != 0 || dht_member_count == 0) {
        /* No members in DHT table, return just owner */
        members = calloc(1, sizeof(dna_group_member_t));
        if (members) {
            strncpy(members[0].fingerprint, cache_entry->creator, 128);
            members[0].added_at = cache_entry->created_at;
            members[0].is_owner = true;
            count = 1;
        }
        goto done;
    }

    /* Convert to dna_group_member_t */
    members = calloc(dht_member_count, sizeof(dna_group_member_t));
    if (!members) {
        dht_groups_free_members(dht_members, dht_member_count);
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    for (int i = 0; i < dht_member_count; i++) {
        strncpy(members[i].fingerprint, dht_members[i], 128);
        members[i].added_at = cache_entry->created_at;  /* DHT doesn't store per-member add time */
        members[i].is_owner = (strcmp(dht_members[i], cache_entry->creator) == 0);
    }
    count = dht_member_count;
    dht_groups_free_members(dht_members, dht_member_count);

done:
    if (cache_entry) free(cache_entry);
    task->callback.group_members(task->request_id, error, members, count, task->user_data);
}

void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    char group_uuid[37] = {0};
    char *uuid_copy = NULL;  /* Heap-allocated for async callback */

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
        &group_id,
        group_uuid  /* Get real UUID */
    );

    if (rc != 0) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Allocate heap copy for async callback (caller must free) */
    uuid_copy = strdup(group_uuid);

done:
    task->callback.group_created(task->request_id, error,
                                  uuid_copy,  /* Heap-allocated, callback must free */
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

void dna_handle_get_group_conversation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_message_t *messages = NULL;
    int count = 0;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *group_uuid = task->params.get_group_conversation.group_uuid;

    /* Get group messages directly from group_messages table in groups.db */
    dna_group_message_t *group_msgs = NULL;
    size_t msg_count = 0;

    int rc = dna_group_outbox_db_get_messages(group_uuid, 0, 0, &group_msgs, &msg_count);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group conversation: %d", rc);
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    QGP_LOG_WARN(LOG_TAG, "[GROUP] Got %zu messages for group %s", msg_count, group_uuid);

    if (msg_count > 0) {
        messages = calloc(msg_count, sizeof(dna_message_t));
        if (!messages) {
            dna_group_outbox_free_messages(group_msgs, msg_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        /* Messages from DB are in DESC order, reverse to ASC for UI */
        for (size_t i = 0; i < msg_count; i++) {
            size_t src_idx = msg_count - 1 - i;  /* Reverse order */
            dna_group_message_t *src = &group_msgs[src_idx];

            messages[i].id = (int64_t)i;  /* Use index as ID since message_id is string */
            strncpy(messages[i].sender, src->sender_fingerprint, 128);
            strncpy(messages[i].recipient, group_uuid, 36);

            /* Use decrypted plaintext */
            if (src->plaintext) {
                messages[i].plaintext = strdup(src->plaintext);
            } else {
                messages[i].plaintext = strdup("[Decryption failed]");
            }

            /* Convert timestamp_ms to seconds */
            messages[i].timestamp = src->timestamp_ms / 1000;

            /* Determine if outgoing */
            messages[i].is_outgoing = (strcmp(src->sender_fingerprint, engine->fingerprint) == 0);

            /* Group messages are always delivered */
            messages[i].status = 3;  /* delivered */
            messages[i].message_type = 0;  /* text */
        }
        count = (int)msg_count;

        dna_group_outbox_free_messages(group_msgs, msg_count);
    }

done:
    task->callback.messages(task->request_id, error, messages, count, task->user_data);
}

void dna_handle_add_group_member(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Look up group_id from UUID using local cache */
    dht_group_cache_entry_t *entries = NULL;
    int entry_count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int group_id = -1;
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].group_uuid, task->params.add_group_member.group_uuid) == 0) {
            group_id = entries[i].local_id;
            break;
        }
    }
    dht_groups_free_cache_entries(entries, entry_count);

    if (group_id < 0) {
        error = DNA_ENGINE_ERROR_NOT_FOUND;
        goto done;
    }

    /* Add member using messenger API */
    int rc = messenger_add_group_member(
        engine->messenger,
        group_id,
        task->params.add_group_member.fingerprint
    );

    if (rc == -3) {
        error = DNA_ENGINE_ERROR_ALREADY_EXISTS;  // Already a member
    } else if (rc != 0) {
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

    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT: START group=%s <<<", task->params.invitation.group_uuid);

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT: Calling messenger <<<");
    int rc = messenger_accept_group_invitation(
        engine->messenger,
        task->params.invitation.group_uuid
    );
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT: messenger returned %d <<<", rc);

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Subscribe to the newly accepted group for real-time messages */
        QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT: Subscribing to groups <<<");
        dna_engine_subscribe_all_groups(engine);
    }

done:
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT: callback error=%d <<<", error);
    task->callback.completion(task->request_id, error, task->user_data);
    QGP_LOG_WARN(LOG_TAG, ">>> ACCEPT: DONE <<<");
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
            qgp_secure_memzero(mnemonic, sizeof(mnemonic));
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        /* Derive wallet addresses from master seed and mnemonic
         * Note: Cellframe needs the mnemonic (SHA3-256 hash), ETH/SOL/TRX use master seed
         */
        rc = blockchain_derive_wallets_from_seed(master_seed, mnemonic, engine->fingerprint, &engine->blockchain_wallets);

        /* Clear sensitive data from memory */
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        qgp_secure_memzero(master_seed, sizeof(master_seed));

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
        int send_rc = blockchain_send_tokens(
                bc_type,
                bc_wallet_info->file_path,
                recipient,
                amount_str,
                token,
                gas_speed,
                tx_hash);
        if (send_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed (wallet file), rc=%d", chain_name, send_rc);
            /* Map blockchain error codes to engine errors */
            if (send_rc == -2) {
                error = DNA_ENGINE_ERROR_INSUFFICIENT_BALANCE;
            } else if (send_rc == -3) {
                error = DNA_ENGINE_ERROR_RENT_MINIMUM;
            } else {
                error = DNA_ENGINE_ERROR_NETWORK;
            }
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
            qgp_secure_memzero(mnemonic, sizeof(mnemonic));
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
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        if (send_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed (on-demand), rc=%d", chain_name, send_rc);
            /* Map blockchain error codes to engine errors */
            if (send_rc == -2) {
                error = DNA_ENGINE_ERROR_INSUFFICIENT_BALANCE;
            } else if (send_rc == -3) {
                error = DNA_ENGINE_ERROR_RENT_MINIMUM;
            } else {
                error = DNA_ENGINE_ERROR_NETWORK;
            }
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

/* v0.3.0: dna_engine_list_identities() removed - single-user model
 * Use dna_engine_has_identity() instead */

dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    dna_identity_created_cb callback,
    void *user_data
) {
    if (!engine || !name || !signing_seed || !encryption_seed || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    /* Enforce lowercase-only identity names */
    if (!is_valid_identity_name(name)) {
        QGP_LOG_ERROR(LOG_TAG, "Identity name must be lowercase (a-z, 0-9, underscore, hyphen only)");
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.create_identity.name, name, sizeof(params.create_identity.name) - 1);
    memcpy(params.create_identity.signing_seed, signing_seed, 32);
    memcpy(params.create_identity.encryption_seed, encryption_seed, 32);

    dna_task_callback_t cb = { .identity_created = callback };
    return dna_submit_task(engine, TASK_CREATE_IDENTITY, &params, cb, user_data);
}

int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
) {
    if (!engine || !name || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Enforce lowercase-only identity names */
    if (!is_valid_identity_name(name)) {
        QGP_LOG_ERROR(LOG_TAG, "Identity name must be lowercase (a-z, 0-9, underscore, hyphen only)");
        return DNA_ERROR_INVALID_ARG;
    }

    /* Step 1: Create keys locally */
    int rc = messenger_generate_keys_from_seeds(name, signing_seed, encryption_seed,
                                                 master_seed, mnemonic,
                                                 engine->data_dir, NULL, fingerprint_out);
    if (rc != 0) {
        return DNA_ERROR_CRYPTO;
    }

    /* Step 2: Create temporary messenger context for registration */
    messenger_context_t *temp_ctx = messenger_init(fingerprint_out);
    if (!temp_ctx) {
        /* Cleanup: v0.3.0 flat structure - delete keys/, db/, wallets/, mnemonic.enc */
        char path[512];
        snprintf(path, sizeof(path), "%s/keys", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/db", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/wallets", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/mnemonic.enc", engine->data_dir);
        remove(path);
        QGP_LOG_ERROR(LOG_TAG, "Failed to create messenger context for identity registration");
        return DNA_ERROR_INTERNAL;
    }

    /* DHT already started by prepare_dht_from_mnemonic() (both CLI and Flutter) */

    /* Step 3: Register name on DHT (atomic - if this fails, cleanup) */
    rc = messenger_register_name(temp_ctx, fingerprint_out, name);
    messenger_free(temp_ctx);

    if (rc != 0) {
        /* Cleanup: v0.3.0 flat structure - delete keys/, db/, wallets/, mnemonic.enc */
        char path[512];
        snprintf(path, sizeof(path), "%s/keys", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/db", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/wallets", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/mnemonic.enc", engine->data_dir);
        remove(path);
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
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
) {
    if (!engine || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Step 1: Create keys locally (uses fingerprint as directory name) */
    int rc = messenger_generate_keys_from_seeds(NULL, signing_seed, encryption_seed,
                                                 master_seed, mnemonic,
                                                 engine->data_dir, NULL, fingerprint_out);
    if (rc != 0) {
        return DNA_ERROR_CRYPTO;
    }

    /* Step 2: v0.6.0+: Load DHT identity into engine-owned context */
    if (messenger_load_dht_identity_for_engine(fingerprint_out, &engine->dht_ctx) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Engine-owned DHT context created for restored identity");
        dht_singleton_set_borrowed_context(engine->dht_ctx);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Fallback: using singleton DHT for restored identity");
        messenger_load_dht_identity(fingerprint_out);
    }

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
    (void)fingerprint;  // Unused in v0.3.0 flat structure

    /* v0.3.0: Flat structure - delete keys/, db/, wallets/ directories and root files */

    /* 1. Delete keys directory: <data_dir>/keys/ */
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
    if (qgp_platform_file_exists(keys_dir)) {
        if (qgp_platform_rmdir_recursive(keys_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete keys directory: %s", keys_dir);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted keys directory: %s", keys_dir);
        }
    }

    /* 2. Delete db directory: <data_dir>/db/ */
    /* Close profile cache first to release file handles before deletion */
    profile_cache_close();

    char db_dir[512];
    snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);
    if (qgp_platform_file_exists(db_dir)) {
        if (qgp_platform_rmdir_recursive(db_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete db directory: %s", db_dir);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted db directory: %s", db_dir);
        }
    }

    /* 3. Delete wallets directory: <data_dir>/wallets/ */
    char wallets_dir[512];
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/wallets", data_dir);
    if (qgp_platform_file_exists(wallets_dir)) {
        if (qgp_platform_rmdir_recursive(wallets_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete wallets directory: %s", wallets_dir);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted wallets directory: %s", wallets_dir);
        }
    }

    /* 4. Delete mnemonic file: <data_dir>/mnemonic.enc */
    char mnemonic_path[512];
    snprintf(mnemonic_path, sizeof(mnemonic_path), "%s/mnemonic.enc", data_dir);
    if (qgp_platform_file_exists(mnemonic_path)) {
        if (remove(mnemonic_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete mnemonic: %s", mnemonic_path);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted mnemonic: %s", mnemonic_path);
        }
    }

    /* 5. Delete DHT identity file: <data_dir>/dht_identity.bin */
    char dht_id_path[512];
    snprintf(dht_id_path, sizeof(dht_id_path), "%s/dht_identity.bin", data_dir);
    if (qgp_platform_file_exists(dht_id_path)) {
        if (remove(dht_id_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete DHT identity: %s", dht_id_path);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted DHT identity: %s", dht_id_path);
        }
    }

    if (errors > 0) {
        QGP_LOG_WARN(LOG_TAG, "Identity deletion completed with %d errors", errors);
        return DNA_ERROR_INTERNAL;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity deleted successfully: %.16s...", fingerprint);
    return DNA_OK;
}

/**
 * Check if an identity exists (v0.3.0 single-user model)
 *
 * Checks if keys/identity.dsa exists in the data directory.
 */
bool dna_engine_has_identity(dna_engine_t *engine) {
    if (!engine || !engine->data_dir) {
        return false;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/keys/identity.dsa", engine->data_dir);
    return qgp_platform_file_exists(path);
}

/**
 * Prepare DHT connection from mnemonic (before identity creation)
 */
int dna_engine_prepare_dht_from_mnemonic(dna_engine_t *engine, const char *mnemonic) {
    (void)engine;  // Engine not needed for this operation
    return messenger_prepare_dht_from_mnemonic(mnemonic);
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

bool dna_engine_is_identity_loaded(dna_engine_t *engine) {
    return engine && engine->identity_loaded;
}

bool dna_engine_is_transport_ready(dna_engine_t *engine) {
    return engine && engine->messenger && engine->messenger->transport_ctx != NULL;
}

dna_request_id_t dna_engine_load_identity_minimal(
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
    params.load_identity.minimal = true;

    QGP_LOG_INFO(LOG_TAG, "Load identity (minimal): DHT + listeners only");

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

dna_request_id_t dna_engine_refresh_contact_profile(
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
    return dna_submit_task(engine, TASK_REFRESH_CONTACT_PROFILE, &params, cb, user_data);
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

    /* v0.3.0: Flat structure - keys/identity.kem, mnemonic.enc in root */
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", engine->data_dir);

    /* Check if mnemonic file exists */
    if (!mnemonic_storage_exists(engine->data_dir)) {
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
                                       kem_key->private_key, engine->data_dir);

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
    /* v0.3.0: Flat structure - keys/identity.{dsa,kem}, mnemonic.enc in root */
    char dsa_path[512];
    char kem_path[512];
    char mnemonic_path[512];

    snprintf(dsa_path, sizeof(dsa_path), "%s/keys/identity.dsa", engine->data_dir);
    snprintf(kem_path, sizeof(kem_path), "%s/keys/identity.kem", engine->data_dir);
    snprintf(mnemonic_path, sizeof(mnemonic_path), "%s/mnemonic.enc", engine->data_dir);

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
    params.send_message.queued_at = time(NULL);  /* Capture send time */
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

    /* Capture timestamp NOW - this is when user clicked send */
    time_t queued_at = time(NULL);

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
    entry->queued_at = queued_at;
    engine->message_queue.size++;

    int slot_id = entry->slot_id;
    pthread_mutex_unlock(&engine->message_queue.mutex);

    /* Submit task to worker queue (fire-and-forget, no callback) */
    dna_task_params_t params = {0};
    strncpy(params.send_message.recipient, recipient_fingerprint, 128);
    params.send_message.message = strdup(message);
    params.send_message.queued_at = queued_at;
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

dna_request_id_t dna_engine_get_conversation_page(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    int limit,
    int offset,
    dna_messages_page_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_conversation_page.contact, contact_fingerprint, 128);
    params.get_conversation_page.limit = limit > 0 ? limit : 50;
    params.get_conversation_page.offset = offset >= 0 ? offset : 0;

    dna_task_callback_t cb = { .messages_page = callback };
    return dna_submit_task(engine, TASK_GET_CONVERSATION_PAGE, &params, cb, user_data);
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

dna_request_id_t dna_engine_check_offline_messages_from(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded || !engine->messenger) {
        callback(1, DNA_ENGINE_ERROR_NO_IDENTITY, user_data);
        return 1;
    }

    size_t fp_len = strlen(contact_fingerprint);
    if (fp_len < 64) {
        QGP_LOG_ERROR(LOG_TAG, "[OFFLINE] Invalid fingerprint length: %zu", fp_len);
        callback(1, DNA_ENGINE_ERROR_INVALID_PARAM, user_data);
        return 1;
    }

    /* Check offline messages from specific contact's outbox.
     * This is faster than checking all contacts and provides
     * immediate updates when entering a specific chat. */
    QGP_LOG_INFO(LOG_TAG, "[OFFLINE] Checking messages from %.20s...", contact_fingerprint);

    size_t offline_count = 0;
    int rc = messenger_transport_check_offline_messages(engine->messenger, contact_fingerprint, &offline_count);
    if (rc == 0) {
        QGP_LOG_INFO(LOG_TAG, "[OFFLINE] From %.20s...: %zu new messages", contact_fingerprint, offline_count);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[OFFLINE] Check from %.20s... failed: %d", contact_fingerprint, rc);
    }

    /* Call completion callback (0 = success for any result including 0 messages) */
    callback(1, rc == 0 ? DNA_OK : DNA_ENGINE_ERROR_NETWORK, user_data);
    return 1;
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

int dna_engine_delete_message_sync(
    dna_engine_t *engine,
    int message_id
) {
    if (!engine || message_id <= 0) return -1;
    if (!engine->messenger) return -1;

    return messenger_delete_message(engine->messenger, message_id);
}

/* ============================================================================
 * MESSAGE RETRY (Bulletproof Message Delivery)
 * ============================================================================
 *
 * v0.4.59: "Never Give Up" retry system
 * - No max retry limit (keeps trying until delivered or stale)
 * - Exponential backoff: 30s, 60s, 120s, ... max 1 hour
 * - Stale marking: 30+ day old messages marked stale (shown differently in UI)
 * - DHT check: Only retry when DHT is connected with ≥1 peer
 */

#define MESSAGE_RETRY_MAX_RETRIES 0  /* 0 = unlimited retries (never give up) */
#define MESSAGE_STALE_DAYS 30        /* Mark as stale after 30 days */
#define MESSAGE_BACKOFF_BASE_SECS 30 /* Base backoff: 30 seconds */
#define MESSAGE_BACKOFF_MAX_SECS 3600 /* Max backoff: 1 hour */

/* Mutex to prevent concurrent retry calls (e.g., DHT reconnect + manual retry race) */
static pthread_mutex_t retry_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Calculate retry backoff interval based on retry_count
 * Exponential: 30s, 60s, 120s, 240s, 480s, 960s, 1920s, 3600s (max)
 */
static int get_retry_backoff_secs(int retry_count) {
    if (retry_count <= 0) return MESSAGE_BACKOFF_BASE_SECS;

    /* Cap the exponent to prevent overflow (2^7 = 128, 30*128 = 3840 > 3600) */
    int exp = retry_count < 7 ? retry_count : 7;
    int interval = MESSAGE_BACKOFF_BASE_SECS * (1 << exp);

    return interval > MESSAGE_BACKOFF_MAX_SECS ? MESSAGE_BACKOFF_MAX_SECS : interval;
}

/**
 * Check if message is ready for retry based on exponential backoff
 * Returns true if enough time has passed since message creation + backoff
 */
static bool is_ready_for_retry(backup_message_t *msg) {
    if (!msg) return false;

    /* First attempt (retry_count=0) always allowed */
    if (msg->retry_count == 0) return true;

    /* Calculate next retry time based on backoff */
    int backoff_secs = get_retry_backoff_secs(msg->retry_count);
    time_t next_retry_at = msg->timestamp + (msg->retry_count * backoff_secs);
    time_t now = time(NULL);

    return now >= next_retry_at;
}

/**
 * Retry a single pending/failed message
 *
 * v14: Re-encrypts plaintext and queues to DHT with a new seq_num.
 * Uses messenger_send_message which handles encryption, DHT queueing, and duplicate detection.
 * Status stays PENDING until watermark confirms DELIVERED. Increments retry_count on failure.
 *
 * @param engine Engine instance
 * @param msg Message to retry (from message_backup_get_pending_messages)
 * @return 0 on success, -1 on failure
 */
static int retry_single_message(dna_engine_t *engine, backup_message_t *msg) {
    if (!engine || !msg) return -1;
    if (!engine->messenger) return -1;

    message_backup_context_t *backup_ctx = messenger_get_backup_ctx(engine->messenger);
    if (!backup_ctx) return -1;

    /* v14: Messages are stored as plaintext - need to re-encrypt before sending */
    if (!msg->plaintext || strlen(msg->plaintext) == 0) {
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d has no plaintext - cannot retry", msg->id);
        return -1;
    }

    /* Call messenger_send_message to re-encrypt and send
     * This handles:
     * - Loading recipient's Kyber public key
     * - Multi-recipient encryption
     * - DHT queueing
     * - Duplicate detection (skips DB save if message exists) */
    const char *recipients[] = { msg->recipient };
    int rc = messenger_send_message(
        engine->messenger,
        recipients,
        1,                      /* recipient_count */
        msg->plaintext,         /* message content */
        msg->group_id,          /* group_id (0 for direct) */
        msg->message_type,      /* message_type */
        msg->timestamp          /* preserve original timestamp for ordering */
    );

    if (rc == 0 || rc == 1) {
        /* Success - queued to DHT (rc=0) or duplicate skipped (rc=1)
         * Update status to SENT (1) using original message ID.
         * For duplicates, messenger_send_message() can't update status (message_id=0)
         * so we must do it here to prevent infinite retry loops. */
        message_backup_update_status(backup_ctx, msg->id, 1);
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Message %d to %.20s... re-encrypted and queued, status=SENT",
                     msg->id, msg->recipient);
        return 0;
    } else if (rc == -3) {
        /* KEY_UNAVAILABLE - recipient's public key not cached and DHT unavailable
         * Don't increment retry count - will retry when DHT reconnects */
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d to %.20s... key unavailable (will retry later)",
                     msg->id, msg->recipient);
        return -1;
    } else {
        /* Failed - increment retry count */
        message_backup_increment_retry_count(backup_ctx, msg->id);
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d to %.20s... failed (retry_count=%d)",
                     msg->id, msg->recipient, msg->retry_count + 1);
        return -1;
    }
}

int dna_engine_retry_pending_messages(dna_engine_t *engine) {
    if (!engine) return -1;
    if (!engine->messenger) return -1;

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) return -1;

    /* Skip retry if DHT is not connected - retries will fail and block for timeout
     * Messages will be retried when DHT reconnects (triggers this function again) */
    if (!dht_context_is_ready(dht_ctx)) {
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Skipping retry - DHT not connected");
        return 0;
    }

    message_backup_context_t *backup_ctx = messenger_get_backup_ctx(engine->messenger);
    if (!backup_ctx) return -1;

    /* Lock to prevent concurrent retry calls */
    pthread_mutex_lock(&retry_mutex);

    /* Get all pending/failed messages (0 = unlimited, no retry_count filter) */
    backup_message_t *messages = NULL;
    int count = 0;
    int rc = message_backup_get_pending_messages(
        backup_ctx,
        MESSAGE_RETRY_MAX_RETRIES,  /* 0 = unlimited */
        &messages,
        &count
    );

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[RETRY] Failed to query pending messages");
        pthread_mutex_unlock(&retry_mutex);
        return -1;
    }

    if (count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[RETRY] No pending messages to retry");
        pthread_mutex_unlock(&retry_mutex);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[RETRY] Found %d pending/failed messages to process", count);

    int success_count = 0;
    int fail_count = 0;
    int skipped_backoff = 0;
    int marked_stale = 0;

    /* Process each message */
    for (int i = 0; i < count; i++) {
        backup_message_t *msg = &messages[i];

        /* Check if message is stale (30+ days old) */
        int age_days = message_backup_get_age_days(backup_ctx, msg->id);
        if (age_days >= MESSAGE_STALE_DAYS) {
            message_backup_mark_stale(backup_ctx, msg->id);
            marked_stale++;
            QGP_LOG_INFO(LOG_TAG, "[RETRY] Message %d marked STALE (age=%d days)", msg->id, age_days);
            continue;
        }

        /* Check exponential backoff - skip if not ready for retry yet */
        if (!is_ready_for_retry(msg)) {
            skipped_backoff++;
            continue;
        }

        /* Retry the message */
        if (retry_single_message(engine, msg) == 0) {
            success_count++;
        } else {
            fail_count++;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "[RETRY] Completed: %d succeeded, %d failed, %d backoff, %d stale",
                 success_count, fail_count, skipped_backoff, marked_stale);

    /* Note: Delivery confirmation handled by persistent watermark listeners */

    /* Free messages array */
    message_backup_free_messages(messages, count);

    pthread_mutex_unlock(&retry_mutex);
    return success_count;
}

int dna_engine_retry_message(dna_engine_t *engine, int message_id) {
    if (!engine || message_id <= 0) return -1;
    if (!engine->messenger) return -1;

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) return -1;
    (void)dht_ctx;  /* Used by retry_single_message via dna_get_dht_ctx */

    message_backup_context_t *backup_ctx = messenger_get_backup_ctx(engine->messenger);
    if (!backup_ctx) return -1;

    /* Lock to prevent concurrent retry calls */
    pthread_mutex_lock(&retry_mutex);

    /* Get all pending/failed messages (we'll filter by ID) */
    backup_message_t *messages = NULL;
    int count = 0;
    int rc = message_backup_get_pending_messages(
        backup_ctx,
        0,  /* 0 = unlimited - allow manual retry regardless of retry_count */
        &messages,
        &count
    );

    if (rc != 0 || count == 0) {
        pthread_mutex_unlock(&retry_mutex);
        return -1;
    }

    /* Find the specific message */
    int result = -1;
    for (int i = 0; i < count; i++) {
        if (messages[i].id == message_id) {
            result = retry_single_message(engine, &messages[i]);
            break;
        }
    }

    message_backup_free_messages(messages, count);

    if (result == -1) {
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d not found or not retryable", message_id);
    }

    pthread_mutex_unlock(&retry_mutex);
    return result;
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

dna_request_id_t dna_engine_get_group_info(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_group_info_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;
    if (strlen(group_uuid) != 36) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_group_info.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .group_info = callback };
    return dna_submit_task(engine, TASK_GET_GROUP_INFO, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_group_members(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_group_members_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;
    if (strlen(group_uuid) != 36) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_group_members.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .group_members = callback };
    return dna_submit_task(engine, TASK_GET_GROUP_MEMBERS, &params, cb, user_data);
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

dna_request_id_t dna_engine_get_group_conversation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_messages_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.get_group_conversation.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .messages = callback };
    return dna_submit_task(engine, TASK_GET_GROUP_CONVERSATION, &params, cb, user_data);
}

dna_request_id_t dna_engine_add_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.add_group_member.group_uuid, group_uuid, 36);
    strncpy(params.add_group_member.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_ADD_GROUP_MEMBER, &params, cb, user_data);
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

    return messenger_transport_peer_online(engine->messenger, fingerprint);
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

dna_request_id_t dna_engine_sync_groups_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUPS_TO_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_group_by_uuid(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }
    if (strlen(group_uuid) != 36) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.sync_group_by_uuid.group_uuid,
             sizeof(params.sync_group_by_uuid.group_uuid),
             "%s", group_uuid);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUP_BY_UUID, &params, cb, user_data);
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
 * Cleanup callback for outbox listeners - frees the context when listener cancelled
 */
static void outbox_listener_cleanup(void *user_data) {
    outbox_listener_ctx_t *ctx = (outbox_listener_ctx_t *)user_data;
    if (ctx) {
        QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Cleanup: freeing outbox listener ctx for %.16s...",
                      ctx->contact_fingerprint);
        free(ctx);
    }
}

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
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] >>> About to return true (continue listening)");
    } else if (expired) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Value expired (ignoring)");
    } else {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] Empty value received (ignoring)");
    }

    QGP_LOG_WARN(LOG_TAG, "[LISTEN-CB] >>> CALLBACK RETURNING TRUE <<<");
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

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Setting up daily bucket listener for %.32s... (len=%zu)",
                 contact_fingerprint, fp_len);

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    /* Check if already listening to this contact */
    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            strcmp(engine->outbox_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {
            /* Verify listener is actually active in DHT layer */
            if (engine->outbox_listeners[i].dm_listen_ctx &&
                dht_is_listener_active(engine->outbox_listeners[i].dht_token)) {
                QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Already listening (token=%zu verified active)",
                             engine->outbox_listeners[i].dht_token);
                pthread_mutex_unlock(&engine->outbox_listeners_mutex);
                return engine->outbox_listeners[i].dht_token;
            } else {
                /* Stale entry - DHT listener was suspended/cancelled but engine not updated */
                QGP_LOG_WARN(LOG_TAG, "[LISTEN] Stale entry (token=%zu inactive in DHT), recreating",
                             engine->outbox_listeners[i].dht_token);
                if (engine->outbox_listeners[i].dm_listen_ctx) {
                    dht_dm_outbox_unsubscribe(dht_ctx, engine->outbox_listeners[i].dm_listen_ctx);
                    engine->outbox_listeners[i].dm_listen_ctx = NULL;
                }
                engine->outbox_listeners[i].active = false;
                /* Don't return - continue to create new listener */
                break;
            }
        }
    }

    /* Check capacity */
    if (engine->outbox_listener_count >= DNA_MAX_OUTBOX_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Max listeners reached (%d)", DNA_MAX_OUTBOX_LISTENERS);
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

    /*
     * v0.4.81: Use daily bucket subscribe with day rotation support.
     * Key format: contact_fp:outbox:my_fp:DAY_BUCKET
     * Day rotation is handled by dht_dm_outbox_check_day_rotation() called from heartbeat.
     */
    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Calling dht_dm_outbox_subscribe() for daily bucket...");

    dht_dm_listen_ctx_t *dm_listen_ctx = NULL;
    int result = dht_dm_outbox_subscribe(dht_ctx,
                                          engine->fingerprint,      /* my_fp (recipient) */
                                          contact_fingerprint,      /* contact_fp (sender) */
                                          outbox_listen_callback,
                                          ctx,
                                          &dm_listen_ctx);

    if (result != 0 || !dm_listen_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] dht_dm_outbox_subscribe() failed");
        free(ctx);
        pthread_mutex_unlock(&engine->outbox_listeners_mutex);
        return 0;
    }

    /* Get token from dm_listen_ctx */
    size_t token = dm_listen_ctx->listen_token;

    /* Store listener info */
    int idx = engine->outbox_listener_count++;
    strncpy(engine->outbox_listeners[idx].contact_fingerprint, contact_fingerprint,
            sizeof(engine->outbox_listeners[idx].contact_fingerprint) - 1);
    engine->outbox_listeners[idx].contact_fingerprint[
        sizeof(engine->outbox_listeners[idx].contact_fingerprint) - 1] = '\0';
    engine->outbox_listeners[idx].dht_token = token;
    engine->outbox_listeners[idx].active = true;
    engine->outbox_listeners[idx].dm_listen_ctx = dm_listen_ctx;

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] ✓ Daily bucket listener active: token=%zu, day=%lu, total=%d",
                 token, (unsigned long)dm_listen_ctx->current_day, engine->outbox_listener_count);

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

            /* Cancel daily bucket listener (v0.4.81+) */
            if (engine->outbox_listeners[i].dm_listen_ctx) {
                dht_dm_outbox_unsubscribe(dht_ctx, engine->outbox_listeners[i].dm_listen_ctx);
                engine->outbox_listeners[i].dm_listen_ctx = NULL;
            } else if (dht_ctx && engine->outbox_listeners[i].dht_token != 0) {
                /* Legacy fallback: direct DHT cancel */
                dht_cancel_listen(dht_ctx, engine->outbox_listeners[i].dht_token);
            }

            QGP_LOG_INFO(LOG_TAG, "Cancelled outbox listener for %.32s... (token=%zu)",
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

/**
 * Debug: Log all active outbox listeners
 * Called to verify which contacts have active listeners
 */
void dna_engine_log_active_listeners(dna_engine_t *engine) {
    if (!engine) return;

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    QGP_LOG_WARN(LOG_TAG, "[LISTEN-DEBUG] === ACTIVE OUTBOX LISTENERS (%d) ===",
                 engine->outbox_listener_count);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active) {
            bool dht_active = dht_is_listener_active(engine->outbox_listeners[i].dht_token);
            QGP_LOG_WARN(LOG_TAG, "[LISTEN-DEBUG]   [%d] %.32s... token=%zu dht_active=%d",
                         i,
                         engine->outbox_listeners[i].contact_fingerprint,
                         engine->outbox_listeners[i].dht_token,
                         dht_active);
        }
    }

    QGP_LOG_WARN(LOG_TAG, "[LISTEN-DEBUG] === END LISTENERS ===");

    pthread_mutex_unlock(&engine->outbox_listeners_mutex);
}

int dna_engine_listen_all_contacts(dna_engine_t *engine)
{
    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] dna_engine_listen_all_contacts() called");

    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] engine is NULL");
        return 0;
    }
    if (!engine->identity_loaded) {
        QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] identity not loaded yet");
        return 0;
    }

    /* Race condition prevention: only one listener setup at a time
     * If another thread is setting up listeners, wait for it to complete.
     * This prevents silent failures where the second caller gets 0 listeners. */
    if (engine->listeners_starting) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Listener setup already in progress, waiting...");
        /* Wait up to 5 seconds for the other thread to finish */
        for (int wait_count = 0; wait_count < 50 && engine->listeners_starting; wait_count++) {
            qgp_platform_sleep_ms(100);
        }
        if (engine->listeners_starting) {
            /* Other thread took too long - something is wrong, but don't block forever */
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Timed out waiting for listener setup, proceeding anyway");
        } else {
            /* Other thread finished - return its listener count (already set up) */
            QGP_LOG_INFO(LOG_TAG, "[LISTEN] Other thread finished listener setup, returning existing count");
            /* Count existing active listeners and return that */
            pthread_mutex_lock(&engine->outbox_listeners_mutex);
            int existing_count = 0;
            for (int i = 0; i < DNA_MAX_OUTBOX_LISTENERS; i++) {
                if (engine->outbox_listeners[i].active) existing_count++;
            }
            pthread_mutex_unlock(&engine->outbox_listeners_mutex);
            return existing_count;
        }
    }
    engine->listeners_starting = true;

    /* Wait for DHT to become ready (have peers in routing table)
     * This ensures listeners actually work instead of silently failing. */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx && !dht_context_is_ready(dht_ctx)) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Waiting for DHT to become ready...");
        int wait_seconds = 0;
        while (!dht_context_is_ready(dht_ctx) && wait_seconds < 30) {
            qgp_platform_sleep_ms(1000);
            wait_seconds++;
            if (wait_seconds % 5 == 0) {
                QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Still waiting for DHT... (%d/30s)", wait_seconds);
            }
        }
        if (dht_context_is_ready(dht_ctx)) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN] DHT ready after %d seconds", wait_seconds);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT not ready after 30s, proceeding anyway");
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] identity=%s", engine->fingerprint);

    /* Initialize contacts database for current identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to initialize contacts database");
        engine->listeners_starting = false;
        return 0;
    }

    /* Get all contacts */
    contact_list_t *list = NULL;
    int db_result = contacts_db_list(&list);
    if (db_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] contacts_db_list failed: %d", db_result);
        if (list) contacts_db_free_list(list);
        engine->listeners_starting = false;
        return 0;
    }
    if (!list || list->count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] No contacts in database (count=%zu)", list ? list->count : 0);
        if (list) contacts_db_free_list(list);
        /* Still start contact request listener even with 0 contacts!
         * Users need to receive contact requests regardless of contact count. */
        size_t contact_req_token = dna_engine_start_contact_request_listener(engine);
        if (contact_req_token > 0) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN] Contact request listener started (no contacts), token=%zu", contact_req_token);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Failed to start contact request listener");
        }
        engine->listeners_starting = false;
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Started 0 outbox + 0 presence + contact_req listeners");
        return 0;
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Found %zu contacts in database", list->count);

    /* PERF: Start listeners in parallel (mobile performance optimization)
     * Uses thread pool with max 8 concurrent threads to avoid overwhelming mobile devices.
     * Each thread sets up outbox + presence + watermark listeners for one contact. */
    size_t count = list->count;
    int max_parallel = 8;  /* Reasonable limit for mobile devices */

    parallel_listener_ctx_t *tasks = calloc(count, sizeof(parallel_listener_ctx_t));
    pthread_t *threads = calloc(count, sizeof(pthread_t));
    if (!tasks || !threads) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to allocate parallel task memory");
        free(tasks);
        free(threads);
        contacts_db_free_list(list);
        engine->listeners_starting = false;
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Starting parallel listeners for %zu contacts (max %d concurrent)",
                 count, max_parallel);

    size_t active = 0;   /* Index of oldest non-joined thread */
    size_t started = 0;  /* Number of threads started */

    for (size_t i = 0; i < count; i++) {
        const char *contact_id = list->contacts[i].identity;
        if (!contact_id) continue;

        /* Initialize task context */
        tasks[i].engine = engine;
        strncpy(tasks[i].fingerprint, contact_id, 128);
        tasks[i].fingerprint[128] = '\0';

        /* Spawn worker thread */
        if (pthread_create(&threads[i], NULL, parallel_listener_worker, &tasks[i]) == 0) {
            started++;
            QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Thread[%zu] started for %.32s...", i, contact_id);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Failed to create thread for contact[%zu]", i);
            continue;
        }

        /* Limit concurrent threads: wait for oldest when at max */
        if (started - active >= (size_t)max_parallel) {
            pthread_join(threads[active], NULL);
            QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Thread[%zu] joined", active);
            active++;
        }
    }

    /* Wait for remaining threads */
    for (size_t i = active; i < started; i++) {
        pthread_join(threads[i], NULL);
        QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Thread[%zu] joined (final)", i);
    }

    free(tasks);
    free(threads);

    /* Cleanup contact list */
    contacts_db_free_list(list);

    /* Start contact request listener (for real-time contact request notifications) */
    size_t contact_req_token = dna_engine_start_contact_request_listener(engine);
    if (contact_req_token > 0) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Contact request listener started, token=%zu", contact_req_token);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Failed to start contact request listener");
    }

    engine->listeners_starting = false;
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Parallel setup complete: %zu contacts processed", count);

    /* Debug: log all active listeners for troubleshooting */
    dna_engine_log_active_listeners(engine);

    return started;
}

/**
 * Start listeners for all contacts - MINIMAL version for Android service/JNI
 *
 * Only starts notification-relevant listeners (outbox, contact requests, groups).
 * Skips presence and watermark listeners which are only useful for UI.
 *
 * @param engine Engine context
 * @return Number of contacts with listeners started
 */
int dna_engine_listen_all_contacts_minimal(dna_engine_t *engine)
{
    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN_MIN] dna_engine_listen_all_contacts_minimal() called");

    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN_MIN] engine is NULL");
        return 0;
    }
    if (!engine->identity_loaded) {
        QGP_LOG_DEBUG(LOG_TAG, "[LISTEN_MIN] identity not loaded yet");
        return 0;
    }

    /* Race condition prevention */
    if (engine->listeners_starting) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN_MIN] Listener setup already in progress, waiting...");
        for (int wait_count = 0; wait_count < 50 && engine->listeners_starting; wait_count++) {
            qgp_platform_sleep_ms(100);
        }
        if (engine->listeners_starting) {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN_MIN] Timed out waiting for listener setup");
        } else {
            pthread_mutex_lock(&engine->outbox_listeners_mutex);
            int existing_count = 0;
            for (int i = 0; i < DNA_MAX_OUTBOX_LISTENERS; i++) {
                if (engine->outbox_listeners[i].active) existing_count++;
            }
            pthread_mutex_unlock(&engine->outbox_listeners_mutex);
            return existing_count;
        }
    }
    engine->listeners_starting = true;

    /* Wait for DHT to become ready */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx && !dht_context_is_ready(dht_ctx)) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] Waiting for DHT to become ready...");
        int wait_seconds = 0;
        while (!dht_context_is_ready(dht_ctx) && wait_seconds < 30) {
            qgp_platform_sleep_ms(1000);
            wait_seconds++;
        }
        if (dht_context_is_ready(dht_ctx)) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] DHT ready after %d seconds", wait_seconds);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN_MIN] DHT not ready after 30s, proceeding anyway");
        }
    }

    /* Initialize contacts database */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN_MIN] Failed to initialize contacts database");
        engine->listeners_starting = false;
        return 0;
    }

    /* Get all contacts */
    contact_list_t *list = NULL;
    int db_result = contacts_db_list(&list);
    if (db_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN_MIN] contacts_db_list failed: %d", db_result);
        if (list) contacts_db_free_list(list);
        engine->listeners_starting = false;
        return 0;
    }
    if (!list || list->count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[LISTEN_MIN] No contacts in database");
        if (list) contacts_db_free_list(list);
        /* Still start contact request listener */
        size_t contact_req_token = dna_engine_start_contact_request_listener(engine);
        if (contact_req_token > 0) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] Contact request listener started (no contacts)");
        }
        engine->listeners_starting = false;
        return 0;
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN_MIN] Found %zu contacts", list->count);

    /* Start MINIMAL listeners in parallel (outbox only - no presence/watermark) */
    size_t count = list->count;
    int max_parallel = 8;

    parallel_listener_ctx_t *tasks = calloc(count, sizeof(parallel_listener_ctx_t));
    pthread_t *threads = calloc(count, sizeof(pthread_t));
    if (!tasks || !threads) {
        free(tasks);
        free(threads);
        contacts_db_free_list(list);
        engine->listeners_starting = false;
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] Starting MINIMAL listeners for %zu contacts (outbox only)", count);

    size_t active = 0;
    size_t started = 0;

    for (size_t i = 0; i < count; i++) {
        const char *contact_id = list->contacts[i].identity;
        if (!contact_id) continue;

        tasks[i].engine = engine;
        strncpy(tasks[i].fingerprint, contact_id, 128);
        tasks[i].fingerprint[128] = '\0';

        /* Use MINIMAL worker - outbox only, no presence/watermark */
        if (pthread_create(&threads[i], NULL, parallel_listener_worker_minimal, &tasks[i]) == 0) {
            started++;
        }

        if (started - active >= (size_t)max_parallel) {
            pthread_join(threads[active], NULL);
            active++;
        }
    }

    /* Wait for remaining threads */
    for (size_t i = active; i < started; i++) {
        pthread_join(threads[i], NULL);
    }

    free(tasks);
    free(threads);
    contacts_db_free_list(list);

    /* Start contact request listener (needed for notifications) */
    size_t contact_req_token = dna_engine_start_contact_request_listener(engine);
    if (contact_req_token > 0) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] Contact request listener started");
    }

    /* Subscribe to all groups (needed for group message notifications) */
    int group_count = dna_engine_subscribe_all_groups(engine);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] Subscribed to %d groups", group_count);

    engine->listeners_starting = false;
    QGP_LOG_INFO(LOG_TAG, "[LISTEN_MIN] Minimal setup complete: %zu outbox + contact_req + %d groups",
                 started, group_count);

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
        if (engine->outbox_listeners[i].active) {
            /* Free daily bucket context (v0.5.0+) */
            if (engine->outbox_listeners[i].dm_listen_ctx) {
                dht_dm_outbox_unsubscribe(dht_ctx, engine->outbox_listeners[i].dm_listen_ctx);
                engine->outbox_listeners[i].dm_listen_ctx = NULL;
            } else if (dht_ctx && engine->outbox_listeners[i].dht_token != 0) {
                /* Legacy fallback */
                dht_cancel_listen(dht_ctx, engine->outbox_listeners[i].dht_token);
            }
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
 * PRESENCE LISTENERS (Real-time contact online status)
 * ============================================================================ */

/**
 * Context passed to DHT presence listen callback
 */
typedef struct {
    dna_engine_t *engine;
    char contact_fingerprint[129];
} presence_listener_ctx_t;

/**
 * Cleanup callback for presence listeners - frees the context when listener cancelled
 */
static void presence_listener_cleanup(void *user_data) {
    presence_listener_ctx_t *ctx = (presence_listener_ctx_t *)user_data;
    if (ctx) {
        QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Cleanup: freeing presence listener ctx for %.16s...",
                      ctx->contact_fingerprint);
        free(ctx);
    }
}

/**
 * DHT listen callback for presence - fires when contact publishes their presence
 */
static bool presence_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    presence_listener_ctx_t *ctx = (presence_listener_ctx_t *)user_data;
    if (!ctx || !ctx->engine) {
        return false;  /* Stop listening */
    }

    if (expired || !value || value_len == 0) {
        /* Presence expired - mark contact as offline */
        presence_cache_update(ctx->contact_fingerprint, false, time(NULL));
        QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Contact %.16s... went offline (expired)",
                      ctx->contact_fingerprint);
        return true;  /* Keep listening */
    }

    /* Parse presence JSON to get actual timestamp */
    /* Format: {"ips":"...","port":...,"timestamp":1234567890} */
    char json_buf[512];
    size_t copy_len = value_len < sizeof(json_buf) - 1 ? value_len : sizeof(json_buf) - 1;
    memcpy(json_buf, value, copy_len);
    json_buf[copy_len] = '\0';

    /* v0.4.61: timestamp-only presence (privacy - no IP disclosure) */
    uint64_t last_seen = 0;
    time_t presence_timestamp = time(NULL);  /* Fallback to now if parse fails */
    if (parse_presence_json(json_buf, &last_seen) == 0 && last_seen > 0) {
        presence_timestamp = (time_t)last_seen;
    }

    /* Update cache with actual timestamp from presence data */
    presence_cache_update(ctx->contact_fingerprint, true, presence_timestamp);
    QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Contact %.16s... is online (timestamp=%lld)",
                  ctx->contact_fingerprint, (long long)presence_timestamp);

    return true;  /* Keep listening */
}

/**
 * Start listening for a contact's presence updates
 */
size_t dna_engine_start_presence_listener(
    dna_engine_t *engine,
    const char *contact_fingerprint)
{
    if (!engine || !contact_fingerprint) {
        return 0;
    }

    size_t fp_len = strlen(contact_fingerprint);
    if (fp_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "[PRESENCE] Invalid fingerprint length: %zu", fp_len);
        return 0;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[PRESENCE] DHT not available");
        return 0;
    }

    pthread_mutex_lock(&engine->presence_listeners_mutex);

    /* Check if already listening to this contact */
    for (int i = 0; i < engine->presence_listener_count; i++) {
        if (engine->presence_listeners[i].active &&
            strcmp(engine->presence_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {
            /* Verify listener is actually active in DHT layer */
            if (dht_is_listener_active(engine->presence_listeners[i].dht_token)) {
                QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Already listening (token=%zu verified active)",
                             engine->presence_listeners[i].dht_token);
                pthread_mutex_unlock(&engine->presence_listeners_mutex);
                return engine->presence_listeners[i].dht_token;
            } else {
                /* Stale entry - DHT listener was suspended/cancelled but engine not updated */
                QGP_LOG_WARN(LOG_TAG, "[PRESENCE] Stale entry (token=%zu inactive in DHT), recreating",
                             engine->presence_listeners[i].dht_token);
                engine->presence_listeners[i].active = false;
                /* Don't return - continue to create new listener */
                break;
            }
        }
    }

    /* Check capacity */
    if (engine->presence_listener_count >= DNA_MAX_PRESENCE_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[PRESENCE] Max listeners reached (%d)", DNA_MAX_PRESENCE_LISTENERS);
        pthread_mutex_unlock(&engine->presence_listeners_mutex);
        return 0;
    }

    /* Convert hex fingerprint to binary DHT key (64 bytes) */
    uint8_t presence_key[64];
    for (int i = 0; i < 64; i++) {
        unsigned int byte;
        if (sscanf(contact_fingerprint + (i * 2), "%02x", &byte) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "[PRESENCE] Invalid fingerprint hex");
            pthread_mutex_unlock(&engine->presence_listeners_mutex);
            return 0;
        }
        presence_key[i] = (uint8_t)byte;
    }

    /* Create callback context */
    presence_listener_ctx_t *ctx = malloc(sizeof(presence_listener_ctx_t));
    if (!ctx) {
        pthread_mutex_unlock(&engine->presence_listeners_mutex);
        return 0;
    }
    ctx->engine = engine;
    strncpy(ctx->contact_fingerprint, contact_fingerprint, sizeof(ctx->contact_fingerprint) - 1);
    ctx->contact_fingerprint[sizeof(ctx->contact_fingerprint) - 1] = '\0';

    /* Start DHT listen on presence key */
    size_t token = dht_listen_ex(dht_ctx, presence_key, 64,
                                  presence_listen_callback, ctx, presence_listener_cleanup);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[PRESENCE] dht_listen_ex() failed for %.16s...", contact_fingerprint);
        free(ctx);  /* Cleanup not called on failure, free manually */
        pthread_mutex_unlock(&engine->presence_listeners_mutex);
        return 0;
    }

    /* Store listener info */
    int idx = engine->presence_listener_count++;
    strncpy(engine->presence_listeners[idx].contact_fingerprint, contact_fingerprint,
            sizeof(engine->presence_listeners[idx].contact_fingerprint) - 1);
    engine->presence_listeners[idx].contact_fingerprint[
        sizeof(engine->presence_listeners[idx].contact_fingerprint) - 1] = '\0';
    engine->presence_listeners[idx].dht_token = token;
    engine->presence_listeners[idx].active = true;

    QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Listener started for %.16s... (token=%zu)",
                  contact_fingerprint, token);

    pthread_mutex_unlock(&engine->presence_listeners_mutex);
    return token;
}

/**
 * Cancel presence listener for a specific contact
 */
void dna_engine_cancel_presence_listener(
    dna_engine_t *engine,
    const char *contact_fingerprint)
{
    if (!engine || !contact_fingerprint) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->presence_listeners_mutex);

    for (int i = 0; i < engine->presence_listener_count; i++) {
        if (engine->presence_listeners[i].active &&
            strcmp(engine->presence_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {

            if (dht_ctx) {
                dht_cancel_listen(dht_ctx, engine->presence_listeners[i].dht_token);
            }

            engine->presence_listeners[i].active = false;

            /* Compact array */
            if (i < engine->presence_listener_count - 1) {
                engine->presence_listeners[i] = engine->presence_listeners[engine->presence_listener_count - 1];
            }
            engine->presence_listener_count--;
            break;
        }
    }

    pthread_mutex_unlock(&engine->presence_listeners_mutex);
}

/**
 * Cancel all presence listeners
 */
void dna_engine_cancel_all_presence_listeners(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->presence_listeners_mutex);

    for (int i = 0; i < engine->presence_listener_count; i++) {
        if (engine->presence_listeners[i].active && dht_ctx) {
            dht_cancel_listen(dht_ctx, engine->presence_listeners[i].dht_token);
        }
        engine->presence_listeners[i].active = false;
    }

    engine->presence_listener_count = 0;
    QGP_LOG_INFO(LOG_TAG, "Cancelled all presence listeners");

    pthread_mutex_unlock(&engine->presence_listeners_mutex);
}

/**
 * Refresh all listeners (cancel stale and restart)
 *
 * Clears engine-level listener tracking and restarts for all contacts.
 * Use after network changes when DHT is reconnected.
 */
int dna_engine_refresh_listeners(dna_engine_t *engine)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "[REFRESH] Cannot refresh - engine=%p identity_loaded=%d",
                      (void*)engine, engine ? engine->identity_loaded : 0);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "[REFRESH] Refreshing all listeners...");

    /* Get listener stats before refresh for debugging */
    size_t total = 0, active = 0, suspended = 0;
    dht_get_listener_stats(&total, &active, &suspended);
    QGP_LOG_INFO(LOG_TAG, "[REFRESH] DHT layer: total=%zu active=%zu suspended=%zu",
                 total, active, suspended);

    /* Cancel all engine-level listener tracking (clears arrays) */
    dna_engine_cancel_all_outbox_listeners(engine);
    dna_engine_cancel_all_presence_listeners(engine);
    dna_engine_cancel_contact_request_listener(engine);

    /* Restart listeners for all contacts (includes contact request listener) */
    int count = dna_engine_listen_all_contacts(engine);
    QGP_LOG_INFO(LOG_TAG, "[REFRESH] Restarted %d listeners", count);

    return count;
}

/* ============================================================================
 * CONTACT REQUEST LISTENER (Real-time contact request notifications)
 * ============================================================================ */

/**
 * Context passed to DHT contact request listen callback
 */
typedef struct {
    dna_engine_t *engine;
} contact_request_listener_ctx_t;

/**
 * Cleanup callback for contact request listener - frees the context when listener cancelled
 */
static void contact_request_listener_cleanup(void *user_data) {
    contact_request_listener_ctx_t *ctx = (contact_request_listener_ctx_t *)user_data;
    if (ctx) {
        QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Cleanup: freeing contact request listener ctx");
        free(ctx);
    }
}

/**
 * DHT callback when contact request data changes
 * Fires DNA_EVENT_CONTACT_REQUEST_RECEIVED only for genuinely new requests
 */
static bool contact_request_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    contact_request_listener_ctx_t *ctx = (contact_request_listener_ctx_t *)user_data;
    if (!ctx || !ctx->engine) {
        return false;  /* Stop listening */
    }

    /* Don't fire events for expirations or empty values */
    if (expired || !value || value_len == 0) {
        return true;  /* Continue listening */
    }

    /* Parse the contact request to check if it's from a known contact */
    dht_contact_request_t request = {0};
    if (dht_deserialize_contact_request(value, value_len, &request) != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Failed to parse request data (%zu bytes)", value_len);
        return true;  /* Continue listening, might be corrupt data */
    }

    /* Skip if sender is already a contact */
    if (contacts_db_exists(request.sender_fingerprint)) {
        QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Ignoring request from existing contact: %.20s...",
                      request.sender_fingerprint);
        return true;  /* Continue listening */
    }

    /* Skip if we already have a pending request from this sender */
    if (contacts_db_request_exists(request.sender_fingerprint)) {
        QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Ignoring duplicate request from: %.20s...",
                      request.sender_fingerprint);
        return true;  /* Continue listening */
    }

    /* Skip if sender is blocked */
    if (contacts_db_is_blocked(request.sender_fingerprint)) {
        QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Ignoring request from blocked user: %.20s...",
                      request.sender_fingerprint);
        return true;  /* Continue listening */
    }

    QGP_LOG_INFO(LOG_TAG, "[CONTACT_REQ] New contact request from: %.20s... (%s)",
                 request.sender_fingerprint,
                 request.sender_name[0] ? request.sender_name : "unknown");

    /* Dispatch event to notify UI */
    dna_event_t event = {0};
    event.type = DNA_EVENT_CONTACT_REQUEST_RECEIVED;
    dna_dispatch_event(ctx->engine, &event);

    return true;  /* Continue listening */
}

/**
 * Start contact request listener
 *
 * Listens on our contact request inbox key: SHA3-512(my_fingerprint + ":requests")
 * When someone sends us a contact request, the listener fires and we emit
 * DNA_EVENT_CONTACT_REQUEST_RECEIVED to refresh the UI.
 *
 * @return Listen token (> 0 on success, 0 on failure or already listening)
 */
size_t dna_engine_start_contact_request_listener(dna_engine_t *engine)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "[CONTACT_REQ] Cannot start listener - no identity loaded");
        return 0;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[CONTACT_REQ] DHT not available");
        return 0;
    }

    pthread_mutex_lock(&engine->contact_request_listener_mutex);

    /* Check if already listening */
    if (engine->contact_request_listener.active) {
        /* Verify listener is actually active in DHT layer */
        if (dht_is_listener_active(engine->contact_request_listener.dht_token)) {
            QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Already listening (token=%zu verified active)",
                         engine->contact_request_listener.dht_token);
            pthread_mutex_unlock(&engine->contact_request_listener_mutex);
            return engine->contact_request_listener.dht_token;
        } else {
            /* Stale entry - DHT listener was suspended/cancelled but engine not updated */
            QGP_LOG_WARN(LOG_TAG, "[CONTACT_REQ] Stale entry (token=%zu inactive in DHT), recreating",
                         engine->contact_request_listener.dht_token);
            engine->contact_request_listener.active = false;
        }
    }

    /* Generate inbox key: SHA3-512(fingerprint + ":requests") */
    uint8_t inbox_key[64];
    dht_generate_requests_inbox_key(engine->fingerprint, inbox_key);

    /* Create callback context */
    contact_request_listener_ctx_t *ctx = malloc(sizeof(contact_request_listener_ctx_t));
    if (!ctx) {
        pthread_mutex_unlock(&engine->contact_request_listener_mutex);
        return 0;
    }
    ctx->engine = engine;

    /* Start DHT listen on inbox key */
    size_t token = dht_listen_ex(dht_ctx, inbox_key, 64,
                                  contact_request_listen_callback, ctx, contact_request_listener_cleanup);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[CONTACT_REQ] dht_listen_ex() failed");
        free(ctx);  /* Cleanup not called on failure, free manually */
        pthread_mutex_unlock(&engine->contact_request_listener_mutex);
        return 0;
    }

    /* Store listener info */
    engine->contact_request_listener.dht_token = token;
    engine->contact_request_listener.active = true;

    QGP_LOG_INFO(LOG_TAG, "[CONTACT_REQ] Listener started (token=%zu)", token);

    pthread_mutex_unlock(&engine->contact_request_listener_mutex);
    return token;
}

/**
 * Cancel contact request listener
 */
void dna_engine_cancel_contact_request_listener(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->contact_request_listener_mutex);

    if (engine->contact_request_listener.active && dht_ctx) {
        dht_cancel_listen(dht_ctx, engine->contact_request_listener.dht_token);
        QGP_LOG_INFO(LOG_TAG, "[CONTACT_REQ] Listener cancelled (token=%zu)",
                     engine->contact_request_listener.dht_token);
    }
    engine->contact_request_listener.active = false;
    engine->contact_request_listener.dht_token = 0;

    pthread_mutex_unlock(&engine->contact_request_listener_mutex);
}

/* ============================================================================
 * PERSISTENT WATERMARK LISTENERS (Message delivery confirmation)
 * ============================================================================ */

/**
 * Internal callback for persistent watermark updates
 * Updates message status and dispatches DNA_EVENT_MESSAGE_DELIVERED
 */
static void watermark_listener_callback(
    const char *sender,
    const char *recipient,
    uint64_t seq_num,
    void *user_data
) {
    dna_engine_t *engine = (dna_engine_t *)user_data;
    if (!engine) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Received: %.20s... → %.20s... seq=%lu",
                 sender, recipient, (unsigned long)seq_num);

    /* Check if this is a new watermark (higher seq than we've seen) */
    uint64_t last_known = 0;

    pthread_mutex_lock(&engine->watermark_listeners_mutex);
    for (int i = 0; i < engine->watermark_listener_count; i++) {
        if (engine->watermark_listeners[i].active &&
            strcmp(engine->watermark_listeners[i].contact_fingerprint, recipient) == 0) {
            last_known = engine->watermark_listeners[i].last_known_watermark;
            if (seq_num > last_known) {
                engine->watermark_listeners[i].last_known_watermark = seq_num;
            }
            break;
        }
    }
    pthread_mutex_unlock(&engine->watermark_listeners_mutex);

    /* Skip if we've already processed this or a higher watermark */
    if (seq_num <= last_known) {
        QGP_LOG_DEBUG(LOG_TAG, "[WATERMARK] Ignoring old/duplicate (seq=%lu <= last=%lu)",
                     (unsigned long)seq_num, (unsigned long)last_known);
        return;
    }

    /* Update message status in database (all messages with seq <= seq_num are delivered) */
    if (engine->messenger && engine->messenger->backup_ctx) {
        int updated = message_backup_mark_delivered_up_to_seq(
            engine->messenger->backup_ctx,
            sender,      /* My fingerprint - I sent the messages */
            recipient,   /* Contact fingerprint - they received */
            seq_num
        );
        if (updated > 0) {
            QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Updated %d messages to DELIVERED", updated);
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

/**
 * Start persistent watermark listener for a contact
 *
 * IMPORTANT: This function releases the mutex before DHT calls to prevent
 * ABBA deadlock (watermark_listeners_mutex vs DHT listeners_mutex).
 *
 * @param engine Engine instance
 * @param contact_fingerprint Contact to listen for watermarks from
 * @return DHT listener token (>0 on success, 0 on failure)
 */
size_t dna_engine_start_watermark_listener(
    dna_engine_t *engine,
    const char *contact_fingerprint
) {
    if (!engine || !contact_fingerprint || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "[WATERMARK] Cannot start: invalid params or no identity");
        return 0;
    }

    /* Validate fingerprints */
    size_t my_fp_len = strlen(engine->fingerprint);
    size_t contact_len = strlen(contact_fingerprint);
    if (my_fp_len != 128 || contact_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "[WATERMARK] Invalid fingerprint length: mine=%zu contact=%zu",
                      my_fp_len, contact_len);
        return 0;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[WATERMARK] DHT not available");
        return 0;
    }

    /* Phase 1: Check duplicates and capacity under mutex */
    pthread_mutex_lock(&engine->watermark_listeners_mutex);

    for (int i = 0; i < engine->watermark_listener_count; i++) {
        if (engine->watermark_listeners[i].active &&
            strcmp(engine->watermark_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "[WATERMARK] Already listening for %.20s...", contact_fingerprint);
            size_t existing = engine->watermark_listeners[i].dht_token;
            pthread_mutex_unlock(&engine->watermark_listeners_mutex);
            return existing;
        }
    }

    if (engine->watermark_listener_count >= DNA_MAX_WATERMARK_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[WATERMARK] Maximum listeners reached (%d)", DNA_MAX_WATERMARK_LISTENERS);
        pthread_mutex_unlock(&engine->watermark_listeners_mutex);
        return 0;
    }

    /* Copy fingerprint for use outside mutex */
    char fp_copy[129];
    strncpy(fp_copy, contact_fingerprint, sizeof(fp_copy) - 1);
    fp_copy[128] = '\0';

    pthread_mutex_unlock(&engine->watermark_listeners_mutex);

    /* Phase 2: DHT operations WITHOUT holding mutex (prevents ABBA deadlock) */

    /* Pre-fetch current watermark to filter stale cached values AND mark delivered */
    uint64_t current_watermark = 0;
    dht_get_watermark(dht_ctx, fp_copy, engine->fingerprint, &current_watermark);
    QGP_LOG_DEBUG(LOG_TAG, "[WATERMARK] Pre-fetched for %.20s...: seq=%lu",
                 fp_copy, (unsigned long)current_watermark);

    /* If we have a watermark, mark those messages as delivered NOW.
     * This handles the case where we missed listener callbacks (e.g., fresh install,
     * or messages sent from another device). Without this, the pre-fetch value
     * becomes the baseline and we ignore listener callbacks with lower seq. */
    if (current_watermark > 0 && engine->messenger && engine->messenger->backup_ctx) {
        int updated = message_backup_mark_delivered_up_to_seq(
            engine->messenger->backup_ctx,
            fp_copy,                /* Contact sent us watermark */
            engine->fingerprint,    /* We sent the messages */
            current_watermark
        );
        if (updated > 0) {
            QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Pre-fetch: marked %d messages as DELIVERED (seq<=%lu)",
                         updated, (unsigned long)current_watermark);

            /* Dispatch event to Flutter so UI updates (double checkmark) */
            dna_event_t event = {0};
            event.type = DNA_EVENT_MESSAGE_DELIVERED;
            strncpy(event.data.message_delivered.recipient, fp_copy,
                    sizeof(event.data.message_delivered.recipient) - 1);
            event.data.message_delivered.seq_num = current_watermark;
            event.data.message_delivered.timestamp = (uint64_t)time(NULL);
            dna_dispatch_event(engine, &event);
            QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Pre-fetch: dispatched MESSAGE_DELIVERED event");
        }
    }

    /* Start DHT watermark listener */
    size_t token = dht_listen_watermark(dht_ctx,
                                        engine->fingerprint,
                                        fp_copy,
                                        watermark_listener_callback,
                                        engine);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[WATERMARK] Failed to start listener for %.20s...", fp_copy);
        return 0;
    }

    /* Phase 3: Store listener info under mutex */
    pthread_mutex_lock(&engine->watermark_listeners_mutex);

    /* Re-check capacity (race condition) */
    if (engine->watermark_listener_count >= DNA_MAX_WATERMARK_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[WATERMARK] Capacity reached after DHT start, cancelling");
        pthread_mutex_unlock(&engine->watermark_listeners_mutex);
        dht_cancel_watermark_listener(dht_ctx, token);
        return 0;
    }

    /* Check if another thread added this listener */
    for (int i = 0; i < engine->watermark_listener_count; i++) {
        if (engine->watermark_listeners[i].active &&
            strcmp(engine->watermark_listeners[i].contact_fingerprint, fp_copy) == 0) {
            QGP_LOG_WARN(LOG_TAG, "[WATERMARK] Race: duplicate for %.20s..., cancelling", fp_copy);
            pthread_mutex_unlock(&engine->watermark_listeners_mutex);
            dht_cancel_watermark_listener(dht_ctx, token);
            return engine->watermark_listeners[i].dht_token;
        }
    }

    /* Store listener */
    int idx = engine->watermark_listener_count++;
    strncpy(engine->watermark_listeners[idx].contact_fingerprint, fp_copy,
            sizeof(engine->watermark_listeners[idx].contact_fingerprint) - 1);
    engine->watermark_listeners[idx].contact_fingerprint[128] = '\0';
    engine->watermark_listeners[idx].dht_token = token;
    engine->watermark_listeners[idx].last_known_watermark = current_watermark;
    engine->watermark_listeners[idx].active = true;

    QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Started listener for %.20s... (token=%zu, baseline=%lu)",
                 fp_copy, token, (unsigned long)current_watermark);

    pthread_mutex_unlock(&engine->watermark_listeners_mutex);
    return token;
}

/**
 * Cancel all watermark listeners (called on engine destroy or identity unload)
 */
void dna_engine_cancel_all_watermark_listeners(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->watermark_listeners_mutex);

    for (int i = 0; i < engine->watermark_listener_count; i++) {
        if (engine->watermark_listeners[i].active && dht_ctx) {
            dht_cancel_watermark_listener(dht_ctx, engine->watermark_listeners[i].dht_token);
            QGP_LOG_DEBUG(LOG_TAG, "[WATERMARK] Cancelled listener for %.20s...",
                          engine->watermark_listeners[i].contact_fingerprint);
        }
        engine->watermark_listeners[i].active = false;
    }

    engine->watermark_listener_count = 0;
    QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Cancelled all listeners");

    pthread_mutex_unlock(&engine->watermark_listeners_mutex);
}

/**
 * Cancel watermark listener for a specific contact
 * Called when a contact is removed.
 */
void dna_engine_cancel_watermark_listener(dna_engine_t *engine, const char *contact_fingerprint)
{
    if (!engine || !contact_fingerprint) {
        return;
    }

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->watermark_listeners_mutex);

    for (int i = 0; i < engine->watermark_listener_count; i++) {
        if (engine->watermark_listeners[i].active &&
            strcmp(engine->watermark_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {

            if (dht_ctx) {
                dht_cancel_watermark_listener(dht_ctx, engine->watermark_listeners[i].dht_token);
            }

            QGP_LOG_INFO(LOG_TAG, "[WATERMARK] Cancelled listener for %.20s...", contact_fingerprint);

            /* Remove by swapping with last element */
            if (i < engine->watermark_listener_count - 1) {
                engine->watermark_listeners[i] = engine->watermark_listeners[engine->watermark_listener_count - 1];
            }
            engine->watermark_listener_count--;
            break;
        }
    }

    pthread_mutex_unlock(&engine->watermark_listeners_mutex);
}

/* ============================================================================
 * P2P & PRESENCE HANDLERS
 * ============================================================================ */

void dna_handle_refresh_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    /* Don't announce presence if app is in background (defense in depth) */
    if (!atomic_load(&engine->presence_active)) {
        QGP_LOG_DEBUG(LOG_TAG, "Skipping presence refresh - app in background");
        if (task->callback.completion) {
            task->callback.completion(task->request_id, DNA_OK, task->user_data);
        }
        return;
    }

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_transport_refresh_presence(engine->messenger) != 0) {
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
        if (messenger_transport_lookup_presence(engine->messenger,
                task->params.lookup_presence.fingerprint,
                &last_seen) == 0 && last_seen > 0) {
            /* Update presence cache with DHT result */
            time_t now = time(NULL);
            bool is_online = (now - (time_t)last_seen) < 300; /* 5 min TTL */
            presence_cache_update(task->params.lookup_presence.fingerprint,
                                  is_online, (time_t)last_seen);
        }
        /* Not found is not an error - just return 0 timestamp */
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

void dna_handle_sync_groups_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        QGP_LOG_INFO(LOG_TAG, "[GROUPLIST_PUBLISH] sync_groups_to_dht handler: calling sync");
        if (messenger_sync_groups_to_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_group_by_uuid(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    const char *group_uuid = task->params.sync_group_by_uuid.group_uuid;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else if (!group_uuid || strlen(group_uuid) != 36) {
        error = DNA_ENGINE_ERROR_INVALID_PARAM;
    } else {
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            int ret = dht_groups_sync_from_dht(dht_ctx, group_uuid);
            if (ret != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to sync group %s from DHT: %d", group_uuid, ret);
                error = DNA_ENGINE_ERROR_NETWORK;
            } else {
                QGP_LOG_INFO(LOG_TAG, "Successfully synced group %s from DHT", group_uuid);
                // Also sync GEK for this group
                int gek_ret = messenger_sync_group_gek(group_uuid);
                if (gek_ret != 0) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to sync GEK for group %s (non-fatal)", group_uuid);
                } else {
                    QGP_LOG_INFO(LOG_TAG, "Successfully synced GEK for group %s", group_uuid);
                }

                // Sync messages from DHT to local DB
                size_t msg_count = 0;
                int msg_ret = dna_group_outbox_sync(dht_ctx, group_uuid, &msg_count);
                if (msg_ret != 0) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to sync messages for group %s (non-fatal)", group_uuid);
                } else if (msg_count > 0) {
                    QGP_LOG_INFO(LOG_TAG, "Synced %zu new messages for group %s", msg_count, group_uuid);
                }
            }
        } else {
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

void dna_free_group_info(dna_group_info_t *info) {
    free(info);
}

void dna_free_group_members(dna_group_member_t *members, int count) {
    (void)count;
    free(members);
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
    /* v0.6.0+: Engine owns its own DHT context (no global singleton) */
    if (engine && engine->dht_ctx) {
        return engine->dht_ctx;
    }
    /* Fallback to singleton during migration (will be removed) */
    return dht_singleton_get();
}

/* Helper: Get private key for signing (caller frees with qgp_key_free) */
static qgp_key_t* dna_load_private_key(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }

    /* v0.3.0: Flat structure - keys/identity.dsa */
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", engine->data_dir);

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

    /* v0.3.0: Flat structure - keys/identity.kem */
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.kem", engine->data_dir);

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
    qgp_log_ring_add(QGP_LOG_LEVEL_INFO, tag, "%s", message);
    qgp_log_file_write(QGP_LOG_LEVEL_INFO, tag, "%s", message);
}

void dna_engine_debug_log_message_level(const char *tag, const char *message, int level) {
    if (!tag || !message) return;
    qgp_log_level_t log_level = (level >= 0 && level <= 3) ? (qgp_log_level_t)level : QGP_LOG_LEVEL_INFO;
    qgp_log_ring_add(log_level, tag, "%s", message);
    qgp_log_file_write(log_level, tag, "%s", message);
}

int dna_engine_debug_log_export(const char *filepath) {
    if (!filepath) return -1;
    return qgp_log_export_to_file(filepath);
}

/* ============================================================================
 * MESSAGE BACKUP/RESTORE IMPLEMENTATION
 * ============================================================================ */

/* Context for async backup thread */
typedef struct {
    dna_engine_t *engine;
    dna_request_id_t request_id;
    dna_backup_result_cb callback;
    void *user_data;
    qgp_key_t *kyber_key;
    qgp_key_t *dilithium_key;
} backup_thread_ctx_t;

/* Context for async restore thread */
typedef struct {
    dna_engine_t *engine;
    dna_request_id_t request_id;
    dna_backup_result_cb callback;
    void *user_data;
    qgp_key_t *kyber_key;
    qgp_key_t *dilithium_key;
} restore_thread_ctx_t;

/* Background thread for message backup (never blocks UI) */
static void *backup_thread_func(void *arg) {
    backup_thread_ctx_t *ctx = (backup_thread_ctx_t *)arg;
    if (!ctx) return NULL;

    QGP_LOG_INFO(LOG_TAG, "[BACKUP-THREAD] Starting async backup...");

    dna_engine_t *engine = ctx->engine;
    if (!engine || !engine->messenger || !engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "[BACKUP-THREAD] Engine not ready, aborting");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[BACKUP-THREAD] DHT not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get message backup context */
    message_backup_context_t *msg_ctx = engine->messenger->backup_ctx;
    if (!msg_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[BACKUP-THREAD] Backup context not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Perform backup (slow DHT operation) */
    int message_count = 0;
    int result = dht_message_backup_publish(
        dht_ctx,
        msg_ctx,
        engine->fingerprint,
        ctx->kyber_key->public_key,
        ctx->kyber_key->private_key,
        ctx->dilithium_key->public_key,
        ctx->dilithium_key->private_key,
        &message_count
    );

    /* Cleanup keys */
    qgp_key_free(ctx->kyber_key);
    qgp_key_free(ctx->dilithium_key);

    /* Invoke callback with results */
    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "[BACKUP-THREAD] Backup completed: %d messages", message_count);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, 0, message_count, 0, ctx->user_data);
        }
    } else {
        QGP_LOG_ERROR(LOG_TAG, "[BACKUP-THREAD] Backup failed: %d", result);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, result, 0, 0, ctx->user_data);
        }
    }

    free(ctx);
    return NULL;
}

/* Background thread for message restore (never blocks UI) */
static void *restore_thread_func(void *arg) {
    restore_thread_ctx_t *ctx = (restore_thread_ctx_t *)arg;
    if (!ctx) return NULL;

    QGP_LOG_INFO(LOG_TAG, "[RESTORE-THREAD] Starting async restore...");

    dna_engine_t *engine = ctx->engine;
    if (!engine || !engine->messenger || !engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "[RESTORE-THREAD] Engine not ready, aborting");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE-THREAD] DHT not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get message backup context */
    message_backup_context_t *msg_ctx = engine->messenger->backup_ctx;
    if (!msg_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE-THREAD] Backup context not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Perform restore (slow DHT operation) */
    int restored_count = 0;
    int skipped_count = 0;
    int result = dht_message_backup_restore(
        dht_ctx,
        msg_ctx,
        engine->fingerprint,
        ctx->kyber_key->private_key,
        ctx->dilithium_key->public_key,
        &restored_count,
        &skipped_count
    );

    /* Cleanup keys */
    qgp_key_free(ctx->kyber_key);
    qgp_key_free(ctx->dilithium_key);

    /* Invoke callback with results */
    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "[RESTORE-THREAD] Restore completed: %d restored, %d skipped",
                     restored_count, skipped_count);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, 0, restored_count, skipped_count, ctx->user_data);
        }
    } else if (result == -2) {
        QGP_LOG_INFO(LOG_TAG, "[RESTORE-THREAD] No backup found in DHT");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -2, 0, 0, ctx->user_data);
        }
    } else {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE-THREAD] Restore failed: %d", result);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, result, 0, 0, ctx->user_data);
        }
    }

    free(ctx);
    return NULL;
}

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

    /* Load keys on main thread for fast-fail validation */
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    /* Load Kyber keypair (v0.3.0: flat structure - keys/identity.kem) */
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

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

    /* Load Dilithium keypair (v0.3.0: flat structure) */
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

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

    /* Allocate thread context - keys ownership transferred to thread */
    backup_thread_ctx_t *ctx = (backup_thread_ctx_t *)malloc(sizeof(backup_thread_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate backup thread context");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    ctx->engine = engine;
    ctx->request_id = request_id;
    ctx->callback = callback;
    ctx->user_data = user_data;
    ctx->kyber_key = kyber_key;
    ctx->dilithium_key = dilithium_key;

    /* Spawn detached thread for async backup (never blocks UI) */
    pthread_t backup_thread;
    if (pthread_create(&backup_thread, NULL, backup_thread_func, ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to spawn backup thread");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        free(ctx);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }
    pthread_detach(backup_thread);

    QGP_LOG_INFO(LOG_TAG, "Backup thread spawned (request_id=%llu)", (unsigned long long)request_id);
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

    /* Load keys on main thread for fast-fail validation */
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    /* Load Kyber keypair (v0.3.0: flat structure - keys/identity.kem) */
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

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

    /* Load Dilithium keypair (v0.3.0: flat structure) */
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

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

    /* Allocate thread context - keys ownership transferred to thread */
    restore_thread_ctx_t *ctx = (restore_thread_ctx_t *)malloc(sizeof(restore_thread_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate restore thread context");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    ctx->engine = engine;
    ctx->request_id = request_id;
    ctx->callback = callback;
    ctx->user_data = user_data;
    ctx->kyber_key = kyber_key;
    ctx->dilithium_key = dilithium_key;

    /* Spawn detached thread for async restore (never blocks UI) */
    pthread_t restore_thread;
    if (pthread_create(&restore_thread, NULL, restore_thread_func, ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to spawn restore thread");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        free(ctx);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }
    pthread_detach(restore_thread);

    QGP_LOG_INFO(LOG_TAG, "Restore thread spawned (request_id=%llu)", (unsigned long long)request_id);
    return request_id;
}

/* ============================================================================
 * BACKUP CHECK API
 * ============================================================================ */

dna_request_id_t dna_engine_check_backup_exists(
    dna_engine_t *engine,
    dna_backup_info_cb callback,
    void *user_data)
{
    dna_request_id_t request_id = dna_next_request_id(engine);

    if (!engine || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "check_backup_exists: invalid parameters");
        if (callback) {
            dna_backup_info_t info = {0};
            callback(request_id, -1, &info, user_data);
        }
        return request_id;
    }

    if (engine->fingerprint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "check_backup_exists: no identity loaded");
        dna_backup_info_t info = {0};
        callback(request_id, -1, &info, user_data);
        return request_id;
    }

    // Get DHT context
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "check_backup_exists: DHT not initialized");
        dna_backup_info_t info = {0};
        callback(request_id, -1, &info, user_data);
        return request_id;
    }

    QGP_LOG_INFO(LOG_TAG, "Checking if backup exists for fingerprint %.20s...",
                 engine->fingerprint);

    // Use dht_message_backup_get_info to check without full download
    uint64_t timestamp = 0;
    int message_count = -1;
    int result = dht_message_backup_get_info(dht_ctx, engine->fingerprint,
                                              &timestamp, &message_count);

    dna_backup_info_t info = {0};
    if (result == 0) {
        info.exists = true;
        info.timestamp = timestamp;
        info.message_count = message_count;
        QGP_LOG_INFO(LOG_TAG, "Backup found: timestamp=%llu, messages=%d",
                     (unsigned long long)timestamp, message_count);
        callback(request_id, 0, &info, user_data);
    } else if (result == -2) {
        info.exists = false;
        info.timestamp = 0;
        info.message_count = 0;
        QGP_LOG_INFO(LOG_TAG, "No backup found in DHT");
        callback(request_id, 0, &info, user_data);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to check backup: %d", result);
        callback(request_id, result, &info, user_data);
    }

    return request_id;
}

/* ============================================================================
 * VERSION CHECK API
 * ============================================================================ */

/* Well-known DHT key for version info */
#define VERSION_DHT_KEY_BASE "dna:system:version"
#define VERSION_VALUE_ID 1  /* Fixed value ID for replacement */

/**
 * Compare semantic version strings (returns: -1 if a<b, 0 if a==b, 1 if a>b)
 */
static int compare_versions(const char *a, const char *b) {
    if (!a || !b) return 0;

    int a_major = 0, a_minor = 0, a_patch = 0;
    int b_major = 0, b_minor = 0, b_patch = 0;

    sscanf(a, "%d.%d.%d", &a_major, &a_minor, &a_patch);
    sscanf(b, "%d.%d.%d", &b_major, &b_minor, &b_patch);

    if (a_major != b_major) return (a_major > b_major) ? 1 : -1;
    if (a_minor != b_minor) return (a_minor > b_minor) ? 1 : -1;
    if (a_patch != b_patch) return (a_patch > b_patch) ? 1 : -1;
    return 0;
}

int dna_engine_publish_version(
    dna_engine_t *engine,
    const char *library_version,
    const char *library_minimum,
    const char *app_version,
    const char *app_minimum,
    const char *nodus_version,
    const char *nodus_minimum
) {
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: engine is NULL");
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }

    if (engine->fingerprint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: no identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    if (!library_version || !app_version || !nodus_version) {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: version parameters required");
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: DHT not available");
        return DNA_ENGINE_ERROR_NETWORK;
    }

    /* Build JSON payload */
    json_object *root = json_object_new_object();
    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "published_at", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(root, "publisher", json_object_new_string(engine->fingerprint));

    /* Library version */
    json_object *lib_obj = json_object_new_object();
    json_object_object_add(lib_obj, "current", json_object_new_string(library_version));
    json_object_object_add(lib_obj, "minimum", json_object_new_string(library_minimum ? library_minimum : library_version));
    json_object_object_add(root, "library", lib_obj);

    /* App version */
    json_object *app_obj = json_object_new_object();
    json_object_object_add(app_obj, "current", json_object_new_string(app_version));
    json_object_object_add(app_obj, "minimum", json_object_new_string(app_minimum ? app_minimum : app_version));
    json_object_object_add(root, "app", app_obj);

    /* Nodus version */
    json_object *nodus_obj = json_object_new_object();
    json_object_object_add(nodus_obj, "current", json_object_new_string(nodus_version));
    json_object_object_add(nodus_obj, "minimum", json_object_new_string(nodus_minimum ? nodus_minimum : nodus_version));
    json_object_object_add(root, "nodus", nodus_obj);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    size_t json_len = strlen(json_str);

    /* Compute DHT key: SHA3-512(VERSION_DHT_KEY_BASE) */
    uint8_t dht_key[64];
    qgp_sha3_512((const uint8_t *)VERSION_DHT_KEY_BASE, strlen(VERSION_DHT_KEY_BASE), dht_key);

    QGP_LOG_INFO(LOG_TAG, "Publishing version info to DHT: lib=%s app=%s nodus=%s",
                 library_version, app_version, nodus_version);

    /* Publish with signed permanent (first writer owns the key) */
    int result = dht_put_signed_permanent(
        dht_ctx,
        dht_key, sizeof(dht_key),
        (const uint8_t *)json_str, json_len,
        VERSION_VALUE_ID,
        "version_publish"
    );

    json_object_put(root);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish version to DHT: %d", result);
        return DNA_ENGINE_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "Version info published successfully");
    return 0;
}

int dna_engine_check_version_dht(
    dna_engine_t *engine,
    dna_version_check_result_t *result_out
) {
    if (!result_out) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }

    memset(result_out, 0, sizeof(dna_version_check_result_t));

    /* Get DHT context - can work without identity for reading */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "check_version: DHT not available");
        return DNA_ENGINE_ERROR_NETWORK;
    }

    /* Compute DHT key: SHA3-512(VERSION_DHT_KEY_BASE) */
    uint8_t dht_key[64];
    qgp_sha3_512((const uint8_t *)VERSION_DHT_KEY_BASE, strlen(VERSION_DHT_KEY_BASE), dht_key);

    /* Fetch from DHT */
    uint8_t *value = NULL;
    size_t value_len = 0;
    int fetch_result = dht_get(dht_ctx, dht_key, sizeof(dht_key), &value, &value_len);

    if (fetch_result != 0 || !value || value_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No version info found in DHT");
        return -2;  /* Not found */
    }

    /* Parse JSON */
    json_object *root = json_tokener_parse((const char *)value);
    free(value);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse version JSON from DHT");
        return -1;
    }

    /* Extract version info */
    json_object *pub_at_obj, *pub_obj, *lib_obj, *app_obj, *nodus_obj;

    if (json_object_object_get_ex(root, "published_at", &pub_at_obj)) {
        result_out->info.published_at = (uint64_t)json_object_get_int64(pub_at_obj);
    }

    if (json_object_object_get_ex(root, "publisher", &pub_obj)) {
        strncpy(result_out->info.publisher, json_object_get_string(pub_obj),
                sizeof(result_out->info.publisher) - 1);
    }

    /* Library versions */
    if (json_object_object_get_ex(root, "library", &lib_obj)) {
        json_object *cur_obj, *min_obj;
        if (json_object_object_get_ex(lib_obj, "current", &cur_obj)) {
            strncpy(result_out->info.library_current, json_object_get_string(cur_obj),
                    sizeof(result_out->info.library_current) - 1);
        }
        if (json_object_object_get_ex(lib_obj, "minimum", &min_obj)) {
            strncpy(result_out->info.library_minimum, json_object_get_string(min_obj),
                    sizeof(result_out->info.library_minimum) - 1);
        }
    }

    /* App versions */
    if (json_object_object_get_ex(root, "app", &app_obj)) {
        json_object *cur_obj, *min_obj;
        if (json_object_object_get_ex(app_obj, "current", &cur_obj)) {
            strncpy(result_out->info.app_current, json_object_get_string(cur_obj),
                    sizeof(result_out->info.app_current) - 1);
        }
        if (json_object_object_get_ex(app_obj, "minimum", &min_obj)) {
            strncpy(result_out->info.app_minimum, json_object_get_string(min_obj),
                    sizeof(result_out->info.app_minimum) - 1);
        }
    }

    /* Nodus versions */
    if (json_object_object_get_ex(root, "nodus", &nodus_obj)) {
        json_object *cur_obj, *min_obj;
        if (json_object_object_get_ex(nodus_obj, "current", &cur_obj)) {
            strncpy(result_out->info.nodus_current, json_object_get_string(cur_obj),
                    sizeof(result_out->info.nodus_current) - 1);
        }
        if (json_object_object_get_ex(nodus_obj, "minimum", &min_obj)) {
            strncpy(result_out->info.nodus_minimum, json_object_get_string(min_obj),
                    sizeof(result_out->info.nodus_minimum) - 1);
        }
    }

    json_object_put(root);

    /* Compare with local version (library) */
    const char *local_lib_version = DNA_VERSION_STRING;
    if (compare_versions(result_out->info.library_current, local_lib_version) > 0) {
        result_out->library_update_available = true;
    }

    /* App and nodus comparisons would need their versions passed in or queried differently */
    /* For now, caller can compare manually using the info struct */

    QGP_LOG_INFO(LOG_TAG, "Version check: lib=%s (local=%s) app=%s nodus=%s",
                 result_out->info.library_current, local_lib_version,
                 result_out->info.app_current, result_out->info.nodus_current);

    return 0;
}

/* ============================================================================
 * ADDRESS BOOK IMPLEMENTATION
 * ============================================================================ */

void dna_free_addressbook_entries(dna_addressbook_entry_t *entries, int count) {
    (void)count;
    free(entries);
}

/* Synchronous: Add address to address book */
int dna_engine_add_address(
    dna_engine_t *engine,
    const char *address,
    const char *label,
    const char *network,
    const char *notes)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (!address || !label || !network) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for add_address");
        return -1;
    }

    /* Initialize address book database if needed */
    if (addressbook_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize address book database");
        return -1;
    }

    return addressbook_db_add(address, label, network, notes);
}

/* Synchronous: Update address in address book */
int dna_engine_update_address(
    dna_engine_t *engine,
    int id,
    const char *label,
    const char *notes)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (id <= 0 || !label) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for update_address");
        return -1;
    }

    return addressbook_db_update(id, label, notes);
}

/* Synchronous: Remove address from address book */
int dna_engine_remove_address(dna_engine_t *engine, int id) {
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (id <= 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid id for remove_address");
        return -1;
    }

    return addressbook_db_remove(id);
}

/* Synchronous: Check if address exists */
bool dna_engine_address_exists(
    dna_engine_t *engine,
    const char *address,
    const char *network)
{
    if (!engine || !engine->identity_loaded || !address || !network) {
        return false;
    }

    /* Initialize address book database if needed */
    if (addressbook_db_init(engine->fingerprint) != 0) {
        return false;
    }

    return addressbook_db_exists(address, network);
}

/* Synchronous: Lookup address */
int dna_engine_lookup_address(
    dna_engine_t *engine,
    const char *address,
    const char *network,
    dna_addressbook_entry_t *entry_out)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (!address || !network || !entry_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for lookup_address");
        return -1;
    }

    /* Initialize address book database if needed */
    if (addressbook_db_init(engine->fingerprint) != 0) {
        return -1;
    }

    addressbook_entry_t *db_entry = NULL;
    int result = addressbook_db_get_by_address(address, network, &db_entry);

    if (result != 0 || !db_entry) {
        return result;  /* -1 for error, 1 for not found */
    }

    /* Copy to output struct */
    entry_out->id = db_entry->id;
    strncpy(entry_out->address, db_entry->address, sizeof(entry_out->address) - 1);
    strncpy(entry_out->label, db_entry->label, sizeof(entry_out->label) - 1);
    strncpy(entry_out->network, db_entry->network, sizeof(entry_out->network) - 1);
    strncpy(entry_out->notes, db_entry->notes, sizeof(entry_out->notes) - 1);
    entry_out->created_at = db_entry->created_at;
    entry_out->updated_at = db_entry->updated_at;
    entry_out->last_used = db_entry->last_used;
    entry_out->use_count = db_entry->use_count;

    addressbook_db_free_entry(db_entry);
    return 0;
}

/* Synchronous: Increment address usage */
int dna_engine_increment_address_usage(dna_engine_t *engine, int id) {
    if (!engine || !engine->identity_loaded) {
        return -1;
    }

    if (id <= 0) {
        return -1;
    }

    return addressbook_db_increment_usage(id);
}

/* Async task data for address book operations */
typedef struct {
    dna_engine_t *engine;
    dna_addressbook_cb callback;
    void *user_data;
    char network[32];  /* For network filter */
    int limit;         /* For recent addresses */
} addressbook_task_t;

/* Helper: Convert addressbook_list_t to dna_addressbook_entry_t array */
static dna_addressbook_entry_t* convert_addressbook_list(
    addressbook_list_t *list,
    int *count_out)
{
    if (!list || list->count == 0) {
        *count_out = 0;
        return NULL;
    }

    dna_addressbook_entry_t *entries = calloc(list->count, sizeof(dna_addressbook_entry_t));
    if (!entries) {
        *count_out = 0;
        return NULL;
    }

    for (size_t i = 0; i < list->count; i++) {
        entries[i].id = list->entries[i].id;
        strncpy(entries[i].address, list->entries[i].address, sizeof(entries[i].address) - 1);
        strncpy(entries[i].label, list->entries[i].label, sizeof(entries[i].label) - 1);
        strncpy(entries[i].network, list->entries[i].network, sizeof(entries[i].network) - 1);
        strncpy(entries[i].notes, list->entries[i].notes, sizeof(entries[i].notes) - 1);
        entries[i].created_at = list->entries[i].created_at;
        entries[i].updated_at = list->entries[i].updated_at;
        entries[i].last_used = list->entries[i].last_used;
        entries[i].use_count = list->entries[i].use_count;
    }

    *count_out = (int)list->count;
    return entries;
}

/* Task: Get all addresses */
static void task_get_addressbook(void *data) {
    addressbook_task_t *task = (addressbook_task_t*)data;
    if (!task) return;

    dna_addressbook_entry_t *entries = NULL;
    int count = 0;
    int error = 0;

    /* Initialize address book database if needed */
    if (addressbook_db_init(task->engine->fingerprint) != 0) {
        error = -1;
    } else {
        addressbook_list_t *list = NULL;
        if (addressbook_db_list(&list) == 0 && list) {
            entries = convert_addressbook_list(list, &count);
            addressbook_db_free_list(list);
        } else {
            error = -1;
        }
    }

    if (task->callback) {
        task->callback(0, error, entries, count, task->user_data);
    }

    free(task);
}

/* Task: Get addresses by network */
static void task_get_addressbook_by_network(void *data) {
    addressbook_task_t *task = (addressbook_task_t*)data;
    if (!task) return;

    dna_addressbook_entry_t *entries = NULL;
    int count = 0;
    int error = 0;

    /* Initialize address book database if needed */
    if (addressbook_db_init(task->engine->fingerprint) != 0) {
        error = -1;
    } else {
        addressbook_list_t *list = NULL;
        if (addressbook_db_list_by_network(task->network, &list) == 0 && list) {
            entries = convert_addressbook_list(list, &count);
            addressbook_db_free_list(list);
        } else {
            error = -1;
        }
    }

    if (task->callback) {
        task->callback(0, error, entries, count, task->user_data);
    }

    free(task);
}

/* Task: Get recent addresses */
static void task_get_recent_addresses(void *data) {
    addressbook_task_t *task = (addressbook_task_t*)data;
    if (!task) return;

    dna_addressbook_entry_t *entries = NULL;
    int count = 0;
    int error = 0;

    /* Initialize address book database if needed */
    if (addressbook_db_init(task->engine->fingerprint) != 0) {
        error = -1;
    } else {
        addressbook_list_t *list = NULL;
        if (addressbook_db_get_recent(task->limit, &list) == 0 && list) {
            entries = convert_addressbook_list(list, &count);
            addressbook_db_free_list(list);
        } else {
            error = -1;
        }
    }

    if (task->callback) {
        task->callback(0, error, entries, count, task->user_data);
    }

    free(task);
}

/* Async: Get all addresses */
dna_request_id_t dna_engine_get_addressbook(
    dna_engine_t *engine,
    dna_addressbook_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded || !callback) {
        if (callback) {
            callback(0, -1, NULL, 0, user_data);
        }
        return 0;
    }

    addressbook_task_t *task = calloc(1, sizeof(addressbook_task_t));
    if (!task) {
        callback(0, -1, NULL, 0, user_data);
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;

    /* Run synchronously for now (can be made async with thread pool if needed) */
    task_get_addressbook(task);
    return 1;
}

/* Async: Get addresses by network */
dna_request_id_t dna_engine_get_addressbook_by_network(
    dna_engine_t *engine,
    const char *network,
    dna_addressbook_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded || !network || !callback) {
        if (callback) {
            callback(0, -1, NULL, 0, user_data);
        }
        return 0;
    }

    addressbook_task_t *task = calloc(1, sizeof(addressbook_task_t));
    if (!task) {
        callback(0, -1, NULL, 0, user_data);
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;
    strncpy(task->network, network, sizeof(task->network) - 1);

    task_get_addressbook_by_network(task);
    return 1;
}

/* Async: Get recent addresses */
dna_request_id_t dna_engine_get_recent_addresses(
    dna_engine_t *engine,
    int limit,
    dna_addressbook_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded || limit <= 0 || !callback) {
        if (callback) {
            callback(0, -1, NULL, 0, user_data);
        }
        return 0;
    }

    addressbook_task_t *task = calloc(1, sizeof(addressbook_task_t));
    if (!task) {
        callback(0, -1, NULL, 0, user_data);
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;
    task->limit = limit;

    task_get_recent_addresses(task);
    return 1;
}

/* DHT Sync task data */
typedef struct {
    dna_engine_t *engine;
    dna_completion_cb callback;
    void *user_data;
} addressbook_sync_task_t;

/* Task: Sync address book to DHT */
static void task_sync_addressbook_to_dht(void *data) {
    addressbook_sync_task_t *task = (addressbook_sync_task_t*)data;
    if (!task) return;

    int error = 0;

    /* Get DHT context */
    dht_context_t *dht_ctx = dna_get_dht_ctx(task->engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "No DHT context for address book sync");
        error = -1;
        goto done;
    }

    /* Load keys */
    qgp_key_t *sign_key = dna_load_private_key(task->engine);
    qgp_key_t *enc_key = dna_load_encryption_key(task->engine);
    if (!sign_key || !enc_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load keys for address book sync");
        error = -1;
        if (sign_key) qgp_key_free(sign_key);
        if (enc_key) qgp_key_free(enc_key);
        goto done;
    }

    /* Get address book from database */
    addressbook_list_t *list = NULL;
    if (addressbook_db_list(&list) != 0 || !list) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get address book for sync");
        error = -1;
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        goto done;
    }

    /* Convert to DHT entries */
    dht_addressbook_entry_t *dht_entries = NULL;
    if (list->count > 0) {
        dht_entries = dht_addressbook_from_db_entries(list->entries, list->count);
    }

    /* Publish to DHT */
    int result = dht_addressbook_publish(
        dht_ctx,
        task->engine->fingerprint,
        dht_entries,
        list->count,
        enc_key->public_key,
        enc_key->private_key,
        sign_key->public_key,
        sign_key->private_key,
        0  /* Use default TTL */
    );

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish address book to DHT");
        error = -1;
    } else {
        QGP_LOG_INFO(LOG_TAG, "Published %zu addresses to DHT", list->count);
    }

    if (dht_entries) {
        dht_addressbook_free_entries(dht_entries, list->count);
    }
    addressbook_db_free_list(list);
    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

done:
    if (task->callback) {
        task->callback(0, error, task->user_data);
    }
    free(task);
}

/* Task: Sync address book from DHT */
static void task_sync_addressbook_from_dht(void *data) {
    addressbook_sync_task_t *task = (addressbook_sync_task_t*)data;
    if (!task) return;

    int error = 0;

    /* Get DHT context */
    dht_context_t *dht_ctx = dna_get_dht_ctx(task->engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "No DHT context for address book sync");
        error = -1;
        goto done;
    }

    /* Load keys */
    qgp_key_t *sign_key = dna_load_private_key(task->engine);
    qgp_key_t *enc_key = dna_load_encryption_key(task->engine);
    if (!sign_key || !enc_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load keys for address book sync");
        error = -1;
        if (sign_key) qgp_key_free(sign_key);
        if (enc_key) qgp_key_free(enc_key);
        goto done;
    }

    /* Fetch from DHT */
    dht_addressbook_entry_t *dht_entries = NULL;
    size_t entry_count = 0;

    int result = dht_addressbook_fetch(
        dht_ctx,
        task->engine->fingerprint,
        &dht_entries,
        &entry_count,
        enc_key->private_key,
        sign_key->public_key
    );

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (result == -2) {
        /* Not found in DHT - not an error, just no data */
        QGP_LOG_INFO(LOG_TAG, "No address book found in DHT");
        goto done;
    }

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch address book from DHT");
        error = -1;
        goto done;
    }

    /* Replace local database with DHT data */
    addressbook_db_clear_all();

    for (size_t i = 0; i < entry_count; i++) {
        addressbook_db_add(
            dht_entries[i].address,
            dht_entries[i].label,
            dht_entries[i].network,
            dht_entries[i].notes
        );
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %zu addresses from DHT", entry_count);

    if (dht_entries) {
        dht_addressbook_free_entries(dht_entries, entry_count);
    }

done:
    if (task->callback) {
        task->callback(0, error, task->user_data);
    }
    free(task);
}

/* Async: Sync address book to DHT */
dna_request_id_t dna_engine_sync_addressbook_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    addressbook_sync_task_t *task = calloc(1, sizeof(addressbook_sync_task_t));
    if (!task) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;

    task_sync_addressbook_to_dht(task);
    return 1;
}

/* Async: Sync address book from DHT */
dna_request_id_t dna_engine_sync_addressbook_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    addressbook_sync_task_t *task = calloc(1, sizeof(addressbook_sync_task_t));
    if (!task) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;

    task_sync_addressbook_from_dht(task);
    return 1;
}

/* ============================================================================
 * SIGNING API (for QR Auth and external authentication)
 * ============================================================================ */

/**
 * Sign arbitrary data with the loaded identity's Dilithium5 key
 */
int dna_engine_sign_data(
    dna_engine_t *engine,
    const uint8_t *data,
    size_t data_len,
    uint8_t *signature_out,
    size_t *sig_len_out)
{
    if (!engine || !data || !signature_out || !sig_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: no identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Load the private signing key */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: failed to load private key");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Verify key has private key data */
    if (!sign_key->private_key || sign_key->private_key_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: key has no private key data");
        qgp_key_free(sign_key);
        return DNA_ERROR_CRYPTO;
    }

    /* Sign with Dilithium5 */
    int ret = qgp_dsa87_sign(signature_out, sig_len_out,
                             data, data_len,
                             sign_key->private_key);

    qgp_key_free(sign_key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: qgp_dsa87_sign failed");
        return DNA_ERROR_CRYPTO;
    }

    QGP_LOG_DEBUG(LOG_TAG, "sign_data: signed %zu bytes, signature length %zu",
                  data_len, *sig_len_out);
    return 0;
}

/**
 * Get the loaded identity's Dilithium5 signing public key
 */
int dna_engine_get_signing_public_key(
    dna_engine_t *engine,
    uint8_t *pubkey_out,
    size_t pubkey_out_len)
{
    if (!engine || !pubkey_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: no identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Load the signing key (contains public key) */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: failed to load key");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Verify key has public key data */
    if (!sign_key->public_key || sign_key->public_key_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: key has no public key data");
        qgp_key_free(sign_key);
        return DNA_ERROR_CRYPTO;
    }

    /* Check buffer size */
    if (pubkey_out_len < sign_key->public_key_size) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: buffer too small (%zu < %zu)",
                      pubkey_out_len, sign_key->public_key_size);
        qgp_key_free(sign_key);
        return DNA_ERROR_INVALID_ARG;
    }

    /* Copy public key to output buffer */
    memcpy(pubkey_out, sign_key->public_key, sign_key->public_key_size);
    size_t result = sign_key->public_key_size;

    qgp_key_free(sign_key);

    QGP_LOG_DEBUG(LOG_TAG, "get_signing_public_key: returned %zu bytes", result);
    return (int)result;
}
