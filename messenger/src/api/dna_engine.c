/*
 * DNA Engine - Implementation
 *
 * Core engine implementation providing async API for DNA Connect.
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

/* Windows: clock_gettime compatibility for pthread_cond_timedwait */
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
static int clock_gettime(int clk_id, struct timespec *tp) {
    (void)clk_id;
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    /* Convert from 100-nanosecond intervals since 1601 to Unix epoch */
    uli.QuadPart -= 116444736000000000ULL;
    tp->tv_sec = (time_t)(uli.QuadPart / 10000000);
    tp->tv_nsec = (long)((uli.QuadPart % 10000000) * 100);
    return 0;
}
#endif

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
#include "crypto/utils/threadpool.h"
#include "messenger/init.h"
#include "messenger/messages.h"
#include "messenger/groups.h"
#include "messenger_transport.h"
#include "message_backup.h"
#include "messenger/status.h"
#include "dht/shared/nodus_init.h"
#include "dht/shared/nodus_ops.h"
#include "dht/core/dht_keyserver.h"
#include "dht/client/dht_contactlist.h"
#include "dht/client/dht_message_backup.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/client/dna_profile.h"
#include "dht/shared/dht_contact_request.h"
#include "dht/shared/dht_groups.h"
#include "dht/client/dna_group_outbox.h"
#include "transport/transport.h"
/* TURN credentials removed in v0.4.61 for privacy */
#include "database/presence_cache.h"
#include "database/keyserver_cache.h"
#include "database/wall_cache.h"
#include "database/channel_cache.h"
#include "database/profile_cache.h"
#include "database/profile_manager.h"
#include "database/contacts_db.h"
#include "database/addressbook_db.h"
#include "database/group_invitations.h"
#include "dht/client/dht_addressbook.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/key/key_encryption.h"
#include "crypto/sign/qgp_dilithium.h"
/* nodus_republish.h removed — migration loop eliminated in v0.9.58 */

/* Blockchain/Wallet includes for send_tokens */
#include "cellframe_wallet.h"

/* JSON and SHA3 for version check API */
#include <json-c/json.h>
#include "crypto/hash/qgp_sha3.h"
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
#include "crypto/key/seed_storage.h"
#include "crypto/key/bip39/bip39.h"
#include "messenger/gek.h"
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"
#include "dna_config.h"

#define LOG_TAG "DNA_ENGINE"

/* v0.6.47: Thread-safe gmtime wrapper (security fix) */
static inline struct tm *safe_gmtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (gmtime_s(result, timer) == 0) ? result : NULL;
#else
    return gmtime_r(timer, result);
#endif
}

/* Use engine-specific error codes */
#define DNA_OK 0

/* DHT stabilization - wait for routing table to fill after bootstrap */
#define DHT_STABILIZATION_MAX_SECONDS 15  /* Maximum wait time */
#define DHT_STABILIZATION_MIN_NODES 2     /* Minimum good nodes for reliable operations */

/* Forward declarations for listener management */
void dna_engine_cancel_all_outbox_listeners(dna_engine_t *engine);
void dna_engine_cancel_contact_request_listener(dna_engine_t *engine);
size_t dna_engine_start_contact_request_listener(dna_engine_t *engine);
void dna_engine_cancel_ack_listener(dna_engine_t *engine, const char *contact_fingerprint);
void dna_engine_cancel_all_ack_listeners(dna_engine_t *engine);
size_t dna_engine_listen_outbox(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_ack_listener(dna_engine_t *engine, const char *contact_fingerprint);
void dna_engine_cancel_all_wall_listeners(dna_engine_t *engine);
void dna_engine_cancel_all_channel_listeners(dna_engine_t *engine);
int dna_engine_listen_all_channels(dna_engine_t *engine);

/* Forward declaration for log config initialization (defined in LOG CONFIGURATION section) */
void init_log_config(void);

/* Core helpers moved to src/api/engine/dna_engine_helpers.c */

/* is_valid_identity_name() moved to dna_engine_identity.c */

/* Global engine pointer for DHT status callback and event dispatch from lower layers
 * Set during create, cleared during destroy. Used by messenger_transport.c to emit events.
 * Protected by g_engine_global_mutex (v0.6.43 race fix). */
static dna_engine_t *g_dht_callback_engine = NULL;
static pthread_mutex_t g_engine_global_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Android notification/service callbacks removed in v0.9.7 */

/* Global engine accessors (for messenger layer event dispatch)
 * Thread-safe via g_engine_global_mutex (v0.6.43 race fix). */
void dna_engine_set_global(dna_engine_t *engine) {
    pthread_mutex_lock(&g_engine_global_mutex);
    g_dht_callback_engine = engine;
    pthread_mutex_unlock(&g_engine_global_mutex);
}

dna_engine_t* dna_engine_get_global(void) {
    pthread_mutex_lock(&g_engine_global_mutex);
    dna_engine_t *engine = g_dht_callback_engine;
    pthread_mutex_unlock(&g_engine_global_mutex);
    return engine;
}

/**
 * Background thread for listener setup
 * Runs on separate thread to avoid blocking the DHT callback thread.
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
    dna_engine_cancel_contact_request_listener(engine);
    dna_engine_cancel_all_wall_listeners(engine);
    dna_engine_cancel_all_channel_listeners(engine);

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    int count = dna_engine_listen_all_contacts(engine);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Background thread: started %d listeners", count);

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* Start channel post listeners for all subscribed channels */
    int channel_count = dna_engine_listen_all_channels(engine);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Background thread: started %d channel listeners", channel_count);

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
     *          This prevents ACKs being published while app is backgrounded,
     *          which would mark messages as "received" before user sees them.
     * Desktop: Fetch immediately since there's no background service. */
#ifndef __ANDROID__
    if (engine->messenger && engine->messenger->transport_ctx) {
        QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: checking for missed messages");
        size_t received = 0;
        transport_check_offline_messages(engine->messenger->transport_ctx, NULL, true, false, &received);
        if (received > 0) {
            QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: received %zu missed messages", received);
        }
    }
#else
    QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: skipping auto-fetch (Android - Flutter handles on resume)");
#endif

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* Wait for DHT routing table to stabilize, then retry again */
    if (!dht_wait_for_stabilization(engine)) goto cleanup;

    int retried_post_stable = dna_engine_retry_pending_messages(engine);
    if (retried_post_stable > 0) {
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Reconnect post-stabilization: retried %d messages", retried_post_stable);
    }

cleanup:
    /* v0.6.0+: Mark thread as not running before exit */
    pthread_mutex_lock(&engine->background_threads_mutex);
    engine->setup_listeners_running = false;
    pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
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
void *dna_engine_stabilization_retry_thread(void *arg) {
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

    /* Wait for DHT routing table to stabilize */
    if (!dht_wait_for_stabilization(engine)) goto cleanup;

    QGP_LOG_INFO(LOG_TAG, "[RETRY] Stabilization complete, starting retries...");

    /* Nodus migration removed (v0.9.58) — migration was running on EVERY startup
     * due to reset loop (check_migrated → reset → republish → mark_done → repeat).
     * All existing users have already migrated. Profile/contacts/groups are kept
     * fresh by their normal sync paths below (steps 1-1c). */

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 1. Sync contacts from DHT (restore on new device)
     * v0.6.54+: Moved from blocking identity load to background thread.
     * Local SQLite cache is shown immediately, DHT sync updates in background. */
    if (engine->messenger) {
        int sync_result = messenger_sync_contacts_from_dht(engine->messenger);
        if (sync_result == 0) {
            int contacts_count = contacts_db_count();
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: synced %d contacts from DHT", contacts_count);

            /* Notify Flutter to refresh contacts UI */
            dna_event_t event = {0};
            event.type = DNA_EVENT_CONTACTS_SYNCED;
            event.data.contacts_synced.contacts_synced = contacts_count;
            dna_dispatch_event(engine, &event);
        } else if (sync_result == -2) {
            QGP_LOG_INFO(LOG_TAG, "[RETRY] Post-stabilization: no contact list in DHT (new identity or first device)");
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: contacts sync failed: %d", sync_result);
        }
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 1c. Sync GEKs from DHT (restore group encryption keys on new device)
     * v0.6.54+: Moved from blocking identity load to background thread. */
    if (engine->messenger) {
        int gek_sync_result = messenger_gek_auto_sync(engine->messenger);
        if (gek_sync_result == 0) {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: synced GEKs from DHT");

            /* Notify Flutter that GEKs are ready */
            dna_event_t event = {0};
            event.type = DNA_EVENT_GEKS_SYNCED;
            event.data.geks_synced.geks_synced = 1;
            dna_dispatch_event(engine, &event);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: GEK sync failed: %d (non-fatal)", gek_sync_result);
        }
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 1d. Restore groups from DHT to local cache (Android startup fix)
     * On fresh startup, local SQLite cache is empty. Fetch group list from DHT
     * and sync each group to local cache so they appear in the UI. */
    if (engine->messenger) {
        int restored = messenger_restore_groups_from_dht(engine->messenger);
        if (restored > 0) {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: restored %d groups from DHT", restored);

            /* Subscribe to the newly restored groups for real-time notifications */
            int subscribed = dna_engine_subscribe_all_groups(engine);
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: subscribed to %d restored groups", subscribed);

            /* Notify Flutter to refresh groups UI - use stack allocation to avoid leak */
            dna_event_t event = {0};
            event.type = DNA_EVENT_GROUPS_SYNCED;
            event.data.groups_synced.groups_restored = restored;
            dna_dispatch_event(engine, &event);
        } else if (restored == 0) {
            QGP_LOG_INFO(LOG_TAG, "[RETRY] Post-stabilization: no groups to restore from DHT");
            /* v0.6.88: Still subscribe to groups already in local cache
             * (e.g., groups created locally before DHT sync) */
            int subscribed = dna_engine_subscribe_all_groups(engine);
            if (subscribed > 0) {
                QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: subscribed to %d local cache groups", subscribed);
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: group restore failed: %d", restored);
        }
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 2. Sync any pending outboxes (messages that failed to publish earlier) */
    {
        int synced = dht_offline_queue_sync_pending();
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

    /* 4. Start outbox listeners for all contacts
     * This was previously called from Dart but blocked UI for up to 30s.
     * Moving here so it runs in background thread after DHT is stable. */
    if (engine->messenger && !atomic_load(&engine->shutdown_requested)) {
        int listener_count = dna_engine_listen_all_contacts(engine);
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: started %d contact listeners", listener_count);
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* v0.9.17: Wallet file creation removed — seed-based derivation only */

    QGP_LOG_WARN(LOG_TAG, "[RETRY] >>> STABILIZATION THREAD COMPLETE <<<");

cleanup:
    /* v0.6.0+: Mark thread as not running before exit */
    pthread_mutex_lock(&engine->background_threads_mutex);
    engine->stabilization_retry_running = false;
    pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
    pthread_mutex_unlock(&engine->background_threads_mutex);
    return NULL;
}

/**
 * DHT status change callback - dispatches DHT_CONNECTED/DHT_DISCONNECTED events
 * Called from the Nodus callback thread when connection status changes.
 */
static void dna_dht_status_callback(bool is_connected, void *user_data) {
    (void)user_data;  /* Using global engine pointer instead */

    /* v0.6.108: Protect engine pointer read with mutex (race condition fix)
     * This prevents use-after-free when callback fires during engine destroy */
    pthread_mutex_lock(&g_engine_global_mutex);
    dna_engine_t *engine = g_dht_callback_engine;
    if (!engine) {
        pthread_mutex_unlock(&g_engine_global_mutex);
        return;
    }
    /* Check shutdown flag before doing any work */
    if (engine->shutdown_requested) {
        pthread_mutex_unlock(&g_engine_global_mutex);
        return;
    }
    pthread_mutex_unlock(&g_engine_global_mutex);

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
         * This callback runs on the Nodus callback thread. If we block here
         * we deadlock (Nodus needs this thread for dispatch). */
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT connected, identity_loaded=%d",
                     engine->identity_loaded);
        if (engine->identity_loaded) {
            /* Spawn listener setup thread for FULL listeners */
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
        case TASK_WALL_POST:
            free(task->params.wall_post.text);
            free(task->params.wall_post.image_json);
            break;
        case TASK_WALL_ADD_COMMENT:
            free(task->params.wall_add_comment.body);
            break;
        case TASK_WALL_BOOST_POST:
            free(task->params.wall_boost_post.text);
            free(task->params.wall_boost_post.image_json);
            break;
        case TASK_CHANNEL_CREATE:
            free(task->params.channel_create.description);
            break;
        case TASK_CHANNEL_POST:
            free(task->params.channel_post.body);
            break;
        default:
            break;
    }
}

/* Workers moved to src/api/engine/dna_engine_workers.c */

/* Presence heartbeat moved to src/api/engine/dna_engine_presence.c */

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

        messenger_transport_check_offline_messages(engine->messenger, sender_fp, true, false, &offline_count);

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
    /* v0.6.114: Check shutdown BEFORE accessing any engine fields.
     * This prevents use-after-free when called from detached background threads
     * after engine destroy has freed the memory. The shutdown_requested field
     * is at a fixed offset and checked atomically - safe even if engine is
     * partially freed (though we shouldn't rely on this - it's defense in depth). */
    if (!engine || atomic_load(&engine->shutdown_requested)) {
        return;
    }

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

    /* Android notification callbacks removed in v0.9.7 */
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
void dna_handle_restore_groups_from_dht(dna_engine_t *engine, dna_task_t *task);

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
        case TASK_CHECK_OFFLINE_MESSAGES_FROM:
            dna_handle_check_offline_messages_from(engine, task);
            break;
        case TASK_DELETE_MESSAGE:
            dna_handle_delete_message(engine, task);
            break;
        case TASK_DELETE_CONVERSATION:
            dna_handle_delete_conversation(engine, task);
            break;
        case TASK_DELETE_ALL_MESSAGES:
            dna_handle_delete_all_messages(engine, task);
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
        case TASK_REMOVE_GROUP_MEMBER:
            dna_handle_remove_group_member(engine, task);
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
        case TASK_GET_CACHED_BALANCES:
            dna_handle_get_cached_balances(engine, task);
            break;
        case TASK_SEND_TOKENS:
            dna_handle_send_tokens(engine, task);
            break;
        case TASK_GET_TX_STATUS:
            dna_handle_get_tx_status(engine, task);
            break;
        case TASK_GET_TRANSACTIONS:
            dna_handle_get_transactions(engine, task);
            break;
        case TASK_GET_CACHED_TRANSACTIONS:
            dna_handle_get_cached_transactions(engine, task);
            break;
        case TASK_ESTIMATE_GAS:
            dna_handle_estimate_gas(engine, task);
            break;
        case TASK_DEX_QUOTE:
            dna_handle_dex_quote(engine, task);
            break;
        case TASK_DEX_LIST_PAIRS:
            dna_handle_dex_list_pairs(engine, task);
            break;
        case TASK_DEX_SWAP:
            dna_handle_dex_swap(engine, task);
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
        case TASK_RESTORE_GROUPS_FROM_DHT:
            dna_handle_restore_groups_from_dht(engine, task);
            break;
        case TASK_SYNC_GROUP_BY_UUID:
            dna_handle_sync_group_by_uuid(engine, task);
            break;
        case TASK_GET_REGISTERED_NAME:
            dna_handle_get_registered_name(engine, task);
            break;

        /* Wall (v0.6.135+) */
        case TASK_WALL_POST:
            dna_handle_wall_post(engine, task);
            break;
        case TASK_WALL_DELETE:
            dna_handle_wall_delete(engine, task);
            break;
        case TASK_WALL_LOAD:
            dna_handle_wall_load(engine, task);
            break;
        case TASK_WALL_TIMELINE:
            dna_handle_wall_timeline(engine, task);
            break;

        /* Wall Comments (v0.7.0+) */
        case TASK_WALL_ADD_COMMENT:
            dna_handle_wall_add_comment(engine, task);
            break;
        case TASK_WALL_GET_COMMENTS:
            dna_handle_wall_get_comments(engine, task);
            break;

        /* Wall Likes (v0.9.52+) */
        case TASK_WALL_LIKE:
            dna_handle_wall_like(engine, task);
            break;
        case TASK_WALL_GET_LIKES:
            dna_handle_wall_get_likes(engine, task);
            break;

        /* Wall Boost (v0.9.71+) */
        case TASK_WALL_BOOST_POST:
            dna_handle_wall_boost_post(engine, task);
            break;
        case TASK_WALL_BOOST_TIMELINE:
            dna_handle_wall_boost_timeline(engine, task);
            break;

        /* Channel system (RSS-like channels) */
        case TASK_CHANNEL_CREATE:
            dna_handle_channel_create(engine, task);
            break;
        case TASK_CHANNEL_GET:
            dna_handle_channel_get(engine, task);
            break;
        case TASK_CHANNEL_DELETE:
            dna_handle_channel_delete(engine, task);
            break;
        case TASK_CHANNEL_DISCOVER:
            dna_handle_channel_discover(engine, task);
            break;
        case TASK_CHANNEL_POST:
            dna_handle_channel_post(engine, task);
            break;
        case TASK_CHANNEL_GET_POSTS:
            dna_handle_channel_get_posts(engine, task);
            break;
        case TASK_CHANNEL_GET_SUBSCRIPTIONS:
            dna_handle_channel_get_subscriptions(engine, task);
            break;
        case TASK_CHANNEL_SYNC_SUBS_TO_DHT:
            dna_handle_channel_sync_subs_to_dht(engine, task);
            break;
        case TASK_CHANNEL_SYNC_SUBS_FROM_DHT:
            dna_handle_channel_sync_subs_from_dht(engine, task);
            break;
    }
}

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================ */

dna_engine_t* dna_engine_create(const char *data_dir) {
    /* Safety net: if an old engine was leaked (e.g. Dart isolate killed without
     * cleanup on Android Activity recreation), destroy it first to release the
     * identity file lock. Without this, the new engine's loadIdentity() would
     * fail with IDENTITY_LOCKED (-117) because flock() is per-fd, not per-process. */
    pthread_mutex_lock(&g_engine_global_mutex);
    if (g_dht_callback_engine != NULL) {
        QGP_LOG_WARN(LOG_TAG, "Leaked engine detected (%p) - destroying before creating new one",
                     (void*)g_dht_callback_engine);
        dna_engine_t *leaked = g_dht_callback_engine;
        pthread_mutex_unlock(&g_engine_global_mutex);
        dna_engine_destroy(leaked);
    } else {
        pthread_mutex_unlock(&g_engine_global_mutex);
    }

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

    /* Initialize identity lock (will be set during identity load) */
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

    /* v0.9.0: Presence listeners removed — batch query via Nodus server */

    /* Initialize contact request listener */
    pthread_mutex_init(&engine->contact_request_listener_mutex, NULL);
    engine->contact_request_listener.dht_token = 0;
    engine->contact_request_listener.active = false;

    /* Initialize ACK listeners (v15: replaced watermarks) */
    pthread_mutex_init(&engine->ack_listeners_mutex, NULL);
    engine->ack_listener_count = 0;
    memset(engine->ack_listeners, 0, sizeof(engine->ack_listeners));

    /* Initialize wall listeners */
    pthread_mutex_init(&engine->wall_listeners_mutex, NULL);
    engine->wall_listener_count = 0;
    memset(engine->wall_listeners, 0, sizeof(engine->wall_listeners));

    /* Initialize channel listeners */
    pthread_mutex_init(&engine->channel_listeners_mutex, NULL);
    engine->channel_listener_count = 0;
    memset(engine->channel_listeners, 0, sizeof(engine->channel_listeners));

    /* Initialize group outbox listeners */
    pthread_mutex_init(&engine->group_listen_mutex, NULL);
    engine->group_listen_count = 0;
    memset(engine->group_listen_contexts, 0, sizeof(engine->group_listen_contexts));

    /* v0.6.0+: Initialize background thread tracking */
    pthread_mutex_init(&engine->background_threads_mutex, NULL);
    pthread_cond_init(&engine->background_thread_exit_cond, NULL);  /* v0.6.113: For efficient thread join */
    engine->setup_listeners_running = false;
    engine->stabilization_retry_running = false;

    /* v0.6.107+: Initialize state synchronization */
    pthread_mutex_init(&engine->state_mutex, NULL);

    /* Initialize task queue */
    dna_task_queue_init(&engine->task_queue);

    /* Initialize request ID counter */
    atomic_store(&engine->next_request_id, 0);

    /* Initialize presence heartbeat as active (will start thread after identity load) */
    atomic_store(&engine->presence_active, true);

    /* Nodus is NOT initialized here - only after identity is created/restored
     * via nodus_messenger_init() in messenger/init.c */

    /* Initialize global keyserver cache (for display names before login) */
    keyserver_cache_init(NULL);

    /* Initialize global wall cache (for instant wall rendering) */
    wall_cache_init();

    /* Initialize global channel cache (for instant channel rendering) */
    channel_cache_init();

    /* Initialize global profile cache + manager (for profile prefetching)
     * MUST be before status callback registration - callback triggers prefetch */
    profile_manager_init();

    /* Register DHT status callback to emit events on connection changes
     * This waits for DHT connection and fires callback which triggers prefetch */
    g_dht_callback_engine = engine;
    nodus_messenger_set_status_callback(dna_dht_status_callback, NULL);

    /* Start worker threads */
    if (dna_start_workers(engine) != 0) {
        g_dht_callback_engine = NULL;
        nodus_messenger_set_status_callback(NULL, NULL);
        pthread_mutex_destroy(&engine->event_mutex);
        pthread_mutex_destroy(&engine->task_mutex);
        pthread_cond_destroy(&engine->task_cond);
        pthread_mutex_destroy(&engine->message_queue.mutex);
        free(engine->message_queue.entries);
        free(engine->data_dir);
        free(engine);
        return NULL;
    }

    return engine;
}

/* ============================================================================
 * ASYNC ENGINE CREATION (v0.6.18)
 *
 * Spawns a background thread to create the engine, avoiding UI thread blocking.
 * Uses atomic cancelled flag for safe cancellation when Dart disposes early.
 * ============================================================================ */

typedef struct {
    char *data_dir;
    dna_engine_created_cb callback;
    void *user_data;
    _Atomic bool *cancelled;  /* Shared with Dart - check before callback */
} dna_engine_create_async_ctx_t;

static void* dna_engine_create_thread(void *arg) {
    dna_engine_create_async_ctx_t *ctx = (dna_engine_create_async_ctx_t*)arg;

    /* Create engine on this background thread */
    dna_engine_t *engine = dna_engine_create(ctx->data_dir);
    int error = engine ? DNA_OK : DNA_ENGINE_ERROR_INIT;

    /* Check if cancelled BEFORE calling callback (Dart may have disposed) */
    bool was_cancelled = ctx->cancelled && atomic_load(ctx->cancelled);

    if (!was_cancelled && ctx->callback) {
        ctx->callback(engine, error, ctx->user_data);
    } else if (engine) {
        /* Cancelled - destroy the engine we created */
        QGP_LOG_INFO(LOG_TAG, "Async engine creation cancelled, destroying engine");
        dna_engine_destroy(engine);
    }

    /* Cleanup - DON'T free cancelled pointer, Dart owns it */
    free(ctx->data_dir);
    free(ctx);

    return NULL;
}

void dna_engine_create_async(
    const char *data_dir,
    dna_engine_created_cb callback,
    void *user_data,
    _Atomic bool *cancelled
) {
    if (!callback) {
        QGP_LOG_ERROR(LOG_TAG, "dna_engine_create_async: callback required");
        return;
    }

    /* Allocate context for thread */
    dna_engine_create_async_ctx_t *ctx = calloc(1, sizeof(dna_engine_create_async_ctx_t));
    if (!ctx) {
        callback(NULL, DNA_ENGINE_ERROR_INIT, user_data);
        return;
    }

    ctx->data_dir = data_dir ? strdup(data_dir) : NULL;
    ctx->callback = callback;
    ctx->user_data = user_data;
    ctx->cancelled = cancelled;

    /* Spawn detached thread for engine creation */
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc = pthread_create(&thread, &attr, dna_engine_create_thread, ctx);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create engine init thread: %d", rc);
        free(ctx->data_dir);
        free(ctx);
        callback(NULL, DNA_ENGINE_ERROR_INIT, user_data);
    }
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

/* Android notification/service callback setters removed in v0.9.7 */

/* v0.6.115: Request shutdown without destroying engine.
 * Sets shutdown_requested flag so ongoing operations abort early.
 * Use case: Android Service calls this BEFORE acquiring engine lock,
 * allowing ongoing DHT operations to abort quickly. */
void dna_engine_request_shutdown(dna_engine_t *engine) {
    if (!engine) return;

    QGP_LOG_INFO(LOG_TAG, "Shutdown requested (operations will abort early)");
    atomic_store(&engine->shutdown_requested, true);

    /* Wake up any threads waiting on condition variables so they can check
     * shutdown_requested and exit quickly */
    pthread_mutex_lock(&engine->task_mutex);
    pthread_cond_broadcast(&engine->task_cond);
    pthread_mutex_unlock(&engine->task_mutex);
}

/* v0.6.116: Check if shutdown was requested */
bool dna_engine_is_shutdown_requested(dna_engine_t *engine) {
    if (!engine) return false;
    return atomic_load(&engine->shutdown_requested);
}

void dna_engine_destroy(dna_engine_t *engine) {
    if (!engine) return;

    /* v0.6.111: Set shutdown flag FIRST - callbacks check this before accessing engine.
     * This must happen before clearing g_dht_callback_engine so that any in-flight
     * DHT callbacks see shutdown_requested=true and exit safely. */
    atomic_store(&engine->shutdown_requested, true);

    /* v0.6.111: Clear DHT status callback BEFORE releasing lock.
     * Order matters for race prevention:
     * 1. Set shutdown_requested (callbacks will see this and exit)
     * 2. Clear callback pointer (no new callbacks will get engine)
     * 3. Brief sleep (let in-flight callbacks complete)
     * 4. Release identity lock (new engine can start) */
    pthread_mutex_lock(&g_engine_global_mutex);
    if (g_dht_callback_engine == engine) {
        nodus_messenger_set_status_callback(NULL, NULL);
        g_dht_callback_engine = NULL;
    }
    pthread_mutex_unlock(&g_engine_global_mutex);

    /* v0.9.7: Force-disconnect TCP to interrupt any blocking nodus operations.
     * Background threads (setup_listeners, stabilization_retry, heartbeat) may be
     * blocked inside nodus_ops calls (wait_response → epoll_wait). Closing the
     * socket makes these return immediately, so thread joins complete quickly. */
    nodus_messenger_force_disconnect();

    /* Brief barrier to let in-flight callbacks see shutdown_requested. */
    struct timespec barrier_sleep = { 0, 20 * 1000000L };  /* 20ms */
    nanosleep(&barrier_sleep, NULL);

    /* v0.6.110: Release identity lock (all platforms).
     * Now safe: shutdown flag set, callbacks cleared, barrier waited. */
    if (engine->identity_lock_fd >= 0) {
        QGP_LOG_INFO(LOG_TAG, "Releasing identity lock (fd=%d)",
                     engine->identity_lock_fd);
        qgp_platform_release_identity_lock(engine->identity_lock_fd);
        engine->identity_lock_fd = -1;
    }

    /* Stop worker threads (shutdown_requested already set above) */
    dna_stop_workers(engine);

    /* v0.6.0+: Wait for background threads to exit (they check shutdown_requested) */
    pthread_mutex_lock(&engine->background_threads_mutex);
    bool join_setup = engine->setup_listeners_running;
    bool join_stab = engine->stabilization_retry_running;
    pthread_mutex_unlock(&engine->background_threads_mutex);

    /* v0.6.113: Use condition variable wait instead of polling (more efficient)
     * v0.6.114: Increased timeout from 3s to 10s to allow DHT operations
     * (sync contacts, GEKs, groups) time to check shutdown_requested and exit. */
    if (join_setup || join_stab) {
        QGP_LOG_INFO(LOG_TAG, "Waiting for background threads to exit (setup=%d, stab=%d)...",
                     join_setup, join_stab);

        /* Calculate absolute timeout (10 seconds from now) */
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 10;

        pthread_mutex_lock(&engine->background_threads_mutex);

        /* Wait for setup_listeners thread */
        if (join_setup) {
            while (engine->setup_listeners_running) {
                int rc = pthread_cond_timedwait(&engine->background_thread_exit_cond,
                                                &engine->background_threads_mutex, &timeout);
                if (rc == ETIMEDOUT) {
                    QGP_LOG_WARN(LOG_TAG, "setup_listeners thread join timeout");
                    break;
                }
            }
        }

        /* Wait for stabilization_retry thread (reuse remaining timeout) */
        if (join_stab) {
            while (engine->stabilization_retry_running) {
                int rc = pthread_cond_timedwait(&engine->background_thread_exit_cond,
                                                &engine->background_threads_mutex, &timeout);
                if (rc == ETIMEDOUT) {
                    QGP_LOG_WARN(LOG_TAG, "stabilization_retry thread join timeout");
                    break;
                }
            }
        }

        pthread_mutex_unlock(&engine->background_threads_mutex);

        /* Join threads outside mutex (pthread_join can block) */
        if (join_setup) {
            pthread_join(engine->setup_listeners_thread, NULL);
            QGP_LOG_INFO(LOG_TAG, "setup_listeners thread exited");
        }
        if (join_stab) {
            pthread_join(engine->stabilization_retry_thread, NULL);
            QGP_LOG_INFO(LOG_TAG, "stabilization_retry thread exited");
        }
    }
    pthread_cond_destroy(&engine->background_thread_exit_cond);
    pthread_mutex_destroy(&engine->background_threads_mutex);

    /* Stop presence heartbeat thread */
    dna_stop_presence_heartbeat(engine);

    /* Clear GEK KEM keys (H3 security fix) */
    gek_clear_kem_keys();

    /* v0.6.107+: Cancel listeners BEFORE freeing messenger (prevents use-after-free) */
    /* Cancel all outbox listeners */
    dna_engine_cancel_all_outbox_listeners(engine);
    pthread_mutex_destroy(&engine->outbox_listeners_mutex);

    /* Cancel all presence listeners */
    /* v0.9.0: Presence listeners removed — batch query via Nodus server */

    /* Cancel contact request listener */
    dna_engine_cancel_contact_request_listener(engine);
    pthread_mutex_destroy(&engine->contact_request_listener_mutex);

    /* Cancel all ACK listeners (v15) */
    dna_engine_cancel_all_ack_listeners(engine);
    pthread_mutex_destroy(&engine->ack_listeners_mutex);

    /* Cancel all wall listeners */
    dna_engine_cancel_all_wall_listeners(engine);
    pthread_mutex_destroy(&engine->wall_listeners_mutex);

    /* Cancel all channel listeners */
    dna_engine_cancel_all_channel_listeners(engine);
    pthread_mutex_destroy(&engine->channel_listeners_mutex);

    /* Unsubscribe from all groups */
    dna_engine_unsubscribe_all_groups(engine);
    pthread_mutex_destroy(&engine->group_listen_mutex);

    /* Free messenger context (now safe after all listeners cancelled) */
    if (engine->messenger) {
        messenger_free(engine->messenger);
    }

    /* Free wallet list */
    // NOTE: engine->wallet_list removed in v0.3.150 - was never assigned (dead code)
    if (engine->blockchain_wallets) {
        blockchain_wallet_list_free(engine->blockchain_wallets);
    }

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

    /* v0.6.107+: Cleanup state mutex */
    pthread_mutex_destroy(&engine->state_mutex);

    /* Global caches (profile_manager, keyserver_cache) intentionally NOT closed.
     * They persist for app lifetime to survive engine destroy/recreate cycles
     * (Android pause/resume). Init functions are idempotent. OS cleans up on exit. */

    /* Close Nodus connection (cancels listeners, disconnects, frees client) */
    nodus_messenger_close();

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

/* ============================================================================
 * IDENTITY PUBLIC API - moved to src/api/engine/dna_engine_identity.c
 * Functions: dna_engine_get_fingerprint, dna_engine_create_identity,
 *   dna_engine_create_identity_sync, dna_engine_restore_identity_sync,
 *   dna_engine_delete_identity_sync, dna_engine_has_identity,
 *   dna_engine_prepare_dht_from_mnemonic, dna_engine_load_identity,
 *   dna_engine_is_identity_loaded, dna_engine_is_transport_ready,
 *   dna_engine_load_identity_minimal, dna_engine_register_name,
 *   dna_engine_get_display_name, dna_engine_get_avatar, dna_engine_lookup_name,
 *   dna_engine_get_profile, dna_engine_lookup_profile,
 *   dna_engine_refresh_contact_profile, dna_engine_update_profile,
 *   dna_engine_get_mnemonic, dna_engine_change_password_sync
 * ============================================================================ */

/* ============================================================================
 * CONTACTS PUBLIC API - moved to src/api/engine/dna_engine_contacts.c
 * Functions: dna_engine_get_contacts, dna_engine_add_contact,
 *   dna_engine_remove_contact, dna_engine_send_contact_request,
 *   dna_engine_get_contact_requests, dna_engine_get_contact_request_count,
 *   dna_engine_approve_contact_request, dna_engine_deny_contact_request,
 *   dna_engine_block_user, dna_engine_unblock_user,
 *   dna_engine_get_blocked_users, dna_engine_is_user_blocked
 * ============================================================================ */

/* ============================================================================
 * MESSAGING PUBLIC API - moved to src/api/engine/dna_engine_messaging.c
 * Functions: dna_engine_send_message, dna_engine_queue_message,
 *   dna_engine_get_message_queue_capacity, dna_engine_get_message_queue_size,
 *   dna_engine_set_message_queue_capacity, dna_engine_get_conversation,
 *   dna_engine_get_conversation_page, dna_engine_check_offline_messages,
 *   dna_engine_check_offline_messages_cached, dna_engine_check_offline_messages_from,
 *   dna_engine_get_unread_count, dna_engine_mark_conversation_read,
 *   dna_engine_delete_message_sync
 * ============================================================================ */

/* ============================================================================
 * GROUPS PUBLIC API - moved to src/api/engine/dna_engine_groups.c
 * Functions: dna_engine_get_groups, dna_engine_get_group_info,
 *   dna_engine_get_group_members, dna_engine_create_group,
 *   dna_engine_send_group_message, dna_engine_get_group_conversation,
 *   dna_engine_add_group_member, dna_engine_get_invitations,
 *   dna_engine_accept_invitation, dna_engine_reject_invitation
 * ============================================================================ */

/* Wallet API moved to src/api/engine/dna_engine_wallet.c */

/* P2P & Presence API moved to src/api/engine/dna_engine_p2p.c */

/* Listeners moved to src/api/engine/dna_engine_listeners.c */

/* ============================================================================
 * BACKWARD COMPATIBILITY
 * ============================================================================ */

void* dna_engine_get_messenger_context(dna_engine_t *engine) {
    if (!engine) return NULL;
    return engine->messenger;
}

int dna_engine_is_dht_connected(dna_engine_t *engine) {
    (void)engine;
    return nodus_messenger_is_ready() ? 1 : 0;
}

/* Version moved to src/api/engine/dna_engine_version.c */

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

void dna_free_profile(dna_profile_t *profile) {
    if (!profile) return;
    free(profile);
}

/* Debug log API moved to src/api/engine/dna_engine_logging.c */

/* Message backup/restore moved to src/api/engine/dna_engine_backup.c */

/* Version check moved to src/api/engine/dna_engine_version.c */
/* Signing API moved to src/api/engine/dna_engine_signing.c */
