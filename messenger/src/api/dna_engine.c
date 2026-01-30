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
#include "crypto/utils/threadpool.h"
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
void dna_engine_cancel_all_presence_listeners(dna_engine_t *engine);
void dna_engine_cancel_contact_request_listener(dna_engine_t *engine);
size_t dna_engine_start_contact_request_listener(dna_engine_t *engine);
void dna_engine_cancel_ack_listener(dna_engine_t *engine, const char *contact_fingerprint);
void dna_engine_cancel_all_ack_listeners(dna_engine_t *engine);
size_t dna_engine_listen_outbox(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_presence_listener(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_ack_listener(dna_engine_t *engine, const char *contact_fingerprint);

/* Forward declaration for log config initialization (defined in LOG CONFIGURATION section) */
void init_log_config(void);

/* Core helpers moved to src/api/engine/dna_engine_helpers.c */

/* is_valid_identity_name() moved to dna_engine_identity.c */
size_t dna_engine_start_presence_listener(dna_engine_t *engine, const char *contact_fingerprint);

/* Global engine pointer for DHT status callback and event dispatch from lower layers
 * Set during create, cleared during destroy. Used by messenger_transport.c to emit events.
 * Protected by g_engine_global_mutex (v0.6.43 race fix). */
static dna_engine_t *g_dht_callback_engine = NULL;
static pthread_mutex_t g_engine_global_mutex = PTHREAD_MUTEX_INITIALIZER;

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

/* Android DHT reconnection callback.
 * Called when DHT reconnects after network change. Used by foreground service
 * to recreate MINIMAL listeners. When set, engine skips automatic listener setup. */
static dna_android_reconnect_cb g_android_reconnect_cb = NULL;
static void *g_android_reconnect_data = NULL;

/* Mutex to protect Android callback globals during set/invoke (v0.6.40 race fix) */
static pthread_mutex_t g_android_callback_mutex = PTHREAD_MUTEX_INITIALIZER;

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
     *          This prevents ACKs being published while app is backgrounded,
     *          which would mark messages as "received" before user sees them.
     * Desktop: Fetch immediately since there's no background service. */
#ifndef __ANDROID__
    if (engine->messenger && engine->messenger->transport_ctx) {
        QGP_LOG_INFO(LOG_TAG, "[FETCH] DHT reconnect: checking for missed messages");
        size_t received = 0;
        transport_check_offline_messages(engine->messenger->transport_ctx, NULL, true, &received);
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

    /* 1b. Sync contacts from DHT (restore on new device)
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

    /* 4. Start outbox listeners for all contacts
     * This was previously called from Dart but blocked UI for up to 30s.
     * Moving here so it runs in background thread after DHT is stable. */
    if (engine->messenger && !atomic_load(&engine->shutdown_requested)) {
        int listener_count = dna_engine_listen_all_contacts(engine);
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: started %d contact listeners", listener_count);
    }

    if (atomic_load(&engine->shutdown_requested)) goto cleanup;

    /* 5. Create missing wallets (v0.6.88+: moved from identity load for instant startup)
     * Loads the Kyber1024 private key to decrypt the master seed, then creates
     * wallets for any newly supported blockchains. */
    if (engine->messenger && engine->messenger->fingerprint) {
        const char *data_dir = qgp_platform_app_data_dir();
        char kem_path[512];

        if (data_dir && messenger_find_key_path(data_dir, engine->messenger->fingerprint, ".kem", kem_path) == 0) {
            qgp_key_t *kem_key = NULL;
            int load_rc = qgp_key_load_encrypted(kem_path, engine->messenger->session_password, &kem_key);

            if (load_rc == 0 && kem_key && kem_key->private_key && kem_key->private_key_size == 3168) {
                int wallets_created = 0;
                int wallet_rc = blockchain_create_missing_wallets(
                    engine->messenger->fingerprint,
                    kem_key->private_key,
                    &wallets_created
                );

                if (wallet_rc == 0 && wallets_created > 0) {
                    QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: created %d missing wallets", wallets_created);
                } else if (wallet_rc == 0) {
                    QGP_LOG_INFO(LOG_TAG, "[RETRY] Post-stabilization: no missing wallets to create");
                } else {
                    QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: wallet creation failed: %d", wallet_rc);
                }
            } else {
                QGP_LOG_WARN(LOG_TAG, "[RETRY] Post-stabilization: could not load KEM key for wallet creation (rc=%d)", load_rc);
            }

            if (kem_key) {
                qgp_key_free(kem_key);
            }
        } else {
            QGP_LOG_INFO(LOG_TAG, "[RETRY] Post-stabilization: no KEM key file found, skipping wallet creation");
        }
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
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT connected, identity_loaded=%d reconnect_cb=%p",
                     engine->identity_loaded, (void*)g_android_reconnect_cb);
        if (engine->identity_loaded) {
            /* v0.6.8+: If Android reconnect callback is registered, let the service
             * handle listener recreation. This allows the foreground service to
             * create MINIMAL listeners instead of FULL listeners. */
            /* v0.6.47: Copy callback under mutex to avoid race with setter (security fix) */
            pthread_mutex_lock(&g_android_callback_mutex);
            dna_android_reconnect_cb reconnect_cb = g_android_reconnect_cb;
            void *reconnect_data = g_android_reconnect_data;
            pthread_mutex_unlock(&g_android_callback_mutex);

            if (reconnect_cb) {
                QGP_LOG_INFO(LOG_TAG, "[LISTEN] Calling Android reconnect callback (service mode)");
                reconnect_cb(reconnect_data);
            } else {
                /* Default: spawn listener setup thread for FULL listeners */
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
        case TASK_ADD_FEED_COMMENT:
            free(task->params.add_feed_comment.text);
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

        messenger_transport_check_offline_messages(engine->messenger, sender_fp, true, &offline_count);

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

    /* v0.6.40: Copy Android callbacks under mutex to avoid race with setter */
    pthread_mutex_lock(&g_android_callback_mutex);
    dna_android_notification_cb notify_cb = g_android_notification_cb;
    void *notify_data = g_android_notification_data;
#ifdef __ANDROID__
    dna_android_contact_request_cb contact_req_cb = g_android_contact_request_cb;
    void *contact_req_data = g_android_contact_request_data;
#endif
    pthread_mutex_unlock(&g_android_callback_mutex);

#ifdef __ANDROID__
    /* Android: When OUTBOX_UPDATED fires and Flutter is NOT attached, just show notification.
     * Don't fetch - let Flutter handle fetching when user opens app.
     * This avoids race conditions between C auto-fetch and Flutter fetch. */
    if (event->type == DNA_EVENT_OUTBOX_UPDATED) {
        QGP_LOG_INFO(LOG_TAG, "[ANDROID-NOTIFY] OUTBOX_UPDATED: cb=%p flutter_attached=%d",
                     (void*)notify_cb, flutter_attached);
    }
    if (event->type == DNA_EVENT_OUTBOX_UPDATED && notify_cb && !flutter_attached) {
        const char *contact_fp = event->data.outbox_updated.contact_fingerprint;
        const char *display_name = NULL;
        char name_buf[256] = {0};

        /* Try to get registered name from profile cache */
        dna_unified_identity_t *cached = NULL;
        uint64_t cached_at = 0;
        if (profile_cache_get(contact_fp, &cached, &cached_at) == 0 && cached) {
            if (cached->registered_name[0]) {
                strncpy(name_buf, cached->registered_name, sizeof(name_buf) - 1);
                display_name = name_buf;
            }
            dna_identity_free(cached);
        }

        QGP_LOG_INFO(LOG_TAG, "[ANDROID-NOTIFY] Flutter detached, notifying: fp=%.16s... name=%s",
                     contact_fp, display_name ? display_name : "(unknown)");
        notify_cb(contact_fp, display_name, notify_data);
    }
#endif

    /* Android notification callback - called for MESSAGE_RECEIVED events
     * (incoming messages only). This allows Android to show native
     * notifications when app is backgrounded. */
    if (event->type == DNA_EVENT_MESSAGE_RECEIVED && notify_cb) {
        /* Only notify for incoming messages, not our own sent messages */
        if (!event->data.message_received.message.is_outgoing) {
            const char *fp = event->data.message_received.message.sender;
            const char *display_name = NULL;
            char name_buf[256] = {0};

            /* Try to get registered name from profile cache */
            dna_unified_identity_t *cached = NULL;
            uint64_t cached_at = 0;
            if (profile_cache_get(fp, &cached, &cached_at) == 0 && cached) {
                if (cached->registered_name[0]) {
                    strncpy(name_buf, cached->registered_name, sizeof(name_buf) - 1);
                    display_name = name_buf;
                }
                dna_identity_free(cached);
            }

            QGP_LOG_INFO(LOG_TAG, "[ANDROID-NOTIFY] Calling callback: fp=%.16s... name=%s",
                         fp, display_name ? display_name : "(unknown)");
            notify_cb(fp, display_name, notify_data);
        }
    }

#ifdef __ANDROID__
    /* Android: Contact request notification - show notification when request arrives */
    if (event->type == DNA_EVENT_CONTACT_REQUEST_RECEIVED && contact_req_cb) {
        const char *user_fingerprint = event->data.contact_request_received.request.fingerprint;
        const char *user_display_name = event->data.contact_request_received.request.display_name;

        QGP_LOG_INFO(LOG_TAG, "[ANDROID-CONTACT-REQ] Contact request from %.16s... name=%s",
                     user_fingerprint, user_display_name[0] ? user_display_name : "(unknown)");
        contact_req_cb(user_fingerprint,
                       user_display_name[0] ? user_display_name : NULL,
                       contact_req_data);
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
        case TASK_RESTORE_GROUPS_FROM_DHT:
            dna_handle_restore_groups_from_dht(engine, task);
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

    /* Initialize ACK listeners (v15: replaced watermarks) */
    pthread_mutex_init(&engine->ack_listeners_mutex, NULL);
    engine->ack_listener_count = 0;
    memset(engine->ack_listeners, 0, sizeof(engine->ack_listeners));

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

void dna_engine_set_android_notification_callback(
    dna_android_notification_cb callback,
    void *user_data
) {
    pthread_mutex_lock(&g_android_callback_mutex);
    g_android_notification_cb = callback;
    g_android_notification_data = user_data;
    pthread_mutex_unlock(&g_android_callback_mutex);
    QGP_LOG_INFO(LOG_TAG, "Android notification callback %s",
                 callback ? "registered" : "cleared");
}

void dna_engine_set_android_group_message_callback(
    dna_android_group_message_cb callback,
    void *user_data
) {
    pthread_mutex_lock(&g_android_callback_mutex);
    g_android_group_message_cb = callback;
    g_android_group_message_data = user_data;
    pthread_mutex_unlock(&g_android_callback_mutex);
    QGP_LOG_INFO(LOG_TAG, "Android group message callback %s",
                 callback ? "registered" : "cleared");
}

void dna_engine_set_android_contact_request_callback(
    dna_android_contact_request_cb callback,
    void *user_data
) {
    pthread_mutex_lock(&g_android_callback_mutex);
    g_android_contact_request_cb = callback;
    g_android_contact_request_data = user_data;
    pthread_mutex_unlock(&g_android_callback_mutex);
    QGP_LOG_INFO(LOG_TAG, "Android contact request callback %s",
                 callback ? "registered" : "cleared");
}

void dna_engine_set_android_reconnect_callback(
    dna_android_reconnect_cb callback,
    void *user_data
) {
    pthread_mutex_lock(&g_android_callback_mutex);
    g_android_reconnect_cb = callback;
    g_android_reconnect_data = user_data;
    pthread_mutex_unlock(&g_android_callback_mutex);
    QGP_LOG_INFO(LOG_TAG, "Android reconnect callback %s",
                 callback ? "registered" : "cleared");
}

/* Internal helper to fire Android group message callback.
 * Called from group outbox subscribe on_new_message callback. */
void dna_engine_fire_group_message_callback(
    const char *group_uuid,
    const char *group_name,
    size_t new_count
) {
    /* Copy callback under mutex to avoid race with setter (v0.6.40) */
    pthread_mutex_lock(&g_android_callback_mutex);
    dna_android_group_message_cb cb = g_android_group_message_cb;
    void *data = g_android_group_message_data;
    pthread_mutex_unlock(&g_android_callback_mutex);

    if (cb && new_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Firing group message callback: group=%s count=%zu",
                     group_uuid, new_count);
        cb(group_uuid, group_name, new_count, data);
    }
}

/* Group listeners and day rotation moved to src/api/engine/dna_engine_listeners.c */

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

    /* Cancel all ACK listeners (v15) */
    dna_engine_cancel_all_ack_listeners(engine);
    pthread_mutex_destroy(&engine->ack_listeners_mutex);

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

    /* Global caches (profile_manager, keyserver_cache) intentionally NOT closed.
     * They persist for app lifetime to survive engine destroy/recreate cycles
     * (Android pause/resume). Init functions are idempotent. OS cleans up on exit. */

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

void* dna_engine_get_dht_context(dna_engine_t *engine) {
    (void)engine; /* DHT is global singleton */
    return dht_singleton_get();
}

int dna_engine_is_dht_connected(dna_engine_t *engine) {
    (void)engine; /* DHT is global singleton */
    return dht_singleton_is_ready() ? 1 : 0;
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

/* Debug log API moved to src/api/engine/dna_engine_logging.c */

/* Message backup/restore moved to src/api/engine/dna_engine_backup.c */

/* Version check moved to src/api/engine/dna_engine_version.c */
/* Signing API moved to src/api/engine/dna_engine_signing.c */
