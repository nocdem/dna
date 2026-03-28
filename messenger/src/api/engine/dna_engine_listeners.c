/*
 * DNA Engine - Listeners Module
 *
 * Real-time DHT listener management:
 *   - Outbox listeners (offline message notifications)
 *   - Contact request listeners (incoming requests)
 *   - ACK listeners (message delivery confirmation)
 *   - Channel post listeners (channel post updates)
 *
 * Functions:
 *   - dna_engine_listen_outbox()                    // Start outbox listener
 *   - dna_engine_cancel_outbox_listener()          // Cancel single outbox listener
 *   - dna_engine_cancel_all_outbox_listeners()     // Cancel all outbox listeners
 *   - dna_engine_listen_all_contacts()             // Start all contact listeners
 *   - dna_engine_refresh_listeners()               // Refresh all listeners
 *   - dna_engine_start_contact_request_listener()  // Start contact request listener
 *   - dna_engine_cancel_contact_request_listener() // Cancel contact request listener
 *   - dna_engine_start_ack_listener()              // Start ACK listener
 *   - dna_engine_cancel_ack_listener()             // Cancel single ACK listener
 *   - dna_engine_cancel_all_ack_listeners()        // Cancel all ACK listeners
 *   - dna_engine_start_channel_listener()          // Start channel post listener
 *   - dna_engine_cancel_channel_listener()         // Cancel single channel listener
 *   - dna_engine_cancel_all_channel_listeners()    // Cancel all channel listeners
 */

#define DNA_ENGINE_LISTENERS_IMPL
#include "engine_includes.h"
/* v0.9.0: transport_core.h no longer needed (presence listeners removed) */
#include "dht/client/dna_channels.h"  /* For dna_channel_make_posts_key */
#include "database/channel_subscriptions_db.h"  /* For dna_engine_listen_all_channels */
#include "database/channel_cache.h"  /* For cache invalidation on new posts */
#include "dht/shared/dht_contact_request.h"  /* For initial contact request pull */

/* ============================================================================
 * PARALLEL LISTENER SETUP (Mobile Performance Optimization)
 * ============================================================================ */

/**
 * Context for parallel listener worker threads
 */
typedef struct {
    dna_engine_t *engine;
    char fingerprint[129];
} parallel_listener_ctx_t;

/**
 * Thread pool task: setup listeners for one contact
 * Starts outbox + presence + ACK listeners in parallel for Flutter
 */
static void parallel_listener_worker(void *arg) {
    parallel_listener_ctx_t *ctx = (parallel_listener_ctx_t *)arg;
    if (!ctx || !ctx->engine) return;

    dna_engine_listen_outbox(ctx->engine, ctx->fingerprint);
    /* v0.9.0: Presence listeners removed — batch query via Nodus server */
    dna_engine_start_ack_listener(ctx->engine, ctx->fingerprint);
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

/* Note: outbox_listener_ctx_t is freed in cancel functions (v0.6.30) */

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

    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Setting up daily bucket listener for %.32s... (len=%zu)",
                 contact_fingerprint, fp_len);

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    /* Check if already listening to this contact */
    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            strcmp(engine->outbox_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {
            /* Verify listener is actually active in DHT layer */
            if (engine->outbox_listeners[i].dm_listen_ctx &&
                nodus_ops_is_listener_active(engine->outbox_listeners[i].dht_token)) {
                QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Already listening (token=%zu verified active)",
                             engine->outbox_listeners[i].dht_token);
                pthread_mutex_unlock(&engine->outbox_listeners_mutex);
                return engine->outbox_listeners[i].dht_token;
            } else {
                /* Stale entry - DHT listener was suspended/cancelled but engine not updated */
                QGP_LOG_WARN(LOG_TAG, "[LISTEN] Stale entry (token=%zu inactive in DHT), recreating",
                             engine->outbox_listeners[i].dht_token);
                if (engine->outbox_listeners[i].dm_listen_ctx) {
                    dht_dm_outbox_unsubscribe(engine->outbox_listeners[i].dm_listen_ctx);
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

    /* Look up per-contact DHT salt */
    uint8_t salt_buf[32];
    const uint8_t *salt_ptr = NULL;
    if (contacts_db_get_salt(contact_fingerprint, salt_buf) == 0) {
        salt_ptr = salt_buf;
    }

    dht_dm_listen_ctx_t *dm_listen_ctx = NULL;
    int result = dht_dm_outbox_subscribe(
                                          engine->fingerprint,      /* my_fp (recipient) */
                                          contact_fingerprint,      /* contact_fp (sender) */
                                          salt_ptr,                 /* per-contact DHT salt */
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

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            strcmp(engine->outbox_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {

            /* Cancel daily bucket listener */
            if (engine->outbox_listeners[i].dm_listen_ctx) {
                dht_dm_outbox_unsubscribe(engine->outbox_listeners[i].dm_listen_ctx);
                engine->outbox_listeners[i].dm_listen_ctx = NULL;
            } else if (engine->outbox_listeners[i].dht_token != 0) {
                nodus_ops_cancel_listen(engine->outbox_listeners[i].dht_token);
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
            bool dht_active = nodus_ops_is_listener_active(engine->outbox_listeners[i].dht_token);
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
     * This prevents silent failures where the second caller gets 0 listeners.
     * v0.6.40: Use mutex to protect listeners_starting check/set (TOCTOU fix)
     * v0.6.113: Use condition variable instead of polling for efficiency */
    pthread_mutex_lock(&engine->background_threads_mutex);
    if (engine->listeners_starting) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Listener setup already in progress, waiting...");

        /* v0.6.113: Wait up to 5 seconds using condition variable (replaces polling) */
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 5;

        while (engine->listeners_starting) {
            int rc = pthread_cond_timedwait(&engine->background_thread_exit_cond,
                                            &engine->background_threads_mutex, &timeout);
            if (rc == ETIMEDOUT) {
                /* Other thread took too long - something is wrong, but don't block forever */
                QGP_LOG_WARN(LOG_TAG, "[LISTEN] Timed out waiting for listener setup, proceeding anyway");
                break;
            }
        }

        if (!engine->listeners_starting) {
            pthread_mutex_unlock(&engine->background_threads_mutex);
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
    pthread_mutex_unlock(&engine->background_threads_mutex);

    /* Wait for nodus to become ready (connected + authenticated).
     * This ensures listeners actually work instead of silently failing.
     * v0.6.113: Reduced from 30s to 10s - listeners retry anyway. */
    if (!nodus_ops_is_ready()) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Waiting for nodus to become ready...");
        bool ready = false;
        for (int w = 0; w < 10; w++) {
            if (nodus_ops_is_ready()) { ready = true; break; }
            qgp_platform_sleep(1);
        }
        if (ready) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN] Nodus ready");
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Nodus not ready after 10s, proceeding anyway");
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] identity=%s", engine->fingerprint);

    /* Initialize contacts database for current identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to initialize contacts database");
        pthread_mutex_lock(&engine->background_threads_mutex);
        engine->listeners_starting = false;
        pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
        pthread_mutex_unlock(&engine->background_threads_mutex);
        return 0;
    }

    /* Get all contacts */
    contact_list_t *list = NULL;
    int db_result = contacts_db_list(&list);
    if (db_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] contacts_db_list failed: %d", db_result);
        if (list) contacts_db_free_list(list);
        pthread_mutex_lock(&engine->background_threads_mutex);
        engine->listeners_starting = false;
        pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
        pthread_mutex_unlock(&engine->background_threads_mutex);
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
        pthread_mutex_lock(&engine->background_threads_mutex);
        engine->listeners_starting = false;
        pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
        pthread_mutex_unlock(&engine->background_threads_mutex);
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Started 0 outbox + 0 presence + contact_req listeners");
        return 0;
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Found %zu contacts in database", list->count);

    /* Verify salt agreement for each contact before setting up listeners.
     * This ensures listeners subscribe to the correct (salted) DHT key.
     * Cost: 1 DHT GET per contact (one-time at startup). */
    {
        qgp_key_t *my_kyber = dna_load_encryption_key(engine);
        qgp_key_t *my_dilithium = dna_load_private_key(engine);

        if (my_kyber && my_dilithium) {
            size_t verified = 0, no_salt = 0, errors = 0;
            for (size_t i = 0; i < list->count; i++) {
                const char *contact_id = list->contacts[i].identity;
                if (!contact_id) continue;

                /* Load contact's Kyber pubkey for potential publish */
                uint8_t *contact_epk = NULL;
                size_t contact_elen = 0;
                uint8_t *contact_spk = NULL;
                size_t contact_slen = 0;
                if (engine->messenger) {
                    messenger_load_pubkey(engine->messenger, contact_id,
                                          &contact_spk, &contact_slen,
                                          &contact_epk, &contact_elen, NULL);
                }

                if (!contact_spk) {
                    /* Can't verify without contact's signing key */
                    no_salt++;
                    free(contact_epk);
                    free(contact_spk);
                    continue;
                }

                int vrc = salt_agreement_verify(
                    engine->fingerprint, contact_id,
                    my_kyber->public_key, my_kyber->private_key,
                    contact_epk,
                    my_dilithium->public_key,
                    my_dilithium->private_key,
                    contact_spk
                );

                if (vrc == 0) verified++;
                else if (vrc == 1) no_salt++;
                else errors++;

                free(contact_epk);
                free(contact_spk);
            }
            QGP_LOG_INFO(LOG_TAG, "[SALT] Verified %zu contacts: %zu ok, %zu pre-salt, %zu errors",
                         list->count, verified, no_salt, errors);
        }

        if (my_kyber) qgp_key_free(my_kyber);
        if (my_dilithium) qgp_key_free(my_dilithium);
    }

    /* Sync DM messages from all contacts BEFORE setting up listeners.
     * Use FULL sync (8 days) to catch all messages received by other devices.
     * Skip if stabilization thread already did a full sync (prevents double sync). */
    if (engine->messenger && !engine->dm_full_sync_done) {
        size_t dm_sync_count = 0;
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Full DM sync before listener setup...");
        int sync_result = messenger_transport_check_offline_messages(
            engine->messenger,
            NULL,           /* All contacts */
            false,          /* Don't publish ACKs yet - user hasn't read */
            false,          /* Smart sync decides: RECENT if <3 days, FULL otherwise */
            &dm_sync_count
        );
        if (sync_result == 0) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN] DM sync complete: %zu messages", dm_sync_count);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] DM sync failed (non-fatal): %d", sync_result);
        }
        engine->dm_full_sync_done = true;
    } else if (engine->dm_full_sync_done) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Skipping DM sync (already done by stabilization thread)");
    }

    /* PERF: Start listeners in parallel (mobile performance optimization)
     * Uses centralized thread pool for parallel listener setup.
     * Each task sets up outbox + presence + ACK listeners for one contact. */
    size_t count = list->count;

    parallel_listener_ctx_t *tasks = calloc(count, sizeof(parallel_listener_ctx_t));
    void **args = calloc(count, sizeof(void *));
    if (!tasks || !args) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to allocate parallel task memory");
        free(tasks);
        free(args);
        contacts_db_free_list(list);
        pthread_mutex_lock(&engine->background_threads_mutex);
        engine->listeners_starting = false;
        pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
        pthread_mutex_unlock(&engine->background_threads_mutex);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Starting parallel listeners for %zu contacts via thread pool", count);

    size_t valid_count = 0;
    for (size_t i = 0; i < count; i++) {
        const char *contact_id = list->contacts[i].identity;
        if (!contact_id) continue;

        /* Initialize task context */
        tasks[valid_count].engine = engine;
        strncpy(tasks[valid_count].fingerprint, contact_id, 128);
        tasks[valid_count].fingerprint[128] = '\0';
        args[valid_count] = &tasks[valid_count];
        valid_count++;
    }

    /* Execute all listener setups in parallel via thread pool */
    if (valid_count > 0) {
        threadpool_map(parallel_listener_worker, args, valid_count, 0);
    }

    free(tasks);
    free(args);

    /* Cleanup contact list */
    contacts_db_free_list(list);

    /* Start contact request listener (for real-time contact request notifications) */
    size_t contact_req_token = dna_engine_start_contact_request_listener(engine);
    if (contact_req_token > 0) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Contact request listener started, token=%zu", contact_req_token);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Failed to start contact request listener");
    }

    /* v0.9.0: Initial pull removed — Flutter calls get_contact_requests on startup
     * which does DHT fetch + auto-approve + DB write. The listener only handles
     * real-time pushes after registration. No duplicate DHT roundtrip needed. */

    pthread_mutex_lock(&engine->background_threads_mutex);
    engine->listeners_starting = false;
    pthread_cond_broadcast(&engine->background_thread_exit_cond);  /* v0.6.113: Signal waiters */
    pthread_mutex_unlock(&engine->background_threads_mutex);
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Parallel setup complete: %zu contacts processed", valid_count);

    /* Debug: log all active listeners for troubleshooting */
    dna_engine_log_active_listeners(engine);

    return valid_count;
}

/* NOTE: dna_engine_listen_all_contacts_minimal() removed in v0.6.15
 * Android service now uses polling (nativeCheckOfflineMessages) instead of listeners.
 * Polling is more battery-efficient and doesn't require continuous DHT subscriptions. */

void dna_engine_cancel_all_outbox_listeners(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active) {
            /* Cancel daily bucket context */
            if (engine->outbox_listeners[i].dm_listen_ctx) {
                dht_dm_outbox_unsubscribe(engine->outbox_listeners[i].dm_listen_ctx);
                engine->outbox_listeners[i].dm_listen_ctx = NULL;
            } else if (engine->outbox_listeners[i].dht_token != 0) {
                nodus_ops_cancel_listen(engine->outbox_listeners[i].dht_token);
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
    size_t active_count = nodus_ops_listen_count();
    QGP_LOG_INFO(LOG_TAG, "[REFRESH] Nodus listeners active: %zu", active_count);

    /* Cancel all engine-level listener tracking (clears arrays) */
    dna_engine_cancel_all_outbox_listeners(engine);
    dna_engine_cancel_contact_request_listener(engine);
#ifdef DNA_CHANNELS_ENABLED
    dna_engine_cancel_all_channel_listeners(engine);
#endif

    /* Restart listeners for all contacts (includes contact request listener) */
    int count = dna_engine_listen_all_contacts(engine);
    QGP_LOG_INFO(LOG_TAG, "[REFRESH] Restarted %d contact listeners", count);

#ifdef DNA_CHANNELS_ENABLED
    /* Restart channel listeners */
    int ch_count = dna_engine_listen_all_channels(engine);
    QGP_LOG_INFO(LOG_TAG, "[REFRESH] Restarted %d channel listeners", ch_count);
    return count + ch_count;
#else
    return count;
#endif
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

    if (!nodus_ops_is_ready()) {
        QGP_LOG_ERROR(LOG_TAG, "[CONTACT_REQ] Nodus not available");
        return 0;
    }

    pthread_mutex_lock(&engine->contact_request_listener_mutex);

    /* Check if already listening */
    if (engine->contact_request_listener.active) {
        /* Verify listener is actually active in nodus layer */
        if (nodus_ops_is_listener_active(engine->contact_request_listener.dht_token)) {
            QGP_LOG_DEBUG(LOG_TAG, "[CONTACT_REQ] Already listening (token=%zu verified active)",
                         engine->contact_request_listener.dht_token);
            pthread_mutex_unlock(&engine->contact_request_listener_mutex);
            return engine->contact_request_listener.dht_token;
        } else {
            /* Stale entry - listener was cancelled but engine not updated */
            QGP_LOG_WARN(LOG_TAG, "[CONTACT_REQ] Stale entry (token=%zu inactive), recreating",
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

    /* Start listening on inbox key */
    size_t token = nodus_ops_listen(inbox_key, 64,
                                     contact_request_listen_callback, ctx, contact_request_listener_cleanup);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[CONTACT_REQ] nodus_ops_listen() failed");
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

    pthread_mutex_lock(&engine->contact_request_listener_mutex);

    if (engine->contact_request_listener.active) {
        nodus_ops_cancel_listen(engine->contact_request_listener.dht_token);
        QGP_LOG_INFO(LOG_TAG, "[CONTACT_REQ] Listener cancelled (token=%zu)",
                     engine->contact_request_listener.dht_token);
    }
    engine->contact_request_listener.active = false;
    engine->contact_request_listener.dht_token = 0;

    pthread_mutex_unlock(&engine->contact_request_listener_mutex);
}

/* ============================================================================
 * SIMPLE ACK LISTENERS (v15: Message delivery confirmation)
 * ============================================================================ */

/**
 * Internal callback for ACK updates (v15: replaced watermarks)
 * Updates message status and dispatches DNA_EVENT_MESSAGE_DELIVERED
 */
static void ack_listener_callback(
    const char *sender,
    const char *recipient,
    uint64_t ack_timestamp,
    void *user_data
) {
    dna_engine_t *engine = (dna_engine_t *)user_data;
    if (!engine) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "[ACK] Received: %.20s... -> %.20s... ts=%lu",
                 sender, recipient, (unsigned long)ack_timestamp);

    /* Check if this is a new ACK (newer than we've seen) */
    uint64_t last_known = 0;

    pthread_mutex_lock(&engine->ack_listeners_mutex);
    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active &&
            strcmp(engine->ack_listeners[i].contact_fingerprint, recipient) == 0) {
            last_known = engine->ack_listeners[i].last_known_ack;
            if (ack_timestamp > last_known) {
                engine->ack_listeners[i].last_known_ack = ack_timestamp;
            }
            break;
        }
    }
    pthread_mutex_unlock(&engine->ack_listeners_mutex);

    /* Skip if we've already processed this or a newer ACK */
    if (ack_timestamp <= last_known) {
        QGP_LOG_DEBUG(LOG_TAG, "[ACK] Ignoring old/duplicate (ts=%lu <= last=%lu)",
                     (unsigned long)ack_timestamp, (unsigned long)last_known);
        return;
    }

    /* Mark ALL pending/sent messages to this contact as RECEIVED */
    if (engine->messenger && engine->messenger->backup_ctx) {
        int updated = message_backup_mark_received_for_contact(
            engine->messenger->backup_ctx,
            recipient   /* Contact fingerprint - they received our messages */
        );
        if (updated > 0) {
            QGP_LOG_INFO(LOG_TAG, "[ACK] Updated %d messages to RECEIVED", updated);
        }
    }

    /* Dispatch DNA_EVENT_MESSAGE_DELIVERED event */
    dna_event_t event = {0};
    event.type = DNA_EVENT_MESSAGE_DELIVERED;
    strncpy(event.data.message_delivered.recipient, recipient,
            sizeof(event.data.message_delivered.recipient) - 1);
    event.data.message_delivered.seq_num = ack_timestamp;  /* Use timestamp for compat */
    event.data.message_delivered.timestamp = (uint64_t)time(NULL);

    dna_dispatch_event(engine, &event);
}

/**
 * Start ACK listener for a contact (v15: replaced watermarks)
 *
 * IMPORTANT: This function releases the mutex before DHT calls to prevent
 * ABBA deadlock (ack_listeners_mutex vs DHT listeners_mutex).
 *
 * @param engine Engine instance
 * @param contact_fingerprint Contact to listen for ACKs from
 * @return DHT listener token (>0 on success, 0 on failure)
 */
size_t dna_engine_start_ack_listener(
    dna_engine_t *engine,
    const char *contact_fingerprint
) {
    if (!engine || !contact_fingerprint || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Cannot start: invalid params or no identity");
        return 0;
    }

    /* Validate fingerprints */
    size_t my_fp_len = strlen(engine->fingerprint);
    size_t contact_len = strlen(contact_fingerprint);
    if (my_fp_len != 128 || contact_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Invalid fingerprint length: mine=%zu contact=%zu",
                      my_fp_len, contact_len);
        return 0;
    }

    /* Phase 1: Check duplicates and capacity under mutex */
    pthread_mutex_lock(&engine->ack_listeners_mutex);

    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active &&
            strcmp(engine->ack_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "[ACK] Already listening for %.20s...", contact_fingerprint);
            size_t existing = engine->ack_listeners[i].dht_token;
            pthread_mutex_unlock(&engine->ack_listeners_mutex);
            return existing;
        }
    }

    if (engine->ack_listener_count >= DNA_MAX_ACK_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Maximum listeners reached (%d)", DNA_MAX_ACK_LISTENERS);
        pthread_mutex_unlock(&engine->ack_listeners_mutex);
        return 0;
    }

    /* Copy fingerprint for use outside mutex */
    char fp_copy[129];
    strncpy(fp_copy, contact_fingerprint, sizeof(fp_copy) - 1);
    fp_copy[128] = '\0';

    pthread_mutex_unlock(&engine->ack_listeners_mutex);

    /* Phase 2: DHT operations WITHOUT holding mutex (prevents ABBA deadlock) */

    /* Look up per-contact DHT salt for ACK key */
    uint8_t ack_salt_buf[32];
    const uint8_t *ack_salt_ptr = NULL;
    if (contacts_db_get_salt(fp_copy, ack_salt_buf) == 0) {
        ack_salt_ptr = ack_salt_buf;
    }

    /* Start DHT ACK listener */
    size_t token = dht_listen_ack(
                                   engine->fingerprint,
                                   fp_copy,
                                   ack_salt_ptr,
                                   ack_listener_callback,
                                   engine);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Failed to start listener for %.20s...", fp_copy);
        return 0;
    }

    /* Phase 3: Store listener info under mutex */
    pthread_mutex_lock(&engine->ack_listeners_mutex);

    /* Re-check capacity (race condition) */
    if (engine->ack_listener_count >= DNA_MAX_ACK_LISTENERS) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Capacity reached after DHT start, cancelling");
        pthread_mutex_unlock(&engine->ack_listeners_mutex);
        dht_cancel_ack_listener(token);
        return 0;
    }

    /* Check if another thread added this listener */
    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active &&
            strcmp(engine->ack_listeners[i].contact_fingerprint, fp_copy) == 0) {
            QGP_LOG_WARN(LOG_TAG, "[ACK] Race: duplicate for %.20s..., cancelling", fp_copy);
            pthread_mutex_unlock(&engine->ack_listeners_mutex);
            dht_cancel_ack_listener(token);
            return engine->ack_listeners[i].dht_token;
        }
    }

    /* Store listener */
    int idx = engine->ack_listener_count++;
    strncpy(engine->ack_listeners[idx].contact_fingerprint, fp_copy,
            sizeof(engine->ack_listeners[idx].contact_fingerprint) - 1);
    engine->ack_listeners[idx].contact_fingerprint[128] = '\0';
    engine->ack_listeners[idx].dht_token = token;
    engine->ack_listeners[idx].last_known_ack = 0;
    engine->ack_listeners[idx].active = true;

    QGP_LOG_INFO(LOG_TAG, "[ACK] Started listener for %.20s... (token=%zu)",
                 fp_copy, token);

    pthread_mutex_unlock(&engine->ack_listeners_mutex);
    return token;
}

/**
 * Cancel all ACK listeners (v15: called on engine destroy or identity unload)
 */
void dna_engine_cancel_all_ack_listeners(dna_engine_t *engine)
{
    if (!engine) {
        return;
    }

    pthread_mutex_lock(&engine->ack_listeners_mutex);

    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active) {
            dht_cancel_ack_listener(engine->ack_listeners[i].dht_token);
            QGP_LOG_DEBUG(LOG_TAG, "[ACK] Cancelled listener for %.20s...",
                          engine->ack_listeners[i].contact_fingerprint);
        }
        engine->ack_listeners[i].active = false;
    }

    engine->ack_listener_count = 0;
    QGP_LOG_INFO(LOG_TAG, "[ACK] Cancelled all listeners");

    pthread_mutex_unlock(&engine->ack_listeners_mutex);
}

/**
 * Cancel ACK listener for a specific contact (v15)
 * Called when a contact is removed.
 */
void dna_engine_cancel_ack_listener(dna_engine_t *engine, const char *contact_fingerprint)
{
    if (!engine || !contact_fingerprint) {
        return;
    }

    pthread_mutex_lock(&engine->ack_listeners_mutex);

    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active &&
            strcmp(engine->ack_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {

            dht_cancel_ack_listener(engine->ack_listeners[i].dht_token);

            QGP_LOG_INFO(LOG_TAG, "[ACK] Cancelled listener for %.20s...", contact_fingerprint);

            /* Remove by swapping with last element */
            if (i < engine->ack_listener_count - 1) {
                engine->ack_listeners[i] = engine->ack_listeners[engine->ack_listener_count - 1];
            }
            engine->ack_listener_count--;
            break;
        }
    }

    pthread_mutex_unlock(&engine->ack_listeners_mutex);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GROUP LISTENERS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Callback for group message notifications from dna_group_outbox_subscribe() */
static void on_group_new_message(const char *group_uuid, size_t new_count, void *user_data) {
    (void)user_data;
    QGP_LOG_INFO(LOG_TAG, "[GROUP] New messages: group=%s count=%zu", group_uuid, new_count);

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

    if (!nodus_ops_is_ready()) {
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
        dna_group_outbox_sync(group_uuid, &sync_count);
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Sync done: %zu messages", sync_count);

        /* Subscribe for real-time updates - single listener per group */
        QGP_LOG_WARN(LOG_TAG, "[GROUP] Subscribing to group %s...", group_uuid);
        dna_group_listen_ctx_t *ctx = NULL;
        ret = dna_group_outbox_subscribe(group_uuid,
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

    pthread_mutex_lock(&engine->group_listen_mutex);

    for (int i = 0; i < engine->group_listen_count; i++) {
        if (engine->group_listen_contexts[i]) {
            dna_group_outbox_unsubscribe(engine->group_listen_contexts[i]);
            engine->group_listen_contexts[i] = NULL;
        }
    }
    engine->group_listen_count = 0;

    pthread_mutex_unlock(&engine->group_listen_mutex);

    QGP_LOG_INFO(LOG_TAG, "[GROUP] Unsubscribed from all groups");
}

int dna_engine_check_group_day_rotation(dna_engine_t *engine) {
    if (!engine) return 0;

    int rotated = 0;
    pthread_mutex_lock(&engine->group_listen_mutex);

    for (int i = 0; i < engine->group_listen_count; i++) {
        if (engine->group_listen_contexts[i]) {
            int result = dna_group_outbox_check_day_rotation(
                engine->group_listen_contexts[i]);
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

/* ═══════════════════════════════════════════════════════════════════════════
 * DAY ROTATION
 * ═══════════════════════════════════════════════════════════════════════════ */

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

    int rotated = 0;
    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active &&
            engine->outbox_listeners[i].dm_listen_ctx) {

            int result = dht_dm_outbox_check_day_rotation(
                engine->outbox_listeners[i].dm_listen_ctx);

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

/* ============================================================================
 * CHANNEL LISTENERS (Real-time channel post notifications)
 * ============================================================================ */

/**
 * Context passed to channel DHT listen callback
 */
typedef struct {
    dna_engine_t *engine;
    char channel_uuid[37];
} channel_listener_ctx_t;

/**
 * Cleanup callback for channel listener - frees the context when listener cancelled
 */
static void channel_listener_cleanup(void *user_data) {
    channel_listener_ctx_t *ctx = (channel_listener_ctx_t *)user_data;
    if (ctx) {
        QGP_LOG_DEBUG(LOG_TAG, "[CHAN_LISTEN] Cleanup: freeing channel listener ctx for %.8s...",
                      ctx->channel_uuid);
        free(ctx);
    }
}

/**
 * DHT callback when a channel's post data changes
 * Fires DNA_EVENT_CHANNEL_NEW_POST to notify Flutter UI
 */
static bool channel_post_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    channel_listener_ctx_t *ctx = (channel_listener_ctx_t *)user_data;
    if (!ctx || !ctx->engine) {
        return false;  /* Stop listening */
    }

    /* Check shutdown */
    if (atomic_load(&ctx->engine->shutdown_requested)) {
        return false;
    }

    /* Only fire for new/updated values, not expirations */
    if (!expired && value && value_len > 0) {
        QGP_LOG_INFO(LOG_TAG, "[CHAN_LISTEN] New post in channel %.8s...",
                     ctx->channel_uuid);

        /* Invalidate posts cache so Flutter re-fetch goes to DHT */
        char cache_key[64];
        snprintf(cache_key, sizeof(cache_key), "posts:%s", ctx->channel_uuid);
        channel_cache_invalidate(cache_key);

        /* Fire DNA_EVENT_CHANNEL_NEW_POST event */
        dna_event_t event = {0};
        event.type = DNA_EVENT_CHANNEL_NEW_POST;
        strncpy(event.data.channel_new_post.channel_uuid,
                ctx->channel_uuid,
                sizeof(event.data.channel_new_post.channel_uuid) - 1);

        dna_dispatch_event(ctx->engine, &event);
    }

    return true;  /* Continue listening */
}

/**
 * Start listening for new posts in a channel
 *
 * @param engine Engine instance
 * @param channel_uuid Channel UUID to listen on
 * @return 0 on success, -1 on failure
 */
int dna_engine_start_channel_listener(dna_engine_t *engine, const char *channel_uuid) {
    if (!engine || !channel_uuid) return -1;

    if (!nodus_ops_is_ready()) return -1;

    pthread_mutex_lock(&engine->channel_listeners_mutex);

    /* Check if already listening */
    for (int i = 0; i < engine->channel_listener_count; i++) {
        if (engine->channel_listeners[i].active &&
            strcmp(engine->channel_listeners[i].channel_uuid, channel_uuid) == 0) {
            pthread_mutex_unlock(&engine->channel_listeners_mutex);
            return 0;  /* Already listening */
        }
    }

    /* Check capacity */
    if (engine->channel_listener_count >= DNA_MAX_CHANNEL_LISTENERS) {
        QGP_LOG_WARN(LOG_TAG, "[CHAN_LISTEN] Max channel listeners reached (%d)",
                     DNA_MAX_CHANNEL_LISTENERS);
        pthread_mutex_unlock(&engine->channel_listeners_mutex);
        return -1;
    }

    /* Derive DHT key for channel posts */
    uint8_t key[32];
    size_t key_len = 0;
    /* Listen on today's daily bucket key */
    char today[12];
    channel_get_today_date(today);
    if (dna_channel_make_posts_key(channel_uuid, today, key, &key_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[CHAN_LISTEN] Failed to derive posts key for %.8s...",
                      channel_uuid);
        pthread_mutex_unlock(&engine->channel_listeners_mutex);
        return -1;
    }

    /* Allocate context */
    channel_listener_ctx_t *ctx = calloc(1, sizeof(channel_listener_ctx_t));
    if (!ctx) {
        pthread_mutex_unlock(&engine->channel_listeners_mutex);
        return -1;
    }
    ctx->engine = engine;
    strncpy(ctx->channel_uuid, channel_uuid, 36);
    ctx->channel_uuid[36] = '\0';

    /* Start listening */
    size_t token = nodus_ops_listen(key, key_len,
                                     channel_post_listen_callback, ctx,
                                     channel_listener_cleanup);

    if (token == 0) {
        QGP_LOG_WARN(LOG_TAG, "[CHAN_LISTEN] Failed to start listener for %.8s...",
                     channel_uuid);
        free(ctx);
        pthread_mutex_unlock(&engine->channel_listeners_mutex);
        return -1;
    }

    /* Store in engine */
    int idx = engine->channel_listener_count;
    strncpy(engine->channel_listeners[idx].channel_uuid, channel_uuid, 36);
    engine->channel_listeners[idx].channel_uuid[36] = '\0';
    strncpy(engine->channel_listeners[idx].current_date, today, 11);
    engine->channel_listeners[idx].current_date[11] = '\0';
    engine->channel_listeners[idx].dht_token = token;
    engine->channel_listeners[idx].active = true;
    engine->channel_listener_count++;

    pthread_mutex_unlock(&engine->channel_listeners_mutex);

    /* v0.9.1: Initial pull — fetch existing channel posts from DHT.
     * The listener only catches NEW puts after registration. */
    {
        uint8_t *ch_data = NULL;
        size_t ch_len = 0;
        if (nodus_ops_get(key, key_len, &ch_data, &ch_len) == 0
            && ch_data && ch_len > 0) {
            channel_post_listen_callback(ch_data, ch_len, false, ctx);
        }
        if (ch_data) free(ch_data);
    }

    QGP_LOG_INFO(LOG_TAG, "[CHAN_LISTEN] Started channel listener for %.8s... (token=%zu)",
                 channel_uuid, token);
    return 0;
}

/**
 * Cancel channel listener for a specific channel
 */
void dna_engine_cancel_channel_listener(dna_engine_t *engine, const char *channel_uuid) {
    if (!engine || !channel_uuid) return;

    pthread_mutex_lock(&engine->channel_listeners_mutex);

    for (int i = 0; i < engine->channel_listener_count; i++) {
        if (engine->channel_listeners[i].active &&
            strcmp(engine->channel_listeners[i].channel_uuid, channel_uuid) == 0) {
            nodus_ops_cancel_listen(engine->channel_listeners[i].dht_token);
            engine->channel_listeners[i].active = false;

            /* Compact: move last entry to this slot */
            if (i < engine->channel_listener_count - 1) {
                engine->channel_listeners[i] = engine->channel_listeners[engine->channel_listener_count - 1];
            }
            engine->channel_listener_count--;
            break;
        }
    }

    pthread_mutex_unlock(&engine->channel_listeners_mutex);
}

/**
 * Cancel all channel listeners
 */
void dna_engine_cancel_all_channel_listeners(dna_engine_t *engine) {
    if (!engine) return;

    pthread_mutex_lock(&engine->channel_listeners_mutex);

    for (int i = 0; i < engine->channel_listener_count; i++) {
        if (engine->channel_listeners[i].active) {
            nodus_ops_cancel_listen(engine->channel_listeners[i].dht_token);
        }
        engine->channel_listeners[i].active = false;
    }

    engine->channel_listener_count = 0;
    QGP_LOG_INFO(LOG_TAG, "Cancelled all channel listeners");

    pthread_mutex_unlock(&engine->channel_listeners_mutex);
}

/**
 * Start listeners for all subscribed channels.
 * Called from setup_listeners_thread on DHT connect.
 *
 * @param engine Engine instance
 * @return Number of listeners started, or -1 on error
 */
int dna_engine_listen_all_channels(dna_engine_t *engine) {
    if (!engine) return -1;

    channel_subscription_t *subs = NULL;
    int count = 0;
    int ret = channel_subscriptions_db_get_all(&subs, &count);
    if (ret != 0 || count == 0) {
        QGP_LOG_INFO(LOG_TAG, "[CHAN_LISTEN] No channel subscriptions to listen on");
        return 0;
    }

    int started = 0;
    for (int i = 0; i < count; i++) {
        if (atomic_load(&engine->shutdown_requested)) break;

        if (dna_engine_start_channel_listener(engine, subs[i].channel_uuid) == 0) {
            started++;
        }
    }

    channel_subscriptions_db_free(subs, count);
    QGP_LOG_INFO(LOG_TAG, "[CHAN_LISTEN] Started %d/%d channel listeners", started, count);
    return started;
}

/**
 * Check and rotate channel post listeners at midnight UTC.
 * Called from heartbeat thread. Cancels old listener and starts
 * new one on today's dated key when the date changes.
 */
int dna_engine_check_channel_day_rotation(dna_engine_t *engine) {
    if (!engine) return 0;

    char today[12];
    channel_get_today_date(today);

    int rotated = 0;
    pthread_mutex_lock(&engine->channel_listeners_mutex);

    for (int i = 0; i < engine->channel_listener_count; i++) {
        if (!engine->channel_listeners[i].active) continue;
        if (strcmp(engine->channel_listeners[i].current_date, today) == 0) continue;

        /* Date changed — rotate this listener */
        char uuid[37];
        strncpy(uuid, engine->channel_listeners[i].channel_uuid, 36);
        uuid[36] = '\0';

        QGP_LOG_INFO(LOG_TAG, "[CHAN_LISTEN] Day rotation for %.8s... (%s -> %s)",
                     uuid, engine->channel_listeners[i].current_date, today);

        /* Cancel old listener */
        nodus_ops_cancel_listen(engine->channel_listeners[i].dht_token);
        engine->channel_listeners[i].active = false;

        /* Compact: move last entry to this slot */
        if (i < engine->channel_listener_count - 1) {
            engine->channel_listeners[i] = engine->channel_listeners[engine->channel_listener_count - 1];
        }
        engine->channel_listener_count--;
        i--;  /* Re-check this slot (now holds moved entry) */

        /* Restart on new day's key (must unlock to avoid deadlock) */
        pthread_mutex_unlock(&engine->channel_listeners_mutex);
        dna_engine_start_channel_listener(engine, uuid);
        pthread_mutex_lock(&engine->channel_listeners_mutex);

        rotated++;
    }

    pthread_mutex_unlock(&engine->channel_listeners_mutex);

    if (rotated > 0) {
        QGP_LOG_INFO(LOG_TAG, "[CHAN_LISTEN] Day rotation completed for %d channels", rotated);
    }
    return rotated;
}
