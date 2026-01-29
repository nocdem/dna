/*
 * DNA Engine - Listeners Module
 *
 * Real-time DHT listener management:
 *   - Outbox listeners (offline message notifications)
 *   - Presence listeners (contact online status)
 *   - Contact request listeners (incoming requests)
 *   - ACK listeners (message delivery confirmation)
 *
 * Functions:
 *   - dna_engine_listen_outbox()                    // Start outbox listener
 *   - dna_engine_cancel_outbox_listener()          // Cancel single outbox listener
 *   - dna_engine_cancel_all_outbox_listeners()     // Cancel all outbox listeners
 *   - dna_engine_listen_all_contacts()             // Start all contact listeners
 *   - dna_engine_start_presence_listener()         // Start presence listener
 *   - dna_engine_cancel_presence_listener()        // Cancel single presence listener
 *   - dna_engine_cancel_all_presence_listeners()   // Cancel all presence listeners
 *   - dna_engine_refresh_listeners()               // Refresh all listeners
 *   - dna_engine_start_contact_request_listener()  // Start contact request listener
 *   - dna_engine_cancel_contact_request_listener() // Cancel contact request listener
 *   - dna_engine_start_ack_listener()              // Start ACK listener
 *   - dna_engine_cancel_ack_listener()             // Cancel single ACK listener
 *   - dna_engine_cancel_all_ack_listeners()        // Cancel all ACK listeners
 */

#define DNA_ENGINE_LISTENERS_IMPL
#include "engine_includes.h"
#include "transport/internal/transport_core.h"  /* For parse_presence_json */

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
    dna_engine_start_presence_listener(ctx->engine, ctx->fingerprint);
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

            /* Cancel daily bucket listener (v0.4.81+)
             * v0.6.48: user_data is freed by dm_listen_cleanup() callback AFTER
             * dht_cancel_listen() marks listener inactive. This prevents use-after-free
             * when callback fires between free() and cancel(). */
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
     * This prevents silent failures where the second caller gets 0 listeners.
     * v0.6.40: Use mutex to protect listeners_starting check/set (TOCTOU fix) */
    pthread_mutex_lock(&engine->background_threads_mutex);
    if (engine->listeners_starting) {
        pthread_mutex_unlock(&engine->background_threads_mutex);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Listener setup already in progress, waiting...");
        /* Wait up to 5 seconds for the other thread to finish */
        for (int wait_count = 0; wait_count < 50; wait_count++) {
            pthread_mutex_lock(&engine->background_threads_mutex);
            bool still_starting = engine->listeners_starting;
            pthread_mutex_unlock(&engine->background_threads_mutex);
            if (!still_starting) break;
            qgp_platform_sleep_ms(100);
        }
        pthread_mutex_lock(&engine->background_threads_mutex);
        if (engine->listeners_starting) {
            pthread_mutex_unlock(&engine->background_threads_mutex);
            /* Other thread took too long - something is wrong, but don't block forever */
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Timed out waiting for listener setup, proceeding anyway");
        } else {
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
        /* Re-acquire mutex to set the flag */
        pthread_mutex_lock(&engine->background_threads_mutex);
    }
    engine->listeners_starting = true;
    pthread_mutex_unlock(&engine->background_threads_mutex);

    /* Wait for DHT to become ready (have peers in routing table)
     * This ensures listeners actually work instead of silently failing. */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx && !dht_context_is_ready(dht_ctx)) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Waiting for DHT to become ready...");
        if (dht_context_wait_for_ready(dht_ctx, 30000)) {
            QGP_LOG_INFO(LOG_TAG, "[LISTEN] DHT ready");
        } else {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] DHT not ready after 30s, proceeding anyway");
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] identity=%s", engine->fingerprint);

    /* Initialize contacts database for current identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to initialize contacts database");
        pthread_mutex_lock(&engine->background_threads_mutex);
        engine->listeners_starting = false;
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
        pthread_mutex_unlock(&engine->background_threads_mutex);
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Started 0 outbox + 0 presence + contact_req listeners");
        return 0;
    }

    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN] Found %zu contacts in database", list->count);

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

    pthread_mutex_lock(&engine->background_threads_mutex);
    engine->listeners_starting = false;
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

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->outbox_listeners_mutex);

    for (int i = 0; i < engine->outbox_listener_count; i++) {
        if (engine->outbox_listeners[i].active) {
            /* Cancel daily bucket context (v0.5.0+)
             * v0.6.48: user_data is freed by dm_listen_cleanup() callback AFTER
             * dht_cancel_listen() marks listener inactive. This prevents use-after-free
             * when callback fires between free() and cancel(). */
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

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] DHT not available");
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

    /* Start DHT ACK listener */
    size_t token = dht_listen_ack(dht_ctx,
                                   engine->fingerprint,
                                   fp_copy,
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
        dht_cancel_ack_listener(dht_ctx, token);
        return 0;
    }

    /* Check if another thread added this listener */
    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active &&
            strcmp(engine->ack_listeners[i].contact_fingerprint, fp_copy) == 0) {
            QGP_LOG_WARN(LOG_TAG, "[ACK] Race: duplicate for %.20s..., cancelling", fp_copy);
            pthread_mutex_unlock(&engine->ack_listeners_mutex);
            dht_cancel_ack_listener(dht_ctx, token);
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

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->ack_listeners_mutex);

    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active && dht_ctx) {
            dht_cancel_ack_listener(dht_ctx, engine->ack_listeners[i].dht_token);
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

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);

    pthread_mutex_lock(&engine->ack_listeners_mutex);

    for (int i = 0; i < engine->ack_listener_count; i++) {
        if (engine->ack_listeners[i].active &&
            strcmp(engine->ack_listeners[i].contact_fingerprint, contact_fingerprint) == 0) {

            if (dht_ctx) {
                dht_cancel_ack_listener(dht_ctx, engine->ack_listeners[i].dht_token);
            }

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
