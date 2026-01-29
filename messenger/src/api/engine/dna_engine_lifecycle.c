/*
 * DNA Engine - Lifecycle Module
 *
 * Engine pause/resume for mobile background/foreground transitions.
 * Keeps DHT connection alive while suspending listeners.
 *
 * Functions:
 *   - dna_engine_pause_presence()    // Pause presence heartbeat
 *   - dna_engine_resume_presence()   // Resume presence heartbeat
 *   - dna_engine_pause()             // Full engine pause (background)
 *   - dna_engine_resume()            // Full engine resume (foreground)
 *   - dna_engine_is_paused()         // Check if engine is paused
 */

#define DNA_ENGINE_LIFECYCLE_IMPL
#include "engine_includes.h"

#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * PRESENCE PAUSE/RESUME
 * ============================================================================ */

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

/* ============================================================================
 * ENGINE PAUSE/RESUME (v0.6.50+)
 *
 * Allows keeping engine alive when app goes to background, avoiding expensive
 * full reinitialization on resume. Listeners are suspended (not destroyed)
 * so they can be quickly resubscribed on resume.
 * ============================================================================ */

int dna_engine_pause(dna_engine_t *engine) {
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "pause: NULL engine");
        return DNA_ENGINE_ERROR_NOT_INITIALIZED;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "pause: No identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    if (engine->state == DNA_ENGINE_STATE_PAUSED) {
        QGP_LOG_DEBUG(LOG_TAG, "pause: Already paused");
        return DNA_OK;
    }

    QGP_LOG_INFO(LOG_TAG, "[PAUSE] Pausing engine (suspending listeners, keeping DHT alive)");

    /* 1. Pause presence heartbeat (stops marking us as online) */
    dna_engine_pause_presence(engine);

    /* 2. Suspend all DHT listeners (preserves them for resubscription)
     * This uses the existing infrastructure from dht_listen.cpp that stores
     * key_data for each listener, allowing fast resubscription. */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx) {
        dht_suspend_all_listeners(dht_ctx);
        QGP_LOG_INFO(LOG_TAG, "[PAUSE] DHT listeners suspended");
    }

    /* 3. Unsubscribe from all groups (group listeners are managed separately) */
    dna_engine_unsubscribe_all_groups(engine);
    QGP_LOG_INFO(LOG_TAG, "[PAUSE] Group listeners cancelled");

    /* 4. Update state */
    engine->state = DNA_ENGINE_STATE_PAUSED;

    QGP_LOG_INFO(LOG_TAG, "[PAUSE] Engine paused successfully - DHT connection and databases remain open");
    return DNA_OK;
}

/**
 * Background thread for engine resume (non-blocking)
 *
 * This runs the heavy DHT resubscription work on a background thread
 * so the UI doesn't freeze. The main thread returns immediately after
 * spawning this thread.
 */
static void *resume_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t *)arg;

    QGP_LOG_INFO(LOG_TAG, "[RESUME-THREAD] Starting background resubscription");

    /* Check engine is still valid and in resuming state */
    if (!engine || engine->state != DNA_ENGINE_STATE_ACTIVE) {
        QGP_LOG_WARN(LOG_TAG, "[RESUME-THREAD] Engine invalid or state changed, aborting");
        return NULL;
    }

    /* 1. Resubscribe all DHT listeners (this is the slow part) */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx) {
        size_t resubscribed = dht_resubscribe_all_listeners(dht_ctx);
        QGP_LOG_INFO(LOG_TAG, "[RESUME-THREAD] Resubscribed %zu DHT listeners", resubscribed);
    }

    /* Check for abort (engine might have been paused again) */
    if (engine->state != DNA_ENGINE_STATE_ACTIVE) {
        QGP_LOG_WARN(LOG_TAG, "[RESUME-THREAD] Engine state changed during resume, stopping");
        return NULL;
    }

    /* 2. Resubscribe to all groups */
    int group_count = dna_engine_subscribe_all_groups(engine);
    QGP_LOG_INFO(LOG_TAG, "[RESUME-THREAD] Subscribed to %d groups", group_count);

    /* 3. Retry any pending messages that may have failed while paused */
    int retried = dna_engine_retry_pending_messages(engine);
    if (retried > 0) {
        QGP_LOG_INFO(LOG_TAG, "[RESUME-THREAD] Retried %d pending messages", retried);
    }

    QGP_LOG_INFO(LOG_TAG, "[RESUME-THREAD] Background resubscription complete");
    return NULL;
}

int dna_engine_resume(dna_engine_t *engine) {
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "resume: NULL engine");
        return DNA_ENGINE_ERROR_NOT_INITIALIZED;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "resume: No identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    if (engine->state != DNA_ENGINE_STATE_PAUSED) {
        QGP_LOG_DEBUG(LOG_TAG, "resume: Not paused (state=%d)", engine->state);
        return DNA_OK;  /* Not an error, just nothing to do */
    }

    QGP_LOG_INFO(LOG_TAG, "[RESUME] Resuming engine (spawning background thread)");

    /* 1. Update state first to allow listeners to work */
    engine->state = DNA_ENGINE_STATE_ACTIVE;

    /* 2. Resume presence heartbeat IMMEDIATELY (marks us as online) */
    dna_engine_resume_presence(engine);

    /* 3. Spawn background thread for the heavy lifting (DHT resubscription)
     * This prevents the UI from freezing during listener resubscription */
    pthread_t resume_tid;
    int rc = pthread_create(&resume_tid, NULL, resume_thread, engine);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[RESUME] Failed to spawn resume thread: %d", rc);
        /* Fall back to synchronous resume */
        dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
        if (dht_ctx) {
            dht_resubscribe_all_listeners(dht_ctx);
        }
        dna_engine_subscribe_all_groups(engine);
        dna_engine_retry_pending_messages(engine);
    } else {
        /* Detach thread - we don't need to join it */
        pthread_detach(resume_tid);
        QGP_LOG_INFO(LOG_TAG, "[RESUME] Background thread spawned, returning immediately");
    }

    return DNA_OK;
}

bool dna_engine_is_paused(dna_engine_t *engine) {
    if (!engine) return false;
    return engine->state == DNA_ENGINE_STATE_PAUSED;
}
