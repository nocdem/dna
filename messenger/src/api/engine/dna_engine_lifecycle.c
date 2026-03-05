/*
 * DNA Engine - Lifecycle Module
 *
 * Engine pause/resume stubs. These are no-ops since v0.9.7 — Android no longer
 * uses a background service or pause/resume lifecycle. Engine stays active while
 * app is open, destroyed when app closes (same as desktop).
 *
 * Functions retained as no-op stubs for ABI compatibility.
 */

#define DNA_ENGINE_LIFECYCLE_IMPL
#include "engine_includes.h"

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
}

/* ============================================================================
 * ENGINE PAUSE/RESUME — NO-OP STUBS (v0.9.7+)
 *
 * Android service and pause/resume lifecycle removed. These remain as stubs
 * to preserve ABI compatibility with existing callers.
 * ============================================================================ */

int dna_engine_pause(dna_engine_t *engine) {
    (void)engine;
    QGP_LOG_DEBUG(LOG_TAG, "pause: no-op (service removed)");
    return 0;  /* DNA_OK */
}

int dna_engine_resume(dna_engine_t *engine) {
    (void)engine;
    QGP_LOG_DEBUG(LOG_TAG, "resume: no-op (service removed)");
    return 0;  /* DNA_OK */
}

bool dna_engine_is_paused(dna_engine_t *engine) {
    (void)engine;
    return false;
}
