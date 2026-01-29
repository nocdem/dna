/*
 * DNA Engine - Helpers Module
 *
 * Core helper functions used by multiple engine modules.
 *
 * Functions:
 *   - dna_get_dht_ctx()           // Get DHT context from engine
 *   - dna_load_private_key()      // Load signing key (DSA)
 *   - dna_load_encryption_key()   // Load encryption key (KEM)
 *   - dht_wait_for_stabilization() // Wait for DHT routing table
 */

#define DNA_ENGINE_HELPERS_IMPL
#include "engine_includes.h"

#include <stdatomic.h>

/* ============================================================================
 * DHT CONTEXT ACCESS
 * ============================================================================ */

/* Get DHT context (uses singleton - P2P transport reserved for voice/video) */
dht_context_t* dna_get_dht_ctx(dna_engine_t *engine) {
    /* v0.6.0+: Engine owns its own DHT context (no global singleton) */
    if (engine && engine->dht_ctx) {
        return engine->dht_ctx;
    }
    /* Fallback to singleton during migration (will be removed) */
    return dht_singleton_get();
}

/* ============================================================================
 * KEY LOADING
 * ============================================================================ */

/* Get private key for signing (caller frees with qgp_key_free) */
qgp_key_t* dna_load_private_key(dna_engine_t *engine) {
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

/* Get encryption key (caller frees with qgp_key_free) */
qgp_key_t* dna_load_encryption_key(dna_engine_t *engine) {
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

/* ============================================================================
 * DHT STABILIZATION
 * ============================================================================ */

/* Wait for DHT routing table to stabilize */
bool dht_wait_for_stabilization(dna_engine_t *engine) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) return false;

    for (int i = 0; i < DHT_STABILIZATION_MAX_SECONDS; i++) {
        if (atomic_load(&engine->shutdown_requested)) return false;

        size_t node_count = dht_context_get_node_count(dht);
        if (node_count >= DHT_STABILIZATION_MIN_NODES) {
            QGP_LOG_INFO(LOG_TAG, "[STABILIZE] Routing table ready: %zu nodes after %ds",
                         node_count, i);
            return true;
        }

        if (i > 0 && i % 5 == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "[STABILIZE] Waiting for nodes... (%zu/%d after %ds)",
                          node_count, DHT_STABILIZATION_MIN_NODES, i);
        }
        qgp_platform_sleep_ms(1000);
    }

    size_t final_count = dht_context_get_node_count(dht);
    QGP_LOG_WARN(LOG_TAG, "[STABILIZE] Timeout after %ds with %zu nodes (wanted %d)",
                 DHT_STABILIZATION_MAX_SECONDS, final_count, DHT_STABILIZATION_MIN_NODES);
    return true;  /* Continue anyway after timeout */
}
