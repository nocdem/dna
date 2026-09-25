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

/* dna_get_dht_ctx() removed — use nodus_ops_is_ready() / nodus_messenger_is_ready() instead */

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

/* Get ML-KEM-1024 key (KEM Faz 1, D6/D12, M1 delta 1b-2 — caller frees with
 * qgp_key_free). Mirrors dna_load_encryption_key() exactly, for the same
 * "session-password loaded, never a by-path load that bypasses it" reason
 * D12 fixes at the DHT layer. NULL when the identity has not migrated —
 * this is the common case (K2 or pre-migration), not an error, so a file-
 * exists check runs FIRST: without it, every profile update / backup /
 * GEKS sync on an unmigrated identity would call qgp_key_load(_encrypted)
 * on a path that does not exist and print "Cannot open file" ERROR on
 * every call — the exact noise D15 already removed from the identity-load
 * path; this helper must not reintroduce it at its own call sites. */
qgp_key_t* dna_load_mlkem_key(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.mlkem", engine->data_dir);

    if (!qgp_platform_file_exists(key_path)) {
        return NULL;
    }

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

/* Wait for DHT (nodus singleton) to stabilize */
bool dht_wait_for_stabilization(dna_engine_t *engine) {
    for (int i = 0; i < DHT_STABILIZATION_MAX_SECONDS; i++) {
        if (atomic_load(&engine->shutdown_requested)) return false;

        if (nodus_ops_is_ready()) {
            QGP_LOG_INFO(LOG_TAG, "[STABILIZE] Nodus ready after %ds", i);
            return true;
        }

        if (i > 0 && i % 5 == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "[STABILIZE] Waiting for nodus connection... (%ds)",
                          i);
        }
        qgp_platform_sleep_ms(1000);
    }

    QGP_LOG_WARN(LOG_TAG, "[STABILIZE] Timeout after %ds (nodus_ready=%d)",
                 DHT_STABILIZATION_MAX_SECONDS, nodus_ops_is_ready());
    return true;  /* Continue anyway — sync functions have invariant guards */
}
