/*
 * DNA Engine - Debug Log Inbox Module (v0.9.164+)
 *
 * Handles encrypted debug log delivery to a receiver's DHT inbox.
 *
 * Flow:
 *   1. Resolve receiver's Kyber1024 public key via profile_manager_get_profile().
 *   2. Encode inner plaintext (hint + log body).
 *   3. Hybrid-encrypt inner with Kyber1024 + AES-256-GCM.
 *   4. Encode outer payload (version + ct + nonce + enc_inner + tag).
 *   5. Derive inbox DHT key from receiver fingerprint (SHA3-512).
 *   6. PUT to DHT with a 1-hour TTL.
 *
 * Functions:
 *   - dna_handle_debug_log_send()     // Async task handler
 *   - dna_engine_debug_log_send()     // Public API wrapper
 */

#define DNA_ENGINE_DEBUG_LOG_IMPL
#include "engine_includes.h"

#include "dna_debug_log_wire.h"

#undef LOG_TAG
#define LOG_TAG "DEBUG_LOG"

#define DEBUG_LOG_TTL_SECONDS 3600u  /* 1 hour */

/* Convert a 128-char hex fingerprint into 64 raw bytes. */
static int fp_hex_to_raw(const char *hex, uint8_t out[64]) {
    if (!hex) return -1;
    if (strlen(hex) != 128) return -1;
    for (size_t i = 0; i < 64; i++) {
        unsigned int b = 0;
        if (sscanf(hex + (i * 2), "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

/* ============================================================================
 * TASK HANDLER
 * ============================================================================ */

void dna_handle_debug_log_send(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_ERROR_INTERNAL;

    if (!engine || !task) {
        /* Can't report — no callback. Just bail. */
        return;
    }

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *fp_hex = task->params.debug_log_send.receiver_fp_hex;
    const uint8_t *log_body = task->params.debug_log_send.log_body;
    size_t log_len = task->params.debug_log_send.log_len;
    const char *hint = task->params.debug_log_send.hint;

    if (!fp_hex || fp_hex[0] == '\0' || strlen(fp_hex) != 128) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }
    if (!log_body || log_len == 0 || log_len > DNA_DEBUG_LOG_MAX_BODY_LEN) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    /* --- 1. Fetch receiver's Kyber1024 public key --- */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fp_hex, &identity);
    if (rc != 0 || !identity) {
        QGP_LOG_WARN(LOG_TAG, "Failed to fetch receiver profile: %.16s... (rc=%d)",
                     fp_hex, rc);
        if (identity) dna_identity_free(identity);
        error = (rc == -2) ? DNA_ERROR_NOT_FOUND : DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    uint8_t receiver_kyber_pub[1568];
    memcpy(receiver_kyber_pub, identity->kyber_pubkey, sizeof(receiver_kyber_pub));
    dna_identity_free(identity);
    identity = NULL;

    /* --- 2. Convert receiver fp_hex -> raw 64-byte fingerprint --- */
    uint8_t receiver_fp_raw[64];
    if (fp_hex_to_raw(fp_hex, receiver_fp_raw) != 0) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    /* --- 3. Encode inner plaintext (hint + body) --- */
    size_t hint_len = hint ? strlen(hint) : 0;
    if (hint_len > DNA_DEBUG_LOG_MAX_HINT_LEN) hint_len = DNA_DEBUG_LOG_MAX_HINT_LEN;

    size_t inner_cap = DNA_DEBUG_LOG_INNER_HDR_LEN + hint_len + log_len;
    uint8_t *inner = malloc(inner_cap);
    if (!inner) {
        error = DNA_ERROR_MEMORY;
        goto done;
    }

    size_t inner_len = 0;
    int wrc = dna_debug_log_encode_inner(
        hint, hint_len, log_body, log_len,
        inner, inner_cap, &inner_len);
    if (wrc != DNA_DEBUG_LOG_OK) {
        QGP_LOG_ERROR(LOG_TAG, "encode_inner failed: %d", wrc);
        qgp_secure_memzero(inner, inner_cap);
        free(inner);
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* --- 4. Hybrid-encrypt inner (Kyber1024 + AES-256-GCM) --- */
    uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN];
    uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN];
    uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN];
    uint8_t *enc_inner = malloc(inner_len);
    if (!enc_inner) {
        qgp_secure_memzero(inner, inner_cap);
        free(inner);
        error = DNA_ERROR_MEMORY;
        goto done;
    }

    int ercc = dna_debug_log_encrypt_inner(
        receiver_kyber_pub, inner, inner_len,
        kyber_ct, nonce, enc_inner, inner_len, gcm_tag);

    /* inner buffer contains plaintext — zero and free immediately */
    qgp_secure_memzero(inner, inner_cap);
    free(inner);
    inner = NULL;

    if (ercc != DNA_DEBUG_LOG_OK) {
        QGP_LOG_ERROR(LOG_TAG, "encrypt_inner failed: %d", ercc);
        qgp_secure_memzero(enc_inner, inner_len);
        free(enc_inner);
        error = DNA_ERROR_CRYPTO;
        goto done;
    }

    /* --- 5. Encode outer wire blob --- */
    size_t outer_cap = 1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN
                       + inner_len + DNA_DEBUG_LOG_GCM_TAG_LEN;
    uint8_t *outer = malloc(outer_cap);
    if (!outer) {
        qgp_secure_memzero(enc_inner, inner_len);
        free(enc_inner);
        error = DNA_ERROR_MEMORY;
        goto done;
    }

    size_t outer_len = 0;
    int orc = dna_debug_log_encode_outer(
        kyber_ct, nonce, enc_inner, inner_len, gcm_tag,
        outer, outer_cap, &outer_len);

    qgp_secure_memzero(enc_inner, inner_len);
    free(enc_inner);
    enc_inner = NULL;

    if (orc != DNA_DEBUG_LOG_OK) {
        QGP_LOG_ERROR(LOG_TAG, "encode_outer failed: %d", orc);
        free(outer);
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* --- 6. Compute DHT inbox key --- */
    uint8_t inbox_key[64];
    int krc = dna_debug_log_inbox_key(receiver_fp_raw, inbox_key);
    if (krc != DNA_DEBUG_LOG_OK) {
        QGP_LOG_ERROR(LOG_TAG, "inbox_key derivation failed: %d", krc);
        free(outer);
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* --- 7. PUT to DHT (1-hour TTL, vid=0 -> auto from identity) --- */
    if (!nodus_ops_is_ready()) {
        QGP_LOG_WARN(LOG_TAG, "Nodus not ready for debug-log PUT");
        free(outer);
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    int prc = nodus_ops_put(inbox_key, sizeof(inbox_key),
                            outer, outer_len,
                            DEBUG_LOG_TTL_SECONDS, 0);
    free(outer);

    if (prc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "nodus_ops_put failed: %d", prc);
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    QGP_LOG_INFO(LOG_TAG, "Debug log sent to %.16s... (log=%zu bytes, wire=%zu bytes)",
                 fp_hex, log_len, outer_len);
    error = DNA_OK;

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

/* ============================================================================
 * PUBLIC API WRAPPER
 * ============================================================================ */

dna_request_id_t dna_engine_debug_log_send(
    dna_engine_t *engine,
    const char *receiver_fp_hex,
    const uint8_t *log_body,
    size_t log_len,
    const char *hint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !receiver_fp_hex || !log_body || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }
    if (strlen(receiver_fp_hex) != 128) return DNA_REQUEST_ID_INVALID;
    if (log_len == 0 || log_len > DNA_DEBUG_LOG_MAX_BODY_LEN) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    memcpy(params.debug_log_send.receiver_fp_hex, receiver_fp_hex, 128);
    params.debug_log_send.receiver_fp_hex[128] = '\0';

    params.debug_log_send.log_body = malloc(log_len);
    if (!params.debug_log_send.log_body) return DNA_REQUEST_ID_INVALID;
    memcpy(params.debug_log_send.log_body, log_body, log_len);
    params.debug_log_send.log_len = log_len;

    if (hint) {
        size_t h = strlen(hint);
        if (h > DNA_DEBUG_LOG_MAX_HINT_LEN) h = DNA_DEBUG_LOG_MAX_HINT_LEN;
        memcpy(params.debug_log_send.hint, hint, h);
        params.debug_log_send.hint[h] = '\0';
    }

    dna_task_callback_t cb = { .completion = callback };
    dna_request_id_t id = dna_submit_task(engine, TASK_DEBUG_LOG_SEND,
                                          &params, cb, user_data);
    if (id == DNA_REQUEST_ID_INVALID) {
        /* Submission failed — free payload ourselves since cleanup won't run */
        qgp_secure_memzero(params.debug_log_send.log_body, log_len);
        free(params.debug_log_send.log_body);
    }
    return id;
}
