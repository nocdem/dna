/*
 * DNA Engine - DNAC (Digital Cash) Module
 *
 * Wraps libdnac API into the engine async task system.
 * Lazy-initializes dnac_context_t on first use.
 *
 * Contains handlers and public API:
 *   - dna_handle_dnac_get_balance()
 *   - dna_handle_dnac_send()
 *   - dna_handle_dnac_sync()
 *   - dna_handle_dnac_get_history()
 *   - dna_handle_dnac_get_utxos()
 *   - dna_handle_dnac_estimate_fee()
 *   - dna_engine_dnac_get_balance()
 *   - dna_engine_dnac_send()
 *   - dna_engine_dnac_sync()
 *   - dna_engine_dnac_get_history()
 *   - dna_engine_dnac_get_utxos()
 *   - dna_engine_dnac_estimate_fee()
 *   - dna_engine_dnac_free_history()
 *   - dna_engine_dnac_free_utxos()
 *
 * STATUS: v0.9.173+ - DNAC wallet integration
 */

#define DNA_ENGINE_DNAC_IMPL

#include "engine_includes.h"
#include "dnac/dnac.h"

/* Override LOG_TAG for this module */
#undef LOG_TAG
#define LOG_TAG "ENGINE_DNAC"

/* ============================================================================
 * LAZY INITIALIZATION
 * ============================================================================ */

/**
 * Ensure DNAC context is initialized. Thread-safe via mutex.
 * Init happens once — no fast path needed, lock cost is negligible.
 * Returns dnac_context_t* or NULL on failure.
 */
static dnac_context_t* ensure_dnac_init(dna_engine_t *engine) {
    pthread_mutex_lock(&engine->task_mutex);

    if (engine->dnac_ctx) {
        pthread_mutex_unlock(&engine->task_mutex);
        return (dnac_context_t *)engine->dnac_ctx;
    }

    if (!engine->identity_loaded) {
        pthread_mutex_unlock(&engine->task_mutex);
        QGP_LOG_ERROR(LOG_TAG, "Cannot init DNAC: no identity loaded");
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Lazy-initializing DNAC context");
    dnac_context_t *ctx = dnac_init(engine);
    if (!ctx) {
        pthread_mutex_unlock(&engine->task_mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize DNAC context");
        return NULL;
    }

    engine->dnac_ctx = ctx;
    pthread_mutex_unlock(&engine->task_mutex);
    QGP_LOG_INFO(LOG_TAG, "DNAC context initialized successfully");
    return ctx;
}

/* ============================================================================
 * TASK HANDLERS
 * ============================================================================ */

void dna_handle_dnac_get_balance(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_balance(task->request_id,
                                     DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                     NULL, task->user_data);
        return;
    }

    dnac_balance_t bal = {0};
    int ret = dnac_get_balance(ctx, &bal);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_balance failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.dnac_balance(task->request_id, ret,
                                     NULL, task->user_data);
        return;
    }

    /* Convert to engine API type — heap-allocated so pointer survives
     * async NativeCallable.listener dispatch to Dart isolate.
     * Dart side frees via malloc.free() after reading. */
    dna_dnac_balance_t *result = calloc(1, sizeof(dna_dnac_balance_t));
    if (!result) {
        task->callback.dnac_balance(task->request_id,
                                     DNA_ERROR_INTERNAL,
                                     NULL, task->user_data);
        return;
    }
    result->confirmed = bal.confirmed;
    result->pending = bal.pending;
    result->locked = bal.locked;
    result->utxo_count = bal.utxo_count;

    QGP_LOG_DEBUG(LOG_TAG, "Balance: confirmed=%llu pending=%llu locked=%llu utxos=%d",
                  (unsigned long long)bal.confirmed,
                  (unsigned long long)bal.pending,
                  (unsigned long long)bal.locked,
                  bal.utxo_count);

    task->callback.dnac_balance(task->request_id, 0, result, task->user_data);
}

void dna_handle_dnac_send(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }

    const char *recipient = task->params.dnac_send.recipient_fingerprint;
    uint64_t amount = task->params.dnac_send.amount;
    const char *memo = task->params.dnac_send.memo[0] != '\0'
                       ? task->params.dnac_send.memo : NULL;

    QGP_LOG_INFO(LOG_TAG, "Sending %llu raw to %.16s... memo=%s",
                 (unsigned long long)amount, recipient,
                 memo ? memo : "(none)");

    int ret = dnac_send(ctx, recipient, amount, memo, NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_send failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.completion(task->request_id, ret, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Payment sent successfully: %llu raw to %.16s...",
                 (unsigned long long)amount, recipient);
    task->callback.completion(task->request_id, 0, task->user_data);
}

void dna_handle_dnac_sync(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }

    int ret = dnac_sync_wallet(ctx);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_sync_wallet failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.completion(task->request_id, ret, task->user_data);
        return;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Wallet sync completed");
    task->callback.completion(task->request_id, 0, task->user_data);
}

void dna_handle_dnac_get_history(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_history(task->request_id,
                                     DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                     NULL, 0, task->user_data);
        return;
    }

    dnac_tx_history_t *history = NULL;
    int count = 0;

    /* Fetch from Nodus (authoritative), fallback to local cache */
    int ret = dnac_get_remote_history(ctx, &history, &count);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_WARN(LOG_TAG, "remote history failed (%d), falling back to local",
                     ret);
        ret = dnac_get_history(ctx, &history, &count);
    }
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_history failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.dnac_history(task->request_id, ret,
                                     NULL, 0, task->user_data);
        return;
    }

    /* Convert to engine API type */
    dna_dnac_history_t *result = NULL;
    if (count > 0) {
        result = calloc(count, sizeof(dna_dnac_history_t));
        if (!result) {
            dnac_free_history(history, count);
            task->callback.dnac_history(task->request_id,
                                         DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
            return;
        }
        for (int i = 0; i < count; i++) {
            memcpy(result[i].tx_hash, history[i].tx_hash, 64);
            result[i].type = (int)history[i].type;
            strncpy(result[i].counterparty, history[i].counterparty, 128);
            result[i].counterparty[128] = '\0';
            result[i].amount_delta = history[i].amount_delta;
            result[i].fee = history[i].fee;
            result[i].timestamp = history[i].timestamp;
            strncpy(result[i].memo, history[i].memo, 255);
            result[i].memo[255] = '\0';
        }
    }

    dnac_free_history(history, count);

    QGP_LOG_DEBUG(LOG_TAG, "History: %d transactions", count);
    task->callback.dnac_history(task->request_id, 0, result, count,
                                 task->user_data);
}

void dna_handle_dnac_get_utxos(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_utxos(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   NULL, 0, task->user_data);
        return;
    }

    dnac_utxo_t *utxos = NULL;
    int count = 0;
    int ret = dnac_get_utxos(ctx, &utxos, &count);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_utxos failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.dnac_utxos(task->request_id, ret,
                                   NULL, 0, task->user_data);
        return;
    }

    /* Convert to engine API type */
    dna_dnac_utxo_t *result = NULL;
    if (count > 0) {
        result = calloc(count, sizeof(dna_dnac_utxo_t));
        if (!result) {
            dnac_free_utxos(utxos, count);
            task->callback.dnac_utxos(task->request_id,
                                       DNA_ERROR_INTERNAL,
                                       NULL, 0, task->user_data);
            return;
        }
        for (int i = 0; i < count; i++) {
            memcpy(result[i].tx_hash, utxos[i].tx_hash, 64);
            result[i].output_index = utxos[i].output_index;
            result[i].amount = utxos[i].amount;
            result[i].status = (int)utxos[i].status;
            result[i].received_at = utxos[i].received_at;
        }
    }

    dnac_free_utxos(utxos, count);

    QGP_LOG_DEBUG(LOG_TAG, "UTXOs: %d entries", count);
    task->callback.dnac_utxos(task->request_id, 0, result, count,
                               task->user_data);
}

void dna_handle_dnac_estimate_fee(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_fee(task->request_id,
                                 DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                 0, task->user_data);
        return;
    }

    uint64_t fee = 0;
    int ret = dnac_estimate_fee(ctx, task->params.dnac_estimate_fee.amount, &fee);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_estimate_fee failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.dnac_fee(task->request_id, ret, 0, task->user_data);
        return;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Fee estimate: %llu raw for amount %llu raw",
                  (unsigned long long)fee,
                  (unsigned long long)task->params.dnac_estimate_fee.amount);
    task->callback.dnac_fee(task->request_id, 0, fee, task->user_data);
}

/* ============================================================================
 * PUBLIC API WRAPPERS
 * ============================================================================ */

dna_request_id_t dna_engine_dnac_get_balance(
    dna_engine_t *engine,
    dna_dnac_balance_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.dnac_balance = callback;
    return dna_submit_task(engine, TASK_DNAC_GET_BALANCE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_send(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    uint64_t amount,
    const char *memo,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !recipient_fingerprint || amount == 0 || !callback)
        return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.dnac_send.recipient_fingerprint, recipient_fingerprint, 128);
    params.dnac_send.recipient_fingerprint[128] = '\0';
    params.dnac_send.amount = amount;
    if (memo) {
        strncpy(params.dnac_send.memo, memo, 255);
        params.dnac_send.memo[255] = '\0';
    }

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_SEND, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_sync(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_SYNC, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_get_history(
    dna_engine_t *engine,
    dna_dnac_history_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.dnac_history = callback;
    return dna_submit_task(engine, TASK_DNAC_GET_HISTORY, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_get_utxos(
    dna_engine_t *engine,
    dna_dnac_utxos_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.dnac_utxos = callback;
    return dna_submit_task(engine, TASK_DNAC_GET_UTXOS, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_estimate_fee(
    dna_engine_t *engine,
    uint64_t amount,
    dna_dnac_fee_cb callback,
    void *user_data
) {
    if (!engine || amount == 0 || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.dnac_estimate_fee.amount = amount;

    dna_task_callback_t cb = {0};
    cb.dnac_fee = callback;
    return dna_submit_task(engine, TASK_DNAC_ESTIMATE_FEE, &params, cb, user_data);
}

void dna_engine_dnac_free_history(dna_dnac_history_t *history, int count) {
    (void)count;
    free(history);
}

void dna_engine_dnac_free_utxos(dna_dnac_utxo_t *utxos, int count) {
    (void)count;
    free(utxos);
}
