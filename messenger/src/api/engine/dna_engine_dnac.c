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
    const uint8_t *token_id = task->params.dnac_send.has_token_id
                              ? task->params.dnac_send.token_id : NULL;

    QGP_LOG_INFO(LOG_TAG, "Sending %llu raw to %.16s... token=%s memo=%s",
                 (unsigned long long)amount, recipient,
                 token_id ? "custom" : "native",
                 memo ? memo : "(none)");

    int ret = dnac_send_token(ctx, recipient, amount, memo, token_id, NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_send failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.completion(task->request_id, ret, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Payment sent successfully: %llu raw to %.16s... token=%s",
                 (unsigned long long)amount, recipient,
                 token_id ? "custom" : "native");
    task->callback.completion(task->request_id, 0, task->user_data);
}

/* Phase 13 / Task 13.5 — sync getter for the most recent send receipt. */
int dna_engine_dnac_last_send_receipt(dna_engine_t *engine,
                                        uint64_t *block_height_out,
                                        uint32_t *tx_index_out,
                                        uint8_t *tx_hash_out) {
    if (!engine) return -1;
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) return -1;
    return dnac_last_send_receipt(ctx, block_height_out, tx_index_out,
                                    tx_hash_out);
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

/* Shared emit path: converts dnac_tx_history_t[] to dna_dnac_history_t[]
 * and fires the task callback. Used by both remote and local handlers. */
static void emit_dnac_history(dna_task_t *task,
                               dnac_tx_history_t *history, int count) {
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
            memcpy(result[i].token_id, history[i].token_id, 64);
        }
    }
    dnac_free_history(history, count);
    QGP_LOG_DEBUG(LOG_TAG, "History: %d transactions", count);
    task->callback.dnac_history(task->request_id, 0, result, count,
                                 task->user_data);
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

    /* Authoritative path: fetch from witnesses (blocks up to 10s).
     * dnac_get_remote_history persists each entry to local DB as a side
     * effect, so subsequent get_history_local calls see incoming TXs. */
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

    emit_dnac_history(task, history, count);
}

/* Local-only history read: returns immediately from the local DB cache,
 * never touches the witness network. Used by the history screen's
 * stale-while-revalidate pattern — Flutter calls this first to populate
 * the UI, then fires dna_engine_dnac_get_history in the background to
 * refresh from witnesses (which also persists new incoming TXs). */
void dna_handle_dnac_get_history_local(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_history(task->request_id,
                                     DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                     NULL, 0, task->user_data);
        return;
    }

    dnac_tx_history_t *history = NULL;
    int count = 0;
    int ret = dnac_get_history(ctx, &history, &count);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_history (local) failed: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.dnac_history(task->request_id, ret,
                                     NULL, 0, task->user_data);
        return;
    }

    emit_dnac_history(task, history, count);
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
    const uint8_t *token_id,
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
    if (token_id) {
        memcpy(params.dnac_send.token_id, token_id, 64);
        params.dnac_send.has_token_id = true;
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

dna_request_id_t dna_engine_dnac_get_history_local(
    dna_engine_t *engine,
    dna_dnac_history_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.dnac_history = callback;
    return dna_submit_task(engine, TASK_DNAC_GET_HISTORY_LOCAL, &params, cb, user_data);
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

#define TOKEN_LIST_MAX 256

void dna_handle_dnac_token_list(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) { task->callback.dnac_token_list(task->request_id, DNA_ENGINE_ERROR_NOT_INITIALIZED, NULL, 0, task->user_data); return; }
    dnac_sync_tokens(ctx);
    dnac_token_t buf[TOKEN_LIST_MAX];
    int count = 0;
    int ret = dnac_token_list(ctx, buf, TOKEN_LIST_MAX, &count);
    if (ret != DNAC_SUCCESS) { QGP_LOG_ERROR(LOG_TAG, "dnac_token_list failed: %d", ret); task->callback.dnac_token_list(task->request_id, ret, NULL, 0, task->user_data); return; }
    dna_dnac_token_t *result = NULL;
    if (count > 0) {
        result = calloc(count, sizeof(dna_dnac_token_t));
        if (!result) { task->callback.dnac_token_list(task->request_id, DNA_ERROR_INTERNAL, NULL, 0, task->user_data); return; }
        for (int i = 0; i < count; i++) {
            memcpy(result[i].token_id, buf[i].token_id, 64);
            strncpy(result[i].name, buf[i].name, 32); result[i].name[32] = '\0';
            strncpy(result[i].symbol, buf[i].symbol, 8); result[i].symbol[8] = '\0';
            result[i].decimals = buf[i].decimals;
            result[i].supply = (int64_t)buf[i].initial_supply;
            strncpy(result[i].creator_fp, buf[i].creator_fp, 128); result[i].creator_fp[128] = '\0';
        }
    }
    QGP_LOG_DEBUG(LOG_TAG, "Token list: %d tokens", count);
    task->callback.dnac_token_list(task->request_id, 0, result, count, task->user_data);
}

void dna_handle_dnac_token_create(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) { task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NOT_INITIALIZED, task->user_data); return; }
    const char *name = task->params.dnac_token_create.name;
    const char *symbol = task->params.dnac_token_create.symbol;
    uint8_t decimals = task->params.dnac_token_create.decimals;
    uint64_t supply = task->params.dnac_token_create.supply;
    QGP_LOG_INFO(LOG_TAG, "Creating token: name=%s symbol=%s decimals=%u supply=%llu", name, symbol, decimals, (unsigned long long)supply);
    int ret = dnac_token_create(ctx, name, symbol, decimals, supply);
    if (ret != DNAC_SUCCESS) { QGP_LOG_ERROR(LOG_TAG, "dnac_token_create failed: %d (%s)", ret, dnac_error_string(ret)); task->callback.completion(task->request_id, ret, task->user_data); return; }
    QGP_LOG_INFO(LOG_TAG, "Token created: %s (%s)", name, symbol);
    task->callback.completion(task->request_id, 0, task->user_data);
}

void dna_handle_dnac_token_balance(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) { task->callback.dnac_balance(task->request_id, DNA_ENGINE_ERROR_NOT_INITIALIZED, NULL, task->user_data); return; }
    dnac_balance_t bal = {0};
    int ret = dnac_wallet_get_balance_token(ctx, task->params.dnac_token_balance.token_id, &bal);
    if (ret != DNAC_SUCCESS) { QGP_LOG_ERROR(LOG_TAG, "token balance failed: %d", ret); task->callback.dnac_balance(task->request_id, ret, NULL, task->user_data); return; }
    dna_dnac_balance_t *result = calloc(1, sizeof(dna_dnac_balance_t));
    if (!result) { task->callback.dnac_balance(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data); return; }
    result->confirmed = bal.confirmed; result->pending = bal.pending; result->locked = bal.locked; result->utxo_count = bal.utxo_count;
    task->callback.dnac_balance(task->request_id, 0, result, task->user_data);
}

dna_request_id_t dna_engine_dnac_token_list(dna_engine_t *engine, dna_dnac_token_list_cb callback, void *user_data) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0}; dna_task_callback_t cb = {0}; cb.dnac_token_list = callback;
    return dna_submit_task(engine, TASK_DNAC_TOKEN_LIST, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_token_create(dna_engine_t *engine, const char *name, const char *symbol, uint8_t decimals, uint64_t supply, dna_completion_cb callback, void *user_data) {
    if (!engine || !name || !symbol || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    strncpy(params.dnac_token_create.name, name, 32); params.dnac_token_create.name[32] = '\0';
    strncpy(params.dnac_token_create.symbol, symbol, 8); params.dnac_token_create.symbol[8] = '\0';
    params.dnac_token_create.decimals = decimals; params.dnac_token_create.supply = supply;
    dna_task_callback_t cb = {0}; cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_TOKEN_CREATE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_token_balance(dna_engine_t *engine, const uint8_t *token_id, dna_dnac_balance_cb callback, void *user_data) {
    if (!engine || !token_id || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0}; memcpy(params.dnac_token_balance.token_id, token_id, 64);
    dna_task_callback_t cb = {0}; cb.dnac_balance = callback;
    return dna_submit_task(engine, TASK_DNAC_TOKEN_BALANCE, &params, cb, user_data);
}

void dna_engine_dnac_free_tokens(dna_dnac_token_t *tokens, int count) { (void)count; free(tokens); }

/* ============================================================================
 * Stake & Delegation (Phase 16 Task 71)
 * ============================================================================ */

void dna_engine_dnac_free_validator_entries(dna_dnac_validator_entry_t *entries,
                                            int count) {
    (void)count;
    free(entries);
}

/* --- Handlers --- */

void dna_handle_dnac_stake(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }
    int ret = dnac_stake(ctx,
                          task->params.dnac_stake.commission_bps,
                          task->params.dnac_stake.unstake_destination_fp,
                          NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_stake failed: %d (%s)", ret,
                      dnac_error_string(ret));
    }
    task->callback.completion(task->request_id, ret, task->user_data);
}

void dna_handle_dnac_unstake(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }
    int ret = dnac_unstake(ctx, NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_unstake failed: %d (%s)", ret,
                      dnac_error_string(ret));
    }
    task->callback.completion(task->request_id, ret, task->user_data);
}

void dna_handle_dnac_delegate(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }
    int ret = dnac_delegate(ctx,
                             task->params.dnac_delegate.validator_pubkey,
                             task->params.dnac_delegate.amount,
                             NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_delegate failed: %d (%s)", ret,
                      dnac_error_string(ret));
    }
    task->callback.completion(task->request_id, ret, task->user_data);
}

void dna_handle_dnac_undelegate(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }
    int ret = dnac_undelegate(ctx,
                               task->params.dnac_undelegate.validator_pubkey,
                               task->params.dnac_undelegate.amount,
                               NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_undelegate failed: %d (%s)", ret,
                      dnac_error_string(ret));
    }
    task->callback.completion(task->request_id, ret, task->user_data);
}

void dna_handle_dnac_validator_update(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.completion(task->request_id,
                                   DNA_ENGINE_ERROR_NOT_INITIALIZED,
                                   task->user_data);
        return;
    }
    int ret = dnac_validator_update(ctx,
        task->params.dnac_validator_update.new_commission_bps,
        task->params.dnac_validator_update.signed_at_block,
        NULL, NULL);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_validator_update failed: %d (%s)", ret,
                      dnac_error_string(ret));
    }
    task->callback.completion(task->request_id, ret, task->user_data);
}

/* Shared: convert C dnac_validator_list_entry_t[] to dna_dnac_validator_entry_t[]
 * (heap allocated; Dart side frees via dna_engine_dnac_free_validator_entries). */
static void emit_validator_list(dna_task_t *task,
                                 dnac_validator_list_entry_t *src,
                                 int count) {
    dna_dnac_validator_entry_t *result = NULL;
    if (count > 0) {
        result = calloc((size_t)count, sizeof(*result));
        if (!result) {
            task->callback.dnac_validator_list(task->request_id,
                DNA_ERROR_INTERNAL, NULL, 0, task->user_data);
            return;
        }
        for (int i = 0; i < count; i++) {
            memcpy(result[i].pubkey, src[i].pubkey, DNAC_PUBKEY_SIZE);
            result[i].self_stake         = src[i].self_stake;
            result[i].total_delegated    = src[i].total_delegated;
            result[i].commission_bps     = src[i].commission_bps;
            result[i].status             = src[i].status;
            result[i].active_since_block = src[i].active_since_block;
        }
    }
    task->callback.dnac_validator_list(task->request_id, 0, result, count,
                                        task->user_data);
}

#define VALIDATOR_LIST_MAX 512

void dna_handle_dnac_validator_list(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_validator_list(task->request_id,
            DNA_ENGINE_ERROR_NOT_INITIALIZED, NULL, 0, task->user_data);
        return;
    }
    dnac_validator_list_entry_t *buf =
        calloc(VALIDATOR_LIST_MAX, sizeof(*buf));
    if (!buf) {
        task->callback.dnac_validator_list(task->request_id,
            DNA_ERROR_INTERNAL, NULL, 0, task->user_data);
        return;
    }
    int count = 0;
    int ret = dnac_validator_list(ctx,
                                   task->params.dnac_validator_list.filter_status,
                                   buf, VALIDATOR_LIST_MAX, &count);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_DEBUG(LOG_TAG, "dnac_validator_list: %d (%s)",
                      ret, dnac_error_string(ret));
        free(buf);
        task->callback.dnac_validator_list(task->request_id, ret, NULL, 0,
                                            task->user_data);
        return;
    }
    emit_validator_list(task, buf, count);
    free(buf);
}

void dna_handle_dnac_get_committee(dna_engine_t *engine, dna_task_t *task) {
    dnac_context_t *ctx = ensure_dnac_init(engine);
    if (!ctx) {
        task->callback.dnac_validator_list(task->request_id,
            DNA_ENGINE_ERROR_NOT_INITIALIZED, NULL, 0, task->user_data);
        return;
    }
    dnac_validator_list_entry_t buf[DNAC_COMMITTEE_SIZE];
    memset(buf, 0, sizeof(buf));
    int count = 0;
    int ret = dnac_get_committee(ctx, buf, &count);
    if (ret != DNAC_SUCCESS) {
        QGP_LOG_DEBUG(LOG_TAG, "dnac_get_committee: %d (%s)",
                      ret, dnac_error_string(ret));
        task->callback.dnac_validator_list(task->request_id, ret, NULL, 0,
                                            task->user_data);
        return;
    }
    emit_validator_list(task, buf, count);
}

/* --- Public API wrappers --- */

dna_request_id_t dna_engine_dnac_stake(dna_engine_t *engine,
                                        uint16_t commission_bps,
                                        const char *unstake_destination_fp,
                                        dna_completion_cb callback,
                                        void *user_data) {
    if (!engine || !unstake_destination_fp || !callback)
        return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    params.dnac_stake.commission_bps = commission_bps;
    strncpy(params.dnac_stake.unstake_destination_fp,
            unstake_destination_fp, 128);
    params.dnac_stake.unstake_destination_fp[128] = '\0';
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_STAKE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_unstake(dna_engine_t *engine,
                                          dna_completion_cb callback,
                                          void *user_data) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_UNSTAKE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_delegate(dna_engine_t *engine,
                                           const uint8_t *validator_pubkey,
                                           uint64_t amount,
                                           dna_completion_cb callback,
                                           void *user_data) {
    if (!engine || !validator_pubkey || amount == 0 || !callback)
        return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    memcpy(params.dnac_delegate.validator_pubkey, validator_pubkey,
           DNAC_PUBKEY_SIZE);
    params.dnac_delegate.amount = amount;
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_DELEGATE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_undelegate(dna_engine_t *engine,
                                             const uint8_t *validator_pubkey,
                                             uint64_t amount,
                                             dna_completion_cb callback,
                                             void *user_data) {
    if (!engine || !validator_pubkey || amount == 0 || !callback)
        return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    memcpy(params.dnac_undelegate.validator_pubkey, validator_pubkey,
           DNAC_PUBKEY_SIZE);
    params.dnac_undelegate.amount = amount;
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_UNDELEGATE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dnac_validator_update(dna_engine_t *engine,
                                                   uint16_t new_commission_bps,
                                                   uint64_t signed_at_block,
                                                   dna_completion_cb callback,
                                                   void *user_data) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    params.dnac_validator_update.new_commission_bps = new_commission_bps;
    params.dnac_validator_update.signed_at_block = signed_at_block;
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_DNAC_VALIDATOR_UPDATE, &params, cb,
                            user_data);
}

dna_request_id_t dna_engine_dnac_validator_list(dna_engine_t *engine,
                                                 int filter_status,
                                                 dna_dnac_validator_list_cb callback,
                                                 void *user_data) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    params.dnac_validator_list.filter_status = filter_status;
    dna_task_callback_t cb = {0};
    cb.dnac_validator_list = callback;
    return dna_submit_task(engine, TASK_DNAC_VALIDATOR_LIST, &params, cb,
                            user_data);
}

dna_request_id_t dna_engine_dnac_get_committee(dna_engine_t *engine,
                                                dna_dnac_validator_list_cb callback,
                                                void *user_data) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.dnac_validator_list = callback;
    return dna_submit_task(engine, TASK_DNAC_GET_COMMITTEE, &params, cb,
                            user_data);
}
