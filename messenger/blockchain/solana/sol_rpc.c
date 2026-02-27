/**
 * @file sol_rpc.c
 * @brief Solana JSON-RPC Client Implementation
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#include "sol_rpc.h"
#include "sol_wallet.h"
#include "../../crypto/utils/base58.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#else
#include <windows.h>
#endif

#define LOG_TAG "SOL_RPC"

/* Rate limiting - minimum ms between requests to avoid 429 errors */
/* Note: getTransaction is heavily rate limited on public RPC */
#define SOL_RPC_MIN_DELAY_MS 500

/* Track last request time for rate limiting */
static uint64_t g_last_request_ms = 0;

/* RPC endpoints with fallbacks (defined in sol_wallet.c) */
extern const char *g_sol_rpc_endpoints[];
extern int g_sol_rpc_current_idx;

static uint64_t get_current_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
#endif
}

void sol_rpc_rate_limit_delay(void) {
    uint64_t now = get_current_ms();
    uint64_t elapsed = now - g_last_request_ms;
    if (elapsed < SOL_RPC_MIN_DELAY_MS && g_last_request_ms > 0) {
        uint64_t delay = SOL_RPC_MIN_DELAY_MS - elapsed;
        qgp_platform_sleep_ms((unsigned int)delay);
    }
    g_last_request_ms = get_current_ms();
}

/* Response buffer */
struct response_buffer {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

/**
 * Internal: Try RPC call to a specific endpoint
 * Returns 0 on success, -1 on network error, -2 on RPC error
 */
static int sol_rpc_call_single(
    const char *endpoint,
    const char *method,
    json_object *params,
    json_object **result_out
) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    /* Build request */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "id", json_object_new_int(1));
    json_object_object_add(req, "method", json_object_new_string(method));

    if (params) {
        /* Increment ref count since we're adding to request object */
        json_object_object_add(req, "params", json_object_get(params));
    } else {
        json_object_object_add(req, "params", json_object_new_array());
    }

    const char *json_str = json_object_to_json_string(req);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(req);

    if (res != CURLE_OK) {
        if (resp_buf.data) free(resp_buf.data);
        return -1;  /* Network error - try next endpoint */
    }

    if (!resp_buf.data) {
        return -1;
    }

    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp) {
        return -1;
    }

    /* Check for RPC error */
    json_object *error_obj;
    if (json_object_object_get_ex(resp, "error", &error_obj) && error_obj) {
        json_object_put(resp);
        return -2;  /* RPC error - don't retry */
    }

    /* Extract result */
    json_object *result;
    if (!json_object_object_get_ex(resp, "result", &result)) {
        json_object_put(resp);
        return -1;
    }

    *result_out = json_object_get(result);
    json_object_put(resp);

    return 0;
}

/**
 * Make JSON-RPC call to Solana with fallback endpoints
 */
static int sol_rpc_call(
    const char *method,
    json_object *params,
    json_object **result_out
) {
    /* Rate limit to avoid 429 errors */
    sol_rpc_rate_limit_delay();

    /* Try endpoints starting from last successful one */
    int start_idx = g_sol_rpc_current_idx;
    for (int attempt = 0; attempt < SOL_RPC_MAINNET_COUNT; attempt++) {
        int idx = (start_idx + attempt) % SOL_RPC_MAINNET_COUNT;
        const char *endpoint = g_sol_rpc_endpoints[idx];

        QGP_LOG_INFO(LOG_TAG, "RPC call: %s -> %s", method, endpoint);

        int result = sol_rpc_call_single(endpoint, method, params, result_out);

        if (result == 0) {
            /* Success - remember this endpoint */
            if (idx != g_sol_rpc_current_idx) {
                g_sol_rpc_current_idx = idx;
                QGP_LOG_INFO(LOG_TAG, "Switched to RPC endpoint: %s", endpoint);
            }
            return 0;
        }

        if (result == -2) {
            /* RPC error - don't retry other endpoints */
            QGP_LOG_ERROR(LOG_TAG, "RPC error from %s", endpoint);
            return -1;
        }

        /* Network error - try next endpoint */
        QGP_LOG_WARN(LOG_TAG, "RPC endpoint failed: %s, trying next...", endpoint);
    }

    QGP_LOG_ERROR(LOG_TAG, "All SOL RPC endpoints failed");
    return -1;
}

/**
 * Make batch JSON-RPC call to Solana (multiple requests in one HTTP call)
 * This avoids rate limiting by sending all requests together
 *
 * @param methods Array of method names
 * @param params Array of params (one per method)
 * @param count Number of requests
 * @param results_out Output array of results (caller must free each with json_object_put)
 * @return 0 on success, -1 on failure
 */
static int sol_rpc_batch_call(
    const char **methods,
    json_object **params,
    int count,
    json_object **results_out
) {
    if (count == 0) return 0;

    /* Rate limit to avoid 429 errors */
    sol_rpc_rate_limit_delay();

    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL for batch call");
        return -1;
    }

    /* Build batch request as JSON array */
    json_object *batch = json_object_new_array();
    for (int i = 0; i < count; i++) {
        json_object *req = json_object_new_object();
        json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
        json_object_object_add(req, "id", json_object_new_int(i + 1));
        json_object_object_add(req, "method", json_object_new_string(methods[i]));

        if (params && params[i]) {
            /* Need to get a reference since we're adding to batch */
            json_object_object_add(req, "params", json_object_get(params[i]));
        } else {
            json_object_object_add(req, "params", json_object_new_array());
        }
        json_object_array_add(batch, req);
    }

    const char *json_str = json_object_to_json_string(batch);
    QGP_LOG_DEBUG(LOG_TAG, "Batch RPC request (%d calls)", count);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, sol_rpc_get_endpoint());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);  /* Longer timeout for batch */

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(batch);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Batch CURL failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty batch response");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Batch RPC response received (len=%zu)", resp_buf.size);

    /* Parse batch response (array of responses) */
    json_object *resp_array = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp_array || !json_object_is_type(resp_array, json_type_array)) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse batch JSON response");
        if (resp_array) json_object_put(resp_array);
        return -1;
    }

    int resp_len = json_object_array_length(resp_array);

    /* Initialize all results to NULL */
    for (int i = 0; i < count; i++) {
        results_out[i] = NULL;
    }

    /* Extract results - responses may be out of order, use id to match */
    for (int i = 0; i < resp_len; i++) {
        json_object *resp_item = json_object_array_get_idx(resp_array, i);

        json_object *id_obj;
        if (!json_object_object_get_ex(resp_item, "id", &id_obj)) continue;
        int id = json_object_get_int(id_obj) - 1;  /* Convert back to 0-indexed */
        if (id < 0 || id >= count) continue;

        /* Check for error */
        json_object *error_obj;
        if (json_object_object_get_ex(resp_item, "error", &error_obj) && error_obj) {
            json_object *msg_obj;
            if (json_object_object_get_ex(error_obj, "message", &msg_obj)) {
                QGP_LOG_DEBUG(LOG_TAG, "Batch item %d error: %s", id, json_object_get_string(msg_obj));
            }
            continue;  /* Leave result as NULL */
        }

        /* Extract result */
        json_object *result;
        if (json_object_object_get_ex(resp_item, "result", &result)) {
            results_out[id] = json_object_get(result);
        }
    }

    json_object_put(resp_array);
    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int sol_rpc_get_balance(
    const char *address,
    uint64_t *lamports_out
) {
    if (!address || !lamports_out) {
        return -1;
    }

    /* Build params: [address, {commitment: "confirmed"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getBalance", params, &result) != 0) {
        return -1;
    }

    /* Parse result: {"context": {...}, "value": <lamports>} */
    json_object *value_obj;
    if (!json_object_object_get_ex(result, "value", &value_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "No value in balance response");
        json_object_put(result);
        return -1;
    }

    *lamports_out = json_object_get_uint64(value_obj);
    json_object_put(result);

    return 0;
}

int sol_rpc_get_recent_blockhash(uint8_t blockhash_out[32]) {
    if (!blockhash_out) {
        return -1;
    }

    /* Build params with commitment */
    json_object *params = json_object_new_array();
    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getLatestBlockhash", params, &result) != 0) {
        return -1;
    }

    /* Parse result: {"context": {...}, "value": {"blockhash": "...", ...}} */
    json_object *value_obj, *blockhash_obj;
    if (!json_object_object_get_ex(result, "value", &value_obj) ||
        !json_object_object_get_ex(value_obj, "blockhash", &blockhash_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "No blockhash in response");
        json_object_put(result);
        return -1;
    }

    const char *blockhash_b58 = json_object_get_string(blockhash_obj);

    /* Decode base58 blockhash */
    size_t decoded_len = base58_decode(blockhash_b58, blockhash_out);
    json_object_put(result);

    if (decoded_len != 32) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid blockhash length: %zu", decoded_len);
        return -1;
    }

    return 0;
}

int sol_rpc_get_minimum_balance_for_rent(
    size_t data_len,
    uint64_t *lamports_out
) {
    if (!lamports_out) {
        return -1;
    }

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_uint64(data_len));

    json_object *result = NULL;
    if (sol_rpc_call("getMinimumBalanceForRentExemption", params, &result) != 0) {
        return -1;
    }

    *lamports_out = json_object_get_uint64(result);
    json_object_put(result);

    return 0;
}

int sol_rpc_send_transaction(
    const char *tx_base64,
    char *signature_out,
    size_t sig_out_size
) {
    if (!tx_base64 || !signature_out || sig_out_size == 0) {
        return -1;
    }

    /* Build params: [tx_base64, {encoding: "base64"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(tx_base64));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("base64"));
    json_object_object_add(opts, "preflightCommitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("sendTransaction", params, &result) != 0) {
        return -1;
    }

    /* Result is the transaction signature */
    const char *sig = json_object_get_string(result);
    strncpy(signature_out, sig, sig_out_size - 1);
    signature_out[sig_out_size - 1] = '\0';

    json_object_put(result);
    return 0;
}

int sol_rpc_get_transaction_status(
    const char *signature,
    bool *success_out
) {
    if (!signature || !success_out) {
        return -1;
    }

    /* Build params */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(signature));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getSignatureStatuses", params, &result) != 0) {
        return -1;
    }

    /* Parse result: {"context": {...}, "value": [status or null]} */
    json_object *value_obj;
    if (!json_object_object_get_ex(result, "value", &value_obj)) {
        json_object_put(result);
        return -1;
    }

    json_object *status = json_object_array_get_idx(value_obj, 0);
    if (!status || json_object_is_type(status, json_type_null)) {
        /* Transaction not found - still pending */
        json_object_put(result);
        return 1;
    }

    /* Check if transaction succeeded */
    json_object *err_obj;
    if (json_object_object_get_ex(status, "err", &err_obj)) {
        *success_out = json_object_is_type(err_obj, json_type_null);
    } else {
        *success_out = true;
    }

    json_object_put(result);
    return 0;
}

/**
 * Helper to extract pubkey string from account key object
 */
static const char* get_account_key_str(json_object *key_obj) {
    if (!key_obj) return NULL;

    /* Handle string format (legacy transactions) */
    if (json_object_is_type(key_obj, json_type_string)) {
        return json_object_get_string(key_obj);
    }

    /* Handle object format with pubkey field (versioned transactions) */
    if (json_object_is_type(key_obj, json_type_object)) {
        json_object *pubkey_obj;
        if (json_object_object_get_ex(key_obj, "pubkey", &pubkey_obj)) {
            return json_object_get_string(pubkey_obj);
        }
    }

    return NULL;
}

/**
 * Helper to get account key at index, considering both static and loaded addresses
 * For versioned transactions, addresses can come from:
 * - staticAccountKeys (indices 0 to N-1)
 * - loadedAddresses.writable (indices N to N+W-1)
 * - loadedAddresses.readonly (indices N+W to N+W+R-1)
 */
static const char* get_full_account_key(
    json_object *account_keys_obj,
    json_object *loaded_addresses_obj,
    int index,
    int num_static_keys
) {
    if (index < num_static_keys) {
        /* Static key */
        return get_account_key_str(json_object_array_get_idx(account_keys_obj, index));
    }

    if (!loaded_addresses_obj) {
        return NULL;
    }

    int loaded_index = index - num_static_keys;

    /* Try writable loaded addresses first */
    json_object *writable_obj;
    if (json_object_object_get_ex(loaded_addresses_obj, "writable", &writable_obj)) {
        int writable_len = json_object_array_length(writable_obj);
        if (loaded_index < writable_len) {
            return json_object_get_string(json_object_array_get_idx(writable_obj, loaded_index));
        }
        loaded_index -= writable_len;
    }

    /* Then readonly loaded addresses */
    json_object *readonly_obj;
    if (json_object_object_get_ex(loaded_addresses_obj, "readonly", &readonly_obj)) {
        int readonly_len = json_object_array_length(readonly_obj);
        if (loaded_index < readonly_len) {
            return json_object_get_string(json_object_array_get_idx(readonly_obj, loaded_index));
        }
    }

    return NULL;
}

/**
 * Parse SPL token balances to detect token transfers
 * Returns the token amount change for our address (positive = received, negative = sent)
 */
static int64_t parse_spl_token_balances(
    json_object *pre_token_balances,
    json_object *post_token_balances,
    const char *our_address,
    char *counterparty_out,
    size_t counterparty_size,
    char *mint_out,
    size_t mint_size
) {
    if (!our_address) {
        return 0;
    }

    int pre_len = pre_token_balances ? json_object_array_length(pre_token_balances) : 0;
    int post_len = post_token_balances ? json_object_array_length(post_token_balances) : 0;

    int64_t our_change = 0;
    const char *counterparty = NULL;
    const char *token_mint = NULL;

    /* First pass: find our token balance change in post balances */
    for (int i = 0; i < post_len; i++) {
        json_object *post_entry = json_object_array_get_idx(post_token_balances, i);
        json_object *owner_obj;

        if (!json_object_object_get_ex(post_entry, "owner", &owner_obj)) {
            continue;
        }
        const char *owner = json_object_get_string(owner_obj);
        if (!owner) continue;

        json_object *ui_token_amount;
        if (!json_object_object_get_ex(post_entry, "uiTokenAmount", &ui_token_amount)) {
            continue;
        }

        /* Get mint address */
        json_object *mint_obj;
        const char *mint = NULL;
        if (json_object_object_get_ex(post_entry, "mint", &mint_obj)) {
            mint = json_object_get_string(mint_obj);
        }

        /* Get account index to match with pre-balance */
        json_object *account_idx_obj;
        int account_idx = -1;
        if (json_object_object_get_ex(post_entry, "accountIndex", &account_idx_obj)) {
            account_idx = json_object_get_int(account_idx_obj);
        }

        /* Get post balance as raw amount string */
        json_object *amount_obj;
        int64_t post_amount = 0;
        if (json_object_object_get_ex(ui_token_amount, "amount", &amount_obj)) {
            post_amount = strtoll(json_object_get_string(amount_obj), NULL, 10);
        }

        /* Find corresponding pre-balance */
        int64_t pre_amount = 0;
        for (int j = 0; j < pre_len; j++) {
            json_object *pre_entry = json_object_array_get_idx(pre_token_balances, j);
            json_object *pre_idx_obj;
            if (json_object_object_get_ex(pre_entry, "accountIndex", &pre_idx_obj)) {
                if (json_object_get_int(pre_idx_obj) == account_idx) {
                    json_object *pre_ui_token_amount;
                    if (json_object_object_get_ex(pre_entry, "uiTokenAmount", &pre_ui_token_amount)) {
                        json_object *pre_amt_obj;
                        if (json_object_object_get_ex(pre_ui_token_amount, "amount", &pre_amt_obj)) {
                            pre_amount = strtoll(json_object_get_string(pre_amt_obj), NULL, 10);
                        }
                    }
                    break;
                }
            }
        }

        int64_t change = post_amount - pre_amount;

        if (strcmp(owner, our_address) == 0 && change != 0) {
            our_change = change;
            token_mint = mint;
        } else if (change != 0 && !counterparty) {
            counterparty = owner;
        }
    }

    /* Also check pre-balances for accounts that no longer exist in post */
    for (int i = 0; i < pre_len; i++) {
        json_object *pre_entry = json_object_array_get_idx(pre_token_balances, i);
        json_object *owner_obj;

        if (!json_object_object_get_ex(pre_entry, "owner", &owner_obj)) {
            continue;
        }
        const char *owner = json_object_get_string(owner_obj);
        if (!owner) continue;

        json_object *account_idx_obj;
        int account_idx = -1;
        if (json_object_object_get_ex(pre_entry, "accountIndex", &account_idx_obj)) {
            account_idx = json_object_get_int(account_idx_obj);
        }

        /* Check if this account exists in post */
        bool found_in_post = false;
        for (int j = 0; j < post_len; j++) {
            json_object *post_entry = json_object_array_get_idx(post_token_balances, j);
            json_object *post_idx_obj;
            if (json_object_object_get_ex(post_entry, "accountIndex", &post_idx_obj)) {
                if (json_object_get_int(post_idx_obj) == account_idx) {
                    found_in_post = true;
                    break;
                }
            }
        }

        if (!found_in_post) {
            /* Get mint address */
            json_object *mint_obj;
            const char *mint = NULL;
            if (json_object_object_get_ex(pre_entry, "mint", &mint_obj)) {
                mint = json_object_get_string(mint_obj);
            }

            json_object *ui_token_amount;
            if (json_object_object_get_ex(pre_entry, "uiTokenAmount", &ui_token_amount)) {
                json_object *amount_obj;
                if (json_object_object_get_ex(ui_token_amount, "amount", &amount_obj)) {
                    int64_t pre_amount = strtoll(json_object_get_string(amount_obj), NULL, 10);
                    if (strcmp(owner, our_address) == 0 && pre_amount > 0) {
                        our_change = -pre_amount;
                        token_mint = mint;
                    } else if (pre_amount > 0 && our_change > 0 && !counterparty) {
                        counterparty = owner;
                    }
                }
            }
        }
    }

    /* Set outputs */
    if (counterparty && counterparty_out && counterparty_size > 0) {
        strncpy(counterparty_out, counterparty, counterparty_size - 1);
        counterparty_out[counterparty_size - 1] = '\0';
    }
    if (token_mint && mint_out && mint_size > 0) {
        strncpy(mint_out, token_mint, mint_size - 1);
        mint_out[mint_size - 1] = '\0';
    }

    return our_change;
}

/**
 * Helper to parse transaction details from a result object
 * (can be used with either single call or batch call results)
 */
static int parse_tx_result(
    json_object *result,
    const char *our_address,
    sol_transaction_t *tx_out
) {
    if (!result || json_object_is_type(result, json_type_null)) {
        return -1;
    }

    /* Get block time */
    json_object *block_time_obj;
    if (json_object_object_get_ex(result, "blockTime", &block_time_obj) &&
        !json_object_is_type(block_time_obj, json_type_null)) {
        tx_out->block_time = json_object_get_int64(block_time_obj);
    }

    /* Get slot */
    json_object *slot_obj;
    if (json_object_object_get_ex(result, "slot", &slot_obj)) {
        tx_out->slot = json_object_get_uint64(slot_obj);
    }

    /* Parse meta for balance changes */
    json_object *meta_obj;
    if (json_object_object_get_ex(result, "meta", &meta_obj)) {
        /* Check transaction error */
        json_object *err_obj;
        if (json_object_object_get_ex(meta_obj, "err", &err_obj)) {
            tx_out->success = json_object_is_type(err_obj, json_type_null);
        }

        /* Get pre and post balances */
        json_object *pre_balances, *post_balances;
        json_object *transaction_obj, *message_obj;

        if (json_object_object_get_ex(meta_obj, "preBalances", &pre_balances) &&
            json_object_object_get_ex(meta_obj, "postBalances", &post_balances) &&
            json_object_object_get_ex(result, "transaction", &transaction_obj) &&
            json_object_object_get_ex(transaction_obj, "message", &message_obj)) {

            /* Try both accountKeys (legacy) and staticAccountKeys (versioned) */
            json_object *account_keys_obj = NULL;
            if (!json_object_object_get_ex(message_obj, "accountKeys", &account_keys_obj)) {
                json_object_object_get_ex(message_obj, "staticAccountKeys", &account_keys_obj);
            }

            /* Get loaded addresses for versioned transactions */
            json_object *loaded_addresses_obj = NULL;
            json_object_object_get_ex(meta_obj, "loadedAddresses", &loaded_addresses_obj);

            if (account_keys_obj) {
                int num_static_keys = json_object_array_length(account_keys_obj);
                int num_balances = json_object_array_length(pre_balances);

                /* Calculate total number of accounts (static + loaded) */
                int num_loaded_writable = 0, num_loaded_readonly = 0;
                if (loaded_addresses_obj) {
                    json_object *writable_obj, *readonly_obj;
                    if (json_object_object_get_ex(loaded_addresses_obj, "writable", &writable_obj)) {
                        num_loaded_writable = json_object_array_length(writable_obj);
                    }
                    if (json_object_object_get_ex(loaded_addresses_obj, "readonly", &readonly_obj)) {
                        num_loaded_readonly = json_object_array_length(readonly_obj);
                    }
                }
                int total_accounts = num_static_keys + num_loaded_writable + num_loaded_readonly;

                /* Find our address in ALL account keys (static + loaded) */
                int our_index = -1;
                for (int i = 0; i < total_accounts && i < num_balances; i++) {
                    const char *key_str = get_full_account_key(
                        account_keys_obj, loaded_addresses_obj, i, num_static_keys);
                    if (key_str && strcmp(key_str, our_address) == 0) {
                        our_index = i;
                        break;
                    }
                }

                /* Check for SPL token transfers first */
                json_object *pre_token_balances = NULL, *post_token_balances = NULL;
                json_object_object_get_ex(meta_obj, "preTokenBalances", &pre_token_balances);
                json_object_object_get_ex(meta_obj, "postTokenBalances", &post_token_balances);

                /* If we found our address and have balance data */
                if (our_index >= 0 && our_index < num_balances) {
                    int64_t pre = json_object_get_int64(
                        json_object_array_get_idx(pre_balances, our_index));
                    int64_t post = json_object_get_int64(
                        json_object_array_get_idx(post_balances, our_index));
                    int64_t diff = post - pre;

                    /* Check if this is an SPL token transfer */
                    /* Token transfers have small native SOL changes (just fees) but token balance changes */
                    char counterparty[48] = {0};
                    char mint[48] = {0};
                    int64_t token_change = parse_spl_token_balances(
                        pre_token_balances, post_token_balances,
                        our_address, counterparty, sizeof(counterparty),
                        mint, sizeof(mint));

                    if (token_change != 0) {
                        /* SPL token transfer detected */
                        tx_out->is_token_transfer = true;
                        if (mint[0]) {
                            strncpy(tx_out->token_mint, mint, sizeof(tx_out->token_mint) - 1);
                        }
                        if (token_change < 0) {
                            tx_out->lamports = (uint64_t)(-token_change);
                            tx_out->is_outgoing = true;
                            strncpy(tx_out->from, our_address, sizeof(tx_out->from) - 1);
                            if (counterparty[0]) {
                                strncpy(tx_out->to, counterparty, sizeof(tx_out->to) - 1);
                            }
                        } else {
                            tx_out->lamports = (uint64_t)token_change;
                            tx_out->is_outgoing = false;
                            strncpy(tx_out->to, our_address, sizeof(tx_out->to) - 1);
                            if (counterparty[0]) {
                                strncpy(tx_out->from, counterparty, sizeof(tx_out->from) - 1);
                            }
                        }
                    } else if (diff < 0) {
                        /* We sent (balance decreased) */
                        tx_out->lamports = (uint64_t)(-diff);
                        tx_out->is_outgoing = true;
                        strncpy(tx_out->from, our_address, sizeof(tx_out->from) - 1);

                        /* Find recipient with largest positive balance change */
                        int64_t max_received = 0;
                        int recipient_idx = -1;
                        for (int i = 0; i < num_balances && i < total_accounts; i++) {
                            if (i == our_index) continue;
                            int64_t o_pre = json_object_get_int64(
                                json_object_array_get_idx(pre_balances, i));
                            int64_t o_post = json_object_get_int64(
                                json_object_array_get_idx(post_balances, i));
                            int64_t o_diff = o_post - o_pre;
                            if (o_diff > max_received) {
                                max_received = o_diff;
                                recipient_idx = i;
                            }
                        }
                        if (recipient_idx >= 0) {
                            const char *key_str = get_full_account_key(
                                account_keys_obj, loaded_addresses_obj, recipient_idx, num_static_keys);
                            if (key_str) {
                                strncpy(tx_out->to, key_str, sizeof(tx_out->to) - 1);
                            }
                        }
                    } else if (diff > 0) {
                        /* We received (balance increased) */
                        tx_out->lamports = (uint64_t)diff;
                        tx_out->is_outgoing = false;
                        strncpy(tx_out->to, our_address, sizeof(tx_out->to) - 1);

                        /* Find sender with largest negative balance change */
                        int64_t max_sent = 0;
                        int sender_idx = -1;
                        for (int i = 0; i < num_balances && i < total_accounts; i++) {
                            if (i == our_index) continue;
                            int64_t o_pre = json_object_get_int64(
                                json_object_array_get_idx(pre_balances, i));
                            int64_t o_post = json_object_get_int64(
                                json_object_array_get_idx(post_balances, i));
                            int64_t o_diff = o_pre - o_post; /* Positive if sent */
                            if (o_diff > max_sent) {
                                max_sent = o_diff;
                                sender_idx = i;
                            }
                        }
                        if (sender_idx >= 0) {
                            const char *key_str = get_full_account_key(
                                account_keys_obj, loaded_addresses_obj, sender_idx, num_static_keys);
                            if (key_str) {
                                strncpy(tx_out->from, key_str, sizeof(tx_out->from) - 1);
                            }
                        }
                    }
                } else {
                    /* Address not found in static or loaded keys - scan all balance changes */
                    /* Find the largest positive and negative balance changes */
                    int64_t max_increase = 0, max_decrease = 0;
                    int increase_idx = -1, decrease_idx = -1;

                    for (int i = 0; i < num_balances && i < total_accounts; i++) {
                        int64_t pre = json_object_get_int64(
                            json_object_array_get_idx(pre_balances, i));
                        int64_t post = json_object_get_int64(
                            json_object_array_get_idx(post_balances, i));
                        int64_t diff = post - pre;

                        if (diff > max_increase) {
                            max_increase = diff;
                            increase_idx = i;
                        }
                        if (-diff > max_decrease) {
                            max_decrease = -diff;
                            decrease_idx = i;
                        }
                    }

                    /* Check if we're the recipient (largest increase) */
                    if (increase_idx >= 0) {
                        const char *key_str = get_full_account_key(
                            account_keys_obj, loaded_addresses_obj, increase_idx, num_static_keys);
                        if (key_str && strcmp(key_str, our_address) == 0) {
                            tx_out->lamports = (uint64_t)max_increase;
                            tx_out->is_outgoing = false;
                            strncpy(tx_out->to, our_address, sizeof(tx_out->to) - 1);
                            if (decrease_idx >= 0) {
                                const char *sender = get_full_account_key(
                                    account_keys_obj, loaded_addresses_obj, decrease_idx, num_static_keys);
                                if (sender) {
                                    strncpy(tx_out->from, sender, sizeof(tx_out->from) - 1);
                                }
                            }
                        }
                    }

                    /* Check if we're the sender (largest decrease) */
                    if (decrease_idx >= 0 && tx_out->lamports == 0) {
                        const char *key_str = get_full_account_key(
                            account_keys_obj, loaded_addresses_obj, decrease_idx, num_static_keys);
                        if (key_str && strcmp(key_str, our_address) == 0) {
                            tx_out->lamports = (uint64_t)max_decrease;
                            tx_out->is_outgoing = true;
                            strncpy(tx_out->from, our_address, sizeof(tx_out->from) - 1);
                            if (increase_idx >= 0) {
                                const char *recipient = get_full_account_key(
                                    account_keys_obj, loaded_addresses_obj, increase_idx, num_static_keys);
                                if (recipient) {
                                    strncpy(tx_out->to, recipient, sizeof(tx_out->to) - 1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/**
 * Helper to get transaction details for a single signature (makes RPC call)
 * Note: Only used as fallback; prefer batch calls for multiple transactions
 */
static int sol_rpc_get_tx_details(
    const char *signature,
    const char *our_address,
    sol_transaction_t *tx_out
) {
    /* Build params for getTransaction */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(signature));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("json"));
    json_object_object_add(opts, "maxSupportedTransactionVersion", json_object_new_int(0));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getTransaction", params, &result) != 0) {
        return -1;
    }

    int ret = parse_tx_result(result, our_address, tx_out);
    if (result) json_object_put(result);
    return ret;
}

int sol_rpc_get_transactions(
    const char *address,
    sol_transaction_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Get signatures for address */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "limit", json_object_new_int(20));
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getSignaturesForAddress", params, &result) != 0) {
        return -1;
    }

    int arr_len = json_object_array_length(result);
    if (arr_len == 0) {
        json_object_put(result);
        return 0;
    }

    /* Allocate transaction array */
    sol_transaction_t *txs = calloc(arr_len, sizeof(sol_transaction_t));
    if (!txs) {
        json_object_put(result);
        return -1;
    }

    int valid_count = 0;
    for (int i = 0; i < arr_len; i++) {
        json_object *sig_info = json_object_array_get_idx(result, i);
        json_object *sig_obj, *err_obj;

        if (!json_object_object_get_ex(sig_info, "signature", &sig_obj)) {
            continue;
        }

        const char *signature = json_object_get_string(sig_obj);
        strncpy(txs[valid_count].signature, signature,
                sizeof(txs[valid_count].signature) - 1);

        /* Check error status from signature list */
        if (json_object_object_get_ex(sig_info, "err", &err_obj)) {
            txs[valid_count].success = json_object_is_type(err_obj, json_type_null);
        } else {
            txs[valid_count].success = true;
        }

        /* Fetch full transaction details (rate limited via sol_rpc_call) */
        if (sol_rpc_get_tx_details(signature, address, &txs[valid_count]) != 0) {
            /* If we can't get details, use basic info from signature list */
            json_object *slot_obj, *time_obj;
            if (json_object_object_get_ex(sig_info, "slot", &slot_obj)) {
                txs[valid_count].slot = json_object_get_uint64(slot_obj);
            }
            if (json_object_object_get_ex(sig_info, "blockTime", &time_obj) &&
                !json_object_is_type(time_obj, json_type_null)) {
                txs[valid_count].block_time = json_object_get_int64(time_obj);
            }
            strncpy(txs[valid_count].from, address, sizeof(txs[valid_count].from) - 1);
        }

        valid_count++;
    }

    json_object_put(result);

    *txs_out = txs;
    *count_out = valid_count;

    return 0;
}

void sol_rpc_free_transactions(sol_transaction_t *txs, int count) {
    (void)count;
    if (txs) {
        free(txs);
    }
}

int sol_rpc_get_slot(uint64_t *slot_out) {
    if (!slot_out) {
        return -1;
    }

    json_object *result = NULL;
    if (sol_rpc_call("getSlot", NULL, &result) != 0) {
        return -1;
    }

    *slot_out = json_object_get_uint64(result);
    json_object_put(result);

    return 0;
}
