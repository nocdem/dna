/**
 * @file sol_spl.c
 * @brief SPL Token Implementation for Solana
 *
 * @author DNA Messenger Team
 * @date 2025-12-16
 */

#include "sol_spl.h"
#include "sol_rpc.h"
#include "sol_wallet.h"
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

#define LOG_TAG "SOL_SPL"

/* Known SPL tokens */
static const sol_spl_token_t known_tokens[] = {
    { SOL_USDT_MINT, "USDT", SOL_USDT_DECIMALS },
    { SOL_USDC_MINT, "USDC", SOL_USDC_DECIMALS },
};

#define NUM_KNOWN_TOKENS (sizeof(known_tokens) / sizeof(known_tokens[0]))

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

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

int sol_spl_get_token(const char *symbol, sol_spl_token_t *token_out) {
    if (!symbol || !token_out) {
        return -1;
    }

    for (size_t i = 0; i < NUM_KNOWN_TOKENS; i++) {
        if (strcasecmp(known_tokens[i].symbol, symbol) == 0) {
            *token_out = known_tokens[i];
            return 0;
        }
    }

    return -1;
}

bool sol_spl_is_supported(const char *symbol) {
    if (!symbol) return false;

    for (size_t i = 0; i < NUM_KNOWN_TOKENS; i++) {
        if (strcasecmp(known_tokens[i].symbol, symbol) == 0) {
            return true;
        }
    }

    return false;
}

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

int sol_spl_get_balance(
    const char *address,
    const char *mint,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !mint || !balance_out || balance_size == 0) {
        return -1;
    }

    /* Initialize with 0 balance */
    strncpy(balance_out, "0", balance_size);

    /* Check endpoint is available */
    const char *endpoint = sol_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "Solana RPC endpoint not configured");
        return -1;
    }

    /* Rate limit to avoid 429 errors */
    sol_rpc_rate_limit_delay();

    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build JSON-RPC request for getTokenAccountsByOwner */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "id", json_object_new_int(1));
    json_object_object_add(req, "method", json_object_new_string("getTokenAccountsByOwner"));

    /* Params: [address, {mint: mint_address}, {encoding: "jsonParsed"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));

    json_object *filter = json_object_new_object();
    json_object_object_add(filter, "mint", json_object_new_string(mint));
    json_object_array_add(params, filter);

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("jsonParsed"));
    json_object_array_add(params, opts);

    json_object_object_add(req, "params", params);

    const char *json_str = json_object_to_json_string(req);

    QGP_LOG_DEBUG(LOG_TAG, "SPL balance request: %s", json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* Configure SSL CA bundle (required for Android) */
    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(req);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "SPL balance response: %.500s", resp_buf.data);

    /* Parse response */
    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON response");
        return -1;
    }

    /* Check for error */
    json_object *error_obj;
    if (json_object_object_get_ex(resp, "error", &error_obj) && error_obj) {
        json_object *msg_obj;
        const char *err_msg = "Unknown error";
        if (json_object_object_get_ex(error_obj, "message", &msg_obj)) {
            err_msg = json_object_get_string(msg_obj);
        }
        QGP_LOG_ERROR(LOG_TAG, "RPC error: %s", err_msg);
        json_object_put(resp);
        return -1;
    }

    /* Extract result */
    json_object *result;
    if (!json_object_object_get_ex(resp, "result", &result)) {
        QGP_LOG_ERROR(LOG_TAG, "No result in response");
        json_object_put(resp);
        return -1;
    }

    /* Get value array */
    json_object *value_arr;
    if (!json_object_object_get_ex(result, "value", &value_arr)) {
        QGP_LOG_ERROR(LOG_TAG, "No value in result");
        json_object_put(resp);
        return -1;
    }

    /* Sum up all token account balances (usually just one) */
    uint64_t total_amount = 0;
    int arr_len = json_object_array_length(value_arr);

    for (int i = 0; i < arr_len; i++) {
        json_object *account = json_object_array_get_idx(value_arr, i);
        json_object *account_data, *parsed, *info, *token_amount, *amount_obj;

        if (json_object_object_get_ex(account, "account", &account_data) &&
            json_object_object_get_ex(account_data, "data", &parsed) &&
            json_object_object_get_ex(parsed, "parsed", &info) &&
            json_object_object_get_ex(info, "info", &token_amount) &&
            json_object_object_get_ex(token_amount, "tokenAmount", &amount_obj)) {

            json_object *amt_str;
            if (json_object_object_get_ex(amount_obj, "amount", &amt_str)) {
                const char *amount_str = json_object_get_string(amt_str);
                if (amount_str) {
                    total_amount += strtoull(amount_str, NULL, 10);
                }
            }
        }
    }

    /* Format balance with decimals */
    if (total_amount == 0) {
        snprintf(balance_out, balance_size, "0");
    } else {
        /* Calculate divisor based on decimals */
        uint64_t divisor = 1;
        for (int i = 0; i < decimals; i++) {
            divisor *= 10;
        }

        uint64_t whole = total_amount / divisor;
        uint64_t frac = total_amount % divisor;

        if (frac == 0) {
            snprintf(balance_out, balance_size, "%llu", (unsigned long long)whole);
        } else {
            /* Format with appropriate decimal places */
            char frac_str[32];
            snprintf(frac_str, sizeof(frac_str), "%0*llu", decimals, (unsigned long long)frac);

            /* Trim trailing zeros */
            int len = strlen(frac_str);
            while (len > 0 && frac_str[len - 1] == '0') {
                frac_str[--len] = '\0';
            }

            snprintf(balance_out, balance_size, "%llu.%s", (unsigned long long)whole, frac_str);
        }
    }

    json_object_put(resp);
    QGP_LOG_DEBUG(LOG_TAG, "SPL balance for %s: %s", mint, balance_out);

    return 0;
}

int sol_spl_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
) {
    sol_spl_token_t token;
    if (sol_spl_get_token(symbol, &token) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Unknown token: %s", symbol);
        return -1;
    }

    return sol_spl_get_balance(address, token.mint, token.decimals, balance_out, balance_size);
}
