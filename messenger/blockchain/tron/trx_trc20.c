/**
 * @file trx_trc20.c
 * @brief TRC-20 Token Implementation for TRON
 *
 * @author DNA Messenger Team
 * @date 2025-12-14
 */

#include "trx_trc20.h"
#include "trx_tx.h"
#include "trx_wallet.h"
#include "trx_rpc.h"
#include "../../crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "TRX_TRC20"

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

/* Known tokens on TRON mainnet */
static const trx_trc20_token_t g_known_tokens[] = {
    { TRX_USDT_CONTRACT, "USDT", TRX_USDT_DECIMALS },
    { TRX_USDC_CONTRACT, "USDC", TRX_USDC_DECIMALS },
    { TRX_USDD_CONTRACT, "USDD", TRX_USDD_DECIMALS },
    { "", "", 0 }  /* Sentinel */
};

int trx_trc20_get_token(const char *symbol, trx_trc20_token_t *token_out) {
    if (!symbol || !token_out) {
        return -1;
    }

    for (int i = 0; g_known_tokens[i].symbol[0] != '\0'; i++) {
        if (strcasecmp(symbol, g_known_tokens[i].symbol) == 0) {
            *token_out = g_known_tokens[i];
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Unknown token symbol: %s", symbol);
    return -1;
}

bool trx_trc20_is_supported(const char *symbol) {
    if (!symbol) return false;

    for (int i = 0; g_known_tokens[i].symbol[0] != '\0'; i++) {
        if (strcasecmp(symbol, g_known_tokens[i].symbol) == 0) {
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

/* Curl response buffer */
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
 * Format raw token value as decimal string
 */
static int format_token_balance(const char *raw_value, uint8_t decimals,
                                 char *out, size_t out_size) {
    if (!raw_value || !out || out_size < 32) return -1;

    /* Parse raw value as uint64 */
    uint64_t raw = strtoull(raw_value, NULL, 10);

    if (raw == 0) {
        snprintf(out, out_size, "0.0");
        return 0;
    }

    /* Calculate divisor */
    uint64_t divisor = 1;
    for (int i = 0; i < decimals; i++) {
        divisor *= 10;
    }

    uint64_t whole = raw / divisor;
    uint64_t frac = raw % divisor;

    if (frac == 0) {
        snprintf(out, out_size, "%llu.0", (unsigned long long)whole);
    } else {
        /* Format with decimal places */
        char frac_fmt[16];
        snprintf(frac_fmt, sizeof(frac_fmt), "%%0%ullu", (unsigned)decimals);

        char frac_str[32];
        snprintf(frac_str, sizeof(frac_str), frac_fmt, (unsigned long long)frac);

        /* Trim trailing zeros */
        int last = (int)strlen(frac_str) - 1;
        while (last > 0 && frac_str[last] == '0') {
            frac_str[last--] = '\0';
        }

        snprintf(out, out_size, "%llu.%s", (unsigned long long)whole, frac_str);
    }

    return 0;
}

/**
 * Parse decimal amount to raw value
 */
static int parse_token_amount(const char *amount, uint8_t decimals, char *raw_out, size_t raw_size) {
    if (!amount || !raw_out || raw_size < 32) return -1;

    double value = strtod(amount, NULL);
    if (value < 0) {
        return -1;
    }

    /* Multiply by 10^decimals */
    double multiplier = 1.0;
    for (int i = 0; i < decimals; i++) {
        multiplier *= 10.0;
    }

    uint64_t raw = (uint64_t)(value * multiplier + 0.5);  /* Round */

    snprintf(raw_out, raw_size, "%llu", (unsigned long long)raw);
    return 0;
}

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

int trx_trc20_get_balance(
    const char *address,
    const char *contract,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !contract || !balance_out || balance_size < 32) {
        return -1;
    }

    /* Validate addresses */
    if (!trx_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid address: %s", address);
        return -1;
    }

    if (!trx_validate_address(contract)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid contract: %s", contract);
        return -1;
    }

    /* Rate limit to avoid 429 errors (TronGrid: 1 req/sec) */
    trx_rate_limit_delay();

    /* Initialize curl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build TronGrid API URL for TRC-20 balances */
    char url[512];
    snprintf(url, sizeof(url), "%s/v1/accounts/%s", trx_rpc_get_endpoint(), address);

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid TRC-20 request: %s", url);

    /* Setup response buffer */
    struct response_buffer resp_buf = {0};

    /* Configure curl */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL request failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response from TronGrid");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid response: %.500s", resp_buf.data);

    /* Parse JSON response */
    json_object *jresp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse TronGrid response");
        return -1;
    }

    /* Get data array */
    json_object *jdata = NULL;
    if (!json_object_object_get_ex(jresp, "data", &jdata) ||
        !json_object_is_type(jdata, json_type_array) ||
        json_object_array_length(jdata) == 0) {
        /* Account not found or no data - balance is 0 */
        json_object_put(jresp);
        snprintf(balance_out, balance_size, "0.0");
        return 0;
    }

    json_object *jaccount = json_object_array_get_idx(jdata, 0);
    if (!jaccount) {
        json_object_put(jresp);
        snprintf(balance_out, balance_size, "0.0");
        return 0;
    }

    /* Look for trc20 array */
    json_object *jtrc20 = NULL;
    if (!json_object_object_get_ex(jaccount, "trc20", &jtrc20) ||
        !json_object_is_type(jtrc20, json_type_array)) {
        /* No TRC-20 tokens */
        json_object_put(jresp);
        snprintf(balance_out, balance_size, "0.0");
        return 0;
    }

    /* Search for our contract in trc20 array */
    int trc20_len = json_object_array_length(jtrc20);
    for (int i = 0; i < trc20_len; i++) {
        json_object *jtoken = json_object_array_get_idx(jtrc20, i);
        if (!jtoken || !json_object_is_type(jtoken, json_type_object)) {
            continue;
        }

        /* Each token is an object with contract address as key */
        json_object_object_foreach(jtoken, key, val) {
            if (strcasecmp(key, contract) == 0) {
                const char *balance_str = json_object_get_string(val);
                if (balance_str) {
                    int ret = format_token_balance(balance_str, decimals, balance_out, balance_size);
                    json_object_put(jresp);
                    QGP_LOG_DEBUG(LOG_TAG, "TRC-20 balance for %s: %s", address, balance_out);
                    return ret;
                }
            }
        }
    }

    /* Token not found in account */
    json_object_put(jresp);
    snprintf(balance_out, balance_size, "0.0");
    return 0;
}

int trx_trc20_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
) {
    trx_trc20_token_t token;
    if (trx_trc20_get_token(symbol, &token) != 0) {
        return -1;
    }

    return trx_trc20_get_balance(address, token.contract, token.decimals,
                                  balance_out, balance_size);
}

/* ============================================================================
 * TOKEN TRANSFERS
 * ============================================================================ */

int trx_trc20_send(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *contract,
    uint8_t decimals,
    char *tx_id_out
) {
    if (!private_key || !from_address || !to_address || !amount ||
        !contract || !tx_id_out) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "TRC-20 send: %s -> %s, amount=%s, contract=%s",
                 from_address, to_address, amount, contract);

    /* Parse amount to raw value */
    char amount_raw[32];
    if (parse_token_amount(amount, decimals, amount_raw, sizeof(amount_raw)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse amount: %s", amount);
        return -1;
    }

    /* Create TRC-20 transfer transaction */
    trx_tx_t tx;
    if (trx_tx_create_trc20_transfer(from_address, to_address, contract, amount_raw, &tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create TRC-20 transaction");
        return -1;
    }

    /* Sign transaction */
    trx_signed_tx_t signed_tx;
    if (trx_tx_sign(&tx, private_key, &signed_tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        return -1;
    }

    /* Broadcast transaction */
    if (trx_tx_broadcast(&signed_tx, tx_id_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to broadcast transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "TRC-20 transfer sent: %s", tx_id_out);
    return 0;
}

int trx_trc20_send_by_symbol(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *symbol,
    char *tx_id_out
) {
    trx_trc20_token_t token;
    if (trx_trc20_get_token(symbol, &token) != 0) {
        return -1;
    }

    return trx_trc20_send(private_key, from_address, to_address, amount,
                          token.contract, token.decimals, tx_id_out);
}
