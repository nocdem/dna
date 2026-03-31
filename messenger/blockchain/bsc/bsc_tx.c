/**
 * @file bsc_tx.c
 * @brief BNB Smart Chain Transaction Implementation
 *
 * BSC-specific RPC calls (nonce, gas price, broadcast) using BSC endpoints.
 * Signing reuses eth_tx_sign with chain_id=56.
 */

#include "bsc_tx.h"
#include "bsc_rpc.h"
#include "bsc_wallet.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "BSC_TX"

/* Curl response buffer */
struct bsc_tx_resp {
    char *data;
    size_t size;
};

static size_t bsc_tx_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct bsc_tx_resp *buf = (struct bsc_tx_resp *)userp;
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&buf->data[buf->size], contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

/* BSC RPC endpoints (same list as bsc_rpc.c) */
static const char *g_bsc_tx_endpoints[] = {
    BSC_RPC_ENDPOINT_DEFAULT,
    BSC_RPC_ENDPOINT_FALLBACK1,
    BSC_RPC_ENDPOINT_FALLBACK2,
    BSC_RPC_ENDPOINT_FALLBACK3
};
static int g_bsc_tx_current_idx = 0;

static int hex_to_u64(const char *hex, uint64_t *out) {
    if (!hex || !out) return -1;
    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    uint64_t val = 0;
    while (*p) {
        char c = *p++;
        uint8_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        val = (val << 4) | d;
    }
    *out = val;
    return 0;
}

/**
 * Make JSON-RPC call to a single BSC endpoint
 */
static int bsc_rpc_call_single(const char *endpoint, const char *method,
                                json_object *params, json_object **result_out) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "method", json_object_new_string(method));
    json_object_object_add(req, "params", json_object_get(params));
    json_object_object_add(req, "id", json_object_new_int(1));

    const char *json_str = json_object_to_json_string(req);

    struct bsc_tx_resp resp = {0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bsc_tx_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(req);

    if (res != CURLE_OK) {
        if (resp.data) free(resp.data);
        return -1;
    }

    if (!resp.data) return -1;

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) return -1;

    json_object *jerr = NULL;
    if (json_object_object_get_ex(jresp, "error", &jerr) && jerr) {
        json_object *jmsg = NULL;
        const char *msg = "Unknown error";
        if (json_object_object_get_ex(jerr, "message", &jmsg))
            msg = json_object_get_string(jmsg);
        QGP_LOG_ERROR(LOG_TAG, "BSC RPC error from %s: %s", endpoint, msg);
        json_object_put(jresp);
        return -2;
    }

    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult)) {
        json_object_put(jresp);
        return -1;
    }

    *result_out = json_object_get(jresult);
    json_object_put(jresp);
    return 0;
}

/**
 * Make JSON-RPC call with fallback across BSC endpoints
 */
static int bsc_rpc_call(const char *method, json_object *params, json_object **result_out) {
    int start_idx = g_bsc_tx_current_idx;
    int ret = -1;

    for (int attempt = 0; attempt < BSC_RPC_ENDPOINT_COUNT; attempt++) {
        int idx = (start_idx + attempt) % BSC_RPC_ENDPOINT_COUNT;
        const char *endpoint = g_bsc_tx_endpoints[idx];

        int rc = bsc_rpc_call_single(endpoint, method, params, result_out);

        if (rc == 0) {
            if (idx != g_bsc_tx_current_idx) {
                g_bsc_tx_current_idx = idx;
                QGP_LOG_INFO(LOG_TAG, "Switched to BSC RPC: %s", endpoint);
            }
            ret = 0;
            goto done;
        }

        if (rc == -2) goto done;

        QGP_LOG_WARN(LOG_TAG, "BSC RPC failed: %s, trying next...", endpoint);
    }

    QGP_LOG_ERROR(LOG_TAG, "All BSC RPC endpoints failed for %s", method);

done:
    json_object_put(params);
    return ret;
}

/* ============================================================================
 * RPC QUERIES
 * ============================================================================ */

int bsc_tx_get_nonce(const char *address, uint64_t *nonce_out) {
    if (!address || !nonce_out) return -1;

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));
    json_object_array_add(params, json_object_new_string("pending"));

    json_object *result = NULL;
    if (bsc_rpc_call("eth_getTransactionCount", params, &result) != 0) return -1;

    const char *hex = json_object_get_string(result);
    int ret = hex_to_u64(hex, nonce_out);
    json_object_put(result);

    QGP_LOG_DEBUG(LOG_TAG, "BSC nonce for %s: %llu", address, (unsigned long long)*nonce_out);
    return ret;
}

int bsc_tx_get_gas_price(uint64_t *gas_price_out) {
    if (!gas_price_out) return -1;

    json_object *params = json_object_new_array();

    json_object *result = NULL;
    if (bsc_rpc_call("eth_gasPrice", params, &result) != 0) return -1;

    const char *hex = json_object_get_string(result);
    int ret = hex_to_u64(hex, gas_price_out);
    json_object_put(result);

    QGP_LOG_DEBUG(LOG_TAG, "BSC gas price: %llu wei", (unsigned long long)*gas_price_out);
    return ret;
}

int bsc_tx_send(const eth_signed_tx_t *signed_tx, char *tx_hash_out) {
    if (!signed_tx || !tx_hash_out) return -1;

    char *hex_tx = malloc(signed_tx->raw_tx_len * 2 + 3);
    if (!hex_tx) return -1;

    hex_tx[0] = '0';
    hex_tx[1] = 'x';
    for (size_t i = 0; i < signed_tx->raw_tx_len; i++) {
        snprintf(hex_tx + 2 + i * 2, 3, "%02x", signed_tx->raw_tx[i]);
    }

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(hex_tx));

    json_object *result = NULL;
    int ret = bsc_rpc_call("eth_sendRawTransaction", params, &result);

    free(hex_tx);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "BSC eth_sendRawTransaction failed");
        return -1;
    }

    const char *hash = json_object_get_string(result);
    if (hash) {
        strncpy(tx_hash_out, hash, 66);
        tx_hash_out[66] = '\0';
    } else {
        strcpy(tx_hash_out, signed_tx->tx_hash);
    }

    json_object_put(result);
    QGP_LOG_INFO(LOG_TAG, "BSC transaction sent: %s", tx_hash_out);
    return 0;
}

/* ============================================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================================ */

/* Gas speed multipliers (in percent) */
static const int BSC_GAS_MULTIPLIERS[] = {
    100,    /* BSC_GAS_SLOW: 1.0x */
    110,    /* BSC_GAS_NORMAL: 1.1x */
    150     /* BSC_GAS_FAST: 1.5x */
};

int bsc_send_bnb_with_gas(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount_bnb,
    int gas_speed,
    char *tx_hash_out
) {
    QGP_LOG_INFO(LOG_TAG, ">>> bsc_send_bnb_with_gas: from=%s to=%s amount=%s speed=%d",
                 from_address ? from_address : "NULL",
                 to_address ? to_address : "NULL",
                 amount_bnb ? amount_bnb : "NULL",
                 gas_speed);

    if (!private_key || !from_address || !to_address || !amount_bnb || !tx_hash_out) {
        return -1;
    }

    if (gas_speed < 0 || gas_speed > 2) gas_speed = BSC_GAS_NORMAL;

    /* Get nonce */
    uint64_t nonce;
    if (bsc_tx_get_nonce(from_address, &nonce) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get BSC nonce");
        return -1;
    }

    /* Get gas price */
    uint64_t gas_price;
    if (bsc_tx_get_gas_price(&gas_price) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get BSC gas price");
        return -1;
    }

    gas_price = (gas_price * BSC_GAS_MULTIPLIERS[gas_speed]) / 100;

    /* Parse recipient address */
    uint8_t to[20];
    if (eth_parse_address(to_address, to) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid BSC recipient address");
        return -1;
    }

    /* Parse amount (BNB has 18 decimals, same as ETH) */
    uint8_t value[32];
    if (eth_parse_amount(amount_bnb, value) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid BNB amount: %s", amount_bnb);
        return -1;
    }

    /* Build transaction with BSC chain_id=56 */
    eth_tx_t tx;
    eth_tx_init_transfer(&tx, nonce, gas_price, to, value, BSC_CHAIN_MAINNET);
    tx.gas_limit = BSC_GAS_LIMIT_TRANSFER;

    /* Sign (eth_tx_sign is chain-agnostic, uses tx.chain_id) */
    eth_signed_tx_t signed_tx;
    if (eth_tx_sign(&tx, private_key, &signed_tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign BSC transaction");
        return -1;
    }

    /* Send via BSC RPC */
    if (bsc_tx_send(&signed_tx, tx_hash_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send BSC transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "<<< bsc_send_bnb_with_gas SUCCESS: %s", tx_hash_out);
    return 0;
}
