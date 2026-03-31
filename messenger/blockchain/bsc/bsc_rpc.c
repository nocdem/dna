/**
 * @file bsc_rpc.c
 * @brief BNB Smart Chain JSON-RPC Client Implementation
 *
 * Forked from eth_rpc.c for BSC-specific RPC endpoints.
 * BSC is EVM-compatible so the JSON-RPC API is identical.
 */

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

#define LOG_TAG "BSC_RPC"

/* RPC endpoints with fallbacks */
static const char *g_bsc_rpc_endpoints[] = {
    BSC_RPC_ENDPOINT_DEFAULT,
    BSC_RPC_ENDPOINT_FALLBACK1,
    BSC_RPC_ENDPOINT_FALLBACK2,
    BSC_RPC_ENDPOINT_FALLBACK3
};

/* Current RPC endpoint */
static char g_bsc_rpc_endpoint[256] = BSC_RPC_ENDPOINT_DEFAULT;

/* Sticky endpoint index */
static int g_bsc_rpc_current_idx = 0;

/* Response buffer for curl */
struct bsc_resp_buf {
    char *data;
    size_t size;
};

static size_t bsc_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct bsc_resp_buf *buf = (struct bsc_resp_buf *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;

    buf->data = ptr;
    memcpy(&buf->data[buf->size], contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================ */

static int hex_to_uint64(const char *hex, uint64_t *value_out) {
    if (!hex || !value_out) return -1;

    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    uint64_t value = 0;
    while (*p) {
        char c = *p;
        uint8_t digit;
        if (c >= '0' && c <= '9') digit = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uint8_t)(c - 'A' + 10);
        else return -1;

        if (value > 0xFFFFFFFFFFFFFFFULL) {
            *value_out = UINT64_MAX;
            return 0;
        }
        value = (value << 4) | digit;
        p++;
    }

    *value_out = value;
    return 0;
}

/**
 * Format wei value as BNB string (18 decimals, same as ETH)
 */
static int wei_to_bnb_string(const char *wei_hex, char *out, size_t out_size) {
    if (!wei_hex || !out || out_size < 32) return -1;

    const char *p = wei_hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    if (strlen(p) == 0 || strcmp(p, "0") == 0) {
        snprintf(out, out_size, "0.0");
        return 0;
    }

    uint64_t wei;
    if (hex_to_uint64(wei_hex, &wei) != 0) {
        snprintf(out, out_size, "0.0");
        return -1;
    }

    if (wei == UINT64_MAX) {
        snprintf(out, out_size, "999999.0");
        return 0;
    }

    uint64_t whole = wei / 1000000000000000000ULL;
    uint64_t frac = wei % 1000000000000000000ULL;

    if (whole > 0) {
        uint64_t frac_display = frac / 1000000000000ULL;  /* 6 decimals */
        if (frac_display > 0) {
            snprintf(out, out_size, "%llu.%06llu",
                    (unsigned long long)whole, (unsigned long long)frac_display);
            char *dot = strchr(out, '.');
            if (dot) {
                char *end = out + strlen(out);
                while (end > dot + 1 && *(end - 1) == '0') end--;
                *end = '\0';
            }
        } else {
            snprintf(out, out_size, "%llu.0", (unsigned long long)whole);
        }
    } else {
        if (frac == 0) {
            snprintf(out, out_size, "0.0");
        } else {
            char frac_str[20];
            snprintf(frac_str, sizeof(frac_str), "%018llu", (unsigned long long)frac);
            int last_nonzero = 17;
            while (last_nonzero > 0 && frac_str[last_nonzero] == '0') last_nonzero--;
            frac_str[last_nonzero + 1] = '\0';
            snprintf(out, out_size, "0.%s", frac_str);
        }
    }

    return 0;
}

/**
 * Convert raw token amount to decimal string using token decimals.
 */
static void bsc_token_raw_to_decimal(const char *raw_str, uint8_t decimals,
                                      char *out, size_t out_size) {
    if (!raw_str || !out || out_size < 8) {
        if (out && out_size > 0) snprintf(out, out_size, "0.0");
        return;
    }

    size_t len = strlen(raw_str);
    if (len == 0 || strcmp(raw_str, "0") == 0) {
        snprintf(out, out_size, "0.0");
        return;
    }

    if (decimals == 0) {
        snprintf(out, out_size, "%s", raw_str);
        return;
    }

    if (len <= (size_t)decimals) {
        int leading_zeros = (int)decimals - (int)len;
        snprintf(out, out_size, "0.");
        size_t pos = 2;
        for (int z = 0; z < leading_zeros && pos < out_size - 1; z++) out[pos++] = '0';
        for (size_t s = 0; s < len && pos < out_size - 1; s++) out[pos++] = raw_str[s];
        out[pos] = '\0';
    } else {
        size_t whole_len = len - (size_t)decimals;
        if (whole_len + 1 + decimals + 1 > out_size) {
            snprintf(out, out_size, "999999.0");
            return;
        }
        memcpy(out, raw_str, whole_len);
        out[whole_len] = '.';
        memcpy(out + whole_len + 1, raw_str + whole_len, decimals);
        out[whole_len + 1 + decimals] = '\0';
    }

    /* Trim trailing zeros */
    char *dot = strchr(out, '.');
    if (dot) {
        char *end = out + strlen(out) - 1;
        while (end > dot + 1 && *end == '0') { *end = '\0'; end--; }
    }
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int bsc_rpc_set_endpoint(const char *endpoint) {
    if (!endpoint || strlen(endpoint) >= sizeof(g_bsc_rpc_endpoint)) return -1;
    strncpy(g_bsc_rpc_endpoint, endpoint, sizeof(g_bsc_rpc_endpoint) - 1);
    g_bsc_rpc_endpoint[sizeof(g_bsc_rpc_endpoint) - 1] = '\0';
    QGP_LOG_INFO(LOG_TAG, "BSC RPC endpoint set to: %s", g_bsc_rpc_endpoint);
    return 0;
}

const char* bsc_rpc_get_endpoint(void) {
    return g_bsc_rpc_endpoint;
}

/**
 * Try RPC call to a specific endpoint
 */
static int bsc_rpc_get_balance_single(
    const char *endpoint,
    const char *address,
    char *balance_out,
    size_t balance_size
) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    json_object *jreq = json_object_new_object();
    json_object_object_add(jreq, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(jreq, "method", json_object_new_string("eth_getBalance"));

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));
    json_object_array_add(params, json_object_new_string("latest"));
    json_object_object_add(jreq, "params", params);
    json_object_object_add(jreq, "id", json_object_new_int(1));

    const char *json_str = json_object_to_json_string(jreq);
    struct bsc_resp_buf resp = {0};

    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bsc_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jreq);

    if (res != CURLE_OK) {
        if (resp.data) free(resp.data);
        return -1;
    }

    if (!resp.data) return -1;

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) return -1;

    json_object *jerror = NULL;
    if (json_object_object_get_ex(jresp, "error", &jerror) && jerror) {
        json_object_put(jresp);
        return -2;
    }

    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult) || !jresult) {
        json_object_put(jresp);
        return -1;
    }

    const char *balance_hex = json_object_get_string(jresult);
    if (!balance_hex) {
        json_object_put(jresp);
        return -1;
    }

    int ret = wei_to_bnb_string(balance_hex, balance_out, balance_size);
    json_object_put(jresp);
    return ret;
}

int bsc_rpc_get_balance(
    const char *address,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !balance_out || balance_size < 32) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to bsc_rpc_get_balance");
        return -1;
    }

    if (!bsc_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid BSC address: %s", address);
        return -1;
    }

    int start_idx = g_bsc_rpc_current_idx;
    for (int attempt = 0; attempt < BSC_RPC_ENDPOINT_COUNT; attempt++) {
        int idx = (start_idx + attempt) % BSC_RPC_ENDPOINT_COUNT;
        const char *endpoint = g_bsc_rpc_endpoints[idx];

        QGP_LOG_INFO(LOG_TAG, "GET balance: %s -> %s", address, endpoint);

        int result = bsc_rpc_get_balance_single(endpoint, address, balance_out, balance_size);

        if (result == 0) {
            if (idx != g_bsc_rpc_current_idx) {
                g_bsc_rpc_current_idx = idx;
                QGP_LOG_INFO(LOG_TAG, "Switched to BSC RPC: %s", endpoint);
            }
            return 0;
        }

        if (result == -2) {
            QGP_LOG_ERROR(LOG_TAG, "BSC RPC error from %s", endpoint);
            return -1;
        }

        QGP_LOG_WARN(LOG_TAG, "BSC RPC failed: %s, trying next...", endpoint);
    }

    QGP_LOG_ERROR(LOG_TAG, "All BSC RPC endpoints failed");
    return -1;
}

/* ============================================================================
 * TRANSACTION HISTORY (Blockscout BSC API)
 * ============================================================================ */

int bsc_rpc_get_transactions(
    const char *address,
    bsc_transaction_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to bsc_rpc_get_transactions");
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    if (!bsc_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid BSC address: %s", address);
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url),
        "%s?module=account&action=txlist&address=%s&startblock=0&endblock=99999999&page=1&offset=50&sort=desc",
        BSC_BLOCKSCOUT_API_URL, address);

    QGP_LOG_DEBUG(LOG_TAG, "Blockscout BSC request: %s", url);

    struct bsc_resp_buf resp = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bsc_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL failed: %s", curl_easy_strerror(res));
        if (resp.data) free(resp.data);
        return -1;
    }

    if (!resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response from Blockscout BSC");
        return -1;
    }

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) return -1;

    json_object *jstatus = NULL;
    if (!json_object_object_get_ex(jresp, "status", &jstatus)) {
        json_object_put(jresp);
        return -1;
    }

    const char *status = json_object_get_string(jstatus);
    if (!status || strcmp(status, "1") != 0) {
        json_object *jmessage = NULL;
        if (json_object_object_get_ex(jresp, "message", &jmessage)) {
            const char *msg = json_object_get_string(jmessage);
            if (msg && strcmp(msg, "No transactions found") == 0) {
                json_object_put(jresp);
                return 0;
            }
        }
        json_object_put(jresp);
        return -1;
    }

    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult) ||
        !json_object_is_type(jresult, json_type_array)) {
        json_object_put(jresp);
        return -1;
    }

    int array_len = json_object_array_length(jresult);
    if (array_len == 0) {
        json_object_put(jresp);
        return 0;
    }

    bsc_transaction_t *txs = calloc(array_len, sizeof(bsc_transaction_t));
    if (!txs) {
        json_object_put(jresp);
        return -1;
    }

    int count = 0;
    for (int i = 0; i < array_len && count < array_len; i++) {
        json_object *jtx = json_object_array_get_idx(jresult, i);
        if (!jtx) continue;

        json_object *jhash = NULL, *jfrom = NULL, *jto = NULL;
        json_object *jvalue = NULL, *jtimestamp = NULL, *jstatus_tx = NULL;

        json_object_object_get_ex(jtx, "hash", &jhash);
        json_object_object_get_ex(jtx, "from", &jfrom);
        json_object_object_get_ex(jtx, "to", &jto);
        json_object_object_get_ex(jtx, "value", &jvalue);
        json_object_object_get_ex(jtx, "timeStamp", &jtimestamp);
        json_object_object_get_ex(jtx, "txreceipt_status", &jstatus_tx);

        if (jhash)
            strncpy(txs[count].tx_hash, json_object_get_string(jhash), sizeof(txs[count].tx_hash) - 1);
        if (jfrom)
            strncpy(txs[count].from, json_object_get_string(jfrom), sizeof(txs[count].from) - 1);
        if (jto)
            strncpy(txs[count].to, json_object_get_string(jto), sizeof(txs[count].to) - 1);

        if (jvalue) {
            const char *wei_str = json_object_get_string(jvalue);
            uint64_t wei = strtoull(wei_str, NULL, 10);
            char wei_hex[32];
            snprintf(wei_hex, sizeof(wei_hex), "0x%llx", (unsigned long long)wei);
            wei_to_bnb_string(wei_hex, txs[count].value, sizeof(txs[count].value));
        }

        if (jtimestamp)
            txs[count].timestamp = (uint64_t)json_object_get_int64(jtimestamp);

        if (jfrom) {
            const char *from = json_object_get_string(jfrom);
            txs[count].is_outgoing = (from && strcasecmp(from, address) == 0) ? 1 : 0;
        }

        if (jstatus_tx) {
            const char *st = json_object_get_string(jstatus_tx);
            txs[count].is_confirmed = (st && strcmp(st, "1") == 0) ? 1 : 0;
        } else {
            txs[count].is_confirmed = 1;
        }

        count++;
    }

    json_object_put(jresp);

    *txs_out = txs;
    *count_out = count;

    QGP_LOG_DEBUG(LOG_TAG, "Fetched %d BSC transactions for %s", count, address);
    return 0;
}

int bsc_rpc_get_token_transactions(
    const char *address,
    const char *contract_address,
    uint8_t token_decimals,
    bsc_transaction_t **txs_out,
    int *count_out
) {
    if (!address || !contract_address || !txs_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to bsc_rpc_get_token_transactions");
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    if (!bsc_validate_address(address)) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[640];
    snprintf(url, sizeof(url),
        "%s?module=account&action=tokentx&address=%s&contractaddress=%s"
        "&startblock=0&endblock=99999999&page=1&offset=50&sort=desc",
        BSC_BLOCKSCOUT_API_URL, address, contract_address);

    QGP_LOG_DEBUG(LOG_TAG, "Blockscout BSC token TX: %s", url);

    struct bsc_resp_buf resp = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bsc_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL failed: %s", curl_easy_strerror(res));
        if (resp.data) free(resp.data);
        return -1;
    }

    if (!resp.data) return -1;

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) return -1;

    json_object *jstatus = NULL;
    if (!json_object_object_get_ex(jresp, "status", &jstatus)) {
        json_object_put(jresp);
        return -1;
    }

    const char *status = json_object_get_string(jstatus);
    if (!status || strcmp(status, "1") != 0) {
        json_object *jmessage = NULL;
        if (json_object_object_get_ex(jresp, "message", &jmessage)) {
            const char *msg = json_object_get_string(jmessage);
            if (msg && strcmp(msg, "No transactions found") == 0) {
                json_object_put(jresp);
                return 0;
            }
        }
        json_object_put(jresp);
        return -1;
    }

    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult) ||
        !json_object_is_type(jresult, json_type_array)) {
        json_object_put(jresp);
        return -1;
    }

    int array_len = json_object_array_length(jresult);
    if (array_len == 0) {
        json_object_put(jresp);
        return 0;
    }

    bsc_transaction_t *txs = calloc(array_len, sizeof(bsc_transaction_t));
    if (!txs) {
        json_object_put(jresp);
        return -1;
    }

    int count = 0;
    for (int i = 0; i < array_len && count < array_len; i++) {
        json_object *jtx = json_object_array_get_idx(jresult, i);
        if (!jtx) continue;

        json_object *jhash = NULL, *jfrom = NULL, *jto = NULL;
        json_object *jvalue = NULL, *jtimestamp = NULL;

        json_object_object_get_ex(jtx, "hash", &jhash);
        json_object_object_get_ex(jtx, "from", &jfrom);
        json_object_object_get_ex(jtx, "to", &jto);
        json_object_object_get_ex(jtx, "value", &jvalue);
        json_object_object_get_ex(jtx, "timeStamp", &jtimestamp);

        if (jhash)
            strncpy(txs[count].tx_hash, json_object_get_string(jhash), sizeof(txs[count].tx_hash) - 1);
        if (jfrom)
            strncpy(txs[count].from, json_object_get_string(jfrom), sizeof(txs[count].from) - 1);
        if (jto)
            strncpy(txs[count].to, json_object_get_string(jto), sizeof(txs[count].to) - 1);

        if (jvalue) {
            const char *raw_amount = json_object_get_string(jvalue);
            bsc_token_raw_to_decimal(raw_amount, token_decimals,
                                     txs[count].value, sizeof(txs[count].value));
        }

        if (jtimestamp)
            txs[count].timestamp = (uint64_t)json_object_get_int64(jtimestamp);

        if (jfrom) {
            const char *from = json_object_get_string(jfrom);
            txs[count].is_outgoing = (from && strcasecmp(from, address) == 0) ? 1 : 0;
        }

        txs[count].is_confirmed = 1;
        count++;
    }

    json_object_put(jresp);

    *txs_out = txs;
    *count_out = count;

    QGP_LOG_DEBUG(LOG_TAG, "Fetched %d BSC token transactions for %s", count, address);
    return 0;
}

void bsc_rpc_free_transactions(bsc_transaction_t *txs, int count) {
    (void)count;
    if (txs) free(txs);
}
