/**
 * @file eth_rpc.c
 * @brief Ethereum JSON-RPC Client Implementation
 *
 * Provides balance queries via public Ethereum RPC endpoints.
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "eth_wallet.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "ETH_RPC"

/* Current RPC endpoint */
static char g_eth_rpc_endpoint[256] = ETH_RPC_ENDPOINT_DEFAULT;

/* Response buffer for curl */
struct response_buffer {
    char *data;
    size_t size;
};

/* Curl write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

/**
 * Convert hex string to uint64_t
 * Handles "0x" prefix
 */
static int hex_to_uint64(const char *hex, uint64_t *value_out) {
    if (!hex || !value_out) {
        return -1;
    }

    const char *p = hex;

    /* Skip 0x prefix */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    /* Parse hex string */
    uint64_t value = 0;
    while (*p) {
        char c = *p;
        uint8_t digit;

        if (c >= '0' && c <= '9') {
            digit = (uint8_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (uint8_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = (uint8_t)(c - 'A' + 10);
        } else {
            return -1;
        }

        /* Check for overflow */
        if (value > 0xFFFFFFFFFFFFFFFULL) {
            /* Value too large for uint64_t */
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
 * Format wei value as ETH string
 *
 * 1 ETH = 10^18 wei
 */
static int wei_to_eth_string(const char *wei_hex, char *eth_out, size_t eth_size) {
    if (!wei_hex || !eth_out || eth_size < 32) {
        return -1;
    }

    const char *p = wei_hex;

    /* Skip 0x prefix */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    /* Handle zero balance */
    if (strlen(p) == 0 || strcmp(p, "0") == 0) {
        snprintf(eth_out, eth_size, "0.0");
        return 0;
    }

    /* For very large balances, we need arbitrary precision
     * For simplicity, we'll handle up to ~18.44 ETH with uint64_t
     * and fall back to raw hex for larger amounts
     */
    uint64_t wei;
    if (hex_to_uint64(wei_hex, &wei) != 0) {
        snprintf(eth_out, eth_size, "0.0");
        return -1;
    }

    if (wei == UINT64_MAX) {
        /* Balance too large for simple conversion - use scientific notation */
        snprintf(eth_out, eth_size, "999999.0");
        return 0;
    }

    /* Convert wei to ETH: divide by 10^18 */
    /* uint64_t max is ~18.4 ETH, so this works for most cases */

    /* Split into whole ETH and fractional parts */
    uint64_t eth_whole = wei / 1000000000000000000ULL;
    uint64_t eth_frac = wei % 1000000000000000000ULL;

    if (eth_whole > 0) {
        /* Format with up to 6 decimal places */
        uint64_t frac_display = eth_frac / 1000000000000ULL;  /* Keep 6 decimals */
        if (frac_display > 0) {
            snprintf(eth_out, eth_size, "%llu.%06llu",
                    (unsigned long long)eth_whole,
                    (unsigned long long)frac_display);
            /* Trim trailing zeros */
            char *dot = strchr(eth_out, '.');
            if (dot) {
                char *end = eth_out + strlen(eth_out);
                while (end > dot + 1 && *(end - 1) == '0') {
                    end--;
                }
                *end = '\0';
            }
        } else {
            snprintf(eth_out, eth_size, "%llu.0", (unsigned long long)eth_whole);
        }
    } else {
        /* Less than 1 ETH - show more decimals */
        if (eth_frac == 0) {
            snprintf(eth_out, eth_size, "0.0");
        } else {
            /* Convert fractional part to string with leading zeros */
            char frac_str[20];
            snprintf(frac_str, sizeof(frac_str), "%018llu", (unsigned long long)eth_frac);

            /* Trim trailing zeros */
            int last_nonzero = 17;
            while (last_nonzero > 0 && frac_str[last_nonzero] == '0') {
                last_nonzero--;
            }
            frac_str[last_nonzero + 1] = '\0';

            snprintf(eth_out, eth_size, "0.%s", frac_str);
        }
    }

    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int eth_rpc_set_endpoint(const char *endpoint) {
    if (!endpoint || strlen(endpoint) >= sizeof(g_eth_rpc_endpoint)) {
        return -1;
    }

    strncpy(g_eth_rpc_endpoint, endpoint, sizeof(g_eth_rpc_endpoint) - 1);
    g_eth_rpc_endpoint[sizeof(g_eth_rpc_endpoint) - 1] = '\0';

    QGP_LOG_INFO(LOG_TAG, "RPC endpoint set to: %s", g_eth_rpc_endpoint);
    return 0;
}

const char* eth_rpc_get_endpoint(void) {
    return g_eth_rpc_endpoint;
}

int eth_rpc_get_balance(
    const char *address,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !balance_out || balance_size < 32) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to eth_rpc_get_balance");
        return -1;
    }

    /* Validate address format */
    if (!eth_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Ethereum address: %s", address);
        return -1;
    }

    /* Initialize curl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build JSON-RPC request
     * {
     *   "jsonrpc": "2.0",
     *   "method": "eth_getBalance",
     *   "params": ["0x...", "latest"],
     *   "id": 1
     * }
     */
    json_object *jreq = json_object_new_object();
    json_object_object_add(jreq, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(jreq, "method", json_object_new_string("eth_getBalance"));

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));
    json_object_array_add(params, json_object_new_string("latest"));
    json_object_object_add(jreq, "params", params);

    json_object_object_add(jreq, "id", json_object_new_int(1));

    const char *json_str = json_object_to_json_string(jreq);

    QGP_LOG_DEBUG(LOG_TAG, "RPC request: %s", json_str);

    /* Setup response buffer */
    struct response_buffer resp_buf = {0};

    /* Setup curl headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Configure curl */
    curl_easy_setopt(curl, CURLOPT_URL, g_eth_rpc_endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    /* Configure SSL CA bundle (required for Android) */
    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);

    /* Cleanup curl */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jreq);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL request failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) {
            free(resp_buf.data);
        }
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response from RPC");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "RPC response: %s", resp_buf.data);

    /* Parse JSON response */
    json_object *jresp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse RPC response");
        return -1;
    }

    /* Check for error */
    json_object *jerror = NULL;
    if (json_object_object_get_ex(jresp, "error", &jerror) && jerror) {
        json_object *jmsg = NULL;
        const char *err_msg = "Unknown error";
        if (json_object_object_get_ex(jerror, "message", &jmsg)) {
            err_msg = json_object_get_string(jmsg);
        }
        QGP_LOG_ERROR(LOG_TAG, "RPC error: %s", err_msg);
        json_object_put(jresp);
        return -1;
    }

    /* Extract result (balance in hex wei) */
    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult) || !jresult) {
        QGP_LOG_ERROR(LOG_TAG, "No result in RPC response");
        json_object_put(jresp);
        return -1;
    }

    const char *balance_hex = json_object_get_string(jresult);
    if (!balance_hex) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid balance result");
        json_object_put(jresp);
        return -1;
    }

    /* Convert wei (hex) to ETH string */
    int ret = wei_to_eth_string(balance_hex, balance_out, balance_size);

    json_object_put(jresp);

    if (ret == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "Balance for %s: %s", address, balance_out);
    }

    return ret;
}

/* Blockscout API endpoint (free, no API key required) */
#define BLOCKSCOUT_API_URL "https://eth.blockscout.com/api"

int eth_rpc_get_transactions(
    const char *address,
    eth_transaction_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to eth_rpc_get_transactions");
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Validate address format */
    if (!eth_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Ethereum address: %s", address);
        return -1;
    }

    /* Initialize curl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build Blockscout API URL */
    char url[512];
    snprintf(url, sizeof(url),
        "%s?module=account&action=txlist&address=%s&startblock=0&endblock=99999999&page=1&offset=50&sort=desc",
        BLOCKSCOUT_API_URL, address);

    QGP_LOG_DEBUG(LOG_TAG, "Blockscout request: %s", url);

    /* Setup response buffer */
    struct response_buffer resp_buf = {0};

    /* Configure curl */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    /* Configure SSL CA bundle (required for Android) */
    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL request failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response from Blockscout");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Blockscout response length: %zu", resp_buf.size);

    /* Parse JSON response */
    json_object *jresp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse Blockscout response");
        return -1;
    }

    /* Check status */
    json_object *jstatus = NULL;
    if (!json_object_object_get_ex(jresp, "status", &jstatus)) {
        QGP_LOG_ERROR(LOG_TAG, "No status in Blockscout response");
        json_object_put(jresp);
        return -1;
    }

    const char *status = json_object_get_string(jstatus);
    if (!status || strcmp(status, "1") != 0) {
        /* Status 0 could mean no transactions (not an error) */
        json_object *jmessage = NULL;
        if (json_object_object_get_ex(jresp, "message", &jmessage)) {
            const char *msg = json_object_get_string(jmessage);
            if (msg && strcmp(msg, "No transactions found") == 0) {
                json_object_put(jresp);
                return 0;  /* Empty but success */
            }
        }
        QGP_LOG_ERROR(LOG_TAG, "Blockscout API error");
        json_object_put(jresp);
        return -1;
    }

    /* Get result array */
    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult) ||
        !json_object_is_type(jresult, json_type_array)) {
        QGP_LOG_ERROR(LOG_TAG, "No result array in Blockscout response");
        json_object_put(jresp);
        return -1;
    }

    int array_len = json_object_array_length(jresult);
    if (array_len == 0) {
        json_object_put(jresp);
        return 0;  /* Empty but success */
    }

    /* Allocate transactions array */
    eth_transaction_t *txs = calloc(array_len, sizeof(eth_transaction_t));
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

        /* Copy hash */
        if (jhash) {
            strncpy(txs[count].tx_hash, json_object_get_string(jhash),
                    sizeof(txs[count].tx_hash) - 1);
        }

        /* Copy from */
        if (jfrom) {
            strncpy(txs[count].from, json_object_get_string(jfrom),
                    sizeof(txs[count].from) - 1);
        }

        /* Copy to */
        if (jto) {
            strncpy(txs[count].to, json_object_get_string(jto),
                    sizeof(txs[count].to) - 1);
        }

        /* Convert value (wei) to ETH */
        if (jvalue) {
            const char *wei_str = json_object_get_string(jvalue);
            /* Etherscan returns decimal wei, convert to hex for our converter */
            uint64_t wei = strtoull(wei_str, NULL, 10);
            char wei_hex[32];
            snprintf(wei_hex, sizeof(wei_hex), "0x%llx", (unsigned long long)wei);
            wei_to_eth_string(wei_hex, txs[count].value, sizeof(txs[count].value));
            /* Remove " ETH" suffix for raw value */
            char *eth_suffix = strstr(txs[count].value, " ETH");
            if (eth_suffix) *eth_suffix = '\0';
        }

        /* Copy timestamp */
        if (jtimestamp) {
            txs[count].timestamp = (uint64_t)json_object_get_int64(jtimestamp);
        }

        /* Determine direction */
        if (jfrom && jto) {
            const char *from = json_object_get_string(jfrom);
            /* Case-insensitive compare for addresses */
            if (from && strcasecmp(from, address) == 0) {
                txs[count].is_outgoing = 1;
            } else {
                txs[count].is_outgoing = 0;
            }
        }

        /* Status: 1 = success, 0 = failed */
        if (jstatus_tx) {
            const char *st = json_object_get_string(jstatus_tx);
            txs[count].is_confirmed = (st && strcmp(st, "1") == 0) ? 1 : 0;
        } else {
            txs[count].is_confirmed = 1;  /* Assume confirmed if no status */
        }

        count++;
    }

    json_object_put(jresp);

    *txs_out = txs;
    *count_out = count;

    QGP_LOG_DEBUG(LOG_TAG, "Fetched %d transactions for %s", count, address);
    return 0;
}

void eth_rpc_free_transactions(eth_transaction_t *txs, int count) {
    if (txs) {
        free(txs);
    }
}
