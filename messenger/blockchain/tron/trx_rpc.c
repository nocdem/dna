/**
 * @file trx_rpc.c
 * @brief TRON RPC Client Implementation (TronGrid API)
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#include "trx_rpc.h"
#include "trx_wallet.h"
#include "../../crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "TRX_RPC"

/* TRX decimal places (1 TRX = 1,000,000 SUN) */
#define TRX_DECIMALS 6
#define SUN_PER_TRX 1000000ULL

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
 * Format SUN value as TRX string
 */
static int sun_to_trx_string(uint64_t sun, char *trx_out, size_t trx_size) {
    if (!trx_out || trx_size < 32) {
        return -1;
    }

    if (sun == 0) {
        snprintf(trx_out, trx_size, "0.0 TRX");
        return 0;
    }

    uint64_t trx_whole = sun / SUN_PER_TRX;
    uint64_t trx_frac = sun % SUN_PER_TRX;

    if (trx_frac == 0) {
        snprintf(trx_out, trx_size, "%llu.0 TRX", (unsigned long long)trx_whole);
    } else {
        /* Format with up to 6 decimal places, trim trailing zeros */
        char frac_str[8];
        snprintf(frac_str, sizeof(frac_str), "%06llu", (unsigned long long)trx_frac);

        /* Trim trailing zeros */
        int last_nonzero = 5;
        while (last_nonzero > 0 && frac_str[last_nonzero] == '0') {
            last_nonzero--;
        }
        frac_str[last_nonzero + 1] = '\0';

        snprintf(trx_out, trx_size, "%llu.%s TRX", (unsigned long long)trx_whole, frac_str);
    }

    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int trx_rpc_get_balance_sun(
    const char *address,
    uint64_t *sun_out
) {
    if (!address || !sun_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to trx_rpc_get_balance_sun");
        return -1;
    }

    *sun_out = 0;

    /* Validate address format */
    if (!trx_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid TRON address: %s", address);
        return -1;
    }

    /* Initialize curl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build TronGrid API URL */
    char url[256];
    snprintf(url, sizeof(url), "%s/v1/accounts/%s", trx_rpc_get_endpoint(), address);

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid request: %s", url);

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

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid response: %.200s...", resp_buf.data);

    /* Parse JSON response */
    json_object *jresp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse TronGrid response");
        return -1;
    }

    /* Check for success field */
    json_object *jsuccess = NULL;
    if (json_object_object_get_ex(jresp, "success", &jsuccess)) {
        if (!json_object_get_boolean(jsuccess)) {
            QGP_LOG_ERROR(LOG_TAG, "TronGrid API returned success=false");
            json_object_put(jresp);
            return -1;
        }
    }

    /* Get data array */
    json_object *jdata = NULL;
    if (!json_object_object_get_ex(jresp, "data", &jdata) ||
        !json_object_is_type(jdata, json_type_array)) {
        /* No data means account doesn't exist (0 balance) */
        QGP_LOG_DEBUG(LOG_TAG, "Account not found, balance is 0");
        json_object_put(jresp);
        *sun_out = 0;
        return 0;
    }

    /* Get first account in array */
    if (json_object_array_length(jdata) == 0) {
        json_object_put(jresp);
        *sun_out = 0;
        return 0;
    }

    json_object *jaccount = json_object_array_get_idx(jdata, 0);
    if (!jaccount) {
        json_object_put(jresp);
        *sun_out = 0;
        return 0;
    }

    /* Get balance field */
    json_object *jbalance = NULL;
    if (!json_object_object_get_ex(jaccount, "balance", &jbalance)) {
        /* No balance field means 0 */
        json_object_put(jresp);
        *sun_out = 0;
        return 0;
    }

    *sun_out = (uint64_t)json_object_get_int64(jbalance);

    json_object_put(jresp);

    QGP_LOG_DEBUG(LOG_TAG, "Balance for %s: %llu SUN", address, (unsigned long long)*sun_out);
    return 0;
}

int trx_rpc_get_balance(
    const char *address,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !balance_out || balance_size < 32) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to trx_rpc_get_balance");
        return -1;
    }

    uint64_t sun;
    if (trx_rpc_get_balance_sun(address, &sun) != 0) {
        return -1;
    }

    return sun_to_trx_string(sun, balance_out, balance_size);
}

int trx_rpc_get_transactions(
    const char *address,
    trx_transaction_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to trx_rpc_get_transactions");
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Validate address format */
    if (!trx_validate_address(address)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid TRON address: %s", address);
        return -1;
    }

    /* Initialize curl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build TronGrid API URL for transactions */
    char url[512];
    snprintf(url, sizeof(url),
        "%s/v1/accounts/%s/transactions?only_confirmed=true&limit=50",
        trx_rpc_get_endpoint(), address);

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid transactions request: %s", url);

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

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid transactions response length: %zu", resp_buf.size);

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
        !json_object_is_type(jdata, json_type_array)) {
        /* No data means no transactions */
        json_object_put(jresp);
        return 0;
    }

    int array_len = json_object_array_length(jdata);
    if (array_len == 0) {
        json_object_put(jresp);
        return 0;
    }

    /* Allocate transactions array */
    trx_transaction_t *txs = calloc(array_len, sizeof(trx_transaction_t));
    if (!txs) {
        json_object_put(jresp);
        return -1;
    }

    int count = 0;
    for (int i = 0; i < array_len && count < array_len; i++) {
        json_object *jtx = json_object_array_get_idx(jdata, i);
        if (!jtx) continue;

        /* Get txID */
        json_object *jtxid = NULL;
        if (json_object_object_get_ex(jtx, "txID", &jtxid)) {
            strncpy(txs[count].tx_hash, json_object_get_string(jtxid),
                    sizeof(txs[count].tx_hash) - 1);
        }

        /* Get raw_data for contract info */
        json_object *jraw_data = NULL;
        if (json_object_object_get_ex(jtx, "raw_data", &jraw_data)) {
            /* Get timestamp */
            json_object *jtimestamp = NULL;
            if (json_object_object_get_ex(jraw_data, "timestamp", &jtimestamp)) {
                txs[count].timestamp = (uint64_t)json_object_get_int64(jtimestamp);
            }

            /* Get contract */
            json_object *jcontract = NULL;
            if (json_object_object_get_ex(jraw_data, "contract", &jcontract) &&
                json_object_is_type(jcontract, json_type_array) &&
                json_object_array_length(jcontract) > 0) {

                json_object *jcontract0 = json_object_array_get_idx(jcontract, 0);
                json_object *jparam = NULL;

                if (jcontract0 && json_object_object_get_ex(jcontract0, "parameter", &jparam)) {
                    json_object *jvalue = NULL;
                    if (json_object_object_get_ex(jparam, "value", &jvalue)) {
                        /* Get owner_address (from) */
                        json_object *jowner = NULL;
                        if (json_object_object_get_ex(jvalue, "owner_address", &jowner)) {
                            strncpy(txs[count].from, json_object_get_string(jowner),
                                    sizeof(txs[count].from) - 1);
                        }

                        /* Get to_address */
                        json_object *jto = NULL;
                        if (json_object_object_get_ex(jvalue, "to_address", &jto)) {
                            strncpy(txs[count].to, json_object_get_string(jto),
                                    sizeof(txs[count].to) - 1);
                        }

                        /* Get amount */
                        json_object *jamount = NULL;
                        if (json_object_object_get_ex(jvalue, "amount", &jamount)) {
                            uint64_t sun = (uint64_t)json_object_get_int64(jamount);
                            /* Convert to TRX */
                            double trx = (double)sun / SUN_PER_TRX;
                            snprintf(txs[count].value, sizeof(txs[count].value),
                                    "%.6f", trx);
                            /* Trim trailing zeros */
                            char *dot = strchr(txs[count].value, '.');
                            if (dot) {
                                char *end = txs[count].value + strlen(txs[count].value) - 1;
                                while (end > dot && *end == '0') {
                                    *end-- = '\0';
                                }
                                if (end == dot) {
                                    strcpy(dot, ".0");
                                }
                            }
                        }
                    }
                }
            }
        }

        /* Determine direction - compare with input address */
        if (strcasecmp(txs[count].from, address) == 0) {
            txs[count].is_outgoing = 1;
        } else {
            txs[count].is_outgoing = 0;
        }

        /* Check ret for confirmation status */
        json_object *jret = NULL;
        if (json_object_object_get_ex(jtx, "ret", &jret) &&
            json_object_is_type(jret, json_type_array) &&
            json_object_array_length(jret) > 0) {
            json_object *jret0 = json_object_array_get_idx(jret, 0);
            json_object *jcode = NULL;
            if (jret0 && json_object_object_get_ex(jret0, "contractRet", &jcode)) {
                const char *code = json_object_get_string(jcode);
                txs[count].is_confirmed = (code && strcmp(code, "SUCCESS") == 0) ? 1 : 0;
            }
        } else {
            txs[count].is_confirmed = 1;  /* Assume confirmed if no ret */
        }

        count++;
    }

    json_object_put(jresp);

    *txs_out = txs;
    *count_out = count;

    QGP_LOG_DEBUG(LOG_TAG, "Fetched %d transactions for %s", count, address);
    return 0;
}

void trx_rpc_free_transactions(trx_transaction_t *txs, int count) {
    (void)count;  /* Unused - simple array allocation */
    if (txs) {
        free(txs);
    }
}
