/**
 * @file trx_chain.c
 * @brief TRON blockchain_ops_t implementation
 *
 * @author DNA Connect Team
 * @date 2025-12-14
 */

#include "../blockchain.h"
#include "trx_wallet.h"
#include "trx_tx.h"
#include "trx_trc20.h"
#include "trx_rpc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "TRX_CHAIN"
#include "crypto/utils/qgp_log.h"

/* Curl write callback for tx status queries */
struct trx_resp_buf {
    char *data;
    size_t size;
};

static size_t trx_chain_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct trx_resp_buf *buf = (struct trx_resp_buf *)userp;
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&buf->data[buf->size], contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

/* ============================================================================
 * INTERFACE IMPLEMENTATIONS
 * ============================================================================ */

static int trx_chain_init(void) {
    QGP_LOG_INFO(LOG_TAG, "TRON chain initialized");
    return 0;
}

static void trx_chain_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "TRON chain cleanup");
}

static int trx_chain_get_balance(
    const char *address,
    const char *token,
    char *balance_out,
    size_t balance_out_size
) {
    if (!address || !balance_out || balance_out_size == 0) {
        return -1;
    }

    /* Native TRX */
    if (token == NULL || strlen(token) == 0 || strcasecmp(token, "TRX") == 0) {
        return trx_rpc_get_balance(address, balance_out, balance_out_size);
    }

    /* TRC-20 token */
    if (trx_trc20_is_supported(token)) {
        return trx_trc20_get_balance_by_symbol(address, token, balance_out, balance_out_size);
    }

    QGP_LOG_ERROR(LOG_TAG, "Unsupported token: %s", token);
    return -1;
}

static int trx_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,
    uint64_t *gas_price_out
) {
    /* TRON uses bandwidth and energy model instead of gas
     * Simple TRX transfers are free if user has bandwidth
     * TRC-20 transfers require energy (or TRX burn)
     *
     * For simplicity, estimate fees in SUN:
     * - Simple transfer: ~0 TRX (free with bandwidth) or ~0.27 TRX without
     * - TRC-20 transfer: ~5-15 TRX energy cost
     */

    uint64_t base_fee;
    switch (speed) {
        case BLOCKCHAIN_FEE_SLOW:
            base_fee = 100000;   /* 0.1 TRX */
            break;
        case BLOCKCHAIN_FEE_FAST:
            base_fee = 500000;   /* 0.5 TRX */
            break;
        default:
            base_fee = 270000;   /* 0.27 TRX (bandwidth cost) */
            break;
    }

    if (fee_out) {
        *fee_out = base_fee;
    }

    if (gas_price_out) {
        *gas_price_out = 1000;  /* SUN per bandwidth point */
    }

    return 0;
}

static int trx_chain_send(
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *token,
    const uint8_t *private_key,
    size_t private_key_len,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    (void)fee_speed;  /* TRON doesn't have adjustable fees like ETH */

    if (!from_address || !to_address || !amount || !private_key || private_key_len != 32) {
        return -1;
    }

    char tx_id[65];
    int ret;

    /* Check if TRC-20 token or native TRX */
    if (token != NULL && strlen(token) > 0 && strcasecmp(token, "TRX") != 0) {
        /* TRC-20 token transfer */
        if (!trx_trc20_is_supported(token)) {
            QGP_LOG_ERROR(LOG_TAG, "Unsupported token: %s", token);
            return -1;
        }
        ret = trx_trc20_send_by_symbol(
            private_key,
            from_address,
            to_address,
            amount,
            token,
            tx_id
        );
    } else {
        /* Native TRX transfer */
        ret = trx_send_trx(
            private_key,
            from_address,
            to_address,
            amount,
            tx_id
        );
    }

    if (ret == 0 && txhash_out && txhash_out_size > 0) {
        strncpy(txhash_out, tx_id, txhash_out_size - 1);
        txhash_out[txhash_out_size - 1] = '\0';
    }

    return ret;
}

static int trx_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    if (!txhash || !status_out) return -1;

    *status_out = BLOCKCHAIN_TX_PENDING;

    const char *endpoint = trx_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "TRON RPC endpoint not configured");
        return -1;
    }

    /* Rate limit to avoid 429 errors */
    trx_rate_limit_delay();

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* TronGrid API: POST /wallet/gettransactioninfobyid */
    char url[256];
    snprintf(url, sizeof(url), "%s/wallet/gettransactioninfobyid", endpoint);

    char body[256];
    snprintf(body, sizeof(body), "{\"value\":\"%s\"}", txhash);

    struct trx_resp_buf resp = {0};
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, trx_chain_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "gettransactioninfobyid CURL failed: %s",
                      curl_easy_strerror(res));
        free(resp.data);
        return -1;
    }

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse TRON tx info response");
        return -1;
    }

    /* Empty object {} means tx not yet confirmed (pending) */
    if (json_object_object_length(jresp) == 0) {
        *status_out = BLOCKCHAIN_TX_PENDING;
        json_object_put(jresp);
        return 0;
    }

    /* Check receipt.result field */
    json_object *jreceipt;
    if (json_object_object_get_ex(jresp, "receipt", &jreceipt)) {
        json_object *jresult;
        if (json_object_object_get_ex(jreceipt, "result", &jresult)) {
            const char *result_str = json_object_get_string(jresult);
            if (result_str && strcasecmp(result_str, "SUCCESS") == 0) {
                *status_out = BLOCKCHAIN_TX_SUCCESS;
                QGP_LOG_DEBUG(LOG_TAG, "TRON tx confirmed: %s", txhash);
            } else {
                *status_out = BLOCKCHAIN_TX_FAILED;
                QGP_LOG_WARN(LOG_TAG, "TRON tx failed (%s): %s",
                             result_str ? result_str : "unknown", txhash);
            }
        } else {
            /* Receipt exists but no result field — native TRX transfer success */
            *status_out = BLOCKCHAIN_TX_SUCCESS;
            QGP_LOG_DEBUG(LOG_TAG, "TRON tx confirmed (native): %s", txhash);
        }
    } else {
        /* Has fields but no receipt — check if id exists (tx found but unconfirmed) */
        json_object *jid;
        if (json_object_object_get_ex(jresp, "id", &jid)) {
            *status_out = BLOCKCHAIN_TX_SUCCESS;
            QGP_LOG_DEBUG(LOG_TAG, "TRON tx found (no receipt): %s", txhash);
        } else {
            *status_out = BLOCKCHAIN_TX_PENDING;
        }
    }

    json_object_put(jresp);
    return 0;
}

static bool trx_chain_validate_address(const char *address) {
    return trx_validate_address(address);
}

static int trx_chain_get_transactions(
    const char *address,
    const char *token,
    blockchain_tx_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Only native TRX transactions supported for now */
    if (token != NULL && strlen(token) > 0 && strcasecmp(token, "TRX") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "TRC-20 transaction history not yet supported");
        return -1;
    }

    trx_transaction_t *trx_txs = NULL;
    int trx_count = 0;

    if (trx_rpc_get_transactions(address, &trx_txs, &trx_count) != 0) {
        return -1;
    }

    if (trx_count == 0 || !trx_txs) {
        return 0;
    }

    /* Convert to blockchain_tx_t */
    blockchain_tx_t *txs = calloc(trx_count, sizeof(blockchain_tx_t));
    if (!txs) {
        trx_rpc_free_transactions(trx_txs, trx_count);
        return -1;
    }

    for (int i = 0; i < trx_count; i++) {
        strncpy(txs[i].tx_hash, trx_txs[i].tx_hash, sizeof(txs[i].tx_hash) - 1);
        strncpy(txs[i].amount, trx_txs[i].value, sizeof(txs[i].amount) - 1);
        txs[i].token[0] = '\0';  /* Native TRX */

        /* TRON timestamps are in milliseconds */
        snprintf(txs[i].timestamp, sizeof(txs[i].timestamp),
                 "%llu", (unsigned long long)(trx_txs[i].timestamp / 1000));

        txs[i].is_outgoing = trx_txs[i].is_outgoing;

        if (trx_txs[i].is_outgoing) {
            strncpy(txs[i].other_address, trx_txs[i].to, sizeof(txs[i].other_address) - 1);
        } else {
            strncpy(txs[i].other_address, trx_txs[i].from, sizeof(txs[i].other_address) - 1);
        }

        strncpy(txs[i].status,
                trx_txs[i].is_confirmed ? "CONFIRMED" : "FAILED",
                sizeof(txs[i].status) - 1);
    }

    trx_rpc_free_transactions(trx_txs, trx_count);

    *txs_out = txs;
    *count_out = trx_count;
    return 0;
}

static void trx_chain_free_transactions(blockchain_tx_t *txs, int count) {
    (void)count;
    if (txs) {
        free(txs);
    }
}

/* ============================================================================
 * REGISTRATION
 * ============================================================================ */

static const blockchain_ops_t trx_ops = {
    .name = "tron",
    .type = BLOCKCHAIN_TYPE_TRON,
    .init = trx_chain_init,
    .cleanup = trx_chain_cleanup,
    .get_balance = trx_chain_get_balance,
    .estimate_fee = trx_chain_estimate_fee,
    .send = trx_chain_send,
    .get_tx_status = trx_chain_get_tx_status,
    .validate_address = trx_chain_validate_address,
    .get_transactions = trx_chain_get_transactions,
    .free_transactions = trx_chain_free_transactions,
    .user_data = NULL,
};

/* Auto-register on library load */
__attribute__((constructor))
static void trx_chain_register(void) {
    blockchain_register(&trx_ops);
}
