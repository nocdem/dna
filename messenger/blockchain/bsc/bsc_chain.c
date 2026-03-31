/**
 * @file bsc_chain.c
 * @brief BNB Smart Chain blockchain_ops_t implementation
 *
 * Registers BSC as a blockchain in the registry system.
 * Forked from eth_chain.c for BSC-specific endpoints and chain_id.
 */

#include "../blockchain.h"
#include "bsc_tx.h"
#include "bsc_wallet.h"
#include "bsc_rpc.h"
#include "bsc_bep20.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "BSC_CHAIN"
#include "crypto/utils/qgp_log.h"

/* Curl write callback for tx status queries */
struct bsc_chain_resp {
    char *data;
    size_t size;
};

static size_t bsc_chain_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct bsc_chain_resp *buf = (struct bsc_chain_resp *)userp;
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

static int bsc_chain_init(void) {
    QGP_LOG_INFO(LOG_TAG, "BSC chain initialized");
    return 0;
}

static void bsc_chain_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "BSC chain cleanup");
}

static int bsc_chain_get_balance(
    const char *address,
    const char *token,
    char *balance_out,
    size_t balance_out_size
) {
    if (!address || !balance_out || balance_out_size == 0) return -1;

    /* Native BNB */
    if (token == NULL || strlen(token) == 0 || strcasecmp(token, "BNB") == 0) {
        return bsc_rpc_get_balance(address, balance_out, balance_out_size);
    }

    /* BEP-20 token */
    if (bsc_bep20_is_supported(token)) {
        return bsc_bep20_get_balance_by_symbol(address, token, balance_out, balance_out_size);
    }

    QGP_LOG_ERROR(LOG_TAG, "Unsupported BSC token: %s", token);
    return -1;
}

static int bsc_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,
    uint64_t *gas_price_out
) {
    uint64_t gas_price;
    if (bsc_tx_get_gas_price(&gas_price) != 0) return -1;

    switch (speed) {
        case BLOCKCHAIN_FEE_SLOW:
            gas_price = (gas_price * 100) / 100;  /* 1.0x */
            break;
        case BLOCKCHAIN_FEE_FAST:
            gas_price = (gas_price * 150) / 100;  /* 1.5x */
            break;
        default:
            gas_price = (gas_price * 110) / 100;  /* 1.1x */
            break;
    }

    if (gas_price_out) *gas_price_out = gas_price;
    if (fee_out) *fee_out = gas_price * BSC_GAS_LIMIT_TRANSFER;
    return 0;
}

static int bsc_chain_send(
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
    if (!from_address || !to_address || !amount || !private_key || private_key_len != 32)
        return -1;

    int gas_speed;
    switch (fee_speed) {
        case BLOCKCHAIN_FEE_SLOW: gas_speed = BSC_GAS_SLOW; break;
        case BLOCKCHAIN_FEE_FAST: gas_speed = BSC_GAS_FAST; break;
        default: gas_speed = BSC_GAS_NORMAL; break;
    }

    char tx_hash[67];
    int ret;

    if (token != NULL && strlen(token) > 0 && strcasecmp(token, "BNB") != 0) {
        /* BEP-20 token transfer */
        if (!bsc_bep20_is_supported(token)) {
            QGP_LOG_ERROR(LOG_TAG, "Unsupported BSC token: %s", token);
            return -1;
        }
        ret = bsc_bep20_send_by_symbol(
            private_key, from_address, to_address, amount, token, gas_speed, tx_hash
        );
    } else {
        /* Native BNB transfer */
        ret = bsc_send_bnb_with_gas(
            private_key, from_address, to_address, amount, gas_speed, tx_hash
        );
    }

    if (ret == 0 && txhash_out && txhash_out_size > 0) {
        strncpy(txhash_out, tx_hash, txhash_out_size - 1);
        txhash_out[txhash_out_size - 1] = '\0';
    }
    return ret;
}

static int bsc_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    if (!txhash || !status_out) return -1;

    *status_out = BLOCKCHAIN_TX_PENDING;

    const char *endpoint = bsc_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "BSC RPC endpoint not configured");
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char body[512];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\","
        "\"params\":[\"%s\"],\"id\":1}", txhash);

    struct bsc_chain_resp resp = {0};
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bsc_chain_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "BSC getTransactionReceipt failed");
        free(resp.data);
        return -1;
    }

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) return -1;

    json_object *jresult;
    if (!json_object_object_get_ex(jresp, "result", &jresult) ||
        json_object_is_type(jresult, json_type_null)) {
        *status_out = BLOCKCHAIN_TX_PENDING;
        json_object_put(jresp);
        return 0;
    }

    json_object *jstatus;
    if (json_object_object_get_ex(jresult, "status", &jstatus)) {
        const char *st = json_object_get_string(jstatus);
        if (st && strcmp(st, "0x1") == 0) {
            *status_out = BLOCKCHAIN_TX_SUCCESS;
        } else {
            *status_out = BLOCKCHAIN_TX_FAILED;
        }
    } else {
        *status_out = BLOCKCHAIN_TX_SUCCESS;
    }

    json_object_put(jresp);
    return 0;
}

static bool bsc_chain_validate_address(const char *address) {
    return bsc_validate_address(address);
}

static int bsc_chain_get_transactions(
    const char *address,
    const char *token,
    blockchain_tx_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) return -1;

    *txs_out = NULL;
    *count_out = 0;

    bsc_transaction_t *bsc_txs = NULL;
    int bsc_count = 0;

    if (token != NULL && strlen(token) > 0) {
        /* BEP-20 token tx history */
        bsc_bep20_token_t bep20;
        if (bsc_bep20_get_token(token, &bep20) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Unknown BEP-20 token: %s", token);
            return -1;
        }
        if (bsc_rpc_get_token_transactions(address, bep20.contract,
                                            bep20.decimals,
                                            &bsc_txs, &bsc_count) != 0) {
            return -1;
        }
    } else {
        /* Native BNB tx history */
        if (bsc_rpc_get_transactions(address, &bsc_txs, &bsc_count) != 0) {
            return -1;
        }
    }

    if (bsc_count == 0 || !bsc_txs) return 0;

    blockchain_tx_t *txs = calloc(bsc_count, sizeof(blockchain_tx_t));
    if (!txs) {
        bsc_rpc_free_transactions(bsc_txs, bsc_count);
        return -1;
    }

    for (int i = 0; i < bsc_count; i++) {
        strncpy(txs[i].tx_hash, bsc_txs[i].tx_hash, sizeof(txs[i].tx_hash) - 1);
        strncpy(txs[i].amount, bsc_txs[i].value, sizeof(txs[i].amount) - 1);
        if (token != NULL && strlen(token) > 0) {
            strncpy(txs[i].token, token, sizeof(txs[i].token) - 1);
        }
        snprintf(txs[i].timestamp, sizeof(txs[i].timestamp),
                 "%llu", (unsigned long long)bsc_txs[i].timestamp);
        txs[i].is_outgoing = bsc_txs[i].is_outgoing;
        if (bsc_txs[i].is_outgoing) {
            strncpy(txs[i].other_address, bsc_txs[i].to, sizeof(txs[i].other_address) - 1);
        } else {
            strncpy(txs[i].other_address, bsc_txs[i].from, sizeof(txs[i].other_address) - 1);
        }
        strncpy(txs[i].status,
                bsc_txs[i].is_confirmed ? "CONFIRMED" : "FAILED",
                sizeof(txs[i].status) - 1);
    }

    bsc_rpc_free_transactions(bsc_txs, bsc_count);

    *txs_out = txs;
    *count_out = bsc_count;
    return 0;
}

static void bsc_chain_free_transactions(blockchain_tx_t *txs, int count) {
    (void)count;
    if (txs) free(txs);
}

/* ============================================================================
 * REGISTRATION
 * ============================================================================ */

static const blockchain_ops_t bsc_ops = {
    .name = "bsc",
    .type = BLOCKCHAIN_TYPE_BSC,
    .init = bsc_chain_init,
    .cleanup = bsc_chain_cleanup,
    .get_balance = bsc_chain_get_balance,
    .estimate_fee = bsc_chain_estimate_fee,
    .send = bsc_chain_send,
    .get_tx_status = bsc_chain_get_tx_status,
    .validate_address = bsc_chain_validate_address,
    .get_transactions = bsc_chain_get_transactions,
    .free_transactions = bsc_chain_free_transactions,
    .user_data = NULL,
};

/* Auto-register on library load */
__attribute__((constructor))
static void bsc_chain_register(void) {
    blockchain_register(&bsc_ops);
}
