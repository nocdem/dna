/**
 * @file eth_chain.c
 * @brief Ethereum blockchain_ops_t implementation
 */

#include "../blockchain.h"
#include "eth_tx.h"
#include "eth_wallet.h"
#include "eth_erc20.h"
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

#define LOG_TAG "ETH_CHAIN"
#include "crypto/utils/qgp_log.h"

/* Curl write callback for tx status queries */
struct eth_resp_buf {
    char *data;
    size_t size;
};

static size_t eth_chain_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct eth_resp_buf *buf = (struct eth_resp_buf *)userp;
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

static int eth_chain_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Ethereum chain initialized");
    return 0;
}

static void eth_chain_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "Ethereum chain cleanup");
}

static int eth_chain_get_balance(
    const char *address,
    const char *token,
    char *balance_out,
    size_t balance_out_size
) {
    if (!address || !balance_out || balance_out_size == 0) {
        return -1;
    }

    /* Native ETH */
    if (token == NULL || strlen(token) == 0 || strcasecmp(token, "ETH") == 0) {
        return eth_rpc_get_balance(address, balance_out, balance_out_size);
    }

    /* ERC-20 token */
    if (eth_erc20_is_supported(token)) {
        return eth_erc20_get_balance_by_symbol(address, token, balance_out, balance_out_size);
    }

    QGP_LOG_ERROR(LOG_TAG, "Unsupported token: %s", token);
    return -1;
}

static int eth_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,
    uint64_t *gas_price_out
) {
    uint64_t gas_price;
    if (eth_tx_get_gas_price(&gas_price) != 0) {
        return -1;
    }

    /* Apply speed multiplier */
    switch (speed) {
        case BLOCKCHAIN_FEE_SLOW:
            gas_price = (gas_price * 80) / 100;  /* 0.8x */
            break;
        case BLOCKCHAIN_FEE_FAST:
            gas_price = (gas_price * 150) / 100; /* 1.5x */
            break;
        default:
            break; /* 1.0x */
    }

    if (gas_price_out) {
        *gas_price_out = gas_price;
    }

    if (fee_out) {
        *fee_out = gas_price * ETH_GAS_LIMIT_TRANSFER;
    }

    return 0;
}

static int eth_chain_send(
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
    if (!from_address || !to_address || !amount || !private_key || private_key_len != 32) {
        return -1;
    }

    /* Map fee speed to ETH gas speed */
    int gas_speed;
    switch (fee_speed) {
        case BLOCKCHAIN_FEE_SLOW:
            gas_speed = ETH_GAS_SLOW;
            break;
        case BLOCKCHAIN_FEE_FAST:
            gas_speed = ETH_GAS_FAST;
            break;
        default:
            gas_speed = ETH_GAS_NORMAL;
            break;
    }

    char tx_hash[67];
    int ret;

    /* Check if ERC-20 token or native ETH */
    if (token != NULL && strlen(token) > 0 && strcasecmp(token, "ETH") != 0) {
        /* ERC-20 token transfer */
        if (!eth_erc20_is_supported(token)) {
            QGP_LOG_ERROR(LOG_TAG, "Unsupported token: %s", token);
            return -1;
        }
        ret = eth_erc20_send_by_symbol(
            private_key,
            from_address,
            to_address,
            amount,
            token,
            gas_speed,
            tx_hash
        );
    } else {
        /* Native ETH transfer */
        ret = eth_send_eth_with_gas(
            private_key,
            from_address,
            to_address,
            amount,
            gas_speed,
            tx_hash
        );
    }

    if (ret == 0 && txhash_out && txhash_out_size > 0) {
        strncpy(txhash_out, tx_hash, txhash_out_size - 1);
        txhash_out[txhash_out_size - 1] = '\0';
    }

    return ret;
}

static int eth_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    if (!txhash || !status_out) return -1;

    *status_out = BLOCKCHAIN_TX_PENDING;

    const char *endpoint = eth_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "ETH RPC endpoint not configured");
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char body[512];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\","
        "\"params\":[\"%s\"],\"id\":1}", txhash);

    struct eth_resp_buf resp = {0};
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, eth_chain_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "eth_getTransactionReceipt CURL failed: %s",
                      curl_easy_strerror(res));
        free(resp.data);
        return -1;
    }

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse tx receipt response");
        return -1;
    }

    json_object *jresult;
    if (!json_object_object_get_ex(jresp, "result", &jresult) ||
        json_object_is_type(jresult, json_type_null)) {
        /* null result = tx still pending in mempool */
        *status_out = BLOCKCHAIN_TX_PENDING;
        json_object_put(jresp);
        return 0;
    }

    /* Receipt exists — check status field */
    json_object *jstatus;
    if (json_object_object_get_ex(jresult, "status", &jstatus)) {
        const char *st = json_object_get_string(jstatus);
        if (st && strcmp(st, "0x1") == 0) {
            *status_out = BLOCKCHAIN_TX_SUCCESS;
            QGP_LOG_DEBUG(LOG_TAG, "ETH tx confirmed: %s", txhash);
        } else {
            *status_out = BLOCKCHAIN_TX_FAILED;
            QGP_LOG_WARN(LOG_TAG, "ETH tx reverted: %s", txhash);
        }
    } else {
        /* Pre-Byzantium: no status field, assume success if receipt exists */
        *status_out = BLOCKCHAIN_TX_SUCCESS;
    }

    json_object_put(jresp);
    return 0;
}

static bool eth_chain_validate_address(const char *address) {
    if (!address) return false;

    /* Must start with 0x */
    if (strncmp(address, "0x", 2) != 0) return false;

    /* Must be 42 chars total (0x + 40 hex) */
    if (strlen(address) != 42) return false;

    /* All chars after 0x must be hex */
    for (int i = 2; i < 42; i++) {
        if (!isxdigit((unsigned char)address[i])) return false;
    }

    return true;
}

static int eth_chain_get_transactions(
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

    eth_transaction_t *eth_txs = NULL;
    int eth_count = 0;

    if (token != NULL && strlen(token) > 0) {
        /* ERC-20 token transaction history */
        eth_erc20_token_t erc20;
        if (eth_erc20_get_token(token, &erc20) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Unknown ERC-20 token: %s", token);
            return -1;
        }
        if (eth_rpc_get_token_transactions(address, erc20.contract,
                                            erc20.decimals,
                                            &eth_txs, &eth_count) != 0) {
            return -1;
        }
    } else {
        /* Native ETH transaction history */
        if (eth_rpc_get_transactions(address, &eth_txs, &eth_count) != 0) {
            return -1;
        }
    }

    if (eth_count == 0 || !eth_txs) {
        return 0;
    }

    /* Convert to blockchain_tx_t */
    blockchain_tx_t *txs = calloc(eth_count, sizeof(blockchain_tx_t));
    if (!txs) {
        eth_rpc_free_transactions(eth_txs, eth_count);
        return -1;
    }

    for (int i = 0; i < eth_count; i++) {
        strncpy(txs[i].tx_hash, eth_txs[i].tx_hash, sizeof(txs[i].tx_hash) - 1);
        strncpy(txs[i].amount, eth_txs[i].value, sizeof(txs[i].amount) - 1);

        if (token != NULL && strlen(token) > 0) {
            strncpy(txs[i].token, token, sizeof(txs[i].token) - 1);
        } else {
            txs[i].token[0] = '\0';
        }

        snprintf(txs[i].timestamp, sizeof(txs[i].timestamp),
                 "%llu", (unsigned long long)eth_txs[i].timestamp);

        txs[i].is_outgoing = eth_txs[i].is_outgoing;

        if (eth_txs[i].is_outgoing) {
            strncpy(txs[i].other_address, eth_txs[i].to, sizeof(txs[i].other_address) - 1);
        } else {
            strncpy(txs[i].other_address, eth_txs[i].from, sizeof(txs[i].other_address) - 1);
        }

        strncpy(txs[i].status,
                eth_txs[i].is_confirmed ? "CONFIRMED" : "FAILED",
                sizeof(txs[i].status) - 1);
    }

    eth_rpc_free_transactions(eth_txs, eth_count);

    *txs_out = txs;
    *count_out = eth_count;
    return 0;
}

static void eth_chain_free_transactions(blockchain_tx_t *txs, int count) {
    (void)count;
    if (txs) {
        free(txs);
    }
}

/* ============================================================================
 * REGISTRATION
 * ============================================================================ */

static const blockchain_ops_t eth_ops = {
    .name = "ethereum",
    .type = BLOCKCHAIN_TYPE_ETHEREUM,
    .init = eth_chain_init,
    .cleanup = eth_chain_cleanup,
    .get_balance = eth_chain_get_balance,
    .estimate_fee = eth_chain_estimate_fee,
    .send = eth_chain_send,
    .get_tx_status = eth_chain_get_tx_status,
    .validate_address = eth_chain_validate_address,
    .get_transactions = eth_chain_get_transactions,
    .free_transactions = eth_chain_free_transactions,
    .user_data = NULL,
};

/* Auto-register on library load */
__attribute__((constructor))
static void eth_chain_register(void) {
    blockchain_register(&eth_ops);
}
