/**
 * @file eth_chain.c
 * @brief Ethereum blockchain_ops_t implementation
 */

#include "../blockchain.h"
#include "eth_tx.h"
#include "eth_wallet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define LOG_TAG "ETH_CHAIN"
#include "crypto/utils/qgp_log.h"

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

    /* Only native ETH supported for now */
    if (token != NULL && strlen(token) > 0) {
        QGP_LOG_ERROR(LOG_TAG, "ERC-20 tokens not yet supported");
        return -1;
    }

    return eth_rpc_get_balance(address, balance_out, balance_out_size);
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
    int ret = eth_send_eth_with_gas(
        private_key,
        from_address,
        to_address,
        amount,
        gas_speed,
        tx_hash
    );

    if (ret == 0 && txhash_out && txhash_out_size > 0) {
        strncpy(txhash_out, tx_hash, txhash_out_size - 1);
        txhash_out[txhash_out_size - 1] = '\0';
    }

    return ret;
}

static int eth_chain_send_from_wallet(
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    const char *network,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    (void)network; /* ETH mainnet only */

    if (!wallet_path || !to_address || !amount) {
        return -1;
    }

    /* Only native ETH supported for now */
    if (token != NULL && strlen(token) > 0) {
        QGP_LOG_ERROR(LOG_TAG, "ERC-20 tokens not yet supported");
        return -1;
    }

    /* Load wallet */
    eth_wallet_t wallet;
    if (eth_wallet_load(wallet_path, &wallet) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load wallet: %s", wallet_path);
        return -1;
    }

    /* Map fee speed */
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
    int ret = eth_send_eth_with_gas(
        wallet.private_key,
        wallet.address_hex,
        to_address,
        amount,
        gas_speed,
        tx_hash
    );

    /* Clear sensitive data */
    eth_wallet_clear(&wallet);

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
    /* TODO: Implement via eth_getTransactionReceipt */
    if (status_out) {
        *status_out = BLOCKCHAIN_TX_PENDING;
    }
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

    /* Only native ETH supported for now */
    if (token != NULL && strlen(token) > 0) {
        QGP_LOG_ERROR(LOG_TAG, "ERC-20 transaction history not yet supported");
        return -1;
    }

    eth_transaction_t *eth_txs = NULL;
    int eth_count = 0;

    if (eth_rpc_get_transactions(address, &eth_txs, &eth_count) != 0) {
        return -1;
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
        txs[i].token[0] = '\0'; /* Native ETH */

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
    .send_from_wallet = eth_chain_send_from_wallet,
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
