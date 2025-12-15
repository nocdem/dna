/**
 * @file sol_chain.c
 * @brief Solana blockchain_ops_t implementation
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#include "../blockchain.h"
#include "sol_wallet.h"
#include "sol_rpc.h"
#include "sol_tx.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

#define LOG_TAG "SOL_CHAIN"
#include "../../crypto/utils/qgp_log.h"

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

/* Check if token is native SOL (NULL, empty, or "SOL") */
static inline bool is_native_sol(const char *token) {
    if (token == NULL || token[0] == '\0') {
        return true;
    }
    /* Case-insensitive comparison for "SOL" */
    return (strcasecmp(token, "SOL") == 0);
}

/* ============================================================================
 * INTERFACE IMPLEMENTATIONS
 * ============================================================================ */

static int sol_chain_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Solana chain initialized");
    return 0;
}

static void sol_chain_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "Solana chain cleanup");
}

static int sol_chain_get_balance(
    const char *address,
    const char *token,
    char *balance_out,
    size_t balance_out_size
) {
    if (!address || !balance_out || balance_out_size == 0) {
        return -1;
    }

    /* Only native SOL supported */
    if (!is_native_sol(token)) {
        QGP_LOG_ERROR(LOG_TAG, "SPL tokens not yet supported: %s", token);
        return -1;
    }

    uint64_t lamports;
    if (sol_rpc_get_balance(address, &lamports) != 0) {
        return -1;
    }

    /* Convert lamports to SOL (9 decimals) */
    double sol = (double)lamports / SOL_LAMPORTS_PER_SOL;
    snprintf(balance_out, balance_out_size, "%.9f", sol);

    return 0;
}

static int sol_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,
    uint64_t *gas_price_out
) {
    (void)speed; /* Solana has fixed transaction fees */

    /*
     * Solana transaction fees are fixed:
     * - Base fee: 5000 lamports per signature
     * - Priority fee: optional (not implemented here)
     *
     * For a simple transfer with 1 signature: 5000 lamports
     */
    if (fee_out) {
        *fee_out = 5000; /* lamports */
    }

    if (gas_price_out) {
        *gas_price_out = 0; /* Not applicable to Solana */
    }

    return 0;
}

static int sol_chain_send(
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
    (void)fee_speed; /* Solana has fixed fees */

    if (!from_address || !to_address || !amount || !private_key ||
        private_key_len != SOL_PRIVATE_KEY_SIZE) {
        return -1;
    }

    /* Only native SOL supported */
    if (!is_native_sol(token)) {
        QGP_LOG_ERROR(LOG_TAG, "SPL tokens not yet supported: %s", token);
        return -1;
    }

    /* Create wallet from private key */
    sol_wallet_t wallet;
    memset(&wallet, 0, sizeof(wallet));
    memcpy(wallet.private_key, private_key, SOL_PRIVATE_KEY_SIZE);

    /* Derive public key from private key */
    /* Note: This requires regenerating the public key from the seed */
    /* For now, we derive from the from_address */
    if (sol_address_to_pubkey(from_address, wallet.public_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid from_address");
        return -1;
    }
    strncpy(wallet.address, from_address, SOL_ADDRESS_SIZE);

    /* Parse amount (in SOL) to lamports */
    double sol_amount = atof(amount);
    uint64_t lamports = (uint64_t)(sol_amount * SOL_LAMPORTS_PER_SOL);

    /* Send transaction */
    int ret = sol_tx_send_lamports(&wallet, to_address, lamports,
                                    txhash_out, txhash_out_size);

    /* Clear wallet */
    sol_wallet_clear(&wallet);

    return ret;
}

static int sol_chain_send_from_wallet(
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    const char *network,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    (void)network;   /* Mainnet only for now */
    (void)fee_speed; /* Solana has fixed fees */

    if (!wallet_path || !to_address || !amount) {
        return -1;
    }

    /* Only native SOL supported */
    if (!is_native_sol(token)) {
        QGP_LOG_ERROR(LOG_TAG, "SPL tokens not yet supported: %s", token);
        return -1;
    }

    /* Load wallet */
    sol_wallet_t wallet;
    if (sol_wallet_load(wallet_path, &wallet) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load wallet: %s", wallet_path);
        return -1;
    }

    /* Parse amount (in SOL) to lamports */
    double sol_amount = atof(amount);
    uint64_t lamports = (uint64_t)(sol_amount * SOL_LAMPORTS_PER_SOL);

    /* Send transaction */
    int ret = sol_tx_send_lamports(&wallet, to_address, lamports,
                                    txhash_out, txhash_out_size);

    /* Clear wallet */
    sol_wallet_clear(&wallet);

    return ret;
}

static int sol_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    if (!txhash || !status_out) {
        return -1;
    }

    bool success;
    int ret = sol_rpc_get_transaction_status(txhash, &success);

    if (ret < 0) {
        *status_out = BLOCKCHAIN_TX_NOT_FOUND;
        return -1;
    } else if (ret == 1) {
        *status_out = BLOCKCHAIN_TX_PENDING;
    } else {
        *status_out = success ? BLOCKCHAIN_TX_SUCCESS : BLOCKCHAIN_TX_FAILED;
    }

    return 0;
}

static bool sol_chain_validate_address(const char *address) {
    return sol_validate_address(address);
}

static int sol_chain_get_transactions(
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

    /* Only native SOL supported */
    if (token != NULL && strlen(token) > 0) {
        QGP_LOG_ERROR(LOG_TAG, "SPL token history not yet supported");
        return -1;
    }

    sol_transaction_t *sol_txs = NULL;
    int sol_count = 0;

    if (sol_rpc_get_transactions(address, &sol_txs, &sol_count) != 0) {
        return -1;
    }

    if (sol_count == 0 || !sol_txs) {
        return 0;
    }

    /* Convert to blockchain_tx_t */
    blockchain_tx_t *txs = calloc(sol_count, sizeof(blockchain_tx_t));
    if (!txs) {
        sol_rpc_free_transactions(sol_txs, sol_count);
        return -1;
    }

    for (int i = 0; i < sol_count; i++) {
        strncpy(txs[i].tx_hash, sol_txs[i].signature, sizeof(txs[i].tx_hash) - 1);

        /* Convert lamports to SOL */
        double sol = (double)sol_txs[i].lamports / SOL_LAMPORTS_PER_SOL;
        snprintf(txs[i].amount, sizeof(txs[i].amount), "%.9f", sol);

        txs[i].token[0] = '\0'; /* Native SOL */

        snprintf(txs[i].timestamp, sizeof(txs[i].timestamp),
                 "%lld", (long long)sol_txs[i].block_time);

        txs[i].is_outgoing = sol_txs[i].is_outgoing;

        if (sol_txs[i].is_outgoing) {
            strncpy(txs[i].other_address, sol_txs[i].to,
                    sizeof(txs[i].other_address) - 1);
        } else {
            strncpy(txs[i].other_address, sol_txs[i].from,
                    sizeof(txs[i].other_address) - 1);
        }

        strncpy(txs[i].status,
                sol_txs[i].success ? "CONFIRMED" : "FAILED",
                sizeof(txs[i].status) - 1);
    }

    sol_rpc_free_transactions(sol_txs, sol_count);

    *txs_out = txs;
    *count_out = sol_count;
    return 0;
}

static void sol_chain_free_transactions(blockchain_tx_t *txs, int count) {
    (void)count;
    if (txs) {
        free(txs);
    }
}

/* ============================================================================
 * REGISTRATION
 * ============================================================================ */

static const blockchain_ops_t sol_ops = {
    .name = "solana",
    .type = BLOCKCHAIN_TYPE_SOLANA,
    .init = sol_chain_init,
    .cleanup = sol_chain_cleanup,
    .get_balance = sol_chain_get_balance,
    .estimate_fee = sol_chain_estimate_fee,
    .send = sol_chain_send,
    .send_from_wallet = sol_chain_send_from_wallet,
    .get_tx_status = sol_chain_get_tx_status,
    .validate_address = sol_chain_validate_address,
    .get_transactions = sol_chain_get_transactions,
    .free_transactions = sol_chain_free_transactions,
    .user_data = NULL,
};

/* Auto-register on library load */
__attribute__((constructor))
static void sol_chain_register(void) {
    blockchain_register(&sol_ops);
}
