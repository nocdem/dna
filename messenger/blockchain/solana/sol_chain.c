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
#include "sol_spl.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define LOG_TAG "SOL_CHAIN"
#include "crypto/utils/qgp_log.h"

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

/**
 * Parse decimal SOL amount string to lamports (no floating-point).
 * SOL has 9 decimals (1 SOL = 1,000,000,000 lamports).
 */
static int sol_parse_amount_to_lamports(const char *amount_str, uint64_t *lamports_out) {
    if (!amount_str || !lamports_out) return -1;

    const char *p = amount_str;
    while (*p == ' ') p++;
    if (*p == '\0') return -1;

    const char *dot = strchr(p, '.');

    /* Parse whole part */
    uint64_t whole = 0;
    const char *end = dot ? dot : p + strlen(p);
    for (const char *c = p; c < end; c++) {
        if (*c < '0' || *c > '9') return -1;
        uint64_t prev = whole;
        whole = whole * 10 + (*c - '0');
        if (whole < prev) return -1;  /* overflow */
    }

    /* Parse fractional part — pad or truncate to 9 digits */
    uint64_t frac = 0;
    if (dot) {
        const char *frac_start = dot + 1;
        int frac_digits = 0;
        for (const char *c = frac_start; *c && frac_digits < 9; c++) {
            if (*c < '0' || *c > '9') return -1;
            frac = frac * 10 + (*c - '0');
            frac_digits++;
        }
        for (int i = frac_digits; i < 9; i++) {
            frac *= 10;
        }
    }

    if (whole > UINT64_MAX / SOL_LAMPORTS_PER_SOL) return -1;
    *lamports_out = whole * SOL_LAMPORTS_PER_SOL + frac;
    return 0;
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

    if (!is_native_sol(token)) {
        /* SPL token balance */
        return sol_spl_get_balance_by_symbol(address, token, balance_out, balance_out_size);
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

    /* Create wallet from private key */
    sol_wallet_t wallet;
    memset(&wallet, 0, sizeof(wallet));
    memcpy(wallet.private_key, private_key, SOL_PRIVATE_KEY_SIZE);

    /* Derive public key from the from_address */
    if (sol_address_to_pubkey(from_address, wallet.public_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid from_address");
        return -1;
    }
    strncpy(wallet.address, from_address, SOL_ADDRESS_SIZE);

    int ret;

    if (!is_native_sol(token)) {
        /* SPL token transfer */
        ret = sol_spl_send_by_symbol(&wallet, to_address, token, amount,
                                      txhash_out, txhash_out_size);
    } else {
        /* Native SOL transfer — string-based conversion, no float */
        uint64_t lamports;
        if (sol_parse_amount_to_lamports(amount, &lamports) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid SOL amount: %s", amount);
            sol_wallet_clear(&wallet);
            return -1;
        }
        ret = sol_tx_send_lamports(&wallet, to_address, lamports,
                                    txhash_out, txhash_out_size);
    }

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

    /* Determine if we're filtering by a specific SPL token */
    bool filter_spl = (token != NULL && token[0] != '\0' &&
                       strcasecmp(token, "SOL") != 0);
    /* Resolve filter token mint if filtering */
    char filter_mint[48] = {0};
    if (filter_spl) {
        sol_spl_token_t filter_token;
        if (sol_spl_get_token(token, &filter_token) == 0) {
            strncpy(filter_mint, filter_token.mint, sizeof(filter_mint) - 1);
        } else if (strlen(token) >= 32) {
            /* Treat as raw mint address */
            strncpy(filter_mint, token, sizeof(filter_mint) - 1);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Unknown SPL token for filter: %s", token);
            return -1;
        }
    }

    sol_transaction_t *sol_txs = NULL;
    int sol_count = 0;

    if (sol_rpc_get_transactions(address, &sol_txs, &sol_count, NULL, 0) != 0) {
        return -1;
    }

    if (sol_count == 0 || !sol_txs) {
        return 0;
    }

    /* Convert to blockchain_tx_t — allocate max, trim later */
    blockchain_tx_t *txs = calloc(sol_count, sizeof(blockchain_tx_t));
    if (!txs) {
        sol_rpc_free_transactions(sol_txs, sol_count);
        return -1;
    }

    int out_idx = 0;
    for (int i = 0; i < sol_count; i++) {
        if (sol_txs[i].is_token_transfer) {
            /* SPL token transaction */
            /* If filtering by native SOL, skip token transfers */
            if (token != NULL && token[0] != '\0' && strcasecmp(token, "SOL") == 0) {
                continue;
            }
            /* If filtering by specific SPL token, check mint match */
            if (filter_spl && strcmp(sol_txs[i].token_mint, filter_mint) != 0) {
                continue;
            }

            /* Look up token symbol from mint */
            sol_spl_token_t tok_info;
            const char *symbol = NULL;
            uint8_t decimals = 9;
            /* Try USDT */
            if (strcmp(sol_txs[i].token_mint, SOL_USDT_MINT) == 0) {
                symbol = "USDT";
                decimals = SOL_USDT_DECIMALS;
            } else if (strcmp(sol_txs[i].token_mint, SOL_USDC_MINT) == 0) {
                symbol = "USDC";
                decimals = SOL_USDC_DECIMALS;
            } else {
                /* Unknown token — use first 8 chars of mint as symbol */
                symbol = NULL;
                decimals = 9; /* fallback */
            }

            strncpy(txs[out_idx].tx_hash, sol_txs[i].signature,
                    sizeof(txs[out_idx].tx_hash) - 1);

            /* Format amount using token decimals */
            if (decimals == 0) {
                snprintf(txs[out_idx].amount, sizeof(txs[out_idx].amount),
                         "%llu", (unsigned long long)sol_txs[i].lamports);
            } else {
                uint64_t divisor = 1;
                for (uint8_t d = 0; d < decimals; d++) divisor *= 10;
                uint64_t whole = sol_txs[i].lamports / divisor;
                uint64_t frac = sol_txs[i].lamports % divisor;
                snprintf(txs[out_idx].amount, sizeof(txs[out_idx].amount),
                         "%llu.%0*llu", (unsigned long long)whole,
                         (int)decimals, (unsigned long long)frac);
            }

            if (symbol) {
                strncpy(txs[out_idx].token, symbol,
                        sizeof(txs[out_idx].token) - 1);
            } else {
                /* Fallback: first 8 chars of mint */
                strncpy(txs[out_idx].token, sol_txs[i].token_mint, 8);
                txs[out_idx].token[8] = '\0';
            }

            (void)tok_info; /* suppress unused warning */
        } else {
            /* Native SOL transaction */
            /* If filtering by specific SPL token, skip native */
            if (filter_spl) {
                continue;
            }

            strncpy(txs[out_idx].tx_hash, sol_txs[i].signature,
                    sizeof(txs[out_idx].tx_hash) - 1);

            /* Convert lamports to SOL */
            double sol = (double)sol_txs[i].lamports / SOL_LAMPORTS_PER_SOL;
            snprintf(txs[out_idx].amount, sizeof(txs[out_idx].amount),
                     "%.9f", sol);

            txs[out_idx].token[0] = '\0'; /* Native SOL */
        }

        snprintf(txs[out_idx].timestamp, sizeof(txs[out_idx].timestamp),
                 "%lld", (long long)sol_txs[i].block_time);

        txs[out_idx].is_outgoing = sol_txs[i].is_outgoing;

        if (sol_txs[i].is_outgoing) {
            strncpy(txs[out_idx].other_address, sol_txs[i].to,
                    sizeof(txs[out_idx].other_address) - 1);
        } else {
            strncpy(txs[out_idx].other_address, sol_txs[i].from,
                    sizeof(txs[out_idx].other_address) - 1);
        }

        strncpy(txs[out_idx].status,
                sol_txs[i].success ? "CONFIRMED" : "FAILED",
                sizeof(txs[out_idx].status) - 1);

        out_idx++;
    }

    sol_rpc_free_transactions(sol_txs, sol_count);

    if (out_idx == 0) {
        free(txs);
        return 0;
    }

    *txs_out = txs;
    *count_out = out_idx;
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
