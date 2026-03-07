/**
 * @file blockchain_wallet.c
 * @brief Generic Blockchain Wallet Interface Implementation
 *
 * Dispatches to chain-specific implementations.
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "blockchain_wallet.h"
#include "cellframe/cellframe_wallet_create.h"

#include "ethereum/eth_wallet.h"
#include "ethereum/eth_tx.h"
#include "ethereum/eth_erc20.h"
#include "solana/sol_wallet.h"
#include "solana/sol_rpc.h"
#include "solana/sol_tx.h"
#include "tron/trx_wallet.h"
#include "tron/trx_rpc.h"
#include "tron/trx_tx.h"
#include "tron/trx_trc20.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include <string.h>
#include <stdlib.h>

#define LOG_TAG "BLOCKCHAIN"

/**
 * Parse decimal SOL amount string to lamports (no floating-point).
 * SOL has 9 decimals (1 SOL = 1,000,000,000 lamports).
 */
static int sol_str_to_lamports(const char *amount_str, uint64_t *lamports_out) {
    if (!amount_str || !lamports_out) return -1;

    const char *p = amount_str;
    while (*p == ' ') p++;
    if (*p == '\0') return -1;

    const char *dot = strchr(p, '.');

    uint64_t whole = 0;
    const char *end = dot ? dot : p + strlen(p);
    for (const char *c = p; c < end; c++) {
        if (*c < '0' || *c > '9') return -1;
        uint64_t prev = whole;
        whole = whole * 10 + (*c - '0');
        if (whole < prev) return -1;
    }

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
 * BLOCKCHAIN TYPE UTILITIES
 * ============================================================================ */

const char* blockchain_type_name(blockchain_type_t type) {
    switch (type) {
        case BLOCKCHAIN_CELLFRAME: return "Cellframe";
        case BLOCKCHAIN_ETHEREUM:  return "Ethereum";
        case BLOCKCHAIN_TRON:      return "TRON";
        case BLOCKCHAIN_SOLANA:    return "Solana";
        default:                   return "Unknown";
    }
}

const char* blockchain_type_ticker(blockchain_type_t type) {
    switch (type) {
        case BLOCKCHAIN_CELLFRAME: return "CPUNK";
        case BLOCKCHAIN_ETHEREUM:  return "ETH";
        case BLOCKCHAIN_TRON:      return "TRX";
        case BLOCKCHAIN_SOLANA:    return "SOL";
        default:                   return "???";
    }
}

/* v0.9.17: Wallet file creation and listing removed — seed-based derivation only */

void blockchain_wallet_list_free(blockchain_wallet_list_t *list) {
    if (list) {
        free(list->wallets);
        free(list);
    }
}

/* ============================================================================
 * BALANCE
 * ============================================================================ */

int blockchain_get_balance(
    blockchain_type_t type,
    const char *address,
    blockchain_balance_t *balance_out
) {
    if (!address || !balance_out) {
        return -1;
    }

    memset(balance_out, 0, sizeof(*balance_out));

    switch (type) {
        case BLOCKCHAIN_ETHEREUM:
            return eth_rpc_get_balance(address, balance_out->balance, sizeof(balance_out->balance));

        case BLOCKCHAIN_CELLFRAME:
            /* Cellframe balance requires RPC to cellframe-node */
            /* This is handled by existing cellframe_rpc.c */
            QGP_LOG_WARN(LOG_TAG, "Cellframe balance check uses separate RPC");
            return -1;

        case BLOCKCHAIN_SOLANA: {
            uint64_t lamports;
            if (sol_rpc_get_balance(address, &lamports) != 0) {
                return -1;
            }
            /* Convert lamports to SOL (9 decimals) */
            uint64_t whole = lamports / 1000000000ULL;
            uint64_t frac = lamports % 1000000000ULL;

            if (frac == 0) {
                snprintf(balance_out->balance, sizeof(balance_out->balance), "%llu.0", (unsigned long long)whole);
            } else {
                /* Format with 9 decimal places, then trim trailing zeros */
                char frac_str[16];
                snprintf(frac_str, sizeof(frac_str), "%09llu", (unsigned long long)frac);
                int len = 9;
                while (len > 1 && frac_str[len - 1] == '0') {
                    frac_str[--len] = '\0';
                }
                snprintf(balance_out->balance, sizeof(balance_out->balance), "%llu.%s", (unsigned long long)whole, frac_str);
            }
            return 0;
        }

        case BLOCKCHAIN_TRON:
            return trx_rpc_get_balance(address, balance_out->balance, sizeof(balance_out->balance));

        default:
            QGP_LOG_ERROR(LOG_TAG, "Balance check not implemented for %s", blockchain_type_name(type));
            return -1;
    }
}

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

bool blockchain_validate_address(blockchain_type_t type, const char *address) {
    if (!address || strlen(address) == 0) {
        return false;
    }

    switch (type) {
        case BLOCKCHAIN_ETHEREUM:
            return eth_validate_address(address);

        case BLOCKCHAIN_CELLFRAME:
            /* Cellframe addresses are base58-encoded, variable length */
            /* Basic check: should be alphanumeric, reasonable length */
            if (strlen(address) < 30 || strlen(address) > 120) {
                return false;
            }
            return true;

        case BLOCKCHAIN_SOLANA:
            return sol_validate_address(address);

        case BLOCKCHAIN_TRON:
            return trx_validate_address(address);

        default:
            return false;
    }
}

/* ============================================================================
 * SEND INTERFACE
 * ============================================================================ */

/* Gas speed multipliers (in percent) */
static const int GAS_MULTIPLIERS[] = {
    80,     /* SLOW: 0.8x */
    100,    /* NORMAL: 1.0x */
    150     /* FAST: 1.5x */
};

int blockchain_estimate_eth_gas(
    int gas_speed,
    blockchain_gas_estimate_t *estimate_out
) {
    if (!estimate_out) return -1;
    if (gas_speed < 0 || gas_speed > 2) gas_speed = 1;

    memset(estimate_out, 0, sizeof(*estimate_out));

    /* Get base gas price from network */
    uint64_t base_gas_price;
    if (eth_tx_get_gas_price(&base_gas_price) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get gas price");
        return -1;
    }

    /* Apply multiplier */
    uint64_t adjusted_price = (base_gas_price * GAS_MULTIPLIERS[gas_speed]) / 100;

    /* ETH transfer gas limit - must match ETH_GAS_LIMIT_TRANSFER in eth_tx.h */
    uint64_t gas_limit = 31500;

    /* Calculate total fee in wei */
    uint64_t total_fee_wei = adjusted_price * gas_limit;

    /* Convert to ETH (divide by 10^18) */
    double fee_eth = (double)total_fee_wei / 1000000000000000000.0;

    estimate_out->gas_price = adjusted_price;
    estimate_out->gas_limit = gas_limit;
    snprintf(estimate_out->fee_eth, sizeof(estimate_out->fee_eth), "%.6f", fee_eth);

    /* USD placeholder - would need price feed */
    snprintf(estimate_out->fee_usd, sizeof(estimate_out->fee_usd), "-");

    QGP_LOG_DEBUG(LOG_TAG, "Gas estimate: %s ETH (speed=%d, price=%llu wei)",
                  estimate_out->fee_eth, gas_speed, (unsigned long long)adjusted_price);

    return 0;
}

/* ============================================================================
 * ON-DEMAND WALLET DERIVATION
 * ============================================================================ */

int blockchain_derive_wallets_from_seed(
    const uint8_t master_seed[64],
    const char *mnemonic,
    const char *fingerprint,
    blockchain_wallet_list_t **list_out
) {
    if (!master_seed || !fingerprint || !list_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to blockchain_derive_wallets_from_seed");
        return -1;
    }

    /* Allocate list for all blockchain types */
    blockchain_wallet_list_t *list = calloc(1, sizeof(blockchain_wallet_list_t));
    if (!list) {
        return -1;
    }

    /* Allocate wallets for ETH, SOL, TRX, Cellframe */
    list->wallets = calloc(BLOCKCHAIN_COUNT, sizeof(blockchain_wallet_info_t));
    if (!list->wallets) {
        free(list);
        return -1;
    }

    size_t idx = 0;

    /* Derive Ethereum wallet address */
    {
        eth_wallet_t eth_wallet;
        if (eth_wallet_generate(master_seed, 64, &eth_wallet) == 0) {
            blockchain_wallet_info_t *info = &list->wallets[idx];
            info->type = BLOCKCHAIN_ETHEREUM;
            strncpy(info->name, fingerprint, sizeof(info->name) - 1);
            strncpy(info->address, eth_wallet.address_hex, sizeof(info->address) - 1);
            info->is_encrypted = false;
            eth_wallet_clear(&eth_wallet);
            idx++;
            QGP_LOG_DEBUG(LOG_TAG, "Derived ETH address: %s", info->address);
        }
    }

    /* Derive Solana wallet address */
    {
        sol_wallet_t sol_wallet;
        if (sol_wallet_generate(master_seed, 64, &sol_wallet) == 0) {
            blockchain_wallet_info_t *info = &list->wallets[idx];
            info->type = BLOCKCHAIN_SOLANA;
            strncpy(info->name, fingerprint, sizeof(info->name) - 1);
            strncpy(info->address, sol_wallet.address, sizeof(info->address) - 1);
            info->is_encrypted = false;
            sol_wallet_clear(&sol_wallet);
            idx++;
            QGP_LOG_DEBUG(LOG_TAG, "Derived SOL address: %s", info->address);
        }
    }

    /* Derive TRON wallet address */
    {
        trx_wallet_t trx_wallet;
        if (trx_wallet_generate(master_seed, 64, &trx_wallet) == 0) {
            blockchain_wallet_info_t *info = &list->wallets[idx];
            info->type = BLOCKCHAIN_TRON;
            strncpy(info->name, fingerprint, sizeof(info->name) - 1);
            strncpy(info->address, trx_wallet.address, sizeof(info->address) - 1);
            info->is_encrypted = false;
            trx_wallet_clear(&trx_wallet);
            idx++;
            QGP_LOG_DEBUG(LOG_TAG, "Derived TRX address: %s", info->address);
        }
    }

    /* Derive Cellframe wallet address from mnemonic
     * Cellframe uses SHA3-256(mnemonic) → 32-byte seed → Dilithium keypair
     * This matches the official Cellframe wallet app derivation.
     */
    if (mnemonic && mnemonic[0] != '\0') {
        uint8_t cf_seed[CF_WALLET_SEED_SIZE];
        if (cellframe_derive_seed_from_mnemonic(mnemonic, cf_seed) == 0) {
            char cf_address[CF_WALLET_ADDRESS_MAX];
            if (cellframe_wallet_derive_address(cf_seed, cf_address) == 0) {
                blockchain_wallet_info_t *info = &list->wallets[idx];
                info->type = BLOCKCHAIN_CELLFRAME;
                strncpy(info->name, fingerprint, sizeof(info->name) - 1);
                strncpy(info->address, cf_address, sizeof(info->address) - 1);
                info->is_encrypted = false;
                idx++;
                QGP_LOG_DEBUG(LOG_TAG, "Derived Cellframe address: %s", info->address);
            } else {
                QGP_LOG_WARN(LOG_TAG, "Failed to derive Cellframe address");
            }
            /* Securely clear seed */
            qgp_secure_memzero(cf_seed, sizeof(cf_seed));
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to derive Cellframe seed from mnemonic");
        }
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "No mnemonic provided, skipping Cellframe derivation");
    }

    list->count = idx;
    *list_out = list;

    QGP_LOG_INFO(LOG_TAG, "Derived %zu wallet addresses from seed", idx);
    return 0;
}

int blockchain_send_tokens_with_seed(
    blockchain_type_t type,
    const uint8_t master_seed[64],
    const char *mnemonic,
    const char *to_address,
    const char *amount,
    const char *token,
    int gas_speed,
    char *tx_hash_out
) {
    if (!master_seed || !to_address || !amount || !tx_hash_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to blockchain_send_tokens_with_seed");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, ">>> blockchain_send_tokens_with_seed: type=%d to=%s amount=%s token=%s",
                 type, to_address, amount, token ? token : "(native)");

    int ret = -1;
    const char *chain_name = NULL;

    switch (type) {
        case BLOCKCHAIN_ETHEREUM: {
            chain_name = "Ethereum";

            /* Derive ETH wallet on-demand */
            eth_wallet_t eth_wallet;
            if (eth_wallet_generate(master_seed, 64, &eth_wallet) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive ETH wallet");
                return -1;
            }

            /* Send using direct ETH functions */
            if (token != NULL && strlen(token) > 0 && strcasecmp(token, "ETH") != 0) {
                /* ERC-20 token transfer */
                ret = eth_erc20_send_by_symbol(
                    eth_wallet.private_key,
                    eth_wallet.address_hex,
                    to_address,
                    amount,
                    token,
                    gas_speed,
                    tx_hash_out
                );
            } else {
                /* Native ETH transfer */
                ret = eth_send_eth_with_gas(
                    eth_wallet.private_key,
                    eth_wallet.address_hex,
                    to_address,
                    amount,
                    gas_speed,
                    tx_hash_out
                );
            }

            /* Securely clear private key */
            eth_wallet_clear(&eth_wallet);
            break;
        }

        case BLOCKCHAIN_SOLANA: {
            chain_name = "Solana";

            /* Derive SOL wallet on-demand */
            sol_wallet_t sol_wallet;
            if (sol_wallet_generate(master_seed, 64, &sol_wallet) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive SOL wallet");
                return -1;
            }

            /* Native SOL transfer — string-based conversion, no float */
            uint64_t lamports;
            if (sol_str_to_lamports(amount, &lamports) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Invalid SOL amount: %s", amount);
                sol_wallet_clear(&sol_wallet);
                return -1;
            }
            ret = sol_tx_send_lamports(&sol_wallet, to_address, lamports, tx_hash_out, 128);

            /* Securely clear private key */
            sol_wallet_clear(&sol_wallet);
            break;
        }

        case BLOCKCHAIN_TRON: {
            chain_name = "TRON";

            /* Derive TRX wallet on-demand */
            trx_wallet_t trx_wallet;
            if (trx_wallet_generate(master_seed, 64, &trx_wallet) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive TRX wallet");
                return -1;
            }

            /* Send using direct TRX functions */
            if (token != NULL && strlen(token) > 0 && strcasecmp(token, "TRX") != 0) {
                /* TRC-20 token transfer */
                ret = trx_trc20_send_by_symbol(
                    trx_wallet.private_key,
                    trx_wallet.address,
                    to_address,
                    amount,
                    token,
                    tx_hash_out
                );
            } else {
                /* Native TRX transfer */
                ret = trx_send_trx(
                    trx_wallet.private_key,
                    trx_wallet.address,
                    to_address,
                    amount,
                    tx_hash_out
                );
            }

            /* Securely clear private key */
            trx_wallet_clear(&trx_wallet);
            break;
        }

        case BLOCKCHAIN_CELLFRAME: {
            chain_name = "Cellframe";

            /* Cellframe requires mnemonic string for key derivation */
            if (!mnemonic || mnemonic[0] == '\0') {
                QGP_LOG_ERROR(LOG_TAG, "Mnemonic required for Cellframe send");
                return -1;
            }

            /* Derive Cellframe seed from mnemonic (SHA3-256 hash) */
            uint8_t cf_seed[CF_WALLET_SEED_SIZE];
            if (cellframe_derive_seed_from_mnemonic(mnemonic, cf_seed) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive Cellframe seed");
                return -1;
            }

            /* Derive wallet keys from seed */
            cellframe_wallet_t *wallet = NULL;
            if (cellframe_wallet_derive_keys(cf_seed, &wallet) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive Cellframe wallet keys");
                qgp_secure_memzero(cf_seed, sizeof(cf_seed));
                return -1;
            }

            /* Clear seed immediately */
            qgp_secure_memzero(cf_seed, sizeof(cf_seed));

            QGP_LOG_INFO(LOG_TAG, "Derived Cellframe wallet: %s", wallet->address);

            /* Send using derived wallet */
            ret = cellframe_send_with_wallet(
                wallet,
                to_address,
                amount,
                token,
                tx_hash_out,
                128
            );

            /* Securely clear and free wallet */
            if (wallet->private_key) {
                qgp_secure_memzero(wallet->private_key, wallet->private_key_size);
            }
            wallet_free(wallet);
            break;
        }

        default:
            QGP_LOG_ERROR(LOG_TAG, "Unknown blockchain type: %d", type);
            return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "<<< blockchain_send_tokens_with_seed result: %d (chain=%s)", ret, chain_name);
    return ret;
}
