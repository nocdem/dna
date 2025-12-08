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
#include "cellframe/cellframe_wallet.h"
#include "ethereum/eth_wallet.h"
#include "ethereum/eth_tx.h"
#include "../crypto/utils/qgp_log.h"
#include "../crypto/utils/qgp_platform.h"
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

#define LOG_TAG "BLOCKCHAIN"

/* ============================================================================
 * BLOCKCHAIN TYPE UTILITIES
 * ============================================================================ */

const char* blockchain_type_name(blockchain_type_t type) {
    switch (type) {
        case BLOCKCHAIN_CELLFRAME: return "Cellframe";
        case BLOCKCHAIN_ETHEREUM:  return "Ethereum";
        case BLOCKCHAIN_BITCOIN:   return "Bitcoin";
        case BLOCKCHAIN_SOLANA:    return "Solana";
        default:                   return "Unknown";
    }
}

const char* blockchain_type_ticker(blockchain_type_t type) {
    switch (type) {
        case BLOCKCHAIN_CELLFRAME: return "CPUNK";
        case BLOCKCHAIN_ETHEREUM:  return "ETH";
        case BLOCKCHAIN_BITCOIN:   return "BTC";
        case BLOCKCHAIN_SOLANA:    return "SOL";
        default:                   return "???";
    }
}

/* ============================================================================
 * WALLET CREATION
 * ============================================================================ */

int blockchain_create_wallet(
    blockchain_type_t type,
    const uint8_t master_seed[64],
    const char *fingerprint,
    const char *wallet_dir,
    char *address_out
) {
    if (!master_seed || !fingerprint || !wallet_dir || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to blockchain_create_wallet");
        return -1;
    }

    switch (type) {
        case BLOCKCHAIN_CELLFRAME: {
            /* Derive Cellframe wallet seed */
            uint8_t cf_seed[32];
            if (cellframe_derive_wallet_seed(master_seed, cf_seed) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive Cellframe wallet seed");
                return -1;
            }

            /* Create Cellframe wallet */
            int result = cellframe_wallet_create_from_seed(cf_seed, fingerprint, wallet_dir, address_out);

            /* Clear sensitive data */
            memset(cf_seed, 0, sizeof(cf_seed));

            if (result != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to create Cellframe wallet");
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG, "Cellframe wallet created: %s", address_out);
            return 0;
        }

        case BLOCKCHAIN_ETHEREUM: {
            /* Create Ethereum wallet using BIP-44 derivation */
            int result = eth_wallet_create_from_seed(master_seed, 64, fingerprint, wallet_dir, address_out);

            if (result != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to create Ethereum wallet");
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG, "Ethereum wallet created: %s", address_out);
            return 0;
        }

        case BLOCKCHAIN_BITCOIN:
        case BLOCKCHAIN_SOLANA:
            QGP_LOG_WARN(LOG_TAG, "Blockchain type %s not yet implemented", blockchain_type_name(type));
            return -1;

        default:
            QGP_LOG_ERROR(LOG_TAG, "Unknown blockchain type: %d", type);
            return -1;
    }
}

int blockchain_create_all_wallets(
    const uint8_t master_seed[64],
    const char *fingerprint,
    const char *wallet_dir
) {
    if (!master_seed || !fingerprint || !wallet_dir) {
        return -1;
    }

    int success_count = 0;
    int total_count = 0;
    char address[BLOCKCHAIN_WALLET_ADDRESS_MAX];

    /* Create Cellframe wallet */
    total_count++;
    if (blockchain_create_wallet(BLOCKCHAIN_CELLFRAME, master_seed, fingerprint, wallet_dir, address) == 0) {
        success_count++;
        QGP_LOG_INFO(LOG_TAG, "Created Cellframe wallet: %s", address);
    }

    /* Create Ethereum wallet */
    total_count++;
    if (blockchain_create_wallet(BLOCKCHAIN_ETHEREUM, master_seed, fingerprint, wallet_dir, address) == 0) {
        success_count++;
        QGP_LOG_INFO(LOG_TAG, "Created Ethereum wallet: %s", address);
    }

    /* Future: Add more blockchains here */

    QGP_LOG_INFO(LOG_TAG, "Created %d/%d wallets for identity", success_count, total_count);

    /* Return success if at least one wallet was created */
    return (success_count > 0) ? 0 : -1;
}

/* ============================================================================
 * WALLET LISTING
 * ============================================================================ */

int blockchain_list_wallets(
    const char *fingerprint,
    blockchain_wallet_list_t **list_out
) {
    if (!fingerprint || !list_out) {
        return -1;
    }

    /* Get wallet directory */
    const char *home = qgp_platform_home_dir();
    if (!home) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot get home directory");
        return -1;
    }

    char wallet_dir[512];
    snprintf(wallet_dir, sizeof(wallet_dir), "%s/.dna/%s/wallets", home, fingerprint);

    /* Check if directory exists */
    if (!qgp_platform_is_directory(wallet_dir)) {
        /* No wallets directory - return empty list */
        *list_out = calloc(1, sizeof(blockchain_wallet_list_t));
        if (!*list_out) return -1;
        (*list_out)->wallets = NULL;
        (*list_out)->count = 0;
        return 0;
    }

    /* Count wallet files */
    DIR *dir = opendir(wallet_dir);
    if (!dir) {
        return -1;
    }

    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".dwallet") || strstr(entry->d_name, ".eth.json")) {
            count++;
        }
    }
    rewinddir(dir);

    /* Allocate list */
    blockchain_wallet_list_t *list = calloc(1, sizeof(blockchain_wallet_list_t));
    if (!list) {
        closedir(dir);
        return -1;
    }

    if (count > 0) {
        list->wallets = calloc(count, sizeof(blockchain_wallet_info_t));
        if (!list->wallets) {
            free(list);
            closedir(dir);
            return -1;
        }
    }

    /* Populate list */
    size_t idx = 0;
    while ((entry = readdir(dir)) != NULL && idx < count) {
        blockchain_wallet_info_t *info = &list->wallets[idx];

        if (strstr(entry->d_name, ".dwallet")) {
            /* Cellframe wallet */
            info->type = BLOCKCHAIN_CELLFRAME;

            /* Extract name (remove .dwallet extension) */
            strncpy(info->name, entry->d_name, sizeof(info->name) - 1);
            char *ext = strstr(info->name, ".dwallet");
            if (ext) *ext = '\0';

            /* Build full path */
            snprintf(info->file_path, sizeof(info->file_path), "%s/%s", wallet_dir, entry->d_name);

            /* Get address */
            cellframe_wallet_t *cf_wallet = NULL;
            if (wallet_read_cellframe_path(info->file_path, &cf_wallet) == 0 && cf_wallet) {
                strncpy(info->address, cf_wallet->address, sizeof(info->address) - 1);
                info->is_encrypted = (cf_wallet->status == WALLET_STATUS_PROTECTED);
                wallet_free(cf_wallet);
            }

            idx++;
        }
        else if (strstr(entry->d_name, ".eth.json")) {
            /* Ethereum wallet */
            info->type = BLOCKCHAIN_ETHEREUM;

            /* Extract name (remove .eth.json extension) */
            strncpy(info->name, entry->d_name, sizeof(info->name) - 1);
            char *ext = strstr(info->name, ".eth.json");
            if (ext) *ext = '\0';

            /* Build full path */
            snprintf(info->file_path, sizeof(info->file_path), "%s/%s", wallet_dir, entry->d_name);

            /* Get address from file */
            if (eth_wallet_get_address(info->file_path, info->address, sizeof(info->address)) != 0) {
                info->address[0] = '\0';
            }

            info->is_encrypted = false;  /* We use unencrypted format */

            idx++;
        }
    }

    list->count = idx;
    closedir(dir);

    *list_out = list;
    return 0;
}

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

        default:
            return false;
    }
}

int blockchain_get_address_from_file(
    blockchain_type_t type,
    const char *wallet_path,
    char *address_out
) {
    if (!wallet_path || !address_out) {
        return -1;
    }

    switch (type) {
        case BLOCKCHAIN_CELLFRAME: {
            cellframe_wallet_t *wallet = NULL;
            if (wallet_read_cellframe_path(wallet_path, &wallet) != 0 || !wallet) {
                return -1;
            }
            strncpy(address_out, wallet->address, BLOCKCHAIN_WALLET_ADDRESS_MAX - 1);
            address_out[BLOCKCHAIN_WALLET_ADDRESS_MAX - 1] = '\0';
            wallet_free(wallet);
            return 0;
        }

        case BLOCKCHAIN_ETHEREUM:
            return eth_wallet_get_address(wallet_path, address_out, BLOCKCHAIN_WALLET_ADDRESS_MAX);

        default:
            return -1;
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

    /* ETH transfer gas limit is fixed at 21000 */
    uint64_t gas_limit = 21000;

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

int blockchain_send_tokens(
    blockchain_type_t type,
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    int gas_speed,
    char *tx_hash_out
) {
    if (!wallet_path || !to_address || !amount || !tx_hash_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to blockchain_send_tokens");
        return -1;
    }

    switch (type) {
        case BLOCKCHAIN_ETHEREUM: {
            /* Load wallet to get private key */
            eth_wallet_t wallet;
            if (eth_wallet_load(wallet_path, &wallet) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to load ETH wallet: %s", wallet_path);
                return -1;
            }

            /* Send ETH with gas speed */
            int ret = eth_send_eth_with_gas(
                wallet.private_key,
                wallet.address_hex,
                to_address,
                amount,
                gas_speed,
                tx_hash_out
            );

            /* Clear sensitive data */
            eth_wallet_clear(&wallet);

            return ret;
        }

        case BLOCKCHAIN_CELLFRAME:
            /* Cellframe send is handled separately in dna_engine.c via UTXO model */
            QGP_LOG_ERROR(LOG_TAG, "Use dna_handle_send_tokens for Cellframe");
            return -1;

        default:
            QGP_LOG_ERROR(LOG_TAG, "Send not implemented for %s", blockchain_type_name(type));
            return -1;
    }
}
