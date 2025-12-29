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

/* Forward declarations from blockchain.h interface to avoid type conflict */
typedef struct blockchain_ops blockchain_ops_t;
typedef enum {
    BLOCKCHAIN_FEE_SLOW = 0,
    BLOCKCHAIN_FEE_NORMAL = 1,
    BLOCKCHAIN_FEE_FAST = 2,
} blockchain_fee_speed_t;
extern const blockchain_ops_t *blockchain_get(const char *name);
extern int blockchain_ops_send_from_wallet(
    const blockchain_ops_t *ops,
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    const char *network,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
);
#include "cellframe/cellframe_wallet.h"
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
#include "../crypto/utils/qgp_log.h"
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/seed_storage.h"
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
            /* Create Cellframe wallet directly from 64-byte BIP39 master seed
             * This matches the official Cellframe wallet app derivation
             */
            int result = cellframe_wallet_create_from_seed(master_seed, fingerprint, wallet_dir, address_out);

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

        case BLOCKCHAIN_SOLANA: {
            /* Create Solana wallet using SLIP-10 Ed25519 derivation */
            int result = sol_wallet_create_from_seed(master_seed, 64, fingerprint, wallet_dir, address_out);

            if (result != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to create Solana wallet");
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG, "Solana wallet created: %s", address_out);
            return 0;
        }

        case BLOCKCHAIN_TRON: {
            /* Create TRON wallet using BIP-44 derivation (m/44'/195'/0'/0/0) */
            int result = trx_wallet_create_from_seed(master_seed, 64, fingerprint, wallet_dir, address_out);

            if (result != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to create TRON wallet");
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG, "TRON wallet created: %s", address_out);
            return 0;
        }

        default:
            QGP_LOG_ERROR(LOG_TAG, "Unknown blockchain type: %d", type);
            return -1;
    }
}

int blockchain_create_all_wallets(
    const uint8_t master_seed[64],
    const char *mnemonic,
    const char *fingerprint,
    const char *wallet_dir
) {
    if (!master_seed || !fingerprint || !wallet_dir) {
        return -1;
    }

    int success_count = 0;
    int total_count = 0;
    char address[BLOCKCHAIN_WALLET_ADDRESS_MAX];

    /* Create Cellframe wallet using mnemonic-derived seed
     * Cellframe wallet app uses SHA3-256(mnemonic) NOT BIP39!
     */
    total_count++;
    if (mnemonic && mnemonic[0] != '\0') {
        uint8_t cf_seed[CF_WALLET_SEED_SIZE];
        if (cellframe_derive_seed_from_mnemonic(mnemonic, cf_seed) == 0) {
            if (cellframe_wallet_create_from_seed(cf_seed, fingerprint, wallet_dir, address) == 0) {
                success_count++;
                QGP_LOG_INFO(LOG_TAG, "Created Cellframe wallet: %s", address);
            }
            /* Securely clear seed */
            memset(cf_seed, 0, sizeof(cf_seed));
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive Cellframe seed from mnemonic");
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "No mnemonic provided - skipping Cellframe wallet");
    }

    /* Create Ethereum wallet using BIP-44 derivation */
    total_count++;
    if (blockchain_create_wallet(BLOCKCHAIN_ETHEREUM, master_seed, fingerprint, wallet_dir, address) == 0) {
        success_count++;
        QGP_LOG_INFO(LOG_TAG, "Created Ethereum wallet: %s", address);
    }

    /* Create Solana wallet using SLIP-10 derivation */
    total_count++;
    if (blockchain_create_wallet(BLOCKCHAIN_SOLANA, master_seed, fingerprint, wallet_dir, address) == 0) {
        success_count++;
        QGP_LOG_INFO(LOG_TAG, "Created Solana wallet: %s", address);
    }

    /* Create TRON wallet using BIP-44 derivation */
    total_count++;
    if (blockchain_create_wallet(BLOCKCHAIN_TRON, master_seed, fingerprint, wallet_dir, address) == 0) {
        success_count++;
        QGP_LOG_INFO(LOG_TAG, "Created TRON wallet: %s", address);
    }

    QGP_LOG_INFO(LOG_TAG, "Created %d/%d wallets for identity", success_count, total_count);

    /* Return success if at least one wallet was created */
    return (success_count > 0) ? 0 : -1;
}

/* ============================================================================
 * MISSING WALLET CREATION
 * ============================================================================ */

/**
 * Securely wipe memory
 */
static void blockchain_secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * Check if wallet file exists for a blockchain type
 */
static bool wallet_file_exists(const char *wallet_dir, const char *fingerprint, blockchain_type_t type) {
    char path[BLOCKCHAIN_WALLET_PATH_MAX];

    switch (type) {
        case BLOCKCHAIN_CELLFRAME:
            snprintf(path, sizeof(path), "%s/%s.dwallet", wallet_dir, fingerprint);
            break;
        case BLOCKCHAIN_ETHEREUM:
            snprintf(path, sizeof(path), "%s/%s.eth.json", wallet_dir, fingerprint);
            break;
        case BLOCKCHAIN_SOLANA:
            snprintf(path, sizeof(path), "%s/%s.sol.json", wallet_dir, fingerprint);
            break;
        case BLOCKCHAIN_TRON:
            snprintf(path, sizeof(path), "%s/%s.trx.json", wallet_dir, fingerprint);
            break;
        default:
            return false;
    }

    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

int blockchain_create_missing_wallets(
    const char *fingerprint,
    const uint8_t kem_privkey[3168],
    int *wallets_created
) {
    if (!fingerprint || !kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to blockchain_create_missing_wallets");
        return -1;
    }

    if (wallets_created) {
        *wallets_created = 0;
    }

    /* Get data directory */
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot get data directory");
        return -1;
    }

    /* Build paths */
    char identity_dir[512];
    char wallet_dir[512];
    snprintf(identity_dir, sizeof(identity_dir), "%s/%s", data_dir, fingerprint);
    snprintf(wallet_dir, sizeof(wallet_dir), "%s/%s/wallets", data_dir, fingerprint);

    /* Check if encrypted seed exists */
    if (!seed_storage_exists(identity_dir)) {
        QGP_LOG_DEBUG(LOG_TAG, "No encrypted seed file - cannot create missing wallets");
        return 0;  /* Not an error, just no seed available */
    }

    /* Check which wallets are missing (skip Cellframe - needs mnemonic) */
    bool need_eth = !wallet_file_exists(wallet_dir, fingerprint, BLOCKCHAIN_ETHEREUM);
    bool need_sol = !wallet_file_exists(wallet_dir, fingerprint, BLOCKCHAIN_SOLANA);
    bool need_trx = !wallet_file_exists(wallet_dir, fingerprint, BLOCKCHAIN_TRON);

    if (!need_eth && !need_sol && !need_trx) {
        QGP_LOG_DEBUG(LOG_TAG, "All wallets already exist");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Missing wallets detected: ETH=%d SOL=%d TRX=%d",
                 need_eth, need_sol, need_trx);

    /* Load encrypted seed */
    uint8_t master_seed[64];
    if (seed_storage_load(master_seed, kem_privkey, identity_dir) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted seed");
        return -1;
    }

    int created = 0;
    char address[BLOCKCHAIN_WALLET_ADDRESS_MAX];

    /* Create missing Ethereum wallet */
    if (need_eth) {
        if (blockchain_create_wallet(BLOCKCHAIN_ETHEREUM, master_seed, fingerprint, wallet_dir, address) == 0) {
            created++;
            QGP_LOG_INFO(LOG_TAG, "Created missing Ethereum wallet: %s", address);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to create Ethereum wallet");
        }
    }

    /* Create missing Solana wallet */
    if (need_sol) {
        if (blockchain_create_wallet(BLOCKCHAIN_SOLANA, master_seed, fingerprint, wallet_dir, address) == 0) {
            created++;
            QGP_LOG_INFO(LOG_TAG, "Created missing Solana wallet: %s", address);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to create Solana wallet");
        }
    }

    /* Create missing TRON wallet */
    if (need_trx) {
        if (blockchain_create_wallet(BLOCKCHAIN_TRON, master_seed, fingerprint, wallet_dir, address) == 0) {
            created++;
            QGP_LOG_INFO(LOG_TAG, "Created missing TRON wallet: %s", address);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to create TRON wallet");
        }
    }

    /* Securely wipe master seed from memory */
    blockchain_secure_memzero(master_seed, sizeof(master_seed));

    if (wallets_created) {
        *wallets_created = created;
    }

    QGP_LOG_INFO(LOG_TAG, "Created %d missing wallets for identity", created);
    return 0;
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
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot get data directory");
        return -1;
    }

    char wallet_dir[512];
    snprintf(wallet_dir, sizeof(wallet_dir), "%s/%s/wallets", data_dir, fingerprint);

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
        if (strstr(entry->d_name, ".dwallet") || strstr(entry->d_name, ".eth.json") ||
            strstr(entry->d_name, ".sol.json") || strstr(entry->d_name, ".trx.json")) {
            count++;
        }
    }
    /* Reopen directory (rewinddir not available on Windows) */
    closedir(dir);
    dir = opendir(wallet_dir);
    if (!dir) {
        return -1;
    }

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
        else if (strstr(entry->d_name, ".sol.json")) {
            /* Solana wallet */
            info->type = BLOCKCHAIN_SOLANA;

            /* Extract name (remove .sol.json extension) */
            strncpy(info->name, entry->d_name, sizeof(info->name) - 1);
            char *ext = strstr(info->name, ".sol.json");
            if (ext) *ext = '\0';

            /* Build full path */
            snprintf(info->file_path, sizeof(info->file_path), "%s/%s", wallet_dir, entry->d_name);

            /* Get address from file */
            sol_wallet_t sol_wallet;
            if (sol_wallet_load(info->file_path, &sol_wallet) == 0) {
                strncpy(info->address, sol_wallet.address, sizeof(info->address) - 1);
                sol_wallet_clear(&sol_wallet);
            } else {
                info->address[0] = '\0';
            }

            info->is_encrypted = false;  /* We use unencrypted format */

            idx++;
        }
        else if (strstr(entry->d_name, ".trx.json")) {
            /* TRON wallet */
            info->type = BLOCKCHAIN_TRON;

            /* Extract name (remove .trx.json extension) */
            strncpy(info->name, entry->d_name, sizeof(info->name) - 1);
            char *ext = strstr(info->name, ".trx.json");
            if (ext) *ext = '\0';

            /* Build full path */
            snprintf(info->file_path, sizeof(info->file_path), "%s/%s", wallet_dir, entry->d_name);

            /* Get address from file */
            if (trx_wallet_get_address(info->file_path, info->address, sizeof(info->address)) != 0) {
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

        case BLOCKCHAIN_SOLANA: {
            sol_wallet_t wallet;
            if (sol_wallet_load(wallet_path, &wallet) != 0) {
                return -1;
            }
            strncpy(address_out, wallet.address, BLOCKCHAIN_WALLET_ADDRESS_MAX - 1);
            address_out[BLOCKCHAIN_WALLET_ADDRESS_MAX - 1] = '\0';
            sol_wallet_clear(&wallet);
            return 0;
        }

        case BLOCKCHAIN_TRON:
            return trx_wallet_get_address(wallet_path, address_out, BLOCKCHAIN_WALLET_ADDRESS_MAX);

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

int blockchain_send_tokens(
    blockchain_type_t type,
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    int gas_speed,
    char *tx_hash_out
) {
    QGP_LOG_INFO(LOG_TAG, ">>> blockchain_send_tokens: type=%d path=%s to=%s amount=%s token=%s gas=%d",
                 type, wallet_path ? wallet_path : "NULL",
                 to_address ? to_address : "NULL",
                 amount ? amount : "NULL",
                 token ? token : "NULL", gas_speed);

    if (!wallet_path || !to_address || !amount || !tx_hash_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to blockchain_send_tokens");
        return -1;
    }

    /* Map blockchain_wallet type to chain name */
    const char *chain_name = NULL;
    const char *network = NULL;
    switch (type) {
        case BLOCKCHAIN_ETHEREUM:
            chain_name = "ethereum";
            network = "mainnet";
            break;
        case BLOCKCHAIN_CELLFRAME:
            chain_name = "cellframe";
            network = "Backbone";
            break;
        case BLOCKCHAIN_SOLANA:
            chain_name = "solana";
            network = "mainnet-beta";
            break;
        case BLOCKCHAIN_TRON:
            chain_name = "tron";
            network = "mainnet";
            break;
        default:
            QGP_LOG_ERROR(LOG_TAG, "Send not implemented for %s", blockchain_type_name(type));
            return -1;
    }

    /* Get blockchain ops via modular interface */
    const blockchain_ops_t *ops = blockchain_get(chain_name);
    if (!ops) {
        QGP_LOG_ERROR(LOG_TAG, "Chain '%s' not registered", chain_name);
        return -1;
    }

    /* Map gas_speed to blockchain_fee_speed_t */
    blockchain_fee_speed_t fee_speed;
    switch (gas_speed) {
        case 0: fee_speed = BLOCKCHAIN_FEE_SLOW; break;
        case 2: fee_speed = BLOCKCHAIN_FEE_FAST; break;
        default: fee_speed = BLOCKCHAIN_FEE_NORMAL; break;
    }

    /* Call the modular interface via wrapper function */
    int ret = blockchain_ops_send_from_wallet(
        ops,
        wallet_path,
        to_address,
        amount,
        token,
        network,
        fee_speed,
        tx_hash_out,
        128  /* tx_hash buffer size */
    );

    QGP_LOG_INFO(LOG_TAG, "<<< blockchain_send_tokens result: %d (chain=%s)", ret, chain_name);
    return ret;
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
            info->file_path[0] = '\0';  /* No file - derived on-demand */
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
            info->file_path[0] = '\0';  /* No file - derived on-demand */
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
            info->file_path[0] = '\0';  /* No file - derived on-demand */
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
                info->file_path[0] = '\0';  /* No file - derived on-demand */
                info->is_encrypted = false;
                idx++;
                QGP_LOG_DEBUG(LOG_TAG, "Derived Cellframe address: %s", info->address);
            } else {
                QGP_LOG_WARN(LOG_TAG, "Failed to derive Cellframe address");
            }
            /* Securely clear seed */
            memset(cf_seed, 0, sizeof(cf_seed));
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

            /* Native SOL transfer (SPL tokens not yet supported) */
            double sol_amount = atof(amount);
            ret = sol_tx_send_sol(&sol_wallet, to_address, sol_amount, tx_hash_out, 128);

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
                memset(cf_seed, 0, sizeof(cf_seed));
                return -1;
            }

            /* Clear seed immediately */
            memset(cf_seed, 0, sizeof(cf_seed));

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
                memset(wallet->private_key, 0, wallet->private_key_size);
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
