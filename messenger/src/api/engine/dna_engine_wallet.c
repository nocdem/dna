/*
 * DNA Engine - Wallet Module
 *
 * Blockchain wallet handling extracted from dna_engine.c.
 * Contains multi-chain wallet operations: ETH, SOL, TRX, Cellframe.
 * Also DEX quote/swap operations (Raydium on Solana, Uniswap v2 on Ethereum).
 *
 * Functions:
 *   - dna_handle_list_wallets()
 *   - dna_handle_get_balances()
 *   - dna_handle_send_tokens()
 *   - dna_handle_get_transactions()
 *   - dna_handle_dex_quote()
 *   - dna_handle_dex_list_pairs()
 *   - dna_handle_dex_swap()
 */

#define DNA_ENGINE_WALLET_IMPL
#include "engine_includes.h"
#include "blockchain/solana/sol_dex.h"
#include "blockchain/ethereum/eth_dex.h"
#include "blockchain/cellframe/cellframe_dex.h"

/* ============================================================================
 * WALLET TASK HANDLERS
 * ============================================================================ */

void dna_handle_list_wallets(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_wallet_t *wallets = NULL;
    int count = 0;

    /* Free existing blockchain wallet list */
    if (engine->blockchain_wallets) {
        blockchain_wallet_list_free(engine->blockchain_wallets);
        engine->blockchain_wallets = NULL;
    }

    /* Derive wallets on-demand from mnemonic (seed-based only, no wallet files) */
    char mnemonic[512] = {0};
    if (dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic)) != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get mnemonic for wallet derivation");
        error = DNA_ERROR_CRYPTO;
        goto done;
    }

    /* Convert mnemonic to 64-byte master seed */
    uint8_t master_seed[64];
    if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive master seed from mnemonic");
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        error = DNA_ERROR_CRYPTO;
        goto done;
    }

    /* Derive wallet addresses from master seed and mnemonic
     * Note: Cellframe needs the mnemonic (SHA3-256 hash), ETH/SOL/TRX use master seed
     */
    int rc = blockchain_derive_wallets_from_seed(master_seed, mnemonic, engine->fingerprint, &engine->blockchain_wallets);

    /* Clear sensitive data from memory */
    qgp_secure_memzero(mnemonic, sizeof(mnemonic));
    qgp_secure_memzero(master_seed, sizeof(master_seed));

    if (rc != 0 || !engine->blockchain_wallets) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive wallets from seed");
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    blockchain_wallet_list_t *list = engine->blockchain_wallets;
    if (list->count > 0) {
        wallets = calloc(list->count, sizeof(dna_wallet_t));
        if (!wallets) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (size_t i = 0; i < list->count; i++) {
            strncpy(wallets[i].name, list->wallets[i].name, sizeof(wallets[i].name) - 1);
            strncpy(wallets[i].address, list->wallets[i].address, sizeof(wallets[i].address) - 1);
            /* Map blockchain type to sig_type for UI display */
            if (list->wallets[i].type == BLOCKCHAIN_ETHEREUM) {
                wallets[i].sig_type = 100;  /* Use 100 for ETH (secp256k1) */
            } else if (list->wallets[i].type == BLOCKCHAIN_SOLANA) {
                wallets[i].sig_type = 101;  /* Use 101 for SOL (Ed25519) */
            } else if (list->wallets[i].type == BLOCKCHAIN_TRON) {
                wallets[i].sig_type = 102;  /* Use 102 for TRX (secp256k1) */
            } else {
                wallets[i].sig_type = 4;    /* Dilithium for Cellframe */
            }
            wallets[i].is_protected = list->wallets[i].is_encrypted;
        }
        count = (int)list->count;
    }

    engine->wallets_loaded = true;

done:
    task->callback.wallets(task->request_id, error, wallets, count, task->user_data);
}

void dna_handle_get_balances(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_balance_t *balances = NULL;
    int count = 0;

    if (!engine->wallets_loaded || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    blockchain_wallet_list_t *list = engine->blockchain_wallets;
    int idx = task->params.get_balances.wallet_index;

    if (idx < 0 || idx >= (int)list->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    blockchain_wallet_info_t *wallet_info = &list->wallets[idx];

    /* Handle non-Cellframe blockchains via modular interface */
    if (wallet_info->type == BLOCKCHAIN_ETHEREUM) {
        /* Ethereum: ETH + USDT + USDC (ERC-20) */
        balances = calloc(3, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 3;

        /* Native ETH balance */
        strncpy(balances[0].token, "ETH", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Ethereum", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (ERC-20) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Ethereum", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0.0");

        char usdt_balance[64] = {0};
        if (eth_erc20_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        /* USDC (ERC-20) balance */
        strncpy(balances[2].token, "USDC", sizeof(balances[2].token) - 1);
        strncpy(balances[2].network, "Ethereum", sizeof(balances[2].network) - 1);
        strcpy(balances[2].balance, "0");

        char usdc_balance_eth[64] = {0};
        if (eth_erc20_get_balance_by_symbol(wallet_info->address, "USDC", usdc_balance_eth, sizeof(usdc_balance_eth)) == 0) {
            strncpy(balances[2].balance, usdc_balance_eth, sizeof(balances[2].balance) - 1);
        }

        goto done;
    }

    if (wallet_info->type == BLOCKCHAIN_TRON) {
        /* TRON: TRX + USDT + USDC (TRC-20) */
        balances = calloc(3, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 3;

        /* Native TRX balance */
        strncpy(balances[0].token, "TRX", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Tron", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (TRC-20) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Tron", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0.0");

        char usdt_balance[64] = {0};
        if (trx_trc20_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        /* USDC (TRC-20) balance */
        strncpy(balances[2].token, "USDC", sizeof(balances[2].token) - 1);
        strncpy(balances[2].network, "Tron", sizeof(balances[2].network) - 1);
        strcpy(balances[2].balance, "0");

        char usdc_balance_trx[64] = {0};
        if (trx_trc20_get_balance_by_symbol(wallet_info->address, "USDC", usdc_balance_trx, sizeof(usdc_balance_trx)) == 0) {
            strncpy(balances[2].balance, usdc_balance_trx, sizeof(balances[2].balance) - 1);
        }

        goto done;
    }

    if (wallet_info->type == BLOCKCHAIN_SOLANA) {
        /* Solana: SOL + USDT + USDC (SPL) */
        balances = calloc(3, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 3;

        /* Native SOL balance */
        strncpy(balances[0].token, "SOL", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Solana", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (SPL) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Solana", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0");

        char usdt_balance[64] = {0};
        if (sol_spl_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        /* USDC (SPL) balance */
        strncpy(balances[2].token, "USDC", sizeof(balances[2].token) - 1);
        strncpy(balances[2].network, "Solana", sizeof(balances[2].network) - 1);
        strcpy(balances[2].balance, "0");

        char usdc_balance_sol[64] = {0};
        if (sol_spl_get_balance_by_symbol(wallet_info->address, "USDC", usdc_balance_sol, sizeof(usdc_balance_sol)) == 0) {
            strncpy(balances[2].balance, usdc_balance_sol, sizeof(balances[2].balance) - 1);
        }

        goto done;
    }

    /* Cellframe wallet - existing logic */
    char address[120] = {0};
    strncpy(address, wallet_info->address, sizeof(address) - 1);

    /* Pre-allocate balances for CF20 tokens: CPUNK, CELL, NYS, KEL, QEVM */
    balances = calloc(5, sizeof(dna_balance_t));
    if (!balances) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Initialize with defaults */
    strncpy(balances[0].token, "CPUNK", sizeof(balances[0].token) - 1);
    strncpy(balances[0].network, "Backbone", sizeof(balances[0].network) - 1);
    strcpy(balances[0].balance, "0.0");

    strncpy(balances[1].token, "CELL", sizeof(balances[1].token) - 1);
    strncpy(balances[1].network, "Backbone", sizeof(balances[1].network) - 1);
    strcpy(balances[1].balance, "0.0");

    strncpy(balances[2].token, "NYS", sizeof(balances[2].token) - 1);
    strncpy(balances[2].network, "Backbone", sizeof(balances[2].network) - 1);
    strcpy(balances[2].balance, "0.0");

    strncpy(balances[3].token, "KEL", sizeof(balances[3].token) - 1);
    strncpy(balances[3].network, "Backbone", sizeof(balances[3].network) - 1);
    strcpy(balances[3].balance, "0.0");

    strncpy(balances[4].token, "QEVM", sizeof(balances[4].token) - 1);
    strncpy(balances[4].network, "Backbone", sizeof(balances[4].network) - 1);
    strcpy(balances[4].balance, "0.0");

    count = 5;

    /* Query balance via RPC - response contains all tokens for address */
    cellframe_rpc_response_t *response = NULL;
    int rc = cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response);

    if (rc == 0 && response && response->result) {
        json_object *jresult = response->result;

        /* Parse response format: result[0][0]["tokens"][i] */
        if (json_object_is_type(jresult, json_type_array) &&
            json_object_array_length(jresult) > 0) {

            json_object *first = json_object_array_get_idx(jresult, 0);
            if (first && json_object_is_type(first, json_type_array) &&
                json_object_array_length(first) > 0) {

                json_object *wallet_obj = json_object_array_get_idx(first, 0);
                json_object *tokens_obj = NULL;

                if (wallet_obj && json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                    int token_count = json_object_array_length(tokens_obj);

                    for (int i = 0; i < token_count; i++) {
                        json_object *token_entry = json_object_array_get_idx(tokens_obj, i);
                        json_object *token_info_obj = NULL;
                        json_object *coins_obj = NULL;

                        if (!json_object_object_get_ex(token_entry, "coins", &coins_obj)) {
                            continue;
                        }

                        if (!json_object_object_get_ex(token_entry, "token", &token_info_obj)) {
                            continue;
                        }

                        json_object *ticker_obj = NULL;
                        if (json_object_object_get_ex(token_info_obj, "ticker", &ticker_obj)) {
                            const char *ticker = json_object_get_string(ticker_obj);
                            const char *coins = json_object_get_string(coins_obj);

                            /* Match ticker to our balance slots */
                            if (ticker && coins) {
                                if (strcmp(ticker, "CPUNK") == 0) {
                                    strncpy(balances[0].balance, coins, sizeof(balances[0].balance) - 1);
                                } else if (strcmp(ticker, "CELL") == 0) {
                                    strncpy(balances[1].balance, coins, sizeof(balances[1].balance) - 1);
                                } else if (strcmp(ticker, "NYS") == 0) {
                                    strncpy(balances[2].balance, coins, sizeof(balances[2].balance) - 1);
                                } else if (strcmp(ticker, "KEL") == 0) {
                                    strncpy(balances[3].balance, coins, sizeof(balances[3].balance) - 1);
                                } else if (strcmp(ticker, "QEVM") == 0) {
                                    strncpy(balances[4].balance, coins, sizeof(balances[4].balance) - 1);
                                }
                            }
                        }
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    }

done:
    /* Write-through: persist balances to SQLite cache on success */
    if (error == DNA_OK && balances && count > 0) {
        wallet_cache_save_balances(task->params.get_balances.wallet_index,
                                   balances, count);
    }

    task->callback.balances(task->request_id, error, balances, count, task->user_data);
}

/* Read balances from SQLite cache only — no network calls */
void dna_handle_get_cached_balances(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;  /* Cache read doesn't need engine state */

    dna_balance_t *balances = NULL;
    int count = 0;
    int rc = wallet_cache_get_balances(task->params.get_balances.wallet_index,
                                       &balances, &count);

    if (rc == 0 && balances && count > 0) {
        task->callback.balances(task->request_id, DNA_OK, balances, count, task->user_data);
    } else {
        /* No cached data — return empty (not an error, just no cache yet) */
        task->callback.balances(task->request_id, DNA_OK, NULL, 0, task->user_data);
    }
}

void dna_handle_send_tokens(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->wallets_loaded || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* Get task parameters */
    int wallet_index = task->params.send_tokens.wallet_index;
    const char *recipient = task->params.send_tokens.recipient;
    const char *amount_str = task->params.send_tokens.amount;
    const char *token = task->params.send_tokens.token;
    const char *network = task->params.send_tokens.network;
    int gas_speed = task->params.send_tokens.gas_speed;

    /* Determine blockchain type from network parameter */
    blockchain_type_t bc_type;
    const char *chain_name;
    if (strcasecmp(network, "Ethereum") == 0 || strcasecmp(network, "ETH") == 0) {
        bc_type = BLOCKCHAIN_ETHEREUM;
        chain_name = "Ethereum";
    } else if (strcasecmp(network, "Solana") == 0 || strcasecmp(network, "SOL") == 0) {
        bc_type = BLOCKCHAIN_SOLANA;
        chain_name = "Solana";
    } else if (strcasecmp(network, "Tron") == 0 || strcasecmp(network, "TRX") == 0) {
        bc_type = BLOCKCHAIN_TRON;
        chain_name = "TRON";
    } else if (strcasecmp(network, "Cellframe") == 0 || strcasecmp(network, "CELL") == 0) {
        bc_type = BLOCKCHAIN_CELLFRAME;
        chain_name = "Cellframe";
    } else {
        /* Default: Backbone = Cellframe */
        bc_type = BLOCKCHAIN_CELLFRAME;
        chain_name = "Cellframe";
    }

    /* Find wallet for this blockchain type */
    blockchain_wallet_list_t *bc_wallets = engine->blockchain_wallets;
    blockchain_wallet_info_t *bc_wallet_info = NULL;
    for (size_t i = 0; i < bc_wallets->count; i++) {
        if (bc_wallets->wallets[i].type == bc_type) {
            bc_wallet_info = &bc_wallets->wallets[i];
            break;
        }
    }

    if (!bc_wallet_info) {
        QGP_LOG_ERROR(LOG_TAG, "No wallet found for network: %s", network);
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    (void)wallet_index; /* wallet_index no longer used - network determines wallet */

    char tx_hash[128] = {0};

    QGP_LOG_INFO(LOG_TAG, "Sending %s: %s %s to %s (gas_speed=%d)",
                 chain_name, amount_str, token ? token : "(native)", recipient, gas_speed);

    /* Derive wallet from mnemonic and send (seed-based only, no wallet files) */
    {
        char mnemonic[512] = {0};
        if (dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic)) != DNA_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get mnemonic for send operation");
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        uint8_t master_seed[64];
        if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive master seed from mnemonic");
            qgp_secure_memzero(mnemonic, sizeof(mnemonic));
            error = DNA_ERROR_CRYPTO;
            goto done;
        }

        int send_rc = blockchain_send_tokens_with_seed(
            bc_type,
            master_seed,
            mnemonic,
            recipient,
            amount_str,
            token,
            gas_speed,
            tx_hash
        );

        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        if (send_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed, rc=%d", chain_name, send_rc);
            if (send_rc == -2) {
                error = DNA_ENGINE_ERROR_INSUFFICIENT_BALANCE;
            } else if (send_rc == -3) {
                error = DNA_ENGINE_ERROR_RENT_MINIMUM;
            } else {
                error = DNA_ENGINE_ERROR_NETWORK;
            }
            goto done;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "%s tx sent: %s", chain_name, tx_hash);
    error = DNA_OK;

done:
    task->callback.send_tokens(task->request_id, error,
                               error == DNA_OK ? tx_hash : NULL,
                               task->user_data);
}

/* Network fee collector address for filtering transactions */
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"

void dna_handle_get_transactions(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_transaction_t *transactions = NULL;
    int count = 0;
    cellframe_rpc_response_t *resp = NULL;

    if (!engine->wallets_loaded || !engine->blockchain_wallets) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* Get wallet address */
    int wallet_index = task->params.get_transactions.wallet_index;
    const char *network = task->params.get_transactions.network;

    blockchain_wallet_list_t *wallets = engine->blockchain_wallets;
    if (wallet_index < 0 || wallet_index >= (int)wallets->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    blockchain_wallet_info_t *wallet_info = &wallets->wallets[wallet_index];

    if (wallet_info->address[0] == '\0') {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* ETH transactions via Etherscan API */
    if (wallet_info->type == BLOCKCHAIN_ETHEREUM) {
        eth_transaction_t *eth_txs = NULL;
        int eth_count = 0;

        if (eth_rpc_get_transactions(wallet_info->address, &eth_txs, &eth_count) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        if (eth_count > 0 && eth_txs) {
            transactions = calloc(eth_count, sizeof(dna_transaction_t));
            if (!transactions) {
                eth_rpc_free_transactions(eth_txs, eth_count);
                error = DNA_ERROR_INTERNAL;
                goto done;
            }

            for (int i = 0; i < eth_count; i++) {
                strncpy(transactions[i].tx_hash, eth_txs[i].tx_hash,
                        sizeof(transactions[i].tx_hash) - 1);
                strncpy(transactions[i].token, "ETH", sizeof(transactions[i].token) - 1);
                strncpy(transactions[i].amount, eth_txs[i].value,
                        sizeof(transactions[i].amount) - 1);
                snprintf(transactions[i].timestamp, sizeof(transactions[i].timestamp),
                        "%llu", (unsigned long long)eth_txs[i].timestamp);

                if (eth_txs[i].is_outgoing) {
                    strncpy(transactions[i].direction, "sent",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, eth_txs[i].to,
                            sizeof(transactions[i].other_address) - 1);
                } else {
                    strncpy(transactions[i].direction, "received",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, eth_txs[i].from,
                            sizeof(transactions[i].other_address) - 1);
                }

                strncpy(transactions[i].status,
                        eth_txs[i].is_confirmed ? "CONFIRMED" : "FAILED",
                        sizeof(transactions[i].status) - 1);
            }
            count = eth_count;
            eth_rpc_free_transactions(eth_txs, eth_count);
        }
        goto done;
    }

    /* TRON transactions via TronGrid API */
    if (wallet_info->type == BLOCKCHAIN_TRON) {
        trx_transaction_t *trx_txs = NULL;
        int trx_count = 0;

        if (trx_rpc_get_transactions(wallet_info->address, &trx_txs, &trx_count) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        if (trx_count > 0 && trx_txs) {
            transactions = calloc(trx_count, sizeof(dna_transaction_t));
            if (!transactions) {
                trx_rpc_free_transactions(trx_txs, trx_count);
                error = DNA_ERROR_INTERNAL;
                goto done;
            }

            for (int i = 0; i < trx_count; i++) {
                strncpy(transactions[i].tx_hash, trx_txs[i].tx_hash,
                        sizeof(transactions[i].tx_hash) - 1);
                strncpy(transactions[i].token, "TRX", sizeof(transactions[i].token) - 1);
                strncpy(transactions[i].amount, trx_txs[i].value,
                        sizeof(transactions[i].amount) - 1);
                snprintf(transactions[i].timestamp, sizeof(transactions[i].timestamp),
                        "%llu", (unsigned long long)(trx_txs[i].timestamp / 1000)); /* ms to sec */

                if (trx_txs[i].is_outgoing) {
                    strncpy(transactions[i].direction, "sent",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, trx_txs[i].to,
                            sizeof(transactions[i].other_address) - 1);
                } else {
                    strncpy(transactions[i].direction, "received",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, trx_txs[i].from,
                            sizeof(transactions[i].other_address) - 1);
                }

                strncpy(transactions[i].status,
                        trx_txs[i].is_confirmed ? "CONFIRMED" : "PENDING",
                        sizeof(transactions[i].status) - 1);
            }
            count = trx_count;
            trx_rpc_free_transactions(trx_txs, trx_count);
        }
        goto done;
    }

    /* Solana transactions via Solana RPC */
    if (wallet_info->type == BLOCKCHAIN_SOLANA) {
        sol_transaction_t *sol_txs = NULL;
        int sol_count = 0;

        if (sol_rpc_get_transactions(wallet_info->address, &sol_txs, &sol_count) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        if (sol_count > 0 && sol_txs) {
            transactions = calloc(sol_count, sizeof(dna_transaction_t));
            if (!transactions) {
                sol_rpc_free_transactions(sol_txs, sol_count);
                error = DNA_ERROR_INTERNAL;
                goto done;
            }

            for (int i = 0; i < sol_count; i++) {
                strncpy(transactions[i].tx_hash, sol_txs[i].signature,
                        sizeof(transactions[i].tx_hash) - 1);
                strncpy(transactions[i].token, "SOL", sizeof(transactions[i].token) - 1);

                /* Convert lamports to SOL */
                if (sol_txs[i].lamports > 0) {
                    double sol_amount = (double)sol_txs[i].lamports / 1000000000.0;
                    snprintf(transactions[i].amount, sizeof(transactions[i].amount),
                            "%.9f", sol_amount);
                    /* Trim trailing zeros */
                    char *dot = strchr(transactions[i].amount, '.');
                    if (dot) {
                        char *end = transactions[i].amount + strlen(transactions[i].amount) - 1;
                        while (end > dot && *end == '0') {
                            *end-- = '\0';
                        }
                        if (end == dot) {
                            /* Bounds-checked: ensure space for ".0\0" (3 bytes) */
                            size_t remaining = sizeof(transactions[i].amount) - (size_t)(dot - transactions[i].amount);
                            if (remaining >= 3) {
                                dot[0] = '.';
                                dot[1] = '0';
                                dot[2] = '\0';
                            }
                        }
                    }
                } else {
                    strncpy(transactions[i].amount, "0", sizeof(transactions[i].amount) - 1);
                }

                snprintf(transactions[i].timestamp, sizeof(transactions[i].timestamp),
                        "%lld", (long long)sol_txs[i].block_time);

                /* Set direction and other address */
                if (sol_txs[i].is_outgoing) {
                    strncpy(transactions[i].direction, "sent",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, sol_txs[i].to,
                            sizeof(transactions[i].other_address) - 1);
                } else {
                    strncpy(transactions[i].direction, "received",
                            sizeof(transactions[i].direction) - 1);
                    strncpy(transactions[i].other_address, sol_txs[i].from,
                            sizeof(transactions[i].other_address) - 1);
                }

                strncpy(transactions[i].status,
                        sol_txs[i].success ? "CONFIRMED" : "FAILED",
                        sizeof(transactions[i].status) - 1);
            }
            count = sol_count;
            sol_rpc_free_transactions(sol_txs, sol_count);
        }
        goto done;
    }

    /* Query transaction history from RPC (Cellframe) */
    if (cellframe_rpc_get_tx_history(network, wallet_info->address, &resp) != 0 || !resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to query tx history from RPC\n");
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    if (!resp->result) {
        /* No transactions - return empty list */
        goto done;
    }

    /* Parse response: result[0] = {addr, limit}, result[1..n] = transactions */
    if (!json_object_is_type(resp->result, json_type_array)) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* First element is array with addr/limit, skip it */
    /* Count actual transaction objects (starting from index 1) */
    int array_len = json_object_array_length(resp->result);
    if (array_len <= 1) {
        /* Only header, no transactions */
        goto done;
    }

    /* First array element contains addr and limit objects */
    json_object *first_elem = json_object_array_get_idx(resp->result, 0);
    if (!first_elem || !json_object_is_type(first_elem, json_type_array)) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Get transactions array - it's inside first_elem starting at index 2 */
    int tx_array_len = json_object_array_length(first_elem);
    int tx_count = tx_array_len - 2;  /* Skip addr and limit objects */

    if (tx_count <= 0) {
        goto done;
    }

    /* Allocate transactions array */
    transactions = calloc(tx_count, sizeof(dna_transaction_t));
    if (!transactions) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Parse each transaction */
    for (int i = 0; i < tx_count; i++) {
        json_object *tx_obj = json_object_array_get_idx(first_elem, i + 2);
        if (!tx_obj) continue;

        json_object *jhash = NULL, *jstatus = NULL, *jtx_created = NULL, *jdata = NULL;

        json_object_object_get_ex(tx_obj, "hash", &jhash);
        json_object_object_get_ex(tx_obj, "status", &jstatus);
        json_object_object_get_ex(tx_obj, "tx_created", &jtx_created);
        json_object_object_get_ex(tx_obj, "data", &jdata);

        /* Copy hash */
        if (jhash) {
            strncpy(transactions[count].tx_hash, json_object_get_string(jhash),
                    sizeof(transactions[count].tx_hash) - 1);
        }

        /* Copy status */
        if (jstatus) {
            strncpy(transactions[count].status, json_object_get_string(jstatus),
                    sizeof(transactions[count].status) - 1);
        }

        /* Copy timestamp */
        if (jtx_created) {
            strncpy(transactions[count].timestamp, json_object_get_string(jtx_created),
                    sizeof(transactions[count].timestamp) - 1);
        }

        /* Parse data - can be array (old format) or object (new format) */
        if (jdata) {
            json_object *jtx_type = NULL, *jtoken = NULL;
            json_object *jrecv_coins = NULL, *jsend_coins = NULL;
            json_object *jsrc_addr = NULL, *jdst_addr = NULL;
            json_object *jaddr_from = NULL, *jaddrs_to = NULL;

            if (json_object_is_type(jdata, json_type_array)) {
                /* Old format: data is array, use first item */
                if (json_object_array_length(jdata) > 0) {
                    json_object *data_item = json_object_array_get_idx(jdata, 0);
                    if (data_item) {
                        json_object_object_get_ex(data_item, "tx_type", &jtx_type);
                        json_object_object_get_ex(data_item, "token", &jtoken);
                        json_object_object_get_ex(data_item, "recv_coins", &jrecv_coins);
                        json_object_object_get_ex(data_item, "send_coins", &jsend_coins);
                        json_object_object_get_ex(data_item, "source_address", &jsrc_addr);
                        json_object_object_get_ex(data_item, "destination_address", &jdst_addr);
                    }
                }
            } else if (json_object_is_type(jdata, json_type_object)) {
                /* New format: data is object with address_from, addresses_to */
                json_object_object_get_ex(jdata, "ticker", &jtoken);
                json_object_object_get_ex(jdata, "address_from", &jaddr_from);
                json_object_object_get_ex(jdata, "addresses_to", &jaddrs_to);
            }

            /* Determine direction and parse addresses */
            if (jtx_type) {
                /* Old format with tx_type */
                const char *tx_type = json_object_get_string(jtx_type);
                if (strcmp(tx_type, "recv") == 0) {
                    strncpy(transactions[count].direction, "received",
                            sizeof(transactions[count].direction) - 1);
                    if (jrecv_coins) {
                        strncpy(transactions[count].amount, json_object_get_string(jrecv_coins),
                                sizeof(transactions[count].amount) - 1);
                    }
                    if (jsrc_addr) {
                        strncpy(transactions[count].other_address, json_object_get_string(jsrc_addr),
                                sizeof(transactions[count].other_address) - 1);
                    }
                } else if (strcmp(tx_type, "send") == 0) {
                    strncpy(transactions[count].direction, "sent",
                            sizeof(transactions[count].direction) - 1);
                    if (jsend_coins) {
                        strncpy(transactions[count].amount, json_object_get_string(jsend_coins),
                                sizeof(transactions[count].amount) - 1);
                    }
                    /* For destination, skip network fee collector address */
                    if (jdst_addr) {
                        const char *dst = json_object_get_string(jdst_addr);
                        if (dst && strcmp(dst, NETWORK_FEE_COLLECTOR) != 0 &&
                            strstr(dst, "DAP_CHAIN") == NULL) {
                            strncpy(transactions[count].other_address, dst,
                                    sizeof(transactions[count].other_address) - 1);
                        }
                    }
                }
            } else if (jaddr_from && jaddrs_to) {
                /* New format: determine direction by comparing wallet address */
                const char *from_addr = json_object_get_string(jaddr_from);

                /* Check if we sent this (our address is sender) */
                if (from_addr && strcmp(from_addr, wallet_info->address) == 0) {
                    strncpy(transactions[count].direction, "sent",
                            sizeof(transactions[count].direction) - 1);

                    /* Find recipient (first non-fee address in addresses_to) */
                    if (json_object_is_type(jaddrs_to, json_type_array)) {
                        int addrs_len = json_object_array_length(jaddrs_to);
                        for (int k = 0; k < addrs_len; k++) {
                            json_object *addr_entry = json_object_array_get_idx(jaddrs_to, k);
                            if (!addr_entry) continue;

                            json_object *jaddr = NULL, *jval = NULL;
                            json_object_object_get_ex(addr_entry, "address", &jaddr);
                            json_object_object_get_ex(addr_entry, "value", &jval);

                            if (jaddr) {
                                const char *addr = json_object_get_string(jaddr);
                                /* Skip fee collector and change addresses (back to sender) */
                                if (addr && strcmp(addr, NETWORK_FEE_COLLECTOR) != 0 &&
                                    strcmp(addr, from_addr) != 0) {
                                    strncpy(transactions[count].other_address, addr,
                                            sizeof(transactions[count].other_address) - 1);
                                    if (jval) {
                                        strncpy(transactions[count].amount, json_object_get_string(jval),
                                                sizeof(transactions[count].amount) - 1);
                                    }
                                    break;  /* Use first valid recipient */
                                }
                            }
                        }
                    }
                } else {
                    /* We received this */
                    strncpy(transactions[count].direction, "received",
                            sizeof(transactions[count].direction) - 1);
                    if (from_addr) {
                        strncpy(transactions[count].other_address, from_addr,
                                sizeof(transactions[count].other_address) - 1);
                    }

                    /* Find amount sent to us */
                    if (json_object_is_type(jaddrs_to, json_type_array)) {
                        int addrs_len = json_object_array_length(jaddrs_to);
                        for (int k = 0; k < addrs_len; k++) {
                            json_object *addr_entry = json_object_array_get_idx(jaddrs_to, k);
                            if (!addr_entry) continue;

                            json_object *jaddr = NULL, *jval = NULL;
                            json_object_object_get_ex(addr_entry, "address", &jaddr);
                            json_object_object_get_ex(addr_entry, "value", &jval);

                            if (jaddr) {
                                const char *addr = json_object_get_string(jaddr);
                                if (addr && strcmp(addr, wallet_info->address) == 0 && jval) {
                                    strncpy(transactions[count].amount, json_object_get_string(jval),
                                            sizeof(transactions[count].amount) - 1);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (jtoken) {
                strncpy(transactions[count].token, json_object_get_string(jtoken),
                        sizeof(transactions[count].token) - 1);
            }
        }

        count++;
    }

done:
    if (resp) cellframe_rpc_response_free(resp);
    task->callback.transactions(task->request_id, error, transactions, count, task->user_data);
}

/* ============================================================================
 * WALLET PUBLIC API WRAPPERS
 * ============================================================================ */

dna_request_id_t dna_engine_list_wallets(
    dna_engine_t *engine,
    dna_wallets_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .wallets = callback };
    return dna_submit_task(engine, TASK_LIST_WALLETS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
) {
    if (!engine || !callback || wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.get_balances.wallet_index = wallet_index;

    dna_task_callback_t cb = { .balances = callback };
    return dna_submit_task(engine, TASK_GET_BALANCES, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_cached_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
) {
    if (!engine || !callback || wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.get_balances.wallet_index = wallet_index;

    dna_task_callback_t cb = { .balances = callback };
    return dna_submit_task(engine, TASK_GET_CACHED_BALANCES, &params, cb, user_data);
}

int dna_engine_estimate_eth_gas(int gas_speed, dna_gas_estimate_t *estimate_out) {
    if (!estimate_out) return -1;
    if (gas_speed < 0 || gas_speed > 2) gas_speed = 1;

    blockchain_gas_estimate_t bc_estimate;
    if (blockchain_estimate_eth_gas(gas_speed, &bc_estimate) != 0) {
        return -1;
    }

    /* Copy to public struct */
    strncpy(estimate_out->fee_eth, bc_estimate.fee_eth, sizeof(estimate_out->fee_eth) - 1);
    estimate_out->gas_price = bc_estimate.gas_price;
    estimate_out->gas_limit = bc_estimate.gas_limit;

    return 0;
}

/* Gas speed multipliers (percent) - must match blockchain_wallet.c */
static const int ENGINE_GAS_MULTIPLIERS[] = { 80, 100, 150 };

static void fill_gas_estimate(dna_gas_estimate_t *out, uint64_t base_gas_price,
                               int multiplier_pct, uint64_t gas_limit) {
    uint64_t adjusted_price = (base_gas_price * multiplier_pct) / 100;
    uint64_t total_fee_wei = adjusted_price * gas_limit;
    double fee_eth = (double)total_fee_wei / 1000000000000000000.0;

    out->gas_price = adjusted_price;
    out->gas_limit = gas_limit;
    snprintf(out->fee_eth, sizeof(out->fee_eth), "%.6f", fee_eth);
}

void dna_handle_estimate_gas(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    /* Single RPC call: get base gas price via normal speed (100% = raw price) */
    blockchain_gas_estimate_t bc_estimate;
    if (blockchain_estimate_eth_gas(1, &bc_estimate) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "estimate_gas: RPC failed");
        if (task->callback.gas_estimates) {
            task->callback.gas_estimates(task->request_id, -1, NULL, task->user_data);
        }
        return;
    }

    /* bc_estimate.gas_price is already the raw base price (1.0x multiplier) */
    uint64_t base_gas_price = bc_estimate.gas_price;
    uint64_t gas_limit = bc_estimate.gas_limit;

    dna_gas_estimates_t estimates;
    memset(&estimates, 0, sizeof(estimates));
    fill_gas_estimate(&estimates.slow,   base_gas_price, ENGINE_GAS_MULTIPLIERS[0], gas_limit);
    fill_gas_estimate(&estimates.normal, base_gas_price, ENGINE_GAS_MULTIPLIERS[1], gas_limit);
    fill_gas_estimate(&estimates.fast,   base_gas_price, ENGINE_GAS_MULTIPLIERS[2], gas_limit);

    QGP_LOG_DEBUG(LOG_TAG, "estimate_gas: slow=%s normal=%s fast=%s ETH",
                  estimates.slow.fee_eth, estimates.normal.fee_eth, estimates.fast.fee_eth);

    if (task->callback.gas_estimates) {
        task->callback.gas_estimates(task->request_id, 0, &estimates, task->user_data);
    }
}

dna_request_id_t dna_engine_estimate_gas_async(
    dna_engine_t *engine,
    dna_gas_estimates_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .gas_estimates = callback };
    return dna_submit_task(engine, TASK_ESTIMATE_GAS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_send_tokens(
    dna_engine_t *engine,
    int wallet_index,
    const char *recipient_address,
    const char *amount,
    const char *token,
    const char *network,
    int gas_speed,
    dna_send_tokens_cb callback,
    void *user_data
) {
    QGP_LOG_INFO(LOG_TAG, "send_tokens: wallet=%d to=%s amount=%s token=%s network=%s gas=%d",
            wallet_index, recipient_address ? recipient_address : "NULL",
            amount ? amount : "NULL", token ? token : "NULL",
            network ? network : "NULL", gas_speed);

    if (!engine || !recipient_address || !amount || !token || !network || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "send_tokens: invalid params");
        return DNA_REQUEST_ID_INVALID;
    }
    if (wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.send_tokens.wallet_index = wallet_index;
    strncpy(params.send_tokens.recipient, recipient_address, sizeof(params.send_tokens.recipient) - 1);
    strncpy(params.send_tokens.amount, amount, sizeof(params.send_tokens.amount) - 1);
    strncpy(params.send_tokens.token, token, sizeof(params.send_tokens.token) - 1);
    strncpy(params.send_tokens.network, network, sizeof(params.send_tokens.network) - 1);
    params.send_tokens.gas_speed = gas_speed;

    dna_task_callback_t cb = { .send_tokens = callback };
    return dna_submit_task(engine, TASK_SEND_TOKENS, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_transactions(
    dna_engine_t *engine,
    int wallet_index,
    const char *network,
    dna_transactions_cb callback,
    void *user_data
) {
    if (!engine || !network || !callback || wallet_index < 0) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    params.get_transactions.wallet_index = wallet_index;
    strncpy(params.get_transactions.network, network, sizeof(params.get_transactions.network) - 1);

    dna_task_callback_t cb = { .transactions = callback };
    return dna_submit_task(engine, TASK_GET_TRANSACTIONS, &params, cb, user_data);
}

/* ============================================================================
 * DEX TASK HANDLERS
 * ============================================================================ */

/**
 * Helper: detect chain from token symbols.
 * Returns "SOL" for Solana pairs, "ETH" for Ethereum pairs, NULL if unknown.
 */
static const char *detect_dex_chain(const char *from_token, const char *to_token) {
    /* SOL-native tokens */
    if (strcasecmp(from_token, "SOL") == 0 || strcasecmp(to_token, "SOL") == 0)
        return "SOL";
    /* ETH-native tokens */
    if (strcasecmp(from_token, "ETH") == 0 || strcasecmp(to_token, "ETH") == 0)
        return "ETH";
    /* Cellframe-native tokens */
    if (strcasecmp(from_token, "CELL") == 0 || strcasecmp(to_token, "CELL") == 0 ||
        strcasecmp(from_token, "CPUNK") == 0 || strcasecmp(to_token, "CPUNK") == 0 ||
        strcasecmp(from_token, "KEL") == 0 || strcasecmp(to_token, "KEL") == 0 ||
        strcasecmp(from_token, "QEVM") == 0 || strcasecmp(to_token, "QEVM") == 0 ||
        strcasecmp(from_token, "mCELL") == 0 || strcasecmp(to_token, "mCELL") == 0 ||
        strcasecmp(from_token, "mKEL") == 0 || strcasecmp(to_token, "mKEL") == 0)
        return "CELL";
    /* Stablecoin pairs — try SOL first (higher liquidity) */
    return NULL;
}

void dna_handle_dex_quote(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    const char *from_token = task->params.dex_quote.from_token;
    const char *to_token   = task->params.dex_quote.to_token;
    const char *amount_in  = task->params.dex_quote.amount_in;
    const char *dex_filter = task->params.dex_quote.dex_filter[0]
                           ? task->params.dex_quote.dex_filter : NULL;

    const char *chain = detect_dex_chain(from_token, to_token);

    /* Collect quotes from all chains into a single array */
    dna_dex_quote_t all_quotes[16];
    int total = 0;

    /* Solana DEX quotes */
    if (!chain || strcmp(chain, "SOL") == 0) {
        sol_dex_quote_t sol_quotes[8];
        int sol_count = 0;
        int rc = sol_dex_get_quotes(from_token, to_token, amount_in,
                                     dex_filter, sol_quotes, 8, &sol_count);
        if (rc == 0) {
            for (int i = 0; i < sol_count && total < 16; i++) {
                dna_dex_quote_t *q = &all_quotes[total];
                memset(q, 0, sizeof(*q));
                strncpy(q->from_token, sol_quotes[i].from_token, sizeof(q->from_token) - 1);
                strncpy(q->to_token, sol_quotes[i].to_token, sizeof(q->to_token) - 1);
                strncpy(q->amount_in, sol_quotes[i].amount_in, sizeof(q->amount_in) - 1);
                strncpy(q->amount_out, sol_quotes[i].amount_out, sizeof(q->amount_out) - 1);
                strncpy(q->price, sol_quotes[i].price, sizeof(q->price) - 1);
                strncpy(q->price_impact, sol_quotes[i].price_impact, sizeof(q->price_impact) - 1);
                strncpy(q->fee, sol_quotes[i].fee, sizeof(q->fee) - 1);
                strncpy(q->pool_address, sol_quotes[i].pool_address, sizeof(q->pool_address) - 1);
                strncpy(q->dex_name, sol_quotes[i].dex_name, sizeof(q->dex_name) - 1);
                strncpy(q->chain, "SOL", sizeof(q->chain) - 1);
                total++;
            }
        }
    }

    /* Ethereum DEX quotes */
    if (!chain || strcmp(chain, "ETH") == 0) {
        eth_dex_quote_t eth_quotes[8];
        int eth_count = 0;
        int rc = eth_dex_get_quotes(from_token, to_token, amount_in,
                                     dex_filter, eth_quotes, 8, &eth_count);
        if (rc == 0) {
            for (int i = 0; i < eth_count && total < 16; i++) {
                dna_dex_quote_t *q = &all_quotes[total];
                memset(q, 0, sizeof(*q));
                strncpy(q->from_token, eth_quotes[i].from_token, sizeof(q->from_token) - 1);
                strncpy(q->to_token, eth_quotes[i].to_token, sizeof(q->to_token) - 1);
                strncpy(q->amount_in, eth_quotes[i].amount_in, sizeof(q->amount_in) - 1);
                strncpy(q->amount_out, eth_quotes[i].amount_out, sizeof(q->amount_out) - 1);
                strncpy(q->price, eth_quotes[i].price, sizeof(q->price) - 1);
                strncpy(q->price_impact, eth_quotes[i].price_impact, sizeof(q->price_impact) - 1);
                strncpy(q->fee, eth_quotes[i].fee, sizeof(q->fee) - 1);
                strncpy(q->pool_address, eth_quotes[i].pool_address, sizeof(q->pool_address) - 1);
                strncpy(q->dex_name, eth_quotes[i].dex_name, sizeof(q->dex_name) - 1);
                strncpy(q->chain, "ETH", sizeof(q->chain) - 1);
                total++;
            }
        }
    }

    /* Cellframe DEX quotes */
    if (!chain || strcmp(chain, "CELL") == 0) {
        cell_dex_quote_t cell_quotes[8];
        int cell_count = 0;
        int rc = cell_dex_get_quotes(from_token, to_token, amount_in,
                                      dex_filter, cell_quotes, 8, &cell_count);
        if (rc == 0) {
            for (int i = 0; i < cell_count && total < 16; i++) {
                dna_dex_quote_t *q = &all_quotes[total];
                memset(q, 0, sizeof(*q));
                strncpy(q->from_token, cell_quotes[i].from_token, sizeof(q->from_token) - 1);
                strncpy(q->to_token, cell_quotes[i].to_token, sizeof(q->to_token) - 1);
                strncpy(q->amount_in, cell_quotes[i].amount_in, sizeof(q->amount_in) - 1);
                strncpy(q->amount_out, cell_quotes[i].amount_out, sizeof(q->amount_out) - 1);
                strncpy(q->price, cell_quotes[i].price, sizeof(q->price) - 1);
                strncpy(q->price_impact, cell_quotes[i].price_impact, sizeof(q->price_impact) - 1);
                strncpy(q->fee, cell_quotes[i].fee, sizeof(q->fee) - 1);
                strncpy(q->pool_address, cell_quotes[i].pool_address, sizeof(q->pool_address) - 1);
                strncpy(q->dex_name, cell_quotes[i].dex_name, sizeof(q->dex_name) - 1);
                strncpy(q->chain, "CELL", sizeof(q->chain) - 1);
                if (cell_quotes[i].stale_warning) {
                    strncpy(q->warning,
                            "Quote based on stale orders (pending migration) - may not reflect actual prices",
                            sizeof(q->warning) - 1);
                }
                total++;
            }
        }
    }

    if (total == 0) {
        if (task->callback.dex_quote) {
            task->callback.dex_quote(task->request_id, DNA_ENGINE_ERROR_NOT_FOUND,
                                     NULL, 0, task->user_data);
        }
        return;
    }

    if (task->callback.dex_quote) {
        task->callback.dex_quote(task->request_id, DNA_OK, all_quotes, total,
                                 task->user_data);
    }
}

void dna_handle_dex_list_pairs(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    /* Collect pairs from both chains */
    char **sol_pairs = NULL, **eth_pairs = NULL;
    int sol_count = 0, eth_count = 0;

    sol_dex_list_pairs(&sol_pairs, &sol_count);
    eth_dex_list_pairs(&eth_pairs, &eth_count);

    int total = sol_count + eth_count;
    if (total == 0) {
        if (task->callback.dex_pairs) {
            task->callback.dex_pairs(task->request_id, DNA_ENGINE_ERROR_NETWORK, NULL, 0, task->user_data);
        }
        return;
    }

    /* Merge into single array */
    char **all_pairs = calloc((size_t)total, sizeof(char *));
    if (!all_pairs) {
        sol_dex_free_pairs(sol_pairs, sol_count);
        eth_dex_free_pairs(eth_pairs, eth_count);
        if (task->callback.dex_pairs) {
            task->callback.dex_pairs(task->request_id, DNA_ENGINE_ERROR_NETWORK, NULL, 0, task->user_data);
        }
        return;
    }

    int idx = 0;
    for (int i = 0; i < sol_count; i++) {
        all_pairs[idx] = malloc(48);
        if (all_pairs[idx]) {
            snprintf(all_pairs[idx], 48, "[SOL] %s", sol_pairs[i]);
        }
        idx++;
    }
    for (int i = 0; i < eth_count; i++) {
        all_pairs[idx] = malloc(48);
        if (all_pairs[idx]) {
            snprintf(all_pairs[idx], 48, "[ETH] %s", eth_pairs[i]);
        }
        idx++;
    }

    /* Cellframe pairs */
    char **cell_pairs = NULL;
    int cell_count = 0;
    cell_dex_list_pairs(&cell_pairs, &cell_count);

    /* Re-count total with Cellframe */
    total += cell_count;

    /* Expand array if needed */
    if (cell_count > 0) {
        char **expanded = realloc(all_pairs, (size_t)total * sizeof(char *));
        if (expanded) {
            all_pairs = expanded;
            for (int i = 0; i < cell_count; i++) {
                all_pairs[idx] = malloc(48);
                if (all_pairs[idx]) {
                    snprintf(all_pairs[idx], 48, "[CELL] %s", cell_pairs[i]);
                }
                idx++;
            }
        }
    }

    sol_dex_free_pairs(sol_pairs, sol_count);
    eth_dex_free_pairs(eth_pairs, eth_count);
    cell_dex_free_pairs(cell_pairs, cell_count);

    if (task->callback.dex_pairs) {
        task->callback.dex_pairs(task->request_id, DNA_OK, (const char **)all_pairs, total, task->user_data);
    }

    for (int i = 0; i < total; i++) free(all_pairs[i]);
    free(all_pairs);
}

/* ============ DEX PUBLIC API ============ */

dna_request_id_t dna_engine_dex_quote(
    dna_engine_t *engine,
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    dna_dex_quote_cb callback,
    void *user_data
) {
    if (!engine || !from_token || !to_token || !amount_in || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.dex_quote.from_token, from_token, sizeof(params.dex_quote.from_token) - 1);
    strncpy(params.dex_quote.to_token, to_token, sizeof(params.dex_quote.to_token) - 1);
    strncpy(params.dex_quote.amount_in, amount_in, sizeof(params.dex_quote.amount_in) - 1);
    if (dex_filter && dex_filter[0]) {
        strncpy(params.dex_quote.dex_filter, dex_filter,
                sizeof(params.dex_quote.dex_filter) - 1);
    }

    dna_task_callback_t cb = { .dex_quote = callback };
    return dna_submit_task(engine, TASK_DEX_QUOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_dex_list_pairs(
    dna_engine_t *engine,
    dna_dex_pairs_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    dna_task_callback_t cb = { .dex_pairs = callback };
    return dna_submit_task(engine, TASK_DEX_LIST_PAIRS, &params, cb, user_data);
}

/* ============ DEX SWAP ============ */

void dna_handle_dex_swap(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_dex_swap_result_t result = {0};

    const char *from_token = task->params.dex_swap.from_token;
    const char *to_token   = task->params.dex_swap.to_token;
    const char *amount_in  = task->params.dex_swap.amount_in;

    QGP_LOG_INFO(LOG_TAG, "DEX swap: %s %s -> %s", amount_in, from_token, to_token);

    /* Derive Solana wallet from mnemonic */
    char mnemonic[512] = {0};
    if (dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic)) != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get mnemonic for DEX swap");
        error = DNA_ERROR_CRYPTO;
        goto done;
    }

    uint8_t master_seed[64];
    if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive master seed for DEX swap");
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        error = DNA_ERROR_CRYPTO;
        goto done;
    }
    qgp_secure_memzero(mnemonic, sizeof(mnemonic));

    {
        sol_wallet_t sol_wallet;
        if (sol_wallet_generate(master_seed, 64, &sol_wallet) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to generate Solana wallet for DEX swap");
            qgp_secure_memzero(master_seed, sizeof(master_seed));
            error = DNA_ERROR_CRYPTO;
            goto done;
        }
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        sol_dex_swap_result_t sol_result = {0};
        int rc = sol_dex_execute_swap(&sol_wallet, from_token, to_token, amount_in, &sol_result);
        sol_wallet_clear(&sol_wallet);

        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "DEX swap failed, rc=%d", rc);
            if (rc == -2) {
                error = DNA_ERROR_INVALID_ARG;  /* Token pair not found */
            } else {
                error = DNA_ENGINE_ERROR_NETWORK;
            }
            goto done;
        }

        /* Copy sol_dex_swap_result_t -> dna_dex_swap_result_t */
        strncpy(result.tx_signature, sol_result.tx_signature, sizeof(result.tx_signature) - 1);
        strncpy(result.amount_in, sol_result.amount_in, sizeof(result.amount_in) - 1);
        strncpy(result.amount_out, sol_result.amount_out, sizeof(result.amount_out) - 1);
        strncpy(result.from_token, sol_result.from_token, sizeof(result.from_token) - 1);
        strncpy(result.to_token, sol_result.to_token, sizeof(result.to_token) - 1);
        strncpy(result.dex_name, sol_result.dex_name, sizeof(result.dex_name) - 1);
        strncpy(result.price_impact, sol_result.price_impact, sizeof(result.price_impact) - 1);
    }

done:
    if (task->callback.dex_swap) {
        dna_dex_swap_result_t *result_ptr = (error == DNA_OK) ? &result : NULL;
        task->callback.dex_swap(task->request_id, error, result_ptr, task->user_data);
    }
}

dna_request_id_t dna_engine_dex_swap(
    dna_engine_t *engine,
    int wallet_index,
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    dna_dex_swap_cb callback,
    void *user_data
) {
    if (!engine || !from_token || !to_token || !amount_in || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    params.dex_swap.wallet_index = wallet_index;
    strncpy(params.dex_swap.from_token, from_token, sizeof(params.dex_swap.from_token) - 1);
    strncpy(params.dex_swap.to_token, to_token, sizeof(params.dex_swap.to_token) - 1);
    strncpy(params.dex_swap.amount_in, amount_in, sizeof(params.dex_swap.amount_in) - 1);

    dna_task_callback_t cb = { .dex_swap = callback };
    return dna_submit_task(engine, TASK_DEX_SWAP, &params, cb, user_data);
}
