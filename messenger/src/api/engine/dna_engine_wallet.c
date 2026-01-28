/*
 * DNA Engine - Wallet Module
 *
 * Blockchain wallet handling extracted from dna_engine.c.
 * Contains multi-chain wallet operations: ETH, SOL, TRX, Cellframe.
 *
 * Functions:
 *   - dna_handle_list_wallets()
 *   - dna_handle_get_balances()
 *   - dna_handle_send_tokens()
 *   - dna_handle_get_transactions()
 */

#define DNA_ENGINE_WALLET_IMPL
#include "engine_includes.h"

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

    /* Try to load wallets from wallet files first */
    int rc = blockchain_list_wallets(engine->fingerprint, &engine->blockchain_wallets);

    /* If no wallet files found, derive wallets on-demand from mnemonic */
    if (rc == 0 && engine->blockchain_wallets && engine->blockchain_wallets->count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No wallet files found, deriving wallets on-demand from mnemonic");

        /* Free the empty list */
        blockchain_wallet_list_free(engine->blockchain_wallets);
        engine->blockchain_wallets = NULL;

        /* Load and decrypt mnemonic */
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
        rc = blockchain_derive_wallets_from_seed(master_seed, mnemonic, engine->fingerprint, &engine->blockchain_wallets);

        /* Clear sensitive data from memory */
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        if (rc != 0 || !engine->blockchain_wallets) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive wallets from seed");
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }
    } else if (rc != 0 || !engine->blockchain_wallets) {
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
        /* Ethereum: ETH + USDT (ERC-20) */
        balances = calloc(2, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 2;

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

        goto done;
    }

    if (wallet_info->type == BLOCKCHAIN_TRON) {
        /* TRON: TRX + USDT (TRC-20) */
        balances = calloc(2, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 2;

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

        goto done;
    }

    if (wallet_info->type == BLOCKCHAIN_SOLANA) {
        /* Solana: SOL + USDT (SPL) */
        balances = calloc(2, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 2;

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
    task->callback.balances(task->request_id, error, balances, count, task->user_data);
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
    if (strcmp(network, "Ethereum") == 0) {
        bc_type = BLOCKCHAIN_ETHEREUM;
        chain_name = "Ethereum";
    } else if (strcmp(network, "Solana") == 0) {
        bc_type = BLOCKCHAIN_SOLANA;
        chain_name = "Solana";
    } else if (strcasecmp(network, "Tron") == 0) {
        bc_type = BLOCKCHAIN_TRON;
        chain_name = "TRON";
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

    /* Check if wallet has a file (legacy) or needs on-demand derivation */
    if (bc_wallet_info->file_path[0] != '\0') {
        /* Legacy: use wallet file */
        int send_rc = blockchain_send_tokens(
                bc_type,
                bc_wallet_info->file_path,
                recipient,
                amount_str,
                token,
                gas_speed,
                tx_hash);
        if (send_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed (wallet file), rc=%d", chain_name, send_rc);
            /* Map blockchain error codes to engine errors */
            if (send_rc == -2) {
                error = DNA_ENGINE_ERROR_INSUFFICIENT_BALANCE;
            } else if (send_rc == -3) {
                error = DNA_ENGINE_ERROR_RENT_MINIMUM;
            } else {
                error = DNA_ENGINE_ERROR_NETWORK;
            }
            goto done;
        }
    } else {
        /* On-demand derivation: derive wallet from mnemonic */
        QGP_LOG_INFO(LOG_TAG, "Using on-demand wallet derivation for %s", chain_name);

        /* Load and decrypt mnemonic */
        char mnemonic[512] = {0};
        if (dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic)) != DNA_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get mnemonic for send operation");
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

        /* Send using on-demand derived wallet
         * Note: mnemonic is passed for Cellframe (which uses SHA3-256 hash of mnemonic)
         * It will be cleared after this call completes */
        int send_rc = blockchain_send_tokens_with_seed(
            bc_type,
            master_seed,
            mnemonic,  /* For Cellframe - uses SHA3-256(mnemonic) instead of BIP39 seed */
            recipient,
            amount_str,
            token,
            gas_speed,
            tx_hash
        );

        /* Clear sensitive data from memory */
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        if (send_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s send failed (on-demand), rc=%d", chain_name, send_rc);
            /* Map blockchain error codes to engine errors */
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
