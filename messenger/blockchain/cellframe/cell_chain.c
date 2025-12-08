/**
 * @file cell_chain.c
 * @brief Cellframe blockchain_ops_t implementation
 *
 * Full implementation of Cellframe UTXO-based transactions.
 */

#include "../blockchain.h"
#include "cellframe_rpc.h"
#include "cellframe_addr.h"
#include "cellframe_wallet.h"
#include "cellframe_tx_builder.h"
#include "cellframe_sign.h"
#include "cellframe_json.h"
#include "cellframe_minimal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json.h>

#define LOG_TAG "CELL_CHAIN"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/base58.h"

/* Default network */
#define CELLFRAME_DEFAULT_NET "Backbone"

/* Fee constants (in datoshi = 10^-18 CELL) */
#define NETWORK_FEE_DATOSHI         2000000000000000ULL    /* 0.002 CELL */
#define DEFAULT_VALIDATOR_FEE_DATOSHI 100000000000000ULL   /* 0.0001 CELL */

/* Network fee collector address */
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"

/* UTXO structure for tracking */
typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} cell_utxo_t;

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

static int parse_utxos_from_response(
    cellframe_rpc_response_t *resp,
    cell_utxo_t **utxos_out,
    int *count_out
) {
    if (!resp || !resp->result || !utxos_out || !count_out) {
        return -1;
    }

    *utxos_out = NULL;
    *count_out = 0;

    if (!json_object_is_type(resp->result, json_type_array) ||
        json_object_array_length(resp->result) == 0) {
        return -1;
    }

    json_object *first_array = json_object_array_get_idx(resp->result, 0);
    if (!first_array || !json_object_is_type(first_array, json_type_array) ||
        json_object_array_length(first_array) == 0) {
        return -1;
    }

    json_object *first_item = json_object_array_get_idx(first_array, 0);
    json_object *outs_obj = NULL;

    if (!first_item || !json_object_object_get_ex(first_item, "outs", &outs_obj) ||
        !json_object_is_type(outs_obj, json_type_array)) {
        return -1;
    }

    int num_utxos = json_object_array_length(outs_obj);
    if (num_utxos == 0) {
        return 0; /* No UTXOs - not an error */
    }

    cell_utxo_t *utxos = calloc(num_utxos, sizeof(cell_utxo_t));
    if (!utxos) {
        return -1;
    }

    int valid = 0;
    for (int i = 0; i < num_utxos; i++) {
        json_object *utxo_obj = json_object_array_get_idx(outs_obj, i);
        json_object *jhash = NULL, *jidx = NULL, *jvalue = NULL;

        if (utxo_obj &&
            json_object_object_get_ex(utxo_obj, "prev_hash", &jhash) &&
            json_object_object_get_ex(utxo_obj, "out_prev_idx", &jidx) &&
            json_object_object_get_ex(utxo_obj, "value_datoshi", &jvalue)) {

            const char *hash_str = json_object_get_string(jhash);
            const char *value_str = json_object_get_string(jvalue);

            if (hash_str && strlen(hash_str) >= 66 &&
                hash_str[0] == '0' && hash_str[1] == 'x') {
                for (int j = 0; j < 32; j++) {
                    sscanf(hash_str + 2 + (j * 2), "%2hhx", &utxos[valid].hash.raw[j]);
                }
                utxos[valid].idx = json_object_get_int(jidx);
                cellframe_uint256_scan_uninteger(value_str, &utxos[valid].value);
                valid++;
            }
        }
    }

    if (valid == 0) {
        free(utxos);
        return 0;
    }

    *utxos_out = utxos;
    *count_out = valid;
    return 0;
}

static int select_utxos(
    cell_utxo_t *all_utxos,
    int all_count,
    uint256_t required,
    cell_utxo_t **selected_out,
    int *selected_count_out,
    uint256_t *total_out
) {
    if (!all_utxos || all_count == 0 || !selected_out || !selected_count_out || !total_out) {
        return -1;
    }

    cell_utxo_t *selected = calloc(all_count, sizeof(cell_utxo_t));
    if (!selected) {
        return -1;
    }

    uint256_t total = uint256_0;
    int count = 0;

    for (int i = 0; i < all_count; i++) {
        selected[count++] = all_utxos[i];
        SUM_256_256(total, all_utxos[i].value, &total);

        if (compare256(total, required) >= 0) {
            break;
        }
    }

    if (compare256(total, required) < 0) {
        free(selected);
        return -1; /* Insufficient funds */
    }

    *selected_out = selected;
    *selected_count_out = count;
    *total_out = total;
    return 0;
}

/* ============================================================================
 * INTERFACE IMPLEMENTATIONS
 * ============================================================================ */

static int cell_chain_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Cellframe chain initialized");
    return 0;
}

static void cell_chain_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "Cellframe chain cleanup");
}

static int cell_chain_get_balance(
    const char *address,
    const char *token,
    char *balance_out,
    size_t balance_out_size
) {
    if (!address || !balance_out || balance_out_size == 0) {
        return -1;
    }

    const char *tok = token ? token : "CELL";
    cellframe_rpc_response_t *resp = NULL;

    int ret = cellframe_rpc_get_balance(CELLFRAME_DEFAULT_NET, address, tok, &resp);
    if (ret != 0 || !resp) {
        snprintf(balance_out, balance_out_size, "0");
        return -1;
    }

    /* Parse balance from response - result[0][0].balance */
    if (resp->result && json_object_is_type(resp->result, json_type_array)) {
        json_object *first = json_object_array_get_idx(resp->result, 0);
        if (first && json_object_is_type(first, json_type_array)) {
            json_object *item = json_object_array_get_idx(first, 0);
            if (item) {
                json_object *jbalance = NULL;
                if (json_object_object_get_ex(item, "balance", &jbalance)) {
                    const char *bal_str = json_object_get_string(jbalance);
                    if (bal_str) {
                        strncpy(balance_out, bal_str, balance_out_size - 1);
                        balance_out[balance_out_size - 1] = '\0';
                        cellframe_rpc_response_free(resp);
                        return 0;
                    }
                }
            }
        }
    }

    snprintf(balance_out, balance_out_size, "0");
    cellframe_rpc_response_free(resp);
    return 0;
}

static int cell_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,
    uint64_t *gas_price_out
) {
    (void)speed; /* Cellframe has fixed fees */

    if (fee_out) {
        *fee_out = NETWORK_FEE_DATOSHI + DEFAULT_VALIDATOR_FEE_DATOSHI;
    }
    if (gas_price_out) {
        *gas_price_out = 0; /* Not applicable */
    }
    return 0;
}

static int cell_chain_send(
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
    (void)from_address;
    (void)to_address;
    (void)amount;
    (void)token;
    (void)private_key;
    (void)private_key_len;
    (void)fee_speed;
    (void)txhash_out;
    (void)txhash_out_size;

    /* Cellframe requires wallet file for Dilithium keys */
    /* Use send_from_wallet instead */
    QGP_LOG_ERROR(LOG_TAG, "Use send_from_wallet for Cellframe");
    return -1;
}

static int cell_chain_send_from_wallet(
    const char *wallet_path,
    const char *to_address,
    const char *amount_str,
    const char *token,
    const char *network,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    (void)fee_speed; /* Cellframe has fixed fees */

    int ret = -1;
    cellframe_wallet_t *wallet = NULL;
    cellframe_rpc_response_t *utxo_resp = NULL;
    cellframe_rpc_response_t *cell_utxo_resp = NULL;
    cellframe_rpc_response_t *submit_resp = NULL;
    cellframe_tx_builder_t *builder = NULL;
    cell_utxo_t *all_utxos = NULL;
    cell_utxo_t *selected_utxos = NULL;
    cell_utxo_t *all_cell_utxos = NULL;
    cell_utxo_t *selected_cell_utxos = NULL;
    uint8_t *dap_sign = NULL;
    char *json = NULL;

    if (!wallet_path || !to_address || !amount_str) {
        return -1;
    }

    const char *net = network ? network : CELLFRAME_DEFAULT_NET;
    int is_native = (!token || token[0] == '\0' || strcmp(token, "CELL") == 0);
    const char *utxo_token = is_native ? "CELL" : token;

    /* Load wallet */
    if (wallet_read_cellframe_path(wallet_path, &wallet) != 0 || !wallet) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load wallet: %s", wallet_path);
        goto done;
    }

    if (wallet->address[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "Wallet address not available");
        goto done;
    }

    /* Parse amount */
    uint256_t amount = uint256_0;
    if (cellframe_uint256_from_str(amount_str, &amount) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid amount: %s", amount_str);
        goto done;
    }

    /* Calculate required amounts */
    uint256_t fee = uint256_0;
    fee.lo.lo = DEFAULT_VALIDATOR_FEE_DATOSHI;

    uint256_t required_cell = uint256_0;
    required_cell.lo.lo = NETWORK_FEE_DATOSHI + fee.lo.lo;

    uint256_t required = uint256_0;
    if (is_native) {
        SUM_256_256(amount, required_cell, &required);
    } else {
        required = amount;
    }

    /* Query UTXOs for token */
    if (cellframe_rpc_get_utxo(net, wallet->address, utxo_token, &utxo_resp) != 0 || !utxo_resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to query %s UTXOs", utxo_token);
        goto done;
    }

    int all_count = 0;
    if (parse_utxos_from_response(utxo_resp, &all_utxos, &all_count) != 0 || all_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No %s UTXOs available", utxo_token);
        goto done;
    }

    int selected_count = 0;
    uint256_t total_input = uint256_0;
    if (select_utxos(all_utxos, all_count, required, &selected_utxos, &selected_count, &total_input) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Insufficient %s balance", utxo_token);
        goto done;
    }

    /* For non-native tokens, also need CELL for fees */
    int selected_cell_count = 0;
    uint256_t total_cell_input = uint256_0;

    if (!is_native) {
        if (cellframe_rpc_get_utxo(net, wallet->address, "CELL", &cell_utxo_resp) != 0 || !cell_utxo_resp) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to query CELL UTXOs for fees");
            goto done;
        }

        int all_cell_count = 0;
        if (parse_utxos_from_response(cell_utxo_resp, &all_cell_utxos, &all_cell_count) != 0 || all_cell_count == 0) {
            QGP_LOG_ERROR(LOG_TAG, "No CELL UTXOs for fees");
            goto done;
        }

        if (select_utxos(all_cell_utxos, all_cell_count, required_cell, &selected_cell_utxos, &selected_cell_count, &total_cell_input) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Insufficient CELL for fees");
            goto done;
        }
    }

    /* Build transaction */
    builder = cellframe_tx_builder_new();
    if (!builder) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create tx builder");
        goto done;
    }

    cellframe_tx_set_timestamp(builder, (uint64_t)time(NULL));

    /* Parse addresses */
    uint8_t recipient_buf[128];
    size_t decoded = base58_decode(to_address, recipient_buf);
    if (decoded != sizeof(cellframe_addr_t)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid recipient address");
        goto done;
    }
    cellframe_addr_t recipient_addr;
    memcpy(&recipient_addr, recipient_buf, sizeof(cellframe_addr_t));

    uint8_t collector_buf[128];
    decoded = base58_decode(NETWORK_FEE_COLLECTOR, collector_buf);
    if (decoded != sizeof(cellframe_addr_t)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fee collector address");
        goto done;
    }
    cellframe_addr_t collector_addr;
    memcpy(&collector_addr, collector_buf, sizeof(cellframe_addr_t));

    uint8_t sender_buf[128];
    decoded = base58_decode(wallet->address, sender_buf);
    if (decoded != sizeof(cellframe_addr_t)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid sender address");
        goto done;
    }
    cellframe_addr_t sender_addr;
    memcpy(&sender_addr, sender_buf, sizeof(cellframe_addr_t));

    /* Calculate change */
    uint256_t token_change = uint256_0;
    uint256_t cell_change = uint256_0;
    uint256_t network_fee = uint256_0;
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    if (is_native) {
        uint256_t fees_total = uint256_0;
        fees_total.lo.lo = NETWORK_FEE_DATOSHI + fee.lo.lo;
        uint256_t temp = uint256_0;
        SUBTRACT_256_256(total_input, amount, &temp);
        SUBTRACT_256_256(temp, fees_total, &token_change);
    } else {
        SUBTRACT_256_256(total_input, amount, &token_change);
        uint256_t fees_total = uint256_0;
        fees_total.lo.lo = NETWORK_FEE_DATOSHI + fee.lo.lo;
        SUBTRACT_256_256(total_cell_input, fees_total, &cell_change);
    }

    /* Add IN items */
    for (int i = 0; i < selected_count; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to add IN");
            goto done;
        }
    }

    if (!is_native && selected_cell_utxos) {
        for (int i = 0; i < selected_cell_count; i++) {
            if (cellframe_tx_add_in(builder, &selected_cell_utxos[i].hash, selected_cell_utxos[i].idx) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to add CELL IN");
                goto done;
            }
        }
    }

    /* Add OUT items */
    int out_ret;
    if (is_native) {
        out_ret = cellframe_tx_add_out(builder, &recipient_addr, amount);
    } else {
        out_ret = cellframe_tx_add_out_ext(builder, &recipient_addr, amount, token);
    }
    if (out_ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add recipient OUT");
        goto done;
    }

    /* Network fee */
    if (is_native) {
        out_ret = cellframe_tx_add_out(builder, &collector_addr, network_fee);
    } else {
        out_ret = cellframe_tx_add_out_ext(builder, &collector_addr, network_fee, "CELL");
    }
    if (out_ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add fee OUT");
        goto done;
    }

    /* Token change */
    if (token_change.hi.hi || token_change.hi.lo || token_change.lo.hi || token_change.lo.lo) {
        if (is_native) {
            out_ret = cellframe_tx_add_out(builder, &sender_addr, token_change);
        } else {
            out_ret = cellframe_tx_add_out_ext(builder, &sender_addr, token_change, token);
        }
        if (out_ret != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to add change OUT");
            goto done;
        }
    }

    /* CELL change (non-native only) */
    if (!is_native && (cell_change.hi.hi || cell_change.hi.lo || cell_change.lo.hi || cell_change.lo.lo)) {
        if (cellframe_tx_add_out_ext(builder, &sender_addr, cell_change, "CELL") != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to add CELL change OUT");
            goto done;
        }
    }

    /* Validator fee */
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add validator fee");
        goto done;
    }

    /* Sign transaction */
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get signing data");
        goto done;
    }

    size_t dap_sign_size = 0;
    if (cellframe_sign_transaction(tx_data, tx_size,
                                   wallet->private_key, wallet->private_key_size,
                                   wallet->public_key, wallet->public_key_size,
                                   &dap_sign, &dap_sign_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        free((void*)tx_data);
        goto done;
    }
    free((void*)tx_data);

    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add signature");
        goto done;
    }

    /* Convert to JSON */
    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get signed tx");
        goto done;
    }

    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to convert to JSON");
        goto done;
    }

    /* Submit */
    if (cellframe_rpc_submit_tx(net, "main", json, &submit_resp) != 0 || !submit_resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to submit transaction");
        goto done;
    }

    /* Parse response */
    if (submit_resp->result) {
        bool tx_created = false;
        const char *tx_hash = NULL;

        if (json_object_is_type(submit_resp->result, json_type_array) &&
            json_object_array_length(submit_resp->result) > 0) {

            json_object *first = json_object_array_get_idx(submit_resp->result, 0);
            if (first) {
                json_object *jtx_create = NULL, *jhash = NULL;
                if (json_object_object_get_ex(first, "tx_create", &jtx_create)) {
                    tx_created = json_object_get_boolean(jtx_create);
                }
                if (json_object_object_get_ex(first, "hash", &jhash)) {
                    tx_hash = json_object_get_string(jhash);
                }
            }
        }

        if (tx_created && tx_hash) {
            if (txhash_out && txhash_out_size > 0) {
                strncpy(txhash_out, tx_hash, txhash_out_size - 1);
                txhash_out[txhash_out_size - 1] = '\0';
            }
            QGP_LOG_INFO(LOG_TAG, "Transaction submitted: %s", tx_hash);
            ret = 0;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Transaction rejected by node");
        }
    }

done:
    if (wallet) wallet_free(wallet);
    if (utxo_resp) cellframe_rpc_response_free(utxo_resp);
    if (cell_utxo_resp) cellframe_rpc_response_free(cell_utxo_resp);
    if (submit_resp) cellframe_rpc_response_free(submit_resp);
    if (builder) cellframe_tx_builder_free(builder);
    if (all_utxos) free(all_utxos);
    if (selected_utxos) free(selected_utxos);
    if (all_cell_utxos) free(all_cell_utxos);
    if (selected_cell_utxos) free(selected_cell_utxos);
    if (dap_sign) free(dap_sign);
    if (json) free(json);

    return ret;
}

static int cell_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    if (!txhash || !status_out) {
        return -1;
    }

    cellframe_rpc_response_t *resp = NULL;
    if (cellframe_rpc_get_tx(CELLFRAME_DEFAULT_NET, txhash, &resp) != 0 || !resp) {
        *status_out = BLOCKCHAIN_TX_NOT_FOUND;
        return 0;
    }

    *status_out = BLOCKCHAIN_TX_SUCCESS;
    cellframe_rpc_response_free(resp);
    return 0;
}

static bool cell_chain_validate_address(const char *address) {
    if (!address) return false;

    size_t len = strlen(address);
    if (len < 100 || len > 110) return false;

    return true;
}

static int cell_chain_get_transactions(
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

    cellframe_rpc_response_t *resp = NULL;
    if (cellframe_rpc_get_tx_history(CELLFRAME_DEFAULT_NET, address, &resp) != 0 || !resp) {
        return -1;
    }

    if (!resp->result || !json_object_is_type(resp->result, json_type_array)) {
        cellframe_rpc_response_free(resp);
        return 0;
    }

    int array_len = json_object_array_length(resp->result);
    if (array_len <= 1) {
        cellframe_rpc_response_free(resp);
        return 0;
    }

    json_object *first_elem = json_object_array_get_idx(resp->result, 0);
    if (!first_elem || !json_object_is_type(first_elem, json_type_array)) {
        cellframe_rpc_response_free(resp);
        return 0;
    }

    int tx_array_len = json_object_array_length(first_elem);
    int tx_count = tx_array_len - 2; /* Skip addr and limit */

    if (tx_count <= 0) {
        cellframe_rpc_response_free(resp);
        return 0;
    }

    blockchain_tx_t *txs = calloc(tx_count, sizeof(blockchain_tx_t));
    if (!txs) {
        cellframe_rpc_response_free(resp);
        return -1;
    }

    int valid_count = 0;
    for (int i = 0; i < tx_count; i++) {
        json_object *tx_obj = json_object_array_get_idx(first_elem, i + 2);
        if (!tx_obj) continue;

        json_object *jhash = NULL, *jstatus = NULL, *jtx_created = NULL, *jdata = NULL;
        json_object_object_get_ex(tx_obj, "hash", &jhash);
        json_object_object_get_ex(tx_obj, "status", &jstatus);
        json_object_object_get_ex(tx_obj, "tx_created", &jtx_created);
        json_object_object_get_ex(tx_obj, "data", &jdata);

        if (jhash) {
            strncpy(txs[valid_count].tx_hash, json_object_get_string(jhash),
                    sizeof(txs[valid_count].tx_hash) - 1);
        }
        if (jstatus) {
            strncpy(txs[valid_count].status, json_object_get_string(jstatus),
                    sizeof(txs[valid_count].status) - 1);
        }
        if (jtx_created) {
            strncpy(txs[valid_count].timestamp, json_object_get_string(jtx_created),
                    sizeof(txs[valid_count].timestamp) - 1);
        }

        /* Parse data for amount/direction */
        if (jdata && json_object_is_type(jdata, json_type_array) &&
            json_object_array_length(jdata) > 0) {
            json_object *data_item = json_object_array_get_idx(jdata, 0);
            if (data_item) {
                json_object *jtx_type = NULL, *jtoken = NULL;
                json_object *jrecv = NULL, *jsend = NULL;
                json_object *jsrc = NULL, *jdst = NULL;

                json_object_object_get_ex(data_item, "tx_type", &jtx_type);
                json_object_object_get_ex(data_item, "token", &jtoken);
                json_object_object_get_ex(data_item, "recv_coins", &jrecv);
                json_object_object_get_ex(data_item, "send_coins", &jsend);
                json_object_object_get_ex(data_item, "source_address", &jsrc);
                json_object_object_get_ex(data_item, "destination_address", &jdst);

                if (jtoken) {
                    strncpy(txs[valid_count].token, json_object_get_string(jtoken),
                            sizeof(txs[valid_count].token) - 1);
                }

                if (jtx_type) {
                    const char *tx_type = json_object_get_string(jtx_type);
                    if (strcmp(tx_type, "recv") == 0) {
                        txs[valid_count].is_outgoing = false;
                        if (jrecv) {
                            strncpy(txs[valid_count].amount, json_object_get_string(jrecv),
                                    sizeof(txs[valid_count].amount) - 1);
                        }
                        if (jsrc) {
                            strncpy(txs[valid_count].other_address, json_object_get_string(jsrc),
                                    sizeof(txs[valid_count].other_address) - 1);
                        }
                    } else {
                        txs[valid_count].is_outgoing = true;
                        if (jsend) {
                            strncpy(txs[valid_count].amount, json_object_get_string(jsend),
                                    sizeof(txs[valid_count].amount) - 1);
                        }
                        if (jdst) {
                            strncpy(txs[valid_count].other_address, json_object_get_string(jdst),
                                    sizeof(txs[valid_count].other_address) - 1);
                        }
                    }
                }
            }
        }

        /* Filter by token if specified */
        if (token && token[0] != '\0') {
            if (strcmp(txs[valid_count].token, token) != 0) {
                continue; /* Skip this tx */
            }
        }

        valid_count++;
    }

    cellframe_rpc_response_free(resp);

    if (valid_count == 0) {
        free(txs);
        return 0;
    }

    *txs_out = txs;
    *count_out = valid_count;
    return 0;
}

static void cell_chain_free_transactions(blockchain_tx_t *txs, int count) {
    (void)count;
    if (txs) {
        free(txs);
    }
}

/* ============================================================================
 * REGISTRATION
 * ============================================================================ */

static const blockchain_ops_t cell_ops = {
    .name = "cellframe",
    .type = BLOCKCHAIN_TYPE_CELLFRAME,
    .init = cell_chain_init,
    .cleanup = cell_chain_cleanup,
    .get_balance = cell_chain_get_balance,
    .estimate_fee = cell_chain_estimate_fee,
    .send = cell_chain_send,
    .send_from_wallet = cell_chain_send_from_wallet,
    .get_tx_status = cell_chain_get_tx_status,
    .validate_address = cell_chain_validate_address,
    .get_transactions = cell_chain_get_transactions,
    .free_transactions = cell_chain_free_transactions,
    .user_data = NULL,
};

__attribute__((constructor))
static void cell_chain_register(void) {
    blockchain_register(&cell_ops);
}
