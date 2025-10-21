/*
 * cellframe_tx_json_sign.c - Sign JSON transactions for Cellframe RPC
 *
 * Signs JSON transactions by:
 * 1. Building JSON items (no timestamp yet)
 * 2. Converting to binary for signing
 * 3. Signing with Dilithium (tx_items_size=0)
 * 4. Adding signature to JSON items
 * 5. Finalizing with timestamp and datum_type
 */

#include "cellframe_tx.h"
#include "cellframe_addr.h"
#include "wallet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Build signed JSON transaction
 *
 * Steps:
 * 1. Build binary transaction (for signing)
 * 2. Sign binary (tx_items_size=0)
 * 3. Build JSON with items + signature
 * 4. Return JSON with timestamp and datum_type
 */
int cellframe_build_signed_json_tx(const cellframe_utxo_list_t *utxos,
                                     const char *recipient_addr,
                                     const char *amount,
                                     const char *network_fee,
                                     const char *network_fee_addr,
                                     const char *validator_fee,
                                     const char *change_addr,
                                     const char *change_amount,
                                     const char *token,
                                     const uint8_t *pub_key, size_t pub_key_size,
                                     const uint8_t *priv_key, size_t priv_key_size,
                                     char **json_out) {

    if (!utxos || !recipient_addr || !amount || !token || !json_out ||
        !pub_key || !priv_key || pub_key_size == 0 || priv_key_size == 0) {
        return -1;
    }

    // Step 1: Build binary transaction for signing
    cellframe_tx_builder_t *binary_builder = cellframe_tx_builder_new();
    if (!binary_builder) return -1;

    // Add IN items
    for (size_t i = 0; i < utxos->count; i++) {
        if (cellframe_tx_add_in(binary_builder, &utxos->utxos[i].prev_hash,
                                 utxos->utxos[i].out_prev_idx) != 0) {
            cellframe_tx_builder_free(binary_builder);
            return -1;
        }
    }

    // Add OUT items
    cellframe_addr_t addr_to;
    if (cellframe_addr_from_str(recipient_addr, &addr_to) != 0) {
        cellframe_tx_builder_free(binary_builder);
        return -1;
    }
    if (cellframe_tx_add_out_ext(binary_builder, &addr_to, amount, token) != 0) {
        cellframe_tx_builder_free(binary_builder);
        return -1;
    }

    // Add network fee output if provided
    if (network_fee && network_fee_addr) {
        cellframe_addr_t net_fee_addr_struct;
        if (cellframe_addr_from_str(network_fee_addr, &net_fee_addr_struct) != 0) {
            cellframe_tx_builder_free(binary_builder);
            return -1;
        }
        if (cellframe_tx_add_out_ext(binary_builder, &net_fee_addr_struct, network_fee, token) != 0) {
            cellframe_tx_builder_free(binary_builder);
            return -1;
        }
    }

    // Add validator fee
    if (cellframe_tx_add_fee(binary_builder, validator_fee) != 0) {
        cellframe_tx_builder_free(binary_builder);
        return -1;
    }

    // Add change output if provided
    if (change_addr && change_amount) {
        cellframe_addr_t addr_change;
        if (cellframe_addr_from_str(change_addr, &addr_change) != 0) {
            cellframe_tx_builder_free(binary_builder);
            return -1;
        }
        if (cellframe_tx_add_out_ext(binary_builder, &addr_change, change_amount, token) != 0) {
            cellframe_tx_builder_free(binary_builder);
            return -1;
        }
    }

    // Step 2: Add signature to binary transaction
    // (cellframe_tx_add_signature will handle signing internally)
    if (cellframe_tx_add_signature(binary_builder, pub_key, pub_key_size,
                                     priv_key, priv_key_size) != 0) {
        cellframe_tx_builder_free(binary_builder);
        return -1;
    }

    // Step 3: Convert signed binary to JSON
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_data(binary_builder, &tx_size);
    if (!tx_data) {
        cellframe_tx_builder_free(binary_builder);
        return -1;
    }

    // Use binary-to-JSON converter
    int ret = cellframe_tx_binary_to_json(tx_data, tx_size, json_out);
    cellframe_tx_builder_free(binary_builder);

    return ret;
}
