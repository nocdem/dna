/**
 * @file cell_chain.c
 * @brief Cellframe blockchain_ops_t implementation
 */

#include "../blockchain.h"
#include "cellframe_rpc.h"
#include "cellframe_addr.h"
#include "cellframe_wallet.h"
#include <string.h>
#include <stdio.h>

#define LOG_TAG "CELL_CHAIN"
#include "crypto/utils/qgp_log.h"

/* Default network */
#define CELLFRAME_DEFAULT_NET "Backbone"

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
        if (balance_out_size > 0) {
            snprintf(balance_out, balance_out_size, "0");
        }
        return -1;
    }

    /* Parse balance from response */
    /* TODO: Parse actual balance from resp->data */
    snprintf(balance_out, balance_out_size, "0");

    cellframe_rpc_response_free(resp);
    return 0;
}

static int cell_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,
    uint64_t *gas_price_out
) {
    /* Cellframe uses fixed fee */
    /* 0.05 CELL = 50000000000000000 datoshi (0.05 * 10^18) */
    if (fee_out) {
        *fee_out = 50000000000000000ULL;
    }
    if (gas_price_out) {
        *gas_price_out = 0; /* Not applicable for Cellframe */
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
    /* Cellframe send is complex and handled by dna_engine.c for now */
    /* This will be refactored to use the full send flow later */
    QGP_LOG_ERROR(LOG_TAG, "cell_chain_send not yet implemented - use dna_engine send");
    return -1;
}

static int cell_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    if (!txhash || !status_out) {
        return -1;
    }

    cellframe_rpc_response_t *resp = NULL;
    int ret = cellframe_rpc_get_tx(CELLFRAME_DEFAULT_NET, txhash, &resp);

    if (ret != 0 || !resp) {
        *status_out = BLOCKCHAIN_TX_NOT_FOUND;
        return 0;
    }

    /* If we got a response, tx exists */
    *status_out = BLOCKCHAIN_TX_SUCCESS;
    cellframe_rpc_response_free(resp);
    return 0;
}

static bool cell_chain_validate_address(const char *address) {
    if (!address) return false;

    /* Cellframe addresses are base58 encoded, typically 103-106 chars */
    size_t len = strlen(address);
    if (len < 100 || len > 110) return false;

    /* Should start with specific chars based on network */
    /* For now, basic length check is sufficient */
    return true;
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
    .get_tx_status = cell_chain_get_tx_status,
    .validate_address = cell_chain_validate_address,
    .user_data = NULL,
};

/* Auto-register on library load */
__attribute__((constructor))
static void cell_chain_register(void) {
    blockchain_register(&cell_ops);
}
