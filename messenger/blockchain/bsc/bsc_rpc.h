/**
 * @file bsc_rpc.h
 * @brief BNB Smart Chain JSON-RPC Client
 *
 * BSC RPC for balance queries and transaction history.
 * Uses public BSC RPC endpoints (no API key required).
 * Transaction history via Blockscout BSC API.
 */

#ifndef BSC_RPC_H
#define BSC_RPC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

/* BSC RPC endpoints (mainnet) with fallbacks */
#define BSC_RPC_ENDPOINT_DEFAULT    "https://bsc-dataseed.binance.org"
#define BSC_RPC_ENDPOINT_FALLBACK1  "https://bsc-dataseed1.defibit.io"
#define BSC_RPC_ENDPOINT_FALLBACK2  "https://bsc.publicnode.com"
#define BSC_RPC_ENDPOINT_FALLBACK3  "https://1rpc.io/bnb"
#define BSC_RPC_ENDPOINT_COUNT      4

/* Blockscout BSC API (free, no API key) */
#define BSC_BLOCKSCOUT_API_URL      "https://bsc.blockscout.com/api"

/* ============================================================================
 * TRANSACTION RECORD
 * ============================================================================ */

/**
 * BSC transaction record (same structure as ETH)
 */
typedef struct {
    char tx_hash[68];      /* Transaction hash (0x + 64 hex chars) */
    char from[44];         /* Sender address */
    char to[44];           /* Recipient address */
    char value[64];        /* Value in BNB (e.g., "0.123") */
    uint64_t timestamp;    /* Unix timestamp */
    int is_outgoing;       /* 1 if we sent, 0 if we received */
    int is_confirmed;      /* 1 if confirmed, 0 if failed */
} bsc_transaction_t;

/* ============================================================================
 * BALANCE
 * ============================================================================ */

/**
 * Get BNB balance via JSON-RPC
 *
 * @param address       BSC address (with 0x prefix)
 * @param balance_out   Output: formatted balance string (e.g., "1.234")
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int bsc_rpc_get_balance(
    const char *address,
    char *balance_out,
    size_t balance_size
);

/**
 * Get current BSC RPC endpoint
 */
const char* bsc_rpc_get_endpoint(void);

/**
 * Set custom BSC RPC endpoint
 */
int bsc_rpc_set_endpoint(const char *endpoint);

/* ============================================================================
 * TRANSACTION HISTORY
 * ============================================================================ */

/**
 * Get BNB transaction history via Blockscout BSC API
 *
 * @param address    BSC address (with 0x prefix)
 * @param txs_out    Output: array of transactions (caller must free)
 * @param count_out  Output: number of transactions
 * @return           0 on success, -1 on error
 */
int bsc_rpc_get_transactions(
    const char *address,
    bsc_transaction_t **txs_out,
    int *count_out
);

/**
 * Get BEP-20 token transaction history via Blockscout BSC API
 *
 * @param address           BSC address (with 0x prefix)
 * @param contract_address  BEP-20 token contract address
 * @param token_decimals    Token decimal places
 * @param txs_out           Output: array of transactions (caller must free)
 * @param count_out         Output: number of transactions
 * @return                  0 on success, -1 on error
 */
int bsc_rpc_get_token_transactions(
    const char *address,
    const char *contract_address,
    uint8_t token_decimals,
    bsc_transaction_t **txs_out,
    int *count_out
);

/**
 * Free transaction array
 */
void bsc_rpc_free_transactions(bsc_transaction_t *txs, int count);

#ifdef __cplusplus
}
#endif

#endif /* BSC_RPC_H */
