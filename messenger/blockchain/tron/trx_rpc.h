/**
 * @file trx_rpc.h
 * @brief TRON RPC Client Interface (TronGrid API)
 *
 * Provides balance queries and transaction history via TronGrid API.
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#ifndef TRX_RPC_H
#define TRX_RPC_H

#include "trx_wallet.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get TRX balance for address
 *
 * @param address       TRON address (Base58Check format)
 * @param balance_out   Output: formatted balance string (e.g., "123.456 TRX")
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int trx_rpc_get_balance(
    const char *address,
    char *balance_out,
    size_t balance_size
);

/**
 * Get raw TRX balance in SUN (1 TRX = 1,000,000 SUN)
 *
 * @param address       TRON address (Base58Check format)
 * @param sun_out       Output: balance in SUN
 * @return              0 on success, -1 on error
 */
int trx_rpc_get_balance_sun(
    const char *address,
    uint64_t *sun_out
);

/**
 * Get transaction history for address
 *
 * Returns up to 50 most recent transactions.
 *
 * @param address       TRON address
 * @param txs_out       Output: array of transactions (caller must free with trx_rpc_free_transactions)
 * @param count_out     Output: number of transactions
 * @return              0 on success, -1 on error
 */
int trx_rpc_get_transactions(
    const char *address,
    trx_transaction_t **txs_out,
    int *count_out
);

/**
 * Free transaction array
 *
 * @param txs       Transaction array to free
 * @param count     Number of transactions
 */
void trx_rpc_free_transactions(trx_transaction_t *txs, int count);

/**
 * Rate limit delay for TronGrid API
 *
 * Call before making TronGrid requests to avoid 429 rate limit errors.
 * TronGrid allows 1 request per second without API key.
 */
void trx_rate_limit_delay(void);

#ifdef __cplusplus
}
#endif

#endif /* TRX_RPC_H */
