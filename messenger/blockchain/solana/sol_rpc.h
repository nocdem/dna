/**
 * @file sol_rpc.h
 * @brief Solana JSON-RPC Client Interface
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#ifndef SOL_RPC_H
#define SOL_RPC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Lamports per SOL */
#define SOL_LAMPORTS_PER_SOL    1000000000ULL

/**
 * Transaction record for history
 */
typedef struct {
    char signature[128];        /* Transaction signature (base58) */
    char from[48];              /* Sender address */
    char to[48];                /* Recipient address */
    uint64_t lamports;          /* Amount in lamports */
    uint64_t slot;              /* Slot number */
    int64_t block_time;         /* Unix timestamp */
    bool is_outgoing;           /* Direction */
    bool success;               /* Transaction success */
} sol_transaction_t;

/**
 * Get account balance
 *
 * @param address       Base58 account address
 * @param lamports_out  Output: balance in lamports
 * @return              0 on success, -1 on error
 */
int sol_rpc_get_balance(
    const char *address,
    uint64_t *lamports_out
);

/**
 * Get recent blockhash (needed for transactions)
 *
 * @param blockhash_out Output: 32-byte blockhash
 * @return              0 on success, -1 on error
 */
int sol_rpc_get_recent_blockhash(
    uint8_t blockhash_out[32]
);

/**
 * Get minimum balance for rent exemption
 *
 * @param data_len      Account data length
 * @param lamports_out  Output: minimum lamports needed
 * @return              0 on success, -1 on error
 */
int sol_rpc_get_minimum_balance_for_rent(
    size_t data_len,
    uint64_t *lamports_out
);

/**
 * Send signed transaction
 *
 * @param tx_base64     Base64-encoded signed transaction
 * @param signature_out Output: transaction signature (base58)
 * @param sig_out_size  Size of signature output buffer
 * @return              0 on success, -1 on error
 */
int sol_rpc_send_transaction(
    const char *tx_base64,
    char *signature_out,
    size_t sig_out_size
);

/**
 * Get transaction status
 *
 * @param signature     Transaction signature (base58)
 * @param success_out   Output: true if confirmed and successful
 * @return              0 on success (found), 1 if pending, -1 on error
 */
int sol_rpc_get_transaction_status(
    const char *signature,
    bool *success_out
);

/**
 * Get transaction history for account
 *
 * @param address       Account address
 * @param txs_out       Output: array of transactions (caller must free)
 * @param count_out     Output: number of transactions
 * @return              0 on success, -1 on error
 */
int sol_rpc_get_transactions(
    const char *address,
    sol_transaction_t **txs_out,
    int *count_out
);

/**
 * Free transaction array
 */
void sol_rpc_free_transactions(sol_transaction_t *txs, int count);

/**
 * Get current slot
 *
 * @param slot_out      Output: current slot number
 * @return              0 on success, -1 on error
 */
int sol_rpc_get_slot(uint64_t *slot_out);

#ifdef __cplusplus
}
#endif

#endif /* SOL_RPC_H */
