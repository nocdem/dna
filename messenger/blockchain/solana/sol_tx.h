/**
 * @file sol_tx.h
 * @brief Solana Transaction Building Interface
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#ifndef SOL_TX_H
#define SOL_TX_H

#include "sol_wallet.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* System program ID (all 0s = address 11111111111111111111111111111112) */
extern const uint8_t SOL_SYSTEM_PROGRAM_ID[32];

/* Maximum transaction size */
#define SOL_TX_MAX_SIZE         1232

/**
 * Build and sign a SOL transfer transaction
 *
 * @param wallet            Source wallet (signer)
 * @param to_pubkey         Destination public key (32 bytes)
 * @param lamports          Amount in lamports
 * @param recent_blockhash  Recent blockhash (32 bytes)
 * @param tx_out            Output: serialized transaction
 * @param tx_out_size       Size of tx_out buffer
 * @param tx_len_out        Output: actual transaction length
 * @return                  0 on success, -1 on error
 */
int sol_tx_build_transfer(
    const sol_wallet_t *wallet,
    const uint8_t to_pubkey[32],
    uint64_t lamports,
    const uint8_t recent_blockhash[32],
    uint8_t *tx_out,
    size_t tx_out_size,
    size_t *tx_len_out
);

/**
 * Send SOL to an address
 *
 * High-level function that:
 * 1. Gets recent blockhash
 * 2. Builds transfer transaction
 * 3. Signs and sends transaction
 *
 * @param wallet            Source wallet
 * @param to_address        Destination address (base58)
 * @param lamports          Amount in lamports
 * @param signature_out     Output: transaction signature (base58)
 * @param sig_out_size      Size of signature output buffer
 * @return                  0 on success, -1 on error
 */
int sol_tx_send_lamports(
    const sol_wallet_t *wallet,
    const char *to_address,
    uint64_t lamports,
    char *signature_out,
    size_t sig_out_size
);

/**
 * Send SOL (in SOL units, not lamports)
 *
 * @param wallet            Source wallet
 * @param to_address        Destination address (base58)
 * @param amount_sol        Amount in SOL (will be converted to lamports)
 * @param signature_out     Output: transaction signature
 * @param sig_out_size      Size of signature output buffer
 * @return                  0 on success, -1 on error
 */
int sol_tx_send_sol(
    const sol_wallet_t *wallet,
    const char *to_address,
    double amount_sol,
    char *signature_out,
    size_t sig_out_size
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_TX_H */
