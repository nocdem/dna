/**
 * @file bsc_tx.h
 * @brief BNB Smart Chain Transaction Building and Signing
 *
 * BSC uses the same EIP-155 transaction format as Ethereum with chain_id=56.
 * Reuses eth_tx_sign / eth_rlp for signing. Only RPC calls differ (BSC endpoints).
 */

#ifndef BSC_TX_H
#define BSC_TX_H

#include "../ethereum/eth_tx.h"   /* eth_tx_t, eth_signed_tx_t, eth_tx_sign, eth_parse_* */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BSC Chain ID */
#define BSC_CHAIN_MAINNET       56
#define BSC_CHAIN_TESTNET       97

/* Default gas limit for simple BNB transfer */
#define BSC_GAS_LIMIT_TRANSFER  21000

/* Gas limits for BEP-20 operations */
#define BSC_GAS_LIMIT_BEP20     100000

/* Gas speed presets (same values as ETH) */
#define BSC_GAS_SLOW     0
#define BSC_GAS_NORMAL   1
#define BSC_GAS_FAST     2

/* ============================================================================
 * RPC QUERIES (BSC endpoints)
 * ============================================================================ */

/**
 * Get transaction count (nonce) via BSC RPC
 */
int bsc_tx_get_nonce(const char *address, uint64_t *nonce_out);

/**
 * Get current BSC gas price
 */
int bsc_tx_get_gas_price(uint64_t *gas_price_out);

/**
 * Broadcast signed transaction to BSC network
 */
int bsc_tx_send(const eth_signed_tx_t *signed_tx, char *tx_hash_out);

/* ============================================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================================ */

/**
 * Send BNB with gas speed preset
 *
 * @param private_key   32-byte secp256k1 private key
 * @param from_address  Sender address (0x + 40 hex)
 * @param to_address    Recipient address (0x + 40 hex)
 * @param amount_bnb    Amount as decimal string (e.g., "0.1")
 * @param gas_speed     Gas speed: 0=slow, 1=normal, 2=fast
 * @param tx_hash_out   Output: transaction hash (67 bytes min)
 * @return              0 on success, -1 on error
 */
int bsc_send_bnb_with_gas(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount_bnb,
    int gas_speed,
    char *tx_hash_out
);

#ifdef __cplusplus
}
#endif

#endif /* BSC_TX_H */
