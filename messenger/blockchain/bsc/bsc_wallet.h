/**
 * @file bsc_wallet.h
 * @brief BNB Smart Chain Wallet Interface
 *
 * BSC is EVM-compatible — uses the same secp256k1 key derivation
 * and address format as Ethereum. This header provides BSC-specific
 * type aliases and constants while reusing ETH wallet internals.
 *
 * BIP-44 path: m/44'/60'/0'/0/0 (same as ETH — shared address)
 */

#ifndef BSC_WALLET_H
#define BSC_WALLET_H

#include "../ethereum/eth_wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * BSC WALLET (same as ETH wallet — EVM-compatible)
 * ============================================================================ */

typedef eth_wallet_t bsc_wallet_t;

/**
 * Generate BSC wallet from BIP39 seed
 *
 * Same derivation as ETH (m/44'/60'/0'/0/0, secp256k1).
 * BSC address = ETH address for the same seed.
 *
 * @param seed       64-byte BIP39 master seed
 * @param seed_len   Seed length (must be 64)
 * @param wallet_out Output: wallet structure
 * @return           0 on success, -1 on error
 */
static inline int bsc_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    bsc_wallet_t *wallet_out
) {
    return eth_wallet_generate(seed, seed_len, wallet_out);
}

/**
 * Clear BSC wallet from memory
 */
static inline void bsc_wallet_clear(bsc_wallet_t *wallet) {
    eth_wallet_clear(wallet);
}

/**
 * Validate BSC address (same format as ETH: 0x + 40 hex)
 */
static inline bool bsc_validate_address(const char *address) {
    return eth_validate_address(address);
}

#ifdef __cplusplus
}
#endif

#endif /* BSC_WALLET_H */
