/**
 * @file bsc_bep20.h
 * @brief BEP-20 Token Interface for BNB Smart Chain
 *
 * BEP-20 is identical to ERC-20 in terms of ABI.
 * Key difference: BSC USDT/USDC use 18 decimals (not 6 like on Ethereum).
 */

#ifndef BSC_BEP20_H
#define BSC_BEP20_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * KNOWN TOKEN CONTRACTS (BSC Mainnet)
 * ============================================================================ */

/* USDT (Binance-Peg BSC-USD) - 18 decimals */
#define BSC_USDT_CONTRACT       "0x55d398326f99059fF775485246999027B3197955"
#define BSC_USDT_DECIMALS       18

/* USDC (Binance-Peg USD Coin) - 18 decimals */
#define BSC_USDC_CONTRACT       "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"
#define BSC_USDC_DECIMALS       18

/* ERC-20 / BEP-20 function signatures (same ABI) */
#define BEP20_BALANCE_OF_SIG    "70a08231"  /* balanceOf(address) */
#define BEP20_TRANSFER_SIG      "a9059cbb"  /* transfer(address,uint256) */

/* Gas limit for BEP-20 operations */
#define BSC_GAS_LIMIT_BEP20_TX  100000

/* ============================================================================
 * TOKEN INFO
 * ============================================================================ */

typedef struct {
    char contract[43];      /* Contract address (0x + 40 hex) */
    char symbol[16];        /* Token symbol */
    uint8_t decimals;       /* Token decimals */
} bsc_bep20_token_t;

/**
 * Get token info by symbol
 */
int bsc_bep20_get_token(const char *symbol, bsc_bep20_token_t *token_out);

/**
 * Check if a token symbol is supported on BSC
 */
bool bsc_bep20_is_supported(const char *symbol);

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

/**
 * Get BEP-20 token balance
 *
 * @param address       BSC address (with 0x prefix)
 * @param contract      Token contract address
 * @param decimals      Token decimals
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int bsc_bep20_get_balance(
    const char *address,
    const char *contract,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
);

/**
 * Get BEP-20 token balance by symbol
 */
int bsc_bep20_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
);

/* ============================================================================
 * TOKEN TRANSFERS
 * ============================================================================ */

/**
 * Send BEP-20 tokens
 */
int bsc_bep20_send(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *contract,
    uint8_t decimals,
    int gas_speed,
    char *tx_hash_out
);

/**
 * Send BEP-20 tokens by symbol
 */
int bsc_bep20_send_by_symbol(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *symbol,
    int gas_speed,
    char *tx_hash_out
);

#ifdef __cplusplus
}
#endif

#endif /* BSC_BEP20_H */
