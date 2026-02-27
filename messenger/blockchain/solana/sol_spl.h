/**
 * @file sol_spl.h
 * @brief SPL Token Interface for Solana
 *
 * Provides SPL token operations including balance queries.
 * Supports USDT and other SPL tokens.
 *
 * @author DNA Messenger Team
 * @date 2025-12-16
 */

#ifndef SOL_SPL_H
#define SOL_SPL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * KNOWN TOKEN MINTS (Solana Mainnet)
 * ============================================================================ */

/* USDT (Tether USD) - 6 decimals */
#define SOL_USDT_MINT           "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
#define SOL_USDT_DECIMALS       6

/* USDC (USD Coin) - 6 decimals */
#define SOL_USDC_MINT           "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
#define SOL_USDC_DECIMALS       6

/* Token Program ID */
#define SOL_TOKEN_PROGRAM_ID    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

/* ============================================================================
 * TOKEN INFO STRUCTURE
 * ============================================================================ */

/**
 * SPL token information
 */
typedef struct {
    char mint[48];          /* Token mint address (base58) */
    char symbol[16];        /* Token symbol (e.g., "USDT") */
    uint8_t decimals;       /* Token decimals (e.g., 6 for USDT) */
} sol_spl_token_t;

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

/**
 * Get token info by symbol
 *
 * @param symbol        Token symbol (e.g., "USDT", "USDC")
 * @param token_out     Output: token information
 * @return              0 on success, -1 if token not found
 */
int sol_spl_get_token(const char *symbol, sol_spl_token_t *token_out);

/**
 * Check if a token symbol is supported
 *
 * @param symbol        Token symbol to check
 * @return              true if supported, false otherwise
 */
bool sol_spl_is_supported(const char *symbol);

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

/**
 * Get SPL token balance for address
 *
 * Uses getTokenAccountsByOwner RPC call.
 *
 * @param address       Solana address (base58)
 * @param mint          Token mint address (base58)
 * @param decimals      Token decimals
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int sol_spl_get_balance(
    const char *address,
    const char *mint,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
);

/**
 * Get SPL token balance by symbol
 *
 * Convenience wrapper that looks up mint by symbol.
 *
 * @param address       Solana address (base58)
 * @param symbol        Token symbol (e.g., "USDT")
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int sol_spl_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_SPL_H */
