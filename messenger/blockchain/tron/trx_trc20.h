/**
 * @file trx_trc20.h
 * @brief TRC-20 Token Interface for TRON
 *
 * Provides TRC-20 token operations including balance queries and transfers.
 * Supports USDT and other standard TRC-20 tokens on TRON network.
 *
 * @author DNA Messenger Team
 * @date 2025-12-14
 */

#ifndef TRX_TRC20_H
#define TRX_TRC20_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * KNOWN TOKEN CONTRACTS (TRON Mainnet)
 * ============================================================================ */

/* USDT (Tether USD) - 6 decimals */
#define TRX_USDT_CONTRACT       "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
#define TRX_USDT_DECIMALS       6

/* USDC (USD Coin) - 6 decimals */
#define TRX_USDC_CONTRACT       "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
#define TRX_USDC_DECIMALS       6

/* USDD (Decentralized USD) - 18 decimals */
#define TRX_USDD_CONTRACT       "TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn"
#define TRX_USDD_DECIMALS       18

/* ============================================================================
 * TOKEN INFO STRUCTURE
 * ============================================================================ */

/**
 * TRC-20 token information
 */
typedef struct {
    char contract[36];      /* Contract address (Base58Check) */
    char symbol[16];        /* Token symbol (e.g., "USDT") */
    uint8_t decimals;       /* Token decimals (e.g., 6 for USDT) */
} trx_trc20_token_t;

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
int trx_trc20_get_token(const char *symbol, trx_trc20_token_t *token_out);

/**
 * Check if a token symbol is supported
 *
 * @param symbol        Token symbol to check
 * @return              true if supported, false otherwise
 */
bool trx_trc20_is_supported(const char *symbol);

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

/**
 * Get TRC-20 token balance for address
 *
 * Uses TronGrid's /v1/accounts/{address}/tokens endpoint.
 *
 * @param address       TRON address (Base58Check)
 * @param contract      Token contract address (Base58Check)
 * @param decimals      Token decimals
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int trx_trc20_get_balance(
    const char *address,
    const char *contract,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
);

/**
 * Get TRC-20 token balance by symbol
 *
 * Convenience wrapper that looks up contract by symbol.
 *
 * @param address       TRON address (Base58Check)
 * @param symbol        Token symbol (e.g., "USDT")
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int trx_trc20_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
);

/* ============================================================================
 * TOKEN TRANSFERS
 * ============================================================================ */

/**
 * Send TRC-20 tokens
 *
 * @param private_key   32-byte sender private key
 * @param from_address  Sender address (Base58Check)
 * @param to_address    Recipient address (Base58Check)
 * @param amount        Amount as decimal string (e.g., "100.5")
 * @param contract      Token contract address (Base58Check)
 * @param decimals      Token decimals
 * @param tx_id_out     Output: transaction ID
 * @return              0 on success, -1 on error
 */
int trx_trc20_send(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *contract,
    uint8_t decimals,
    char *tx_id_out
);

/**
 * Send TRC-20 tokens by symbol
 *
 * Convenience wrapper that looks up contract by symbol.
 *
 * @param private_key   32-byte sender private key
 * @param from_address  Sender address (Base58Check)
 * @param to_address    Recipient address (Base58Check)
 * @param amount        Amount as decimal string (e.g., "100.5")
 * @param symbol        Token symbol (e.g., "USDT")
 * @param tx_id_out     Output: transaction ID
 * @return              0 on success, -1 on error
 */
int trx_trc20_send_by_symbol(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *symbol,
    char *tx_id_out
);

#ifdef __cplusplus
}
#endif

#endif /* TRX_TRC20_H */
