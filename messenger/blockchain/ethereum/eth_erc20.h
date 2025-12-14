/**
 * @file eth_erc20.h
 * @brief ERC-20 Token Interface for Ethereum
 *
 * Provides ERC-20 token operations including balance queries and transfers.
 * Supports USDT and other standard ERC-20 tokens.
 *
 * @author DNA Messenger Team
 * @date 2025-12-14
 */

#ifndef ETH_ERC20_H
#define ETH_ERC20_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * KNOWN TOKEN CONTRACTS (Ethereum Mainnet)
 * ============================================================================ */

/* USDT (Tether USD) - 6 decimals */
#define ETH_USDT_CONTRACT       "0xdAC17F958D2ee523a2206206994597C13D831ec7"
#define ETH_USDT_DECIMALS       6

/* USDC (USD Coin) - 6 decimals */
#define ETH_USDC_CONTRACT       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
#define ETH_USDC_DECIMALS       6

/* DAI (Dai Stablecoin) - 18 decimals */
#define ETH_DAI_CONTRACT        "0x6B175474E89094C44Da98b954EescdeCB5AF3F"
#define ETH_DAI_DECIMALS        18

/* ERC-20 function signatures (first 4 bytes of keccak256 hash) */
#define ERC20_BALANCE_OF_SIG    "70a08231"  /* balanceOf(address) */
#define ERC20_TRANSFER_SIG      "a9059cbb"  /* transfer(address,uint256) */
#define ERC20_DECIMALS_SIG      "313ce567"  /* decimals() */
#define ERC20_SYMBOL_SIG        "95d89b41"  /* symbol() */

/* Gas limits for ERC-20 operations */
#define ETH_GAS_LIMIT_ERC20     100000      /* ERC-20 transfer gas limit */

/* ============================================================================
 * TOKEN INFO STRUCTURE
 * ============================================================================ */

/**
 * ERC-20 token information
 */
typedef struct {
    char contract[43];      /* Contract address (0x + 40 hex) */
    char symbol[16];        /* Token symbol (e.g., "USDT") */
    uint8_t decimals;       /* Token decimals (e.g., 6 for USDT) */
} eth_erc20_token_t;

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
int eth_erc20_get_token(const char *symbol, eth_erc20_token_t *token_out);

/**
 * Check if a token symbol is supported
 *
 * @param symbol        Token symbol to check
 * @return              true if supported, false otherwise
 */
bool eth_erc20_is_supported(const char *symbol);

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

/**
 * Get ERC-20 token balance for address
 *
 * @param address       Ethereum address (with 0x prefix)
 * @param contract      Token contract address (with 0x prefix)
 * @param decimals      Token decimals
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int eth_erc20_get_balance(
    const char *address,
    const char *contract,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
);

/**
 * Get ERC-20 token balance by symbol
 *
 * Convenience wrapper that looks up contract by symbol.
 *
 * @param address       Ethereum address (with 0x prefix)
 * @param symbol        Token symbol (e.g., "USDT")
 * @param balance_out   Output: formatted balance string
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int eth_erc20_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
);

/* ============================================================================
 * TRANSFER ENCODING
 * ============================================================================ */

/**
 * Encode ERC-20 transfer call data
 *
 * Encodes: transfer(address to, uint256 amount)
 *
 * @param to_address    Recipient address (with 0x prefix)
 * @param amount        Amount as decimal string (e.g., "100.5")
 * @param decimals      Token decimals
 * @param data_out      Output: encoded call data (must be at least 68 bytes)
 * @param data_size     Size of data_out buffer
 * @return              Length of encoded data, or -1 on error
 */
int eth_erc20_encode_transfer(
    const char *to_address,
    const char *amount,
    uint8_t decimals,
    uint8_t *data_out,
    size_t data_size
);

/**
 * Encode balanceOf call data
 *
 * Encodes: balanceOf(address owner)
 *
 * @param address       Address to query (with 0x prefix)
 * @param data_out      Output: encoded call data (must be at least 36 bytes)
 * @param data_size     Size of data_out buffer
 * @return              Length of encoded data, or -1 on error
 */
int eth_erc20_encode_balance_of(
    const char *address,
    uint8_t *data_out,
    size_t data_size
);

/* ============================================================================
 * TOKEN TRANSFERS
 * ============================================================================ */

/**
 * Send ERC-20 tokens
 *
 * @param private_key   32-byte sender private key
 * @param from_address  Sender address (with 0x prefix)
 * @param to_address    Recipient address (with 0x prefix)
 * @param amount        Amount as decimal string (e.g., "100.5")
 * @param contract      Token contract address
 * @param decimals      Token decimals
 * @param gas_speed     Gas speed (ETH_GAS_SLOW/NORMAL/FAST)
 * @param tx_hash_out   Output: transaction hash
 * @return              0 on success, -1 on error
 */
int eth_erc20_send(
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
 * Send ERC-20 tokens by symbol
 *
 * Convenience wrapper that looks up contract by symbol.
 *
 * @param private_key   32-byte sender private key
 * @param from_address  Sender address
 * @param to_address    Recipient address
 * @param amount        Amount as decimal string
 * @param symbol        Token symbol (e.g., "USDT")
 * @param gas_speed     Gas speed
 * @param tx_hash_out   Output: transaction hash
 * @return              0 on success, -1 on error
 */
int eth_erc20_send_by_symbol(
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

#endif /* ETH_ERC20_H */
