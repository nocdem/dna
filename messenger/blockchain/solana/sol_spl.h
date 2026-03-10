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
#include "sol_wallet.h"

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

/* Associated Token Program ID */
#define SOL_ASSOCIATED_TOKEN_PROGRAM_ID "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

/* Token account data size (for rent calculation) */
#define SOL_TOKEN_ACCOUNT_DATA_SIZE 165

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

/* ============================================================================
 * ATA (ASSOCIATED TOKEN ACCOUNT) FUNCTIONS
 * ============================================================================ */

/**
 * Derive Associated Token Account (ATA) address
 *
 * Computes the PDA for the given owner and mint.
 *
 * @param owner_pubkey    Owner public key (32 bytes)
 * @param mint_pubkey     Token mint public key (32 bytes)
 * @param ata_pubkey_out  Output: ATA public key (32 bytes)
 * @return                0 on success, -1 on error
 */
int sol_spl_derive_ata(
    const uint8_t owner_pubkey[32],
    const uint8_t mint_pubkey[32],
    uint8_t ata_pubkey_out[32]
);

/**
 * Check if an ATA exists on-chain
 *
 * @param ata_address     ATA address (base58)
 * @param exists_out      Output: true if account exists with data
 * @return                0 on success, -1 on RPC error
 */
int sol_spl_check_ata(
    const char *ata_address,
    bool *exists_out
);

/* ============================================================================
 * TRANSFER FUNCTIONS
 * ============================================================================ */

/**
 * Send SPL tokens to an address
 *
 * High-level function that:
 * 1. Derives sender and recipient ATAs
 * 2. Checks if recipient ATA exists
 * 3. If not, includes CreateAssociatedTokenAccount instruction
 * 4. Builds, signs, and sends the transaction
 *
 * @param wallet          Source wallet (signer)
 * @param to_address      Recipient wallet address (base58, NOT ATA)
 * @param mint_address    Token mint address (base58)
 * @param amount          Amount as decimal string (e.g., "10.5")
 * @param decimals        Token decimals
 * @param signature_out   Output: transaction signature (base58)
 * @param sig_out_size    Size of signature output buffer
 * @return                0 success, -1 error, -2 insufficient token balance,
 *                        -3 insufficient SOL for rent/fees, -4 invalid mint
 */
int sol_spl_send(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *mint_address,
    const char *amount,
    uint8_t decimals,
    char *signature_out,
    size_t sig_out_size
);

/**
 * Send SPL tokens by symbol (convenience wrapper)
 *
 * @param wallet          Source wallet
 * @param to_address      Recipient address (base58)
 * @param symbol          Token symbol (e.g., "USDT") or mint address
 * @param amount          Amount as decimal string
 * @param signature_out   Output: transaction signature
 * @param sig_out_size    Size of signature output buffer
 * @return                0 success, -1 error, -2 insufficient balance,
 *                        -3 insufficient SOL, -4 unknown token
 */
int sol_spl_send_by_symbol(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *symbol,
    const char *amount,
    char *signature_out,
    size_t sig_out_size
);

/**
 * Estimate fee for SPL token transfer
 *
 * Checks if recipient ATA exists. Returns exact fee including
 * ATA creation rent if needed.
 *
 * @param owner_address     Sender address (base58)
 * @param to_address        Recipient address (base58)
 * @param mint_address      Token mint address (base58)
 * @param fee_lamports_out  Output: total fee in lamports
 * @param ata_exists_out    Output: whether recipient ATA exists (can be NULL)
 * @return                  0 on success, -1 on error
 */
int sol_spl_estimate_fee(
    const char *owner_address,
    const char *to_address,
    const char *mint_address,
    uint64_t *fee_lamports_out,
    bool *ata_exists_out
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_SPL_H */
