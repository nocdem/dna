/**
 * @file sol_dex.h
 * @brief Solana DEX Quote Interface (Jupiter Aggregator)
 *
 * Quote fetching via Jupiter public API (api.jup.ag).
 * Jupiter aggregates all major Solana DEXes (Raydium, Orca, Meteora, etc.)
 * and returns the best route. Supports on-chain referral fees via platformFeeBps.
 *
 * @author DNA Connect Team
 * @date 2026-03-09
 */

#ifndef SOL_DEX_H
#define SOL_DEX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sol_wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DEX QUOTE RESULT
 * ============================================================================ */

typedef struct {
    char from_token[16];        /* Input token symbol */
    char to_token[16];          /* Output token symbol */
    char amount_in[64];         /* Input amount (decimal string) */
    char amount_out[64];        /* Output amount (decimal string) */
    char price[64];             /* Price ratio (1 from = X to) */
    char price_impact[16];      /* Price impact percentage (e.g., "0.12") */
    char fee[64];               /* Fee amount in input token */
    char pool_address[48];      /* Pool/AMM key used */
    char dex_name[32];          /* DEX name from route (e.g. "Raydium", "Orca") */
    uint8_t from_decimals;      /* Input token decimals */
    uint8_t to_decimals;        /* Output token decimals */
} sol_dex_quote_t;

/* ============================================================================
 * DEX SWAP RESULT
 * ============================================================================ */

typedef struct {
    char tx_signature[128];     /* Transaction signature (base58) */
    char amount_in[64];         /* Input amount (decimal string) */
    char amount_out[64];        /* Expected output amount (decimal string) */
    char from_token[16];        /* Input token symbol */
    char to_token[16];          /* Output token symbol */
    char dex_name[32];          /* DEX name from route */
    char price_impact[16];      /* Price impact percentage */
} sol_dex_swap_result_t;

/* ============================================================================
 * QUOTE FUNCTIONS
 * ============================================================================ */

/**
 * Get swap quotes via Jupiter aggregator
 *
 * @param from_token    Input token symbol (e.g., "SOL")
 * @param to_token      Output token symbol (e.g., "USDT")
 * @param amount_in     Input amount as decimal string (e.g., "1.5")
 * @param dex_filter    DEX filter (NULL or ""=all, matches routePlan label)
 * @param quotes_out    Output: array of quotes (caller provides buffer)
 * @param max_quotes    Size of quotes_out array
 * @param count_out     Output: number of quotes returned
 * @return              0 on success, -1 on error, -2 if pair not found
 */
int sol_dex_get_quotes(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    sol_dex_quote_t *quotes_out,
    int max_quotes,
    int *count_out
);

/**
 * List available swap pairs
 *
 * @param pairs_out     Output: array of "FROM/TO" strings (caller frees)
 * @param count_out     Output: number of pairs
 * @return              0 on success, -1 on error
 */
int sol_dex_list_pairs(char ***pairs_out, int *count_out);

/**
 * Free pairs array from sol_dex_list_pairs
 */
void sol_dex_free_pairs(char **pairs, int count);

/* ============================================================================
 * SWAP FUNCTIONS
 * ============================================================================ */

/**
 * Execute a DEX swap via Jupiter aggregator
 *
 * Single-call: fetches quote, posts to /swap, signs TX, submits to Solana.
 * Private key derived from wallet, never sent to Jupiter.
 *
 * @param wallet       Solana wallet (must have private key for signing)
 * @param from_token   Input token symbol (e.g., "SOL")
 * @param to_token     Output token symbol (e.g., "USDC")
 * @param amount_in    Input amount as decimal string (e.g., "0.01")
 * @param result_out   Output: swap result with TX signature
 * @return             0 on success, -1 on error, -2 if pair not found
 */
int sol_dex_execute_swap(
    const sol_wallet_t *wallet,
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    sol_dex_swap_result_t *result_out
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_DEX_H */
