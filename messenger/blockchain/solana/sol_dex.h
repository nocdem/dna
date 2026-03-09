/**
 * @file sol_dex.h
 * @brief Solana DEX Quote Interface (Raydium AMM)
 *
 * On-chain quote fetching from Raydium CPMM pools via Solana RPC.
 * No external API dependencies — reads pool reserves directly.
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#ifndef SOL_DEX_H
#define SOL_DEX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

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
    char pool_address[48];      /* Pool address used */
    uint8_t from_decimals;      /* Input token decimals */
    uint8_t to_decimals;        /* Output token decimals */
} sol_dex_quote_t;

/* ============================================================================
 * QUOTE FUNCTIONS
 * ============================================================================ */

/**
 * Get swap quote from Raydium AMM pool
 *
 * Reads pool reserves via getAccountInfo RPC and calculates output
 * using constant product formula: out = (R_out * in * 997) / (R_in * 1000 + in * 997)
 *
 * @param from_token    Input token symbol (e.g., "SOL")
 * @param to_token      Output token symbol (e.g., "USDT")
 * @param amount_in     Input amount as decimal string (e.g., "1.5")
 * @param quote_out     Output: quote result
 * @return              0 on success, -1 on error, -2 if pair not found
 */
int sol_dex_get_quote(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    sol_dex_quote_t *quote_out
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

#ifdef __cplusplus
}
#endif

#endif /* SOL_DEX_H */
