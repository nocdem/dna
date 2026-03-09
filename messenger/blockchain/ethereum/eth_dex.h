/**
 * @file eth_dex.h
 * @brief Ethereum DEX Quote Interface (Uniswap v2/v3 + PancakeSwap v2/v3)
 *
 * On-chain quote fetching via eth_call:
 * - V2 (Uniswap/PancakeSwap): getReserves() + CPMM formula
 * - V3 (Uniswap/PancakeSwap): QuoterV2.quoteExactInputSingle()
 * No external API dependencies — reads pool data directly from chain.
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#ifndef ETH_DEX_H
#define ETH_DEX_H

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
    char price_impact[16];      /* Price impact percentage */
    char fee[64];               /* Fee amount in input token */
    char pool_address[48];      /* Pair contract address */
    char dex_name[32];          /* DEX name (e.g. "Uniswap v2") */
    uint8_t from_decimals;      /* Input token decimals */
    uint8_t to_decimals;        /* Output token decimals */
} eth_dex_quote_t;

/* ============================================================================
 * QUOTE FUNCTIONS
 * ============================================================================ */

/**
 * Get swap quotes from all matching Uniswap pools
 *
 * Returns quotes from all matching DEXes (V2 + V3).
 * If dex_filter is set, only matching DEX quotes are returned.
 *
 * @param from_token    Input token symbol (e.g., "ETH")
 * @param to_token      Output token symbol (e.g., "USDC")
 * @param amount_in     Input amount as decimal string (e.g., "1.5")
 * @param dex_filter    DEX filter (NULL or ""=all, "uniswap-v2", "uniswap-v3")
 * @param quotes_out    Output: array of quotes (caller provides buffer)
 * @param max_quotes    Size of quotes_out array
 * @param count_out     Output: number of quotes returned
 * @return              0 on success, -1 on error, -2 if pair not found
 */
int eth_dex_get_quotes(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    eth_dex_quote_t *quotes_out,
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
int eth_dex_list_pairs(char ***pairs_out, int *count_out);

/**
 * Free pairs array from eth_dex_list_pairs
 */
void eth_dex_free_pairs(char **pairs, int count);

#ifdef __cplusplus
}
#endif

#endif /* ETH_DEX_H */
