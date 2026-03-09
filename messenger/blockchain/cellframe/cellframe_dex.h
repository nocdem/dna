/**
 * @file cellframe_dex.h
 * @brief Cellframe DEX Quote Interface (Order Book Simulation)
 *
 * Quote simulation via Cellframe public RPC (rpc.cellframe.net/connect).
 * Cellframe DEX is order-book based (not AMM). Quotes are simulated by
 * walking the order book from best rate to worst, filling the user's
 * requested amount across multiple orders.
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#ifndef CELLFRAME_DEX_H
#define CELLFRAME_DEX_H

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
    char price[64];             /* Effective price (1 from = X to) */
    char price_impact[16];      /* Slippage vs best order (e.g., "0.12") */
    char fee[64];               /* Fee info */
    char pool_address[48];      /* Not applicable — "orderbook" */
    char dex_name[32];          /* "Cellframe DEX" */
    uint8_t from_decimals;      /* Input token decimals (18) */
    uint8_t to_decimals;        /* Output token decimals (18) */
    int orders_used;            /* Number of orders consumed in simulation */
    bool stale_warning;         /* true if quote is based on stale/migrate orders */
} cell_dex_quote_t;

/* ============================================================================
 * QUOTE FUNCTIONS
 * ============================================================================ */

/**
 * Get swap quote via Cellframe DEX order book simulation
 *
 * Fetches open orders from public RPC, filters by pair and availability,
 * sorts by best rate for taker, then walks the order book to simulate
 * filling the requested amount.
 *
 * @param from_token    Input token symbol (e.g., "CELL")
 * @param to_token      Output token symbol (e.g., "CPUNK")
 * @param amount_in     Input amount as decimal string (e.g., "10.0")
 * @param dex_filter    DEX filter (unused, for API compat — pass NULL)
 * @param quotes_out    Output: array of quotes (caller provides buffer)
 * @param max_quotes    Size of quotes_out array
 * @param count_out     Output: number of quotes returned (0 or 1)
 * @return              0 on success, -1 on error, -2 if pair not found
 */
int cell_dex_get_quotes(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    cell_dex_quote_t *quotes_out,
    int max_quotes,
    int *count_out
);

/**
 * List available swap pairs on Cellframe DEX
 *
 * @param pairs_out     Output: array of "FROM/TO" strings (caller frees)
 * @param count_out     Output: number of pairs
 * @return              0 on success, -1 on error
 */
int cell_dex_list_pairs(char ***pairs_out, int *count_out);

/**
 * Free pairs array from cell_dex_list_pairs
 */
void cell_dex_free_pairs(char **pairs, int count);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_DEX_H */
