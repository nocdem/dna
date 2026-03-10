/**
 * Wallet Balance Cache Database
 * GLOBAL SQLite cache for wallet balances (stale-while-revalidate pattern)
 *
 * Architecture:
 * - Global database: <data_dir>/wallet_cache.db
 * - No TTL eviction: balances are always overwritten on fresh fetch
 * - Stale-while-revalidate: UI reads cache instantly, live fetch updates in background
 * - Shared across engine restarts (survives pause/resume, app restart)
 *
 * Database Schema:
 * CREATE TABLE wallet_balances (
 *     wallet_index INTEGER NOT NULL,
 *     token        TEXT NOT NULL,
 *     network      TEXT NOT NULL,
 *     balance      TEXT NOT NULL,
 *     cached_at    INTEGER NOT NULL,
 *     PRIMARY KEY(wallet_index, token, network)
 * );
 *
 * @file wallet_cache.h
 * @date 2026-02-23
 */

#ifndef DNA_WALLET_CACHE_H
#define DNA_WALLET_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include "dna/dna_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/**
 * Initialize wallet cache database
 * Creates database file at <data_dir>/wallet_cache.db if it doesn't exist
 *
 * @return 0 on success, -1 on error
 */
int wallet_cache_init(void);

/**
 * Close wallet cache database
 * Call on shutdown. Safe to call multiple times.
 */
void wallet_cache_close(void);

/* ── Balance operations ────────────────────────────────────────────── */

/**
 * Save balances to cache (upsert — replaces existing entries)
 * Called after successful live blockchain fetch
 *
 * @param wallet_index Wallet index (0-based)
 * @param balances     Array of balance entries
 * @param count        Number of entries
 * @return 0 on success, -1 on error
 */
int wallet_cache_save_balances(int wallet_index,
                               const dna_balance_t *balances, int count);

/**
 * Get cached balances for a wallet (instant, no network calls)
 * Caller must free *balances_out with free() when done
 *
 * @param wallet_index  Wallet index (0-based)
 * @param balances_out  Output: heap-allocated array of dna_balance_t
 * @param count_out     Output: number of entries
 * @return 0 on success, -1 on error, -2 if no cached data
 */
int wallet_cache_get_balances(int wallet_index,
                              dna_balance_t **balances_out, int *count_out);

/* ── Transaction operations ────────────────────────────────────────── */

/**
 * Save transactions to cache (upsert by tx_hash)
 * Called after successful RPC fetch — accumulates over time
 *
 * @param wallet_index Wallet index (0-based)
 * @param network      Network name (e.g., "Solana", "Ethereum", "Backbone")
 * @param txs          Array of transaction entries
 * @param count        Number of entries
 * @return 0 on success, -1 on error
 */
int wallet_cache_save_transactions(int wallet_index, const char *network,
                                    const dna_transaction_t *txs, int count);

/**
 * Get cached transactions for a wallet/network (instant, no network calls)
 * Caller must free *txs_out with free() when done
 *
 * @param wallet_index Wallet index (0-based)
 * @param network      Network name
 * @param txs_out      Output: heap-allocated array of dna_transaction_t
 * @param count_out    Output: number of entries
 * @return 0 on success, -1 on error, -2 if no cached data
 */
int wallet_cache_get_transactions(int wallet_index, const char *network,
                                   dna_transaction_t **txs_out, int *count_out);

/**
 * Clear all cached data (balances + transactions)
 * Used on logout or identity switch
 *
 * @return 0 on success, -1 on error
 */
int wallet_cache_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* DNA_WALLET_CACHE_H */
