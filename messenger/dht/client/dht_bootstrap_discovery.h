/**
 * DHT Bootstrap Discovery - Client-side node discovery
 *
 * Enables decentralization by:
 * - Discovering active Nodus nodes from DHT bootstrap registry
 * - Running discovery in background thread (non-blocking)
 * - Caching discovered nodes to SQLite for cold-start resilience
 * - Providing reliability-first bootstrap (cached nodes > hardcoded)
 */

#ifndef DHT_BOOTSTRAP_DISCOVERY_H
#define DHT_BOOTSTRAP_DISCOVERY_H

#include "../core/dht_context.h"
#include "../../dna_config.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Discovery completion callback
 * Called from discovery thread when discovery finishes
 *
 * @param nodes_found: Number of new nodes discovered and connected
 * @param user_data: User-provided context
 */
typedef void (*dht_discovery_callback_t)(int nodes_found, void *user_data);

/**
 * Populate dht_config with best cached bootstrap nodes
 * Uses reliability-first selection: sorted by (failures ASC, last_connected DESC)
 *
 * @param dht_config: DHT config to populate (bootstrap_nodes, bootstrap_count)
 * @param max_nodes: Maximum number of nodes to add (usually 3)
 * @return: Number of nodes added, 0 if cache empty
 */
int dht_bootstrap_from_cache(dht_config_t *dht_config, size_t max_nodes);

/**
 * Start background discovery thread
 * Fetches bootstrap registry from DHT and saves discovered nodes to SQLite
 * NON-BLOCKING - returns immediately, discovery runs in background
 *
 * @param dht_ctx: Active (connected) DHT context
 * @return: 0 on success (thread started), -1 on error
 */
int dht_bootstrap_discovery_start(dht_context_t *dht_ctx);

/**
 * Stop discovery thread
 * Call on application shutdown
 */
void dht_bootstrap_discovery_stop(void);

/**
 * Check if discovery is currently running
 *
 * @return: true if discovery thread is active
 */
bool dht_bootstrap_discovery_is_running(void);

/**
 * Set callback for discovery completion
 * Callback is called from discovery thread - use mutex if accessing shared state
 *
 * @param callback: Function to call when discovery completes (NULL to clear)
 * @param user_data: User context passed to callback
 */
void dht_bootstrap_discovery_set_callback(dht_discovery_callback_t callback, void *user_data);

/**
 * Run discovery synchronously (blocking)
 * Use this instead of start/stop for testing or single-shot discovery
 *
 * @param dht_ctx: Active (connected) DHT context
 * @return: Number of nodes discovered and connected, -1 on error
 */
int dht_bootstrap_discovery_run_sync(dht_context_t *dht_ctx);

#ifdef __cplusplus
}
#endif

#endif // DHT_BOOTSTRAP_DISCOVERY_H
