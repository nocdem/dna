#ifndef DHT_STATS_H
#define DHT_STATS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Forward declarations
 */
typedef struct dht_context dht_context_t;
struct dht_value_storage;

/**
 * Get DHT statistics
 *
 * Returns the number of DHT nodes in the routing table and
 * the number of values stored locally.
 *
 * @param ctx DHT context
 * @param node_count Output: number of nodes in routing table (IPv4 + IPv6)
 * @param stored_values Output: number of values stored locally
 * @return 0 on success, -1 on error
 */
int dht_get_stats(dht_context_t *ctx,
                  size_t *node_count,
                  size_t *stored_values);

/**
 * Get storage pointer from DHT context
 *
 * Used by bootstrap nodes to access the persistent value storage.
 * Returns NULL for client nodes without storage.
 *
 * @param ctx DHT context
 * @return Storage pointer or NULL
 */
struct dht_value_storage* dht_get_storage(dht_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // DHT_STATS_H
