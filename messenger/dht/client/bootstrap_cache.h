/**
 * Bootstrap Node Cache - SQLite-based local cache for discovered bootstrap nodes
 *
 * Enables decentralization by:
 * - Caching discovered Nodus nodes from DHT registry
 * - Prioritizing cached nodes over hardcoded ones
 * - Tracking reliability (connection failures, last_connected)
 * - Providing cold-start resilience if official nodes are down
 *
 * Database: ~/.dna/bootstrap_cache.db
 */

#ifndef BOOTSTRAP_CACHE_H
#define BOOTSTRAP_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Cached bootstrap node entry
 */
typedef struct {
    char ip[64];                   // IPv4 or IPv6 address
    uint16_t port;                 // DHT port (usually 4000)
    char node_id[129];             // SHA3-512(public_key) as hex
    char version[32];              // Nodus version (e.g., "v0.4.3")
    uint64_t last_seen;            // Last seen in DHT registry (Unix timestamp)
    uint64_t last_connected;       // When we last successfully connected (Unix timestamp)
    int connection_attempts;       // Total connection attempts
    int connection_failures;       // Total failed connection attempts
} bootstrap_cache_entry_t;

/**
 * Initialize bootstrap cache
 * Creates SQLite database if it doesn't exist
 *
 * @param db_path: Path to SQLite database file (NULL = default ~/.dna/bootstrap_cache.db)
 * @return: 0 on success, -1 on error
 */
int bootstrap_cache_init(const char *db_path);

/**
 * Cleanup bootstrap cache
 * Closes database connection
 */
void bootstrap_cache_cleanup(void);

/**
 * Store or update a discovered bootstrap node
 * Updates existing entry if IP:port exists, creates new one otherwise
 *
 * @param ip: Node IP address
 * @param port: Node DHT port
 * @param node_id: DHT node fingerprint (can be NULL)
 * @param version: Nodus version string (can be NULL)
 * @param last_seen: Unix timestamp from DHT registry
 * @return: 0 on success, -1 on error
 */
int bootstrap_cache_put(const char *ip, uint16_t port, const char *node_id,
                        const char *version, uint64_t last_seen);

/**
 * Get top N nodes sorted by reliability
 * Sorted by: connection_failures ASC, last_connected DESC
 *
 * @param limit: Maximum number of nodes to return
 * @param nodes_out: Output array (caller must free)
 * @param count_out: Number of nodes returned
 * @return: 0 on success, -1 on error
 */
int bootstrap_cache_get_best(size_t limit, bootstrap_cache_entry_t **nodes_out,
                             size_t *count_out);

/**
 * Get all cached nodes
 *
 * @param nodes_out: Output array (caller must free)
 * @param count_out: Number of nodes returned
 * @return: 0 on success, -1 on error
 */
int bootstrap_cache_get_all(bootstrap_cache_entry_t **nodes_out, size_t *count_out);

/**
 * Mark a node as successfully connected
 * Resets connection_failures to 0 and updates last_connected
 *
 * @param ip: Node IP address
 * @param port: Node DHT port
 * @return: 0 on success, -1 on error
 */
int bootstrap_cache_mark_connected(const char *ip, uint16_t port);

/**
 * Mark a node as failed to connect
 * Increments connection_failures counter
 *
 * @param ip: Node IP address
 * @param port: Node DHT port
 * @return: 0 on success, -1 on error
 */
int bootstrap_cache_mark_failed(const char *ip, uint16_t port);

/**
 * Remove nodes not seen in DHT registry for X seconds
 *
 * @param max_age_seconds: Maximum age in seconds (nodes older are deleted)
 * @return: Number of entries deleted, -1 on error
 */
int bootstrap_cache_expire(uint64_t max_age_seconds);

/**
 * Get count of cached nodes
 *
 * @return: Number of cached nodes, -1 on error
 */
int bootstrap_cache_count(void);

/**
 * Check if a node exists in cache
 *
 * @param ip: Node IP address
 * @param port: Node DHT port
 * @return: true if exists, false otherwise
 */
bool bootstrap_cache_exists(const char *ip, uint16_t port);

/**
 * Free array of cache entries
 *
 * @param entries: Array to free
 */
void bootstrap_cache_free_entries(bootstrap_cache_entry_t *entries);

#ifdef __cplusplus
}
#endif

#endif // BOOTSTRAP_CACHE_H
