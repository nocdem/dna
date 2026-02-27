/**
 * DHT Bootstrap Node Registry
 *
 * Distributed discovery system for DNA Messenger bootstrap nodes.
 * Instead of hardcoding bootstrap IPs, nodes register themselves in DHT
 * and clients discover them dynamically.
 *
 * Storage Model (Owner-Namespaced via Chunked):
 * - Each node's entry stored at: dna:bootstrap:node:node_id (chunked)
 * - Node index at: dna:bootstrap:nodes (multi-owner, small)
 * - Nodes refresh registration every 5 minutes (heartbeat)
 * - Clients query index and filter by last_seen < 15 minutes
 *
 * Cold Start:
 * - Clients need ONE hardcoded seed node to read the registry
 * - After that, use dynamic discovery for resilience
 */

#ifndef DHT_BOOTSTRAP_REGISTRY_H
#define DHT_BOOTSTRAP_REGISTRY_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct dht_context dht_context_t;

#define DHT_BOOTSTRAP_MAX_NODES 256
#define DHT_BOOTSTRAP_REGISTRY_KEY_SIZE 129  // SHA3-512 hex = 128 + null
#define DHT_BOOTSTRAP_STALE_TIMEOUT 900      // 15 minutes (in seconds)
#define DHT_BOOTSTRAP_REFRESH_INTERVAL 300   // 5 minutes (in seconds)

/**
 * Bootstrap node entry
 */
typedef struct {
    char ip[64];               // IPv4 or IPv6 address
    uint16_t port;             // DHT port (usually 4000)
    char node_id[129];         // SHA3-512(public_key) as hex string
    char version[32];          // dna-nodus version (e.g., "v0.2")
    uint64_t last_seen;        // Unix timestamp of last registration
    uint64_t uptime;           // Seconds since node started
} bootstrap_node_entry_t;

/**
 * Bootstrap registry (collection of all active nodes)
 */
typedef struct {
    bootstrap_node_entry_t nodes[DHT_BOOTSTRAP_MAX_NODES];
    size_t node_count;
    uint64_t registry_version;  // Incremented on each update
} bootstrap_registry_t;

/**
 * Register this bootstrap node in the DHT registry
 * Called by dna-nodus on startup and every 5 minutes
 *
 * @param dht_ctx: DHT context
 * @param my_ip: This node's public IP
 * @param my_port: This node's DHT port
 * @param node_id: SHA3-512(public_key) hex string
 * @param version: Version string (e.g., "v0.2")
 * @param uptime: Seconds since node started
 * @return: 0 on success, -1 on error
 */
int dht_bootstrap_registry_register(
    dht_context_t *dht_ctx,
    const char *my_ip,
    uint16_t my_port,
    const char *node_id,
    const char *version,
    uint64_t uptime
);

/**
 * Fetch the bootstrap registry from DHT
 * Used by clients to discover active bootstrap nodes
 *
 * @param dht_ctx: DHT context
 * @param registry_out: Output registry structure
 * @return: 0 on success, -1 on error
 */
int dht_bootstrap_registry_fetch(
    dht_context_t *dht_ctx,
    bootstrap_registry_t *registry_out
);

/**
 * Filter registry to only include active nodes (last_seen < 15 min)
 *
 * @param registry: Input/output registry (modified in-place)
 */
void dht_bootstrap_registry_filter_active(bootstrap_registry_t *registry);

/**
 * Serialize registry to JSON
 * Caller must free() returned string
 */
char* dht_bootstrap_registry_to_json(const bootstrap_registry_t *registry);

/**
 * Deserialize registry from JSON
 * Returns: 0 on success, -1 on error
 */
int dht_bootstrap_registry_from_json(const char *json, bootstrap_registry_t *registry);

#ifdef __cplusplus
}
#endif

#endif // DHT_BOOTSTRAP_REGISTRY_H
