#include "dht_stats.h"
#include "../shared/dht_value_storage.h"

#include <opendht/dhtrunner.h>
#include <iostream>
#include <cstring>
#include <stdint.h>
#include <stdbool.h>

// Forward declare dht_config_t (avoid circular dependency)
typedef struct {
    uint16_t port;
    bool is_bootstrap;
    char identity[256];
    char bootstrap_nodes[5][256];
    size_t bootstrap_count;
    char persistence_path[512];
} dht_config_t;

// Need the full dht_context struct definition (from dht_context.cpp)
struct dht_context {
    dht::DhtRunner runner;
    dht_config_t config;
    bool running;
    dht_value_storage_t *storage;  // Value persistence (NULL for user nodes)

    dht_context() : running(false), storage(nullptr) {
        memset(&config, 0, sizeof(config));
    }
};

//=============================================================================
// DHT Statistics
//=============================================================================

/**
 * Get DHT statistics
 */
extern "C" int dht_get_stats(dht_context_t *ctx,
                             size_t *node_count,
                             size_t *stored_values) {
    if (!ctx || !node_count || !stored_values) {
        std::cerr << "[DHT] ERROR: NULL parameter in dht_get_stats" << std::endl;
        return -1;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
        return -1;
    }

    try {
        auto node_info = ctx->runner.getNodeInfo();

        // In OpenDHT 2.4, stats are split between ipv4 and ipv6
        size_t ipv4_nodes = node_info.ipv4.good_nodes + node_info.ipv4.dubious_nodes;
        size_t ipv6_nodes = node_info.ipv6.good_nodes + node_info.ipv6.dubious_nodes;
        *node_count = ipv4_nodes + ipv6_nodes;
        *stored_values = node_info.storage_size;

        std::cout << "[STATS_DEBUG] node_info.storage_size=" << node_info.storage_size
                  << ", node_info.storage_values=" << node_info.storage_values << std::endl;
        std::cout << "[DHT] Stats: " << *node_count << " nodes, "
                  << *stored_values << " stored values" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_get_stats: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Get storage pointer from DHT context
 */
extern "C" dht_value_storage_t* dht_get_storage(dht_context_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    return ctx->storage;
}
