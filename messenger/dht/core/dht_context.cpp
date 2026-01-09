/**
 * DHT Context - C++ Implementation using OpenDHT
 *
 * This wraps OpenDHT's DhtRunner class with a C API.
 *
 * @file dht_context.cpp
 * @author DNA Messenger Team
 * @date 2025-11-01
 */

#include "dht_context.h"
#include "../shared/dht_value_storage.h"  // Phase 4: Moved to shared/
#include "dht_stats.h"     // Phase 3: Stats functions
#include "../client/dht_identity.h" // Phase 3: Identity functions
#include <opendht/dhtrunner.h>
#include <opendht/crypto.h>
#include <cstring>
#include <memory>
#include <vector>
#include <iostream>
#include <sstream>
#include <chrono>
#include <future>
#include <thread>
#include <fstream>

// Use unified QGP logging (respects config log level)
extern "C" {
#include "crypto/utils/qgp_log.h"
}
#define DHT_LOG_TAG "DHT_CONTEXT"
#define DHT_LOGI(...) QGP_LOG_INFO(DHT_LOG_TAG, __VA_ARGS__)
#define DHT_LOGE(...) QGP_LOG_ERROR(DHT_LOG_TAG, __VA_ARGS__)

// Opaque handle for DHT Identity (wraps C++ dht::crypto::Identity)
// Must be defined before any functions that use it
struct dht_identity {
    dht::crypto::Identity identity;  // C++ OpenDHT Identity
    dht_identity(const dht::crypto::Identity& id) : identity(id) {}
};

// Global storage pointer (accessed from ValueType store callbacks)
// Using the old working approach: global pointer set after storage init
static dht_value_storage_t *g_global_storage = nullptr;
static std::mutex g_storage_mutex;

// Helper functions for persistent Dilithium5 identity
namespace {
    // Save Dilithium5 identity to binary files
    bool save_identity_dilithium5(const dht::crypto::Identity& id, const std::string& base_path) {
        try {
            // Save Dilithium5 identity using OpenDHT-PQ API
            // Creates: base_path.dsa (private key), base_path.pub (public key), base_path.cert (certificate)
            dht::crypto::saveDilithiumIdentity(id, base_path);

            QGP_LOG_INFO("DHT", "Saved Dilithium5 identity to %s.{dsa,pub,cert}", base_path.c_str());
            QGP_LOG_INFO("DHT", "FIPS 204 - ML-DSA-87 - NIST Category 5 (256-bit quantum)");
            return true;
        } catch (const std::exception& e) {
            QGP_LOG_ERROR("DHT", "Exception saving Dilithium5 identity: %s", e.what());
            return false;
        }
    }

    // Load Dilithium5 identity from binary files
    dht::crypto::Identity load_identity_dilithium5(const std::string& base_path) {
        try {
            // Load Dilithium5 identity using OpenDHT-PQ API
            // Reads: base_path.dsa (private key), base_path.pub (public key), base_path.cert (certificate)
            auto id = dht::crypto::loadDilithiumIdentity(base_path);

            QGP_LOG_INFO("DHT", "Loaded Dilithium5 identity from %s.{dsa,pub,cert}", base_path.c_str());
            QGP_LOG_INFO("DHT", "FIPS 204 - ML-DSA-87 - NIST Category 5 (256-bit quantum)");
            return id;
        } catch (const std::exception& e) {
            QGP_LOG_ERROR("DHT", "Exception loading Dilithium5 identity: %s", e.what());
            throw;
        }
    }
}

// Internal C++ struct (hidden from C code)
struct dht_context {
    dht::DhtRunner runner;
    dht_config_t config;
    bool running;
    dht_value_storage_t *storage;  // Value persistence (NULL for user nodes)
    dht_identity_t *owned_identity;  // User-provided identity (freed on cleanup)

    // ValueTypes with lambda-captured context (eliminates global storage pointer)
    dht::ValueType type_7day;
    dht::ValueType type_30day;
    dht::ValueType type_365day;

    // Status change callback (called from OpenDHT thread)
    dht_status_callback_t status_callback;
    void *status_callback_user_data;
    std::mutex status_callback_mutex;
    bool prev_connected;  // Track connection state per-context (not static!)

    dht_context() : running(false), storage(nullptr), owned_identity(nullptr),
                    // Initialize with default values (configured properly in start())
                    type_7day(0, "", std::chrono::hours(0)),
                    type_30day(0, "", std::chrono::hours(0)),
                    type_365day(0, "", std::chrono::hours(0)),
                    status_callback(nullptr),
                    status_callback_user_data(nullptr),
                    prev_connected(false) {
        memset(&config, 0, sizeof(config));
    }
};

// Factory functions to create ValueTypes with captured context (MUST be after struct definition)
namespace {
    // Factory: Create 7-day ValueType with captured context
    dht::ValueType create_7day_type(dht_context_t* ctx) {
        return dht::ValueType(
            0x1001,                      // Type ID
            "DNA_7DAY",                  // Type name
            std::chrono::hours(7 * 24),  // 7 days TTL
            [](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
                  const dht::InfoHash&, const dht::SockAddr&) -> bool {
                // Store to persistent storage if available (using global storage pointer)
                std::lock_guard<std::mutex> lock(g_storage_mutex);
                if (g_global_storage && value) {
                    uint64_t now = time(NULL);
                    uint64_t expires_at = now + (7 * 24 * 3600);

                    if (dht_value_storage_should_persist(value->type, expires_at)) {
                        // CRITICAL FIX: Store full serialized Value (including signature)
                        // Previously stored only value->data, losing signature on republish
                        dht::Blob packed = value->getPacked();

                        dht_value_metadata_t metadata;
                        // Use binary InfoHash (20 bytes) - hash_to_hex() will convert to 40 hex chars
                        // Previously used key.toString() which was then double-encoded to 80 hex chars
                        metadata.key_hash = key.data();
                        metadata.key_hash_len = key.size();  // 20 bytes
                        metadata.value_data = packed.data();
                        metadata.value_data_len = packed.size();
                        metadata.value_type = value->type;
                        metadata.created_at = now;
                        metadata.expires_at = expires_at;

                        if (dht_value_storage_put(g_global_storage, &metadata) == 0) {
                            QGP_LOG_DEBUG("Storage", "Persisted 7-day value (packed %zu bytes, data %zu bytes)", packed.size(), value->data.size());
                        }
                    }
                }
                return true;  // Accept all
            }
        );
    }

    // Factory: Create 30-day ValueType with captured context
    dht::ValueType create_30day_type(dht_context_t* ctx) {
        return dht::ValueType(
            0x1003,                      // Type ID
            "DNA_30DAY",                 // Type name
            std::chrono::hours(30 * 24), // 30 days TTL
            [](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
                  const dht::InfoHash&, const dht::SockAddr&) -> bool {
                // Store to persistent storage if available (using global storage pointer)
                std::lock_guard<std::mutex> lock(g_storage_mutex);
                if (g_global_storage && value) {
                    uint64_t now = time(NULL);
                    uint64_t expires_at = now + (30 * 24 * 3600);

                    if (dht_value_storage_should_persist(value->type, expires_at)) {
                        // CRITICAL FIX: Store full serialized Value (including signature)
                        dht::Blob packed = value->getPacked();

                        dht_value_metadata_t metadata;
                        // Use binary InfoHash (20 bytes) - hash_to_hex() will convert to 40 hex chars
                        metadata.key_hash = key.data();
                        metadata.key_hash_len = key.size();  // 20 bytes
                        metadata.value_data = packed.data();
                        metadata.value_data_len = packed.size();
                        metadata.value_type = value->type;
                        metadata.created_at = now;
                        metadata.expires_at = expires_at;

                        if (dht_value_storage_put(g_global_storage, &metadata) == 0) {
                            QGP_LOG_DEBUG("Storage", "Persisted 30-day value (packed %zu bytes, data %zu bytes)", packed.size(), value->data.size());
                        }
                    }
                }
                return true;  // Accept all
            }
        );
    }

    // Factory: Create 365-day ValueType with captured context
    dht::ValueType create_365day_type(dht_context_t* ctx) {
        return dht::ValueType(
            0x1002,                       // Type ID
            "DNA_365DAY",                 // Type name
            std::chrono::hours(365 * 24), // 365 days TTL
            [](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
                  const dht::InfoHash&, const dht::SockAddr&) -> bool {
                // Store to persistent storage if available (using global storage pointer)
                std::lock_guard<std::mutex> lock(g_storage_mutex);
                if (g_global_storage && value) {
                    uint64_t now = time(NULL);
                    uint64_t expires_at = now + (365 * 24 * 3600);

                    if (dht_value_storage_should_persist(value->type, expires_at)) {
                        // CRITICAL FIX: Store full serialized Value (including signature)
                        dht::Blob packed = value->getPacked();

                        dht_value_metadata_t metadata;
                        // Use binary InfoHash (20 bytes) - hash_to_hex() will convert to 40 hex chars
                        metadata.key_hash = key.data();
                        metadata.key_hash_len = key.size();  // 20 bytes
                        metadata.value_data = packed.data();
                        metadata.value_data_len = packed.size();
                        metadata.value_type = value->type;
                        metadata.created_at = now;
                        metadata.expires_at = expires_at;

                        if (dht_value_storage_put(g_global_storage, &metadata) == 0) {
                            QGP_LOG_DEBUG("Storage", "Persisted 365-day value (packed %zu bytes, data %zu bytes)", packed.size(), value->data.size());
                        }
                    }
                }
                return true;  // Accept all
            }
        );
    }

    /**
     * Persist value metadata to storage (internal helper)
     *
     * Factors out the duplicated persistent storage logic from dht_put_ttl()
     * and dht_put_signed(). This is an internal helper, not a public C API.
     *
     * @param ctx DHT context (for accessing ctx->storage)
     * @param key Original key bytes (not hashed)
     * @param key_len Key length (typically 64 for SHA3-512)
     * @param value Original value bytes
     * @param value_len Value length
     * @param value_type The assigned ValueType (0x1001, 0x1002, 0x1003)
     * @param ttl_seconds TTL in seconds (UINT_MAX = permanent)
     */
    static void persist_value_if_enabled(
        dht_context_t *ctx,
        const uint8_t *key, size_t key_len,
        const uint8_t *value, size_t value_len,
        uint32_t value_type,
        unsigned int ttl_seconds
    ) {
        if (!ctx->storage) {
            return;
        }

        uint64_t expires_at = 0;  // 0 = permanent
        if (ttl_seconds != UINT_MAX) {
            expires_at = time(NULL) + ttl_seconds;
        }

        // CRITICAL FIX (2025-11-12): Store ORIGINAL key, not derived infohash
        // This prevents double-hashing bug on republish after bootstrap restart
        // Old bug: stored infohash -> republish hashed infohash -> wrong DHT key
        dht_value_metadata_t metadata;
        metadata.key_hash = key;           // Original 64-byte SHA3-512 input
        metadata.key_hash_len = key_len;   // 64 bytes (not 40-char hex infohash)
        metadata.value_data = value;
        metadata.value_data_len = value_len;
        metadata.value_type = value_type;
        metadata.created_at = time(NULL);
        metadata.expires_at = expires_at;

        if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
            if (dht_value_storage_should_persist(metadata.value_type, metadata.expires_at)) {
                QGP_LOG_DEBUG("Storage", "Value persisted to disk (key: %zu bytes)", key_len);
            }
        }
    }

    /**
     * Register custom ValueTypes with the DHT runner (internal helper)
     *
     * @param ctx DHT context
     */
    static void register_value_types(dht_context_t *ctx) {
        QGP_LOG_INFO("DHT", "Registering custom ValueTypes...");

        // Create ValueTypes with captured context (eliminates global storage)
        ctx->type_7day = create_7day_type(ctx);
        ctx->type_30day = create_30day_type(ctx);
        ctx->type_365day = create_365day_type(ctx);

        // Register with DhtRunner
        ctx->runner.registerType(ctx->type_7day);
        ctx->runner.registerType(ctx->type_30day);
        ctx->runner.registerType(ctx->type_365day);

        QGP_LOG_INFO("DHT", "Registered DNA_TYPE_7DAY (id=0x1001, TTL=7 days)");
        QGP_LOG_INFO("DHT", "Registered DNA_TYPE_30DAY (id=0x1003, TTL=30 days)");
        QGP_LOG_INFO("DHT", "Registered DNA_TYPE_365DAY (id=0x1002, TTL=365 days)");
    }

    /**
     * Bootstrap to configured nodes (internal helper)
     *
     * @param ctx DHT context
     */
    static void bootstrap_to_nodes(dht_context_t *ctx) {
        if (ctx->config.bootstrap_count == 0) {
            QGP_LOG_INFO("DHT", "No bootstrap nodes (first node in network)");
            return;
        }

        QGP_LOG_INFO("DHT", "Bootstrapping to %zu nodes:", ctx->config.bootstrap_count);

        for (size_t i = 0; i < ctx->config.bootstrap_count; i++) {
            std::string node_addr(ctx->config.bootstrap_nodes[i]);

            // Parse IP:port
            size_t colon_pos = node_addr.find(':');
            if (colon_pos == std::string::npos) {
                QGP_LOG_ERROR("DHT", "Invalid bootstrap node format: %s", node_addr.c_str());
                continue;
            }

            std::string ip = node_addr.substr(0, colon_pos);
            std::string port_str = node_addr.substr(colon_pos + 1);

            QGP_LOG_INFO("DHT", "  -> %s:%s", ip.c_str(), port_str.c_str());

            ctx->runner.bootstrap(ip, port_str);
        }
    }
}

/**
 * Initialize DHT context
 */
extern "C" dht_context_t* dht_context_new(const dht_config_t *config) {
    if (!config) {
        QGP_LOG_ERROR("DHT", "NULL config");
        return nullptr;
    }

    try {
        auto ctx = new dht_context();
        memcpy(&ctx->config, config, sizeof(dht_config_t));
        ctx->owned_identity = nullptr;

        QGP_LOG_INFO("DHT", "Created context for node: %s", config->identity);
        QGP_LOG_INFO("DHT", "Requested port: %d%s", config->port, config->port == 0 ? " (auto-assign)" : "");
        QGP_LOG_INFO("DHT", "Bootstrap node: %s", config->is_bootstrap ? "yes" : "no");

        return ctx;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_context_new: %s", e.what());
        return nullptr;
    }
}

/**
 * Start DHT node
 */
extern "C" int dht_context_start(dht_context_t *ctx) {
    if (!ctx) {
        DHT_LOGE("NULL context");
        return -1;
    }

    if (ctx->running) {
        DHT_LOGI("Already running");
        return 0;
    }

    try {
        // Load or generate persistent node identity
        dht::crypto::Identity identity;

        DHT_LOGI("Generating ephemeral Dilithium5 identity...");

        if (ctx->config.persistence_path[0] != '\0') {
            // Bootstrap nodes: Use persistent identity (OpenDHT 2.x/3.x compatible)
            std::string identity_path = std::string(ctx->config.persistence_path) + ".identity";

            try {
                // Try to load existing identity from Dilithium5 binary files
                identity = load_identity_dilithium5(identity_path);
                DHT_LOGI("Loaded persistent identity from: %s", identity_path.c_str());
            } catch (const std::exception& e) {
                // Generate new identity if files don't exist
                DHT_LOGI("Generating new persistent identity...");
                identity = dht::crypto::generateDilithiumIdentity("dht_node");

                // Save for future restarts (Dilithium5 binary format)
                if (!save_identity_dilithium5(identity, identity_path)) {
                    DHT_LOGE("WARNING: Failed to save identity, will be ephemeral!");
                }
            }
        } else {
            // User nodes: Ephemeral random Dilithium5 identity
            identity = dht::crypto::generateDilithiumIdentity("dht_node");
            DHT_LOGI("Generated ephemeral identity");
        }

        // Check if disk persistence is requested
        if (ctx->config.persistence_path[0] != '\0') {
            // Bootstrap nodes: Enable disk persistence
            std::string persist_path(ctx->config.persistence_path);
            DHT_LOGI("Enabling disk persistence: %s", persist_path.c_str());
            DHT_LOGI("Bootstrap mode: %s", ctx->config.is_bootstrap ? "enabled" : "disabled");

            // Create DhtRunner::Config with persistence
            dht::DhtRunner::Config config;
            config.dht_config.node_config.maintain_storage = true;
            config.dht_config.node_config.persist_path = persist_path;
            config.dht_config.node_config.max_store_size = -1;  // Unlimited storage (default 0 = no storage!)
            // NOTE: Testing with is_bootstrap = true
            config.dht_config.node_config.is_bootstrap = ctx->config.is_bootstrap;
            config.dht_config.node_config.public_stable = ctx->config.is_bootstrap;  // Public bootstrap nodes are stable
            config.dht_config.id = identity;
            config.threaded = true;

            DHT_LOGI("Configured persistence: maintain_storage=1, max_store_size=-1");
            DHT_LOGI("  is_bootstrap=%d, public_stable=%d",
                     config.dht_config.node_config.is_bootstrap,
                     config.dht_config.node_config.public_stable);

            ctx->runner.run(ctx->config.port, config);
        } else {
            // User nodes: Memory-only (fast, no disk I/O)
            DHT_LOGI("Running in memory-only mode (no disk persistence)");
            DHT_LOGI("Starting DHT (requesting port %d)...", ctx->config.port);
            ctx->runner.run(ctx->config.port, identity, true);
        }

        // Get actual bound port (may differ from requested if port was 0)
        in_port_t actual_port = ctx->runner.getBoundPort();
        DHT_LOGI("Node started on port %d", (int)actual_port);

        // Initialize value storage BEFORE ValueTypes (bootstrap nodes only)
        // CRITICAL: Storage must be initialized before ValueTypes so storeCallback can use it
        if (ctx->config.persistence_path[0] != '\0') {
            std::string storage_path = std::string(ctx->config.persistence_path) + ".values.db";
            DHT_LOGI("Initializing value storage: %s", storage_path.c_str());

            ctx->storage = dht_value_storage_new(storage_path.c_str());
            if (ctx->storage) {
                DHT_LOGI("Value storage initialized");

                // Set global storage pointer (used by ValueType store callbacks)
                {
                    std::lock_guard<std::mutex> lock(g_storage_mutex);
                    g_global_storage = ctx->storage;
                }
                DHT_LOGI("Storage callbacks enabled in ValueTypes");

                // Launch async republish in background
                if (dht_value_storage_restore_async(ctx->storage, ctx) == 0) {
                    DHT_LOGI("Async value republish started");
                } else {
                    DHT_LOGE("WARNING: Failed to start async republish");
                }
            } else {
                DHT_LOGE("WARNING: Value storage initialization failed");
            }
        }

        // Register custom ValueTypes (CRITICAL: all nodes must know these types!)
        DHT_LOGI("Registering custom ValueTypes...");
        register_value_types(ctx);

        // Bootstrap to other nodes
        DHT_LOGI("Bootstrapping to seed nodes...");
        bootstrap_to_nodes(ctx);

        ctx->running = true;
        DHT_LOGI("DHT context started successfully");
        return 0;
    } catch (const std::exception& e) {
        DHT_LOGE("Exception in dht_context_start: %s", e.what());
        return -1;
    }
}

/**
 * Start DHT node with user-provided identity
 * (Used for encrypted backup system)
 */
extern "C" int dht_context_start_with_identity(dht_context_t *ctx, dht_identity_t *user_identity) {
    if (!ctx || !user_identity) {
        QGP_LOG_ERROR("DHT", "NULL context or identity");
        return -1;
    }

    if (ctx->running) {
        QGP_LOG_INFO("DHT", "Already running");
        return 0;
    }

    try {
        // Use provided identity instead of generating one
        dht::crypto::Identity& identity = user_identity->identity;

        // Take ownership of identity for cleanup
        ctx->owned_identity = user_identity;

        QGP_LOG_INFO("DHT", "Using user-provided DHT identity");

        // User nodes always run memory-only (no disk persistence)
        QGP_LOG_INFO("DHT", "Running in memory-only mode (no disk persistence)");
        ctx->runner.run(ctx->config.port, identity, true);

        QGP_LOG_INFO("DHT", "Node started on port %d", ctx->config.port);

        // Register custom ValueTypes
        register_value_types(ctx);

        // Bootstrap to other nodes
        bootstrap_to_nodes(ctx);

        ctx->running = true;
        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_context_start_with_identity: %s", e.what());
        return -1;
    }
}

/**
 * Stop DHT node
 */
extern "C" void dht_context_stop(dht_context_t *ctx) {
    if (!ctx) return;

    try {
        QGP_LOG_INFO("DHT", "Stopping DHT context...");
        if (ctx->running) {
            ctx->running = false;
            ctx->runner.shutdown();
            ctx->runner.join();
            QGP_LOG_INFO("DHT", "DHT runner stopped");

            // Cleanup value storage
            if (ctx->storage) {
                QGP_LOG_INFO("DHT", "Cleaning up value storage...");
                dht_value_storage_free(ctx->storage);
                ctx->storage = nullptr;
            }

            ctx->running = false;
        }
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_context_stop: %s", e.what());
    }
}

/**
 * Free DHT context
 */
extern "C" void dht_context_free(dht_context_t *ctx) {
    if (!ctx) return;

    try {
        dht_context_stop(ctx);

        // Free owned identity (if any)
        if (ctx->owned_identity) {
            delete ctx->owned_identity;
            ctx->owned_identity = nullptr;
        }

        delete ctx;
        QGP_LOG_INFO("DHT", "Context freed");
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_context_free: %s", e.what());
    }
}

/**
 * Check if DHT is ready
 *
 * Optimized to use getNodesStats() directly instead of getNodeInfo()
 * to avoid unnecessary getStoreSize() calls during bootstrap polling.
 */
extern "C" bool dht_context_is_ready(dht_context_t *ctx) {
    if (!ctx || !ctx->running) return false;

    try {
        // Check if we have connected to at least one peer
        // Use getNodesStats() directly (lighter than getNodeInfo() which also queries store size)
        auto stats_v4 = ctx->runner.getNodesStats(AF_INET);
        auto stats_v6 = ctx->runner.getNodesStats(AF_INET6);
        size_t total_good = stats_v4.good_nodes + stats_v6.good_nodes;
        return total_good > 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_context_is_ready: %s", e.what());
        return false;
    }
}

/**
 * Check if DHT context is running (not stopped/cleaned up)
 *
 * This is a simpler check than dht_context_is_ready() - it only checks
 * if the context is running, not if it's connected to peers.
 * Use this to detect if DHT is being cleaned up during reinit.
 */
extern "C" bool dht_context_is_running(dht_context_t *ctx) {
    if (!ctx) return false;
    return ctx->running;
}

/**
 * Set callback for DHT connection status changes
 */
extern "C" void dht_context_set_status_callback(dht_context_t *ctx, dht_status_callback_t callback, void *user_data) {
    if (!ctx) return;

    // Store callback info (thread-safe)
    {
        std::lock_guard<std::mutex> lock(ctx->status_callback_mutex);
        ctx->status_callback = callback;
        ctx->status_callback_user_data = user_data;
    }

    if (!callback) {
        QGP_LOG_INFO("DHT", "Status callback cleared");
        return;
    }

    QGP_LOG_INFO("DHT", "Status callback registered");

    // Register with OpenDHT's status change notification
    // NOTE: Callback params are (status_ipv4, status_ipv6), NOT (old, new)!
    // NOTE: This callback is called from OpenDHT's internal thread - do NOT call
    // runner methods from here (like getNodesStats) as it causes deadlock!
    ctx->runner.setOnStatusChanged([ctx](dht::NodeStatus status4, dht::NodeStatus status6) {
        // Combined status: connected if either IPv4 or IPv6 is connected
        bool is_connected = (status4 == dht::NodeStatus::Connected ||
                             status6 == dht::NodeStatus::Connected);

        QGP_LOG_INFO("DHT", "OpenDHT status: v4=%s, v6=%s, combined=%s",
            dht::statusToStr(status4), dht::statusToStr(status6),
            is_connected ? "connected" : "disconnected");

        // Only notify on actual transitions (track previous state per-context)
        if (ctx->prev_connected != is_connected) {
            QGP_LOG_WARN("DHT", "Status transition: %s -> %s",
                         ctx->prev_connected ? "connected" : "disconnected",
                         is_connected ? "connected" : "disconnected");
            ctx->prev_connected = is_connected;

            // Get callback info (thread-safe)
            dht_status_callback_t cb = nullptr;
            void *ud = nullptr;
            {
                std::lock_guard<std::mutex> lock(ctx->status_callback_mutex);
                cb = ctx->status_callback;
                ud = ctx->status_callback_user_data;
            }

            if (cb) {
                cb(is_connected, ud);
            } else {
                QGP_LOG_WARN("DHT", "No callback registered!");
            }
        }
    });

    // Check if already connected (callback registered after DHT started)
    // Check BOTH IPv4 and IPv6 - original code only checked IPv4
    try {
        auto stats_v4 = ctx->runner.getNodesStats(AF_INET);
        auto stats_v6 = ctx->runner.getNodesStats(AF_INET6);
        size_t total_good = stats_v4.good_nodes + stats_v6.good_nodes;
        if (total_good > 0) {
            QGP_LOG_WARN("DHT", "Already connected (%zu nodes: v4=%u, v6=%u) - firing callback",
                         total_good, stats_v4.good_nodes, stats_v6.good_nodes);
            callback(true, user_data);
        } else {
            QGP_LOG_INFO("DHT", "Not yet connected (0 good nodes) - waiting for event");
        }
    } catch (const std::exception& e) {
        QGP_LOG_WARN("DHT", "Status check failed: %s - waiting for event", e.what());
    }
}

/**
 * Put value in DHT with custom TTL
 */
extern "C" int dht_put_ttl(dht_context_t *ctx,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *value, size_t value_len,
                           unsigned int ttl_seconds) {
    if (!ctx || !key || !value) {
        QGP_LOG_ERROR("DHT", "NULL parameter in dht_put_ttl");
        return -1;
    }

    if (!ctx->running) {
        QGP_LOG_ERROR("DHT", "Node not running");
        return -1;
    }

    try {
        // Hash the key to get infohash
        auto hash = dht::InfoHash::get(key, key_len);

        // Create value blob
        std::vector<uint8_t> data(value, value + value_len);
        auto dht_value = std::make_shared<dht::Value>(data);

        // Set TTL (0 = use default 7 days, UINT_MAX = permanent)
        if (ttl_seconds == 0) {
            ttl_seconds = 7 * 24 * 3600;  // 7 days
        }

        // Handle permanent vs timed expiration
        if (ttl_seconds == UINT_MAX) {
            // Permanent storage (never expires)
            // IMPORTANT: Must assign ValueType so bootstrap nodes recognize it
            dht_value->type = 0x1002;  // Use 365-day type for permanent data
            QGP_LOG_INFO("DHT", "PUT PERMANENT (async): %s (%zu bytes, type=0x%x)", hash.toString().c_str(), value_len, dht_value->type);

            // Use done callback to track completion
            std::promise<bool> done_promise;
            auto done_future = done_promise.get_future();

            QGP_LOG_INFO("DHT", "Initiating PUT to network (expecting replication to %zu bootstrap nodes)...", ctx->config.bootstrap_count);

            ctx->runner.put(hash, dht_value, [&done_promise](bool success, const std::vector<std::shared_ptr<dht::Node>>& nodes) {
                if (success) {
                    QGP_LOG_INFO("DHT", "PUT PERMANENT: Stored on %zu remote node(s)", nodes.size());
                    if (nodes.empty()) {
                        QGP_LOG_WARN("DHT", "Success but 0 nodes confirmed! Data might be local-only.");
                    }
                } else {
                    QGP_LOG_INFO("DHT", "PUT PERMANENT: Failed to store on any node");
                }
                done_promise.set_value(success);
            }, dht::time_point::max(), true);

            // Wait for confirmation (timeout after 30 seconds)
            QGP_LOG_INFO("DHT", "Waiting for confirmation from DHT network...");
            auto status = done_future.wait_for(std::chrono::seconds(30));

            if (status == std::future_status::timeout) {
                QGP_LOG_WARN("DHT", "PUT operation timed out after 30 seconds");
                return -2;  // Timeout error
            }

            bool success = done_future.get();
            if (!success) {
                QGP_LOG_ERROR("DHT", "PUT operation failed");
                return -3;  // Put failed
            }

            QGP_LOG_INFO("DHT", "PUT PERMANENT confirmed by network");

            // Verify data is actually retrievable (wait 5 seconds for propagation, then test GET)
            QGP_LOG_INFO("DHT", "Verifying data is retrievable (waiting 5 seconds)...");
            std::this_thread::sleep_for(std::chrono::seconds(5));

            // Try to GET the data back from the network
            auto get_future = ctx->runner.get(hash);
            auto get_status = get_future.wait_for(std::chrono::seconds(10));

            if (get_status == std::future_status::timeout) {
                QGP_LOG_WARN("DHT", "GET timed out, data may not be retrievable yet");
            } else {
                auto values = get_future.get();
                bool found = false;
                for (const auto& val : values) {
                    if (val && val->data.size() == value_len) {
                        found = true;
                        break;
                    }
                }
                if (found) {
                    QGP_LOG_INFO("DHT", "Verified: Data is retrievable from DHT network");
                } else {
                    QGP_LOG_WARN("DHT", "PUT succeeded but data not yet retrievable from network");
                }
            }
        } else {
            // Choose ValueType based on TTL (365/30/7 days)
            if (ttl_seconds >= 365 * 24 * 3600) {
                dht_value->type = 0x1002;  // 365-day
            } else if (ttl_seconds >= 30 * 24 * 3600) {
                dht_value->type = 0x1003;  // 30-day
            } else {
                dht_value->type = 0x1001;  // 7-day
            }

            QGP_LOG_INFO("DHT", "PUT: %s (%zu bytes, TTL=%us, type=0x%x)", hash.toString().c_str(), value_len, ttl_seconds, dht_value->type);

            // CRITICAL: Pass creation_time explicitly (NOT time_point::max()!)
            // OpenDHT calculates expiration as: creation_time + ValueType.expiration
            // If we let it default to time_point::max(), OpenDHT uses a fallback 3-hour TTL
            auto creation_time = dht::clock::now();  // Use OpenDHT's clock (steady_clock)

            // Put value with explicit creation time (permanent=false to use ValueType's expiration)
            ctx->runner.put(hash, dht_value,
                           [](bool success, const std::vector<std::shared_ptr<dht::Node>>&){},
                           creation_time, false);
        }

        // Store value to persistent storage (if enabled)
        persist_value_if_enabled(ctx, key, key_len, value, value_len, dht_value->type, ttl_seconds);

        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_put_ttl: %s", e.what());
        return -1;
    }
}

/**
 * Put value in DHT (default 7-day TTL)
 */
extern "C" int dht_put(dht_context_t *ctx,
                       const uint8_t *key, size_t key_len,
                       const uint8_t *value, size_t value_len) {
    return dht_put_ttl(ctx, key, key_len, value, value_len, 0);  // 0 = use default
}

/**
 * Put value in DHT permanently (never expires)
 */
extern "C" int dht_put_permanent(dht_context_t *ctx,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *value, size_t value_len) {
    return dht_put_ttl(ctx, key, key_len, value, value_len, UINT_MAX);
}

/**
 * Put SIGNED value in DHT permanently with fixed value ID
 *
 * This is a convenience wrapper that combines dht_put_signed() with permanent TTL.
 * Use this for data that should:
 * 1. Never expire (permanent storage)
 * 2. Support replacement via fixed value_id (no accumulation)
 *
 * Examples: contact lists, user profiles, settings
 */
extern "C" int dht_put_signed_permanent(dht_context_t *ctx,
                                        const uint8_t *key, size_t key_len,
                                        const uint8_t *value, size_t value_len,
                                        uint64_t value_id) {
    return dht_put_signed(ctx, key, key_len, value, value_len, value_id, UINT_MAX);
}

/**
 * Put SIGNED value in DHT with fixed value ID (enables editing/replacement)
 *
 * This function uses OpenDHT's putSigned() with a fixed value ID, which allows
 * subsequent PUTs with the same ID to REPLACE the old value instead of accumulating.
 * This solves the value accumulation problem where multiple unsigned values with
 * different IDs would pile up at the same key.
 *
 * Implementation details:
 * - Creates a shared Value with the provided data
 * - Sets fixed value ID (not auto-generated)
 * - Uses putSigned() which enables editing via EditPolicy
 * - Sequence numbers auto-increment for versioning
 * - Old values with same ID are replaced (not accumulated)
 */
extern "C" int dht_put_signed(dht_context_t *ctx,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *value, size_t value_len,
                              uint64_t value_id,
                              unsigned int ttl_seconds) {
    if (!ctx || !key || !value) {
        QGP_LOG_ERROR("DHT", "NULL parameter in dht_put_signed");
        return -1;
    }

    if (!ctx->running) {
        QGP_LOG_ERROR("DHT", "Node not running");
        return -1;
    }

    try {
        // Hash the key to get infohash
        auto hash = dht::InfoHash::get(key, key_len);

        // Create value blob
        std::vector<uint8_t> data(value, value + value_len);
        auto dht_value = std::make_shared<dht::Value>(data);

        // Set TTL (0 = use default 7 days)
        if (ttl_seconds == 0) {
            ttl_seconds = 7 * 24 * 3600;  // 7 days
        }

        // Choose ValueType based on TTL (365/30/7 days)
        if (ttl_seconds >= 365 * 24 * 3600) {
            dht_value->type = 0x1002;  // 365-day
        } else if (ttl_seconds >= 30 * 24 * 3600) {
            dht_value->type = 0x1003;  // 30-day
        } else {
            dht_value->type = 0x1001;  // 7-day
        }

        // CRITICAL: Set fixed value ID (not auto-generated)
        // This allows subsequent PUTs with same ID to replace old values
        dht_value->id = value_id;

        // Debug: show key and value info for each PUT attempt
        char key_hex_start[41];
        for (int i = 0; i < 20 && i < (int)key_len; i++) {
            sprintf(&key_hex_start[i * 2], "%02x", key[i]);
        }
        key_hex_start[40] = '\0';
        QGP_LOG_DEBUG("DHT", "PUT_SIGNED: key=%s... (%zu bytes, TTL=%us, type=0x%x, id=%llu)",
                     key_hex_start, value_len, ttl_seconds, dht_value->type, (unsigned long long)value_id);

        // Use putSigned() instead of put() to enable editing/replacement
        // Note: putSigned() doesn't support creation_time parameter (uses current time)
        // Permanent flag controls whether value expires based on ValueType
        // SYNCHRONOUS: Wait for network confirmation to get accurate success/failure
        // This ensures message status reflects actual DHT storage result
        auto result_promise = std::make_shared<std::promise<bool>>();
        std::future<bool> result_future = result_promise->get_future();

        ctx->runner.putSigned(hash, dht_value,
                             [result_promise, key_hex_start](bool success, const std::vector<std::shared_ptr<dht::Node>>& nodes){
                                 if (success) {
                                     QGP_LOG_DEBUG("DHT", "PUT_SIGNED: Stored on %zu node(s)", nodes.size());
                                 } else {
                                     QGP_LOG_WARN("DHT", "PUT_SIGNED: Failed to store on any node (key=%s...)", key_hex_start);
                                 }
                                 result_promise->set_value(success);
                             },
                             true);  // permanent=true for maintain_storage behavior

        // Wait for DHT confirmation with timeout (5 seconds)
        // In practice: ~10ms when online, fast failure when offline (no nodes reachable)
        auto status = result_future.wait_for(std::chrono::seconds(5));
        if (status == std::future_status::timeout) {
            QGP_LOG_WARN("DHT", "PUT_SIGNED: Timeout waiting for network confirmation (5s)");
            // Still persist locally for retry
            persist_value_if_enabled(ctx, key, key_len, value, value_len, dht_value->type, ttl_seconds);
            return -2;  // Timeout
        }

        bool success = result_future.get();

        // Store value to persistent storage (if enabled) - do this regardless of network result
        persist_value_if_enabled(ctx, key, key_len, value, value_len, dht_value->type, ttl_seconds);

        return success ? 0 : -1;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_put_signed: %s", e.what());
        return -1;
    }
}

/**
 * Republish a serialized (packed) Value to DHT exactly as-is
 *
 * This function deserializes a msgpack-encoded dht::Value and publishes it
 * back to the DHT network. Unlike dht_put_ttl(), this preserves the original
 * signature and all other Value fields (owner, seq, id, etc.).
 *
 * Used by republish_worker() to restore signed values after bootstrap restart.
 *
 * @param ctx DHT context
 * @param key_hex InfoHash as hex string (40 chars)
 * @param packed_data Serialized Value from Value::getPacked()
 * @param packed_len Length of packed data
 * @return 0 on success, -1 on error
 */
extern "C" int dht_republish_packed(dht_context_t *ctx,
                                     const char *key_hex,
                                     const uint8_t *packed_data,
                                     size_t packed_len) {
    if (!ctx || !key_hex || !packed_data || packed_len == 0) {
        QGP_LOG_ERROR("DHT", "NULL parameter in dht_republish_packed");
        return -1;
    }

    if (!ctx->running) {
        QGP_LOG_ERROR("DHT", "Node not running");
        return -1;
    }

    try {
        // Parse InfoHash from hex string
        dht::InfoHash hash(key_hex);
        if (!hash) {
            QGP_LOG_ERROR("DHT", "Invalid InfoHash hex: %s", key_hex);
            return -1;
        }

        // Deserialize the packed Value using msgpack
        // NOTE: Corrupt data may throw std::bad_cast - we catch and skip these
        std::shared_ptr<dht::Value> value;
        try {
            auto msg = msgpack::unpack((const char*)packed_data, packed_len);
            value = std::make_shared<dht::Value>();
            value->msgpack_unpack(msg.get());
        } catch (const msgpack::type_error& e) {
            // NOTE: type_error inherits from std::bad_cast, so catch it first
            QGP_LOG_WARN("DHT", "REPUBLISH_PACKED: %s skipped (corrupt data: type_error)", key_hex);
            return -1;  // Skip corrupt value
        } catch (const std::bad_cast& e) {
            QGP_LOG_WARN("DHT", "REPUBLISH_PACKED: %s skipped (corrupt data: bad_cast)", key_hex);
            return -1;  // Skip corrupt value, don't crash
        }

        // Log details about what we're republishing
        bool is_signed = value->owner && !value->signature.empty();
        (void)is_signed;  // Used only in debug builds
        QGP_LOG_DEBUG("DHT", "REPUBLISH_PACKED: %s (type=0x%x, id=%llu, data=%zu bytes, signed=%s)",
                     hash.toString().c_str(), value->type, (unsigned long long)value->id, value->data.size(), is_signed ? "YES" : "no");

        // Put the value back to the DHT network exactly as-is
        // permanent=true so it maintains storage behavior
        std::string hash_str = hash.toString();
        ctx->runner.put(hash, value,
                       [hash_str](bool success, const std::vector<std::shared_ptr<dht::Node>>& nodes){
                           if (success) {
                               QGP_LOG_INFO("DHT", "REPUBLISH_PACKED: %s stored on %zu node(s)", hash_str.c_str(), nodes.size());
                           } else {
                               QGP_LOG_ERROR("DHT", "REPUBLISH_PACKED: %s failed", hash_str.c_str());
                           }
                       },
                       dht::time_point::max(), true);  // permanent=true

        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_republish_packed: %s", e.what());
        return -1;
    }
}

/*============================================================================
 * DHT GET Validation Macros
 * Consolidate common validation logic for dht_get, dht_get_async, dht_get_all
 *============================================================================*/

#define DHT_GET_VALIDATE_CTX(ctx, func_name) \
    do { \
        if (!(ctx)) { \
            QGP_LOG_ERROR("DHT", "NULL context in %s", func_name); \
            return -1; \
        } \
        if (!(ctx)->running) { \
            QGP_LOG_ERROR("DHT", "Node not running in %s", func_name); \
            return -1; \
        } \
    } while(0)

#define DHT_GET_VALIDATE_CTX_ASYNC(ctx, callback, userdata, func_name) \
    do { \
        if (!(ctx)) { \
            QGP_LOG_ERROR("DHT", "NULL context in %s", func_name); \
            if (callback) (callback)(nullptr, 0, userdata); \
            return; \
        } \
        if (!(ctx)->running) { \
            QGP_LOG_ERROR("DHT", "Node not running in %s", func_name); \
            if (callback) (callback)(nullptr, 0, userdata); \
            return; \
        } \
    } while(0)

/**
 * Get value from DHT (returns first value only)
 */
extern "C" int dht_get(dht_context_t *ctx,
                       const uint8_t *key, size_t key_len,
                       uint8_t **value_out, size_t *value_len_out) {
    if (!key || !value_out || !value_len_out) {
        QGP_LOG_ERROR("DHT", "NULL parameter in dht_get");
        return -1;
    }
    DHT_GET_VALIDATE_CTX(ctx, "dht_get");

    try {
        auto start_total = std::chrono::steady_clock::now();

        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);

        QGP_LOG_INFO("DHT", "GET: %s", hash.toString().c_str());

        // Get value using future-based API (OpenDHT 2.4 compatible)
        auto start_network = std::chrono::steady_clock::now();
        auto future = ctx->runner.get(hash);

        // Wait with 10 second timeout (30s was too long for mobile UX)
        auto status = future.wait_for(std::chrono::seconds(10));
        if (status == std::future_status::timeout) {
            auto network_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start_network).count();
            QGP_LOG_INFO("DHT", "GET: Timeout after %lldms", (long long)network_ms);
            return -2;  // Timeout error
        }

        auto values = future.get();
        auto network_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_network).count();

        if (values.empty()) {
            QGP_LOG_INFO("DHT", "Value not found (took %lldms)", (long long)network_ms);
            return -1;
        }

        // Get first value
        auto val = values[0];
        if (!val || val->data.empty()) {
            QGP_LOG_INFO("DHT", "Value empty (took %lldms)", (long long)network_ms);
            return -1;
        }

        // Allocate C buffer and copy data (+ 1 for null terminator)
        auto start_copy = std::chrono::steady_clock::now();
        *value_out = (uint8_t*)malloc(val->data.size() + 1);
        if (!*value_out) {
            QGP_LOG_ERROR("DHT", "malloc failed");
            return -1;
        }

        memcpy(*value_out, val->data.data(), val->data.size());
        (*value_out)[val->data.size()] = '\0';  // Null-terminate for string safety
        *value_len_out = val->data.size();
        auto copy_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_copy).count();

        auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_total).count();

        QGP_LOG_INFO("DHT", "GET successful: %zu bytes (network: %lldms, copy: %lldms, total: %lldms)",
                     val->data.size(), (long long)network_ms, (long long)copy_ms, (long long)total_ms);

        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get: %s", e.what());
        return -1;
    }
}

/**
 * Get value from DHT asynchronously with callback
 * This is non-blocking and calls the callback when data arrives
 */
extern "C" void dht_get_async(dht_context_t *ctx,
                              const uint8_t *key, size_t key_len,
                              void (*callback)(uint8_t *value, size_t value_len, void *userdata),
                              void *userdata) {
    if (!key || !callback) {
        QGP_LOG_ERROR("DHT", "NULL parameter in dht_get_async");
        if (callback) callback(nullptr, 0, userdata);
        return;
    }
    DHT_GET_VALIDATE_CTX_ASYNC(ctx, callback, userdata, "dht_get_async");

    try {
        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);
        QGP_LOG_INFO("DHT", "GET_ASYNC: %s", hash.toString().c_str());

        // Use OpenDHT's async get with callback (GetCallbackSimple)
        // GetCallbackSimple signature: bool(std::shared_ptr<Value>)
        // Use shared_ptr to track if GetCallback was invoked
        auto value_found = std::make_shared<bool>(false);
        std::string hash_str = hash.toString();

        ctx->runner.get(hash,
            // GetCallback - called for each value
            [callback, userdata, hash_str, value_found](const std::shared_ptr<dht::Value>& val) {
                if (!val || val->data.empty()) {
                    QGP_LOG_INFO("DHT", "GET_ASYNC: Value empty for %s", hash_str.c_str());
                    *value_found = true;  // Mark as handled
                    callback(nullptr, 0, userdata);
                    return false;  // Stop listening
                }

                // Allocate C buffer and copy data
                uint8_t *value_copy = (uint8_t*)malloc(val->data.size());
                if (!value_copy) {
                    QGP_LOG_ERROR("DHT", "malloc failed in async callback");
                    *value_found = true;  // Mark as handled
                    callback(nullptr, 0, userdata);
                    return false;  // Stop listening
                }

                memcpy(value_copy, val->data.data(), val->data.size());
                QGP_LOG_INFO("DHT", "GET_ASYNC successful: %zu bytes", val->data.size());

                // Call the user callback with data
                *value_found = true;  // Mark as handled
                callback(value_copy, val->data.size(), userdata);

                return false;  // Stop listening after first value
            },
            // DoneCallback - called when query completes
            [callback, userdata, hash_str, value_found](bool success) {
                // If GetCallback was never called (no values found), call user callback now
                if (!*value_found) {
                    QGP_LOG_INFO("DHT", "GET_ASYNC: No values found for %s", hash_str.c_str());
                    callback(nullptr, 0, userdata);
                } else if (!success) {
                    QGP_LOG_INFO("DHT", "GET_ASYNC: Query failed for %s", hash_str.c_str());
                }
            }
        );

    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get_async: %s", e.what());
        callback(nullptr, 0, userdata);
    }
}

/**
 * Get all values from DHT for a given key
 */
extern "C" int dht_get_all(dht_context_t *ctx,
                           const uint8_t *key, size_t key_len,
                           uint8_t ***values_out, size_t **values_len_out,
                           size_t *count_out) {
    if (!key || !values_out || !values_len_out || !count_out) {
        QGP_LOG_ERROR("DHT", "NULL parameter in dht_get_all");
        return -1;
    }
    DHT_GET_VALIDATE_CTX(ctx, "dht_get_all");

    try {
        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);

        QGP_LOG_INFO("DHT", "GET_ALL: %s", hash.toString().c_str());

        // Get all values using future-based API
        auto future = ctx->runner.get(hash);

        // Wait with 10 second timeout (30s was too long for mobile UX)
        auto status = future.wait_for(std::chrono::seconds(10));
        if (status == std::future_status::timeout) {
            QGP_LOG_INFO("DHT", "GET_ALL: Timeout after 10 seconds");
            return -2;  // Timeout error
        }

        auto values = future.get();

        if (values.empty()) {
            QGP_LOG_INFO("DHT", "No values found");
            return -1;
        }

        QGP_LOG_INFO("DHT", "Found %zu value(s)", values.size());

        // Allocate arrays for C API
        uint8_t **value_array = (uint8_t**)malloc(values.size() * sizeof(uint8_t*));
        size_t *len_array = (size_t*)malloc(values.size() * sizeof(size_t));

        if (!value_array || !len_array) {
            QGP_LOG_ERROR("DHT", "malloc failed");
            free(value_array);
            free(len_array);
            return -1;
        }

        // Copy each value
        for (size_t i = 0; i < values.size(); i++) {
            auto val = values[i];
            if (!val || val->data.empty()) {
                // Skip empty values
                value_array[i] = nullptr;
                len_array[i] = 0;
                continue;
            }

            value_array[i] = (uint8_t*)malloc(val->data.size());
            if (!value_array[i]) {
                // Cleanup on failure
                for (size_t j = 0; j < i; j++) {
                    free(value_array[j]);
                }
                free(value_array);
                free(len_array);
                return -1;
            }

            memcpy(value_array[i], val->data.data(), val->data.size());
            len_array[i] = val->data.size();

            // Debug: show value details including owner
            if (val->owner && val->owner->getId()) {
                QGP_LOG_INFO("DHT", "  Value %zu: %zu bytes, owner=%s..., id=%llu, type=0x%x",
                             i+1, val->data.size(), val->owner->getId().toString().substr(0, 16).c_str(),
                             (unsigned long long)val->id, val->type);
            } else {
                QGP_LOG_INFO("DHT", "  Value %zu: %zu bytes, id=%llu, type=0x%x",
                             i+1, val->data.size(), (unsigned long long)val->id, val->type);
            }
        }

        *values_out = value_array;
        *values_len_out = len_array;
        *count_out = values.size();

        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get_all: %s", e.what());
        return -1;
    }
}

/**
 * Batch GET - retrieve multiple keys in parallel
 */
extern "C" void dht_get_batch(
    dht_context_t *ctx,
    const uint8_t **keys,
    const size_t *key_lens,
    size_t count,
    dht_batch_callback_t callback,
    void *userdata)
{
    if (!ctx || !keys || !key_lens || count == 0 || !callback) {
        QGP_LOG_ERROR("DHT", "Invalid parameters in dht_get_batch");
        if (callback) callback(nullptr, 0, userdata);
        return;
    }

    if (!ctx->running) {
        QGP_LOG_ERROR("DHT", "Node not running in dht_get_batch");
        callback(nullptr, 0, userdata);
        return;
    }

    try {
        QGP_LOG_INFO("DHT", "BATCH_GET: %zu keys in parallel", count);

        // Build vector of InfoHash keys
        std::vector<dht::InfoHash> hashes;
        hashes.reserve(count);
        for (size_t i = 0; i < count; i++) {
            hashes.push_back(dht::InfoHash::get(keys[i], key_lens[i]));
        }

        // Capture callback state
        struct BatchCallbackState {
            const uint8_t **keys;
            const size_t *key_lens;
            size_t count;
            dht_batch_callback_t callback;
            void *userdata;
        };

        auto state = std::make_shared<BatchCallbackState>();
        state->keys = keys;
        state->key_lens = key_lens;
        state->count = count;
        state->callback = callback;
        state->userdata = userdata;

        // Call OpenDHT batch GET
        dht::DhtRunner::BatchDoneCallback batch_cb = [state](dht::DhtRunner::BatchGetResult&& results) {
                // Allocate results array for C callback
                dht_batch_result_t *c_results = (dht_batch_result_t*)calloc(
                    state->count, sizeof(dht_batch_result_t));

                if (!c_results) {
                    QGP_LOG_ERROR("DHT", "Failed to allocate batch results");
                    state->callback(nullptr, 0, state->userdata);
                    return;
                }

                // Convert C++ results to C results
                for (size_t i = 0; i < results.size() && i < state->count; i++) {
                    auto& [hash, values] = results[i];

                    c_results[i].key = state->keys[i];
                    c_results[i].key_len = state->key_lens[i];

                    if (!values.empty() && values[0] && !values[0]->data.empty()) {
                        // Found value - copy first one
                        c_results[i].value = (uint8_t*)malloc(values[0]->data.size());
                        if (c_results[i].value) {
                            memcpy(c_results[i].value, values[0]->data.data(), values[0]->data.size());
                            c_results[i].value_len = values[0]->data.size();
                            c_results[i].found = 1;
                        } else {
                            c_results[i].found = 0;
                        }
                    } else {
                        // Not found
                        c_results[i].value = nullptr;
                        c_results[i].value_len = 0;
                        c_results[i].found = 0;
                    }
                }

                QGP_LOG_INFO("DHT", "BATCH_GET: Complete, %zu results", state->count);

                // Call user callback
                state->callback(c_results, state->count, state->userdata);

            // Note: c_results values must be freed by caller or in callback
            // We free the array structure here, but not the value buffers
            // Actually, the callback owns everything now, so we don't free here
        };

        ctx->runner.getBatch(hashes, std::move(batch_cb));

    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get_batch: %s", e.what());
        callback(nullptr, 0, userdata);
    }
}

/**
 * Synchronous batch GET - blocks until all complete
 */
extern "C" int dht_get_batch_sync(
    dht_context_t *ctx,
    const uint8_t **keys,
    const size_t *key_lens,
    size_t count,
    dht_batch_result_t **results_out)
{
    if (!ctx || !keys || !key_lens || count == 0 || !results_out) {
        QGP_LOG_ERROR("DHT", "Invalid parameters in dht_get_batch_sync");
        return -1;
    }

    if (!ctx->running) {
        QGP_LOG_ERROR("DHT", "Node not running in dht_get_batch_sync");
        return -1;
    }

    try {
        QGP_LOG_INFO("DHT", "BATCH_GET_SYNC: %zu keys in parallel", count);

        // Build vector of InfoHash keys
        std::vector<dht::InfoHash> hashes;
        hashes.reserve(count);
        for (size_t i = 0; i < count; i++) {
            hashes.push_back(dht::InfoHash::get(keys[i], key_lens[i]));
        }

        // Call synchronous batch GET
        auto results = ctx->runner.getBatch(hashes);

        // Allocate results array
        dht_batch_result_t *c_results = (dht_batch_result_t*)calloc(
            count, sizeof(dht_batch_result_t));

        if (!c_results) {
            QGP_LOG_ERROR("DHT", "Failed to allocate batch results");
            return -1;
        }

        // Convert C++ results to C results
        for (size_t i = 0; i < results.size() && i < count; i++) {
            auto& [hash, values] = results[i];

            c_results[i].key = keys[i];
            c_results[i].key_len = key_lens[i];

            if (!values.empty() && values[0] && !values[0]->data.empty()) {
                // Found value - copy first one
                c_results[i].value = (uint8_t*)malloc(values[0]->data.size());
                if (c_results[i].value) {
                    memcpy(c_results[i].value, values[0]->data.data(), values[0]->data.size());
                    c_results[i].value_len = values[0]->data.size();
                    c_results[i].found = 1;
                } else {
                    c_results[i].found = 0;
                }
            } else {
                // Not found
                c_results[i].value = nullptr;
                c_results[i].value_len = 0;
                c_results[i].found = 0;
            }
        }

        QGP_LOG_INFO("DHT", "BATCH_GET_SYNC: Complete, %zu results", count);

        *results_out = c_results;
        return 0;

    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get_batch_sync: %s", e.what());
        return -1;
    }
}

/**
 * Free batch results array
 */
extern "C" void dht_batch_results_free(dht_batch_result_t *results, size_t count) {
    if (!results) return;

    for (size_t i = 0; i < count; i++) {
        if (results[i].value) {
            free(results[i].value);
        }
    }
    free(results);
}

/**
 * Get this DHT node's ID (SHA3-512 hash of public key)
 */
extern "C" int dht_get_node_id(dht_context_t *ctx, char *node_id_out) {
    if (!ctx || !node_id_out) {
        return -1;
    }

    try {
        // Get the node's public key from OpenDHT
        auto node_id = ctx->runner.getPublicKey()->getLongId();

        // Convert to hex string
        std::string id_hex = node_id.toString();

        // Copy to output (OpenDHT node IDs are already hex strings)
        strncpy(node_id_out, id_hex.c_str(), 128);
        node_id_out[128] = '\0';

        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get_node_id: %s", e.what());
        return -1;
    }
}

/**
 * Get unique value_id for this DHT node's identity
 * Returns first 8 bytes of node ID as uint64_t
 */
extern "C" int dht_get_owner_value_id(dht_context_t *ctx, uint64_t *value_id_out) {
    if (!ctx || !value_id_out) {
        return -1;
    }

    try {
        auto pk = ctx->runner.getPublicKey();
        if (!pk) {
            return -1;
        }

        // Get the long ID (64-byte hash)
        auto long_id = pk->getLongId();

        // Use first 8 bytes as uint64_t value_id
        // This gives each DHT identity a unique value_id slot
        uint64_t id = 0;
        auto id_data = long_id.data();
        for (int i = 0; i < 8; i++) {
            id = (id << 8) | id_data[i];
        }

        *value_id_out = id;
        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_get_owner_value_id: %s", e.what());
        return -1;
    }
}

/**
 * Bootstrap to additional DHT nodes at runtime
 */
extern "C" int dht_context_bootstrap_runtime(dht_context_t *ctx, const char *ip, uint16_t port) {
    if (!ctx || !ip) {
        return -1;
    }

    try {
        // Convert port to string
        std::string port_str = std::to_string(port);

        // Add bootstrap node at runtime
        ctx->runner.bootstrap(ip, port_str);

        return 0;
    } catch (const std::exception& e) {
        QGP_LOG_ERROR("DHT", "Exception in dht_context_bootstrap_runtime: %s", e.what());
        return -1;
    }
}

// NOTE: dht_get_stats() and dht_get_storage() moved to dht/core/dht_stats.cpp (Phase 3)
// NOTE: dht_identity_* functions moved to dht/client/dht_identity.cpp (Phase 3)
