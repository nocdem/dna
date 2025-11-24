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
#include <chrono>
#include <future>
#include <thread>
#include <fstream>

// Opaque handle for DHT Identity (wraps C++ dht::crypto::Identity)
// Must be defined before any functions that use it
struct dht_identity {
    dht::crypto::Identity identity;  // C++ OpenDHT Identity
    dht_identity(const dht::crypto::Identity& id) : identity(id) {}
};

// Helper functions for persistent Dilithium5 identity
namespace {
    // Save Dilithium5 identity to binary files
    bool save_identity_dilithium5(const dht::crypto::Identity& id, const std::string& base_path) {
        try {
            // Save Dilithium5 identity using OpenDHT-PQ API
            // Creates: base_path.dsa (private key), base_path.pub (public key), base_path.cert (certificate)
            dht::crypto::saveDilithiumIdentity(id, base_path);

            std::cout << "[DHT] Saved Dilithium5 identity to " << base_path << ".{dsa,pub,cert}" << std::endl;
            std::cout << "[DHT] FIPS 204 - ML-DSA-87 - NIST Category 5 (256-bit quantum)" << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[DHT] Exception saving Dilithium5 identity: " << e.what() << std::endl;
            return false;
        }
    }

    // Load Dilithium5 identity from binary files
    dht::crypto::Identity load_identity_dilithium5(const std::string& base_path) {
        try {
            // Load Dilithium5 identity using OpenDHT-PQ API
            // Reads: base_path.dsa (private key), base_path.pub (public key), base_path.cert (certificate)
            auto id = dht::crypto::loadDilithiumIdentity(base_path);

            std::cout << "[DHT] Loaded Dilithium5 identity from " << base_path << ".{dsa,pub,cert}" << std::endl;
            std::cout << "[DHT] FIPS 204 - ML-DSA-87 - NIST Category 5 (256-bit quantum)" << std::endl;
            return id;
        } catch (const std::exception& e) {
            std::cerr << "[DHT] Exception loading Dilithium5 identity: " << e.what() << std::endl;
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

    // ValueTypes with lambda-captured context (eliminates global storage pointer)
    dht::ValueType type_7day;
    dht::ValueType type_30day;
    dht::ValueType type_365day;

    dht_context() : running(false), storage(nullptr),
                    // Initialize with dummy values (will be replaced in start())
                    type_7day(0, "", std::chrono::hours(0)),
                    type_30day(0, "", std::chrono::hours(0)),
                    type_365day(0, "", std::chrono::hours(0)) {
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
            [ctx](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
                  const dht::InfoHash&, const dht::SockAddr&) -> bool {
                // Store to persistent storage if available (ctx->storage may be NULL)
                if (ctx && ctx->storage && value) {
                    uint64_t now = time(NULL);
                    uint64_t expires_at = now + (7 * 24 * 3600);

                    if (dht_value_storage_should_persist(value->type, expires_at)) {
                        std::string key_str = key.toString();
                        dht_value_metadata_t metadata;
                        metadata.key_hash = (const uint8_t*)key_str.data();
                        metadata.key_hash_len = key_str.size();
                        metadata.value_data = value->data.data();
                        metadata.value_data_len = value->data.size();
                        metadata.value_type = value->type;
                        metadata.created_at = now;
                        metadata.expires_at = expires_at;

                        if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
                            std::cout << "[Storage] ✓ Persisted 7-day value ("
                                      << value->data.size() << " bytes)" << std::endl;
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
            [ctx](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
                  const dht::InfoHash&, const dht::SockAddr&) -> bool {
                // Store to persistent storage if available
                if (ctx && ctx->storage && value) {
                    uint64_t now = time(NULL);
                    uint64_t expires_at = now + (30 * 24 * 3600);

                    if (dht_value_storage_should_persist(value->type, expires_at)) {
                        std::string key_str = key.toString();
                        dht_value_metadata_t metadata;
                        metadata.key_hash = (const uint8_t*)key_str.data();
                        metadata.key_hash_len = key_str.size();
                        metadata.value_data = value->data.data();
                        metadata.value_data_len = value->data.size();
                        metadata.value_type = value->type;
                        metadata.created_at = now;
                        metadata.expires_at = expires_at;

                        if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
                            std::cout << "[Storage] ✓ Persisted 30-day value ("
                                      << value->data.size() << " bytes)" << std::endl;
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
            [ctx](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
                  const dht::InfoHash&, const dht::SockAddr&) -> bool {
                // Store to persistent storage if available
                if (ctx && ctx->storage && value) {
                    uint64_t now = time(NULL);
                    uint64_t expires_at = now + (365 * 24 * 3600);

                    if (dht_value_storage_should_persist(value->type, expires_at)) {
                        std::string key_str = key.toString();
                        dht_value_metadata_t metadata;
                        metadata.key_hash = (const uint8_t*)key_str.data();
                        metadata.key_hash_len = key_str.size();
                        metadata.value_data = value->data.data();
                        metadata.value_data_len = value->data.size();
                        metadata.value_type = value->type;
                        metadata.created_at = now;
                        metadata.expires_at = expires_at;

                        if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
                            std::cout << "[Storage] ✓ Persisted 365-day value ("
                                      << value->data.size() << " bytes)" << std::endl;
                        }
                    }
                }
                return true;  // Accept all
            }
        );
    }
}

/**
 * Initialize DHT context
 */
extern "C" dht_context_t* dht_context_new(const dht_config_t *config) {
    if (!config) {
        std::cerr << "[DHT] ERROR: NULL config" << std::endl;
        return nullptr;
    }

    try {
        auto ctx = new dht_context();
        memcpy(&ctx->config, config, sizeof(dht_config_t));

        std::cout << "[DHT] Created context for node: " << config->identity << std::endl;
        std::cout << "[DHT] Port: " << config->port << std::endl;
        std::cout << "[DHT] Bootstrap node: " << (config->is_bootstrap ? "yes" : "no") << std::endl;

        return ctx;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_context_new: " << e.what() << std::endl;
        return nullptr;
    }
}

/**
 * Start DHT node
 */
extern "C" int dht_context_start(dht_context_t *ctx) {
    if (!ctx) {
        std::cerr << "[DHT] ERROR: NULL context" << std::endl;
        return -1;
    }

    if (ctx->running) {
        std::cout << "[DHT] Already running" << std::endl;
        return 0;
    }

    try {
        // Load or generate persistent node identity
        dht::crypto::Identity identity;

        if (ctx->config.persistence_path[0] != '\0') {
            // Bootstrap nodes: Use persistent identity (OpenDHT 2.x/3.x compatible)
            std::string identity_path = std::string(ctx->config.persistence_path) + ".identity";

            try {
                // Try to load existing identity from Dilithium5 binary files
                identity = load_identity_dilithium5(identity_path);
                std::cout << "[DHT] Loaded persistent identity from: " << identity_path << std::endl;
            } catch (const std::exception& e) {
                // Generate new identity if files don't exist
                std::cout << "[DHT] Generating new persistent identity..." << std::endl;
                identity = dht::crypto::generateDilithiumIdentity("dht_node");

                // Save for future restarts (Dilithium5 binary format)
                if (!save_identity_dilithium5(identity, identity_path)) {
                    std::cerr << "[DHT] WARNING: Failed to save identity, will be ephemeral!" << std::endl;
                }
            }
        } else {
            // User nodes: Ephemeral random Dilithium5 identity
            identity = dht::crypto::generateDilithiumIdentity("dht_node");
        }

        // Check if disk persistence is requested
        if (ctx->config.persistence_path[0] != '\0') {
            // Bootstrap nodes: Enable disk persistence
            std::string persist_path(ctx->config.persistence_path);
            std::cout << "[DHT] Enabling disk persistence: " << persist_path << std::endl;
            std::cout << "[DHT] Bootstrap mode: " << (ctx->config.is_bootstrap ? "enabled" : "disabled") << std::endl;

            // Create DhtRunner::Config with persistence
            dht::DhtRunner::Config config;
            config.dht_config.node_config.maintain_storage = true;
            config.dht_config.node_config.persist_path = persist_path;
            config.dht_config.node_config.is_bootstrap = ctx->config.is_bootstrap;
            config.dht_config.node_config.public_stable = ctx->config.is_bootstrap;  // Public bootstrap nodes are stable
            config.dht_config.id = identity;
            config.threaded = true;

            std::cout << "[DHT] Configured persistence:" << std::endl;
            std::cout << "[DHT]   maintain_storage = " << config.dht_config.node_config.maintain_storage << std::endl;
            std::cout << "[DHT]   persist_path = " << config.dht_config.node_config.persist_path << std::endl;
            std::cout << "[DHT]   is_bootstrap = " << config.dht_config.node_config.is_bootstrap << std::endl;
            std::cout << "[DHT]   public_stable = " << config.dht_config.node_config.public_stable << std::endl;

            ctx->runner.run(ctx->config.port, config);
        } else {
            // User nodes: Memory-only (fast, no disk I/O)
            std::cout << "[DHT] Running in memory-only mode (no disk persistence)" << std::endl;
            ctx->runner.run(ctx->config.port, identity, true);
        }

        std::cout << "[DHT] Node started on port " << ctx->config.port << std::endl;

        // Register custom ValueTypes (CRITICAL: all nodes must know these types!)
        std::cout << "[DHT] Registering custom ValueTypes..." << std::endl;

        // Create ValueTypes with captured context (eliminates global storage)
        ctx->type_7day = create_7day_type(ctx);
        ctx->type_30day = create_30day_type(ctx);
        ctx->type_365day = create_365day_type(ctx);

        // Register with DhtRunner
        ctx->runner.registerType(ctx->type_7day);
        ctx->runner.registerType(ctx->type_30day);
        ctx->runner.registerType(ctx->type_365day);

        std::cout << "[DHT] ✓ Registered DNA_TYPE_7DAY (id=0x1001, TTL=7 days)" << std::endl;
        std::cout << "[DHT] ✓ Registered DNA_TYPE_30DAY (id=0x1003, TTL=30 days)" << std::endl;
        std::cout << "[DHT] ✓ Registered DNA_TYPE_365DAY (id=0x1002, TTL=365 days)" << std::endl;

        // Bootstrap to other nodes
        if (ctx->config.bootstrap_count > 0) {
            std::cout << "[DHT] Bootstrapping to " << ctx->config.bootstrap_count << " nodes:" << std::endl;

            for (size_t i = 0; i < ctx->config.bootstrap_count; i++) {
                std::string node_addr(ctx->config.bootstrap_nodes[i]);

                // Parse IP:port
                size_t colon_pos = node_addr.find(':');
                if (colon_pos == std::string::npos) {
                    std::cerr << "[DHT] Invalid bootstrap node format: " << node_addr << std::endl;
                    continue;
                }

                std::string ip = node_addr.substr(0, colon_pos);
                std::string port_str = node_addr.substr(colon_pos + 1);

                std::cout << "[DHT]   → " << ip << ":" << port_str << std::endl;

                ctx->runner.bootstrap(ip, port_str);
            }
        } else {
            std::cout << "[DHT] No bootstrap nodes (first node in network)" << std::endl;
        }

        // Initialize value storage (bootstrap nodes only)
        if (ctx->config.persistence_path[0] != '\0') {
            std::string storage_path = std::string(ctx->config.persistence_path) + ".values.db";
            std::cout << "[DHT] Initializing value storage: " << storage_path << std::endl;

            ctx->storage = dht_value_storage_new(storage_path.c_str());
            if (ctx->storage) {
                std::cout << "[DHT] ✓ Value storage initialized (captured in ValueTypes)" << std::endl;

                // Launch async republish in background
                if (dht_value_storage_restore_async(ctx->storage, ctx) == 0) {
                    std::cout << "[DHT] ✓ Async value republish started" << std::endl;
                } else {
                    std::cerr << "[DHT] WARNING: Failed to start async republish" << std::endl;
                }
            } else {
                std::cerr << "[DHT] WARNING: Value storage initialization failed" << std::endl;
            }
        }

        ctx->running = true;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_context_start: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Start DHT node with user-provided identity
 * (Used for encrypted backup system)
 */
extern "C" int dht_context_start_with_identity(dht_context_t *ctx, dht_identity_t *user_identity) {
    if (!ctx || !user_identity) {
        std::cerr << "[DHT] ERROR: NULL context or identity" << std::endl;
        return -1;
    }

    if (ctx->running) {
        std::cout << "[DHT] Already running" << std::endl;
        return 0;
    }

    try {
        // Use provided identity instead of generating one
        dht::crypto::Identity& identity = user_identity->identity;

        std::cout << "[DHT] Using user-provided DHT identity" << std::endl;

        // User nodes always run memory-only (no disk persistence)
        std::cout << "[DHT] Running in memory-only mode (no disk persistence)" << std::endl;
        ctx->runner.run(ctx->config.port, identity, true);

        std::cout << "[DHT] Node started on port " << ctx->config.port << std::endl;

        // Register custom ValueTypes
        std::cout << "[DHT] Registering custom ValueTypes..." << std::endl;

        // Create ValueTypes with captured context (eliminates global storage)
        ctx->type_7day = create_7day_type(ctx);
        ctx->type_30day = create_30day_type(ctx);
        ctx->type_365day = create_365day_type(ctx);

        // Register with DhtRunner
        ctx->runner.registerType(ctx->type_7day);
        ctx->runner.registerType(ctx->type_30day);
        ctx->runner.registerType(ctx->type_365day);

        std::cout << "[DHT] ✓ Registered DNA_TYPE_7DAY (id=0x1001, TTL=7 days)" << std::endl;
        std::cout << "[DHT] ✓ Registered DNA_TYPE_30DAY (id=0x1003, TTL=30 days)" << std::endl;
        std::cout << "[DHT] ✓ Registered DNA_TYPE_365DAY (id=0x1002, TTL=365 days)" << std::endl;

        // Bootstrap to other nodes
        if (ctx->config.bootstrap_count > 0) {
            std::cout << "[DHT] Bootstrapping to " << ctx->config.bootstrap_count << " nodes:" << std::endl;

            for (size_t i = 0; i < ctx->config.bootstrap_count; i++) {
                std::string node_addr(ctx->config.bootstrap_nodes[i]);

                // Parse IP:port
                size_t colon_pos = node_addr.find(':');
                if (colon_pos == std::string::npos) {
                    std::cerr << "[DHT] Invalid bootstrap node format: " << node_addr << std::endl;
                    continue;
                }

                std::string ip = node_addr.substr(0, colon_pos);
                std::string port_str = node_addr.substr(colon_pos + 1);

                std::cout << "[DHT]   → " << ip << ":" << port_str << std::endl;

                ctx->runner.bootstrap(ip, port_str);
            }
        } else {
            std::cout << "[DHT] No bootstrap nodes (first node in network)" << std::endl;
        }

        ctx->running = true;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_context_start_with_identity: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Stop DHT node
 */
extern "C" void dht_context_stop(dht_context_t *ctx) {
    if (!ctx) return;

    try {
        if (ctx->running) {
            std::cout << "[DHT] Stopping node..." << std::endl;
            std::cout << "[DHT] Shutting down DHT runner (this will persist state to disk)..." << std::endl;
            ctx->runner.shutdown();
            ctx->runner.join();
            std::cout << "[DHT] ✓ DHT shutdown complete" << std::endl;

            // Cleanup value storage
            if (ctx->storage) {
                std::cout << "[DHT] Cleaning up value storage..." << std::endl;
                dht_value_storage_free(ctx->storage);
                ctx->storage = nullptr;
            }

            ctx->running = false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_context_stop: " << e.what() << std::endl;
    }
}

/**
 * Free DHT context
 */
extern "C" void dht_context_free(dht_context_t *ctx) {
    if (!ctx) return;

    try {
        dht_context_stop(ctx);
        delete ctx;
        std::cout << "[DHT] Context freed" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_context_free: " << e.what() << std::endl;
    }
}

/**
 * Check if DHT is ready
 */
extern "C" bool dht_context_is_ready(dht_context_t *ctx) {
    if (!ctx || !ctx->running) return false;

    try {
        // Check if we have connected to at least one peer
        auto node_info = ctx->runner.getNodeInfo();
        // In OpenDHT 2.4, good_nodes is in ipv4/ipv6 substats
        size_t total_good = node_info.ipv4.good_nodes + node_info.ipv6.good_nodes;
        return total_good > 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_context_is_ready: " << e.what() << std::endl;
        return false;
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
        std::cerr << "[DHT] ERROR: NULL parameter in dht_put_ttl" << std::endl;
        return -1;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
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
            std::cout << "[DHT] PUT PERMANENT (async): " << hash << " (" << value_len << " bytes, type=0x" << std::hex << dht_value->type << std::dec << ")" << std::endl;

            // Use done callback to track completion
            std::promise<bool> done_promise;
            auto done_future = done_promise.get_future();

            std::cout << "[DHT] Initiating PUT to network (expecting replication to " << ctx->config.bootstrap_count << " bootstrap nodes)..." << std::endl;

            ctx->runner.put(hash, dht_value, [&done_promise](bool success, const std::vector<std::shared_ptr<dht::Node>>& nodes) {
                if (success) {
                    std::cout << "[DHT] PUT PERMANENT: ✓ Stored on " << nodes.size() << " remote node(s)" << std::endl;
                    if (nodes.empty()) {
                        std::cerr << "[DHT] WARNING: Success but 0 nodes confirmed! Data might be local-only." << std::endl;
                    }
                } else {
                    std::cout << "[DHT] PUT PERMANENT: ✗ Failed to store on any node" << std::endl;
                }
                done_promise.set_value(success);
            }, dht::time_point::max(), true);

            // Wait for confirmation (timeout after 30 seconds)
            std::cout << "[DHT] Waiting for confirmation from DHT network..." << std::endl;
            auto status = done_future.wait_for(std::chrono::seconds(30));

            if (status == std::future_status::timeout) {
                std::cerr << "[DHT] WARNING: PUT operation timed out after 30 seconds" << std::endl;
                return -2;  // Timeout error
            }

            bool success = done_future.get();
            if (!success) {
                std::cerr << "[DHT] ERROR: PUT operation failed" << std::endl;
                return -3;  // Put failed
            }

            std::cout << "[DHT] ✓ PUT PERMANENT confirmed by network" << std::endl;

            // Verify data is actually retrievable (wait 5 seconds for propagation, then test GET)
            std::cout << "[DHT] Verifying data is retrievable (waiting 5 seconds)..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));

            // Try to GET the data back from the network
            auto get_future = ctx->runner.get(hash);
            auto get_status = get_future.wait_for(std::chrono::seconds(10));

            if (get_status == std::future_status::timeout) {
                std::cerr << "[DHT] WARNING: GET timed out, data may not be retrievable yet" << std::endl;
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
                    std::cout << "[DHT] ✓ Verified: Data is retrievable from DHT network" << std::endl;
                } else {
                    std::cerr << "[DHT] WARNING: PUT succeeded but data not yet retrievable from network" << std::endl;
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

            std::cout << "[DHT] PUT: " << hash << " (" << value_len << " bytes, TTL=" << ttl_seconds << "s, type=0x" << std::hex << dht_value->type << std::dec << ")" << std::endl;

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
        if (ctx->storage) {
            uint64_t expires_at = 0;  // 0 = permanent
            if (ttl_seconds != UINT_MAX) {
                expires_at = time(NULL) + ttl_seconds;
            }

            // CRITICAL FIX (2025-11-12): Store ORIGINAL key, not derived infohash
            // This prevents double-hashing bug on republish after bootstrap restart
            // Old bug: stored infohash → republish hashed infohash → wrong DHT key
            dht_value_metadata_t metadata;
            metadata.key_hash = key;           // Original 64-byte SHA3-512 input
            metadata.key_hash_len = key_len;   // 64 bytes (not 40-char hex infohash)
            metadata.value_data = value;
            metadata.value_data_len = value_len;
            metadata.value_type = dht_value->type;
            metadata.created_at = time(NULL);
            metadata.expires_at = expires_at;

            if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
                if (dht_value_storage_should_persist(metadata.value_type, metadata.expires_at)) {
                    std::cout << "[Storage] ✓ Value persisted to disk (key: " << key_len << " bytes)" << std::endl;
                }
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_put_ttl: " << e.what() << std::endl;
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
        std::cerr << "[DHT] ERROR: NULL parameter in dht_put_signed" << std::endl;
        return -1;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
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

        std::cout << "[DHT] PUT_SIGNED: " << hash
                  << " (" << value_len << " bytes"
                  << ", TTL=" << ttl_seconds << "s"
                  << ", type=0x" << std::hex << dht_value->type << std::dec
                  << ", id=" << value_id << ")" << std::endl;

        // Use putSigned() instead of put() to enable editing/replacement
        // Note: putSigned() doesn't support creation_time parameter (uses current time)
        // Permanent flag controls whether value expires based on ValueType
        ctx->runner.putSigned(hash, dht_value,
                             [](bool success, const std::vector<std::shared_ptr<dht::Node>>& nodes){
                                 if (success) {
                                     std::cout << "[DHT] PUT_SIGNED: ✓ Stored/updated on "
                                               << nodes.size() << " remote node(s)" << std::endl;
                                 } else {
                                     std::cout << "[DHT] PUT_SIGNED: ✗ Failed to store on any node" << std::endl;
                                 }
                             },
                             false);  // permanent=false to use ValueType's expiration

        // Store value to persistent storage (if enabled)
        if (ctx->storage) {
            uint64_t expires_at = 0;  // 0 = permanent
            if (ttl_seconds != UINT_MAX) {
                expires_at = time(NULL) + ttl_seconds;
            }

            // CRITICAL FIX (2025-11-12): Store ORIGINAL key, not derived infohash
            // This prevents double-hashing bug on republish after bootstrap restart
            // Old bug: stored infohash → republish hashed infohash → wrong DHT key
            dht_value_metadata_t metadata;
            metadata.key_hash = key;           // Original 64-byte SHA3-512 input
            metadata.key_hash_len = key_len;   // 64 bytes (not 40-char hex infohash)
            metadata.value_data = value;
            metadata.value_data_len = value_len;
            metadata.value_type = dht_value->type;
            metadata.created_at = time(NULL);
            metadata.expires_at = expires_at;

            if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
                if (dht_value_storage_should_persist(metadata.value_type, metadata.expires_at)) {
                    std::cout << "[Storage] ✓ Value persisted to disk (key: " << key_len << " bytes)" << std::endl;
                }
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_put_signed: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Get value from DHT (returns first value only)
 */
extern "C" int dht_get(dht_context_t *ctx,
                       const uint8_t *key, size_t key_len,
                       uint8_t **value_out, size_t *value_len_out) {
    if (!ctx || !key || !value_out || !value_len_out) {
        std::cerr << "[DHT] ERROR: NULL parameter in dht_get" << std::endl;
        return -1;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
        return -1;
    }

    try {
        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);

        std::cout << "[DHT] GET: " << hash << std::endl;

        // Get value using future-based API (OpenDHT 2.4 compatible)
        auto future = ctx->runner.get(hash);
        auto values = future.get();

        if (values.empty()) {
            std::cout << "[DHT] Value not found" << std::endl;
            return -1;
        }

        // Get first value
        auto val = values[0];
        if (!val || val->data.empty()) {
            std::cout << "[DHT] Value empty" << std::endl;
            return -1;
        }

        // Allocate C buffer and copy data (+ 1 for null terminator)
        *value_out = (uint8_t*)malloc(val->data.size() + 1);
        if (!*value_out) {
            std::cerr << "[DHT] ERROR: malloc failed" << std::endl;
            return -1;
        }

        memcpy(*value_out, val->data.data(), val->data.size());
        (*value_out)[val->data.size()] = '\0';  // Null-terminate for string safety
        *value_len_out = val->data.size();

        std::cout << "[DHT] GET successful: " << val->data.size() << " bytes" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_get: " << e.what() << std::endl;
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
    if (!ctx || !key || !callback) {
        std::cerr << "[DHT] ERROR: NULL parameter in dht_get_async" << std::endl;
        if (callback) callback(nullptr, 0, userdata);  // Call with error
        return;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
        callback(nullptr, 0, userdata);  // Call with error
        return;
    }

    try {
        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);
        std::cout << "[DHT] GET_ASYNC: " << hash << std::endl;

        // Use OpenDHT's async get with callback (GetCallbackSimple)
        // GetCallbackSimple signature: bool(std::shared_ptr<Value>)
        ctx->runner.get(hash,
            // GetCallback - called for each value
            [callback, userdata, hash](const std::shared_ptr<dht::Value>& val) {
                if (!val || val->data.empty()) {
                    std::cout << "[DHT] GET_ASYNC: Value empty for " << hash << std::endl;
                    callback(nullptr, 0, userdata);
                    return false;  // Stop listening
                }

                // Allocate C buffer and copy data
                uint8_t *value_copy = (uint8_t*)malloc(val->data.size());
                if (!value_copy) {
                    std::cerr << "[DHT] ERROR: malloc failed in async callback" << std::endl;
                    callback(nullptr, 0, userdata);
                    return false;  // Stop listening
                }

                memcpy(value_copy, val->data.data(), val->data.size());
                std::cout << "[DHT] GET_ASYNC successful: " << val->data.size() << " bytes" << std::endl;

                // Call the user callback with data
                callback(value_copy, val->data.size(), userdata);

                return false;  // Stop listening after first value
            },
            // DoneCallback - called when query completes
            [callback, userdata, hash](bool success) {
                if (!success) {
                    std::cout << "[DHT] GET_ASYNC: Query failed for " << hash << std::endl;
                    callback(nullptr, 0, userdata);
                }
            }
        );

    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_get_async: " << e.what() << std::endl;
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
    if (!ctx || !key || !values_out || !values_len_out || !count_out) {
        std::cerr << "[DHT] ERROR: NULL parameter in dht_get_all" << std::endl;
        return -1;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
        return -1;
    }

    try {
        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);

        std::cout << "[DHT] GET_ALL: " << hash << std::endl;

        // Get all values using future-based API
        auto future = ctx->runner.get(hash);
        auto values = future.get();

        if (values.empty()) {
            std::cout << "[DHT] No values found" << std::endl;
            return -1;
        }

        std::cout << "[DHT] Found " << values.size() << " value(s)" << std::endl;

        // Allocate arrays for C API
        uint8_t **value_array = (uint8_t**)malloc(values.size() * sizeof(uint8_t*));
        size_t *len_array = (size_t*)malloc(values.size() * sizeof(size_t));

        if (!value_array || !len_array) {
            std::cerr << "[DHT] ERROR: malloc failed" << std::endl;
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

            std::cout << "[DHT]   Value " << (i+1) << ": " << val->data.size() << " bytes" << std::endl;
        }

        *values_out = value_array;
        *values_len_out = len_array;
        *count_out = values.size();

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_get_all: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Delete value from DHT
 */
extern "C" int dht_delete(dht_context_t *ctx,
                          const uint8_t *key, size_t key_len) {
    if (!ctx || !key) {
        std::cerr << "[DHT] ERROR: NULL parameter in dht_delete" << std::endl;
        return -1;
    }

    if (!ctx->running) {
        std::cerr << "[DHT] ERROR: Node not running" << std::endl;
        return -1;
    }

    try {
        // Hash the key
        auto hash = dht::InfoHash::get(key, key_len);

        // Phase 6.5: dht_delete() is a NO-OP - documented behavior
        // OpenDHT does not support direct deletion. Values expire naturally based on TTL:
        //   - PERMANENT: Never expire (identity keys, contact lists)
        //   - 365-day TTL: Name registrations
        //   - 7-day TTL: Profiles, groups, offline queue
        //
        // To "delete" a value:
        //   1. Wait for natural TTL expiration (recommended)
        //   2. Publish empty/null value to overwrite (for mutable data)

        std::cout << "[DHT] WARNING: dht_delete() is a no-op (key=" << hash << ")" << std::endl;
        std::cout << "[DHT] Values expire automatically based on TTL. See dht_context.h documentation." << std::endl;

        return 0;  // Always succeed (no-op is intentional)
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_delete: " << e.what() << std::endl;
        return -1;
    }
}

// NOTE: dht_get_stats() and dht_get_storage() moved to dht/core/dht_stats.cpp (Phase 3)
// NOTE: dht_identity_* functions moved to dht/client/dht_identity.cpp (Phase 3)
