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
#include "dht_value_storage.h"
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
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

// Global storage pointer (accessed from ValueType store callbacks)
static dht_value_storage_t *g_global_storage = nullptr;

// Custom ValueTypes with different TTLs and storage callbacks
static const dht::ValueType DNA_TYPE_7DAY {
    0x1001,                      // Type ID for 7-day data (messages, contacts, etc.)
    "DNA_7DAY",
    std::chrono::hours(7 * 24),  // 7 days
    [](dht::InfoHash key, std::shared_ptr<dht::Value>& value, const dht::InfoHash&, const dht::SockAddr&) {
        // Store to persistent storage if available (7-day values - skip ephemeral)
        if (g_global_storage && value) {
            uint64_t now = time(NULL);
            uint64_t expires_at = now + (7 * 24 * 3600);  // 7 days from now

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

                if (dht_value_storage_put(g_global_storage, &metadata) == 0) {
                    std::cout << "[Storage] ✓ Persisted 7-day value (" << value->data.size() << " bytes)" << std::endl;
                }
            }
        }
        return true;  // Accept all
    }
};

static const dht::ValueType DNA_TYPE_365DAY {
    0x1002,                       // Type ID for 365-day data (name registrations)
    "DNA_365DAY",
    std::chrono::hours(365 * 24), // 365 days
    [](dht::InfoHash key, std::shared_ptr<dht::Value>& value, const dht::InfoHash&, const dht::SockAddr&) {
        // Store to persistent storage if available (365-day values - PERMANENT)
        if (g_global_storage && value) {
            uint64_t now = time(NULL);
            uint64_t expires_at = now + (365 * 24 * 3600);  // 365 days from now

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

                if (dht_value_storage_put(g_global_storage, &metadata) == 0) {
                    std::cout << "[Storage] ✓ Persisted 365-day value (" << value->data.size() << " bytes)" << std::endl;
                }
            }
        }
        return true;  // Accept all
    }
};

// Helper functions for persistent identity (OpenDHT 2.x and 3.x compatible)
namespace {
    // Save identity to PEM files (works with both 2.x and 3.x)
    bool save_identity_pem(const dht::crypto::Identity& id, const std::string& base_path) {
        try {
            std::string cert_path = base_path + ".crt";
            std::string key_path = base_path + ".pem";

            // Get GNUTLS objects from OpenDHT Identity
            auto cert = id.second->cert;  // gnutls_x509_crt_t
            auto privkey = id.first->x509_key;  // gnutls_x509_privkey_t

            // Export certificate to PEM
            gnutls_datum_t cert_pem;
            if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_PEM, &cert_pem) != GNUTLS_E_SUCCESS) {
                std::cerr << "[DHT] Failed to export certificate" << std::endl;
                return false;
            }

            // Export private key to PEM
            gnutls_datum_t key_pem;
            if (gnutls_x509_privkey_export2(privkey, GNUTLS_X509_FMT_PEM, &key_pem) != GNUTLS_E_SUCCESS) {
                gnutls_free(cert_pem.data);
                std::cerr << "[DHT] Failed to export private key" << std::endl;
                return false;
            }

            // Write certificate to file
            std::ofstream cert_file(cert_path, std::ios::binary);
            cert_file.write(reinterpret_cast<char*>(cert_pem.data), cert_pem.size);
            cert_file.close();

            // Write private key to file
            std::ofstream key_file(key_path, std::ios::binary);
            key_file.write(reinterpret_cast<char*>(key_pem.data), key_pem.size);
            key_file.close();

            gnutls_free(cert_pem.data);
            gnutls_free(key_pem.data);

            std::cout << "[DHT] Saved identity to " << base_path << ".{crt,pem}" << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[DHT] Exception saving identity: " << e.what() << std::endl;
            return false;
        }
    }

    // Load identity from PEM files (works with both 2.x and 3.x)
    dht::crypto::Identity load_identity_pem(const std::string& base_path) {
        std::string cert_path = base_path + ".crt";
        std::string key_path = base_path + ".pem";

        // Read certificate file
        std::ifstream cert_file(cert_path, std::ios::binary);
        if (!cert_file) {
            throw std::runtime_error("Certificate file not found");
        }
        std::string cert_pem((std::istreambuf_iterator<char>(cert_file)), std::istreambuf_iterator<char>());
        cert_file.close();

        // Read private key file
        std::ifstream key_file(key_path, std::ios::binary);
        if (!key_file) {
            throw std::runtime_error("Private key file not found");
        }
        std::string key_pem((std::istreambuf_iterator<char>(key_file)), std::istreambuf_iterator<char>());
        key_file.close();

        // Import certificate
        gnutls_x509_crt_t cert;
        gnutls_x509_crt_init(&cert);
        gnutls_datum_t cert_datum = { (unsigned char*)cert_pem.data(), (unsigned int)cert_pem.size() };
        if (gnutls_x509_crt_import(cert, &cert_datum, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
            gnutls_x509_crt_deinit(cert);
            throw std::runtime_error("Failed to import certificate");
        }

        // Import private key
        gnutls_x509_privkey_t privkey;
        gnutls_x509_privkey_init(&privkey);
        gnutls_datum_t key_datum = { (unsigned char*)key_pem.data(), (unsigned int)key_pem.size() };
        if (gnutls_x509_privkey_import(privkey, &key_datum, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
            gnutls_x509_crt_deinit(cert);
            gnutls_x509_privkey_deinit(privkey);
            throw std::runtime_error("Failed to import private key");
        }

        // Create Identity from GNUTLS objects
        auto priv = std::make_shared<dht::crypto::PrivateKey>(privkey);
        auto certificate = std::make_shared<dht::crypto::Certificate>(cert);

        std::cout << "[DHT] Loaded identity from " << base_path << ".{crt,pem}" << std::endl;
        return dht::crypto::Identity(priv, certificate);
    }
}

// Internal C++ struct (hidden from C code)
struct dht_context {
    dht::DhtRunner runner;
    dht_config_t config;
    bool running;
    dht_value_storage_t *storage;  // Value persistence (NULL for user nodes)

    dht_context() : running(false), storage(nullptr) {
        memset(&config, 0, sizeof(config));
    }
};

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
                // Try to load existing identity from PEM files
                identity = load_identity_pem(identity_path);
                std::cout << "[DHT] Loaded persistent identity from: " << identity_path << std::endl;
            } catch (const std::exception& e) {
                // Generate new identity if files don't exist
                std::cout << "[DHT] Generating new persistent identity..." << std::endl;
                identity = dht::crypto::generateIdentity();

                // Save for future restarts (PEM format, works on 2.x and 3.x)
                if (!save_identity_pem(identity, identity_path)) {
                    std::cerr << "[DHT] WARNING: Failed to save identity, will be ephemeral!" << std::endl;
                }
            }
        } else {
            // User nodes: Ephemeral random identity
            identity = dht::crypto::generateIdentity();
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
        ctx->runner.registerType(DNA_TYPE_7DAY);
        ctx->runner.registerType(DNA_TYPE_365DAY);
        std::cout << "[DHT] ✓ Registered DNA_TYPE_7DAY (id=0x1001, TTL=7 days)" << std::endl;
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
                std::cout << "[DHT] ✓ Value storage initialized" << std::endl;

                // Set global storage pointer (used by ValueType store callbacks)
                g_global_storage = ctx->storage;
                std::cout << "[DHT] ✓ Storage callbacks enabled in ValueTypes" << std::endl;

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
                g_global_storage = nullptr;  // Clear global pointer first
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
            dht_value->type = DNA_TYPE_365DAY.id;  // Use 365-day type for permanent data
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
            // Choose ValueType based on TTL (365 days vs 7 days)
            if (ttl_seconds >= 365 * 24 * 3600) {
                dht_value->type = DNA_TYPE_365DAY.id;  // Assign type ID
            } else {
                dht_value->type = DNA_TYPE_7DAY.id;    // Assign type ID
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

            // Convert InfoHash to bytes
            std::string hash_str = hash.toString();
            const uint8_t *hash_bytes = (const uint8_t*)hash_str.data();

            dht_value_metadata_t metadata;
            metadata.key_hash = hash_bytes;
            metadata.key_hash_len = hash_str.size();
            metadata.value_data = value;
            metadata.value_data_len = value_len;
            metadata.value_type = dht_value->type;
            metadata.created_at = time(NULL);
            metadata.expires_at = expires_at;

            if (dht_value_storage_put(ctx->storage, &metadata) == 0) {
                if (dht_value_storage_should_persist(metadata.value_type, metadata.expires_at)) {
                    std::cout << "[Storage] ✓ Value persisted to disk" << std::endl;
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

        // Allocate C buffer and copy data
        *value_out = (uint8_t*)malloc(val->data.size());
        if (!*value_out) {
            std::cerr << "[DHT] ERROR: malloc failed" << std::endl;
            return -1;
        }

        memcpy(*value_out, val->data.data(), val->data.size());
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

        std::cout << "[DHT] DELETE: " << hash << std::endl;

        // Note: OpenDHT doesn't have a direct "delete" - we'd need to
        // track value IDs from put() and cancel them. For now, this is
        // a placeholder that returns success but doesn't actually delete.
        // True deletion requires storing value IDs.

        std::cout << "[DHT] WARNING: Delete is not implemented (DHT values expire naturally)" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT] Exception in dht_delete: " << e.what() << std::endl;
        return -1;
    }
}

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
