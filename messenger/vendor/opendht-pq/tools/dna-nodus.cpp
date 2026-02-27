/*
 * DNA Nodus - Post-Quantum DHT Bootstrap Node
 *
 * Features:
 * - SQLite DHT value persistence
 * - Mandatory Dilithium5 signature enforcement
 * - Auto-discovery of peer nodus via DHT registry
 * - JSON config file: /etc/dna-nodus.conf
 *
 * Config is loaded from /etc/dna-nodus.conf - no CLI arguments needed.
 *
 * Privacy: STUN/TURN removed in v0.4.61
 * - No longer provides TURN relay service
 * - No longer issues TURN credentials
 * - Improves user privacy by not having central relay servers
 */

#include "nodus_version.h"
#include "nodus_config.h"
// TURN includes removed in v0.4.61 for privacy
// #include "turn_server.h"
// #include "turn_credential_manager.h"
// #include "turn_credential_udp.h"

#include "../../dht/core/dht_context.h"
#include "../../dht/shared/dht_value_storage.h"
#include "../../dht/core/dht_bootstrap_registry.h"

#include <iostream>
#include <fstream>
#include <csignal>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <set>

static dht_context_t *global_ctx = nullptr;
// TURN server and credential manager removed in v0.4.61 for privacy

void signal_handler(int sig) {
    (void)sig;
    std::cout << "\nShutting down..." << std::endl;

    if (global_ctx) {
        dht_context_stop(global_ctx);
        dht_context_free(global_ctx);
        global_ctx = nullptr;
    }
    exit(0);
}

// Get the first non-loopback IPv4 address
std::string get_interface_ip() {
    struct ifaddrs *ifaddr, *ifa;
    std::string ip;

    if (getifaddrs(&ifaddr) == -1) {
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);

            // Skip loopback
            if (std::string(ip_str) != "127.0.0.1") {
                ip = ip_str;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return ip;
}

// Get file size as human-readable string
std::string get_file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return "0 B";
    }

    double size = st.st_size;
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;

    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return buf;
}

// Track connected peers to avoid duplicate connections
static std::set<std::string> connected_peers;

bool already_connected(const char* ip, uint16_t port) {
    char key[128];
    snprintf(key, sizeof(key), "%s:%u", ip, port);
    return connected_peers.count(key) > 0;
}

void mark_connected(const char* ip, uint16_t port) {
    char key[128];
    snprintf(key, sizeof(key), "%s:%u", ip, port);
    connected_peers.insert(key);
}

int main(int argc, char** argv) {
    // Handle --version / -v
    if (argc > 1 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
        std::cout << "dna-nodus v" << NODUS_VERSION_STRING << std::endl;
        return 0;
    }

    std::cout << "DNA Nodus v" << NODUS_VERSION_STRING << " - Post-Quantum DHT Bootstrap" << std::endl;
    std::cout << "FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5 Security" << std::endl;
    std::cout << "Privacy: STUN/TURN removed in v0.4.61 - DHT-only mode" << std::endl;
    std::cout << std::endl;

    // Load configuration
    NodusConfig cfg;
    cfg.load();  // Loads from /etc/dna-nodus.conf or uses defaults
    cfg.print();

    // Auto-detect public IP if "auto"
    std::string public_ip = cfg.public_ip;
    if (public_ip == "auto" || public_ip.empty()) {
        public_ip = get_interface_ip();
        if (!public_ip.empty()) {
            std::cout << "[IP] Auto-detected: " << public_ip << std::endl;
        } else {
            std::cerr << "[IP] WARNING: Could not detect public IP" << std::endl;
        }
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Configure DHT context
    dht_config_t dht_config;
    memset(&dht_config, 0, sizeof(dht_config));
    dht_config.port = cfg.dht_port;
    dht_config.is_bootstrap = true;
    strncpy(dht_config.identity, cfg.identity.c_str(), sizeof(dht_config.identity) - 1);
    strncpy(dht_config.persistence_path, cfg.persistence_path.c_str(),
            sizeof(dht_config.persistence_path) - 1);

    // Add seed nodes
    dht_config.bootstrap_count = std::min((int)cfg.seed_nodes.size(), 5);
    for (size_t i = 0; i < dht_config.bootstrap_count; i++) {
        strncpy(dht_config.bootstrap_nodes[i], cfg.seed_nodes[i].c_str(),
                sizeof(dht_config.bootstrap_nodes[i]) - 1);
        mark_connected(cfg.seed_nodes[i].c_str(), cfg.dht_port);
    }

    std::cout << std::endl << "[DHT] Creating context..." << std::endl;
    global_ctx = dht_context_new(&dht_config);
    if (!global_ctx) {
        std::cerr << "[DHT] ERROR: Failed to create context" << std::endl;
        return 1;
    }

    std::cout << "[DHT] Starting on port " << cfg.dht_port << "..." << std::endl;

    // Check database size
    std::string db_path = cfg.persistence_path + ".values.db";
    std::cout << "[DHT] Database: " << db_path << " (" << get_file_size(db_path) << ")" << std::endl;

    if (dht_context_start(global_ctx) != 0) {
        std::cerr << "[DHT] ERROR: Failed to start" << std::endl;
        dht_context_free(global_ctx);
        return 1;
    }
    std::cout << "[DHT] Started" << std::endl;

    // Get node ID
    char node_id[129];
    if (dht_get_node_id(global_ctx, node_id) != 0) {
        std::cerr << "[DHT] ERROR: Failed to get node ID" << std::endl;
        dht_context_free(global_ctx);
        return 1;
    }
    std::cout << "[DHT] Node ID: " << std::string(node_id).substr(0, 16) << "..." << std::endl;

    // TURN server removed in v0.4.61 for privacy
    // No longer providing STUN/TURN relay services to protect user IP privacy

    // Register in bootstrap registry
    if (dht_bootstrap_registry_register(global_ctx, public_ip.c_str(), cfg.dht_port,
                                         node_id, NODUS_VERSION_STRING, 0) == 0) {
        std::cout << "[REGISTRY] Registered in bootstrap registry" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "=== DNA Nodus v" << NODUS_VERSION_STRING << " Running ===" << std::endl;
    std::cout << "DHT:   " << public_ip << ":" << cfg.dht_port << std::endl;
    std::cout << "Mode:  DHT-only (privacy-preserving)" << std::endl;
    std::cout << "===============================" << std::endl;
    std::cout << std::endl;

    // Main loop
    int seconds = 0;
    while (true) {
        sleep(1);
        seconds++;

        // Every 60 seconds: Print stats
        if (seconds % 60 == 0) {
            size_t node_count = 0;
            size_t stored_values = 0;
            dht_get_stats(global_ctx, &node_count, &stored_values);

            std::cout << "[" << seconds / 60 << " min] ";
            std::cout << "[" << node_count << " nodes] ";
            std::cout << "[" << stored_values << " values]";

            // Storage stats
            dht_value_storage_t *storage = dht_get_storage(global_ctx);
            if (storage) {
                dht_storage_stats_t storage_stats;
                if (dht_value_storage_get_stats(storage, &storage_stats) == 0) {
                    std::cout << " | DB: " << storage_stats.total_values;
                    if (storage_stats.republish_in_progress) {
                        std::cout << " (republishing)";
                    }
                }
            }

            std::cout << std::endl;
        }

        // Every 5 minutes: Refresh registry + discover peers
        if (seconds % 300 == 0) {
            // Refresh own registration
            dht_bootstrap_registry_register(global_ctx, public_ip.c_str(), cfg.dht_port,
                                            node_id, NODUS_VERSION_STRING, seconds);

            // Discover new peers
            bootstrap_registry_t registry;
            if (dht_bootstrap_registry_fetch(global_ctx, &registry) == 0) {
                dht_bootstrap_registry_filter_active(&registry);

                int new_peers = 0;
                for (size_t i = 0; i < registry.node_count; i++) {
                    if (!already_connected(registry.nodes[i].ip, registry.nodes[i].port)) {
                        if (dht_context_bootstrap_runtime(global_ctx,
                                registry.nodes[i].ip, registry.nodes[i].port) == 0) {
                            mark_connected(registry.nodes[i].ip, registry.nodes[i].port);
                            new_peers++;
                            std::cout << "[DISCOVERY] Connected to new peer: "
                                      << registry.nodes[i].ip << ":"
                                      << registry.nodes[i].port << std::endl;
                        }
                    }
                }

                if (new_peers > 0) {
                    std::cout << "[DISCOVERY] Found " << new_peers << " new peer(s)" << std::endl;
                }
            }
        }
    }

    return 0;
}
