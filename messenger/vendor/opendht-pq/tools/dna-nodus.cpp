/*
 * DNA Nodus - Post-Quantum DHT Bootstrap Node with SQL Persistence
 *
 * Dilithium5 (FIPS 204 / ML-DSA-87) enforced bootstrap node for DNA Messenger
 *
 * Features:
 * - SQLite value persistence (survives restarts)
 * - Mandatory Dilithium5 signature enforcement
 * - Binary identity files (.dsa, .pub, .cert)
 * - Public bootstrap node (no rate limiting)
 * - Auto-registration in DHT bootstrap registry
 * - Listens on port 4000
 */

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

static dht_context_t *global_ctx = NULL;

void signal_handler(int sig) {
    (void)sig;
    std::cout << "\nShutting down..." << std::endl;
    if (global_ctx) {
        dht_context_stop(global_ctx);
        dht_context_free(global_ctx);
    }
    exit(0);
}

// Get the first non-loopback IPv4 address
std::string get_interface_ip() {
    struct ifaddrs *ifaddr, *ifa;
    std::string ip;

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get interface addresses" << std::endl;
        return "";
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
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

// Get file size and format as human-readable string
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
    return std::string(buf);
}

int main(int argc, char** argv) {
    std::cout << "DNA Nodus v0.2 - Post-Quantum DHT Bootstrap Node" << std::endl;
    std::cout << "FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5 Security" << std::endl;
    std::cout << "SQLite value persistence enabled" << std::endl << std::endl;

    // Default settings
    int port = 4000;
    std::string identity_path = "dna-bootstrap-node";
    std::string persist_path = "/var/lib/dna-dht/bootstrap.state";
    std::string bootstrap_hosts[3];
    int bootstrap_count = 0;
    std::string public_ip = "";
    bool verbose = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "-i" && i + 1 < argc) {
            identity_path = argv[++i];
        } else if (arg == "-b" && i + 1 < argc) {
            if (bootstrap_count < 3) {
                bootstrap_hosts[bootstrap_count++] = argv[++i];
            }
        } else if (arg == "--public-ip" && i + 1 < argc) {
            public_ip = argv[++i];
        } else if (arg == "-s" && i + 1 < argc) {
            persist_path = argv[++i];
        } else if (arg == "-v") {
            verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: dna-nodus [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  -p <port>           Port to listen on (default: 4000)" << std::endl;
            std::cout << "  -i <path>           Identity name (default: dna-bootstrap-node)" << std::endl;
            std::cout << "  -s <path>           Persistence path (default: /var/lib/dna-dht/bootstrap.state)" << std::endl;
            std::cout << "  -b <host>:port      Bootstrap from host (can specify multiple times)" << std::endl;
            std::cout << "  --public-ip <ip>    Public IP address" << std::endl;
            std::cout << "  -v                  Verbose logging" << std::endl;
            std::cout << "  -h, --help          Show this help" << std::endl;
            return 0;
        }
    }

    // Auto-detect public IP if not specified
    if (public_ip.empty()) {
        public_ip = get_interface_ip();
        if (!public_ip.empty())
            std::cout << "Auto-detected IP: " << public_ip << std::endl;
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Configure DHT context for bootstrap node
    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = port;
    config.is_bootstrap = true;  // Enable bootstrap mode + value storage
    strncpy(config.identity, identity_path.c_str(), sizeof(config.identity) - 1);
    strncpy(config.persistence_path, persist_path.c_str(), sizeof(config.persistence_path) - 1);

    // Add bootstrap nodes
    config.bootstrap_count = bootstrap_count;
    for (int i = 0; i < bootstrap_count; i++) {
        strncpy(config.bootstrap_nodes[i], bootstrap_hosts[i].c_str(),
                sizeof(config.bootstrap_nodes[i]) - 1);
    }

    std::cout << "Creating DHT context (bootstrap mode)..." << std::endl;
    global_ctx = dht_context_new(&config);
    if (!global_ctx) {
        std::cerr << "ERROR: Failed to create DHT context" << std::endl;
        return 1;
    }
    std::cout << "✓ DHT context created" << std::endl << std::endl;

    std::cout << "Starting DHT node on port " << port << "..." << std::endl;
    std::cout << "Persistence: " << persist_path << std::endl;

    // Check database size
    std::string db_path = persist_path + ".values.db";
    std::string db_size = get_file_size(db_path);
    std::cout << "Database:    " << db_path << " (" << db_size << ")" << std::endl;

    if (dht_context_start(global_ctx) != 0) {
        std::cerr << "ERROR: Failed to start DHT node" << std::endl;
        dht_context_free(global_ctx);
        return 1;
    }
    std::cout << "✓ DHT node started" << std::endl << std::endl;

    std::cout << "=== DNA Nodus Running ===" << std::endl;
    std::cout << "Port:     " << port << std::endl;
    std::cout << "Security: Dilithium5 (ML-DSA-87) - Mandatory Signatures" << std::endl;
    if (!public_ip.empty()) {
        std::cout << "Public IP: " << public_ip << std::endl;
    }
    std::cout << "Press Ctrl+C to stop" << std::endl << std::endl;

    // Register this bootstrap node in DHT registry
    {
        char node_id[129];
        if (dht_get_node_id(global_ctx, node_id) == 0) {
            std::cout << "[REGISTRY] Node ID: " << std::string(node_id).substr(0, 16) << "..." << std::endl;

            if (dht_bootstrap_registry_register(global_ctx, public_ip.c_str(), port,
                                                node_id, "v0.2", 0) == 0) {
                std::cout << "[REGISTRY] ✓ Registered in bootstrap registry" << std::endl;
            } else {
                std::cerr << "[REGISTRY] WARNING: Failed to register in bootstrap registry" << std::endl;
            }
        }
    }

    // Main loop - print stats every 60 seconds, refresh registry every 5 minutes
    int seconds = 0;
    while (true) {
        sleep(1);
        seconds++;

        // Refresh bootstrap registry every 5 minutes
        if (seconds % 300 == 0) {
            char node_id[129];
            if (dht_get_node_id(global_ctx, node_id) == 0) {
                dht_bootstrap_registry_register(global_ctx, public_ip.c_str(), port,
                                                node_id, "v0.2", seconds);
            }
        }

        if (seconds % 60 == 0) {
            size_t node_count = 0;
            size_t stored_values = 0;
            if (dht_get_stats(global_ctx, &node_count, &stored_values) == 0) {
                std::cout << "[" << seconds / 60 << " min] ";
                std::cout << "[" << node_count << " nodes] ";
                std::cout << "[" << stored_values << " values]";

                // Print storage stats if available
                dht_value_storage_t *storage = dht_get_storage(global_ctx);
                if (storage) {
                    dht_storage_stats_t storage_stats;
                    if (dht_value_storage_get_stats(storage, &storage_stats) == 0) {
                        std::cout << " | DB: " << storage_stats.total_values << " values";

                        if (storage_stats.republish_in_progress) {
                            std::cout << " (republishing...)";
                        }
                    }
                }
                std::cout << std::endl;
            }
        }
    }

    return 0;
}
