/*
 * DNA Nodus - Post-Quantum DHT Bootstrap Node
 *
 * Dilithium5 (FIPS 204 / ML-DSA-87) enforced bootstrap node for DNA Messenger
 *
 * Features:
 * - Mandatory Dilithium5 signature enforcement
 * - Binary identity files (.dsa, .pub, .cert)
 * - Public bootstrap node (no rate limiting)
 * - Auto-registration in DHT bootstrap registry
 * - Listens on port 4000
 */

#include <opendht/dhtrunner.h>
#include <opendht/log.h>
#include <opendht/crypto.h>

#include <iostream>
#include <fstream>
#include <csignal>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace dht;

static std::atomic_bool running{true};

void signal_handler(int sig) {
    (void)sig;
    running = false;
}

// Bootstrap registry key - all nodus nodes publish to this key
const InfoHash BOOTSTRAP_REGISTRY_KEY = InfoHash::get("dna:bootstrap:registry:v1");

// Get the first non-loopback IPv4 address
std::string get_interface_ip() {
    struct ifaddrs *ifaddr, *ifa;
    std::string ip;

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get interface addresses" << std::endl;
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            continue;

        // Check for IPv4 address
        if (ifa->ifa_addr->sa_family == AF_INET) {
            void* addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, addr, addressBuffer, INET_ADDRSTRLEN);

            // Skip loopback
            std::string addr_str(addressBuffer);
            if (addr_str != "127.0.0.1" && addr_str.substr(0, 4) != "127.") {
                ip = addr_str;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return ip;
}

int main(int argc, char** argv) {
    std::cout << "DNA Nodus v0.1 - Post-Quantum DHT Bootstrap Node" << std::endl;
    std::cout << "FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5 Security" << std::endl;
    std::cout << "Mandatory signature enforcement enabled" << std::endl << std::endl;

    // Default settings
    int port = 4000;
    std::string identity_path = "/root/.nodus/identity";
    std::string persist_path = "/var/lib/dna-dht/bootstrap.state";  // Default persistence path
    std::string bootstrap_host = "";
    int bootstrap_port = 4000;
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
            std::string bootstrap = argv[++i];
            size_t colon_pos = bootstrap.find(':');
            if (colon_pos != std::string::npos) {
                bootstrap_host = bootstrap.substr(0, colon_pos);
                bootstrap_port = std::stoi(bootstrap.substr(colon_pos + 1));
            } else {
                bootstrap_host = bootstrap;
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
            std::cout << "  -i <path>           Identity file path (default: /root/.nodus/identity)" << std::endl;
            std::cout << "  -s <path>           Persistence file path (default: /var/lib/dna-dht/bootstrap.state)" << std::endl;
            std::cout << "  -b <host>[:port]    Bootstrap from host (default port: 4000)" << std::endl;
            std::cout << "  --public-ip <ip>    Public IP address for DHT registry" << std::endl;
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

    try {
        // Load or generate Dilithium5 identity
        crypto::Identity id;
        std::cout << "Identity path: " << identity_path << std::endl;

        std::ifstream sk_test(identity_path + ".dsa");
        if (sk_test.good()) {
            sk_test.close();
            std::cout << "Loading existing Dilithium5 identity..." << std::endl;
            id = crypto::loadDilithiumIdentity(identity_path);
            std::cout << "Identity loaded: " << id.second->getId() << std::endl;
        } else {
            std::cout << "Generating new Dilithium5 identity (FIPS 204 / ML-DSA-87)..." << std::endl;
            id = crypto::generateDilithiumIdentity("dna-nodus");

            // Create directory if it doesn't exist
            std::string dir_path = identity_path.substr(0, identity_path.find_last_of('/'));
            system(("mkdir -p " + dir_path).c_str());

            crypto::saveDilithiumIdentity(id, identity_path);
            std::cout << "New identity saved: " << id.second->getId() << std::endl;
        }

        // Create DHT node configuration
        DhtRunner::Config config;
        config.dht_config.node_config.network = 0;  // Default network
        config.dht_config.node_config.maintain_storage = false;
        config.dht_config.node_config.persist_path = persist_path;  // Enable persistence
        config.dht_config.id = id;
        config.threaded = true;

        // Create and start DHT runner
        DhtRunner dht;
        std::cout << "Starting DHT node on port " << port << "..." << std::endl;
        std::cout << "Persistence: " << persist_path << std::endl;
        dht.run(port, config);

        // Bootstrap if host specified
        if (!bootstrap_host.empty()) {
            std::cout << "Bootstrapping from " << bootstrap_host << ":" << bootstrap_port << "..." << std::endl;
            dht.bootstrap(bootstrap_host, std::to_string(bootstrap_port));
        }

        std::cout << std::endl;
        std::cout << "=== DNA Nodus Running ===" << std::endl;
        std::cout << "Node ID:  " << dht.getNodeId() << std::endl;
        std::cout << "Cert ID:  " << id.second->getId() << std::endl;
        std::cout << "Port:     " << port << std::endl;
        std::cout << "Security: Dilithium5 (ML-DSA-87) - Mandatory Signatures" << std::endl;
        if (!public_ip.empty())
            std::cout << "Public IP: " << public_ip << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl << std::endl;

        // Publish bootstrap node info to DHT registry (if public IP specified)
        auto publish_bootstrap_info = [&]() {
            if (public_ip.empty())
                return;

            // Create bootstrap info value
            std::stringstream info;
            info << "{";
            info << "\"ip\":\"" << public_ip << "\",";
            info << "\"port\":" << port << ",";
            info << "\"fingerprint\":\"" << id.second->getId() << "\",";
            info << "\"node_id\":\"" << dht.getNodeId() << "\",";
            info << "\"timestamp\":" << std::time(nullptr);
            info << "}";

            auto value = std::make_shared<Value>(info.str());
            value->sign(*id.first);

            // Put with 30-day TTL
            auto expire_time = dht::clock::now() + std::chrono::hours(24 * 30);
            dht.put(BOOTSTRAP_REGISTRY_KEY, value, [](bool success) {
                if (success)
                    std::cout << "[Registry] Published bootstrap node info" << std::endl;
                else
                    std::cerr << "[Registry] Failed to publish bootstrap node info" << std::endl;
            }, expire_time);
        };

        // Initial publish (wait for DHT to stabilize and connect to network)
        if (!public_ip.empty()) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            publish_bootstrap_info();
        }

        // Main loop
        int counter = 0;
        int registry_counter = 0;
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // Print stats every 60 seconds if verbose
            if (verbose && ++counter >= 60) {
                counter = 0;
                auto store_size = dht.getStoreSize();
                std::cout << "[" << dht.getNodesStats(AF_INET).good_nodes
                          << " nodes] [" << store_size.first
                          << " values]" << std::endl;
            }

            // Refresh bootstrap registry every 30 minutes (DHT values expire after ~1 hour)
            if (!public_ip.empty() && ++registry_counter >= 1800) {
                registry_counter = 0;
                publish_bootstrap_info();
            }
        }

        std::cout << std::endl << "Shutting down..." << std::endl;
        dht.join();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "DNA Nodus stopped" << std::endl;
    return 0;
}
