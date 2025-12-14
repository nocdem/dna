/**
 * DNA Nodus Configuration - Implementation
 */

#include "nodus_config.h"
#include "../../nlohmann/json.hpp"

#include <fstream>
#include <iostream>

using json = nlohmann::json;

void NodusConfig::apply_defaults() {
    dht_port = NODUS_DEFAULT_DHT_PORT;
    seed_nodes.clear();
    seed_nodes.push_back(NODUS_DEFAULT_SEED_NODE);
    persistence_path = NODUS_DEFAULT_PERSISTENCE_PATH;

    turn_port = NODUS_DEFAULT_TURN_PORT;
    credential_port = NODUS_DEFAULT_CREDENTIAL_PORT;
    relay_port_begin = NODUS_DEFAULT_RELAY_PORT_BEGIN;
    relay_port_end = NODUS_DEFAULT_RELAY_PORT_END;
    credential_ttl_seconds = NODUS_DEFAULT_CREDENTIAL_TTL;

    identity = "dna-bootstrap-node";
    public_ip = "auto";
    verbose = false;
}

bool NodusConfig::load(const std::string& path) {
    // Start with defaults
    apply_defaults();

    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "[CONFIG] No config file at " << path << ", using defaults" << std::endl;
        return false;
    }

    try {
        json config = json::parse(file);

        // DHT settings
        if (config.contains("dht")) {
            auto& dht = config["dht"];
            if (dht.contains("port")) {
                dht_port = dht["port"].get<uint16_t>();
            }
            if (dht.contains("seed_nodes")) {
                seed_nodes.clear();
                for (const auto& node : dht["seed_nodes"]) {
                    seed_nodes.push_back(node.get<std::string>());
                }
            }
            if (dht.contains("persistence_path")) {
                persistence_path = dht["persistence_path"].get<std::string>();
            }
        }

        // TURN settings
        if (config.contains("turn")) {
            auto& turn = config["turn"];
            if (turn.contains("port")) {
                turn_port = turn["port"].get<uint16_t>();
            }
            if (turn.contains("relay_port_begin")) {
                relay_port_begin = turn["relay_port_begin"].get<uint16_t>();
            }
            if (turn.contains("relay_port_end")) {
                relay_port_end = turn["relay_port_end"].get<uint16_t>();
            }
            if (turn.contains("credential_ttl_seconds")) {
                credential_ttl_seconds = turn["credential_ttl_seconds"].get<uint32_t>();
            }
        }

        // Flat config keys (actual format used in /etc/dna-nodus.conf)
        if (config.contains("dht_port")) {
            dht_port = config["dht_port"].get<uint16_t>();
        }
        if (config.contains("seed_nodes")) {
            seed_nodes.clear();
            for (const auto& node : config["seed_nodes"]) {
                seed_nodes.push_back(node.get<std::string>());
            }
        }
        if (config.contains("persistence_path")) {
            persistence_path = config["persistence_path"].get<std::string>();
        }
        if (config.contains("turn_port")) {
            turn_port = config["turn_port"].get<uint16_t>();
        }
        if (config.contains("credential_port")) {
            credential_port = config["credential_port"].get<uint16_t>();
        }
        if (config.contains("relay_port_begin")) {
            relay_port_begin = config["relay_port_begin"].get<uint16_t>();
        }
        if (config.contains("relay_port_end")) {
            relay_port_end = config["relay_port_end"].get<uint16_t>();
        }
        if (config.contains("credential_ttl_seconds")) {
            credential_ttl_seconds = config["credential_ttl_seconds"].get<uint32_t>();
        }

        // General settings
        if (config.contains("identity")) {
            identity = config["identity"].get<std::string>();
        }
        if (config.contains("public_ip")) {
            public_ip = config["public_ip"].get<std::string>();
        }
        if (config.contains("verbose")) {
            verbose = config["verbose"].get<bool>();
        }

        std::cout << "[CONFIG] Loaded from " << path << std::endl;
        return true;

    } catch (const json::exception& e) {
        std::cerr << "[CONFIG] Parse error: " << e.what() << std::endl;
        std::cerr << "[CONFIG] Using defaults" << std::endl;
        apply_defaults();
        return false;
    }
}

void NodusConfig::print() const {
    std::cout << "=== DNA Nodus Configuration ===" << std::endl;
    std::cout << "DHT:" << std::endl;
    std::cout << "  port: " << dht_port << std::endl;
    std::cout << "  seed_nodes: ";
    for (size_t i = 0; i < seed_nodes.size(); i++) {
        if (i > 0) std::cout << ", ";
        std::cout << seed_nodes[i];
    }
    std::cout << std::endl;
    std::cout << "  persistence_path: " << persistence_path << std::endl;

    std::cout << "TURN:" << std::endl;
    std::cout << "  port: " << turn_port << std::endl;
    std::cout << "  relay_ports: " << relay_port_begin << "-" << relay_port_end << std::endl;
    std::cout << "  credential_ttl: " << credential_ttl_seconds << "s ("
              << (credential_ttl_seconds / 86400) << " days)" << std::endl;

    std::cout << "General:" << std::endl;
    std::cout << "  identity: " << identity << std::endl;
    std::cout << "  public_ip: " << public_ip << std::endl;
    std::cout << "  verbose: " << (verbose ? "true" : "false") << std::endl;
    std::cout << "===============================" << std::endl;
}
