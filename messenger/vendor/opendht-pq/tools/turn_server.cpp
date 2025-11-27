/**
 * DNA TURN Server Wrapper - Implementation
 */

#include "turn_server.h"
#include <juice/juice.h>
#include <iostream>
#include <cstring>

TurnServer::TurnServer() {}

TurnServer::~TurnServer() {
    stop();
}

bool TurnServer::start(const Config& config) {
    if (server_) {
        std::cerr << "[TURN] Server already running" << std::endl;
        return false;
    }

    // Configure libjuice server
    juice_server_config_t juice_config;
    memset(&juice_config, 0, sizeof(juice_config));

    juice_config.port = config.port;
    juice_config.max_allocations = config.max_allocations;
    juice_config.max_peers = config.max_peers;
    juice_config.relay_port_range_begin = config.relay_port_begin;
    juice_config.relay_port_range_end = config.relay_port_end;

    // External IP for relay candidates
    if (!config.external_ip.empty()) {
        juice_config.external_address = config.external_ip.c_str();
    }

    // Realm for TURN authentication
    if (!config.realm.empty()) {
        juice_config.realm = config.realm.c_str();
    }

    // Start with no credentials (added dynamically)
    juice_config.credentials = nullptr;
    juice_config.credentials_count = 0;

    // Set log level to WARN (suppress verbose STUN/TURN debug)
    juice_set_log_level(JUICE_LOG_LEVEL_WARN);

    // Create server
    server_ = juice_server_create(&juice_config);
    if (!server_) {
        std::cerr << "[TURN] Failed to create server" << std::endl;
        return false;
    }

    port_ = juice_server_get_port(server_);
    std::cout << "[TURN] Server started on port " << port_ << std::endl;
    std::cout << "[TURN] Relay ports: " << config.relay_port_begin
              << "-" << config.relay_port_end << std::endl;
    std::cout << "[TURN] Max allocations: " << config.max_allocations << std::endl;

    return true;
}

void TurnServer::stop() {
    if (server_) {
        juice_server_destroy(server_);
        server_ = nullptr;
        port_ = 0;
        credential_count_ = 0;
        std::cout << "[TURN] Server stopped" << std::endl;
    }
}

bool TurnServer::add_credentials(const std::string& username,
                                  const std::string& password,
                                  unsigned long ttl_ms) {
    if (!server_) {
        std::cerr << "[TURN] Server not running" << std::endl;
        return false;
    }

    juice_server_credentials_t creds;
    memset(&creds, 0, sizeof(creds));
    creds.username = username.c_str();
    creds.password = password.c_str();
    creds.allocations_quota = 10;  // Max allocations per user

    int result = juice_server_add_credentials(server_, &creds, ttl_ms);
    if (result != JUICE_ERR_SUCCESS) {
        std::cerr << "[TURN] Failed to add credentials: " << result << std::endl;
        return false;
    }

    credential_count_++;
    return true;
}

uint16_t TurnServer::get_port() const {
    return port_;
}

bool TurnServer::is_running() const {
    return server_ != nullptr;
}

TurnServer::Stats TurnServer::get_stats() const {
    Stats stats;
    stats.total_credentials = credential_count_;
    // Note: libjuice doesn't expose allocation count directly
    // Would need to track internally if needed
    return stats;
}
