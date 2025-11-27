/**
 * DNA TURN Server Wrapper
 *
 * Wraps libjuice TURN server for dna-nodus.
 * Provides STUN + TURN functionality on port 3478.
 */

#ifndef TURN_SERVER_H
#define TURN_SERVER_H

#include <stdint.h>
#include <string>

// Forward declaration
struct juice_server;

class TurnServer {
public:
    struct Config {
        uint16_t port = 3478;
        std::string external_ip;         // Public IP for relay candidates
        std::string realm = "dna-messenger";
        int max_allocations = 1000;
        int max_peers = 16;
        uint16_t relay_port_begin = 49152;
        uint16_t relay_port_end = 65535;
    };

    TurnServer();
    ~TurnServer();

    // Start the TURN server
    bool start(const Config& config);

    // Stop the TURN server
    void stop();

    // Add credentials with TTL (milliseconds)
    // Credentials are valid across all allocations
    bool add_credentials(const std::string& username,
                         const std::string& password,
                         unsigned long ttl_ms);

    // Get actual port (may differ if 0 was specified)
    uint16_t get_port() const;

    // Check if server is running
    bool is_running() const;

    // Get stats
    struct Stats {
        int active_allocations = 0;
        int total_credentials = 0;
    };
    Stats get_stats() const;

private:
    juice_server* server_ = nullptr;
    uint16_t port_ = 0;
    int credential_count_ = 0;
};

#endif // TURN_SERVER_H
