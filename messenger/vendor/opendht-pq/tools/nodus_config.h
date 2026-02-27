/**
 * DNA Nodus Configuration
 *
 * JSON config file loader for dna-nodus.
 * Default path: /etc/dna-nodus.conf
 *
 * Privacy: STUN/TURN removed in v0.4.61
 * TURN config fields kept for backwards compatibility but ignored.
 */

#ifndef NODUS_CONFIG_H
#define NODUS_CONFIG_H

#include <stdint.h>
#include <string>
#include <vector>

// Default values
#define NODUS_DEFAULT_DHT_PORT 4000
#define NODUS_DEFAULT_SEED_NODE "154.38.182.161:4000"
#define NODUS_DEFAULT_PERSISTENCE_PATH "/var/lib/dna-dht/bootstrap.state"
#define NODUS_DEFAULT_CONFIG_PATH "/etc/dna-nodus.conf"

// TURN defaults removed in v0.4.61 - no longer used
// These were: turn_port=3478, credential_port=3479, relay_ports=49152-65535

struct NodusConfig {
    // DHT settings
    uint16_t dht_port = NODUS_DEFAULT_DHT_PORT;
    std::vector<std::string> seed_nodes;
    std::string persistence_path = NODUS_DEFAULT_PERSISTENCE_PATH;

    // TURN settings removed in v0.4.61 for privacy
    // Fields kept for config file backwards compatibility (ignored)
    uint16_t turn_port = 0;              // Deprecated, ignored
    uint16_t credential_port = 0;        // Deprecated, ignored
    uint16_t relay_port_begin = 0;       // Deprecated, ignored
    uint16_t relay_port_end = 0;         // Deprecated, ignored
    uint32_t credential_ttl_seconds = 0; // Deprecated, ignored

    // General settings
    std::string identity = "dna-bootstrap-node";
    std::string public_ip = "auto";  // "auto" means detect
    bool verbose = false;

    // Load config from JSON file
    // Returns true on success, false on error (uses defaults on error)
    bool load(const std::string& path = NODUS_DEFAULT_CONFIG_PATH);

    // Apply default values
    void apply_defaults();

    // Print config to stdout
    void print() const;
};

#endif // NODUS_CONFIG_H
