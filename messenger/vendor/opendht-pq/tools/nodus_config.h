/**
 * DNA Nodus Configuration
 *
 * JSON config file loader for dna-nodus.
 * Default path: /etc/dna-nodus.conf
 */

#ifndef NODUS_CONFIG_H
#define NODUS_CONFIG_H

#include <stdint.h>
#include <string>
#include <vector>

// Default values
#define NODUS_DEFAULT_DHT_PORT 4000
#define NODUS_DEFAULT_TURN_PORT 3478
#define NODUS_DEFAULT_CREDENTIAL_PORT 3479
#define NODUS_DEFAULT_RELAY_PORT_BEGIN 49152
#define NODUS_DEFAULT_RELAY_PORT_END 65535
#define NODUS_DEFAULT_CREDENTIAL_TTL 604800  // 7 days in seconds
#define NODUS_DEFAULT_SEED_NODE "154.38.182.161:4000"
#define NODUS_DEFAULT_PERSISTENCE_PATH "/var/lib/dna-dht/bootstrap.state"
#define NODUS_DEFAULT_CONFIG_PATH "/etc/dna-nodus.conf"

struct NodusConfig {
    // DHT settings
    uint16_t dht_port = NODUS_DEFAULT_DHT_PORT;
    std::vector<std::string> seed_nodes;
    std::string persistence_path = NODUS_DEFAULT_PERSISTENCE_PATH;

    // TURN settings
    uint16_t turn_port = NODUS_DEFAULT_TURN_PORT;
    uint16_t credential_port = NODUS_DEFAULT_CREDENTIAL_PORT;
    uint16_t relay_port_begin = NODUS_DEFAULT_RELAY_PORT_BEGIN;
    uint16_t relay_port_end = NODUS_DEFAULT_RELAY_PORT_END;
    uint32_t credential_ttl_seconds = NODUS_DEFAULT_CREDENTIAL_TTL;

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
