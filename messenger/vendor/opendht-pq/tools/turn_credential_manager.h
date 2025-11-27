/**
 * TURN Credential Manager
 *
 * Handles DHT-based credential requests and issuing for TURN server.
 * - Monitors DHT for credential requests
 * - Verifies Dilithium5 signatures
 * - Issues credentials to authenticated clients
 * - Syncs credentials between nodus instances
 */

#ifndef TURN_CREDENTIAL_MANAGER_H
#define TURN_CREDENTIAL_MANAGER_H

#include "turn_server.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <ctime>

// Forward declarations
extern "C" {
    typedef struct dht_context dht_context_t;
}

// TURN server info for credential response
struct TurnServerInfo {
    std::string host;
    uint16_t port;
};

// Issued credential record
struct IssuedCredential {
    std::string username;
    std::string password;
    std::string client_fingerprint;
    time_t expires_at;
    time_t issued_at;
    std::string issued_by_node;
};

class TurnCredentialManager {
public:
    struct Config {
        dht_context_t* dht_ctx = nullptr;
        TurnServer* turn_server = nullptr;
        std::vector<TurnServerInfo> turn_servers;  // All known TURN servers
        uint32_t credential_ttl_seconds = 604800;  // 7 days
        std::string node_id;  // This node's ID
    };

    TurnCredentialManager();
    ~TurnCredentialManager();

    // Initialize with config
    bool init(const Config& config);

    // Poll for credential requests (call every few seconds)
    void poll_requests();

    // Poll for credential sync from other nodus (call every 30 seconds)
    void poll_sync();

    // Get stats
    struct Stats {
        size_t requests_processed = 0;
        size_t credentials_issued = 0;
        size_t auth_failures = 0;
        size_t sync_received = 0;
    };
    Stats get_stats() const;

private:
    // Process a single credential request
    bool process_request(const uint8_t* data, size_t len,
                         const std::string& client_fingerprint);

    // Verify Dilithium5 signature
    bool verify_signature(const uint8_t* pubkey, size_t pubkey_len,
                          const uint8_t* message, size_t message_len,
                          const uint8_t* signature, size_t sig_len);

    // Generate random credentials
    void generate_credentials(std::string& username, std::string& password);

    // Publish credential response to DHT
    bool publish_response(const std::string& client_fingerprint,
                          const std::string& username,
                          const std::string& password);

    // Publish credential to sync key (for other nodus)
    bool publish_sync(const IssuedCredential& cred);

    // Process synced credential from another nodus
    bool process_sync_entry(const uint8_t* data, size_t len);

    Config config_;
    Stats stats_;
    std::map<std::string, time_t> processed_requests_;  // Nonce tracking
    std::map<std::string, IssuedCredential> issued_credentials_;
    mutable std::mutex mutex_;
};

#endif // TURN_CREDENTIAL_MANAGER_H
