/**
 * TURN Credential Manager - Implementation
 */

#include "turn_credential_manager.h"
#include "../../../dht/core/dht_context.h"

extern "C" {
#include "../../../crypto/utils/qgp_sha3.h"
#include "../../../crypto/utils/qgp_dilithium.h"
}

#include <iostream>
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>

// Request format:
// [version:1] [type:1] [timestamp:8] [nonce:32] [pubkey:2592] [signature:4627]
#define REQUEST_VERSION 1
#define REQUEST_TYPE_CREDENTIAL 1
#define REQUEST_HEADER_SIZE (1 + 1 + 8 + 32)
#define REQUEST_MIN_SIZE (REQUEST_HEADER_SIZE + QGP_DSA87_PUBLICKEYBYTES + QGP_DSA87_SIGNATURE_BYTES)

// Response format:
// [version:1] [type:1] [count:1]
// Per server: [host:64] [port:2] [username:128] [password:128] [expires:8]
#define RESPONSE_TYPE_CREDENTIALS 2
#define RESPONSE_SERVER_ENTRY_SIZE (64 + 2 + 128 + 128 + 8)

// Sync format:
// [username:128] [password:128] [expires_at:8] [issued_by:64]
#define SYNC_ENTRY_SIZE (128 + 128 + 8 + 64)

// Timestamp tolerance (5 minutes)
#define TIMESTAMP_TOLERANCE 300

TurnCredentialManager::TurnCredentialManager() {}

TurnCredentialManager::~TurnCredentialManager() {}

bool TurnCredentialManager::init(const Config& config) {
    if (!config.dht_ctx || !config.turn_server) {
        std::cerr << "[CRED] Invalid config: missing DHT or TURN server" << std::endl;
        return false;
    }

    config_ = config;
    std::cout << "[CRED] Credential manager initialized" << std::endl;
    std::cout << "[CRED] Credential TTL: " << config.credential_ttl_seconds
              << "s (" << (config.credential_ttl_seconds / 86400) << " days)" << std::endl;
    std::cout << "[CRED] Known TURN servers: " << config.turn_servers.size() << std::endl;

    return true;
}

void TurnCredentialManager::poll_requests() {
    // Poll DHT for credential requests targeted at any client
    // In practice, we'd need to monitor a specific key pattern
    // For now, we check for requests addressed to us via a well-known prefix

    // TODO: Implement DHT subscription for credential request keys
    // The key pattern is: SHA3-512(client_fingerprint + ":turn_request")
    // We need a way to discover these keys - likely through a separate index
}

void TurnCredentialManager::poll_sync() {
    if (!config_.dht_ctx) return;

    // Poll the credential sync key
    char sync_key_input[] = "dna:turn:credentials";
    char sync_key[129];
    qgp_sha3_512_hex((uint8_t*)sync_key_input, strlen(sync_key_input),
                     sync_key, sizeof(sync_key));

    uint8_t* data = nullptr;
    size_t data_len = 0;

    // Note: This is simplified - in practice we'd want to get all values
    // and process each one
    if (dht_get(config_.dht_ctx, (uint8_t*)sync_key, strlen(sync_key),
                &data, &data_len) == 0 && data) {
        // Process sync entries
        size_t offset = 0;
        while (offset + SYNC_ENTRY_SIZE <= data_len) {
            process_sync_entry(data + offset, SYNC_ENTRY_SIZE);
            offset += SYNC_ENTRY_SIZE;
        }
        free(data);
    }
}

bool TurnCredentialManager::process_request(const uint8_t* data, size_t len,
                                             const std::string& client_fingerprint) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.requests_processed++;

    if (len < REQUEST_MIN_SIZE) {
        std::cerr << "[CRED] Request too short: " << len << std::endl;
        stats_.auth_failures++;
        return false;
    }

    // Parse header
    uint8_t version = data[0];
    uint8_t type = data[1];

    if (version != REQUEST_VERSION || type != REQUEST_TYPE_CREDENTIAL) {
        std::cerr << "[CRED] Invalid version/type: " << (int)version
                  << "/" << (int)type << std::endl;
        stats_.auth_failures++;
        return false;
    }

    // Parse timestamp
    uint64_t timestamp;
    memcpy(&timestamp, data + 2, 8);

    // Check timestamp freshness
    time_t now = time(nullptr);
    if (std::abs((long long)(now - timestamp)) > TIMESTAMP_TOLERANCE) {
        std::cerr << "[CRED] Stale timestamp: " << timestamp
                  << " (now: " << now << ")" << std::endl;
        stats_.auth_failures++;
        return false;
    }

    // Parse nonce
    std::string nonce_hex;
    for (int i = 0; i < 32; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", data[10 + i]);
        nonce_hex += hex;
    }

    // Check for replay
    std::string replay_key = client_fingerprint + ":" + nonce_hex;
    if (processed_requests_.count(replay_key)) {
        std::cerr << "[CRED] Replay detected" << std::endl;
        stats_.auth_failures++;
        return false;
    }

    // Parse public key
    const uint8_t* pubkey = data + REQUEST_HEADER_SIZE;

    // Parse signature
    const uint8_t* signature = data + REQUEST_HEADER_SIZE + QGP_DSA87_PUBLICKEYBYTES;

    // Verify signature (over header + pubkey, excluding signature itself)
    size_t signed_len = REQUEST_HEADER_SIZE + QGP_DSA87_PUBLICKEYBYTES;
    if (!verify_signature(pubkey, QGP_DSA87_PUBLICKEYBYTES,
                          data, signed_len,
                          signature, QGP_DSA87_SIGNATURE_BYTES)) {
        std::cerr << "[CRED] Signature verification failed" << std::endl;
        stats_.auth_failures++;
        return false;
    }

    // Generate credentials
    std::string username, password;
    generate_credentials(username, password);

    // Add to TURN server
    unsigned long ttl_ms = config_.credential_ttl_seconds * 1000UL;
    if (!config_.turn_server->add_credentials(username, password, ttl_ms)) {
        std::cerr << "[CRED] Failed to add credentials to TURN server" << std::endl;
        return false;
    }

    // Record issued credential
    IssuedCredential cred;
    cred.username = username;
    cred.password = password;
    cred.client_fingerprint = client_fingerprint;
    cred.expires_at = now + config_.credential_ttl_seconds;
    cred.issued_at = now;
    cred.issued_by_node = config_.node_id;

    issued_credentials_[username] = cred;

    // Publish response to DHT
    if (!publish_response(client_fingerprint, username, password)) {
        std::cerr << "[CRED] Failed to publish response" << std::endl;
        // Continue anyway - credentials are added to TURN server
    }

    // Publish to sync key for other nodus
    if (!publish_sync(cred)) {
        std::cerr << "[CRED] Failed to publish sync" << std::endl;
    }

    // Track nonce for replay protection
    processed_requests_[replay_key] = now;

    stats_.credentials_issued++;
    std::cout << "[CRED] Issued credentials for " << client_fingerprint.substr(0, 16)
              << "... (expires: " << cred.expires_at << ")" << std::endl;

    return true;
}

bool TurnCredentialManager::verify_signature(const uint8_t* pubkey, size_t pubkey_len,
                                              const uint8_t* message, size_t message_len,
                                              const uint8_t* signature, size_t sig_len) {
    if (pubkey_len != QGP_DSA87_PUBLICKEYBYTES ||
        sig_len != QGP_DSA87_SIGNATURE_BYTES) {
        return false;
    }

    return qgp_dsa87_verify(signature, sig_len, message, message_len, pubkey) == 0;
}

void TurnCredentialManager::generate_credentials(std::string& username,
                                                   std::string& password) {
    // Generate random username and password
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // Username: timestamp_random
    time_t now = time(nullptr);
    std::stringstream ss;
    ss << "dna_" << now << "_";
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << dis(gen);
    }
    username = ss.str();

    // Password: 32 random bytes as hex
    std::stringstream ps;
    for (int i = 0; i < 32; i++) {
        ps << std::hex << std::setfill('0') << std::setw(2) << dis(gen);
    }
    password = ps.str();
}

bool TurnCredentialManager::publish_response(const std::string& client_fingerprint,
                                              const std::string& username,
                                              const std::string& password) {
    if (!config_.dht_ctx) return false;

    // Create response key
    std::string key_input = client_fingerprint + ":turn_credentials";
    char response_key[129];
    qgp_sha3_512_hex((uint8_t*)key_input.c_str(), key_input.length(),
                     response_key, sizeof(response_key));

    // Build response
    size_t server_count = config_.turn_servers.size();
    size_t response_len = 3 + server_count * RESPONSE_SERVER_ENTRY_SIZE;
    std::vector<uint8_t> response(response_len, 0);

    response[0] = REQUEST_VERSION;
    response[1] = RESPONSE_TYPE_CREDENTIALS;
    response[2] = (uint8_t)server_count;

    size_t offset = 3;
    time_t expires_at = time(nullptr) + config_.credential_ttl_seconds;

    for (const auto& server : config_.turn_servers) {
        // Host (64 bytes)
        strncpy((char*)&response[offset], server.host.c_str(), 63);
        offset += 64;

        // Port (2 bytes)
        memcpy(&response[offset], &server.port, 2);
        offset += 2;

        // Username (128 bytes)
        strncpy((char*)&response[offset], username.c_str(), 127);
        offset += 128;

        // Password (128 bytes)
        strncpy((char*)&response[offset], password.c_str(), 127);
        offset += 128;

        // Expires (8 bytes)
        memcpy(&response[offset], &expires_at, 8);
        offset += 8;
    }

    // Publish to DHT with TTL matching credential TTL
    return dht_put_signed(config_.dht_ctx,
                          (uint8_t*)response_key, strlen(response_key),
                          response.data(), response.size(),
                          1,  // value_id
                          config_.credential_ttl_seconds) == 0;
}

bool TurnCredentialManager::publish_sync(const IssuedCredential& cred) {
    if (!config_.dht_ctx) return false;

    // Create sync key
    char sync_key_input[] = "dna:turn:credentials";
    char sync_key[129];
    qgp_sha3_512_hex((uint8_t*)sync_key_input, strlen(sync_key_input),
                     sync_key, sizeof(sync_key));

    // Build sync entry
    std::vector<uint8_t> entry(SYNC_ENTRY_SIZE, 0);

    // Username (128 bytes)
    strncpy((char*)&entry[0], cred.username.c_str(), 127);

    // Password (128 bytes)
    strncpy((char*)&entry[128], cred.password.c_str(), 127);

    // Expires (8 bytes)
    memcpy(&entry[256], &cred.expires_at, 8);

    // Issued by node (64 bytes)
    strncpy((char*)&entry[264], cred.issued_by_node.c_str(), 63);

    // Publish with 1-hour TTL (sync is refreshed frequently)
    return dht_put_signed(config_.dht_ctx,
                          (uint8_t*)sync_key, strlen(sync_key),
                          entry.data(), entry.size(),
                          0,  // value_id = 0 means append (multi-value)
                          3600) == 0;  // 1 hour
}

bool TurnCredentialManager::process_sync_entry(const uint8_t* data, size_t len) {
    if (len < SYNC_ENTRY_SIZE) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    // Parse entry
    char username[129] = {0};
    char password[129] = {0};
    char issued_by[65] = {0};
    time_t expires_at;

    strncpy(username, (const char*)data, 127);
    strncpy(password, (const char*)(data + 128), 127);
    memcpy(&expires_at, data + 256, 8);
    strncpy(issued_by, (const char*)(data + 264), 63);

    // Skip if issued by us
    if (config_.node_id == issued_by) {
        return true;
    }

    // Skip if already have this credential
    if (issued_credentials_.count(username)) {
        return true;
    }

    // Skip if expired
    if (expires_at <= time(nullptr)) {
        return true;
    }

    // Add to TURN server
    time_t now = time(nullptr);
    unsigned long ttl_ms = (expires_at - now) * 1000UL;

    if (!config_.turn_server->add_credentials(username, password, ttl_ms)) {
        std::cerr << "[CRED] Failed to add synced credential" << std::endl;
        return false;
    }

    // Record
    IssuedCredential cred;
    cred.username = username;
    cred.password = password;
    cred.expires_at = expires_at;
    cred.issued_at = now;
    cred.issued_by_node = issued_by;

    issued_credentials_[username] = cred;
    stats_.sync_received++;

    std::cout << "[CRED] Synced credential from " << issued_by << std::endl;
    return true;
}

TurnCredentialManager::Stats TurnCredentialManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}
