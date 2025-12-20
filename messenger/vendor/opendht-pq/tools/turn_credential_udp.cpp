/**
 * TURN Credential UDP Server - Implementation
 *
 * Handles direct UDP credential requests from clients.
 */

#include "turn_credential_udp.h"
#include "turn_server.h"

extern "C" {
#include "../../../crypto/utils/qgp_dilithium.h"
#include "../../../crypto/utils/qgp_sha3.h"
#include "../../../crypto/utils/qgp_random.h"
}

#include <iostream>
#include <cstring>
#include <ctime>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
typedef int SOCKET;
#endif

// Global state
static SOCKET g_socket = INVALID_SOCKET;
static std::thread g_server_thread;
static std::atomic<bool> g_running{false};
static std::mutex g_mutex;
static cred_udp_stats_t g_stats = {0, 0, 0, 0, 0};
static cred_udp_server_config_t g_config;
static TurnServer* g_turn_server = nullptr;

// Nonce tracking for replay protection (nonce_hex -> timestamp)
static std::map<std::string, time_t> g_used_nonces;
static const int NONCE_EXPIRY_SECONDS = 600;  // 10 minutes

// Clean expired nonces (called periodically)
static void cleanup_expired_nonces() {
    time_t now = time(nullptr);
    auto it = g_used_nonces.begin();
    while (it != g_used_nonces.end()) {
        if (now - it->second > NONCE_EXPIRY_SECONDS) {
            it = g_used_nonces.erase(it);
        } else {
            ++it;
        }
    }
}

// Convert bytes to hex string
static std::string bytes_to_hex(const uint8_t *data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", data[i]);
        result += hex;
    }
    return result;
}

// Setter for TURN server reference (called by dna-nodus)
void cred_udp_set_turn_server(void* turn) {
    g_turn_server = static_cast<TurnServer*>(turn);
}

// Generate random credential string
static void generate_credential(char *out, size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t random_bytes[128];
    qgp_randombytes(random_bytes, len - 1);

    for (size_t i = 0; i < len - 1; i++) {
        out[i] = charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    out[len - 1] = '\0';
}

// Process a credential request packet
static int process_request(const uint8_t *data, size_t len,
                           struct sockaddr_in *client_addr,
                           uint8_t *response, size_t *response_len) {
    std::lock_guard<std::mutex> lock(g_mutex);
    (void)client_addr;  // Reserved for future rate limiting

    g_stats.requests_received++;

    // Clean expired nonces periodically
    cleanup_expired_nonces();

    // Validate minimum size: magic(4) + header + fingerprint + nonce + pubkey + signature
    size_t min_size = 4 + 2 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE +
                      CRED_UDP_PUBKEY_SIZE + CRED_UDP_SIGNATURE_SIZE;
    if (len < min_size) {
        std::cerr << "[CRED-UDP] Packet too short: " << len << " < " << min_size << std::endl;
        g_stats.invalid_packets++;
        return -1;
    }

    // Check magic
    uint32_t magic;
    memcpy(&magic, data, 4);
    if (magic != CRED_UDP_MAGIC) {
        std::cerr << "[CRED-UDP] Invalid magic: 0x" << std::hex << magic << std::dec << std::endl;
        g_stats.invalid_packets++;
        return -1;
    }

    // Parse header
    uint8_t version = data[4];
    uint8_t type = data[5];

    if (version != CRED_UDP_VERSION) {
        std::cerr << "[CRED-UDP] Invalid version: " << (int)version << std::endl;
        g_stats.invalid_packets++;
        return -1;
    }

    if (type != CRED_UDP_TYPE_REQUEST) {
        std::cerr << "[CRED-UDP] Invalid type: " << (int)type << std::endl;
        g_stats.invalid_packets++;
        return -1;
    }

    // Parse timestamp (8 bytes, big-endian)
    uint64_t timestamp = 0;
    for (int i = 0; i < 8; i++) {
        timestamp = (timestamp << 8) | data[6 + i];
    }

    // Check timestamp freshness
    time_t now = time(nullptr);
    if (std::abs((long long)(now - timestamp)) > CRED_UDP_TIMESTAMP_TOLERANCE) {
        std::cerr << "[CRED-UDP] Stale timestamp: " << timestamp << " (now: " << now << ")" << std::endl;
        g_stats.auth_failures++;
        return -1;
    }

    // Extract fingerprint (128 hex chars)
    char fingerprint[129];
    memcpy(fingerprint, data + 14, CRED_UDP_FINGERPRINT_SIZE);
    fingerprint[128] = '\0';

    // Extract nonce (32 bytes)
    const uint8_t *nonce = data + 14 + CRED_UDP_FINGERPRINT_SIZE;

    // Check for nonce replay
    std::string nonce_hex = bytes_to_hex(nonce, CRED_UDP_NONCE_SIZE);
    std::string replay_key = std::string(fingerprint) + ":" + nonce_hex;
    if (g_used_nonces.count(replay_key)) {
        std::cerr << "[CRED-UDP] Replay attack detected (nonce reuse)" << std::endl;
        g_stats.auth_failures++;
        return -1;
    }

    // Extract public key (2592 bytes)
    const uint8_t *pubkey = data + 14 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE;

    // Verify fingerprint matches SHA3-512(pubkey)
    char computed_fingerprint[129];
    if (qgp_sha3_512_hex(pubkey, CRED_UDP_PUBKEY_SIZE,
                         computed_fingerprint, sizeof(computed_fingerprint)) != 0) {
        std::cerr << "[CRED-UDP] Failed to compute fingerprint hash" << std::endl;
        g_stats.auth_failures++;
        return -1;
    }

    if (strncmp(fingerprint, computed_fingerprint, 128) != 0) {
        std::cerr << "[CRED-UDP] Fingerprint mismatch - pubkey doesn't match claimed identity" << std::endl;
        g_stats.auth_failures++;
        return -1;
    }

    // Extract signature (4627 bytes)
    const uint8_t *signature = data + 14 + CRED_UDP_FINGERPRINT_SIZE +
                               CRED_UDP_NONCE_SIZE + CRED_UDP_PUBKEY_SIZE;

    // Verify Dilithium5 signature over (timestamp + fingerprint + nonce)
    // Signed data starts at offset 6 (after magic + version + type)
    const uint8_t *signed_data = data + 6;
    size_t signed_len = 8 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE;

    if (qgp_dsa87_verify(signature, CRED_UDP_SIGNATURE_SIZE,
                         signed_data, signed_len, pubkey) != 0) {
        std::cerr << "[CRED-UDP] Signature verification FAILED for "
                  << std::string(fingerprint, 16) << "..." << std::endl;
        g_stats.auth_failures++;
        return -1;
    }

    // Signature valid - record nonce to prevent replay
    g_used_nonces[replay_key] = now;

    std::cout << "[CRED-UDP] ✓ Verified request from "
              << std::string(fingerprint, 16) << "..." << std::endl;

    // Generate credentials
    char username[CRED_UDP_USERNAME_SIZE];
    char password[CRED_UDP_PASSWORD_SIZE];

    // Username format: fingerprint_timestamp (truncated)
    snprintf(username, sizeof(username), "%.16s_%ld", fingerprint, (long)now);
    generate_credential(password, 32);

    // Calculate expiration
    int64_t expires_at = now + g_config.credential_ttl;

    // Add credentials to TURN server
    if (g_turn_server) {
        unsigned long ttl_ms = g_config.credential_ttl * 1000UL;
        if (!g_turn_server->add_credentials(username, password, ttl_ms)) {
            std::cerr << "[CRED-UDP] Failed to add credentials to TURN server" << std::endl;
            return -1;
        }
    }

    g_stats.credentials_issued++;
    g_stats.requests_processed++;

    std::cout << "[CRED-UDP] Issued credentials: " << username << " (expires: " << expires_at << ")" << std::endl;

    // Build response
    // [MAGIC:4][VERSION:1][TYPE:1][COUNT:1][SERVER_ENTRY...]
    size_t offset = 0;

    // Magic
    uint32_t resp_magic = CRED_UDP_MAGIC;
    memcpy(response + offset, &resp_magic, 4);
    offset += 4;

    // Version
    response[offset++] = CRED_UDP_VERSION;

    // Type
    response[offset++] = CRED_UDP_TYPE_RESPONSE;

    // Server count
    response[offset++] = 1;  // Just this server for now

    // Server entry
    // [HOST:64][PORT:2][USERNAME:128][PASSWORD:128][EXPIRES:8]
    memset(response + offset, 0, CRED_UDP_HOST_SIZE);
    strncpy((char*)(response + offset), g_config.turn_host, CRED_UDP_HOST_SIZE - 1);
    offset += CRED_UDP_HOST_SIZE;

    // Port (big-endian)
    response[offset++] = (g_config.turn_port >> 8) & 0xFF;
    response[offset++] = g_config.turn_port & 0xFF;

    // Username
    memset(response + offset, 0, CRED_UDP_USERNAME_SIZE);
    snprintf((char*)(response + offset), CRED_UDP_USERNAME_SIZE, "%s", username);
    offset += CRED_UDP_USERNAME_SIZE;

    // Password
    memset(response + offset, 0, CRED_UDP_PASSWORD_SIZE);
    snprintf((char*)(response + offset), CRED_UDP_PASSWORD_SIZE, "%s", password);
    offset += CRED_UDP_PASSWORD_SIZE;

    // Expires (big-endian)
    for (int i = 7; i >= 0; i--) {
        response[offset++] = (expires_at >> (i * 8)) & 0xFF;
    }

    *response_len = offset;
    return 0;
}

// Server thread function
static void server_thread_func() {
    std::cout << "[CRED-UDP] Server thread started on port " << g_config.port << std::endl;

    uint8_t recv_buf[8192];
    uint8_t send_buf[1024];

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // Set receive timeout (1 second) to allow clean shutdown
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(g_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        ssize_t recv_len = recvfrom(g_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                                    (struct sockaddr*)&client_addr, &client_len);

        if (recv_len <= 0) {
            // Timeout or error - check if we should continue
            continue;
        }

        // Process request
        size_t response_len = 0;
        if (process_request(recv_buf, recv_len, &client_addr, send_buf, &response_len) == 0) {
            // Send response
            sendto(g_socket, (char*)send_buf, response_len, 0,
                   (struct sockaddr*)&client_addr, client_len);
        }
    }

    std::cout << "[CRED-UDP] Server thread stopped" << std::endl;
}

extern "C" {

int cred_udp_server_start(const cred_udp_server_config_t *config) {
    if (g_running) {
        std::cerr << "[CRED-UDP] Server already running" << std::endl;
        return -1;
    }

    if (!config || !config->turn_host) {
        std::cerr << "[CRED-UDP] Invalid configuration" << std::endl;
        return -1;
    }

    // Copy config
    g_config = *config;
    if (g_config.port == 0) g_config.port = 3479;
    if (g_config.turn_port == 0) g_config.turn_port = 3478;
    if (g_config.credential_ttl == 0) g_config.credential_ttl = CRED_UDP_CREDENTIAL_TTL;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[CRED-UDP] WSAStartup failed" << std::endl;
        return -1;
    }
#endif

    // Create UDP socket
    g_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_socket == INVALID_SOCKET) {
        std::cerr << "[CRED-UDP] Failed to create socket" << std::endl;
        return -1;
    }

    // Allow address reuse
    int reuse = 1;
    setsockopt(g_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    // Bind to port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(g_config.port);

    if (bind(g_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[CRED-UDP] Failed to bind to port " << g_config.port << std::endl;
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
        return -1;
    }

    // Reset stats
    memset(&g_stats, 0, sizeof(g_stats));

    // Start server thread
    g_running = true;
    g_server_thread = std::thread(server_thread_func);

    std::cout << "[CRED-UDP] Server started on port " << g_config.port << std::endl;
    return 0;
}

void cred_udp_server_stop(void) {
    if (!g_running) return;

    g_running = false;

    if (g_server_thread.joinable()) {
        g_server_thread.join();
    }

    if (g_socket != INVALID_SOCKET) {
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    std::cout << "[CRED-UDP] Server stopped" << std::endl;
}

bool cred_udp_server_is_running(void) {
    return g_running;
}

void cred_udp_server_get_stats(cred_udp_stats_t *stats) {
    if (!stats) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    *stats = g_stats;
}

} // extern "C"
