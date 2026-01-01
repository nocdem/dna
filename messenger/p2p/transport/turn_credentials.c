/**
 * TURN Credential Client - Implementation
 *
 * Requests TURN credentials from dna-nodus via DHT.
 */

#include "turn_credentials.h"
#include "../../dht/core/dht_context.h"
#include "../../dht/client/dht_singleton.h"
#include "../../crypto/utils/qgp_sha3.h"
#include "../../crypto/utils/qgp_dilithium.h"
#include "../../crypto/utils/qgp_random.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
typedef int socklen_t;
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
typedef int SOCKET;
#endif

// Request format constants (must match server)
#define REQUEST_VERSION 1
#define REQUEST_TYPE_CREDENTIAL 1

// UDP protocol constants (must match turn_credential_udp.h)
#define CRED_UDP_MAGIC 0x444E4143
#define CRED_UDP_VERSION 1
#define CRED_UDP_TYPE_REQUEST 1
#define CRED_UDP_TYPE_RESPONSE 2
#define CRED_UDP_FINGERPRINT_SIZE 128
#define CRED_UDP_NONCE_SIZE 32
#define CRED_UDP_HOST_SIZE 64
#define CRED_UDP_USERNAME_SIZE 128
#define CRED_UDP_PASSWORD_SIZE 128

// Bootstrap servers for direct credential requests
#define CRED_UDP_DEFAULT_PORT 3479
static const char *bootstrap_servers[] = {
    "154.38.182.161",   // US-1
    "164.68.105.227",   // EU-1
    "164.68.116.180",   // EU-2
    NULL
};
#define REQUEST_HEADER_SIZE (1 + 1 + 8 + 32)

// Response format constants
#define RESPONSE_TYPE_CREDENTIALS 2
#define RESPONSE_SERVER_ENTRY_SIZE (64 + 2 + 128 + 128 + 8)

// Credential cache entry
typedef struct {
    char fingerprint[129];
    turn_credentials_t credentials;
    int valid;
} cache_entry_t;

// Global cache
static cache_entry_t *credential_cache = NULL;
static size_t cache_size = 0;
static size_t cache_capacity = 0;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialized = 0;

// Per-server cache entry (forward declaration for cache functions defined later)
typedef struct {
    char server_ip[64];
    turn_server_info_t credentials;
    int valid;
} server_cache_entry_t;

// Per-server cache (separate from fingerprint-based cache)
static server_cache_entry_t *server_cache = NULL;
static size_t server_cache_size = 0;
static size_t server_cache_capacity = 0;

static void init_server_cache(void) {
    if (server_cache) return;
    server_cache_capacity = 8;
    server_cache = calloc(server_cache_capacity, sizeof(server_cache_entry_t));
    server_cache_size = 0;
}

static server_cache_entry_t* find_server_cache_entry(const char *server_ip) {
    for (size_t i = 0; i < server_cache_size; i++) {
        if (server_cache[i].valid &&
            strcmp(server_cache[i].server_ip, server_ip) == 0) {
            return &server_cache[i];
        }
    }
    return NULL;
}

static server_cache_entry_t* add_server_cache_entry(const char *server_ip) {
    if (!server_cache) init_server_cache();

    // Look for existing or invalid slot
    for (size_t i = 0; i < server_cache_size; i++) {
        if (!server_cache[i].valid ||
            strcmp(server_cache[i].server_ip, server_ip) == 0) {
            server_cache[i].valid = 1;
            strncpy(server_cache[i].server_ip, server_ip, 63);
            server_cache[i].server_ip[63] = '\0';
            return &server_cache[i];
        }
    }

    // Need new slot
    if (server_cache_size >= server_cache_capacity) {
        size_t new_capacity = server_cache_capacity * 2;
        server_cache_entry_t *new_cache = realloc(server_cache,
                                                   new_capacity * sizeof(server_cache_entry_t));
        if (!new_cache) return NULL;
        memset(new_cache + server_cache_capacity, 0,
               (new_capacity - server_cache_capacity) * sizeof(server_cache_entry_t));
        server_cache = new_cache;
        server_cache_capacity = new_capacity;
    }

    server_cache_entry_t *entry = &server_cache[server_cache_size++];
    entry->valid = 1;
    strncpy(entry->server_ip, server_ip, 63);
    entry->server_ip[63] = '\0';
    return entry;
}

// =============================================================================
// Initialization
// =============================================================================

int turn_credentials_init(void) {
    pthread_mutex_lock(&cache_mutex);

    if (initialized) {
        pthread_mutex_unlock(&cache_mutex);
        return 0;
    }

    // Initial cache capacity
    cache_capacity = 16;
    credential_cache = calloc(cache_capacity, sizeof(cache_entry_t));
    if (!credential_cache) {
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    cache_size = 0;
    initialized = 1;

    pthread_mutex_unlock(&cache_mutex);

    QGP_LOG_INFO("TURN", "Client initialized");
    return 0;
}

void turn_credentials_shutdown(void) {
    pthread_mutex_lock(&cache_mutex);

    if (credential_cache) {
        free(credential_cache);
        credential_cache = NULL;
    }
    cache_size = 0;
    cache_capacity = 0;
    initialized = 0;

    pthread_mutex_unlock(&cache_mutex);

    QGP_LOG_INFO("TURN", "Client shutdown");
}

// =============================================================================
// Cache Operations
// =============================================================================

static cache_entry_t* find_cache_entry(const char *fingerprint) {
    for (size_t i = 0; i < cache_size; i++) {
        if (credential_cache[i].valid &&
            strcmp(credential_cache[i].fingerprint, fingerprint) == 0) {
            return &credential_cache[i];
        }
    }
    return NULL;
}

static cache_entry_t* add_cache_entry(const char *fingerprint) {
    // Look for existing or invalid slot
    for (size_t i = 0; i < cache_size; i++) {
        if (!credential_cache[i].valid ||
            strcmp(credential_cache[i].fingerprint, fingerprint) == 0) {
            credential_cache[i].valid = 1;
            strncpy(credential_cache[i].fingerprint, fingerprint, 128);
            credential_cache[i].fingerprint[128] = '\0';
            return &credential_cache[i];
        }
    }

    // Need new slot
    if (cache_size >= cache_capacity) {
        // Grow cache
        size_t new_capacity = cache_capacity * 2;
        cache_entry_t *new_cache = realloc(credential_cache,
                                            new_capacity * sizeof(cache_entry_t));
        if (!new_cache) {
            return NULL;
        }
        memset(new_cache + cache_capacity, 0,
               (new_capacity - cache_capacity) * sizeof(cache_entry_t));
        credential_cache = new_cache;
        cache_capacity = new_capacity;
    }

    cache_entry_t *entry = &credential_cache[cache_size++];
    entry->valid = 1;
    strncpy(entry->fingerprint, fingerprint, 128);
    entry->fingerprint[128] = '\0';
    return entry;
}

// =============================================================================
// Request/Response Protocol
// =============================================================================

static int create_credential_request(
    const char *fingerprint,
    const uint8_t *pubkey,
    const uint8_t *privkey,
    uint8_t **out_data,
    size_t *out_len)
{
    // Request format:
    // [version:1] [type:1] [timestamp:8] [nonce:32] [pubkey:2592] [signature:4627]

    size_t request_len = REQUEST_HEADER_SIZE + QGP_DSA87_PUBLICKEYBYTES + QGP_DSA87_SIGNATURE_BYTES;
    uint8_t *request = calloc(1, request_len);
    if (!request) {
        return -1;
    }

    // Version and type
    request[0] = REQUEST_VERSION;
    request[1] = REQUEST_TYPE_CREDENTIAL;

    // Timestamp
    int64_t timestamp = (int64_t)time(NULL);
    memcpy(request + 2, &timestamp, 8);

    // Random nonce (32 bytes)
    uint8_t nonce[32];
    if (qgp_randombytes(nonce, 32) != 0) {
        free(request);
        return -1;
    }
    memcpy(request + 10, nonce, 32);

    // Public key
    memcpy(request + REQUEST_HEADER_SIZE, pubkey, QGP_DSA87_PUBLICKEYBYTES);

    // Sign (header + pubkey)
    size_t signed_len = REQUEST_HEADER_SIZE + QGP_DSA87_PUBLICKEYBYTES;
    uint8_t *signature = request + REQUEST_HEADER_SIZE + QGP_DSA87_PUBLICKEYBYTES;
    size_t sig_len = QGP_DSA87_SIGNATURE_BYTES;

    if (qgp_dsa87_sign(signature, &sig_len,
                       request, signed_len, privkey) != 0) {
        free(request);
        return -1;
    }

    *out_data = request;
    *out_len = request_len;
    return 0;
}

static int parse_credential_response(
    const uint8_t *data,
    size_t len,
    turn_credentials_t *out)
{
    if (len < 3) {
        QGP_LOG_ERROR("TURN", "Response too short");
        return -1;
    }

    // Check version and type
    if (data[0] != REQUEST_VERSION || data[1] != RESPONSE_TYPE_CREDENTIALS) {
        QGP_LOG_ERROR("TURN", "Invalid response version/type");
        return -1;
    }

    // Server count
    uint8_t server_count = data[2];
    if (server_count > MAX_TURN_SERVERS) {
        server_count = MAX_TURN_SERVERS;
    }

    // Check length
    size_t expected_len = 3 + server_count * RESPONSE_SERVER_ENTRY_SIZE;
    if (len < expected_len) {
        QGP_LOG_ERROR("TURN", "Response truncated");
        return -1;
    }

    // Parse servers
    memset(out, 0, sizeof(*out));
    out->server_count = server_count;
    out->fetched_at = time(NULL);

    size_t offset = 3;
    for (size_t i = 0; i < server_count; i++) {
        turn_server_info_t *server = &out->servers[i];

        // Host (64 bytes)
        strncpy(server->host, (const char*)(data + offset), 63);
        server->host[63] = '\0';
        offset += 64;

        // Port (2 bytes)
        memcpy(&server->port, data + offset, 2);
        offset += 2;

        // Username (128 bytes)
        strncpy(server->username, (const char*)(data + offset), 127);
        server->username[127] = '\0';
        offset += 128;

        // Password (128 bytes)
        strncpy(server->password, (const char*)(data + offset), 127);
        server->password[127] = '\0';
        offset += 128;

        // Expires (8 bytes)
        memcpy(&server->expires_at, data + offset, 8);
        offset += 8;
    }

    return 0;
}

// =============================================================================
// Direct UDP Credential Request (bypasses DHT - faster and more reliable)
// =============================================================================

/**
 * Request credentials via direct UDP to bootstrap servers
 * Returns 0 on success, -1 on error
 */
static int request_credentials_udp(
    const char *fingerprint,
    const uint8_t *pubkey,
    const uint8_t *privkey,
    turn_credentials_t *out,
    int timeout_ms)
{
    QGP_LOG_INFO("TURN", "Trying direct UDP credential request...");

    // Create UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        QGP_LOG_ERROR("TURN", "Failed to create UDP socket");
        return -1;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Build request packet
    // [MAGIC:4][VERSION:1][TYPE:1][TIMESTAMP:8][FINGERPRINT:128][NONCE:32][PUBKEY:2592][SIGNATURE:4627]
    size_t request_size = 4 + 1 + 1 + 8 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE +
                          QGP_DSA87_PUBLICKEYBYTES + QGP_DSA87_SIGNATURE_BYTES;
    uint8_t *request = (uint8_t*)malloc(request_size);
    if (!request) {
        closesocket(sock);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = CRED_UDP_MAGIC;
    memcpy(request + offset, &magic, 4);
    offset += 4;

    // Version
    request[offset++] = CRED_UDP_VERSION;

    // Type
    request[offset++] = CRED_UDP_TYPE_REQUEST;

    // Timestamp (big-endian)
    uint64_t timestamp = (uint64_t)time(NULL);
    for (int i = 7; i >= 0; i--) {
        request[offset++] = (timestamp >> (i * 8)) & 0xFF;
    }

    // Fingerprint (128 chars)
    memset(request + offset, 0, CRED_UDP_FINGERPRINT_SIZE);
    strncpy((char*)(request + offset), fingerprint, CRED_UDP_FINGERPRINT_SIZE);
    offset += CRED_UDP_FINGERPRINT_SIZE;

    // Nonce (32 random bytes)
    uint8_t nonce[CRED_UDP_NONCE_SIZE];
    qgp_randombytes(nonce, CRED_UDP_NONCE_SIZE);
    memcpy(request + offset, nonce, CRED_UDP_NONCE_SIZE);
    offset += CRED_UDP_NONCE_SIZE;

    // Public key (2592 bytes) - included so server can verify signature without DHT lookup
    memcpy(request + offset, pubkey, QGP_DSA87_PUBLICKEYBYTES);
    offset += QGP_DSA87_PUBLICKEYBYTES;

    // Sign the request (timestamp + fingerprint + nonce)
    // Note: pubkey is NOT signed, only timestamp+fingerprint+nonce
    size_t sign_data_len = 8 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE;
    uint8_t *sign_data = request + 6;  // After magic, version, type
    size_t sig_len = 0;

    if (qgp_dsa87_sign(request + offset, &sig_len, sign_data, sign_data_len, privkey) != 0) {
        QGP_LOG_ERROR("TURN", "Failed to sign request");
        free(request);
        closesocket(sock);
        return -1;
    }
    offset += sig_len;

    // Try each bootstrap server
    int result = -1;
    uint8_t response[2048];

    for (int i = 0; bootstrap_servers[i] != NULL; i++) {
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(CRED_UDP_DEFAULT_PORT);

        if (inet_pton(AF_INET, bootstrap_servers[i], &server_addr.sin_addr) <= 0) {
            QGP_LOG_WARN("TURN", "Invalid server IP: %s", bootstrap_servers[i]);
            continue;
        }

        QGP_LOG_INFO("TURN", "Sending credential request to %s:%d",
                     bootstrap_servers[i], CRED_UDP_DEFAULT_PORT);

        // Send request
        ssize_t sent = sendto(sock, (char*)request, offset, 0,
                              (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (sent != (ssize_t)offset) {
            QGP_LOG_WARN("TURN", "Send failed to %s", bootstrap_servers[i]);
            continue;
        }

        // Receive response
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t recv_len = recvfrom(sock, (char*)response, sizeof(response), 0,
                                    (struct sockaddr*)&from_addr, &from_len);

        if (recv_len <= 0) {
            QGP_LOG_WARN("TURN", "No response from %s (timeout)", bootstrap_servers[i]);
            continue;
        }

        QGP_LOG_INFO("TURN", "Got %zd byte response from %s", recv_len, bootstrap_servers[i]);

        // Validate response
        if (recv_len < 7) {
            QGP_LOG_WARN("TURN", "Response too short");
            continue;
        }

        // Check magic
        uint32_t resp_magic;
        memcpy(&resp_magic, response, 4);
        if (resp_magic != CRED_UDP_MAGIC) {
            QGP_LOG_WARN("TURN", "Invalid response magic");
            continue;
        }

        // Check version and type
        if (response[4] != CRED_UDP_VERSION || response[5] != CRED_UDP_TYPE_RESPONSE) {
            QGP_LOG_WARN("TURN", "Invalid response version/type");
            continue;
        }

        // Parse servers
        uint8_t server_count = response[6];
        if (server_count == 0 || server_count > MAX_TURN_SERVERS) {
            QGP_LOG_WARN("TURN", "Invalid server count: %d", server_count);
            continue;
        }

        out->server_count = server_count;
        out->fetched_at = time(NULL);

        size_t resp_offset = 7;
        for (size_t s = 0; s < server_count && s < MAX_TURN_SERVERS; s++) {
            turn_server_info_t *srv = &out->servers[s];

            // Host (64 bytes)
            strncpy(srv->host, (const char*)(response + resp_offset), CRED_UDP_HOST_SIZE - 1);
            srv->host[CRED_UDP_HOST_SIZE - 1] = '\0';
            resp_offset += CRED_UDP_HOST_SIZE;

            // Port (2 bytes, big-endian)
            srv->port = (response[resp_offset] << 8) | response[resp_offset + 1];
            resp_offset += 2;

            // Username (128 bytes)
            strncpy(srv->username, (const char*)(response + resp_offset), CRED_UDP_USERNAME_SIZE - 1);
            srv->username[CRED_UDP_USERNAME_SIZE - 1] = '\0';
            resp_offset += CRED_UDP_USERNAME_SIZE;

            // Password (128 bytes)
            strncpy(srv->password, (const char*)(response + resp_offset), CRED_UDP_PASSWORD_SIZE - 1);
            srv->password[CRED_UDP_PASSWORD_SIZE - 1] = '\0';
            resp_offset += CRED_UDP_PASSWORD_SIZE;

            // Expires (8 bytes, big-endian)
            srv->expires_at = 0;
            for (int b = 0; b < 8; b++) {
                srv->expires_at = (srv->expires_at << 8) | response[resp_offset + b];
            }
            resp_offset += 8;

            QGP_LOG_INFO("TURN", "Server %zu: %s:%d user=%s",
                         s, srv->host, srv->port, srv->username);

            // Cache credentials for this server in per-server cache
            pthread_mutex_lock(&cache_mutex);
            server_cache_entry_t *cache_entry = add_server_cache_entry(srv->host);
            if (cache_entry) {
                memcpy(&cache_entry->credentials, srv, sizeof(*srv));
                cache_entry->valid = 1;
                QGP_LOG_DEBUG("TURN", "Cached credentials for server %s", srv->host);
            }
            pthread_mutex_unlock(&cache_mutex);
        }

        result = 0;
        break;
    }

    free(request);
    closesocket(sock);

    if (result == 0) {
        QGP_LOG_INFO("TURN", "Got %zu TURN servers via UDP", out->server_count);
    } else {
        QGP_LOG_ERROR("TURN", "All UDP servers failed");
    }

    return result;
}

// =============================================================================
// Public API
// =============================================================================

int turn_credentials_request(
    const char *fingerprint,
    const uint8_t *pubkey,
    const uint8_t *privkey,
    turn_credentials_t *out,
    int timeout_ms)
{
    if (!fingerprint || !pubkey || !privkey || !out) {
        return -1;
    }

    QGP_LOG_INFO("TURN", "Requesting credentials for %.16s...", fingerprint);

    // Try UDP first (faster, more reliable)
    int udp_timeout = timeout_ms > 0 ? timeout_ms / 2 : 3000;  // Half timeout for UDP
    if (request_credentials_udp(fingerprint, pubkey, privkey, out, udp_timeout) == 0) {
        // Cache credentials
        pthread_mutex_lock(&cache_mutex);
        cache_entry_t *entry = add_cache_entry(fingerprint);
        if (entry) {
            memcpy(&entry->credentials, out, sizeof(*out));
        }
        pthread_mutex_unlock(&cache_mutex);
        return 0;
    }

    QGP_LOG_WARN("TURN", "UDP request failed, falling back to DHT...");

    // Get DHT instance for fallback
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR("TURN", "DHT not initialized");
        return -1;
    }

    // Create signed request
    uint8_t *request_data = NULL;
    size_t request_len = 0;

    if (create_credential_request(fingerprint, pubkey, privkey,
                                  &request_data, &request_len) != 0) {
        QGP_LOG_ERROR("TURN", "Failed to create request");
        return -1;
    }

    // Create request DHT key: SHA3-512(fingerprint + ":turn_request")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:turn_request", fingerprint);

    char request_key[129];
    if (qgp_sha3_512_hex((uint8_t*)key_input, strlen(key_input),
                         request_key, sizeof(request_key)) != 0) {
        free(request_data);
        return -1;
    }

    // Publish request to DHT (short TTL, will be consumed)
    int ret = dht_put_signed(dht, (uint8_t*)request_key, strlen(request_key),
                             request_data, request_len, 1, 300);  // 5 min TTL
    free(request_data);

    if (ret != 0) {
        QGP_LOG_ERROR("TURN", "Failed to publish request to DHT");
        return -1;
    }

    QGP_LOG_DEBUG("TURN", "Request published, polling for response...");

    // Create response DHT key: SHA3-512(fingerprint + ":turn_credentials")
    snprintf(key_input, sizeof(key_input), "%s:turn_credentials", fingerprint);

    char response_key[129];
    if (qgp_sha3_512_hex((uint8_t*)key_input, strlen(key_input),
                         response_key, sizeof(response_key)) != 0) {
        return -1;
    }

    // Poll for response
    int64_t start_time = time(NULL);
    int64_t deadline = start_time + (timeout_ms / 1000);

    while (time(NULL) < deadline) {
        uint8_t *response_data = NULL;
        size_t response_len = 0;

        ret = dht_get(dht, (uint8_t*)response_key, strlen(response_key),
                      &response_data, &response_len);

        if (ret == 0 && response_data && response_len >= 3) {
            // Parse response
            if (parse_credential_response(response_data, response_len, out) == 0) {
                free(response_data);

                // Cache credentials
                pthread_mutex_lock(&cache_mutex);
                cache_entry_t *entry = add_cache_entry(fingerprint);
                if (entry) {
                    memcpy(&entry->credentials, out, sizeof(*out));
                }
                pthread_mutex_unlock(&cache_mutex);

                QGP_LOG_INFO("TURN", "Got %zu TURN servers", out->server_count);
                return 0;
            }
            free(response_data);
        }

        if (response_data) {
            free(response_data);
        }

        // Wait before next poll
        qgp_platform_sleep(1);
    }

    QGP_LOG_ERROR("TURN", "Timeout waiting for credentials");
    return -1;
}

int turn_credentials_get_cached(
    const char *fingerprint,
    turn_credentials_t *out)
{
    if (!fingerprint || !out) {
        return -1;
    }

    pthread_mutex_lock(&cache_mutex);

    cache_entry_t *entry = find_cache_entry(fingerprint);
    if (!entry) {
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    // Check if any credentials are still valid
    int64_t now = time(NULL);
    int valid = 0;

    for (size_t i = 0; i < entry->credentials.server_count; i++) {
        if (entry->credentials.servers[i].expires_at > now) {
            valid = 1;
            break;
        }
    }

    if (!valid) {
        // All expired
        entry->valid = 0;
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    memcpy(out, &entry->credentials, sizeof(*out));
    pthread_mutex_unlock(&cache_mutex);

    return 0;
}

int turn_credentials_needed(const char *fingerprint) {
    turn_credentials_t creds;
    return (turn_credentials_get_cached(fingerprint, &creds) != 0) ? 1 : 0;
}

void turn_credentials_clear(const char *fingerprint) {
    pthread_mutex_lock(&cache_mutex);

    if (!fingerprint) {
        // Clear all
        for (size_t i = 0; i < cache_size; i++) {
            credential_cache[i].valid = 0;
        }
    } else {
        // Clear specific
        cache_entry_t *entry = find_cache_entry(fingerprint);
        if (entry) {
            entry->valid = 0;
        }
    }

    pthread_mutex_unlock(&cache_mutex);
}

int turn_credentials_request_from_server(
    const char *server_ip,
    uint16_t server_port,
    const char *fingerprint,
    const uint8_t *pubkey,
    const uint8_t *privkey,
    turn_server_info_t *out,
    int timeout_ms)
{
    if (!server_ip || !fingerprint || !pubkey || !privkey || !out) {
        return -1;
    }

    QGP_LOG_INFO("TURN", "Requesting credentials from %s:%d", server_ip, server_port);

    // Create UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        QGP_LOG_ERROR("TURN", "Failed to create UDP socket");
        return -1;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Build request packet
    size_t request_size = 4 + 1 + 1 + 8 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE +
                          QGP_DSA87_PUBLICKEYBYTES + QGP_DSA87_SIGNATURE_BYTES;
    uint8_t *request = (uint8_t*)malloc(request_size);
    if (!request) {
        closesocket(sock);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = CRED_UDP_MAGIC;
    memcpy(request + offset, &magic, 4);
    offset += 4;

    // Version
    request[offset++] = CRED_UDP_VERSION;

    // Type
    request[offset++] = CRED_UDP_TYPE_REQUEST;

    // Timestamp (big-endian)
    uint64_t timestamp = (uint64_t)time(NULL);
    for (int i = 7; i >= 0; i--) {
        request[offset++] = (timestamp >> (i * 8)) & 0xFF;
    }

    // Fingerprint
    memset(request + offset, 0, CRED_UDP_FINGERPRINT_SIZE);
    strncpy((char*)(request + offset), fingerprint, CRED_UDP_FINGERPRINT_SIZE);
    offset += CRED_UDP_FINGERPRINT_SIZE;

    // Nonce
    uint8_t nonce[CRED_UDP_NONCE_SIZE];
    qgp_randombytes(nonce, CRED_UDP_NONCE_SIZE);
    memcpy(request + offset, nonce, CRED_UDP_NONCE_SIZE);
    offset += CRED_UDP_NONCE_SIZE;

    // Public key
    memcpy(request + offset, pubkey, QGP_DSA87_PUBLICKEYBYTES);
    offset += QGP_DSA87_PUBLICKEYBYTES;

    // Sign (timestamp + fingerprint + nonce)
    size_t sign_data_len = 8 + CRED_UDP_FINGERPRINT_SIZE + CRED_UDP_NONCE_SIZE;
    uint8_t *sign_data = request + 6;
    size_t sig_len = 0;

    if (qgp_dsa87_sign(request + offset, &sig_len, sign_data, sign_data_len, privkey) != 0) {
        QGP_LOG_ERROR("TURN", "Failed to sign request");
        free(request);
        closesocket(sock);
        return -1;
    }
    offset += sig_len;

    // Send to specific server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        QGP_LOG_ERROR("TURN", "Invalid server IP: %s", server_ip);
        free(request);
        closesocket(sock);
        return -1;
    }

    QGP_LOG_WARN("TURN", ">>> Sending %zu bytes to %s:%d (socket=%d)", offset, server_ip, server_port, (int)sock);

    ssize_t sent = sendto(sock, (char*)request, offset, 0,
                          (struct sockaddr*)&server_addr, sizeof(server_addr));
    free(request);

    if (sent != (ssize_t)offset) {
        QGP_LOG_ERROR("TURN", "Send failed to %s (sent=%zd, errno=%d)", server_ip, sent, errno);
        closesocket(sock);
        return -1;
    }

    QGP_LOG_WARN("TURN", ">>> Sent %zd bytes, waiting for response (timeout=%dms)...", sent, timeout_ms);

    // Receive response
    uint8_t response[2048];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t recv_len = recvfrom(sock, (char*)response, sizeof(response), 0,
                                (struct sockaddr*)&from_addr, &from_len);
    closesocket(sock);

    if (recv_len <= 0) {
        QGP_LOG_ERROR("TURN", "No response from %s (timeout)", server_ip);
        return -1;
    }

    // Validate response
    if (recv_len < 7) {
        QGP_LOG_ERROR("TURN", "Response too short from %s", server_ip);
        return -1;
    }

    // Check magic
    uint32_t resp_magic;
    memcpy(&resp_magic, response, 4);
    if (resp_magic != CRED_UDP_MAGIC) {
        QGP_LOG_ERROR("TURN", "Invalid response magic from %s", server_ip);
        return -1;
    }

    // Check version and type
    if (response[4] != CRED_UDP_VERSION || response[5] != CRED_UDP_TYPE_RESPONSE) {
        QGP_LOG_ERROR("TURN", "Invalid response type from %s", server_ip);
        return -1;
    }

    // Parse first server entry (we requested from this specific server)
    uint8_t server_count = response[6];
    if (server_count == 0) {
        QGP_LOG_ERROR("TURN", "No servers in response from %s", server_ip);
        return -1;
    }

    size_t resp_offset = 7;

    // Host
    strncpy(out->host, (const char*)(response + resp_offset), CRED_UDP_HOST_SIZE - 1);
    out->host[CRED_UDP_HOST_SIZE - 1] = '\0';
    resp_offset += CRED_UDP_HOST_SIZE;

    // Port (big-endian)
    out->port = (response[resp_offset] << 8) | response[resp_offset + 1];
    resp_offset += 2;

    // Username
    strncpy(out->username, (const char*)(response + resp_offset), CRED_UDP_USERNAME_SIZE - 1);
    out->username[CRED_UDP_USERNAME_SIZE - 1] = '\0';
    resp_offset += CRED_UDP_USERNAME_SIZE;

    // Password
    strncpy(out->password, (const char*)(response + resp_offset), CRED_UDP_PASSWORD_SIZE - 1);
    out->password[CRED_UDP_PASSWORD_SIZE - 1] = '\0';
    resp_offset += CRED_UDP_PASSWORD_SIZE;

    // Expires (big-endian)
    out->expires_at = 0;
    for (int b = 0; b < 8; b++) {
        out->expires_at = (out->expires_at << 8) | response[resp_offset + b];
    }

    // Cache the credentials
    pthread_mutex_lock(&cache_mutex);
    server_cache_entry_t *entry = add_server_cache_entry(server_ip);
    if (entry) {
        memcpy(&entry->credentials, out, sizeof(*out));
    }
    pthread_mutex_unlock(&cache_mutex);

    QGP_LOG_INFO("TURN", "✓ Got credentials from %s (user=%s)", server_ip, out->username);
    return 0;
}

int turn_credentials_get_for_server(
    const char *server_ip,
    turn_server_info_t *out)
{
    if (!server_ip || !out) {
        return -1;
    }

    pthread_mutex_lock(&cache_mutex);

    server_cache_entry_t *entry = find_server_cache_entry(server_ip);
    if (!entry) {
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    // Check if credentials are still valid
    int64_t now = time(NULL);
    if (entry->credentials.expires_at <= now) {
        entry->valid = 0;
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    memcpy(out, &entry->credentials, sizeof(*out));
    pthread_mutex_unlock(&cache_mutex);

    return 0;
}

int turn_credentials_get_server_list(
    const char **servers,
    int max_servers)
{
    if (!servers || max_servers <= 0) {
        return 0;
    }

    int count = 0;
    for (int i = 0; bootstrap_servers[i] != NULL && count < max_servers; i++) {
        servers[count++] = bootstrap_servers[i];
    }
    return count;
}
