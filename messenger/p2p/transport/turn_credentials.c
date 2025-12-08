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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Request format constants (must match server)
#define REQUEST_VERSION 1
#define REQUEST_TYPE_CREDENTIAL 1
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

    // Get DHT instance
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR("TURN", "DHT not initialized");
        return -1;
    }

    QGP_LOG_DEBUG("TURN", "Requesting credentials for %.16s...", fingerprint);

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
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
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
