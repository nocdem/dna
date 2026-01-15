/**
 * Transport Core - Shared types and internal APIs
 * Used by all transport modules
 */

#ifndef TRANSPORT_CORE_H
#define TRANSPORT_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #endif

    #define sleep(x) Sleep((x)*1000)

    #include <pthread.h>
#else
    #include <unistd.h>
    #include <pthread.h>
#endif

// External dependencies
#include "transport.h"
#include "dht_context.h"
#include "dht_offline_queue.h"
#include "dht_singleton.h"
#include "../database/contacts_db.h"
#include "../crypto/utils/qgp_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Transport Context (internal)
 * Main structure for transport layer - DHT-only messaging
 */
struct transport {
    // Configuration
    transport_config_t config;

    // My cryptographic keys (NIST Category 5: ML-DSA-87 + ML-KEM-1024)
    uint8_t my_private_key[4896];       // Dilithium5 private key (ML-DSA-87)
    uint8_t my_public_key[2592];        // Dilithium5 public key (ML-DSA-87)
    uint8_t my_kyber_key[3168];         // Kyber1024 private key (ML-KEM-1024)
    char my_fingerprint[129];           // My fingerprint (SHA3-512 hex)

    // State
    bool running;                       // Transport is running

    // Callbacks (protected by callback_mutex to prevent TOCTOU race conditions)
    pthread_mutex_t callback_mutex;
    transport_message_callback_t message_callback;
    void *callback_user_data;

    // Statistics
    size_t messages_sent;
    size_t messages_received;
    size_t offline_queued;
};

// ===== HELPER FUNCTIONS (internal use by transport modules) =====

/**
 * Compute SHA3-512 hash
 * @param data: Input data
 * @param len: Length of data
 * @param hash_out: Output hash (64 bytes)
 */
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

/**
 * Create presence JSON for DHT registration (timestamp only - privacy)
 * @param json_out: Output JSON string buffer
 * @param len: Buffer length
 * @return: 0 on success, -1 on failure
 */
int create_presence_json(char *json_out, size_t len);

/**
 * Parse presence JSON from DHT (timestamp only)
 * @param json_str: JSON string
 * @param last_seen_out: Output timestamp
 * @return: 0 on success, -1 on failure
 */
int parse_presence_json(const char *json_str, uint64_t *last_seen_out);

#ifdef __cplusplus
}
#endif

#endif // TRANSPORT_CORE_H
