/**
 * TURN Credential Client - Request TURN credentials from dna-nodus
 *
 * Part of DNA Messenger Phase 11: NAT Traversal
 *
 * Requests TURN credentials from dna-nodus bootstrap nodes via DHT.
 * Credentials are authenticated using Dilithium5 signatures.
 *
 * Protocol:
 * 1. Client creates signed request with nonce + timestamp
 * 2. Publishes to DHT key: SHA3-512(client_fingerprint + ":turn_request")
 * 3. Polls DHT key: SHA3-512(client_fingerprint + ":turn_credentials")
 * 4. Receives list of TURN servers with username/password
 */

#ifndef TURN_CREDENTIALS_H
#define TURN_CREDENTIALS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum TURN servers per response
#define MAX_TURN_SERVERS 4

// Credential TTL (7 days default, refreshed as needed)
#define TURN_CREDENTIAL_TTL_SECONDS 604800

// TURN server info
typedef struct {
    char host[64];
    uint16_t port;
    char username[128];
    char password[128];
    int64_t expires_at;
} turn_server_info_t;

// TURN credentials response
typedef struct {
    turn_server_info_t servers[MAX_TURN_SERVERS];
    size_t server_count;
    int64_t fetched_at;
} turn_credentials_t;

// Credential cache (global, thread-safe)
typedef struct turn_credential_cache turn_credential_cache_t;

/**
 * Initialize TURN credential client
 *
 * Must be called once at startup.
 * @return 0 on success, -1 on error
 */
int turn_credentials_init(void);

/**
 * Shutdown TURN credential client
 */
void turn_credentials_shutdown(void);

/**
 * Request TURN credentials from dna-nodus
 *
 * Signs request with node's Dilithium5 key and publishes to DHT.
 * Then polls for response.
 *
 * @param fingerprint: Client's fingerprint (128 hex chars)
 * @param pubkey: Client's Dilithium5 public key (2592 bytes)
 * @param privkey: Client's Dilithium5 private key (4896 bytes)
 * @param out: Output credentials structure
 * @param timeout_ms: Timeout in milliseconds
 * @return 0 on success, -1 on error
 */
int turn_credentials_request(
    const char *fingerprint,
    const uint8_t *pubkey,
    const uint8_t *privkey,
    turn_credentials_t *out,
    int timeout_ms
);

/**
 * Get cached TURN credentials
 *
 * Returns cached credentials if still valid (not expired).
 *
 * @param fingerprint: Client's fingerprint
 * @param out: Output credentials structure
 * @return 0 if valid credentials found, -1 if expired/not found
 */
int turn_credentials_get_cached(
    const char *fingerprint,
    turn_credentials_t *out
);

/**
 * Check if TURN credentials are needed
 *
 * Returns true if no valid cached credentials exist.
 *
 * @param fingerprint: Client's fingerprint
 * @return 1 if credentials needed, 0 if valid credentials exist
 */
int turn_credentials_needed(const char *fingerprint);

/**
 * Clear cached credentials
 *
 * @param fingerprint: Client's fingerprint (NULL to clear all)
 */
void turn_credentials_clear(const char *fingerprint);

#ifdef __cplusplus
}
#endif

#endif // TURN_CREDENTIALS_H
