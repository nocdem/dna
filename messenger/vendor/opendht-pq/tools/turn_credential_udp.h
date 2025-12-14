/**
 * TURN Credential UDP Server
 *
 * Handles direct UDP requests for TURN credentials on port 3479.
 * This bypasses DHT for credential requests - faster and more reliable.
 *
 * Protocol:
 * - Client sends signed request to dna-nodus:3479
 * - Server verifies signature, generates credentials
 * - Server responds with TURN server list + credentials
 */

#ifndef TURN_CREDENTIAL_UDP_H
#define TURN_CREDENTIAL_UDP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic header for credential packets: "DNAC" (DNA Credentials)
#define CRED_UDP_MAGIC 0x444E4143

// Protocol version
#define CRED_UDP_VERSION 1

// Packet types
#define CRED_UDP_TYPE_REQUEST  1
#define CRED_UDP_TYPE_RESPONSE 2
#define CRED_UDP_TYPE_ERROR    3

// Sizes
#define CRED_UDP_FINGERPRINT_SIZE 128
#define CRED_UDP_NONCE_SIZE 32
#define CRED_UDP_SIGNATURE_SIZE 4627  // Dilithium5 signature
#define CRED_UDP_HOST_SIZE 64
#define CRED_UDP_USERNAME_SIZE 128
#define CRED_UDP_PASSWORD_SIZE 128

// Request packet structure (after magic)
// [VERSION:1][TYPE:1][TIMESTAMP:8][FINGERPRINT:128][NONCE:32][SIGNATURE:4627]
#define CRED_UDP_REQUEST_SIZE (1 + 1 + 8 + 128 + 32 + 4627)

// Server entry in response
// [HOST:64][PORT:2][USERNAME:128][PASSWORD:128][EXPIRES:8]
#define CRED_UDP_SERVER_ENTRY_SIZE (64 + 2 + 128 + 128 + 8)

// Response header (after magic)
// [VERSION:1][TYPE:2][COUNT:1][SERVERS...]
#define CRED_UDP_RESPONSE_HEADER_SIZE (1 + 1 + 1)

// Max servers per response
#define CRED_UDP_MAX_SERVERS 4

// Timestamp tolerance (5 minutes)
#define CRED_UDP_TIMESTAMP_TOLERANCE 300

// Credential TTL (7 days)
#define CRED_UDP_CREDENTIAL_TTL 604800

/**
 * TURN credential UDP server configuration
 */
typedef struct {
    uint16_t port;              // UDP listen port (default: 3479)
    const char *turn_host;      // TURN server hostname/IP
    uint16_t turn_port;         // TURN server port (default: 3478)
    uint32_t credential_ttl;    // Credential TTL in seconds
} cred_udp_server_config_t;

/**
 * Set the TURN server reference for adding credentials
 *
 * @param turn: Pointer to TurnServer instance (cast to void*)
 */
void cred_udp_set_turn_server(void *turn);

/**
 * Initialize and start the credential UDP server
 *
 * @param config: Server configuration
 * @return 0 on success, -1 on error
 */
int cred_udp_server_start(const cred_udp_server_config_t *config);

/**
 * Stop the credential UDP server
 */
void cred_udp_server_stop(void);

/**
 * Check if server is running
 */
bool cred_udp_server_is_running(void);

/**
 * Get server statistics
 */
typedef struct {
    uint64_t requests_received;
    uint64_t requests_processed;
    uint64_t credentials_issued;
    uint64_t auth_failures;
    uint64_t invalid_packets;
} cred_udp_stats_t;

void cred_udp_server_get_stats(cred_udp_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif // TURN_CREDENTIAL_UDP_H
