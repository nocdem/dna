#ifndef TRANSPORT_ICE_H
#define TRANSPORT_ICE_H

/**
 * transport_ice.h - ICE (Interactive Connectivity Establishment) Transport
 *
 * Provides NAT traversal using libnice (STUN+ICE, no TURN for decentralization)
 *
 * Part of Phase 11: Decentralized NAT Traversal
 * - Uses public STUN servers (stun.l.google.com, stun.cloudflare.com)
 * - DHT-based candidate exchange (no signaling servers)
 * - 3-tier fallback: LAN DHT → ICE → DHT queue
 *
 * Success rate: ~85-90% direct connection
 * Fallback: DHT offline queue (7-day TTL)
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct ice_context ice_context_t;

/**
 * Initialize ICE context
 *
 * Creates a new NiceAgent with:
 * - RFC5245 compatibility (full ICE)
 * - STUN-only mode (no TURN relays)
 * - glib main loop in separate thread
 *
 * @return New ICE context, or NULL on error
 */
ice_context_t* ice_context_new(void);

/**
 * Free ICE context
 *
 * Stops glib main loop, destroys NiceAgent, frees memory
 *
 * @param ctx ICE context to free
 */
void ice_context_free(ice_context_t *ctx);

/**
 * Gather local ICE candidates
 *
 * Performs STUN binding requests to discover:
 * - Host candidates (local interfaces)
 * - Server-reflexive candidates (external IP via STUN)
 *
 * Blocks until gathering completes (max 5 seconds)
 *
 * @param ctx ICE context
 * @param stun_server STUN server hostname (e.g., "stun.l.google.com")
 * @param stun_port STUN server port (typically 19302 or 3478)
 * @return 0 on success, -1 on error
 */
int ice_gather_candidates(ice_context_t *ctx, const char *stun_server, uint16_t stun_port);

/**
 * Publish local candidates to DHT
 *
 * DHT key: SHA3-512(fingerprint + ":ice_candidates") - PHASE 4 FIX
 * Value: SDP-formatted candidate strings (newline-separated)
 * TTL: 7 days
 *
 * @param ctx ICE context
 * @param my_fingerprint Local identity fingerprint
 * @return 0 on success, -1 on error
 */
int ice_publish_to_dht(ice_context_t *ctx, const char *my_fingerprint);

/**
 * Fetch remote candidates from DHT
 *
 * DHT key: SHA3-512(peer_fingerprint + ":ice_candidates") - PHASE 4 FIX
 * Stores candidates internally for later connection
 *
 * @param ctx ICE context
 * @param peer_fingerprint Peer identity fingerprint
 * @return 0 on success, -1 on error (peer not found or no candidates)
 */
int ice_fetch_from_dht(ice_context_t *ctx, const char *peer_fingerprint);

/**
 * Start ICE connectivity checks
 *
 * Performs:
 * - Parse remote candidates from DHT
 * - Add to NiceAgent
 * - Start STUN connectivity checks
 * - Wait for CONNECTED or READY state
 *
 * Blocks until connection succeeds or times out (max 10 seconds)
 *
 * @param ctx ICE context
 * @return 0 on success (connected), -1 on error or timeout
 */
int ice_connect(ice_context_t *ctx);

/**
 * Send data over ICE connection
 *
 * Uses nice_agent_send() for reliable UDP transport
 *
 * @param ctx ICE context
 * @param data Data buffer to send
 * @param len Length of data
 * @return Number of bytes sent, or -1 on error
 */
int ice_send(ice_context_t *ctx, const uint8_t *data, size_t len);

/**
 * Receive data from ICE connection with timeout (PHASE 2 FIX)
 *
 * Blocks until data is available or timeout expires.
 * Uses GCond for efficient waiting (no busy-wait polling).
 *
 * Message queue implementation (PHASE 1 FIX):
 * - Up to 16 messages buffered
 * - Oldest message dropped if queue full
 * - Thread-safe with GMutex
 *
 * @param ctx ICE context
 * @param buf Buffer to store received data
 * @param buflen Buffer size
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking, -1 = infinite)
 * @return Number of bytes received, 0 on timeout/no data, -1 on error
 */
int ice_recv_timeout(ice_context_t *ctx, uint8_t *buf, size_t buflen, int timeout_ms);

/**
 * Receive data from ICE connection (non-blocking)
 *
 * Wrapper for ice_recv_timeout() with 0 timeout.
 * Returns immediately if no data is available.
 *
 * @param ctx ICE context
 * @param buf Buffer to store received data
 * @param buflen Buffer size
 * @return Number of bytes received, 0 if no data, -1 on error
 */
int ice_recv(ice_context_t *ctx, uint8_t *buf, size_t buflen);

/**
 * Check if ICE connection is established
 *
 * @param ctx ICE context
 * @return 1 if connected, 0 if not
 */
int ice_is_connected(ice_context_t *ctx);

/**
 * Shutdown ICE connection
 *
 * Stops connectivity checks, closes streams
 * Does not free context (use ice_context_free for that)
 *
 * @param ctx ICE context
 */
void ice_shutdown(ice_context_t *ctx);

/**
 * Get local candidates as string
 *
 * Returns SDP-formatted candidates (newline-separated)
 * Useful for debugging
 *
 * @param ctx ICE context
 * @return Candidate string (internal buffer, do not free), or NULL
 */
const char* ice_get_local_candidates(ice_context_t *ctx);

/**
 * Get remote candidates as string
 *
 * Returns SDP-formatted candidates received from DHT
 *
 * @param ctx ICE context
 * @return Candidate string (internal buffer, do not free), or NULL
 */
const char* ice_get_remote_candidates(ice_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // TRANSPORT_ICE_H
