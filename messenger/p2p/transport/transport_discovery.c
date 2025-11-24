/**
 * P2P Transport Discovery Module
 * DHT-based peer discovery (presence registration and peer lookup)
 */

#include "transport_core.h"
#include "transport_ice.h"  // Phase 11: ICE NAT traversal

/**
 * Register presence in DHT
 * Publishes IP:port information for peer discovery
 *
 * Phase 11 FIX: ICE candidates now published by persistent ICE context
 * (no longer done here - see ice_init_persistent() in p2p_transport_start)
 *
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int p2p_register_presence(p2p_transport_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Get external IP
    char my_ip[64];
    if (get_external_ip(my_ip, sizeof(my_ip)) != 0) {
        printf("[P2P] Failed to get external IP\n");
        return -1;
    }

    // Create presence JSON
    char presence_data[512];
    if (create_presence_json(my_ip, ctx->config.listen_port,
                            presence_data, sizeof(presence_data)) != 0) {
        printf("[P2P] Failed to create presence JSON\n");
        return -1;
    }

    // Compute DHT key: SHA3-512(public_key)
    uint8_t dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(ctx->my_public_key, 2592, dht_key);  // Dilithium5 public key size

    printf("[P2P] Registering presence in DHT\n");
    printf("[P2P] DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);
    printf("[P2P] Presence data: %s\n", presence_data);

    // Store in DHT (signed, 7-day TTL, value_id=1 for replacement)
    // Presence data is ephemeral and refreshed regularly
    unsigned int ttl_7days = 7 * 24 * 3600;  // 604800 seconds
    int result = dht_put_signed(ctx->dht, dht_key, sizeof(dht_key),
                                (const uint8_t*)presence_data, strlen(presence_data),
                                1, ttl_7days);

    if (result == 0) {
        printf("[P2P] Presence registered successfully (signed)\n");
    } else {
        printf("[P2P] Failed to register presence in DHT\n");
        return result;
    }

    // Phase 11 FIX: ICE candidates are now published by ice_init_persistent()
    // during p2p_transport_start(), not here. This prevents Bug #2
    // (destroying ICE context after publishing candidates).

    if (ctx->ice_ready) {
        printf("[P2P] ✓ Presence and ICE candidates both registered (ICE ready for NAT traversal)\n");
    } else {
        printf("[P2P] ✓ Presence registered (ICE unavailable, TCP-only mode)\n");
    }

    return 0;
}

/**
 * Lookup peer in DHT
 * Retrieves IP:port information for peer connection
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's Dilithium5 public key (2592 bytes)
 * @param peer_info: Output peer information structure
 * @return: 0 on success, -1 on error
 */
int p2p_lookup_peer(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    peer_info_t *peer_info)
{
    if (!ctx || !peer_pubkey || !peer_info) {
        return -1;
    }

    // Compute DHT key: SHA3-512(peer_pubkey)
    uint8_t dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(peer_pubkey, 2592, dht_key);  // Dilithium5 public key size

    printf("[P2P] Looking up peer in DHT\n");
    printf("[P2P] DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);

    // Query DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(ctx->dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
        printf("[P2P] Peer not found in DHT\n");
        return -1;
    }

    printf("[P2P] Found peer data: %.*s\n", (int)value_len, value);

    // Parse JSON
    if (parse_presence_json((const char*)value, peer_info) != 0) {
        printf("[P2P] Failed to parse peer presence JSON\n");
        free(value);
        return -1;
    }

    // Copy public key
    memcpy(peer_info->public_key, peer_pubkey, 2592);  // Dilithium5 public key size

    // Check if peer is online (last seen < 10 minutes)
    time_t now = time(NULL);
    peer_info->is_online = (now - (time_t)peer_info->last_seen) < 600;

    free(value);

    printf("[P2P] Peer lookup successful: %s:%d (online: %s)\n",
           peer_info->ip, peer_info->port,
           peer_info->is_online ? "yes" : "no");

    return 0;
}

/**
 * Send message to peer with 3-tier fallback (Phase 11 FIX: Connection Reuse)
 *
 * Tier 1: LAN DHT lookup + Direct TCP connection
 * Tier 2: ICE NAT traversal (PERSISTENT, REUSED connections)
 * Tier 3: DHT offline queue (handled by caller)
 *
 * FIXES:
 * - Bug #1: ICE connections now reused (not created per-message)
 * - Bug #3: ICE connections cached in connections[] array
 * - Bug #4: Bidirectional communication via receive threads
 *
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's Dilithium5 public key (2592 bytes)
 * @param message: Encrypted message data
 * @param message_len: Message length
 * @return: 0 on success (ACK received), -1 on error (triggers DHT queue fallback)
 */
int p2p_send_message(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const uint8_t *message,
    size_t message_len)
{
    if (!ctx || !peer_pubkey || !message || message_len == 0) {
        fprintf(stderr, "[P2P] Invalid parameters\n");
        return -1;
    }

    // ========================================================================
    // TIER 1: LAN DHT Lookup + Direct TCP Connection
    // ========================================================================

    printf("[P2P] [TIER 1] Attempting direct connection via LAN DHT...\n");

    // Step 1: Look up peer in DHT
    peer_info_t peer_info;
    int tier1_lookup_success = (p2p_lookup_peer(ctx, peer_pubkey, &peer_info) == 0);

    if (tier1_lookup_success && peer_info.is_online) {
        printf("[P2P] [TIER 1] Peer found with IPs: %s (port %d)\n",
               peer_info.ip, peer_info.port);

        // Step 2: Try ALL peer IPs (comma-separated) until one works
        char ips_copy[64];
        snprintf(ips_copy, sizeof(ips_copy), "%s", peer_info.ip);

        char *ip_token = strtok(ips_copy, ",");
        while (ip_token) {
            // Trim whitespace
            while (*ip_token == ' ') ip_token++;

            printf("[P2P] [TIER 1] Trying IP: %s:%d...\n", ip_token, peer_info.port);

            int sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd >= 0) {
                // Set connection timeout (1 second per IP - faster fallback)
                struct timeval timeout;
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
#ifdef _WIN32
                DWORD timeout_ms = 1000;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif

                struct sockaddr_in peer_addr;
                memset(&peer_addr, 0, sizeof(peer_addr));
                peer_addr.sin_family = AF_INET;
                peer_addr.sin_port = htons(peer_info.port);

                if (inet_pton(AF_INET, ip_token, &peer_addr.sin_addr) > 0) {
                    if (connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == 0) {
                        printf("[P2P] [TIER 1] ✓ TCP connected to %s:%d\n", ip_token, peer_info.port);

                        // Step 3: Send message (format: [4-byte length][message data])
                        uint32_t msg_len_network = htonl((uint32_t)message_len);

                        // Send length header
                        ssize_t sent = send(sockfd, (char*)&msg_len_network, sizeof(msg_len_network), 0);
                        if (sent == sizeof(msg_len_network)) {
                            // Send message data
                            size_t total_sent = 0;
                            int send_error = 0;
                            while (total_sent < message_len && !send_error) {
                                sent = send(sockfd, (char*)message + total_sent, message_len - total_sent, 0);
                                if (sent <= 0) {
                                    send_error = 1;
                                } else {
                                    total_sent += sent;
                                }
                            }

                            if (!send_error) {
                                printf("[P2P] [TIER 1] ✓ Sent %zu bytes\n", message_len);

                                // Step 4: Wait for ACK
                                uint8_t ack;
                                ssize_t ack_received = recv(sockfd, (char*)&ack, 1, 0);

                                if (ack_received == 1 && ack == 0x01) {
                                    printf("[P2P] [TIER 1] ✓✓ SUCCESS - ACK received from %s!\n", ip_token);
                                    close(sockfd);
                                    return 0;  // SUCCESS - Tier 1 worked!
                                }
                            }
                        }

                        close(sockfd);
                    } else {
                        printf("[P2P] [TIER 1] Connection to %s:%d failed\n", ip_token, peer_info.port);
                        close(sockfd);
                    }
                } else {
                    printf("[P2P] [TIER 1] Invalid IP: %s\n", ip_token);
                    close(sockfd);
                }
            }

            // Try next IP
            ip_token = strtok(NULL, ",");
        }
    }

    printf("[P2P] [TIER 1] Failed - peer unreachable via direct TCP\n");

    // ========================================================================
    // TIER 2: ICE NAT Traversal (PERSISTENT - Phase 11 FIX)
    // ========================================================================

    // FIX: Check if ICE is available first
    if (!ctx->ice_ready) {
        printf("[P2P] [TIER 2] ICE unavailable (initialization failed or disabled)\n");
        goto tier3_fallback;
    }

    printf("[P2P] [TIER 2] Attempting ICE NAT traversal (persistent connections)...\n");

    // Compute peer fingerprint (hex string) from public key hash
    uint8_t peer_dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(peer_pubkey, 2592, peer_dht_key);  // Dilithium5 public key size

    char peer_fingerprint_hex[129];  // SHA3-512 = 64 bytes * 2 hex chars + null
    for (int i = 0; i < 64; i++) {
        snprintf(peer_fingerprint_hex + (i * 2), 3, "%02x", peer_dht_key[i]);
    }
    peer_fingerprint_hex[128] = '\0';

    // FIX: Find or create ICE connection (reuse existing, Bug #1 #3)
    p2p_connection_t *ice_conn = ice_get_or_create_connection(ctx, peer_pubkey, peer_fingerprint_hex);
    if (!ice_conn) {
        printf("[P2P] [TIER 2] Failed to establish ICE connection\n");
        goto tier3_fallback;
    }

    printf("[P2P] [TIER 2] ✓ Using ICE connection to peer %.32s...\n", peer_fingerprint_hex);

    // FIX: Send via existing ICE connection (Bug #1 - no more per-message context creation)
    int ice_sent = ice_send(ice_conn->ice_ctx, message, message_len);
    if (ice_sent > 0) {
        printf("[P2P] [TIER 2] ✓✓ SUCCESS - Sent %d bytes via ICE (connection cached)!\n", ice_sent);
        return 0;  // SUCCESS - Tier 2 worked!
    }

    printf("[P2P] [TIER 2] Failed to send message via ICE\n");

    // ========================================================================
    // TIER 3: DHT Offline Queue (handled by caller - messenger_p2p.c)
    // ========================================================================

tier3_fallback:
    printf("[P2P] [TIER 3] Both direct and ICE failed - falling back to DHT offline queue\n");
    return -1;  // Caller (messenger_p2p.c) will queue to DHT offline storage
}
