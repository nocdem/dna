/**
 * P2P Transport Discovery Module
 * DHT-based peer discovery (presence registration and peer lookup)
 */

#include "transport_core.h"
#include "transport_ice.h"  // Phase 11: ICE NAT traversal
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "P2P_DISC"

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

    // Get public IP via STUN (NAT-mapped address)
    // Only use STUN result - local IPs are useless for remote peers
    char my_ip[64] = {0};
    if (stun_get_public_ip(my_ip, sizeof(my_ip)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "STUN query failed - cannot register presence without public IP\n");
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "STUN discovered public IP: %s\n", my_ip);

    // Create presence JSON
    char presence_data[512];
    if (create_presence_json(my_ip, ctx->config.listen_port,
                            presence_data, sizeof(presence_data)) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Failed to create presence JSON\n");
        return -1;
    }

    // Compute DHT key: SHA3-512(public_key)
    uint8_t dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(ctx->my_public_key, 2592, dht_key);  // Dilithium5 public key size

    QGP_LOG_INFO(LOG_TAG, "Registering presence in DHT\n");
    QGP_LOG_INFO(LOG_TAG, "DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);
    QGP_LOG_INFO(LOG_TAG, "Presence data: %s\n", presence_data);

    // Store in DHT (signed, 7-day TTL, value_id=1 for replacement)
    // Presence data is ephemeral and refreshed regularly
    unsigned int ttl_7days = 7 * 24 * 3600;  // 604800 seconds
    int result = dht_put_signed(ctx->dht, dht_key, sizeof(dht_key),
                                (const uint8_t*)presence_data, strlen(presence_data),
                                1, ttl_7days);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Presence registered successfully (signed)\n");
    } else {
        QGP_LOG_INFO(LOG_TAG, "Failed to register presence in DHT\n");
        return result;
    }

    // Phase 11 FIX: ICE candidates are now published by ice_init_persistent()
    // during p2p_transport_start(), not here. This prevents Bug #2
    // (destroying ICE context after publishing candidates).

    if (ctx->ice_ready) {
        QGP_LOG_INFO(LOG_TAG, "✓ Presence and ICE candidates both registered (ICE ready for NAT traversal)\n");
    } else {
        QGP_LOG_INFO(LOG_TAG, "✓ Presence registered (ICE unavailable, TCP-only mode)\n");
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

    QGP_LOG_INFO(LOG_TAG, "Looking up peer in DHT\n");
    QGP_LOG_INFO(LOG_TAG, "DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);

    // Query DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(ctx->dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
        QGP_LOG_INFO(LOG_TAG, "Peer not found in DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Found peer data: %.*s\n", (int)value_len, value);

    // Parse JSON
    if (parse_presence_json((const char*)value, peer_info) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Failed to parse peer presence JSON\n");
        free(value);
        return -1;
    }

    // Copy public key
    memcpy(peer_info->public_key, peer_pubkey, 2592);  // Dilithium5 public key size

    // Check if peer is online (last seen < 10 minutes)
    time_t now = time(NULL);
    peer_info->is_online = (now - (time_t)peer_info->last_seen) < 600;

    free(value);

    QGP_LOG_INFO(LOG_TAG, "Peer lookup successful: %s:%d (online: %s)\n",
           peer_info->ip, peer_info->port,
           peer_info->is_online ? "yes" : "no");

    return 0;
}

/**
 * Lookup peer presence by fingerprint
 * Queries DHT directly using fingerprint (no public key needed)
 * Returns timestamp when peer last registered presence
 *
 * @param ctx: P2P transport context
 * @param fingerprint: Peer's fingerprint (128 hex chars)
 * @param last_seen_out: Output timestamp (0 if not found)
 * @return: 0 on success, -1 on error/not found
 */
int p2p_lookup_presence_by_fingerprint(
    p2p_transport_t *ctx,
    const char *fingerprint,
    uint64_t *last_seen_out)
{
    if (!ctx || !fingerprint || !last_seen_out) {
        return -1;
    }

    *last_seen_out = 0;

    // Validate fingerprint length (128 hex chars)
    size_t fp_len = strlen(fingerprint);
    if (fp_len != 128) {
        QGP_LOG_INFO(LOG_TAG, "Invalid fingerprint length: %zu (expected 128)\n", fp_len);
        return -1;
    }

    // Convert hex fingerprint to binary DHT key (64 bytes)
    uint8_t dht_key[64];
    for (int i = 0; i < 64; i++) {
        unsigned int byte;
        if (sscanf(fingerprint + (i * 2), "%02x", &byte) != 1) {
            QGP_LOG_INFO(LOG_TAG, "Invalid fingerprint hex at position %d\n", i * 2);
            return -1;
        }
        dht_key[i] = (uint8_t)byte;
    }

    QGP_LOG_INFO(LOG_TAG, "Looking up presence for fingerprint: %.16s...\n", fingerprint);

    // Query DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(ctx->dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
        QGP_LOG_INFO(LOG_TAG, "Presence not found in DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Found presence data: %.*s\n", (int)value_len, value);

    // Parse JSON to extract timestamp
    peer_info_t peer_info;
    memset(&peer_info, 0, sizeof(peer_info));

    if (parse_presence_json((const char*)value, &peer_info) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Failed to parse presence JSON\n");
        free(value);
        return -1;
    }

    *last_seen_out = peer_info.last_seen;
    free(value);

    QGP_LOG_INFO(LOG_TAG, "Presence lookup successful: last_seen=%lu\n",
           (unsigned long)*last_seen_out);

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
    QGP_LOG_WARN(LOG_TAG, ">>> ENTERED p2p_send_message (ctx=%p, msg_len=%zu)\n", (void*)ctx, message_len);

    if (!ctx || !peer_pubkey || !message || message_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // ========================================================================
    // TIER 1: LAN DHT Lookup + Direct TCP Connection
    // ========================================================================

    QGP_LOG_WARN(LOG_TAG, "[TIER 1] Attempting direct connection via LAN DHT...\n");

    // Step 1: Look up peer in DHT
    peer_info_t peer_info;
    int tier1_lookup_success = (p2p_lookup_peer(ctx, peer_pubkey, &peer_info) == 0);

    if (tier1_lookup_success && peer_info.is_online) {
        QGP_LOG_INFO(LOG_TAG, "[TIER 1] Peer found with IPs: %s (port %d)\n",
               peer_info.ip, peer_info.port);

        // Step 2: Try ALL peer IPs (comma-separated) until one works
        char ips_copy[64];
        snprintf(ips_copy, sizeof(ips_copy), "%s", peer_info.ip);

        // Get our own IPs to avoid self-connection
        char my_ips[256] = {0};
        get_external_ip(my_ips, sizeof(my_ips));

        char *ip_token = strtok(ips_copy, ",");
        while (ip_token) {
            // Trim whitespace
            while (*ip_token == ' ') ip_token++;

            // Skip self-connection (same IP + same port = our own listener)
            if (peer_info.port == ctx->config.listen_port && strstr(my_ips, ip_token)) {
                QGP_LOG_INFO(LOG_TAG, "[TIER 1] Skipping %s:%d (self-connection)\n", ip_token, peer_info.port);
                ip_token = strtok(NULL, ",");
                continue;
            }

            QGP_LOG_INFO(LOG_TAG, "[TIER 1] Trying IP: %s:%d...\n", ip_token, peer_info.port);

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
                        QGP_LOG_INFO(LOG_TAG, "[TIER 1] ✓ TCP connected to %s:%d\n", ip_token, peer_info.port);

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
                                QGP_LOG_INFO(LOG_TAG, "[TIER 1] ✓ Sent %zu bytes\n", message_len);

                                // Step 4: Wait for ACK
                                uint8_t ack;
                                ssize_t ack_received = recv(sockfd, (char*)&ack, 1, 0);

                                if (ack_received == 1 && ack == 0x01) {
                                    QGP_LOG_INFO(LOG_TAG, "[TIER 1] ✓✓ SUCCESS - ACK received from %s!\n", ip_token);
                                    close(sockfd);
                                    return 0;  // SUCCESS - Tier 1 worked!
                                }
                            }
                        }

                        close(sockfd);
                    } else {
                        QGP_LOG_INFO(LOG_TAG, "[TIER 1] Connection to %s:%d failed\n", ip_token, peer_info.port);
                        close(sockfd);
                    }
                } else {
                    QGP_LOG_INFO(LOG_TAG, "[TIER 1] Invalid IP: %s\n", ip_token);
                    close(sockfd);
                }
            }

            // Try next IP
            ip_token = strtok(NULL, ",");
        }
    }

    QGP_LOG_WARN(LOG_TAG, "[TIER 1] Failed - peer unreachable via direct TCP\n");

    // ========================================================================
    // TIER 2: ICE NAT Traversal (PERSISTENT - Phase 11 FIX)
    // ========================================================================

    // FIX: Check if ICE is available first
    if (!ctx->ice_ready) {
        QGP_LOG_WARN(LOG_TAG, "[TIER 2] ICE unavailable (initialization failed or disabled)\n");
        goto tier3_fallback;
    }

    // Compute peer fingerprint (hex string) from public key hash
    uint8_t peer_dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(peer_pubkey, 2592, peer_dht_key);  // Dilithium5 public key size

    char peer_fingerprint_hex[129];  // SHA3-512 = 64 bytes * 2 hex chars + null
    for (int i = 0; i < 64; i++) {
        snprintf(peer_fingerprint_hex + (i * 2), 3, "%02x", peer_dht_key[i]);
    }
    peer_fingerprint_hex[128] = '\0';

    // OPTIMIZATION: Skip ICE for offline peers (no point in 10s timeout)
    // But still try if we have an existing cached connection
    if (tier1_lookup_success && !peer_info.is_online) {
        // Check for existing cached ICE connection first
        pthread_mutex_lock(&ctx->connections_mutex);
        p2p_connection_t *cached_conn = NULL;
        for (size_t i = 0; i < 256; i++) {
            if (ctx->connections[i] &&
                ctx->connections[i]->type == CONNECTION_TYPE_ICE &&
                ctx->connections[i]->active &&
                strcmp(ctx->connections[i]->peer_fingerprint, peer_fingerprint_hex) == 0) {
                cached_conn = ctx->connections[i];
                break;
            }
        }
        pthread_mutex_unlock(&ctx->connections_mutex);

        if (!cached_conn) {
            QGP_LOG_INFO(LOG_TAG, "[TIER 2] Skipped - peer offline, no cached ICE connection\n");
            goto tier3_fallback;
        }
        QGP_LOG_INFO(LOG_TAG, "[TIER 2] Peer offline but have cached ICE connection, trying it...\n");
    } else {
        QGP_LOG_INFO(LOG_TAG, "[TIER 2] Attempting ICE NAT traversal (persistent connections)...\n");
    }

    // Find or create ICE connection (reuse existing, create new only if peer online)
    p2p_connection_t *ice_conn = ice_get_or_create_connection(ctx, peer_pubkey, peer_fingerprint_hex);
    if (!ice_conn) {
        QGP_LOG_INFO(LOG_TAG, "[TIER 2] Failed to establish ICE connection\n");
        goto tier3_fallback;
    }

    QGP_LOG_INFO(LOG_TAG, "[TIER 2] ✓ Using ICE connection to peer %.32s...\n", peer_fingerprint_hex);

    // Send via existing ICE connection and wait for ACK
    int ice_sent = ice_send(ice_conn->ice_ctx, message, message_len);
    if (ice_sent > 0) {
        QGP_LOG_INFO(LOG_TAG, "[TIER 2] ✓ Sent %d bytes via ICE, waiting for ACK...\n", ice_sent);

        // Wait for ACK (2 second timeout)
        uint8_t ack_buf[1];
        int ack_result = ice_recv_timeout(ice_conn->ice_ctx, ack_buf, 1, 2000);

        if (ack_result == 1 && ack_buf[0] == 0x01) {
            QGP_LOG_INFO(LOG_TAG, "[TIER 2] ✓✓ SUCCESS - ACK received via ICE!\n");
            return 0;  // SUCCESS - Tier 2 worked!
        } else if (ack_result > 0) {
            // Got data but not ACK - might be a message from peer
            QGP_LOG_INFO(LOG_TAG, "[TIER 2] Received %d bytes but not ACK (0x%02x)\n", ack_result, ack_buf[0]);
        } else {
            QGP_LOG_INFO(LOG_TAG, "[TIER 2] No ACK received (timeout or error)\n");
        }
    } else {
        QGP_LOG_INFO(LOG_TAG, "[TIER 2] Failed to send message via ICE\n");
    }

    // ========================================================================
    // TIER 3: DHT Offline Queue (handled by caller - messenger_p2p.c)
    // Always queue to DHT when ICE is used (no ACK = can't trust delivery)
    // ========================================================================

tier3_fallback:
    QGP_LOG_WARN(LOG_TAG, "[TIER 3] Queueing to DHT offline queue for guaranteed delivery\n");
    return -1;  // Caller (messenger_p2p.c) will queue to DHT offline storage
}
