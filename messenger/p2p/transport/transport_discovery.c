/**
 * P2P Transport Discovery Module
 * DHT-based peer discovery (presence registration and peer lookup)
 */

#include "transport_core.h"

/**
 * Register presence in DHT
 * Publishes IP:port information for peer discovery
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

    // Store in DHT
    int result = dht_put(ctx->dht, dht_key, sizeof(dht_key),
                        (const uint8_t*)presence_data, strlen(presence_data));

    if (result == 0) {
        printf("[P2P] Presence registered successfully\n");
    } else {
        printf("[P2P] Failed to register presence in DHT\n");
    }

    return result;
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
 * Send message to peer (direct TCP connection)
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's Dilithium5 public key (2592 bytes)
 * @param message: Encrypted message data
 * @param message_len: Message length
 * @return: 0 on success (ACK received), -1 on error
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

    // Step 1: Look up peer in DHT
    peer_info_t peer_info;
    if (p2p_lookup_peer(ctx, peer_pubkey, &peer_info) != 0) {
        printf("[P2P] Peer not found in DHT - may be offline\n");
        return -1;  // Peer not online, use DHT queue fallback
    }

    if (!peer_info.is_online) {
        printf("[P2P] Peer last seen too long ago - may be offline\n");
        return -1;  // Peer appears offline, use DHT queue fallback
    }

    printf("[P2P] Connecting to peer at %s:%d...\n", peer_info.ip, peer_info.port);

    // Step 2: Establish TCP connection
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[P2P] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    // Set connection timeout (3 seconds)
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
#ifdef _WIN32
    DWORD timeout_ms = 3000;
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

    if (inet_pton(AF_INET, peer_info.ip, &peer_addr.sin_addr) <= 0) {
        fprintf(stderr, "[P2P] Invalid peer IP address: %s\n", peer_info.ip);
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        fprintf(stderr, "[P2P] Failed to connect to %s:%d: %s\n",
                peer_info.ip, peer_info.port, strerror(errno));
        close(sockfd);
        return -1;
    }

    printf("[P2P] ✓ Connected to peer at %s:%d\n", peer_info.ip, peer_info.port);

    // Step 3: Send message
    // Format: [4-byte length][message data]
    uint32_t msg_len_network = htonl((uint32_t)message_len);

    // Send length header
    ssize_t sent = send(sockfd, (char*)&msg_len_network, sizeof(msg_len_network), 0);
    if (sent != sizeof(msg_len_network)) {
        fprintf(stderr, "[P2P] Failed to send message length header\n");
        close(sockfd);
        return -1;
    }

    // Send message data
    size_t total_sent = 0;
    while (total_sent < message_len) {
        sent = send(sockfd, (char*)message + total_sent, message_len - total_sent, 0);
        if (sent <= 0) {
            fprintf(stderr, "[P2P] Failed to send message data: %s\n", strerror(errno));
            close(sockfd);
            return -1;
        }
        total_sent += sent;
    }

    printf("[P2P] ✓ Sent %zu bytes to peer\n", message_len);

    // Step 4: Wait for ACK (1 byte acknowledgment)
    // This confirms the peer received AND stored the message
    uint8_t ack;
    ssize_t ack_received = recv(sockfd, (char*)&ack, 1, 0);

    if (ack_received == 1 && ack == 0x01) {
        printf("[P2P] ✓ Received ACK from peer (message confirmed)\n");
        close(sockfd);
        return 0;  // Success - peer confirmed receipt
    } else {
        printf("[P2P] ⚠ No ACK received from peer (may not have processed message)\n");
        close(sockfd);
        return -1;  // Consider failed - fallback to DHT queue
    }
}
