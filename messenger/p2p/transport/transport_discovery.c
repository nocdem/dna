/**
 * P2P Transport Discovery Module
 * DHT-based peer discovery (presence registration and peer lookup)
 */

#include "transport_core.h"
#include "transport_ice.h"  // Phase 11: ICE NAT traversal
#include "crypto/utils/qgp_log.h"
#include "dht/client/dht_singleton.h"  // Phase 14: Direct DHT access

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
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for presence registration\n");
        return -1;
    }
    unsigned int ttl_7days = 7 * 24 * 3600;  // 604800 seconds
    int result = dht_put_signed(dht, dht_key, sizeof(dht_key),
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
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for peer lookup\n");
        return -1;
    }
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
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
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for presence lookup\n");
        return -1;
    }
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
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

// ============================================================================
// p2p_send_message() REMOVED in v0.3.154
// ============================================================================
// The 3-tier fallback system (TCP → ICE → DHT) was dead code since Phase 14.
// All messaging now uses DHT-only path via messenger_queue_to_dht().
//
// P2P/ICE infrastructure is preserved in transport_juice.c for future voice/video.
// ============================================================================
