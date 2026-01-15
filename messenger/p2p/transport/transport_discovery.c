/**
 * P2P Transport Discovery Module
 * DHT-based peer discovery (presence registration and peer lookup)
 *
 * Privacy: ICE/STUN/TURN removed in v0.4.61
 * - Presence now timestamp-only (no IP address published)
 * - Contacts can see online status without learning your IP
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "dht/client/dht_singleton.h"

#define LOG_TAG "P2P_DISC"

/**
 * Register presence in DHT (timestamp only - privacy preserving)
 * Publishes only timestamp for online status indication
 * No IP address is published to protect user privacy.
 *
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int p2p_register_presence(p2p_transport_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Create timestamp-only presence JSON (no IP - privacy)
    char presence_data[128];
    if (create_presence_json(presence_data, sizeof(presence_data)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create presence JSON\n");
        return -1;
    }

    // Compute DHT key: SHA3-512(public_key)
    uint8_t dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(ctx->my_public_key, 2592, dht_key);  // Dilithium5 public key size

    QGP_LOG_INFO(LOG_TAG, "Registering presence in DHT (timestamp only, privacy-preserving)\n");
    QGP_LOG_INFO(LOG_TAG, "DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);
    QGP_LOG_INFO(LOG_TAG, "Presence data: %s\n", presence_data);

    // Store in DHT (signed, 7-day TTL, value_id=1 for replacement)
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for presence registration\n");
        return -1;
    }
    unsigned int ttl_7days = 7 * 24 * 3600;  // 604800 seconds
    int result = dht_put_signed(dht, dht_key, sizeof(dht_key),
                                (const uint8_t*)presence_data, strlen(presence_data),
                                1, ttl_7days, "presence");

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "✓ Presence registered (timestamp only, no IP leaked)\n");
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to register presence in DHT\n");
        return result;
    }

    return 0;
}

/**
 * Lookup peer in DHT (timestamp only)
 * Retrieves online status without IP disclosure
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

    memset(peer_info, 0, sizeof(peer_info_t));

    // Compute DHT key: SHA3-512(peer_pubkey)
    uint8_t dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(peer_pubkey, 2592, dht_key);  // Dilithium5 public key size

    QGP_LOG_INFO(LOG_TAG, "Looking up peer presence in DHT\n");
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

    QGP_LOG_INFO(LOG_TAG, "Found peer presence: %.*s\n", (int)value_len, value);

    // Parse JSON (timestamp only)
    if (parse_presence_json((const char*)value, &peer_info->last_seen) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse peer presence JSON\n");
        free(value);
        return -1;
    }

    // Copy public key
    memcpy(peer_info->public_key, peer_pubkey, 2592);  // Dilithium5 public key size

    // Check if peer is online (last seen < 10 minutes)
    time_t now = time(NULL);
    peer_info->is_online = (now - (time_t)peer_info->last_seen) < 600;

    free(value);

    QGP_LOG_INFO(LOG_TAG, "Peer lookup successful: last_seen=%lu (online: %s)\n",
           (unsigned long)peer_info->last_seen,
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
    if (parse_presence_json((const char*)value, last_seen_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse presence JSON\n");
        free(value);
        return -1;
    }

    free(value);

    QGP_LOG_INFO(LOG_TAG, "Presence lookup successful: last_seen=%lu\n",
           (unsigned long)*last_seen_out);

    return 0;
}

// ============================================================================
// ICE candidate functions removed in v0.4.61 for privacy
// ============================================================================
// The following were removed:
// - ICE candidate publishing to DHT
// - ICE candidate lookup from DHT
// - 3-tier fallback system (TCP → ICE → DHT)
//
// All messaging now uses DHT-only path via messenger_queue_to_dht().
// This provides better privacy by not leaking IP addresses.
// ============================================================================
