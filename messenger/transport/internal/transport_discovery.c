/**
 * Transport Discovery Module
 * DHT-based presence registration
 *
 * Privacy: Only timestamp is published (no IP address)
 * Contacts can see online status without learning your IP
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "dht/client/dht_singleton.h"

#define LOG_TAG "PRESENCE"

/**
 * Register presence in DHT (timestamp only - privacy preserving)
 * Publishes only timestamp for online status indication
 * No IP address is published to protect user privacy.
 *
 * @param ctx Transport context
 * @return 0 on success, -1 on error
 */
int transport_register_presence(transport_t *ctx) {
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
        QGP_LOG_INFO(LOG_TAG, "Presence registered (timestamp only, no IP leaked)\n");
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to register presence in DHT\n");
        return result;
    }

    return 0;
}
