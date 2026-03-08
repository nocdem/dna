/**
 * Transport Helper Functions
 * Shared utilities used by transport modules
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "TRANSPORT"

/**
 * Compute SHA3-512 hash (Category 5 security)
 * Used for DHT keys: key = SHA3-512(public_key)
 */
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    qgp_sha3_512(data, len, hash_out);
}

