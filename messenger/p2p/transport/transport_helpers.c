/**
 * P2P Transport Helper Functions
 * Shared utilities used by all transport modules
 *
 * Privacy: ICE/STUN/TURN removed in v0.4.61
 * - No external IP discovery (was leaking to Google/Cloudflare STUN servers)
 * - Presence now timestamp-only (no IP published to DHT)
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "P2P"

/**
 * Compute SHA3-512 hash (Category 5 security)
 * Used for DHT keys: key = SHA3-512(public_key)
 */
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    qgp_sha3_512(data, len, hash_out);
}

// ============================================================================
// IP Discovery functions removed in v0.4.61 for privacy
// ============================================================================
// The following functions were removed:
// - get_external_ip() - returned local network IPs
// - stun_get_public_ip() - queried Google/Cloudflare STUN servers
//
// Reason: Publishing IP addresses to DHT is a privacy leak.
// Contacts could see user's real IP, enabling:
// - Location tracking
// - ISP identification
// - Correlation attacks
//
// Now: Only timestamp is published, showing online/offline status
// without revealing any network information.
// ============================================================================

/**
 * Create JSON string for peer presence (timestamp only - privacy preserving)
 * Format: {"timestamp":1234567890}
 * No IP address is published to protect user privacy.
 */
int create_presence_json(char *json_out, size_t len) {
    int written = snprintf(json_out, len,
                          "{\"timestamp\":%lld}",
                          (long long)time(NULL));
    return (written >= 0 && (size_t)written < len) ? 0 : -1;
}

/**
 * Parse JSON presence data (timestamp only)
 * Format: {"timestamp":1234567890}
 */
int parse_presence_json(const char *json_str, uint64_t *last_seen_out) {
    if (!json_str || !last_seen_out) {
        return -1;
    }

    *last_seen_out = 0;

    // Extract timestamp
    const char *ts_start = strstr(json_str, "\"timestamp\":");
    if (ts_start) {
        *last_seen_out = (uint64_t)atoll(ts_start + 12);
        return 0;
    }

    // Legacy format support: try to extract timestamp from old format
    // {"ips":"...","port":...,"timestamp":...}
    ts_start = strstr(json_str, "timestamp");
    if (ts_start) {
        ts_start = strchr(ts_start, ':');
        if (ts_start) {
            *last_seen_out = (uint64_t)atoll(ts_start + 1);
            return 0;
        }
    }

    return -1;  // No timestamp found
}
