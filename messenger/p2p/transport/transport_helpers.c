/**
 * P2P Transport Helper Functions
 * Shared utilities used by all transport modules
 */

#include "transport_core.h"

/**
 * Compute SHA3-512 hash (Category 5 security)
 * Used for DHT keys: key = SHA3-512(public_key)
 */
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    qgp_sha3_512(data, len, hash_out);
}

/**
 * Get external IP address
 * Currently returns local network IP (works for LAN and DHT-mediated connections)
 * DHT handles NAT traversal via OpenDHT's built-in peer discovery
 * TODO (Future Enhancement): Add STUN/HTTP API for direct internet P2P without DHT
 */
int get_external_ip(char *ip_out, size_t len) {
#ifdef _WIN32
    // Windows implementation using GetAdaptersAddresses
    IP_ADAPTER_ADDRESSES *addresses = NULL;
    IP_ADAPTER_ADDRESSES *adapter = NULL;
    ULONG size = 0;
    ULONG result;
    int found = 0;

    // Get required buffer size
    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &size);
    if (result != ERROR_BUFFER_OVERFLOW) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    addresses = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (!addresses) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &size);
    if (result != NO_ERROR) {
        free(addresses);
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    // Look for first non-loopback IPv4 address
    for (adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
        if (unicast && unicast->Address.lpSockaddr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
            const char *ip = inet_ntoa(addr->sin_addr);

            // Skip loopback (127.0.0.1)
            if (strncmp(ip, "127.", 4) != 0) {
                snprintf(ip_out, len, "%s", ip);
                found = 1;
                break;
            }
        }
    }

    free(addresses);

    if (!found) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    return 0;
#else
    // Linux implementation using getifaddrs
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    // Look for first non-loopback IPv4 address
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {  // IPv4
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            const char *ip = inet_ntoa(addr->sin_addr);

            // Skip loopback (127.0.0.1)
            if (strncmp(ip, "127.", 4) != 0) {
                snprintf(ip_out, len, "%s", ip);
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    if (!found) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    return 0;
#endif
}

/**
 * Create JSON string for peer presence
 * Format: {"ip":"x.x.x.x","port":4001,"timestamp":1234567890}
 */
int create_presence_json(const char *ip, uint16_t port, char *json_out, size_t len) {
    int written = snprintf(json_out, len,
                          "{\"ip\":\"%s\",\"port\":%d,\"timestamp\":%ld}",
                          ip, port, time(NULL));
    return (written < len) ? 0 : -1;
}

/**
 * Parse JSON presence data
 * Simple manual parsing (no json-c dependency for minimal build)
 */
int parse_presence_json(const char *json_str, peer_info_t *peer_info) {
    // Extract IP
    const char *ip_start = strstr(json_str, "\"ip\":\"");
    if (ip_start) {
        ip_start += 6;
        const char *ip_end = strchr(ip_start, '"');
        if (ip_end) {
            size_t ip_len = ip_end - ip_start;
            if (ip_len < sizeof(peer_info->ip)) {
                memcpy(peer_info->ip, ip_start, ip_len);
                peer_info->ip[ip_len] = '\0';
            }
        }
    }

    // Extract port
    const char *port_start = strstr(json_str, "\"port\":");
    if (port_start) {
        peer_info->port = (uint16_t)atoi(port_start + 7);
    }

    // Extract timestamp
    const char *ts_start = strstr(json_str, "\"timestamp\":");
    if (ts_start) {
        peer_info->last_seen = (uint64_t)atoll(ts_start + 12);
    }

    return 0;
}
