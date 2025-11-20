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
 * Get ALL network interface IPs
 * Returns comma-separated list of all non-loopback IPv4 addresses
 * Example: "192.168.0.111,10.0.0.5,203.0.113.45"
 * This allows peer to try all IPs when connecting (first one wins!)
 */
int get_external_ip(char *ip_out, size_t len) {
    char all_ips[512] = {0};
    int count = 0;

#ifdef _WIN32
    // Windows implementation using GetAdaptersAddresses
    IP_ADAPTER_ADDRESSES *addresses = NULL;
    IP_ADAPTER_ADDRESSES *adapter = NULL;
    ULONG size = 0;
    ULONG result;

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

    // Collect ALL non-loopback IPv4 addresses
    for (adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
        if (unicast && unicast->Address.lpSockaddr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
            const char *ip = inet_ntoa(addr->sin_addr);

            // Skip loopback (127.0.0.1) and Docker (172.17.0.0/16)
            if (strncmp(ip, "127.", 4) != 0 && strncmp(ip, "172.17.", 7) != 0) {
                if (count > 0) strcat(all_ips, ",");
                strcat(all_ips, ip);
                count++;
            }
        }
    }

    free(addresses);
#else
    // Linux implementation using getifaddrs
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    // Collect ALL non-loopback IPv4 addresses
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {  // IPv4
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            const char *ip = inet_ntoa(addr->sin_addr);

            // Skip loopback (127.0.0.1) and Docker (172.17.0.0/16)
            if (strncmp(ip, "127.", 4) != 0 && strncmp(ip, "172.17.", 7) != 0) {
                if (count > 0) strcat(all_ips, ",");
                strcat(all_ips, ip);
                count++;
            }
        }
    }

    freeifaddrs(ifaddr);
#endif

    if (count == 0) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    snprintf(ip_out, len, "%s", all_ips);
    return 0;
}

/**
 * Create JSON string for peer presence
 * Format: {"ips":"192.168.0.111,10.0.0.5","port":4001,"timestamp":1234567890}
 * Multiple IPs comma-separated - peer will try all of them!
 */
int create_presence_json(const char *ips, uint16_t port, char *json_out, size_t len) {
    int written = snprintf(json_out, len,
                          "{\"ips\":\"%s\",\"port\":%d,\"timestamp\":%ld}",
                          ips, port, time(NULL));
    return (written < len) ? 0 : -1;
}

/**
 * Parse JSON presence data
 * Simple manual parsing (no json-c dependency for minimal build)
 * Supports both old "ip" and new "ips" (comma-separated) formats for backwards compatibility
 */
int parse_presence_json(const char *json_str, peer_info_t *peer_info) {
    // Extract IPs (try "ips" first, fallback to "ip" for backwards compatibility)
    const char *ips_start = strstr(json_str, "\"ips\":\"");
    if (ips_start) {
        ips_start += 7;  // Skip "ips":"
        const char *ips_end = strchr(ips_start, '"');
        if (ips_end) {
            size_t ips_len = ips_end - ips_start;
            if (ips_len < sizeof(peer_info->ip)) {
                memcpy(peer_info->ip, ips_start, ips_len);
                peer_info->ip[ips_len] = '\0';
            }
        }
    } else {
        // Fallback to old "ip" format
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
