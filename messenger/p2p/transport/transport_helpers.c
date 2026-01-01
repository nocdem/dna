/**
 * P2P Transport Helper Functions
 * Shared utilities used by all transport modules
 */

#include "transport_core.h"

// Windows static linking: define JUICE_STATIC to avoid dllimport declarations
#ifdef _WIN32
#define JUICE_STATIC
#endif

#include <juice/juice.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "P2P"

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

// ============================================================================
// STUN Public IP Discovery
// ============================================================================

// State for STUN callback
typedef struct {
    char public_ip[64];
    volatile int gathering_done;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} stun_state_t;

// Callback for STUN candidate discovery
static void on_stun_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    stun_state_t *state = (stun_state_t*)user_ptr;
    if (!state || !sdp) return;

    // Look for srflx (server-reflexive) candidate - this contains public IP
    // Format: a=candidate:2 1 UDP 1678769919 195.174.168.27 35404 typ srflx ...
    if (strstr(sdp, "typ srflx") != NULL) {
        // Parse IP from candidate string
        // Skip "a=candidate:X X UDP PRIORITY "
        const char *p = sdp;
        int space_count = 0;
        while (*p && space_count < 4) {
            if (*p == ' ') space_count++;
            p++;
        }

        if (*p) {
            // Now p points to IP address
            char ip[64] = {0};
            int i = 0;
            while (*p && *p != ' ' && i < 63) {
                ip[i++] = *p++;
            }
            ip[i] = '\0';

            pthread_mutex_lock(&state->mutex);
            if (state->public_ip[0] == '\0') {
                strncpy(state->public_ip, ip, sizeof(state->public_ip) - 1);
                QGP_LOG_INFO(LOG_TAG, "Discovered public IP: %s\n", ip);
            }
            pthread_mutex_unlock(&state->mutex);
        }
    }
}

// Callback for gathering done
static void on_stun_gathering_done(juice_agent_t *agent, void *user_ptr) {
    stun_state_t *state = (stun_state_t*)user_ptr;
    if (!state) return;

    pthread_mutex_lock(&state->mutex);
    state->gathering_done = 1;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->mutex);
}

// No-op callbacks required by libjuice API (only candidate/gathering_done callbacks are used for STUN)
static void on_stun_state_changed(juice_agent_t *agent, juice_state_t s, void *user_ptr) {}
static void on_stun_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {}

/**
 * Get public IP address via STUN query
 * Queries STUN server to discover NAT-mapped public IP
 * @param ip_out: Output buffer for public IP string
 * @param len: Buffer length
 * @return: 0 on success, -1 on failure
 */
int stun_get_public_ip(char *ip_out, size_t len) {
    if (!ip_out || len < 16) {
        return -1;
    }

    // Initialize state
    stun_state_t state;
    memset(&state, 0, sizeof(state));
    state.gathering_done = 0;
    pthread_mutex_init(&state.mutex, NULL);
    pthread_cond_init(&state.cond, NULL);

    // Configure libjuice for STUN-only query
    juice_config_t config;
    memset(&config, 0, sizeof(config));
    config.concurrency_mode = JUICE_CONCURRENCY_MODE_THREAD;
    config.stun_server_host = "stun.l.google.com";
    config.stun_server_port = 19302;
    config.cb_state_changed = on_stun_state_changed;
    config.cb_candidate = on_stun_candidate;
    config.cb_gathering_done = on_stun_gathering_done;
    config.cb_recv = on_stun_recv;
    config.user_ptr = &state;

    // Create temporary agent
    juice_agent_t *agent = juice_create(&config);
    if (!agent) {
        pthread_mutex_destroy(&state.mutex);
        pthread_cond_destroy(&state.cond);
        return -1;
    }

    // Start gathering (this triggers STUN query)
    if (juice_gather_candidates(agent) < 0) {
        juice_destroy(agent);
        pthread_mutex_destroy(&state.mutex);
        pthread_cond_destroy(&state.cond);
        return -1;
    }

    // Wait for gathering to complete (max 5 seconds)
    pthread_mutex_lock(&state.mutex);

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;

    while (!state.gathering_done) {
        int ret = pthread_cond_timedwait(&state.cond, &state.mutex, &deadline);
        if (ret == ETIMEDOUT) {
            break;
        }
    }

    // Copy result
    int success = (state.public_ip[0] != '\0');
    if (success) {
        strncpy(ip_out, state.public_ip, len - 1);
        ip_out[len - 1] = '\0';
    }

    pthread_mutex_unlock(&state.mutex);

    // Cleanup
    juice_destroy(agent);
    pthread_mutex_destroy(&state.mutex);
    pthread_cond_destroy(&state.cond);

    return success ? 0 : -1;
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
    return (written >= 0 && (size_t)written < len) ? 0 : -1;
}

/**
 * Parse JSON presence data
 * Format: {"ips":"192.168.0.111,10.0.0.5","port":4001,"timestamp":1234567890}
 */
int parse_presence_json(const char *json_str, peer_info_t *peer_info) {
    // Extract IPs (comma-separated)
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
