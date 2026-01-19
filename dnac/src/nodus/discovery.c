/**
 * @file discovery.c
 * @brief Nodus server discovery via DHT
 *
 * Discovers Nodus servers by:
 * 1. Querying DHT for system Nodus server list
 * 2. Falling back to hardcoded bootstrap servers
 * 3. Caching results for performance
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Forward declare DHT context type */
typedef struct dht_context dht_context_t;

/* DHT functions from libdna */
extern void* dna_engine_get_dht_context(dna_engine_t *engine);
extern int dht_get(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   uint8_t **value_out, size_t *value_len_out);

/* DHT key for Nodus server list */
#define NODUS_DHT_KEY "dna:system:nodus-servers"

/* Cache configuration */
#define NODUS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* Cached server list (shared with client.c) */
extern dnac_nodus_info_t *g_nodus_servers;
extern int g_nodus_count;
extern uint64_t g_nodus_cache_time;

/* ============================================================================
 * Bootstrap Nodus Servers (Hardcoded Fallback)
 * ========================================================================== */

/*
 * These are the initial Nodus servers for the network.
 * They are the same machines that run DNA Messenger bootstrap nodes.
 * In production, the list should be fetched from DHT.
 */
static const struct {
    const char *id;       /* 32-byte hex server ID */
    const char *address;  /* hostname:port */
} BOOTSTRAP_NODUS[] = {
    /* Server 1 - Primary */
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "nodus1.dna-messenger.io:4100"
    },
    /* Server 2 - Secondary */
    {
        "0000000000000000000000000000000000000000000000000000000000000002",
        "nodus2.dna-messenger.io:4100"
    },
    /* Server 3 - Tertiary */
    {
        "0000000000000000000000000000000000000000000000000000000000000003",
        "nodus3.dna-messenger.io:4100"
    }
};
#define BOOTSTRAP_NODUS_COUNT 3

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * Compute SHA3-512 hash of data
 */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * Get current time in seconds
 */
static uint64_t get_time_sec(void) {
    return (uint64_t)time(NULL);
}

/**
 * Derive fingerprint from Dilithium5 public key
 * Fingerprint = hex(SHA3-512(pubkey))
 */
static void derive_fingerprint(const uint8_t *pubkey, char *fingerprint_out) {
    uint8_t hash[64];
    if (compute_sha3_512(pubkey, DNAC_PUBKEY_SIZE, hash) != 0) {
        /* On error, use empty fingerprint */
        fingerprint_out[0] = '\0';
        return;
    }

    /* Convert to hex string */
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        fingerprint_out[i * 2] = hex[(hash[i] >> 4) & 0xF];
        fingerprint_out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    fingerprint_out[128] = '\0';
}

/**
 * Parse Nodus server list from DHT value
 *
 * Format: count(1) + [id(64 hex) + address(256) + pubkey(2592)]...
 */
static int parse_nodus_list(const uint8_t *data, size_t len,
                            dnac_nodus_info_t **servers_out, int *count_out) {
    if (!data || len < 1 || !servers_out || !count_out) return -1;

    uint8_t count = data[0];
    if (count == 0 || count > DNAC_MAX_NODUS_SERVERS) return -1;

    size_t entry_size = 64 + 256 + DNAC_PUBKEY_SIZE;  /* id + address + pubkey */
    if (len < 1 + count * entry_size) return -1;

    dnac_nodus_info_t *servers = calloc(count, sizeof(dnac_nodus_info_t));
    if (!servers) return -1;

    const uint8_t *ptr = data + 1;
    for (int i = 0; i < count; i++) {
        /* ID (64 hex chars) */
        memcpy(servers[i].id, ptr, 64);
        servers[i].id[64] = '\0';
        ptr += 64;

        /* Address (256 chars) */
        memcpy(servers[i].address, ptr, 255);
        servers[i].address[255] = '\0';
        ptr += 256;

        /* Public key (2592 bytes) */
        memcpy(servers[i].pubkey, ptr, DNAC_PUBKEY_SIZE);
        ptr += DNAC_PUBKEY_SIZE;

        /* Derive fingerprint from public key */
        derive_fingerprint(servers[i].pubkey, servers[i].fingerprint);

        servers[i].is_available = true;  /* Assume available */
        servers[i].last_seen = get_time_sec();
    }

    *servers_out = servers;
    *count_out = count;
    return 0;
}

/**
 * Create bootstrap server list (fallback)
 */
static int create_bootstrap_list(dnac_nodus_info_t **servers_out, int *count_out) {
    dnac_nodus_info_t *servers = calloc(BOOTSTRAP_NODUS_COUNT, sizeof(dnac_nodus_info_t));
    if (!servers) return -1;

    for (int i = 0; i < BOOTSTRAP_NODUS_COUNT; i++) {
        strncpy(servers[i].id, BOOTSTRAP_NODUS[i].id, sizeof(servers[i].id) - 1);
        strncpy(servers[i].address, BOOTSTRAP_NODUS[i].address, sizeof(servers[i].address) - 1);
        /* Note: Bootstrap servers don't have pubkeys in this hardcoded list */
        /* Real pubkeys would be fetched from DHT or stored in config */
        memset(servers[i].pubkey, 0, sizeof(servers[i].pubkey));

        /* Derive fingerprint (will be hash of zeros for bootstrap servers) */
        derive_fingerprint(servers[i].pubkey, servers[i].fingerprint);

        servers[i].is_available = true;
        servers[i].last_seen = get_time_sec();
    }

    *servers_out = servers;
    *count_out = BOOTSTRAP_NODUS_COUNT;
    return 0;
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_nodus_discover(dnac_context_t *ctx,
                        dnac_nodus_info_t **servers_out,
                        int *count_out) {
    if (!ctx || !servers_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *servers_out = NULL;
    *count_out = 0;

    /* Check cache first */
    uint64_t now = get_time_sec();
    if (g_nodus_servers && g_nodus_count > 0 &&
        (now - g_nodus_cache_time) < NODUS_CACHE_TTL_SEC) {
        /* Return cached copy */
        dnac_nodus_info_t *cached = calloc(g_nodus_count, sizeof(dnac_nodus_info_t));
        if (cached) {
            memcpy(cached, g_nodus_servers, g_nodus_count * sizeof(dnac_nodus_info_t));
            *servers_out = cached;
            *count_out = g_nodus_count;
            return DNAC_SUCCESS;
        }
    }

    /* Get DNA engine and DHT context */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        /* Fallback to bootstrap list */
        return create_bootstrap_list(servers_out, count_out);
    }

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        /* Fallback to bootstrap list */
        return create_bootstrap_list(servers_out, count_out);
    }

    /* Build DHT key for Nodus server list */
    uint8_t dht_key[64];
    if (compute_sha3_512((const uint8_t *)NODUS_DHT_KEY, strlen(NODUS_DHT_KEY), dht_key) != 0) {
        return create_bootstrap_list(servers_out, count_out);
    }

    /* Query DHT for Nodus server list */
    uint8_t *value = NULL;
    size_t value_len = 0;
    int rc = dht_get(dht, dht_key, 64, &value, &value_len);

    if (rc == 0 && value && value_len > 0) {
        /* Parse server list from DHT */
        dnac_nodus_info_t *servers = NULL;
        int count = 0;

        if (parse_nodus_list(value, value_len, &servers, &count) == 0) {
            /* Update cache */
            if (g_nodus_servers) {
                free(g_nodus_servers);
            }
            g_nodus_servers = calloc(count, sizeof(dnac_nodus_info_t));
            if (g_nodus_servers) {
                memcpy(g_nodus_servers, servers, count * sizeof(dnac_nodus_info_t));
                g_nodus_count = count;
                g_nodus_cache_time = now;
            }

            *servers_out = servers;
            *count_out = count;
            free(value);
            return DNAC_SUCCESS;
        }

        free(value);
    }

    /* DHT query failed - fallback to bootstrap list */
    rc = create_bootstrap_list(servers_out, count_out);
    if (rc == 0) {
        /* Cache bootstrap list too */
        if (g_nodus_servers) {
            free(g_nodus_servers);
        }
        g_nodus_servers = calloc(*count_out, sizeof(dnac_nodus_info_t));
        if (g_nodus_servers) {
            memcpy(g_nodus_servers, *servers_out, *count_out * sizeof(dnac_nodus_info_t));
            g_nodus_count = *count_out;
            g_nodus_cache_time = now;
        }
        return DNAC_SUCCESS;
    }

    return DNAC_ERROR_NETWORK;
}

int dnac_get_nodus_list(dnac_context_t *ctx,
                        dnac_nodus_info_t **servers,
                        int *count) {
    return dnac_nodus_discover(ctx, servers, count);
}

void dnac_free_nodus_list(dnac_nodus_info_t *servers, int count) {
    (void)count;
    free(servers);
}

int dnac_check_nullifier(dnac_context_t *ctx,
                         const uint8_t *nullifier,
                         bool *is_spent) {
    return dnac_nodus_check_nullifier(ctx, nullifier, is_spent);
}
