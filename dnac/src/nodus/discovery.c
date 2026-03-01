/**
 * @file discovery.c
 * @brief Witness server discovery via DHT
 *
 * Discovers witness servers by:
 * 1. Querying DHT for system witness server list
 * 2. Falling back to hardcoded bootstrap servers
 * 3. Caching results for performance
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/bft.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* DHT key for witness server list */
#define WITNESS_DHT_KEY "dna:system:witness-servers"

/* Cache configuration */
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* Cached server list (shared with client.c) */
extern dnac_witness_info_t *g_witness_servers;
extern int g_witness_count;
extern uint64_t g_witness_cache_time;

/* ============================================================================
 * Bootstrap Witness Servers (Hardcoded Fallback)
 * ========================================================================== */

/*
 * These are the initial witness servers for the network.
 * They are the same machines that run DNA Messenger bootstrap nodes.
 * In production, the list should be fetched from DHT.
 */
static const struct {
    const char *id;          /* 32-byte hex server ID (first 64 chars of fingerprint) */
    const char *address;     /* hostname:port */
    const char *fingerprint; /* Full 128-char SHA3-512 fingerprint */
} BOOTSTRAP_WITNESSES[] = {
    /* node1 (chat1) */
    {
        "46de00d4e2ac54bdb70f3867498707ebaca58c65ca7713569fe183ffeeea46bd",
        "192.168.0.195:4100",
        "46de00d4e2ac54bdb70f3867498707ebaca58c65ca7713569fe183ffeeea46bdf380804405430d4684d8fc17b4702003d46d013151749a43fdc6b84d7472709d"
    },
    /* treasury */
    {
        "d43514f121b508ca304ce741edca0bd1fbe661fe5fbd6f188b6831d079417997",
        "192.168.0.196:4100",
        "d43514f121b508ca304ce741edca0bd1fbe661fe5fbd6f188b6831d0794179977083e9fbae4aa40e7d16ee73918b6e26f9c29011914415732322a2b129303634"
    },
    /* cpunkroot2 */
    {
        "7dea0967abe22f720be1b1c0f68131eb1e39d93a5bb58039836fe842a10fefec",
        "192.168.0.199:4100",
        "7dea0967abe22f720be1b1c0f68131eb1e39d93a5bb58039836fe842a10fefec1db52df710238edcb90216f232da5c621e4a2e92b6c42508b64baf43594935e7"
    }
};
#define BOOTSTRAP_WITNESSES_COUNT 3

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
 * Parse witness server list from DHT value
 *
 * Format: count(1) + [id(64 hex) + address(256) + pubkey(2592)]...
 */
static int parse_witness_list(const uint8_t *data, size_t len,
                              dnac_witness_info_t **servers_out, int *count_out) {
    if (!data || len < 1 || !servers_out || !count_out) return -1;

    uint8_t count = data[0];
    if (count == 0 || count > DNAC_MAX_WITNESS_SERVERS) return -1;

    size_t entry_size = 64 + 256 + DNAC_PUBKEY_SIZE;  /* id + address + pubkey */
    if (len < 1 + count * entry_size) return -1;

    dnac_witness_info_t *servers = calloc(count, sizeof(dnac_witness_info_t));
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
static int create_bootstrap_list(dnac_witness_info_t **servers_out, int *count_out) {
    dnac_witness_info_t *servers = calloc(BOOTSTRAP_WITNESSES_COUNT, sizeof(dnac_witness_info_t));
    if (!servers) return -1;

    for (int i = 0; i < BOOTSTRAP_WITNESSES_COUNT; i++) {
        strncpy(servers[i].id, BOOTSTRAP_WITNESSES[i].id, sizeof(servers[i].id) - 1);
        strncpy(servers[i].address, BOOTSTRAP_WITNESSES[i].address, sizeof(servers[i].address) - 1);
        /* Note: Bootstrap servers don't have pubkeys in this hardcoded list */
        /* Real pubkeys would be fetched from DHT or stored in config */
        memset(servers[i].pubkey, 0, sizeof(servers[i].pubkey));

        /* Use pre-computed fingerprints from bootstrap list */
        strncpy(servers[i].fingerprint, BOOTSTRAP_WITNESSES[i].fingerprint,
                sizeof(servers[i].fingerprint) - 1);

        servers[i].is_available = true;
        servers[i].last_seen = get_time_sec();
    }

    *servers_out = servers;
    *count_out = BOOTSTRAP_WITNESSES_COUNT;
    return 0;
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_witness_discover(dnac_context_t *ctx,
                          dnac_witness_info_t **servers_out,
                          int *count_out) {
    if (!ctx || !servers_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *servers_out = NULL;
    *count_out = 0;

    /* Check cache first */
    uint64_t now = get_time_sec();
    if (g_witness_servers && g_witness_count > 0 &&
        (now - g_witness_cache_time) < WITNESS_CACHE_TTL_SEC) {
        /* Return cached copy */
        dnac_witness_info_t *cached = calloc(g_witness_count, sizeof(dnac_witness_info_t));
        if (cached) {
            memcpy(cached, g_witness_servers, g_witness_count * sizeof(dnac_witness_info_t));
            *servers_out = cached;
            *count_out = g_witness_count;
            return DNAC_SUCCESS;
        }
    }

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);

    /* Try BFT roster discovery first (file-based) */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(engine, &roster);
    if (rc == DNAC_BFT_SUCCESS && roster.n_witnesses > 0) {
        /* Convert roster to witness info array */
        dnac_witness_info_t *servers = calloc(roster.n_witnesses, sizeof(dnac_witness_info_t));
        if (servers) {
            for (uint32_t i = 0; i < roster.n_witnesses; i++) {
                dnac_roster_entry_t *entry = &roster.witnesses[i];
                dnac_witness_info_t *info = &servers[i];

                /* Convert ID to hex string */
                for (int j = 0; j < 32; j++) {
                    snprintf(info->id + j*2, 3, "%02x", entry->witness_id[j]);
                }

                strncpy(info->address, entry->address, sizeof(info->address) - 1);
                memcpy(info->pubkey, entry->pubkey, DNAC_PUBKEY_SIZE);
                info->is_available = entry->active;
                info->last_seen = entry->joined_epoch * DNAC_EPOCH_DURATION_SEC;

                /* Derive fingerprint from public key */
                derive_fingerprint(entry->pubkey, info->fingerprint);
            }

            /* Update cache */
            if (g_witness_servers) free(g_witness_servers);
            g_witness_servers = calloc(roster.n_witnesses, sizeof(dnac_witness_info_t));
            if (g_witness_servers) {
                memcpy(g_witness_servers, servers, roster.n_witnesses * sizeof(dnac_witness_info_t));
                g_witness_count = roster.n_witnesses;
                g_witness_cache_time = now;
            }

            *servers_out = servers;
            *count_out = roster.n_witnesses;
            return DNAC_SUCCESS;
        }
    }

    /* BFT roster not found - fallback to bootstrap list */
    rc = create_bootstrap_list(servers_out, count_out);
    if (rc == 0) {
        /* Cache bootstrap list too */
        if (g_witness_servers) {
            free(g_witness_servers);
        }
        g_witness_servers = calloc(*count_out, sizeof(dnac_witness_info_t));
        if (g_witness_servers) {
            memcpy(g_witness_servers, *servers_out, *count_out * sizeof(dnac_witness_info_t));
            g_witness_count = *count_out;
            g_witness_cache_time = now;
        }
        return DNAC_SUCCESS;
    }

    return DNAC_ERROR_NETWORK;
}

int dnac_get_witness_list(dnac_context_t *ctx,
                          dnac_witness_info_t **servers,
                          int *count) {
    return dnac_witness_discover(ctx, servers, count);
}

void dnac_free_witness_list(dnac_witness_info_t *servers, int count) {
    (void)count;
    free(servers);
}

int dnac_check_nullifier(dnac_context_t *ctx,
                         const uint8_t *nullifier,
                         bool *is_spent) {
    return dnac_witness_check_nullifier(ctx, nullifier, is_spent);
}
