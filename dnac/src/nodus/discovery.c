/**
 * @file discovery.c
 * @brief Witness server discovery via DHT roster
 *
 * Discovers witness servers by querying the BFT roster from DHT.
 * Results are cached for performance.
 *
 * v0.10.3: Removed hardcoded LAN bootstrap servers (192.168.0.x).
 * Discovery now relies solely on the BFT roster from DHT.
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/bft.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Cache configuration */
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* Cached server list (shared with client.c) */
extern dnac_witness_info_t *g_witness_servers;
extern int g_witness_count;
extern uint64_t g_witness_cache_time;

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

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

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fingerprint_out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, pubkey, DNAC_PUBKEY_SIZE) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fingerprint_out[0] = '\0';
        return;
    }
    EVP_MD_CTX_free(ctx);

    /* Convert to hex string */
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        fingerprint_out[i * 2] = hex[(hash[i] >> 4) & 0xF];
        fingerprint_out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    fingerprint_out[128] = '\0';
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

    /* Discover roster from DHT */
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

    /* No roster found */
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
