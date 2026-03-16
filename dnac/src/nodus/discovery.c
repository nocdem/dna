/**
 * @file discovery.c
 * @brief Witness server discovery via Nodus SDK roster query
 *
 * Discovers witness servers by querying the BFT roster through the
 * Nodus client SDK. Results are cached for performance.
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* Shared crypto */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

/* Nodus client SDK */
#include "nodus/nodus.h"

/* Nodus singleton access */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "DNAC_DISC"

/* Cache configuration */
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* Cached server list (shared with client.c) */
extern dnac_witness_info_t *g_witness_servers;
extern int g_witness_count;
extern uint64_t g_witness_cache_time;
extern pthread_mutex_t g_witness_cache_mutex;  /* M-30 */

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * Get current time in seconds
 */
static uint64_t get_time_sec(void) {
    return (uint64_t)time(NULL);
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

    /* M-30: Thread-safe cache check */
    uint64_t now = get_time_sec();
    pthread_mutex_lock(&g_witness_cache_mutex);
    if (g_witness_servers && g_witness_count > 0 &&
        (now - g_witness_cache_time) < WITNESS_CACHE_TTL_SEC) {
        /* Return cached copy */
        dnac_witness_info_t *cached = calloc(g_witness_count, sizeof(dnac_witness_info_t));
        if (cached) {
            memcpy(cached, g_witness_servers, g_witness_count * sizeof(dnac_witness_info_t));
            *servers_out = cached;
            *count_out = g_witness_count;
            pthread_mutex_unlock(&g_witness_cache_mutex);
            return DNAC_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_witness_cache_mutex);

    /* Query roster via Nodus SDK */
    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    nodus_dnac_roster_result_t roster;
    int rc = nodus_client_dnac_roster(client, &roster);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Roster discovery failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (roster.count <= 0) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Convert roster entries to witness info array */
    dnac_witness_info_t *servers = calloc(roster.count, sizeof(dnac_witness_info_t));
    if (!servers) {
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < roster.count; i++) {
        nodus_dnac_roster_entry_t *entry = &roster.entries[i];
        dnac_witness_info_t *info = &servers[i];

        /* Convert witness_id to hex string */
        for (int j = 0; j < NODUS_T3_WITNESS_ID_LEN; j++) {
            info->id[j * 2] = hex[(entry->witness_id[j] >> 4) & 0xF];
            info->id[j * 2 + 1] = hex[entry->witness_id[j] & 0xF];
        }
        info->id[NODUS_T3_WITNESS_ID_LEN * 2] = '\0';

        strncpy(info->address, entry->address, sizeof(info->address) - 1);
        memcpy(info->pubkey, entry->pubkey, NODUS_PK_BYTES);
        info->is_available = entry->active;

        /* Derive fingerprint from public key: hex(SHA3-512(pubkey)) */
        uint8_t fp_hash[64];
        if (qgp_sha3_512(entry->pubkey, NODUS_PK_BYTES, fp_hash) == 0) {
            for (int j = 0; j < 64; j++) {
                info->fingerprint[j * 2] = hex[(fp_hash[j] >> 4) & 0xF];
                info->fingerprint[j * 2 + 1] = hex[fp_hash[j] & 0xF];
            }
            info->fingerprint[128] = '\0';
        }
    }

    /* Update cache (M-30: thread-safe) */
    pthread_mutex_lock(&g_witness_cache_mutex);
    if (g_witness_servers) free(g_witness_servers);
    g_witness_servers = calloc(roster.count, sizeof(dnac_witness_info_t));
    if (g_witness_servers) {
        memcpy(g_witness_servers, servers, roster.count * sizeof(dnac_witness_info_t));
        g_witness_count = roster.count;
        g_witness_cache_time = now;
    }
    pthread_mutex_unlock(&g_witness_cache_mutex);

    *servers_out = servers;
    *count_out = roster.count;

    QGP_LOG_INFO(LOG_TAG, "Discovered %d witnesses via Nodus SDK", roster.count);
    return DNAC_SUCCESS;
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
