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
#include "crypto/utils/qgp_fingerprint.h"

/* Nodus client SDK */
#include "nodus/nodus.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

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

/**
 * Phase 14 / Task 64: prefer the chain-authoritative committee query for
 * witness discovery. The committee query returns the 7 validators the
 * chain will actually use to sign the next block — this is the set any
 * dnac_spend MUST target. Falling back to the legacy roster path only
 * when the committee query fails (pre-genesis / initial bootstrap where
 * no committee has been elected yet).
 *
 * Returns 0 on success (populates *out and *count_out), -1 if the query
 * was reachable but did not yield usable committee data. The caller
 * then falls back to the roster path. Caller owns *out on success.
 */
static int discover_from_committee(dnac_witness_info_t **out, int *count_out) {
    *out = NULL;
    *count_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return -1;

    nodus_singleton_lock();
    nodus_dnac_committee_result_t committee;
    int rc = nodus_client_dnac_committee(client, &committee);
    nodus_singleton_unlock();

    if (rc != 0 || committee.count <= 0) {
        /* -1 drives fallback; do not treat as hard error. */
        return -1;
    }

    /* At least one committee entry must carry an address for the chain
     * path to be actionable. Early epochs may report empty address
     * fields while the DHT roster catches up — in that case fall
     * through so the caller tries the legacy roster (which includes
     * DHT-sourced endpoints). */
    int addr_count = 0;
    for (int i = 0; i < committee.count; i++) {
        if (committee.entries[i].address[0] != '\0') addr_count++;
    }
    if (addr_count == 0) return -1;

    dnac_witness_info_t *servers =
        calloc((size_t)addr_count, sizeof(dnac_witness_info_t));
    if (!servers) return -1;

    static const char hex[] = "0123456789abcdef";
    int w = 0;
    for (int i = 0; i < committee.count; i++) {
        const nodus_dnac_committee_entry_t *e = &committee.entries[i];
        if (e->address[0] == '\0') continue;
        dnac_witness_info_t *info = &servers[w];

        /* id: hex(SHA3-512(pubkey))[:64] — same derivation as witness_id
         * used in the roster path, and stable across callers. */
        uint8_t fp_hash[QGP_FP_RAW_BYTES];
        if (qgp_sha3_512(e->pubkey, NODUS_PK_BYTES, fp_hash) == 0) {
            /* Short id: first 16 bytes of the full fp, as 32 hex chars. */
            for (int j = 0; j < 16; j++) {
                info->id[j * 2]     = hex[(fp_hash[j] >> 4) & 0xF];
                info->id[j * 2 + 1] = hex[fp_hash[j] & 0xF];
            }
            info->id[32] = '\0';

            /* Full 128-hex fingerprint via shared helper. */
            qgp_fp_raw_to_hex(fp_hash, info->fingerprint);
        }

        strncpy(info->address, e->address, sizeof(info->address) - 1);
        info->address[sizeof(info->address) - 1] = '\0';
        memcpy(info->pubkey, e->pubkey, NODUS_PK_BYTES);
        info->is_available = (e->status == 0 /* ACTIVE */ ||
                              e->status == 1 /* RETIRING — still in epoch */);
        info->last_seen = (uint64_t)time(NULL);
        w++;
    }

    *out = servers;
    *count_out = w;
    return 0;
}

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

    /* Phase 14 / Task 64: chain-committee first. */
    dnac_witness_info_t *from_committee = NULL;
    int committee_count = 0;
    if (discover_from_committee(&from_committee, &committee_count) == 0 &&
        committee_count > 0) {
        /* Seed cache. */
        pthread_mutex_lock(&g_witness_cache_mutex);
        if (g_witness_servers) free(g_witness_servers);
        g_witness_servers =
            calloc((size_t)committee_count, sizeof(dnac_witness_info_t));
        if (g_witness_servers) {
            memcpy(g_witness_servers, from_committee,
                    (size_t)committee_count * sizeof(dnac_witness_info_t));
            g_witness_count = committee_count;
            g_witness_cache_time = now;
        }
        pthread_mutex_unlock(&g_witness_cache_mutex);

        *servers_out = from_committee;
        *count_out = committee_count;
        QGP_LOG_INFO(LOG_TAG,
                      "Discovered %d committee witnesses (chain-authoritative)",
                      committee_count);
        return DNAC_SUCCESS;
    }

    /* Fallback: legacy roster path (pre-genesis / bootstrap). */
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
        uint8_t fp_hash[QGP_FP_RAW_BYTES];
        if (qgp_sha3_512(entry->pubkey, NODUS_PK_BYTES, fp_hash) == 0) {
            qgp_fp_raw_to_hex(fp_hash, info->fingerprint);
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

    QGP_LOG_INFO(LOG_TAG,
                  "Discovered %d witnesses via legacy roster (fallback)",
                  roster.count);
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
