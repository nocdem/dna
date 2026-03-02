/**
 * @file replay.c
 * @brief Nonce-based replay prevention for BFT messages
 *
 * Extracted from consensus.c (v0.6.0 Gap 23-24 fix).
 * Provides is_replay() for detecting duplicate messages and
 * generate_nonce() for creating secure random nonces.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <time.h>
#include <pthread.h>

#include "dnac/bft.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_random.h"

#include <stdlib.h>  /* abort() */

#define LOG_TAG "BFT_REPLAY"

/* ============================================================================
 * Nonce Cache
 * ========================================================================== */

#define NONCE_CACHE_SIZE 1000
#define NONCE_CACHE_TTL_SECS 300  /* 5 minutes */

typedef struct {
    uint8_t sender_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint64_t nonce;
    uint64_t timestamp;
} nonce_entry_t;

static nonce_entry_t g_nonce_cache[NONCE_CACHE_SIZE];
static int g_nonce_cache_count = 0;
static pthread_mutex_t g_nonce_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * Generate a random nonce for message headers.
 * Aborts on RNG failure (CRITICAL-3: no weak fallback).
 */
uint64_t dnac_bft_generate_nonce(void) {
    uint64_t nonce = 0;
    if (qgp_randombytes((uint8_t*)&nonce, sizeof(nonce)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "FATAL: Cannot generate secure nonce");
        abort();
    }
    return nonce;
}

/**
 * Check if message is a replay (already seen nonce from sender).
 * Returns true if replay detected, false if new message.
 */
bool is_replay(const uint8_t *sender_id, uint64_t nonce, uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);

    /* Reject if timestamp too old (>5 minutes) or too far in future (>1 minute) */
    if (timestamp < now - NONCE_CACHE_TTL_SECS || timestamp > now + 60) {
        QGP_LOG_WARN(LOG_TAG, "Replay check: timestamp out of range (ts=%llu, now=%llu)",
                     (unsigned long long)timestamp, (unsigned long long)now);
        return true;
    }

    pthread_mutex_lock(&g_nonce_mutex);

    /* Check nonce cache */
    for (int i = 0; i < g_nonce_cache_count; i++) {
        if (memcmp(g_nonce_cache[i].sender_id, sender_id, DNAC_BFT_WITNESS_ID_SIZE) == 0 &&
            g_nonce_cache[i].nonce == nonce) {
            pthread_mutex_unlock(&g_nonce_mutex);
            QGP_LOG_WARN(LOG_TAG, "Replay detected: duplicate nonce from %.8s", sender_id);
            return true;  /* Duplicate nonce = replay */
        }
    }

    /* Evict old entries */
    int write_idx = 0;
    for (int i = 0; i < g_nonce_cache_count; i++) {
        if (now - g_nonce_cache[i].timestamp < NONCE_CACHE_TTL_SECS) {
            if (write_idx != i) {
                g_nonce_cache[write_idx] = g_nonce_cache[i];
            }
            write_idx++;
        }
    }
    g_nonce_cache_count = write_idx;

    /* Add to cache (circular if full) */
    int idx = g_nonce_cache_count;
    if (idx >= NONCE_CACHE_SIZE) {
        idx = 0;  /* Overwrite oldest */
    } else {
        g_nonce_cache_count++;
    }
    memcpy(g_nonce_cache[idx].sender_id, sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    g_nonce_cache[idx].nonce = nonce;
    g_nonce_cache[idx].timestamp = timestamp;

    pthread_mutex_unlock(&g_nonce_mutex);
    return false;
}
