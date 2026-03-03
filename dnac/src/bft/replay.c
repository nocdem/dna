/**
 * @file replay.c
 * @brief Nonce-based replay prevention for BFT messages
 *
 * Extracted from consensus.c (v0.6.0 Gap 23-24 fix).
 * Provides is_replay() for detecting duplicate messages and
 * generate_nonce() for creating secure random nonces.
 *
 * v0.11.0: Replaced linear-scan array with hash table + TTL eviction
 * to prevent DoS via cache exhaustion (HIGH-2).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>

#include "dnac/bft.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_random.h"

#define LOG_TAG "BFT_REPLAY"

/* ============================================================================
 * Nonce Hash Table
 * ========================================================================== */

#define NONCE_BUCKET_COUNT  512
#define NONCE_CACHE_TTL_SECS 300  /* 5 minutes */

typedef struct nonce_node {
    uint8_t sender_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint64_t nonce;
    uint64_t timestamp;
    struct nonce_node *next;
} nonce_node_t;

static nonce_node_t *g_nonce_buckets[NONCE_BUCKET_COUNT];
static pthread_mutex_t g_nonce_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Hash function: combines sender_id and nonce into a bucket index.
 */
static uint32_t nonce_hash(const uint8_t *sender_id, uint64_t nonce) {
    uint32_t h = 0x811c9dc5;  /* FNV-1a offset basis */
    for (int i = 0; i < DNAC_BFT_WITNESS_ID_SIZE; i++) {
        h ^= sender_id[i];
        h *= 0x01000193;  /* FNV-1a prime */
    }
    for (int i = 0; i < 8; i++) {
        h ^= (uint8_t)(nonce >> (i * 8));
        h *= 0x01000193;
    }
    return h % NONCE_BUCKET_COUNT;
}

/**
 * Evict expired entries from a single bucket.
 */
static void evict_bucket(uint32_t bucket, uint64_t now) {
    nonce_node_t **pp = &g_nonce_buckets[bucket];
    while (*pp) {
        if (now - (*pp)->timestamp >= NONCE_CACHE_TTL_SECS) {
            nonce_node_t *expired = *pp;
            *pp = expired->next;
            free(expired);
        } else {
            pp = &(*pp)->next;
        }
    }
}

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
 *
 * Uses hash table with chaining for O(1) average lookup.
 */
bool is_replay(const uint8_t *sender_id, uint64_t nonce, uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);

    /* Reject if timestamp too old (>5 minutes) or too far in future (>1 minute) */
    if (timestamp < now - NONCE_CACHE_TTL_SECS || timestamp > now + 60) {
        QGP_LOG_WARN(LOG_TAG, "Replay check: timestamp out of range (ts=%llu, now=%llu)",
                     (unsigned long long)timestamp, (unsigned long long)now);
        return true;
    }

    uint32_t bucket = nonce_hash(sender_id, nonce);

    pthread_mutex_lock(&g_nonce_mutex);

    /* Evict expired entries from this bucket */
    evict_bucket(bucket, now);

    /* Check for existing entry */
    for (nonce_node_t *n = g_nonce_buckets[bucket]; n; n = n->next) {
        if (memcmp(n->sender_id, sender_id, DNAC_BFT_WITNESS_ID_SIZE) == 0 &&
            n->nonce == nonce) {
            pthread_mutex_unlock(&g_nonce_mutex);
            QGP_LOG_WARN(LOG_TAG, "Replay detected: duplicate nonce from %.8s", sender_id);
            return true;
        }
    }

    /* Insert new entry at head */
    nonce_node_t *node = malloc(sizeof(nonce_node_t));
    if (node) {
        memcpy(node->sender_id, sender_id, DNAC_BFT_WITNESS_ID_SIZE);
        node->nonce = nonce;
        node->timestamp = timestamp;
        node->next = g_nonce_buckets[bucket];
        g_nonce_buckets[bucket] = node;
    }

    pthread_mutex_unlock(&g_nonce_mutex);
    return false;
}
