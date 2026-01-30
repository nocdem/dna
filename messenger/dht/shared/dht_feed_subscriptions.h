/**
 * DHT Feed Subscriptions Sync
 * Multi-device sync for feed topic subscriptions
 *
 * Architecture:
 * - Local subscriptions stored in SQLite (feed_subscriptions_db.c)
 * - This module syncs subscriptions to/from DHT for multi-device support
 * - DHT key: SHA3-512("dna:feeds:subscriptions:" + fingerprint)
 * - Uses signed values for owner verification
 */

#ifndef DHT_FEED_SUBSCRIPTIONS_H
#define DHT_FEED_SUBSCRIPTIONS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct dht_context dht_context_t;

/**
 * Sync format version (increment on format changes)
 */
#define DHT_FEED_SUBS_VERSION 1

/**
 * DHT TTL for subscriptions (30 days, same as other feed data)
 */
#define DHT_FEED_SUBS_TTL_SECONDS (30 * 24 * 60 * 60)

/**
 * Maximum subscriptions that can be synced (fits in ~16KB DHT value)
 * Each entry: 36 (uuid) + 8 (timestamp) + 8 (last_synced) = 52 bytes
 * 16KB / 52 = ~315 entries, rounded down to 300 for safety
 */
#define DHT_FEED_SUBS_MAX_COUNT 300

/**
 * Subscription entry for sync (matches feed_subscription_t in feed_subscriptions_db.h)
 */
typedef struct {
    char topic_uuid[37];        /* UUID v4 of subscribed topic */
    uint64_t subscribed_at;     /* Unix timestamp when subscribed */
    uint64_t last_synced;       /* Unix timestamp of last DHT sync */
} dht_feed_subscription_entry_t;

/**
 * Sync subscription list TO DHT
 *
 * Serializes local subscriptions and publishes to DHT at:
 * SHA3-512("dna:feeds:subscriptions:" + fingerprint)
 *
 * Uses dht_put_signed() for owner verification - only the identity owner
 * can update their subscription list.
 *
 * @param dht_ctx DHT context
 * @param fingerprint User's 128-char fingerprint
 * @param subscriptions Array of subscriptions to sync
 * @param count Number of subscriptions (max DHT_FEED_SUBS_MAX_COUNT)
 * @return 0 on success, -1 on error, -2 if too many subscriptions
 */
int dht_feed_subscriptions_sync_to_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dht_feed_subscription_entry_t *subscriptions,
    size_t count
);

/**
 * Sync subscription list FROM DHT
 *
 * Retrieves subscriptions from DHT and returns them.
 * Does NOT automatically merge with local database - caller decides policy.
 *
 * @param dht_ctx DHT context
 * @param fingerprint User's 128-char fingerprint
 * @param subscriptions_out Output array (caller must free with dht_feed_subscriptions_free)
 * @param count_out Number of subscriptions returned
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_feed_subscriptions_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dht_feed_subscription_entry_t **subscriptions_out,
    size_t *count_out
);

/**
 * Free subscription array from sync_from_dht
 *
 * @param subscriptions Array to free
 * @param count Number of elements (unused, included for API consistency)
 */
void dht_feed_subscriptions_free(dht_feed_subscription_entry_t *subscriptions, size_t count);

/**
 * Generate DHT key for subscription list
 *
 * Creates SHA3-512 hash of "dna:feeds:subscriptions:" + fingerprint
 * Key is stored in DHT as 64-byte binary.
 *
 * @param fingerprint User's 128-char fingerprint
 * @param key_out Output buffer (must be at least 64 bytes)
 * @param key_len_out Output key length (always 64)
 * @return 0 on success, -1 on error
 */
int dht_feed_subscriptions_make_key(
    const char *fingerprint,
    uint8_t *key_out,
    size_t *key_len_out
);

#ifdef __cplusplus
}
#endif

#endif /* DHT_FEED_SUBSCRIPTIONS_H */
