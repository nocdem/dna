/**
 * DHT Channel Subscriptions Sync
 * Multi-device sync for channel subscriptions
 *
 * Architecture:
 * - Local subscriptions stored in SQLite
 * - This module syncs subscriptions to/from DHT for multi-device support
 * - DHT key: SHA3-512("dna:channels:subs:" + fingerprint)
 * - Uses signed values for owner verification
 */

#ifndef DHT_CHANNEL_SUBSCRIPTIONS_H
#define DHT_CHANNEL_SUBSCRIPTIONS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dht_context dht_context_t;

#define DHT_CHANNEL_SUBS_VERSION     1
#define DHT_CHANNEL_SUBS_TTL_SECONDS (30 * 24 * 60 * 60)
#define DHT_CHANNEL_SUBS_MAX_COUNT   300
#define DHT_CHANNEL_SUBS_NS "dna:channels:subs:"

typedef struct {
    char channel_uuid[37];
    uint64_t subscribed_at;
    uint64_t last_synced;
    uint64_t last_read_at;
} dht_channel_subscription_entry_t;

/**
 * Sync channel subscription list TO DHT
 *
 * Serializes local subscriptions and publishes to DHT at:
 * SHA3-512("dna:channels:subs:" + fingerprint)
 *
 * Uses dht_put_signed() for owner verification - only the identity owner
 * can update their subscription list.
 *
 * @param dht_ctx DHT context
 * @param fingerprint User's 128-char fingerprint
 * @param subscriptions Array of subscriptions to sync
 * @param count Number of subscriptions (max DHT_CHANNEL_SUBS_MAX_COUNT)
 * @return 0 on success, -1 on error, -2 if too many subscriptions
 */
int dht_channel_subscriptions_sync_to_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dht_channel_subscription_entry_t *subscriptions,
    size_t count);

/**
 * Sync channel subscription list FROM DHT
 *
 * Retrieves subscriptions from DHT and returns them.
 * Does NOT automatically merge with local database - caller decides policy.
 *
 * @param dht_ctx DHT context
 * @param fingerprint User's 128-char fingerprint
 * @param subscriptions_out Output array (caller must free with dht_channel_subscriptions_free)
 * @param count_out Number of subscriptions returned
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_channel_subscriptions_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dht_channel_subscription_entry_t **subscriptions_out,
    size_t *count_out);

/**
 * Free subscription array from sync_from_dht
 *
 * @param subscriptions Array to free
 * @param count Number of elements (unused, included for API consistency)
 */
void dht_channel_subscriptions_free(
    dht_channel_subscription_entry_t *subscriptions,
    size_t count);

/**
 * Generate DHT key for channel subscription list
 *
 * Creates SHA3-512 hash of "dna:channels:subs:" + fingerprint
 * Key is stored in DHT as 64-byte binary.
 *
 * @param fingerprint User's 128-char fingerprint
 * @param key_out Output buffer (must be at least 64 bytes)
 * @param key_len_out Output key length (always 64)
 * @return 0 on success, -1 on error
 */
int dht_channel_subscriptions_make_key(
    const char *fingerprint,
    uint8_t *key_out,
    size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif /* DHT_CHANNEL_SUBSCRIPTIONS_H */
