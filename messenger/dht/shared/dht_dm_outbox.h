/**
 * @file dht_dm_outbox.h
 * @brief Direct Message Outbox via DHT with Daily Buckets
 *
 * Daily bucket messaging for 1-1 direct messages:
 * - Key format: sender_fp:outbox:recipient_fp:DAY_BUCKET
 * - DAY_BUCKET = unix_timestamp / 86400 (days since epoch)
 * - TTL: 7 days (auto-expire, no watermark pruning needed)
 * - Day rotation: Listeners rotate at midnight UTC
 *
 * Sync Strategy:
 * - Recent sync: yesterday + today + tomorrow (3 days parallel)
 * - Full sync: last 8 days (today-6 to today+1)
 * - Clock skew tolerance: +/- 1 day
 *
 * Part of DNA Messenger
 *
 * @date 2026-01-16
 */

#ifndef DHT_DM_OUTBOX_H
#define DHT_DM_OUTBOX_H

#include "../core/dht_context.h"
#include "../core/dht_listen.h"
#include "dht_offline_queue.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Seconds per day for bucket calculation */
#define DNA_DM_OUTBOX_SECONDS_PER_DAY 86400

/** TTL for DM outbox buckets (7 days in seconds) */
#define DNA_DM_OUTBOX_TTL (7 * 24 * 3600)

/** Maximum days to sync on full catch-up (7 days + 1 for clock skew) */
#define DNA_DM_OUTBOX_MAX_CATCHUP_DAYS 8

/** Days to sync on recent check (yesterday, today, tomorrow) */
#define DNA_DM_OUTBOX_RECENT_DAYS 3

/** Maximum messages per day bucket (DoS prevention) */
#define DNA_DM_OUTBOX_MAX_MESSAGES_PER_BUCKET 500

/*============================================================================
 * Listen Context (for day rotation)
 *============================================================================*/

/**
 * @brief Listen context for DM outbox with day rotation support
 *
 * Tracks current day bucket and manages listener rotation at midnight.
 * Created by dht_dm_outbox_subscribe(), freed by unsubscribe().
 */
typedef struct {
    char my_fp[129];                    /* My fingerprint (recipient) */
    char contact_fp[129];               /* Contact fingerprint (sender) */
    uint64_t current_day;               /* Current day bucket being listened */
    size_t listen_token;                /* Token from dht_listen_ex() */
    dht_listen_callback_t callback;     /* User callback for new messages */
    void *user_data;                    /* User data for callback */
    dht_context_t *dht_ctx;             /* DHT context (for resubscription) */
} dht_dm_listen_ctx_t;

/*============================================================================
 * Key Generation
 *============================================================================*/

/**
 * @brief Get current day bucket
 *
 * @return Current unix timestamp / 86400 (days since epoch)
 */
uint64_t dht_dm_outbox_get_day_bucket(void);

/**
 * @brief Generate DHT key for DM outbox bucket
 *
 * Key format: sender_fp:outbox:recipient_fp:day_bucket
 *
 * @param sender_fp Sender's fingerprint (128 hex chars)
 * @param recipient_fp Recipient's fingerprint (128 hex chars)
 * @param day_bucket Day bucket (0 = current day)
 * @param key_out Output buffer for key string
 * @param key_out_size Size of output buffer (must be >= 300)
 * @return 0 on success, -1 on error
 */
int dht_dm_outbox_make_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t day_bucket,
    char *key_out,
    size_t key_out_size
);

/*============================================================================
 * Send API
 *============================================================================*/

/**
 * @brief Queue message to daily bucket (NO watermark pruning)
 *
 * Flow:
 * 1. Generate today's bucket key: sender_fp:outbox:recipient_fp:day
 * 2. Check local cache for existing messages
 * 3. If cache miss, fetch from DHT via dht_chunked_fetch()
 * 4. Append new message to bucket
 * 5. Publish updated bucket via dht_chunked_publish()
 *
 * NOTE: No watermark fetching or pruning! TTL handles cleanup.
 *
 * @param ctx DHT context
 * @param sender Sender fingerprint (128 hex chars)
 * @param recipient Recipient fingerprint (128 hex chars)
 * @param ciphertext Encrypted message blob
 * @param ciphertext_len Length of ciphertext
 * @param seq_num Sequence number (for ordering within day)
 * @param ttl_seconds TTL in seconds (0 = default 7 days)
 * @return 0 on success, -1 on failure
 */
int dht_dm_queue_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds
);

/*============================================================================
 * Receive API
 *============================================================================*/

/**
 * @brief Sync messages from a specific day bucket
 *
 * @param ctx DHT context
 * @param my_fp My fingerprint (recipient)
 * @param contact_fp Contact fingerprint (sender)
 * @param day_bucket Day to sync (0 = current day)
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count
 * @return 0 on success, -1 on failure
 */
int dht_dm_outbox_sync_day(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    uint64_t day_bucket,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * @brief Sync recent messages (yesterday + today + tomorrow)
 *
 * Fetches 3 days in parallel for clock skew tolerance.
 * Use this for periodic sync while app is running.
 *
 * @param ctx DHT context
 * @param my_fp My fingerprint (recipient)
 * @param contact_fp Contact fingerprint (sender)
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count
 * @return 0 on success, -1 on failure
 */
int dht_dm_outbox_sync_recent(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * @brief Sync all messages from last 8 days
 *
 * Fetches today-6 to today+1 (8 days total).
 * Use this on login or recovery.
 *
 * @param ctx DHT context
 * @param my_fp My fingerprint (recipient)
 * @param contact_fp Contact fingerprint (sender)
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count
 * @return 0 on success, -1 on failure
 */
int dht_dm_outbox_sync_full(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * @brief Sync recent messages from all contacts in parallel
 *
 * For each contact, syncs 3 days (yesterday, today, tomorrow).
 * All contacts queried in parallel for performance.
 *
 * @param ctx DHT context
 * @param my_fp My fingerprint (recipient)
 * @param contact_list Array of contact fingerprints (senders)
 * @param contact_count Number of contacts
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count
 * @return 0 on success, -1 on failure
 */
int dht_dm_outbox_sync_all_contacts_recent(
    dht_context_t *ctx,
    const char *my_fp,
    const char **contact_list,
    size_t contact_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/*============================================================================
 * Listen API (Real-time notifications with day rotation)
 *============================================================================*/

/**
 * @brief Subscribe to contact's outbox for real-time notifications
 *
 * Creates DHT listener on contact's today bucket.
 * Caller must call dht_dm_outbox_check_day_rotation() periodically
 * to rotate listener at midnight UTC.
 *
 * @param ctx DHT context
 * @param my_fp My fingerprint (recipient)
 * @param contact_fp Contact fingerprint (sender to listen to)
 * @param callback Callback when new messages arrive
 * @param user_data User data for callback
 * @param listen_ctx_out Output: Listen context (caller must free with unsubscribe)
 * @return 0 on success, -1 on failure
 */
int dht_dm_outbox_subscribe(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    dht_listen_callback_t callback,
    void *user_data,
    dht_dm_listen_ctx_t **listen_ctx_out
);

/**
 * @brief Unsubscribe from contact's outbox
 *
 * Cancels DHT listener and frees context.
 *
 * @param ctx DHT context (may be NULL if already freed)
 * @param listen_ctx Listen context to free
 */
void dht_dm_outbox_unsubscribe(
    dht_context_t *ctx,
    dht_dm_listen_ctx_t *listen_ctx
);

/**
 * @brief Check and rotate listener if day changed
 *
 * Call this periodically (e.g., every 4 minutes from heartbeat).
 * If day changed since last check:
 * 1. Cancels old listener
 * 2. Subscribes to new day's bucket
 * 3. Syncs yesterday (catch any messages from previous bucket)
 *
 * @param ctx DHT context
 * @param listen_ctx Listen context
 * @return 1 if rotated, 0 if no change, -1 on error
 */
int dht_dm_outbox_check_day_rotation(
    dht_context_t *ctx,
    dht_dm_listen_ctx_t *listen_ctx
);

/*============================================================================
 * Cache Management
 *============================================================================*/

/**
 * @brief Clear local outbox cache
 *
 * Called when DHT connection is lost or on shutdown.
 */
void dht_dm_outbox_cache_clear(void);

/**
 * @brief Sync pending cached entries to DHT
 *
 * Republishes entries that failed to publish earlier.
 * Call when DHT becomes ready.
 *
 * @param ctx DHT context
 * @return Number of entries synced
 */
int dht_dm_outbox_cache_sync_pending(dht_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* DHT_DM_OUTBOX_H */
