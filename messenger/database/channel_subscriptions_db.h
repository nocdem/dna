/**
 * Channel Subscriptions Database
 *
 * Local SQLite database for channel subscriptions.
 * Tracks which channels the user has subscribed to.
 * Stores last-read timestamps for unread count tracking.
 */

#ifndef CHANNEL_SUBSCRIPTIONS_DB_H
#define CHANNEL_SUBSCRIPTIONS_DB_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Channel subscription info
 */
typedef struct {
    char channel_uuid[37];      /* UUID v4 of subscribed channel */
    uint64_t subscribed_at;     /* Unix timestamp when subscribed */
    uint64_t last_synced;       /* Unix timestamp of last DHT sync */
    uint64_t last_read_at;      /* Unix timestamp of last read */
} channel_subscription_t;

/**
 * Initialize the channel subscriptions database
 * Creates tables if they don't exist
 *
 * @return 0 on success, negative on error
 */
int channel_subscriptions_db_init(void);

/**
 * Close the channel subscriptions database
 */
void channel_subscriptions_db_close(void);

/**
 * Subscribe to a channel
 *
 * @param channel_uuid UUID of the channel to subscribe to
 * @return 0 on success, -1 if already subscribed, negative on error
 */
int channel_subscriptions_db_subscribe(const char *channel_uuid);

/**
 * Unsubscribe from a channel
 *
 * @param channel_uuid UUID of the channel to unsubscribe from
 * @return 0 on success, -1 if not subscribed, negative on error
 */
int channel_subscriptions_db_unsubscribe(const char *channel_uuid);

/**
 * Check if subscribed to a channel
 *
 * @param channel_uuid UUID of the channel to check
 * @return true if subscribed, false otherwise
 */
bool channel_subscriptions_db_is_subscribed(const char *channel_uuid);

/**
 * Get all subscriptions
 * Caller must free the returned array with channel_subscriptions_db_free()
 *
 * @param out_subscriptions Pointer to receive array of subscriptions
 * @param out_count Pointer to receive count
 * @return 0 on success, negative on error
 */
int channel_subscriptions_db_get_all(channel_subscription_t **out_subscriptions, int *out_count);

/**
 * Free subscriptions array
 *
 * @param subscriptions Array to free
 * @param count Number of elements
 */
void channel_subscriptions_db_free(channel_subscription_t *subscriptions, int count);

/**
 * Update last_synced timestamp for a subscription
 *
 * @param channel_uuid UUID of the channel
 * @return 0 on success, negative on error
 */
int channel_subscriptions_db_update_synced(const char *channel_uuid);

/**
 * Mark a channel as read up to the given timestamp
 *
 * @param channel_uuid UUID of the channel
 * @param timestamp Unix timestamp to mark as read up to
 * @return 0 on success, negative on error
 */
int channel_subscriptions_db_mark_read(const char *channel_uuid, uint64_t timestamp);

/**
 * Get the last-read timestamp for a channel
 *
 * @param channel_uuid UUID of the channel
 * @return last_read_at timestamp, or 0 if not found/error
 */
uint64_t channel_subscriptions_db_get_last_read(const char *channel_uuid);

#ifdef __cplusplus
}
#endif

#endif /* CHANNEL_SUBSCRIPTIONS_DB_H */
