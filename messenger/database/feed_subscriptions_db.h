/**
 * Feed Subscriptions Database
 *
 * Local SQLite database for feed topic subscriptions.
 * Tracks which topics the user has subscribed to for notifications.
 * Syncs to/from DHT for multi-device support.
 */

#ifndef FEED_SUBSCRIPTIONS_DB_H
#define FEED_SUBSCRIPTIONS_DB_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Feed subscription info
 */
typedef struct {
    char topic_uuid[37];        /* UUID v4 of subscribed topic */
    uint64_t subscribed_at;     /* Unix timestamp when subscribed */
    uint64_t last_synced;       /* Unix timestamp of last DHT sync */
} feed_subscription_t;

/**
 * Initialize the feed subscriptions database
 * Creates tables if they don't exist
 *
 * @return 0 on success, negative on error
 */
int feed_subscriptions_db_init(void);

/**
 * Close the feed subscriptions database
 */
void feed_subscriptions_db_close(void);

/**
 * Subscribe to a topic
 *
 * @param topic_uuid UUID of the topic to subscribe to
 * @return 0 on success, -1 if already subscribed, negative on error
 */
int feed_subscriptions_db_subscribe(const char *topic_uuid);

/**
 * Unsubscribe from a topic
 *
 * @param topic_uuid UUID of the topic to unsubscribe from
 * @return 0 on success, -1 if not subscribed, negative on error
 */
int feed_subscriptions_db_unsubscribe(const char *topic_uuid);

/**
 * Check if subscribed to a topic
 *
 * @param topic_uuid UUID of the topic to check
 * @return true if subscribed, false otherwise
 */
bool feed_subscriptions_db_is_subscribed(const char *topic_uuid);

/**
 * Get all subscriptions
 * Caller must free the returned array with feed_subscriptions_db_free()
 *
 * @param out_subscriptions Pointer to receive array of subscriptions
 * @param out_count Pointer to receive count
 * @return 0 on success, negative on error
 */
int feed_subscriptions_db_get_all(feed_subscription_t **out_subscriptions, int *out_count);

/**
 * Free subscriptions array
 *
 * @param subscriptions Array to free
 * @param count Number of elements
 */
void feed_subscriptions_db_free(feed_subscription_t *subscriptions, int count);

/**
 * Update last_synced timestamp for a subscription
 *
 * @param topic_uuid UUID of the topic
 * @return 0 on success, negative on error
 */
int feed_subscriptions_db_update_synced(const char *topic_uuid);

/**
 * Get subscription count
 *
 * @return Number of subscriptions, or negative on error
 */
int feed_subscriptions_db_count(void);

/**
 * Clear all subscriptions (for testing/reset)
 *
 * @return 0 on success, negative on error
 */
int feed_subscriptions_db_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* FEED_SUBSCRIPTIONS_DB_H */
