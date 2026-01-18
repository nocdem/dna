/**
 * Transport Offline Queue Module
 * Spillway Protocol: Sender outbox architecture for offline message delivery
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "dht/client/dht_singleton.h"
#include "dht/shared/dht_dm_outbox.h"  /* v0.5.0+ daily bucket API */
#include "database/contacts_db.h"       /* v0.5.22+ smart sync timestamps */
#include <time.h>

#define LOG_TAG "SPILLWAY"

/* 3 days in seconds - threshold for full sync */
#define SMART_SYNC_FULL_THRESHOLD (3 * 86400)

/**
 * Queue offline message in sender's DHT outbox (Spillway)
 * Stores encrypted message in sender's outbox for recipient to retrieve
 *
 * @param ctx Transport context
 * @param sender Sender fingerprint (owner of outbox)
 * @param recipient Recipient fingerprint
 * @param message Encrypted message data
 * @param message_len Message length
 * @param seq_num Monotonic sequence number for watermark pruning
 * @return 0 on success, -1 on error
 */
int transport_queue_offline_message(
    transport_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *message,
    size_t message_len,
    uint64_t seq_num)
{
    QGP_LOG_DEBUG(LOG_TAG, "Queue message (len=%zu, seq=%lu)\n",
                  message_len, (unsigned long)seq_num);

    if (!ctx || !sender || !recipient || !message || message_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for queuing offline message\n");
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        QGP_LOG_DEBUG(LOG_TAG, "Offline queue disabled in config\n");
        return -1;
    }

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for offline queue\n");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Calling dht_queue_message (seq=%lu, ttl=%u)\n",
                  (unsigned long)seq_num, ctx->config.offline_ttl_seconds);

    int result = dht_queue_message(
        dht,
        sender,
        recipient,
        message,
        message_len,
        seq_num,
        ctx->config.offline_ttl_seconds
    );

    if (result == 0) {
        ctx->offline_queued++;
        QGP_LOG_DEBUG(LOG_TAG, "Message queued (total: %zu)\n", ctx->offline_queued);
    }

    return result;
}

/**
 * Check offline messages from contacts' outboxes (Spillway)
 * Queries each contact's outbox for messages addressed to this user
 *
 * @param ctx Transport context
 * @param sender_fp If non-NULL, fetch only from this contact. If NULL, fetch from all contacts.
 * @param messages_received Output number of messages delivered (optional)
 * @return 0 on success, -1 on error
 */
int transport_check_offline_messages(
    transport_t *ctx,
    const char *sender_fp,
    size_t *messages_received)
{
    QGP_LOG_DEBUG(LOG_TAG, "Checking offline messages (sender=%s)\n",
                  sender_fp ? sender_fp : "ALL");

    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Context is NULL\n");
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        QGP_LOG_DEBUG(LOG_TAG, "Offline queue disabled\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    // Build sender fingerprint array
    const char **sender_fps_array = NULL;
    size_t sender_count = 0;
    contact_list_t *contacts = NULL;

    if (sender_fp) {
        // Single contact mode - just use the provided fingerprint
        sender_fps_array = (const char**)malloc(sizeof(char*));
        if (!sender_fps_array) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate sender array\n");
            if (messages_received) *messages_received = 0;
            return -1;
        }
        sender_fps_array[0] = sender_fp;
        sender_count = 1;
        QGP_LOG_DEBUG(LOG_TAG, "Single contact fetch: %.20s...\n", sender_fp);
    } else {
        // All contacts mode - load from database
        if (contacts_db_list(&contacts) != 0 || !contacts || contacts->count == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "No contacts in database\n");
            if (contacts) contacts_db_free_list(contacts);
            if (messages_received) *messages_received = 0;
            return 0;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Checking %zu contact outboxes\n", contacts->count);

        sender_fps_array = (const char**)malloc(contacts->count * sizeof(char*));
        if (!sender_fps_array) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate sender fingerprint array\n");
            contacts_db_free_list(contacts);
            if (messages_received) *messages_received = 0;
            return -1;
        }

        for (size_t i = 0; i < contacts->count; i++) {
            sender_fps_array[i] = contacts->contacts[i].identity;
        }
        sender_count = contacts->count;
    }

    // Query contact outboxes
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for offline message check\n");
        free(sender_fps_array);
        if (contacts) contacts_db_free_list(contacts);
        if (messages_received) *messages_received = 0;
        return -1;
    }

    dht_offline_message_t *messages = NULL;
    size_t count = 0;

    /* Smart sync: check oldest last_sync timestamp to decide full vs recent sync */
    uint64_t now = (uint64_t)time(NULL);
    bool need_full_sync = false;

    if (!sender_fp) {  /* All contacts mode - check timestamps */
        uint64_t oldest_sync = now;

        for (size_t i = 0; i < sender_count; i++) {
            uint64_t last_sync = contacts_db_get_dm_sync_timestamp(sender_fps_array[i]);
            if (last_sync == 0) {
                /* Never synced this contact - need full sync */
                need_full_sync = true;
                QGP_LOG_DEBUG(LOG_TAG, "Contact %.16s... never synced - need full sync",
                             sender_fps_array[i]);
                break;
            }
            if (last_sync < oldest_sync) {
                oldest_sync = last_sync;
            }
        }

        if (!need_full_sync && (now - oldest_sync) > SMART_SYNC_FULL_THRESHOLD) {
            need_full_sync = true;
            QGP_LOG_INFO(LOG_TAG, "Smart sync: oldest sync %lu seconds ago (>3 days) - need full sync",
                        (unsigned long)(now - oldest_sync));
        }
    }

    int result;
    if (need_full_sync) {
        QGP_LOG_INFO(LOG_TAG, "Smart sync: FULL (8 days) from %zu contacts", sender_count);
        result = dht_dm_outbox_sync_all_contacts_full(
            dht,
            ctx->config.identity,
            (const char **)sender_fps_array,
            sender_count,
            &messages,
            &count
        );
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "Smart sync: RECENT (3 days) from %zu contacts", sender_count);
        result = dht_dm_outbox_sync_all_contacts_recent(
            dht,
            ctx->config.identity,
            (const char **)sender_fps_array,
            sender_count,
            &messages,
            &count
        );
    }

    /* Update sync timestamps on success for all-contacts mode */
    if (result == 0 && !sender_fp) {
        for (size_t i = 0; i < sender_count; i++) {
            contacts_db_set_dm_sync_timestamp(sender_fps_array[i], now);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "[OFFLINE] DHT retrieve: result=%d, count=%zu (from %zu senders, %s)\n",
                 result, count, sender_count, need_full_sync ? "full" : "recent");

    free(sender_fps_array);
    if (contacts) contacts_db_free_list(contacts);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to retrieve offline messages from contacts' outboxes\n");
        if (messages_received) *messages_received = 0;
        return -1;
    }

    if (count == 0) {
        if (messages_received) *messages_received = 0;
        return 0;
    }

    // Track max seq_num per sender for watermark publishing
    typedef struct {
        char sender[129];
        uint64_t max_seq_num;
    } sender_watermark_t;

    sender_watermark_t *watermarks = NULL;
    size_t watermark_count = 0;
    size_t watermark_capacity = 0;

    // Deliver each message via callback and track max seq_num per sender
    size_t delivered_count = 0;
    for (size_t i = 0; i < count; i++) {
        dht_offline_message_t *msg = &messages[i];

        // Track max seq_num for this sender
        bool found = false;
        for (size_t j = 0; j < watermark_count; j++) {
            if (strcmp(watermarks[j].sender, msg->sender) == 0) {
                if (msg->seq_num > watermarks[j].max_seq_num) {
                    watermarks[j].max_seq_num = msg->seq_num;
                }
                found = true;
                break;
            }
        }

        if (!found) {
            // Add new sender to watermarks array
            if (watermark_count >= watermark_capacity) {
                size_t new_capacity = (watermark_capacity == 0) ? 16 : (watermark_capacity * 2);
                sender_watermark_t *new_array = realloc(watermarks, new_capacity * sizeof(sender_watermark_t));
                if (new_array) {
                    watermarks = new_array;
                    watermark_capacity = new_capacity;
                }
            }

            if (watermark_count < watermark_capacity) {
                strncpy(watermarks[watermark_count].sender, msg->sender, sizeof(watermarks[watermark_count].sender) - 1);
                watermarks[watermark_count].sender[sizeof(watermarks[watermark_count].sender) - 1] = '\0';
                watermarks[watermark_count].max_seq_num = msg->seq_num;
                watermark_count++;
            }
        }

        // Deliver to application layer (messenger_transport.c)
        if (ctx->message_callback) {
            ctx->message_callback(
                NULL,                    // peer_pubkey (unknown for offline messages)
                msg->sender,             // sender_fingerprint from DHT queue
                msg->ciphertext,
                msg->ciphertext_len,
                ctx->callback_user_data
            );
            delivered_count++;
        }
    }

    // Publish watermarks asynchronously (fire-and-forget)
    // This tells senders which messages we've received so they can prune their outboxes
    for (size_t i = 0; i < watermark_count; i++) {
        QGP_LOG_INFO(LOG_TAG, "Publishing watermark for sender %.20s...: seq=%lu\n",
               watermarks[i].sender, (unsigned long)watermarks[i].max_seq_num);
        dht_publish_watermark_async(
            dht,
            ctx->config.identity,     // My fingerprint (recipient/watermark owner)
            watermarks[i].sender,     // Sender fingerprint
            watermarks[i].max_seq_num
        );
    }

    if (watermarks) {
        free(watermarks);
    }

    if (messages_received) {
        *messages_received = delivered_count;
    }

    dht_offline_messages_free(messages, count);
    return 0;
}
