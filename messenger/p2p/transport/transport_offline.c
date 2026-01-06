/**
 * P2P Transport Offline Queue Module
 * Spillway Protocol: Sender outbox architecture for offline message delivery
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "dht/client/dht_singleton.h"  // Phase 14: Direct DHT access

#define LOG_TAG "SPILLWAY_OUTBOX"

/**
 * Queue offline message in sender's DHT outbox (Spillway)
 * Stores encrypted message in sender's outbox for recipient to retrieve
 * @param ctx: P2P transport context
 * @param sender: Sender fingerprint (owner of outbox)
 * @param recipient: Recipient fingerprint
 * @param message: Encrypted message data
 * @param message_len: Message length
 * @param seq_num: Monotonic sequence number for watermark pruning
 * @return: 0 on success, -1 on error
 */
int p2p_queue_offline_message(
    p2p_transport_t *ctx,
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
 * @param ctx: P2P transport context
 * @param messages_received: Output number of messages delivered (optional)
 * @return: 0 on success, -1 on error
 */
int p2p_check_offline_messages(
    p2p_transport_t *ctx,
    size_t *messages_received)
{
    QGP_LOG_DEBUG(LOG_TAG, "Checking offline messages\n");

    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Context is NULL\n");
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        QGP_LOG_DEBUG(LOG_TAG, "Offline queue disabled\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    // 1. Load contacts from database
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts || contacts->count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No contacts in database\n");
        if (contacts) contacts_db_free_list(contacts);
        if (messages_received) *messages_received = 0;
        return 0;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Checking %zu contact outboxes\n", contacts->count);

    // 2. Build array of sender fingerprints
    const char **sender_fps = (const char**)malloc(contacts->count * sizeof(char*));
    if (!sender_fps) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate sender fingerprint array\n");
        contacts_db_free_list(contacts);
        if (messages_received) *messages_received = 0;
        return -1;
    }

    for (size_t i = 0; i < contacts->count; i++) {
        sender_fps[i] = contacts->contacts[i].identity;  // Fingerprint
    }

    // 3. Query all contacts' outboxes
    // For each contact: Key = SHA3-512(contact_fp + ":outbox:" + my_fp)
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available for offline message check\n");
        free(sender_fps);
        contacts_db_free_list(contacts);
        if (messages_received) *messages_received = 0;
        return -1;
    }

    dht_offline_message_t *messages = NULL;
    size_t count = 0;

    // Use parallel version for 10-100× speedup
    int result = dht_retrieve_queued_messages_from_contacts_parallel(
        dht,
        ctx->config.identity,  // My fingerprint (recipient)
        sender_fps,
        contacts->count,
        &messages,
        &count
    );

    QGP_LOG_WARN(LOG_TAG, "[OFFLINE] DHT retrieve: result=%d, messages_from_dht=%zu\n", result, count);

    free(sender_fps);
    contacts_db_free_list(contacts);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to retrieve offline messages from contacts' outboxes\n");
        if (messages_received) *messages_received = 0;
        return -1;
    }

    if (count == 0) {
        if (messages_received) *messages_received = 0;
        return 0;
    }

    // 4. Track max seq_num per sender for watermark publishing
    // Using a simple array (O(n²) but contacts count is small)
    typedef struct {
        char sender[129];
        uint64_t max_seq_num;
    } sender_watermark_t;

    sender_watermark_t *watermarks = NULL;
    size_t watermark_count = 0;
    size_t watermark_capacity = 0;

    // 5. Deliver each message via callback and track max seq_num per sender
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

        // Deliver to application layer (messenger_p2p.c)
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

    // 6. Publish watermarks asynchronously (fire-and-forget)
    // This tells senders which messages we've received so they can prune their outboxes
    for (size_t i = 0; i < watermark_count; i++) {
        QGP_LOG_INFO(LOG_TAG, "Publishing watermark for sender %.20s...: seq=%lu\n",
               watermarks[i].sender, (unsigned long)watermarks[i].max_seq_num);
        dht_publish_watermark_async(
            dht,                      // Use dht from singleton above
            ctx->config.identity,     // My fingerprint (recipient/watermark owner)
            watermarks[i].sender,     // Sender fingerprint
            watermarks[i].max_seq_num
        );
    }

    if (watermarks) {
        free(watermarks);
    }

    // Note (Spillway): No queue clearing needed - recipients don't control sender outboxes.
    // Senders manage their own outboxes. Watermarks tell senders to prune delivered messages.

    if (messages_received) {
        *messages_received = delivered_count;
    }

    dht_offline_messages_free(messages, count);
    return 0;
}
