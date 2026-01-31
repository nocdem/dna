/**
 * Transport Offline Queue Module
 * Spillway Protocol: Sender outbox architecture for offline message delivery
 *
 * v15: Replaced watermarks with simple ACK system
 */

#include "transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/threadpool.h"   /* Parallel ACK publishing */
#include "dht/client/dht_singleton.h"
#include "dht/shared/dht_dm_outbox.h"  /* v0.5.0+ daily bucket API */
#include "dht/shared/dht_offline_queue.h"  /* v15: ACK API */
#include "database/contacts_db.h"       /* v0.5.22+ smart sync timestamps */
#include <time.h>

#define LOG_TAG "SPILLWAY"

/* Context for parallel ACK publishing (v15) */
typedef struct {
    dht_context_t *dht;
    char my_identity[129];
    char sender[129];
} ack_task_t;

/* Thread pool task: publish single ACK (v15) */
static void ack_publish_task(void *arg) {
    ack_task_t *task = (ack_task_t *)arg;
    if (!task) return;

    /* Publish ACK to notify sender we received their messages */
    dht_publish_ack(task->dht, task->my_identity, task->sender);
}

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
 * @param publish_watermarks If true, publish watermarks to tell senders we received their messages.
 *                           Set false for background service caching (user hasn't read them yet).
 * @param force_full_sync If true, always do full 8-day sync (bypass smart sync).
 *                        Use at startup to catch messages received by other devices.
 * @param messages_received Output number of messages delivered (optional)
 * @return 0 on success, -1 on error
 */
int transport_check_offline_messages(
    transport_t *ctx,
    const char *sender_fp,
    bool publish_watermarks,
    bool force_full_sync,
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

    /* Smart sync: check oldest last_sync timestamp to decide full vs recent sync.
     * If force_full_sync is true, bypass smart sync logic entirely (startup case). */
    uint64_t now = (uint64_t)time(NULL);
    bool need_full_sync = force_full_sync;  /* Start with force flag */

    if (!need_full_sync && !sender_fp) {  /* All contacts mode - check timestamps */
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

    // v15: Track unique senders for ACK publishing (replaced watermarks)
    typedef struct {
        char sender[129];
    } sender_ack_t;

    sender_ack_t *acks = NULL;
    size_t ack_count = 0;
    size_t ack_capacity = 0;

    // Deliver each message via callback and track unique senders
    size_t delivered_count = 0;
    for (size_t i = 0; i < count; i++) {
        dht_offline_message_t *msg = &messages[i];

        // Track unique senders for ACK publishing
        bool found = false;
        for (size_t j = 0; j < ack_count; j++) {
            if (strcmp(acks[j].sender, msg->sender) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            // Add new sender to ACK array
            if (ack_count >= ack_capacity) {
                size_t new_capacity = (ack_capacity == 0) ? 16 : (ack_capacity * 2);
                sender_ack_t *new_array = realloc(acks, new_capacity * sizeof(sender_ack_t));
                if (new_array) {
                    acks = new_array;
                    ack_capacity = new_capacity;
                }
            }

            if (ack_count < ack_capacity) {
                strncpy(acks[ack_count].sender, msg->sender, sizeof(acks[ack_count].sender) - 1);
                acks[ack_count].sender[sizeof(acks[ack_count].sender) - 1] = '\0';
                ack_count++;
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

    // v15: Publish ACKs only if requested (skip for background caching)
    if (publish_watermarks && ack_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Publishing %zu ACKs via thread pool", ack_count);

        // Build task array for thread pool
        ack_task_t *tasks = calloc(ack_count, sizeof(ack_task_t));
        void **task_args = calloc(ack_count, sizeof(void *));

        if (tasks && task_args) {
            for (size_t i = 0; i < ack_count; i++) {
                tasks[i].dht = dht;
                strncpy(tasks[i].my_identity, ctx->config.identity, sizeof(tasks[i].my_identity) - 1);
                strncpy(tasks[i].sender, acks[i].sender, sizeof(tasks[i].sender) - 1);
                task_args[i] = &tasks[i];
            }

            // Publish all ACKs in parallel using thread pool
            threadpool_map(ack_publish_task, task_args, ack_count, 0);

            free(tasks);
            free(task_args);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate ACK task array");
            // Clean up partial allocation (free(NULL) is safe)
            free(tasks);
            free(task_args);
        }
    } else if (ack_count > 0) {
        QGP_LOG_DEBUG(LOG_TAG, "Skipping %zu ACKs (background caching mode)", ack_count);
    }

    if (acks) {
        free(acks);
    }

    if (messages_received) {
        *messages_received = delivered_count;
    }

    dht_offline_messages_free(messages, count);
    return 0;
}
