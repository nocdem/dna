/**
 * P2P Transport Offline Queue Module
 * Per-Message Model: Each message gets unique DHT key (no GET-MODIFY-PUT)
 */

#include "transport_core.h"
#include "../../dht/shared/dht_permsg.h"

/**
 * Queue offline message using per-message DHT keys (NEW MODEL)
 * Each message gets its own unique DHT key - no blocking GET required!
 * @param ctx: P2P transport context
 * @param sender: Sender fingerprint
 * @param recipient: Recipient fingerprint
 * @param message: Encrypted message data
 * @param message_len: Message length
 * @return: 0 on success, -1 on error
 */
int p2p_queue_offline_message(
    p2p_transport_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *message,
    size_t message_len)
{
    if (!ctx || !sender || !recipient || !message || message_len == 0) {
        fprintf(stderr, "[P2P] Invalid parameters for queuing offline message\n");
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        printf("[P2P] Offline queue disabled\n");
        return -1;
    }

    printf("[P2P] Queueing offline message for %s (%zu bytes) [PER-MESSAGE MODEL]\n", recipient, message_len);

    // Use NEW per-message model: instant PUT, no blocking GET!
    int result = dht_permsg_put(
        ctx->dht,
        sender,
        recipient,
        message,
        message_len,
        ctx->config.offline_ttl_seconds,
        NULL  // Don't need message key back
    );

    if (result == 0) {
        printf("[P2P] ✓ Message queued successfully (per-message key)\n");
        // Update statistics
        ctx->offline_queued++;
    } else {
        fprintf(stderr, "[P2P] Failed to queue message in DHT\n");
    }

    return result;
}

/**
 * Check offline messages using per-message DHT keys (NEW MODEL)
 * Fetches notifications and retrieves individual messages
 * @param ctx: P2P transport context
 * @param messages_received: Output number of messages delivered (optional)
 * @return: 0 on success, -1 on error
 */
int p2p_check_offline_messages(
    p2p_transport_t *ctx,
    size_t *messages_received)
{
    if (!ctx) {
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        printf("[P2P] Offline queue disabled, skipping check\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    printf("[P2P] Checking DHT for offline messages [PER-MESSAGE MODEL]...\n");

    // 1. Load contacts from database
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts || contacts->count == 0) {
        printf("[P2P] No contacts in database, skipping offline message check\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    printf("[P2P] Loaded %zu contacts for message filtering\n", contacts->count);

    // 2. Build array of sender fingerprints
    const char **sender_fps = (const char**)malloc(contacts->count * sizeof(char*));
    if (!sender_fps) {
        fprintf(stderr, "[P2P] Failed to allocate sender fingerprint array\n");
        contacts_db_free_list(contacts);
        if (messages_received) *messages_received = 0;
        return -1;
    }

    for (size_t i = 0; i < contacts->count; i++) {
        sender_fps[i] = contacts->contacts[i].identity;  // Fingerprint
    }

    // 3. Fetch messages using per-message model
    dht_permsg_t *messages = NULL;
    size_t count = 0;

    int result = dht_permsg_fetch_from_contacts(
        ctx->dht,
        ctx->config.identity,  // My fingerprint (recipient)
        sender_fps,
        contacts->count,
        &messages,
        &count
    );

    free(sender_fps);
    contacts_db_free_list(contacts);

    if (result != 0) {
        fprintf(stderr, "[P2P] Failed to retrieve offline messages\n");
        if (messages_received) *messages_received = 0;
        return -1;
    }

    if (count == 0) {
        printf("[P2P] No offline messages found\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    printf("[P2P] Found %zu offline messages\n", count);

    // 4. Deliver each message via callback
    size_t delivered_count = 0;
    for (size_t i = 0; i < count; i++) {
        dht_permsg_t *msg = &messages[i];

        printf("[P2P] Delivering offline message %zu/%zu from %.20s... (%zu bytes)\n",
               i + 1, count, msg->sender_fp, msg->ciphertext_len);

        // Deliver to application layer (messenger_p2p.c)
        if (ctx->message_callback) {
            ctx->message_callback(
                NULL,  // peer_pubkey (unknown for offline messages)
                msg->ciphertext,
                msg->ciphertext_len,
                ctx->callback_user_data
            );
            delivered_count++;
        } else {
            printf("[P2P] Warning: No message callback registered, skipping message\n");
        }
    }

    printf("[P2P] ✓ Delivered %zu/%zu offline messages\n", delivered_count, count);

    if (messages_received) {
        *messages_received = delivered_count;
    }

    dht_permsg_free_messages(messages, count);
    return 0;
}
