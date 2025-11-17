/*
 * DNA Messenger - Messages Module
 *
 * Message sending, receiving, listing, and conversation management.
 * Handles E2E encryption (Kyber1024 + AES-256-GCM), SQLite storage,
 * and conversation threading.
 */

#ifndef MESSENGER_MESSAGES_H
#define MESSENGER_MESSAGES_H

#include "messenger_core.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Send encrypted message to recipients
 *
 * Encrypts with Kyber1024 + AES-256-GCM, stores in SQLite, delivers via P2P.
 * Supports multi-recipient (each recipient gets independent encryption).
 * Falls back to DHT offline queue if P2P fails (7-day TTL).
 *
 * @param ctx: Messenger context
 * @param recipients: Array of recipient identity strings
 * @param recipient_count: Number of recipients
 * @param message: Plaintext message (NULL-terminated string)
 * @param group_id: Group ID (0 for direct messages, >0 for group messages)
 * @param message_type: Message type (MESSAGE_TYPE_CHAT or MESSAGE_TYPE_GROUP_INVITATION)
 * @return: 0 on success, -1 on error
 */
int messenger_send_message(
    messenger_context_t *ctx,
    const char **recipients,
    size_t recipient_count,
    const char *message,
    int group_id,
    int message_type
);

/**
 * List all received messages
 *
 * Displays messages from SQLite with sender, timestamp, preview.
 * Does NOT decrypt message content (use messenger_decrypt_message).
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_messages(messenger_context_t *ctx);

/**
 * List all sent messages
 *
 * Displays sent messages from SQLite with recipients, timestamp, preview.
 * Shows delivery status (delivered/pending).
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_sent_messages(messenger_context_t *ctx);

/**
 * Read message (mark as read)
 *
 * Marks message as read in SQLite, sends read receipt via P2P.
 * Does NOT decrypt message content (use messenger_decrypt_message).
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID from SQLite
 * @return: 0 on success, -1 on error
 */
int messenger_read_message(messenger_context_t *ctx, int message_id);

/**
 * Decrypt message content
 *
 * Decrypts message with Kyber1024 + AES-256-GCM.
 * Returns plaintext (caller must free).
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID from SQLite
 * @param plaintext_out: Output plaintext buffer (caller must free)
 * @param plaintext_len_out: Output plaintext length
 * @return: 0 on success, -1 on error
 */
int messenger_decrypt_message(messenger_context_t *ctx, int message_id,
                                char **plaintext_out, size_t *plaintext_len_out);

/**
 * Delete public key (stub - DHT migration pending)
 *
 * Legacy function for deleting keys from centralized keyserver.
 * Not yet implemented for DHT keyserver (keys are permanent).
 *
 * @param ctx: Messenger context
 * @param identity: Identity to delete
 * @return: -1 (not implemented)
 */
int messenger_delete_pubkey(messenger_context_t *ctx, const char *identity);

/**
 * Delete message from SQLite
 *
 * Permanently deletes message from local database.
 * Does NOT affect copies on other devices or DHT queue.
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID from SQLite
 * @return: 0 on success, -1 on error
 */
int messenger_delete_message(messenger_context_t *ctx, int message_id);

/**
 * Search messages by sender
 *
 * Lists all messages from specific sender.
 * Does NOT decrypt message content.
 *
 * @param ctx: Messenger context
 * @param sender: Sender identity
 * @return: 0 on success, -1 on error
 */
int messenger_search_by_sender(messenger_context_t *ctx, const char *sender);

/**
 * Show conversation with contact
 *
 * Displays threaded conversation (sent + received messages).
 * Chronological order, does NOT decrypt content.
 *
 * @param ctx: Messenger context
 * @param other_identity: Contact identity
 * @return: 0 on success, -1 on error
 */
int messenger_show_conversation(messenger_context_t *ctx, const char *other_identity);

/**
 * Get conversation messages (API version)
 *
 * Returns array of message_info_t structs for GUI/API use.
 * Caller must free array with messenger_free_messages().
 *
 * @param ctx: Messenger context
 * @param other_identity: Contact identity
 * @param messages_out: Output message array (caller must free)
 * @param count_out: Output message count
 * @return: 0 on success, -1 on error
 */
int messenger_get_conversation(messenger_context_t *ctx, const char *other_identity,
                                 message_info_t **messages_out, int *count_out);

/**
 * Search messages by date range
 *
 * Lists messages within date range (YYYY-MM-DD format).
 * Filters by sent/received flags.
 *
 * @param ctx: Messenger context
 * @param start_date: Start date (YYYY-MM-DD)
 * @param end_date: End date (YYYY-MM-DD)
 * @param include_sent: Include sent messages
 * @param include_received: Include received messages
 * @return: 0 on success, -1 on error
 */
int messenger_search_by_date(messenger_context_t *ctx, const char *start_date,
                              const char *end_date, bool include_sent, bool include_received);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_MESSAGES_H
