/*
 * DNA Messenger - Status Module
 *
 * Message delivery status and read receipt management.
 * Simple database operations for tracking message status.
 */

#ifndef MESSENGER_STATUS_H
#define MESSENGER_STATUS_H

#include "messenger_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mark message as delivered
 *
 * Updates the message status in the local SQLite database to indicate
 * that the message has been delivered to the recipient.
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID to mark as delivered
 * @return: 0 on success, -1 on error
 */
int messenger_mark_delivered(messenger_context_t *ctx, int message_id);

/**
 * Mark all messages in conversation as read
 *
 * Called when recipient opens the conversation. Marks all incoming messages
 * from the specified sender as both delivered and read.
 *
 * @param ctx: Messenger context
 * @param sender_identity: The sender whose messages to mark as read
 * @return: 0 on success, -1 on error
 */
int messenger_mark_conversation_read(messenger_context_t *ctx, const char *sender_identity);

/**
 * Get unread message count for a specific contact
 *
 * @param ctx: Messenger context
 * @param contact_identity: Contact fingerprint
 * @return: Unread count (>=0), or -1 on error
 */
int messenger_get_unread_count(messenger_context_t *ctx, const char *contact_identity);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_STATUS_H
