/*
 * DNA Messenger - Status Module Implementation
 */

#include "status.h"
#include <stdio.h>
#include <string.h>
#include "../message_backup.h"
#include "../crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_STATUS"

// ============================================================================
// MESSAGE STATUS / READ RECEIPTS
// ============================================================================

int messenger_mark_delivered(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Mark message as delivered in SQLite local database
    int result = message_backup_mark_delivered(ctx->backup_ctx, message_id);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Mark delivered failed from SQLite");
        return -1;
    }

    return 0;
}

int messenger_mark_conversation_read(messenger_context_t *ctx, const char *sender_identity) {
    if (!ctx || !sender_identity) {
        return -1;
    }

    // Get all messages in conversation with sender
    backup_message_t *messages = NULL;
    int count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx, sender_identity, &messages, &count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Mark conversation read failed from SQLite");
        return -1;
    }

    // Mark all incoming messages (where we are recipient) as read
    for (int i = 0; i < count; i++) {
        if (strcmp(messages[i].recipient, ctx->identity) == 0 && !messages[i].read) {
            // First ensure it's marked as delivered
            if (!messages[i].delivered) {
                message_backup_mark_delivered(ctx->backup_ctx, messages[i].id);
            }
            // Then mark as read
            message_backup_mark_read(ctx->backup_ctx, messages[i].id);
        }
    }

    message_backup_free_messages(messages, count);
    return 0;
}

int messenger_get_unread_count(messenger_context_t *ctx, const char *contact_identity) {
    if (!ctx || !contact_identity) {
        return -1;
    }

    return message_backup_get_unread_count(ctx->backup_ctx, contact_identity);
}
