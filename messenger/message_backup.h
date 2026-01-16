/**
 * Local Message Backup - SQLite Database
 *
 * Saves all messages to local SQLite database for data sovereignty.
 * Users own their message history with local-first storage.
 *
 * v0.3.0 flat structure: ~/.dna/db/messages.db
 *
 * @file message_backup.h
 * @author DNA Messenger Team
 * @date 2025-11-02
 */

#ifndef MESSAGE_BACKUP_H
#define MESSAGE_BACKUP_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Message Backup Context
 */
typedef struct message_backup_context message_backup_context_t;

/**
 * Message Types (Phase 6.2)
 */
#define MESSAGE_TYPE_CHAT 0
#define MESSAGE_TYPE_GROUP_INVITATION 1
#define MESSAGE_TYPE_CPUNK_TRANSFER 2

/**
 * Message Status Values
 */
#define MESSAGE_STATUS_PENDING   0  // Queued for sending
#define MESSAGE_STATUS_SENT      1  // Legacy (unused)
#define MESSAGE_STATUS_FAILED    2  // Temporary failure
#define MESSAGE_STATUS_DELIVERED 3  // Watermark confirmed
#define MESSAGE_STATUS_READ      4  // Read receipt received
#define MESSAGE_STATUS_STALE     5  // 30+ days old, never delivered (v0.4.59)

/**
 * Invitation Status (Phase 6.2 - only for MESSAGE_TYPE_GROUP_INVITATION)
 * NOTE: These match the enum in database/group_invitations.h
 */
#define MESSAGE_INVITATION_STATUS_PENDING 0
#define MESSAGE_INVITATION_STATUS_ACCEPTED 1
#define MESSAGE_INVITATION_STATUS_REJECTED 2

/**
 * Message Structure (for retrieval)
 * NOTE: Messages stored as PLAINTEXT in database (v14+)
 *       Database encryption will be handled by SQLCipher later
 */
typedef struct {
    int id;
    char sender[256];
    char recipient[256];
    char *plaintext;                      // Decrypted message content (UTF-8)
    char sender_fingerprint[129];         // Sender fingerprint hex (128 chars + null)
    time_t timestamp;
    bool delivered;
    bool read;
    int status;  // 0=PENDING (queued), 1=SENT (legacy), 2=FAILED, 3=DELIVERED (watermark confirmed), 4=READ, 5=STALE
    int group_id;  // Group ID (0 for direct messages, >0 for group messages) - Phase 5.2
    int message_type;  // 0=chat, 1=group_invitation - Phase 6.2
    int invitation_status;  // 0=pending, 1=accepted, 2=declined - Phase 6.2
    int retry_count;  // Number of send retry attempts (for failed messages)
    bool is_outgoing;  // true if we sent it, false if we received it
} backup_message_t;

/**
 * Initialize message backup system
 *
 * Creates ~/.dna/messages.db if it doesn't exist.
 * Opens connection to SQLite database.
 *
 * @param identity Current user identity (for multi-user support)
 * @return Backup context or NULL on error
 */
message_backup_context_t* message_backup_init(const char *identity);

/**
 * Check if message already exists in database (by sender + recipient + timestamp)
 *
 * Prevents duplicate messages from being stored (e.g., when polling DHT offline queue).
 *
 * @param ctx Backup context
 * @param sender_fp Sender fingerprint (hex string)
 * @param recipient Recipient identity
 * @param timestamp Message timestamp
 * @return true if message exists, false otherwise
 */
bool message_backup_exists(message_backup_context_t *ctx,
                           const char *sender_fp,
                           const char *recipient,
                           time_t timestamp);

/**
 * Save a message to local backup (PLAINTEXT)
 *
 * Stores the decrypted plaintext directly. Database encryption will be
 * handled at the SQLite level (SQLCipher) in a future update.
 *
 * @param ctx Backup context
 * @param sender Sender identity (fingerprint hex)
 * @param recipient Recipient identity (fingerprint hex)
 * @param plaintext Decrypted message content (UTF-8)
 * @param sender_fingerprint Sender's fingerprint (hex, 128 chars)
 * @param timestamp Message timestamp
 * @param is_outgoing true if we sent it, false if we received it
 * @param group_id Group ID (0 for direct messages, >0 for group) - Phase 5.2
 * @param message_type Message type (0=chat, 1=group_invitation) - Phase 6.2
 * @return 0 on success, -1 on error, 1 if already exists (duplicate skipped)
 */
int message_backup_save(message_backup_context_t *ctx,
                        const char *sender,
                        const char *recipient,
                        const char *plaintext,
                        const char *sender_fingerprint,
                        time_t timestamp,
                        bool is_outgoing,
                        int group_id,
                        int message_type,
                        uint64_t offline_seq);

/**
 * Mark message as delivered
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @return 0 on success, -1 on error
 */
int message_backup_mark_delivered(message_backup_context_t *ctx, int message_id);

/**
 * Mark message as read
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @return 0 on success, -1 on error
 */
int message_backup_mark_read(message_backup_context_t *ctx, int message_id);

/**
 * Get unread message count for a specific contact
 *
 * @param ctx Backup context
 * @param contact_identity Contact fingerprint
 * @return Unread count (>=0), or -1 on error
 */
int message_backup_get_unread_count(message_backup_context_t *ctx, const char *contact_identity);

/**
 * Update message status
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @param status New status (0=PENDING, 2=FAILED, 3=DELIVERED)
 * @return 0 on success, -1 on error
 */
int message_backup_update_status(message_backup_context_t *ctx, int message_id, int status);

/**
 * Increment retry count for a message
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @return 0 on success, -1 on error
 */
int message_backup_increment_retry_count(message_backup_context_t *ctx, int message_id);

/**
 * Mark message as stale (30+ days without delivery)
 *
 * Messages marked stale are shown differently in UI but not deleted.
 * User can still manually retry or delete stale messages.
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @return 0 on success, -1 on error
 */
int message_backup_mark_stale(message_backup_context_t *ctx, int message_id);

/**
 * Get message age in days
 *
 * Calculates days since message was created (timestamp field).
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @return Age in days (>=0), or -1 on error
 */
int message_backup_get_age_days(message_backup_context_t *ctx, int message_id);

/**
 * Get all pending/failed messages for retry
 *
 * Returns outgoing messages with status PENDING(0) or FAILED(2) that haven't
 * exceeded MAX_RETRIES. Used for automatic retry on identity load and DHT reconnect.
 *
 * @param ctx Backup context
 * @param max_retries Maximum retry attempts (0 = unlimited, no filtering by retry_count)
 * @param messages_out Array of messages (caller must free with message_backup_free_messages)
 * @param count_out Number of messages returned
 * @return 0 on success, -1 on error
 */
int message_backup_get_pending_messages(message_backup_context_t *ctx,
                                         int max_retries,
                                         backup_message_t **messages_out,
                                         int *count_out);

/**
 * Update message status by sender/recipient/timestamp
 *
 * Useful when message ID is not known (e.g., after async send)
 *
 * @param ctx Message backup context
 * @param sender Sender fingerprint
 * @param recipient Recipient fingerprint
 * @param timestamp Message timestamp
 * @param status New status (0=PENDING, 2=FAILED, 3=DELIVERED)
 * @return 0 on success, -1 on error
 */
int message_backup_update_status_by_key(
    message_backup_context_t *ctx,
    const char *sender,
    const char *recipient,
    time_t timestamp,
    int status
);

/**
 * Get the last inserted message ID
 *
 * @param ctx Message backup context
 * @return Last inserted message ID, or -1 on error
 */
int message_backup_get_last_id(message_backup_context_t *ctx);

/**
 * Get conversation history
 *
 * Returns all messages between current user and specified contact.
 *
 * @param ctx Backup context
 * @param contact_identity Contact identity
 * @param messages_out Array of messages (caller must free)
 * @param count_out Number of messages returned
 * @return 0 on success, -1 on error
 */
int message_backup_get_conversation(message_backup_context_t *ctx,
                                     const char *contact_identity,
                                     backup_message_t **messages_out,
                                     int *count_out);

/**
 * Get conversation history with pagination
 *
 * Returns a page of messages between current user and specified contact.
 * Messages are ordered by timestamp DESC (newest first) for efficient
 * loading in reverse-scroll chat UIs.
 *
 * @param ctx Backup context
 * @param contact_identity Contact identity
 * @param limit Max messages to return (page size, e.g. 50)
 * @param offset Number of messages to skip (for pagination)
 * @param messages_out Array of messages (caller must free)
 * @param count_out Number of messages returned in this page
 * @param total_out Total messages in conversation (for has_more check)
 * @return 0 on success, -1 on error
 */
int message_backup_get_conversation_page(message_backup_context_t *ctx,
                                          const char *contact_identity,
                                          int limit,
                                          int offset,
                                          backup_message_t **messages_out,
                                          int *count_out,
                                          int *total_out);

/**
 * Get group conversation history (Phase 5.2)
 *
 * Returns all messages for specified group ID.
 *
 * @param ctx Backup context
 * @param group_id Group ID
 * @param messages_out Array of messages (caller must free)
 * @param count_out Number of messages returned
 * @return 0 on success, -1 on error
 */
int message_backup_get_group_conversation(message_backup_context_t *ctx,
                                           int group_id,
                                           backup_message_t **messages_out,
                                           int *count_out);

/**
 * Get all recent conversations
 *
 * Returns list of contacts with last message timestamp.
 *
 * @param ctx Backup context
 * @param contacts_out Array of contact names (caller must free)
 * @param count_out Number of contacts
 * @return 0 on success, -1 on error
 */
int message_backup_get_recent_contacts(message_backup_context_t *ctx,
                                        char ***contacts_out,
                                        int *count_out);

/**
 * Search messages by sender/recipient
 *
 * NOTE: Cannot search message content since messages are stored encrypted.
 * Search only by sender or recipient identity.
 *
 * @param ctx Backup context
 * @param identity Sender or recipient identity to search
 * @param messages_out Array of messages (caller must free)
 * @param count_out Number of messages returned
 * @return 0 on success, -1 on error
 */
int message_backup_search_by_identity(message_backup_context_t *ctx,
                                       const char *identity,
                                       backup_message_t **messages_out,
                                       int *count_out);

/**
 * Delete a message by ID
 *
 * @param ctx Backup context
 * @param message_id Message ID to delete
 * @return 0 on success, -1 on error
 */
int message_backup_delete(message_backup_context_t *ctx, int message_id);

/**
 * Free message array
 *
 * @param messages Message array from get_conversation() or search()
 * @param count Number of messages
 */
void message_backup_free_messages(backup_message_t *messages, int count);

/**
 * Get database handle from backup context
 *
 * Used by modules that need direct database access (e.g., GEK subsystem).
 *
 * @param ctx Backup context
 * @return SQLite database handle or NULL if ctx is NULL
 */
void* message_backup_get_db(message_backup_context_t *ctx);

/**
 * ============================================================================
 * Offline Message Sequence Numbers (Watermark Pruning)
 * ============================================================================
 *
 * Track monotonic sequence numbers for offline message watermarks.
 * Each sender-recipient pair has independent sequence numbers.
 */

/**
 * Get and increment the next sequence number for a recipient
 *
 * Atomically returns current next_seq and increments it for next call.
 * Creates new entry if recipient doesn't exist in table.
 *
 * @param ctx Backup context
 * @param recipient Recipient fingerprint
 * @return Next seq_num to use (always >= 1)
 */
uint64_t message_backup_get_next_seq(message_backup_context_t *ctx, const char *recipient);

/**
 * Mark all outgoing messages as DELIVERED up to a sequence number
 *
 * Updates the status of all messages sent to a recipient where seq_num <= max_seq.
 * Used for delivery confirmation when watermark is received from recipient.
 *
 * Message status values:
 * - 0 = PENDING
 * - 1 = SENT
 * - 2 = FAILED
 * - 3 = DELIVERED (set by this function)
 * - 4 = READ
 *
 * @param ctx Backup context
 * @param sender My fingerprint (the sender)
 * @param recipient Recipient fingerprint
 * @param max_seq_num Maximum seq_num that was delivered
 * @return Number of messages updated, or -1 on error
 */
int message_backup_mark_delivered_up_to_seq(
    message_backup_context_t *ctx,
    const char *sender,
    const char *recipient,
    uint64_t max_seq_num
);

/**
 * Get unique recipients with pending outgoing messages
 *
 * Returns list of unique recipient fingerprints that have undelivered
 * outgoing messages (status=PENDING). Used to restore delivery trackers
 * on app startup.
 *
 * @param ctx Backup context
 * @param recipients_out Array to receive recipient fingerprints (caller allocates)
 * @param max_recipients Maximum number of recipients to return
 * @param count_out Receives actual count of recipients
 * @return 0 on success, -1 on error
 */
int message_backup_get_pending_recipients(
    message_backup_context_t *ctx,
    char recipients_out[][129],
    int max_recipients,
    int *count_out
);

/**
 * Close backup context
 *
 * @param ctx Backup context
 */
void message_backup_close(message_backup_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // MESSAGE_BACKUP_H
