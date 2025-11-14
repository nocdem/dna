/**
 * Local Message Backup - SQLite Database
 *
 * Saves all messages to local SQLite database for data sovereignty.
 * Users own their message history, not dependent on remote PostgreSQL.
 *
 * Database Location: ~/.dna/messages.db
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
 * Message Structure (for retrieval)
 * NOTE: Messages stored ENCRYPTED in database for security
 */
typedef struct {
    int id;
    char sender[256];
    char recipient[256];
    uint8_t *encrypted_message;  // Encrypted ciphertext (binary)
    size_t encrypted_len;
    time_t timestamp;
    bool delivered;
    bool read;
    int status;  // 0=PENDING, 1=SENT, 2=FAILED
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
 * Check if message already exists in database (by ciphertext hash)
 *
 * Prevents duplicate messages from being stored (e.g., when polling DHT offline queue).
 *
 * @param ctx Backup context
 * @param encrypted_message Encrypted message ciphertext (binary)
 * @param encrypted_len Length of encrypted message
 * @return true if message exists, false otherwise
 */
bool message_backup_exists_ciphertext(message_backup_context_t *ctx,
                                       const uint8_t *encrypted_message,
                                       size_t encrypted_len);

/**
 * Save a message to local backup (ENCRYPTED)
 *
 * Stores the encrypted ciphertext for security. Messages remain encrypted at rest.
 * Decryption only happens in RAM when displaying to user.
 *
 * @param ctx Backup context
 * @param sender Sender identity
 * @param recipient Recipient identity
 * @param encrypted_message Encrypted message ciphertext (binary)
 * @param encrypted_len Length of encrypted message
 * @param timestamp Message timestamp
 * @param is_outgoing true if we sent it, false if we received it
 * @return 0 on success, -1 on error, 1 if already exists (duplicate skipped)
 */
int message_backup_save(message_backup_context_t *ctx,
                        const char *sender,
                        const char *recipient,
                        const uint8_t *encrypted_message,
                        size_t encrypted_len,
                        time_t timestamp,
                        bool is_outgoing);

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
 * Update message status
 *
 * @param ctx Backup context
 * @param message_id Message ID from database
 * @param status New status (0=PENDING, 1=SENT, 2=FAILED)
 * @return 0 on success, -1 on error
 */
int message_backup_update_status(message_backup_context_t *ctx, int message_id, int status);

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
 * Get database statistics
 *
 * @param ctx Backup context
 * @param total_messages_out Total messages stored
 * @param unread_count_out Number of unread messages
 * @param db_size_bytes_out Database file size in bytes
 * @return 0 on success, -1 on error
 */
int message_backup_get_stats(message_backup_context_t *ctx,
                              int *total_messages_out,
                              int *unread_count_out,
                              long *db_size_bytes_out);

/**
 * Export messages to JSON file
 *
 * Backup all messages to portable JSON format.
 *
 * @param ctx Backup context
 * @param output_path Path to JSON file (e.g., ~/backup.json)
 * @return 0 on success, -1 on error
 */
int message_backup_export_json(message_backup_context_t *ctx,
                                const char *output_path);

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
 * Close backup context
 *
 * @param ctx Backup context
 */
void message_backup_close(message_backup_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // MESSAGE_BACKUP_H
