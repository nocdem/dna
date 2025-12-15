/*
 * DNA Messenger - CLI Messenger Module
 *
 * Storage Architecture:
 * - Private keys: ~/.dna/<fingerprint>/keys/<fingerprint>.dsa, .kem (filesystem)
 * - Public keys: DHT-based keyserver (decentralized, permanent)
 * - Messages: SQLite local database (user owns their data)
 *
 * Phase 9.1b: Hybrid P2P Transport
 * - P2P direct messaging when both peers online (via DHT + TCP)
 * - SQLite local storage for all messages (no server dependency)
 */

#ifndef MESSENGER_H
#define MESSENGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dna_api.h"
#include "p2p/p2p_transport.h"
#include "message_backup.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// MESSENGER CONTEXT
// ============================================================================

// Public key cache entry
typedef struct {
    char *identity;
    uint8_t *signing_pubkey;
    size_t signing_pubkey_len;
    uint8_t *encryption_pubkey;
    size_t encryption_pubkey_len;
} pubkey_cache_entry_t;

#define PUBKEY_CACHE_SIZE 100

/**
 * Messenger Context
 * Manages SQLite local database and DNA API context
 */
typedef struct {
    char *identity;              // User's identity input (name or fingerprint, for file access)
    char *fingerprint;           // SHA3-512 fingerprint (128 hex chars) - canonical identity (Phase 4)
    message_backup_context_t *backup_ctx;  // SQLite local message storage
    dna_context_t *dna_ctx;      // DNA API context

    // P2P Transport (Phase 9.1b: Hybrid P2P messaging)
    p2p_transport_t *p2p_transport;  // P2P transport layer (NULL if disabled)
    bool p2p_enabled;                 // Enable/disable P2P messaging

    // Public key cache (API fetch caching)
    pubkey_cache_entry_t cache[PUBKEY_CACHE_SIZE];
    int cache_count;
} messenger_context_t;

/**
 * Message Info
 * Represents a single message in a conversation
 */
typedef struct {
    int id;                      // Message ID
    char *sender;                // Sender identity
    char *recipient;             // Recipient identity
    char *timestamp;             // Timestamp string
    char *status;                // Message status: "sent", "delivered", "read"
    char *delivered_at;          // Delivery timestamp (NULL if not delivered)
    char *read_at;               // Read timestamp (NULL if not read)
    char *plaintext;             // Decrypted message text (NULL if not decrypted)
    int message_type;            // Message type: 0=chat, 1=group_invitation (Phase 6.2)
} message_info_t;

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize messenger context
 *
 * Opens local SQLite database at ~/.dna/messages.db
 * Creates database if it doesn't exist.
 *
 * @param identity: User's identity name
 * @return: Messenger context, or NULL on error
 */
messenger_context_t* messenger_init(const char *identity);

/**
 * Free messenger context
 *
 * @param ctx: Messenger context to free
 */
void messenger_free(messenger_context_t *ctx);

/**
 * Load DHT identity and reinitialize DHT singleton with permanent identity
 *
 * This function loads the user's permanent DHT identity (RSA-2048) from
 * encrypted backup (local file or DHT) and reinitializes the DHT singleton.
 *
 * @param fingerprint: User's fingerprint (128 hex chars)
 * @return: 0 on success, -1 on error (non-fatal)
 */
int messenger_load_dht_identity(const char *fingerprint);

// ============================================================================
// KEY GENERATION
// ============================================================================

/**
 * Generate new key pair for identity
 *
 * Creates:
 * - ~/.dna/<fingerprint>/keys/<fingerprint>.dsa (private signing key)
 * - ~/.dna/<fingerprint>/keys/<fingerprint>.kem (private encryption key)
 * - Publishes public keys to DHT keyserver
 *
 * @param ctx: Messenger context
 * @param identity: Identity name (e.g., "alice")
 * @return: 0 on success, -1 on error
 */
int messenger_generate_keys(messenger_context_t *ctx, const char *identity);

/**
 * Generate key pair from BIP39-derived seeds (non-interactive, for GUI)
 *
 * Generates keys deterministically from provided seeds without user prompts.
 * Creates fingerprint-based identity (no name required).
 * Keys are saved as <data_dir>/<fingerprint>.dsa and <data_dir>/<fingerprint>.kem
 * Wallet keys are derived on-demand from mnemonic (no plaintext wallet files).
 * Directory structure: ~/.dna/<fingerprint>/keys/
 *
 * @param name: Identity name (optional display name, can be NULL)
 * @param signing_seed: 32-byte seed for Dilithium5 key generation
 * @param encryption_seed: 32-byte seed for Kyber1024 key generation
 * @param wallet_seed: 32-byte seed for Cellframe wallet (DEPRECATED, use mnemonic)
 * @param master_seed: 64-byte BIP39 master seed for multi-chain wallets (optional, can be NULL)
 * @param mnemonic: Space-separated BIP39 mnemonic (for recovery, optional)
 * @param data_dir: Base directory (e.g., ~/.dna)
 * @param password: Password to encrypt keys (NULL for no encryption - not recommended)
 * @param fingerprint_out: Output buffer for 128-char fingerprint (must be 129 bytes for null terminator)
 * @return: 0 on success, -1 on error
 */
int messenger_generate_keys_from_seeds(
    const char *name,
    const uint8_t *signing_seed,
    const uint8_t *encryption_seed,
    const uint8_t *wallet_seed,
    const uint8_t *master_seed,
    const char *mnemonic,
    const char *data_dir,
    const char *password,
    char *fingerprint_out
);

/**
 * Register a human-readable name for an existing fingerprint identity
 *
 * Uploads public keys to DHT keyserver with both forward and reverse mappings:
 * - Forward: name → keys (so others can find you)
 * - Reverse: fingerprint → name (for display purposes)
 *
 * Payment integration: Free for now (will require 1 CPUNK in future)
 *
 * @param ctx: Messenger context
 * @param fingerprint: 128-char fingerprint of existing identity
 * @param desired_name: Human-readable name to register (3-20 chars, alphanumeric + underscore)
 * @return: 0 on success, -1 on error
 */
int messenger_register_name(
    messenger_context_t *ctx,
    const char *fingerprint,
    const char *desired_name
);

/**
 * Restore key pair from BIP39 recovery seed
 *
 * Prompts user for 24-word mnemonic and optional passphrase.
 * Regenerates keys deterministically and uploads to keyserver.
 *
 * @param ctx: Messenger context
 * @param identity: Identity name (e.g., "alice")
 * @return: 0 on success, -1 on error
 */
int messenger_restore_keys(messenger_context_t *ctx, const char *identity);

/**
 * Restore key pair from file containing BIP39 recovery seed
 *
 * File format: "word1 word2 word3 ... word24 [passphrase]"
 * Passphrase is optional (on same line after 24 words).
 *
 * @param ctx: Messenger context
 * @param identity: Identity name (e.g., "alice")
 * @param seed_file: Path to file containing seed phrase
 * @return: 0 on success, -1 on error
 */
int messenger_restore_keys_from_file(messenger_context_t *ctx, const char *identity, const char *seed_file);

// ============================================================================
// FINGERPRINT UTILITIES (Phase 4: Fingerprint-First Identity)
// ============================================================================

/**
 * Compute fingerprint from Dilithium5 public key in a key file
 *
 * Reads the .dsa file and computes SHA3-512(dilithium_pubkey).
 * This is the primary identity in the fingerprint-first model.
 *
 * @param identity: Fingerprint (used to locate ~/.dna/<fingerprint>/keys/<fingerprint>.dsa)
 * @param fingerprint_out: Output buffer (must be 129 bytes: 128 hex + null)
 * @return: 0 on success, -1 on error
 */
int messenger_compute_identity_fingerprint(const char *identity, char *fingerprint_out);

/**
 * Check if a string is a valid fingerprint (128 hex characters)
 *
 * @param str: String to check
 * @return: true if valid fingerprint, false otherwise
 */
bool messenger_is_fingerprint(const char *str);

/**
 * Get display name for an identity (fingerprint or name)
 *
 * Resolution order:
 * 1. If input is 128-char fingerprint → check DHT for registered name
 * 2. If registered name found → return name
 * 3. Otherwise → return shortened fingerprint (first 16 chars + "...")
 *
 * @param ctx: Messenger context
 * @param identifier: Fingerprint or DNA name
 * @param display_name_out: Output buffer (must be at least 256 bytes)
 * @return: 0 on success, -1 on error
 */
int messenger_get_display_name(messenger_context_t *ctx, const char *identifier, char *display_name_out);

// ============================================================================
// PUBLIC KEY MANAGEMENT (keyserver table)
// ============================================================================

/**
 * Store public key in keyserver (FINGERPRINT-FIRST architecture)
 *
 * Called when generating or importing a key pair.
 * Publishes keys to DHT with fingerprint as PRIMARY KEY.
 *
 * @param ctx: Messenger context
 * @param fingerprint: SHA3-512 fingerprint (128 hex chars) - PRIMARY KEY
 * @param display_name: Optional human-readable name (can be NULL)
 * @param signing_pubkey: Dilithium5 public key (2592 bytes)
 * @param signing_pubkey_len: Signing key length
 * @param encryption_pubkey: Kyber1024 public key (1568 bytes)
 * @param encryption_pubkey_len: Encryption key length
 * @return: 0 on success, -1 on error
 */
int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *fingerprint,
    const char *display_name,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
);

/**
 * Load public key from keyserver
 *
 * @param ctx: Messenger context
 * @param identity: Key owner's identity
 * @param signing_pubkey_out: Output signing key (caller must free)
 * @param signing_pubkey_len_out: Output signing key length
 * @param encryption_pubkey_out: Output encryption key (caller must free)
 * @param encryption_pubkey_len_out: Output encryption key length
 * @return: 0 on success, -1 on error
 */
int messenger_load_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **signing_pubkey_out,
    size_t *signing_pubkey_len_out,
    uint8_t **encryption_pubkey_out,
    size_t *encryption_pubkey_len_out,
    char *fingerprint_out  // NEW: Output fingerprint (129 bytes: 128 hex + null), can be NULL
);

/**
 * List all public keys in keyserver
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_pubkeys(messenger_context_t *ctx);

/**
 * Get contact list (identities from keyserver)
 *
 * Returns array of identity strings. Caller must free each string and the array.
 *
 * @param ctx: Messenger context
 * @param identities_out: Output array of identity strings (caller must free)
 * @param count_out: Number of identities returned
 * @return: 0 on success, -1 on error
 */
int messenger_get_contact_list(messenger_context_t *ctx, char ***identities_out, int *count_out);

// DHT contact list synchronization
int messenger_sync_contacts_to_dht(messenger_context_t *ctx);
int messenger_sync_contacts_from_dht(messenger_context_t *ctx);
int messenger_contacts_auto_sync(messenger_context_t *ctx);

// NOTE: messenger_delete_pubkey() removed - DHT keys are PERMANENT by design
// (see CLAUDE.md:205 - Identity keys persist indefinitely for security)

// ============================================================================
// MESSAGE OPERATIONS (messages table)
// ============================================================================

/**
 * Send message to recipient(s)
 *
 * Encrypts message and stores in messages table.
 * Sender is automatically added as first recipient so they can decrypt their own sent messages.
 * In Phase 3, messages are stored in PostgreSQL (ready for network access).
 *
 * @param ctx: Messenger context
 * @param recipients: Array of recipient identities (1-254, sender is added automatically)
 * @param recipient_count: Number of recipients (1-254)
 * @param message: Plaintext message
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
 * List messages for current user
 *
 * Shows messages where recipient = current identity
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_messages(messenger_context_t *ctx);

/**
 * List sent messages
 *
 * Shows messages where sender = current identity
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_sent_messages(messenger_context_t *ctx);

/**
 * Read and decrypt specific message
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID
 * @return: 0 on success, -1 on error
 */
int messenger_read_message(messenger_context_t *ctx, int message_id);

/**
 * Decrypt a message and return plaintext
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID
 * @param plaintext_out: Output plaintext (caller must free)
 * @param plaintext_len_out: Output plaintext length
 * @return: 0 on success, -1 on error
 */
int messenger_decrypt_message(messenger_context_t *ctx, int message_id,
                                char **plaintext_out, size_t *plaintext_len_out);

/**
 * Delete message
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID
 * @return: 0 on success, -1 on error
 */
int messenger_delete_message(messenger_context_t *ctx, int message_id);

/**
 * Search messages by sender
 *
 * Shows all messages from a specific sender to current user
 *
 * @param ctx: Messenger context
 * @param sender: Sender's identity to search for
 * @return: 0 on success, -1 on error
 */
int messenger_search_by_sender(messenger_context_t *ctx, const char *sender);

/**
 * Show conversation with another user
 *
 * Shows all messages exchanged with another user (both sent and received),
 * sorted by timestamp
 *
 * @param ctx: Messenger context
 * @param other_identity: The other person's identity
 * @return: 0 on success, -1 on error
 */
int messenger_show_conversation(messenger_context_t *ctx, const char *other_identity);

/**
 * Get conversation with another user
 *
 * Returns array of messages exchanged with another user (both sent and received),
 * sorted by timestamp. Messages are NOT decrypted (plaintext field is NULL).
 * Caller must free the array using messenger_free_messages().
 *
 * @param ctx: Messenger context
 * @param other_identity: The other person's identity
 * @param messages_out: Output array of message_info_t (caller must free)
 * @param count_out: Number of messages returned
 * @return: 0 on success, -1 on error
 */
int messenger_get_conversation(messenger_context_t *ctx, const char *other_identity,
                                 message_info_t **messages_out, int *count_out);

/**
 * Free message array
 *
 * @param messages: Array of message_info_t to free
 * @param count: Number of messages in array
 */
void messenger_free_messages(message_info_t *messages, int count);

/**
 * Search messages by date range
 *
 * Shows messages (sent or received) within a specific date range
 *
 * @param ctx: Messenger context
 * @param start_date: Start date (format: "YYYY-MM-DD") or NULL for no start limit
 * @param end_date: End date (format: "YYYY-MM-DD") or NULL for no end limit
 * @param include_sent: Include sent messages
 * @param include_received: Include received messages
 * @return: 0 on success, -1 on error
 */
int messenger_search_by_date(messenger_context_t *ctx, const char *start_date,
                              const char *end_date, bool include_sent, bool include_received);

// ============================================================================
// MESSAGE STATUS / READ RECEIPTS
// ============================================================================

/**
 * Mark message as delivered
 *
 * Called when recipient fetches the message from server.
 * Updates status from 'sent' to 'delivered' and sets delivered_at timestamp.
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID to mark as delivered
 * @return: 0 on success, -1 on error
 */
int messenger_mark_delivered(messenger_context_t *ctx, int message_id);

/**
 * Mark all messages in conversation as read
 *
 * Called when recipient opens the conversation.
 * Updates status from 'sent'/'delivered' to 'read' and sets read_at timestamp.
 *
 * @param ctx: Messenger context
 * @param sender_identity: The sender whose messages to mark as read
 * @return: 0 on success, -1 on error
 */
int messenger_mark_conversation_read(messenger_context_t *ctx, const char *sender_identity);

// ============================================================================
// GROUP MANAGEMENT
// ============================================================================

/**
 * Group Info
 * Represents a group with its metadata
 */
typedef struct {
    int id;                      // Group ID
    char *name;                  // Group name
    char *description;           // Optional description
    char *creator;               // Creator identity
    char *created_at;            // Creation timestamp
    int member_count;            // Number of members
} group_info_t;

/**
 * Create a new group
 *
 * @param ctx: Messenger context
 * @param name: Group name
 * @param description: Optional group description (can be NULL)
 * @param members: Array of member identities (excluding creator, who is added automatically)
 * @param member_count: Number of members
 * @param group_id_out: Output group ID
 * @return: 0 on success, -1 on error
 */
int messenger_create_group(
    messenger_context_t *ctx,
    const char *name,
    const char *description,
    const char **members,
    size_t member_count,
    int *group_id_out
);

/**
 * Get list of all groups current user belongs to
 *
 * @param ctx: Messenger context
 * @param groups_out: Output array of group_info_t (caller must free with messenger_free_groups)
 * @param count_out: Number of groups returned
 * @return: 0 on success, -1 on error
 */
int messenger_get_groups(
    messenger_context_t *ctx,
    group_info_t **groups_out,
    int *count_out
);

/**
 * Get group info by ID
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @param group_out: Output group_info_t (caller must free fields)
 * @return: 0 on success, -1 on error
 */
int messenger_get_group_info(
    messenger_context_t *ctx,
    int group_id,
    group_info_t *group_out
);

/**
 * Get members of a specific group
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @param members_out: Output array of identity strings (caller must free)
 * @param count_out: Number of members returned
 * @return: 0 on success, -1 on error
 */
int messenger_get_group_members(
    messenger_context_t *ctx,
    int group_id,
    char ***members_out,
    int *count_out
);

/**
 * Add member to group
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @param member: Identity to add
 * @return: 0 on success, -1 on error
 */
int messenger_add_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
);

/**
 * Remove member from group
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @param member: Identity to remove
 * @return: 0 on success, -1 on error
 */
int messenger_remove_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
);

/**
 * Leave a group
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @return: 0 on success, -1 on error
 */
int messenger_leave_group(
    messenger_context_t *ctx,
    int group_id
);

/**
 * Delete a group (creator only)
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @return: 0 on success, -1 on error
 */
int messenger_delete_group(
    messenger_context_t *ctx,
    int group_id
);

/**
 * Update group info (name, description)
 *
 * @param ctx: Messenger context
 * @param group_id: Group ID
 * @param name: New name (NULL to keep current)
 * @param description: New description (NULL to keep current)
 * @return: 0 on success, -1 on error
 */
int messenger_update_group_info(
    messenger_context_t *ctx,
    int group_id,
    const char *name,
    const char *description
);

/**
 * Send group invitation to a user
 *
 * @param ctx: Messenger context
 * @param group_uuid: Group UUID
 * @param recipient: Identity to invite
 * @param group_name: Group name
 * @param member_count: Current member count
 * @return: 0 on success, -1 on error
 */
int messenger_send_group_invitation(
    messenger_context_t *ctx,
    const char *group_uuid,
    const char *recipient,
    const char *group_name,
    int member_count
);

/**
 * Accept a group invitation
 *
 * @param ctx: Messenger context
 * @param group_uuid: Group UUID to accept
 * @return: 0 on success, -1 on error
 */
int messenger_accept_group_invitation(
    messenger_context_t *ctx,
    const char *group_uuid
);

/**
 * Reject a group invitation
 *
 * @param ctx: Messenger context
 * @param group_uuid: Group UUID to reject
 * @return: 0 on success, -1 on error
 */
int messenger_reject_group_invitation(
    messenger_context_t *ctx,
    const char *group_uuid
);

/**
 * Sync groups and invitations from DHT and offline messages
 *
 * This function:
 * - Checks for offline messages
 * - Scans recent messages for group invitations
 * - Stores new invitations in local database
 * - Should be called on login and periodically
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_sync_groups(messenger_context_t *ctx);

/**
 * Send message to a group (Phase 6.2)
 *
 * Looks up group members from DHT and sends encrypted message to all members
 * using multi-recipient encryption (Kyber1024 + AES-256-GCM).
 *
 * @param ctx: Messenger context
 * @param group_uuid: Group UUID (36 chars)
 * @param message: Plaintext message
 * @return: 0 on success, -1 on error
 */
int messenger_send_group_message(
    messenger_context_t *ctx,
    const char *group_uuid,
    const char *message
);

/**
 * Load group conversation messages (Phase 6.2)
 *
 * Retrieves all messages for a specific group from local SQLite database.
 * Messages are returned ENCRYPTED - caller must decrypt each message.
 *
 * @param ctx: Messenger context
 * @param group_uuid: Group UUID (36 chars)
 * @param messages_out: Output array of messages (caller must free with message_backup_free_messages)
 * @param count_out: Number of messages returned
 * @return: 0 on success, -1 on error
 */
int messenger_load_group_messages(
    messenger_context_t *ctx,
    const char *group_uuid,
    backup_message_t **messages_out,
    int *count_out
);

/**
 * Free group array
 *
 * @param groups: Array of group_info_t to free
 * @param count: Number of groups in array
 */
void messenger_free_groups(group_info_t *groups, int count);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_H
