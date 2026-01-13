/**
 * @file dna_group_outbox.h
 * @brief Group Message Outbox via DHT
 *
 * Feed-pattern group messaging with per-sender chunked storage:
 * - Message encrypted once with GEK (AES-256-GCM)
 * - Each sender stores at their OWN key (single-writer per key)
 * - Storage uses chunked ZSTD compression (unlimited size)
 * - Real-time notifications via dht_listen() per member
 * - Day-based buckets (7 days retention)
 *
 * Key Format:
 *   dna:group:<group_uuid>:out:<day_bucket>:<sender_fingerprint>
 *
 * Message ID Format:
 *   <sender_fingerprint>_<group_uuid>_<timestamp_ms>
 *
 * Part of DNA Messenger
 *
 * @date 2025-11-29
 * @updated 2026-01-13 - Per-sender keys, day buckets, chunked storage, dht_listen
 */

#ifndef DNA_GROUP_OUTBOX_H
#define DNA_GROUP_OUTBOX_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Maximum message text length */
#define DNA_GROUP_MSG_MAX_TEXT 8192

/** Maximum message ID length: fingerprint(128) + '_' + uuid(36) + '_' + timestamp(20) + null */
#define DNA_GROUP_MSG_ID_SIZE 200

/** TTL for group outbox buckets (7 days in seconds) */
#define DNA_GROUP_OUTBOX_TTL (7 * 24 * 3600)

/** Seconds per day for bucket calculation */
#define DNA_GROUP_OUTBOX_SECONDS_PER_DAY 86400

/** Maximum days to sync on catch-up (7 days) */
#define DNA_GROUP_OUTBOX_MAX_CATCHUP_DAYS 7

/** Key format for per-sender storage */
#define DNA_GROUP_OUTBOX_KEY_FMT "dna:group:%s:out:%lu:%s"

/** @deprecated Use DNA_GROUP_OUTBOX_MAX_CATCHUP_DAYS instead */
#define DNA_GROUP_OUTBOX_MAX_CATCHUP_BUCKETS (DNA_GROUP_OUTBOX_MAX_CATCHUP_DAYS * 24)

/** AES-256-GCM nonce size */
#define DNA_GROUP_OUTBOX_NONCE_SIZE 12

/** AES-256-GCM tag size */
#define DNA_GROUP_OUTBOX_TAG_SIZE 16

/** Dilithium5 signature size */
#define DNA_GROUP_OUTBOX_SIG_SIZE 4627

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum {
    DNA_GROUP_OUTBOX_OK = 0,
    DNA_GROUP_OUTBOX_ERR_NULL_PARAM = -1,
    DNA_GROUP_OUTBOX_ERR_NO_GEK = -2,
    DNA_GROUP_OUTBOX_ERR_ENCRYPT = -3,
    DNA_GROUP_OUTBOX_ERR_DECRYPT = -4,
    DNA_GROUP_OUTBOX_ERR_SIGN = -5,
    DNA_GROUP_OUTBOX_ERR_VERIFY = -6,
    DNA_GROUP_OUTBOX_ERR_DHT_PUT = -7,
    DNA_GROUP_OUTBOX_ERR_DHT_GET = -8,
    DNA_GROUP_OUTBOX_ERR_SERIALIZE = -9,
    DNA_GROUP_OUTBOX_ERR_DESERIALIZE = -10,
    DNA_GROUP_OUTBOX_ERR_ALLOC = -11,
    DNA_GROUP_OUTBOX_ERR_DB = -12,
    DNA_GROUP_OUTBOX_ERR_DUPLICATE = -13
} dna_group_outbox_error_t;

/*============================================================================
 * Data Structures
 *============================================================================*/

/**
 * @brief Single group message (encrypted with GEK)
 *
 * Stored in DHT at: dna:group:<group_uuid>:out:<hour_bucket>
 * Multiple senders write to same key with their value_id
 */
typedef struct {
    char message_id[DNA_GROUP_MSG_ID_SIZE];     /* sender_group_timestamp */
    char sender_fingerprint[129];               /* SHA3-512 fingerprint of sender */
    char group_uuid[37];                        /* UUID v4 of group */
    uint64_t timestamp_ms;                      /* Unix timestamp in milliseconds */
    uint32_t gsk_version;                       /* GEK version used for encryption */

    /* Encrypted payload (AES-256-GCM) */
    uint8_t nonce[DNA_GROUP_OUTBOX_NONCE_SIZE]; /* 12-byte nonce */
    uint8_t *ciphertext;                        /* Encrypted message content */
    size_t ciphertext_len;
    uint8_t tag[DNA_GROUP_OUTBOX_TAG_SIZE];     /* 16-byte auth tag */

    /* Dilithium5 signature over: message_id + timestamp_ms + ciphertext */
    uint8_t signature[DNA_GROUP_OUTBOX_SIG_SIZE];
    size_t signature_len;

    /* Decrypted content (populated by fetch, not stored in DHT) */
    char *plaintext;                            /* Decrypted message text (NULL until decrypted) */
} dna_group_message_t;

/**
 * @brief Day bucket containing messages from this sender
 *
 * Each sender has their own DHT key for each day.
 * Key format: dna:group:<uuid>:out:<day>:<sender_fp>
 */
typedef struct {
    char group_uuid[37];
    char sender_fingerprint[129];
    uint64_t day_bucket;                        /* unix_timestamp / 86400 */
    dna_group_message_t *messages;              /* Array of messages */
    size_t message_count;
    size_t allocated_count;
} dna_group_outbox_bucket_t;

/*============================================================================
 * Listen Context Structures (for real-time notifications)
 *============================================================================*/

/**
 * @brief Listen context for a single group member
 */
typedef struct {
    char sender_fingerprint[129];               /* Member's fingerprint */
    size_t listen_token;                        /* Token from dht_listen_ex() */
    bool active;                                /* Is listener active? */
} dna_group_member_listen_t;

/**
 * @brief Listen context for entire group
 *
 * Manages dht_listen() subscriptions for all members of a group.
 * Created by dna_group_outbox_subscribe(), freed by unsubscribe().
 */
typedef struct {
    char group_uuid[37];                        /* Group UUID */
    uint64_t current_day;                       /* Current day bucket being listened */
    dna_group_member_listen_t *members;         /* Array of member listeners */
    size_t member_count;                        /* Number of members */
    void (*on_new_message)(const char *group_uuid, size_t new_count, void *user_data);
    void *user_data;                            /* User data for callback */
} dna_group_listen_ctx_t;

/*============================================================================
 * Send API
 *============================================================================*/

/**
 * @brief Send a message to group outbox
 *
 * Flow:
 * 1. gek_load_active(group_uuid) -> get GEK + version
 * 2. hour_bucket = time(NULL) / 3600
 * 3. Generate message_id: sprintf("%s_%s_%lu", my_fingerprint, group_uuid, timestamp_ms)
 * 4. Encrypt plaintext with GEK (AES-256-GCM)
 * 5. Sign with Dilithium5
 * 6. dht_get_owner_value_id() -> my unique value_id
 * 7. dht_get() my existing messages at this key (my value_id slot)
 * 8. Append new message to my array
 * 9. dht_put_signed(key, my_messages_array, my_value_id, TTL)
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param sender_fingerprint Sender's SHA3-512 fingerprint
 * @param plaintext Message text to send
 * @param dilithium_privkey Sender's Dilithium5 private key (4896 bytes)
 * @param message_id_out Output: Generated message ID (optional, can be NULL)
 * @return DNA_GROUP_OUTBOX_OK on success, error code on failure
 */
int dna_group_outbox_send(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *sender_fingerprint,
    const char *plaintext,
    const uint8_t *dilithium_privkey,
    char *message_id_out
);

/*============================================================================
 * Receive API
 *============================================================================*/

/**
 * @brief Fetch messages from a single sender for a specific day
 *
 * Uses chunked DHT storage to fetch one sender's messages.
 * Messages are NOT decrypted (caller must decrypt with GEK).
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param sender_fingerprint Sender's fingerprint (128 hex chars)
 * @param day_bucket Day bucket (unix_timestamp / 86400, 0 = current day)
 * @param messages_out Output: Array of messages (caller must free with dna_group_outbox_free_messages)
 * @param count_out Output: Number of messages
 * @return DNA_GROUP_OUTBOX_OK on success, error code on failure
 */
int dna_group_outbox_fetch_sender(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *sender_fingerprint,
    uint64_t day_bucket,
    dna_group_message_t **messages_out,
    size_t *count_out
);

/**
 * @brief Fetch all messages from all members for a specific day
 *
 * Iterates through member list and fetches each sender's messages.
 * Messages are NOT decrypted (caller must decrypt with GEK).
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param day_bucket Day bucket (unix_timestamp / 86400, 0 = current day)
 * @param member_fps Array of member fingerprints (128 hex chars each)
 * @param member_count Number of members
 * @param messages_out Output: Array of messages (caller must free with dna_group_outbox_free_messages)
 * @param count_out Output: Number of messages
 * @return DNA_GROUP_OUTBOX_OK on success, error code on failure
 */
int dna_group_outbox_fetch(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    uint64_t day_bucket,
    const char **member_fps,
    size_t member_count,
    dna_group_message_t **messages_out,
    size_t *count_out
);

/**
 * @brief Sync all days since last sync for a group
 *
 * Flow:
 * 1. Get last_sync_day from group_sync_state table
 * 2. current_day = time(NULL) / 86400
 * 3. For each day from (last_sync_day + 1) to current_day:
 *    - Fetch all members' buckets via dht_chunked_fetch()
 *    - Dedupe against existing messages by message_id
 *    - Decrypt and store new messages in group_messages table
 * 4. Update last_sync_day in group_sync_state
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param member_fps Array of member fingerprints (128 hex chars each)
 * @param member_count Number of members
 * @param new_message_count_out Output: Number of new messages stored (optional)
 * @return DNA_GROUP_OUTBOX_OK on success, error code on failure
 */
int dna_group_outbox_sync(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char **member_fps,
    size_t member_count,
    size_t *new_message_count_out
);

/**
 * @brief Sync all groups the user is a member of
 *
 * Iterates through dht_group_members table and syncs each group.
 *
 * @param dht_ctx DHT context
 * @param my_fingerprint User's fingerprint
 * @param total_new_messages_out Output: Total new messages across all groups (optional)
 * @return DNA_GROUP_OUTBOX_OK on success, error code on failure
 */
int dna_group_outbox_sync_all(
    dht_context_t *dht_ctx,
    const char *my_fingerprint,
    size_t *total_new_messages_out
);

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * @brief Get current day bucket
 *
 * @return Current unix timestamp / 86400 (days since epoch)
 */
uint64_t dna_group_outbox_get_day_bucket(void);

/**
 * @brief Generate per-sender DHT key for group outbox
 *
 * Key format: dna:group:<group_uuid>:out:<day_bucket>:<sender_fingerprint>
 *
 * @param group_uuid Group UUID
 * @param day_bucket Day bucket (unix_timestamp / 86400)
 * @param sender_fingerprint Sender's fingerprint (128 hex chars)
 * @param key_out Output buffer for key string (must be at least 256 bytes)
 * @param key_out_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_make_sender_key(
    const char *group_uuid,
    uint64_t day_bucket,
    const char *sender_fingerprint,
    char *key_out,
    size_t key_out_size
);

/**
 * @brief Get current hour bucket
 * @deprecated Use dna_group_outbox_get_day_bucket() instead
 * @return Current unix timestamp / 3600
 */
uint64_t dna_group_outbox_get_hour_bucket(void);

/**
 * @brief Generate DHT key for group outbox (shared key format)
 * @deprecated Use dna_group_outbox_make_sender_key() instead
 *
 * Key format: dna:group:<group_uuid>:out:<hour_bucket>
 *
 * @param group_uuid Group UUID
 * @param hour_bucket Hour bucket (unix_timestamp / 3600)
 * @param key_out Output buffer for key string (must be at least 128 bytes)
 * @param key_out_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_make_key(
    const char *group_uuid,
    uint64_t hour_bucket,
    char *key_out,
    size_t key_out_size
);

/**
 * @brief Generate message ID
 *
 * Format: <sender_fingerprint>_<group_uuid>_<timestamp_ms>
 *
 * @param sender_fingerprint Sender's fingerprint
 * @param group_uuid Group UUID
 * @param timestamp_ms Timestamp in milliseconds
 * @param message_id_out Output buffer (must be DNA_GROUP_MSG_ID_SIZE bytes)
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_make_message_id(
    const char *sender_fingerprint,
    const char *group_uuid,
    uint64_t timestamp_ms,
    char *message_id_out
);

/**
 * @brief Get human-readable error message
 *
 * @param error Error code
 * @return Static string describing the error
 */
const char *dna_group_outbox_strerror(int error);

/*============================================================================
 * Database Functions (group_messages and group_sync_state tables)
 *============================================================================*/

/**
 * @brief Initialize group outbox tables
 *
 * Creates group_messages and group_sync_state tables if they don't exist.
 *
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_db_init(void);

/**
 * @brief Store a message in group_messages table
 *
 * @param msg Message to store
 * @return 0 on success, -1 on error, DNA_GROUP_OUTBOX_ERR_DUPLICATE if already exists
 */
int dna_group_outbox_db_store_message(const dna_group_message_t *msg);

/**
 * @brief Check if message exists by message_id
 *
 * @param message_id Message ID to check
 * @return 1 if exists, 0 if not, -1 on error
 */
int dna_group_outbox_db_message_exists(const char *message_id);

/**
 * @brief Get messages for a group (ordered by timestamp)
 *
 * @param group_uuid Group UUID
 * @param limit Maximum messages to return (0 = no limit)
 * @param offset Offset for pagination
 * @param messages_out Output: Array of messages (caller frees with dna_group_outbox_free_messages)
 * @param count_out Output: Number of messages
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_db_get_messages(
    const char *group_uuid,
    size_t limit,
    size_t offset,
    dna_group_message_t **messages_out,
    size_t *count_out
);

/**
 * @brief Get last sync day for a group
 *
 * @param group_uuid Group UUID
 * @param last_sync_day_out Output: Last synced day bucket (0 if never synced)
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_db_get_last_sync_day(
    const char *group_uuid,
    uint64_t *last_sync_day_out
);

/**
 * @brief Update last sync day for a group
 *
 * @param group_uuid Group UUID
 * @param last_sync_day Day bucket that was synced
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_db_set_last_sync_day(
    const char *group_uuid,
    uint64_t last_sync_day
);

/**
 * @brief Get last sync hour for a group
 * @deprecated Use dna_group_outbox_db_get_last_sync_day() instead
 */
int dna_group_outbox_db_get_last_sync_hour(
    const char *group_uuid,
    uint64_t *last_sync_hour_out
);

/**
 * @brief Update last sync hour for a group
 * @deprecated Use dna_group_outbox_db_set_last_sync_day() instead
 */
int dna_group_outbox_db_set_last_sync_hour(
    const char *group_uuid,
    uint64_t last_sync_hour
);

/*============================================================================
 * Listen API (Real-time notifications via DHT listen)
 *============================================================================*/

/**
 * @brief Subscribe to group for real-time message notifications
 *
 * Creates dht_listen() subscriptions for each member's chunk:0 key.
 * Callback fires when any member publishes new messages.
 *
 * @param dht_ctx DHT context
 * @param group_uuid Group UUID
 * @param member_fps Array of member fingerprints
 * @param member_count Number of members
 * @param on_new_message Callback when new messages arrive
 * @param user_data User data for callback
 * @param ctx_out Output: Listen context (caller must free with unsubscribe)
 * @return 0 on success, error code on failure
 */
int dna_group_outbox_subscribe(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char **member_fps,
    size_t member_count,
    void (*on_new_message)(const char *group_uuid, size_t new_count, void *user_data),
    void *user_data,
    dna_group_listen_ctx_t **ctx_out
);

/**
 * @brief Unsubscribe from group
 *
 * Cancels all dht_listen() subscriptions and frees context.
 *
 * @param dht_ctx DHT context (may be NULL if already freed)
 * @param ctx Listen context to free
 */
void dna_group_outbox_unsubscribe(
    dht_context_t *dht_ctx,
    dna_group_listen_ctx_t *ctx
);

/**
 * @brief Check and rotate listeners if day changed
 *
 * Call this periodically (e.g., every minute).
 * If day changed, cancels old listeners and subscribes to new day.
 *
 * @param dht_ctx DHT context
 * @param ctx Listen context
 * @return 1 if rotated, 0 if no change, -1 on error
 */
int dna_group_outbox_check_day_rotation(
    dht_context_t *dht_ctx,
    dna_group_listen_ctx_t *ctx
);

/**
 * @brief Add listener for a new group member
 *
 * Call when a member joins the group.
 *
 * @param dht_ctx DHT context
 * @param ctx Listen context
 * @param member_fingerprint New member's fingerprint
 * @return 0 on success, -1 on error
 */
int dna_group_outbox_add_member_listener(
    dht_context_t *dht_ctx,
    dna_group_listen_ctx_t *ctx,
    const char *member_fingerprint
);

/**
 * @brief Remove listener for a departing member
 *
 * Call when a member leaves the group.
 *
 * @param dht_ctx DHT context
 * @param ctx Listen context
 * @param member_fingerprint Departing member's fingerprint
 * @return 0 on success, -1 if not found
 */
int dna_group_outbox_remove_member_listener(
    dht_context_t *dht_ctx,
    dna_group_listen_ctx_t *ctx,
    const char *member_fingerprint
);

/*============================================================================
 * Memory Management
 *============================================================================*/

/**
 * @brief Free a single message structure
 *
 * @param msg Message to free
 */
void dna_group_outbox_free_message(dna_group_message_t *msg);

/**
 * @brief Free an array of messages
 *
 * @param messages Array of messages
 * @param count Number of messages
 */
void dna_group_outbox_free_messages(dna_group_message_t *messages, size_t count);

/**
 * @brief Free a bucket structure
 *
 * @param bucket Bucket to free
 */
void dna_group_outbox_free_bucket(dna_group_outbox_bucket_t *bucket);

/**
 * @brief Set database handle for group outbox
 *
 * Must be called during messenger initialization with the SQLite database handle.
 *
 * @param db SQLite3 database handle (from message_backup_get_db)
 */
void dna_group_outbox_set_db(void *db);

#ifdef __cplusplus
}
#endif

#endif /* DNA_GROUP_OUTBOX_H */
