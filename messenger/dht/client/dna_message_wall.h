/*
 * DNA Message Wall - Public Message Board via DHT
 *
 * Storage Model (Owner-Namespaced via Chunked):
 * - Each poster's messages stored at: wall_owner:wall:poster_fingerprint (chunked)
 * - Contributors index at: wall_owner:wall:contributors (multi-owner, small)
 * - Rotation: Keep latest 100 messages per poster
 * - TTL: 30 days
 */

#ifndef DNA_MESSAGE_WALL_H
#define DNA_MESSAGE_WALL_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNA_MESSAGE_WALL_MAX_MESSAGES 100
#define DNA_MESSAGE_WALL_MAX_TEXT_LEN 1024
#define DNA_MESSAGE_WALL_TTL_SECONDS (30 * 24 * 60 * 60)  // 30 days

// Single message structure
typedef struct {
    char post_id[160];        // Unique ID: <fingerprint>_<timestamp> (128+1+19+null)
    char text[DNA_MESSAGE_WALL_MAX_TEXT_LEN];
    uint64_t timestamp;
    uint8_t signature[4627];  // Dilithium5 signature (Category 5)
    size_t signature_len;

    // Threading support (3-level: post → comment → reply)
    char reply_to[160];       // Parent post_id (empty for top-level posts)
    int reply_depth;          // 0=post, 1=comment, 2=reply (max depth enforced)
    int reply_count;          // Number of direct replies (for UI display)

    // Community voting (optional - loaded separately from DHT)
    int upvotes;              // Total upvotes (0 if not loaded)
    int downvotes;            // Total downvotes (0 if not loaded)
} dna_wall_message_t;

// Message wall structure (array of messages)
typedef struct {
    char fingerprint[129];  // SHA3-512 (128 hex chars + null)
    dna_wall_message_t *messages;
    size_t message_count;
    size_t allocated_count;
} dna_message_wall_t;

/**
 * @brief Post a message to user's public message wall
 *
 * This function:
 * 1. Loads existing wall from DHT (if any)
 * 2. Adds new message with Dilithium5 signature
 * 3. Rotates to keep latest 100 messages
 * 4. Re-publishes to DHT with 30-day TTL
 *
 * Threading support:
 * - Pass NULL or empty string for reply_to to create top-level post
 * - Pass parent post_id to create reply (3-level max: post → comment → reply)
 * - reply_depth automatically calculated (0=post, 1=comment, 2=reply)
 *
 * @param dht_ctx DHT context
 * @param wall_owner_fingerprint Wall owner's SHA3-512 fingerprint (where wall is stored)
 * @param poster_fingerprint Poster's SHA3-512 fingerprint (who is posting)
 * @param message_text Message text (max 1024 chars)
 * @param private_key Dilithium5 private key for signing (4896 bytes)
 * @param reply_to Parent post_id for threading (NULL or "" for top-level post)
 * @return 0 on success, -1 on error, -2 if max depth exceeded
 */
int dna_post_to_wall(dht_context_t *dht_ctx,
                     const char *wall_owner_fingerprint,
                     const char *poster_fingerprint,
                     const char *message_text,
                     const uint8_t *private_key,
                     const char *reply_to);

/**
 * @brief Load user's public message wall from DHT
 *
 * This function:
 * 1. Queries DHT for wall data
 * 2. Parses JSON array of messages
 * 3. Verifies all Dilithium5 signatures
 * 4. Returns wall structure (caller must free)
 *
 * @param dht_ctx DHT context
 * @param fingerprint User's SHA3-512 fingerprint (128 hex chars)
 * @param wall_out Output: Allocated wall structure (caller frees with dna_message_wall_free)
 * @return 0 on success, -1 on error, -2 if wall not found
 */
int dna_load_wall(dht_context_t *dht_ctx,
                  const char *fingerprint,
                  dna_message_wall_t **wall_out);

/**
 * @brief Free message wall structure
 *
 * @param wall Message wall to free
 */
void dna_message_wall_free(dna_message_wall_t *wall);

/**
 * @brief Verify message signature
 *
 * Verifies that the message was signed by the wall owner's private key.
 * Signature covers: message_text || timestamp (network byte order)
 *
 * @param message Message to verify
 * @param public_key Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_message_wall_verify_signature(const dna_wall_message_t *message,
                                       const uint8_t *public_key);

/**
 * @brief Serialize wall to JSON string
 *
 * JSON format:
 * {
 *   "version": 1,
 *   "fingerprint": "...",
 *   "messages": [
 *     {
 *       "text": "...",
 *       "timestamp": 1234567890,
 *       "signature": "base64..."
 *     }
 *   ]
 * }
 *
 * @param wall Message wall
 * @param json_out Output: Allocated JSON string (caller frees)
 * @return 0 on success, -1 on error
 */
int dna_message_wall_to_json(const dna_message_wall_t *wall, char **json_out);

/**
 * @brief Parse wall from JSON string
 *
 * @param json_str JSON string
 * @param wall_out Output: Allocated wall structure (caller frees)
 * @return 0 on success, -1 on error
 */
int dna_message_wall_from_json(const char *json_str, dna_message_wall_t **wall_out);

/**
 * @brief Get all direct replies to a post
 *
 * Returns all messages where reply_to matches the given post_id.
 * Does not include nested replies (use dna_wall_get_thread for full recursion).
 *
 * @param wall Message wall
 * @param post_id Post ID to get replies for
 * @param replies_out Output: Array of message pointers (caller frees array, not messages)
 * @param count_out Output: Number of replies found
 * @return 0 on success, -1 on error
 */
int dna_wall_get_replies(const dna_message_wall_t *wall,
                         const char *post_id,
                         dna_wall_message_t ***replies_out,
                         size_t *count_out);

/**
 * @brief Get full conversation thread for a post
 *
 * Recursively fetches all replies up to 3 levels deep (post → comment → reply).
 * Returns a flat array with messages sorted by timestamp.
 *
 * @param wall Message wall
 * @param post_id Root post ID
 * @param thread_out Output: Array of message pointers (caller frees array, not messages)
 * @param count_out Output: Number of messages in thread (including root post)
 * @return 0 on success, -1 on error
 */
int dna_wall_get_thread(const dna_message_wall_t *wall,
                        const char *post_id,
                        dna_wall_message_t ***thread_out,
                        size_t *count_out);

/**
 * @brief Generate post_id from fingerprint and timestamp
 *
 * Format: <fingerprint>_<timestamp>
 *
 * @param fingerprint SHA3-512 fingerprint (128 hex chars)
 * @param timestamp Unix timestamp
 * @param post_id_out Output buffer (160 bytes minimum)
 * @return 0 on success, -1 on error
 */
int dna_wall_make_post_id(const char *fingerprint, uint64_t timestamp, char *post_id_out);

/**
 * @brief Update reply counts for all messages
 *
 * Scans wall and updates reply_count field for each message based on
 * number of direct replies.
 *
 * @param wall Message wall
 * @return 0 on success, -1 on error
 */
int dna_wall_update_reply_counts(dna_message_wall_t *wall);

#ifdef __cplusplus
}
#endif

#endif // DNA_MESSAGE_WALL_H
