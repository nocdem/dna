/*
 * DNA Message Wall - Public Message Board via DHT
 *
 * Each user has a public message wall stored in DHT:
 * - Key: SHA256(fingerprint + ":message_wall")
 * - Value: JSON array of messages with signatures
 * - Rotation: Keep latest 100 messages
 * - TTL: 30 days (re-publish on new post)
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
    char text[DNA_MESSAGE_WALL_MAX_TEXT_LEN];
    uint64_t timestamp;
    uint8_t signature[4627];  // Dilithium5 signature (Category 5)
    size_t signature_len;
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
 * @param dht_ctx DHT context
 * @param fingerprint User's SHA3-512 fingerprint (128 hex chars)
 * @param message_text Message text (max 1024 chars)
 * @param private_key Dilithium5 private key for signing (4896 bytes)
 * @return 0 on success, -1 on error
 */
int dna_post_to_wall(dht_context_t *dht_ctx,
                     const char *fingerprint,
                     const char *message_text,
                     const uint8_t *private_key);

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
 * @brief Get DHT key for user's message wall
 *
 * Key format: SHA256(fingerprint + ":message_wall")
 *
 * @param fingerprint User's SHA3-512 fingerprint (128 hex chars)
 * @param key_out Output buffer (65 bytes: 64 hex + null)
 * @return 0 on success, -1 on error
 */
int dna_message_wall_get_dht_key(const char *fingerprint, char *key_out);

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

#ifdef __cplusplus
}
#endif

#endif // DNA_MESSAGE_WALL_H
