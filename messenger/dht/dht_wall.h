/**
 * DHT Wall Posts and Comments (Alpha Version)
 * Censorship-resistant social media storage
 *
 * Alpha Features:
 * - Free posting (no CPUNK costs)
 * - No PoH requirements
 * - Simple text posts + comments
 * - 7-day TTL
 * - Dilithium5 signatures for authenticity
 *
 * Architecture:
 * - Posts stored in DHT with 7-day TTL
 * - Comment threading via parent_hash
 * - No deletion after publish (permanent record)
 *
 * Post Structure:
 * - Root posts: parent_hash = empty (64 zeros)
 * - Comments: parent_hash = post_id of parent
 *
 * DHT Storage:
 * - Key: SHA3-512(post_id)
 * - Value: [json_len:4][json:N][sig_len:4][signature:4627]
 * - TTL: 7 days (604800 seconds)
 *
 * @file dht_wall.h
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#ifndef DHT_WALL_H
#define DHT_WALL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dht_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// Limits (Alpha version - simple)
#define DHT_WALL_MAX_CONTENT        5120    // 5K chars for all posts
#define DHT_WALL_POST_ID_SIZE       128     // SHA3-512 hex
#define DHT_WALL_AUTHOR_FP_SIZE     128     // SHA3-512 fingerprint hex
#define DHT_WALL_TTL_SECONDS        (7*24*3600)  // 7 days

// Post types
typedef enum {
    DHT_WALL_TYPE_POST = 0,      // Root post
    DHT_WALL_TYPE_COMMENT = 1    // Comment/reply
} dht_wall_post_type_t;

// Wall post structure
typedef struct {
    char post_id[DHT_WALL_POST_ID_SIZE + 1];           // SHA3-512 hex (unique ID)
    char author_fingerprint[DHT_WALL_AUTHOR_FP_SIZE + 1];  // Author's fingerprint
    char parent_hash[DHT_WALL_POST_ID_SIZE + 1];       // Parent post ID (empty = root)
    char content[DHT_WALL_MAX_CONTENT + 1];            // Text content
    dht_wall_post_type_t post_type;                    // Post type
    uint64_t timestamp;                                 // Unix timestamp
} dht_wall_post_t;

/**
 * Publish wall post (root post or comment)
 *
 * Flow:
 * 1. Generate post_id = SHA3-512(author + content + timestamp)
 * 2. Serialize to JSON
 * 3. Sign with Dilithium5
 * 4. Store in DHT with 7-day TTL
 *
 * @param dht_ctx DHT context
 * @param post Post data (post_id will be generated if empty)
 * @param dilithium_privkey Author's Dilithium private key (4896 bytes)
 * @return 0 on success, -1 on error
 */
int dht_wall_publish_post(
    dht_context_t *dht_ctx,
    dht_wall_post_t *post,
    const uint8_t *dilithium_privkey
);

/**
 * Fetch wall post by ID
 *
 * Flow:
 * 1. Compute DHT key = SHA3-512(post_id)
 * 2. Fetch from DHT
 * 3. Verify Dilithium5 signature
 * 4. Parse JSON
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID (SHA3-512 hex)
 * @param post_out Output post data (caller provides buffer)
 * @return 0 on success, -1 on error, -2 if not found, -3 if signature invalid
 */
int dht_wall_fetch_post(
    dht_context_t *dht_ctx,
    const char *post_id,
    dht_wall_post_t *post_out
);

/**
 * Validate post content
 *
 * Rules:
 * - Max 5120 chars
 * - Content not empty
 * - Valid parent_hash (64 zeros or 128 hex chars)
 *
 * @param post Post to validate
 * @return true if valid, false otherwise
 */
bool dht_wall_validate_post(const dht_wall_post_t *post);

/**
 * Generate post_id from content
 *
 * Algorithm: SHA3-512(author_fingerprint + content + timestamp)
 *
 * @param author_fingerprint Author's fingerprint
 * @param content Post content
 * @param timestamp Unix timestamp
 * @param post_id_out Output post ID (129 bytes: 128 hex + null)
 * @return 0 on success, -1 on error
 */
int dht_wall_generate_post_id(
    const char *author_fingerprint,
    const char *content,
    uint64_t timestamp,
    char *post_id_out
);

/**
 * Check if post is a root post (not a comment)
 *
 * @param post Post to check
 * @return true if root post (parent_hash = empty), false if comment
 */
bool dht_wall_is_root_post(const dht_wall_post_t *post);

#ifdef __cplusplus
}
#endif

#endif // DHT_WALL_H
