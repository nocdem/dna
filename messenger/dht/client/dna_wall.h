/*
 * DNA Wall - Personal wall posts stored on DHT
 *
 * Each user's wall posts are stored under a per-user DHT key:
 *   SHA3-512("dna:wall:<fingerprint>")
 *
 * Posts are signed with Dilithium5 for authenticity.
 * Max 50 posts per user, 30-day TTL.
 *
 * Wall Comments (v0.7.0+):
 * - Comments stored under separate multi-owner DHT key per post
 * - Key: SHA3-512("dna:wall:comments:<post_uuid>")
 * - Each commenter stores their own values (multi-owner pattern)
 * - Single-level threading via parent_comment_uuid
 */

#ifndef DNA_WALL_H
#define DNA_WALL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ── */
#define DNA_WALL_MAX_TEXT_LEN    2048
#define DNA_WALL_MAX_POSTS       50
#define DNA_WALL_TTL_DAYS        30
#define DNA_WALL_KEY_PREFIX      "dna:wall:"

/* Wall Comments (v0.7.0+) */
#define DNA_WALL_COMMENT_MAX_BODY       2000
#define DNA_WALL_COMMENT_KEY_PREFIX     "dna:wall:comments:"
#define DNA_WALL_COMMENT_TTL_SECONDS    2592000   /* 30 days */
#define DNA_WALL_COMMENT_VERSION        1

/* ── Data Structures ── */

/**
 * Single wall post
 */
typedef struct {
    char uuid[37];                      /* UUID v4 */
    char author_fingerprint[129];       /* SHA3-512 hex */
    char text[DNA_WALL_MAX_TEXT_LEN];   /* Post content */
    char *image_json;                   /* Heap-allocated image JSON, NULL if no image (v0.7.0+) */
    uint64_t timestamp;                 /* Unix epoch seconds */
    uint8_t signature[4627];            /* Dilithium5 signature */
    size_t signature_len;
    bool verified;                      /* Signature verified flag */
} dna_wall_post_t;

/**
 * Collection of wall posts for a user
 */
typedef struct {
    char owner_fingerprint[129];        /* Wall owner's fingerprint */
    dna_wall_post_t *posts;             /* Array of posts */
    size_t post_count;                  /* Number of posts */
} dna_wall_t;

/* ── DHT Key Derivation ── */

/**
 * Derive DHT key for a user's wall
 * @param fingerprint  User's SHA3-512 fingerprint (128 hex chars)
 * @param out_key      Output buffer (64 bytes for SHA3-512 hash)
 */
void dna_wall_make_key(const char *fingerprint, uint8_t *out_key);

/* ── Wall Operations ── */

/**
 * Post a message to own wall
 * @param dht          DHT context
 * @param fingerprint  Poster's SHA3-512 fingerprint
 * @param private_key  Poster's Dilithium5 private key (for signing)
 * @param text         Post text (max DNA_WALL_MAX_TEXT_LEN-1 chars)
 * @param out_post     If non-NULL, filled with the created post
 * @return 0 on success, negative on error
 */
int dna_wall_post(const char *fingerprint,
                  const uint8_t *private_key,
                  const char *text,
                  dna_wall_post_t *out_post);

/**
 * Post a message with image to own wall (v0.7.0+)
 *
 * @param fingerprint  Poster's SHA3-512 fingerprint
 * @param private_key  Poster's Dilithium5 private key (for signing)
 * @param text         Post text (max DNA_WALL_MAX_TEXT_LEN-1 chars)
 * @param image_json   JSON with image data (base64+metadata), NULL for text-only
 * @param out_post     If non-NULL, filled with the created post (caller owns image_json)
 * @return 0 on success, negative on error
 */
int dna_wall_post_with_image(const char *fingerprint,
                              const uint8_t *private_key,
                              const char *text,
                              const char *image_json,
                              dna_wall_post_t *out_post);

/**
 * Delete a post from own wall
 * @param fingerprint  Owner's SHA3-512 fingerprint
 * @param private_key  Owner's Dilithium5 private key
 * @param post_uuid    UUID of post to delete
 * @return 0 on success, negative on error
 */
int dna_wall_delete(const char *fingerprint,
                    const uint8_t *private_key,
                    const char *post_uuid);

/**
 * Load a user's wall posts from DHT
 * @param fingerprint  Wall owner's fingerprint
 * @param wall         Output wall structure (caller must free with dna_wall_free)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_wall_load(const char *fingerprint,
                  dna_wall_t *wall);

/* ── Memory Management ── */

/**
 * Free wall structure
 */
void dna_wall_free(dna_wall_t *wall);

/* ── Verification ── */

/**
 * Verify a wall post's Dilithium5 signature
 * @param post       Post to verify
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_wall_post_verify(const dna_wall_post_t *post,
                         const uint8_t *public_key);

/* ── Serialization ── */

/**
 * Serialize wall to JSON string
 * @param wall  Wall to serialize
 * @return JSON string (caller frees) or NULL on error
 */
char *dna_wall_to_json(const dna_wall_t *wall);

/**
 * Deserialize wall from JSON string
 * @param json  JSON string
 * @param wall  Output wall structure
 * @return 0 on success, -1 on error
 */
int dna_wall_from_json(const char *json, dna_wall_t *wall);

/* ============================================================================
 * WALL COMMENTS (v0.7.0+)
 * ============================================================================ */

/**
 * Single wall comment (DHT/internal format)
 */
typedef struct {
    char uuid[37];                              /* Comment UUID v4 */
    char post_uuid[37];                         /* Parent post UUID */
    char parent_comment_uuid[37];               /* Reply-to comment (empty = top-level) */
    char author_fingerprint[129];               /* Commenter's fingerprint */
    char body[DNA_WALL_COMMENT_MAX_BODY + 1];   /* Comment text */
    uint64_t created_at;                        /* Unix epoch seconds */
    uint32_t version;                           /* Format version */
    uint32_t comment_type;                      /* 0=text, 1=tip */
    uint8_t signature[4627];                    /* Dilithium5 signature */
    size_t signature_len;
} dna_wall_comment_t;

/**
 * Add a comment to a wall post (multi-owner DHT)
 *
 * @param post_uuid            UUID of the wall post to comment on
 * @param parent_comment_uuid  Parent comment UUID for replies (NULL = top-level)
 * @param body                 Comment text (max DNA_WALL_COMMENT_MAX_BODY chars)
 * @param author_fingerprint   Commenter's SHA3-512 fingerprint
 * @param private_key          Commenter's Dilithium5 private key
 * @param comment_type         0=text, 1=tip
 * @param uuid_out             Output: created comment UUID (37 bytes)
 * @return 0 on success, negative on error
 */
int dna_wall_comment_add(const char *post_uuid,
                          const char *parent_comment_uuid,
                          const char *body,
                          const char *author_fingerprint,
                          const uint8_t *private_key,
                          uint32_t comment_type,
                          char *uuid_out);

/**
 * Fetch all comments for a wall post from DHT
 *
 * @param post_uuid     UUID of the wall post
 * @param comments_out  Output: heap-allocated array (caller frees with dna_wall_comments_free)
 * @param count_out     Output: number of comments
 * @return 0 on success, -1 on error, -2 if no comments found
 */
int dna_wall_comments_get(const char *post_uuid,
                           dna_wall_comment_t **comments_out,
                           size_t *count_out);

/**
 * Verify a wall comment's Dilithium5 signature
 *
 * @param comment    Comment to verify
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_wall_comment_verify(const dna_wall_comment_t *comment,
                             const uint8_t *public_key);

/**
 * Free a wall comments array
 */
void dna_wall_comments_free(dna_wall_comment_t *comments, size_t count);

/* ============================================================================
 * WALL LIKES (v0.9.52+)
 * ============================================================================ */

/* Like Constants */
#define DNA_WALL_LIKE_KEY_PREFIX     "dna:wall:likes:"
#define DNA_WALL_LIKE_MAX            100
#define DNA_WALL_LIKE_TTL_SECONDS    2592000   /* 30 days */

/**
 * Single wall like (DHT/internal format)
 *
 * Each like is a fingerprint + Dilithium5 signature over the post_uuid.
 * Stored under multi-owner DHT key: SHA3-512("dna:wall:likes:<post_uuid>")
 */
typedef struct {
    char author_fingerprint[129];       /* Liker's SHA3-512 fingerprint */
    uint64_t timestamp;                 /* Unix epoch seconds */
    uint8_t signature[4627];            /* Dilithium5 signature */
    size_t signature_len;
} dna_wall_like_t;

/**
 * Add a like to a wall post (multi-owner DHT)
 *
 * Signs the post_uuid with Dilithium5 and stores on DHT.
 * Client-side enforces max DNA_WALL_LIKE_MAX likes per post.
 * Duplicate likes (same fingerprint) are rejected.
 *
 * @param post_uuid            UUID of the wall post to like
 * @param author_fingerprint   Liker's SHA3-512 fingerprint
 * @param private_key          Liker's Dilithium5 private key
 * @return 0 on success, -1 on error, -3 if already liked, -4 if max likes reached
 */
int dna_wall_like_add(const char *post_uuid,
                       const char *author_fingerprint,
                       const uint8_t *private_key);

/**
 * Fetch all likes for a wall post from DHT
 *
 * @param post_uuid    UUID of the wall post
 * @param likes_out    Output: heap-allocated array (caller frees with dna_wall_likes_free)
 * @param count_out    Output: number of likes
 * @return 0 on success, -1 on error, -2 if no likes found
 */
int dna_wall_likes_get(const char *post_uuid,
                        dna_wall_like_t **likes_out,
                        size_t *count_out);

/**
 * Verify a wall like's Dilithium5 signature
 *
 * @param like       Like to verify
 * @param post_uuid  The post UUID that was signed
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_wall_like_verify(const dna_wall_like_t *like,
                          const char *post_uuid,
                          const uint8_t *public_key);

/**
 * Free a wall likes array
 */
void dna_wall_likes_free(dna_wall_like_t *likes, size_t count);

/* ============================================================================
 * WALL BOOST (v0.9.71+)
 * ============================================================================
 *
 * Boosted posts appear on a global daily DHT key visible to all users.
 * Each user writes lightweight pointers (uuid + author_fp + timestamp) to
 * the daily boost key using the multi-owner pattern (same as comments/likes).
 *
 * DHT Key:   SHA3-512("dna:boost:YYYY-MM-DD")
 * TTL:       7 days
 * Value:     JSON array of pointer objects per author (multi-owner)
 *
 * To display a boosted post the client resolves the real post data from
 * the author's wall key: SHA3-512("dna:wall:<author_fp>").
 */

/* Boost Constants */
#define DNA_WALL_BOOST_KEY_PREFIX     "dna:boost:"
#define DNA_WALL_BOOST_TTL_SECONDS    604800    /* 7 days */
#define DNA_WALL_BOOST_MAX_PER_DAY    10        /* Max boost posts per user per day */

/**
 * Boost pointer — lightweight reference stored on the daily boost key.
 */
typedef struct {
    char uuid[37];                      /* Post UUID */
    char author_fingerprint[129];       /* Post author's fingerprint */
    uint64_t timestamp;                 /* Post creation timestamp */
} dna_wall_boost_ptr_t;

/**
 * Register a wall post as boosted on today's boost key.
 * Writes a pointer to the multi-owner DHT key "dna:boost:YYYY-MM-DD".
 *
 * @param post_uuid           UUID of the wall post to boost
 * @param author_fingerprint  Post author's fingerprint
 * @param post_timestamp      Post creation timestamp
 * @return 0 on success, -1 on error, -3 if already boosted, -4 if daily limit reached
 */
int dna_wall_boost_post(const char *post_uuid,
                         const char *author_fingerprint,
                         uint64_t post_timestamp);

/**
 * Fetch all boost pointers for a specific date.
 * Uses nodus_ops_get_all_str() to collect from all authors.
 *
 * @param date_str     Date string "YYYY-MM-DD"
 * @param ptrs_out     Output: heap-allocated array (caller frees)
 * @param count_out    Output: number of pointers
 * @return 0 on success, -1 on error, -2 if none found
 */
int dna_wall_boost_load(const char *date_str,
                         dna_wall_boost_ptr_t **ptrs_out,
                         size_t *count_out);

/**
 * Fetch all boost pointers for the last N days (convenience).
 *
 * @param days         Number of days to look back (max 7)
 * @param ptrs_out     Output: heap-allocated array (caller frees)
 * @param count_out    Output: number of pointers
 * @return 0 on success, -1 on error, -2 if none found
 */
int dna_wall_boost_load_recent(int days,
                                dna_wall_boost_ptr_t **ptrs_out,
                                size_t *count_out);

/**
 * Free a boost pointers array
 */
void dna_wall_boost_free(dna_wall_boost_ptr_t *ptrs, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* DNA_WALL_H */
