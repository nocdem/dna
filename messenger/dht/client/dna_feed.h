/*
 * DNA Feeds v2 - Topic-Based Public Feed System via DHT
 *
 * Topic-based public feeds with categories and tags:
 * - Topic: SHA256("dna:feeds:topic:" + uuid) -> full topic content
 * - Comments: SHA256("dna:feeds:topic:" + uuid + ":comments") -> multi-owner comments
 * - Category Index: SHA256("dna:feeds:idx:cat:" + cat_id + ":" + YYYYMMDD) -> day bucket
 * - Global Index: SHA256("dna:feeds:idx:all:" + YYYYMMDD) -> day bucket
 *
 * Features:
 * - User-created topics with categories and tags
 * - Identity-required posts (Dilithium5 signed)
 * - Single-level threaded comments with @mentions (v0.6.96+)
 * - Soft delete (author only)
 * - 30-day TTL for all data
 * - NO VOTING (deferred until identity unification)
 *
 * v2 Changes from v1:
 * - Topics replace channels (user-created categories vs fixed channels)
 * - No voting system
 * - Namespace: "dna:feeds:" (v1 was "dna:feed:")
 */

#ifndef DNA_FEED_H
#define DNA_FEED_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

#define DNA_FEED_VERSION 2                        /* Feed system version */
#define DNA_FEED_TTL_SECONDS (30 * 24 * 60 * 60)  /* 30 days */

/* Topic limits */
#define DNA_FEED_MAX_TITLE_LEN 200                /* Max title length */
#define DNA_FEED_MAX_BODY_LEN 4000                /* Max body length */
#define DNA_FEED_MAX_TAG_LEN 32                   /* Max tag length */
#define DNA_FEED_MAX_TAGS 5                       /* Max tags per topic */
#define DNA_FEED_UUID_LEN 37                      /* UUID v4 + null */
#define DNA_FEED_CATEGORY_ID_LEN 65               /* SHA256 hex + null */
#define DNA_FEED_FINGERPRINT_LEN 129              /* SHA3-512 hex + null */

/* Comment limits */
#define DNA_FEED_MAX_COMMENT_LEN 2000             /* Max comment length */
#define DNA_FEED_MAX_MENTIONS 10                  /* Max @mentions per comment */

/* Index limits */
#define DNA_FEED_MAX_INDEX_ENTRIES 1000           /* Max entries per day bucket */
#define DNA_FEED_INDEX_DAYS_DEFAULT 7             /* Default days to fetch */
#define DNA_FEED_INDEX_DAYS_MAX 30                /* Max days to fetch */

/* Default categories (lowercase, SHA256 computed at runtime) */
#define DNA_FEED_CATEGORY_GENERAL "general"
#define DNA_FEED_CATEGORY_TECHNOLOGY "technology"
#define DNA_FEED_CATEGORY_HELP "help"
#define DNA_FEED_CATEGORY_ANNOUNCEMENTS "announcements"
#define DNA_FEED_CATEGORY_TRADING "trading"
#define DNA_FEED_CATEGORY_OFFTOPIC "offtopic"

/* ============================================================================
 * Data Structures
 * ========================================================================== */

/**
 * @brief Topic (stored at: SHA256("dna:feeds:topic:" + uuid))
 *
 * Represents a single topic/post in the feed system.
 * Topics are owned by their author and signed with Dilithium5.
 */
typedef struct {
    char topic_uuid[DNA_FEED_UUID_LEN];           /* UUID v4 identifier */
    char author_fingerprint[DNA_FEED_FINGERPRINT_LEN]; /* Creator's fingerprint */
    char title[DNA_FEED_MAX_TITLE_LEN + 1];       /* Topic title */
    char body[DNA_FEED_MAX_BODY_LEN + 1];         /* Topic body/content */
    char category_id[DNA_FEED_CATEGORY_ID_LEN];   /* SHA256 of lowercase category */
    char tags[DNA_FEED_MAX_TAGS][DNA_FEED_MAX_TAG_LEN + 1]; /* Up to 5 tags */
    uint8_t tag_count;                            /* Number of tags (0-5) */
    uint64_t created_at;                          /* Creation timestamp (Unix) */
    bool deleted;                                 /* Soft delete flag */
    uint64_t deleted_at;                          /* Deletion timestamp (0 if not deleted) */
    uint32_t version;                             /* Format version (DNA_FEED_VERSION) */

    /* Dilithium5 signature over serialized topic (excludes signature itself) */
    uint8_t signature[4627];
    size_t signature_len;
} dna_feed_topic_t;

/**
 * @brief Comment (stored multi-owner at: SHA256("dna:feeds:topic:" + uuid + ":comments"))
 *
 * Comments use multi-owner DHT pattern - multiple users can add values
 * to the same DHT key, each signed by their own identity.
 *
 * Supports single-level threading: comments can reply to other comments
 * via parent_comment_uuid. Empty parent = top-level comment.
 */
typedef struct {
    char comment_uuid[DNA_FEED_UUID_LEN];         /* UUID v4 identifier */
    char topic_uuid[DNA_FEED_UUID_LEN];           /* Parent topic UUID */
    char parent_comment_uuid[DNA_FEED_UUID_LEN];  /* Parent comment UUID (empty = top-level) */
    char author_fingerprint[DNA_FEED_FINGERPRINT_LEN]; /* Commenter's fingerprint */
    char body[DNA_FEED_MAX_COMMENT_LEN + 1];      /* Comment text */
    char mentions[DNA_FEED_MAX_MENTIONS][DNA_FEED_FINGERPRINT_LEN]; /* @mentioned fingerprints */
    uint8_t mention_count;                        /* Number of mentions (0-10) */
    uint64_t created_at;                          /* Creation timestamp (Unix) */
    uint32_t version;                             /* Format version (DNA_FEED_VERSION) */

    /* Dilithium5 signature over serialized comment (excludes signature itself) */
    uint8_t signature[4627];
    size_t signature_len;
} dna_feed_comment_t;

/**
 * @brief Index Entry (stored in day buckets for listing)
 *
 * Lightweight entry for category and global indexes.
 * Contains enough info for list view without fetching full topic.
 */
typedef struct {
    char topic_uuid[DNA_FEED_UUID_LEN];           /* Topic UUID */
    char author_fingerprint[DNA_FEED_FINGERPRINT_LEN]; /* Author fingerprint */
    char title[DNA_FEED_MAX_TITLE_LEN + 1];       /* Title preview */
    char category_id[DNA_FEED_CATEGORY_ID_LEN];   /* Category ID */
    uint64_t created_at;                          /* Creation timestamp */
    bool deleted;                                 /* Soft delete flag */
} dna_feed_index_entry_t;

/**
 * @brief Category info for listing available categories
 */
typedef struct {
    char category_id[DNA_FEED_CATEGORY_ID_LEN];   /* SHA256 of lowercase name */
    char name[64];                                /* Display name */
    int topic_count;                              /* Approximate topic count */
} dna_feed_category_t;

/* ============================================================================
 * Topic Operations (dna_feed_topic.c)
 * ========================================================================== */

/**
 * @brief Create a new topic
 *
 * Creates topic at DHT key and adds to category + global indexes.
 *
 * @param dht_ctx DHT context
 * @param title Topic title (max 200 chars)
 * @param body Topic body (max 4000 chars)
 * @param category Category name (lowercase, will compute SHA256)
 * @param tags Array of tags (NULL-terminated or tag_count entries)
 * @param tag_count Number of tags (0-5)
 * @param author_fingerprint Author's SHA3-512 fingerprint
 * @param private_key Author's Dilithium5 private key for signing
 * @param uuid_out Output: Generated UUID (37 bytes)
 * @return 0 on success, negative on error
 */
int dna_feed_topic_create(dht_context_t *dht_ctx,
                          const char *title,
                          const char *body,
                          const char *category,
                          const char **tags,
                          int tag_count,
                          const char *author_fingerprint,
                          const uint8_t *private_key,
                          char *uuid_out);

/**
 * @brief Get a topic by UUID
 *
 * @param dht_ctx DHT context
 * @param uuid Topic UUID
 * @param topic_out Output: Topic structure (caller frees with dna_feed_topic_free)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_feed_topic_get(dht_context_t *dht_ctx,
                       const char *uuid,
                       dna_feed_topic_t **topic_out);

/**
 * @brief Soft delete a topic (author only)
 *
 * Sets deleted flag and updates DHT. Topic remains in DHT until TTL expires.
 *
 * @param dht_ctx DHT context
 * @param uuid Topic UUID
 * @param author_fingerprint Author's fingerprint (for ownership verification)
 * @param private_key Author's Dilithium5 private key
 * @return 0 on success, -1 on error, -2 if not found, -3 if not owner
 */
int dna_feed_topic_delete(dht_context_t *dht_ctx,
                          const char *uuid,
                          const char *author_fingerprint,
                          const uint8_t *private_key);

/**
 * @brief Verify topic signature
 *
 * @param topic Topic to verify
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_feed_topic_verify(const dna_feed_topic_t *topic,
                          const uint8_t *public_key);

/**
 * @brief Free topic structure
 */
void dna_feed_topic_free(dna_feed_topic_t *topic);

/**
 * @brief Free array of topics
 */
void dna_feed_topics_free(dna_feed_topic_t *topics, size_t count);

/* ============================================================================
 * Comment Operations (dna_feed_comments.c)
 * ========================================================================== */

/**
 * @brief Add a comment to a topic (optionally as a reply)
 *
 * Uses multi-owner DHT pattern - each user's comment is a separate value.
 * Supports single-level threading via parent_comment_uuid.
 *
 * @param dht_ctx DHT context
 * @param topic_uuid Topic UUID to comment on
 * @param parent_comment_uuid Parent comment UUID for replies (NULL = top-level comment)
 * @param body Comment text (max 2000 chars)
 * @param mentions Array of mentioned fingerprints (NULL-terminated or mention_count entries)
 * @param mention_count Number of mentions (0-10)
 * @param author_fingerprint Author's SHA3-512 fingerprint
 * @param private_key Author's Dilithium5 private key
 * @param uuid_out Output: Generated comment UUID (37 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_comment_add(dht_context_t *dht_ctx,
                         const char *topic_uuid,
                         const char *parent_comment_uuid,
                         const char *body,
                         const char **mentions,
                         int mention_count,
                         const char *author_fingerprint,
                         const uint8_t *private_key,
                         char *uuid_out);

/**
 * @brief Get all comments for a topic
 *
 * Fetches all values from multi-owner DHT key, sorted by timestamp.
 *
 * @param dht_ctx DHT context
 * @param topic_uuid Topic UUID
 * @param comments_out Output: Array of comments (caller frees with dna_feed_comments_free)
 * @param count_out Output: Number of comments
 * @return 0 on success, -1 on error, -2 if no comments
 */
int dna_feed_comments_get(dht_context_t *dht_ctx,
                          const char *topic_uuid,
                          dna_feed_comment_t **comments_out,
                          size_t *count_out);

/**
 * @brief Verify comment signature
 *
 * @param comment Comment to verify
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_feed_comment_verify(const dna_feed_comment_t *comment,
                            const uint8_t *public_key);

/**
 * @brief Free comment structure
 */
void dna_feed_comment_free(dna_feed_comment_t *comment);

/**
 * @brief Free array of comments
 */
void dna_feed_comments_free(dna_feed_comment_t *comments, size_t count);

/* ============================================================================
 * Index Operations (dna_feed_index.c)
 * ========================================================================== */

/**
 * @brief Add entry to category and global indexes
 *
 * Called internally by dna_feed_topic_create(). Adds entry to:
 * - Category index: SHA256("dna:feeds:idx:cat:" + cat_id + ":" + YYYYMMDD)
 * - Global index: SHA256("dna:feeds:idx:all:" + YYYYMMDD)
 *
 * @param dht_ctx DHT context
 * @param entry Index entry to add
 * @return 0 on success, negative on error
 */
int dna_feed_index_add(dht_context_t *dht_ctx,
                       const dna_feed_index_entry_t *entry);

/**
 * @brief Update index entries to mark topic as deleted
 *
 * Republishes index entries with deleted=true to the correct day buckets
 * based on the topic's original creation timestamp.
 *
 * @param dht_ctx DHT context
 * @param topic_uuid Topic UUID
 * @param author_fingerprint Author's fingerprint
 * @param title Topic title
 * @param category_id Category ID (SHA256 hex)
 * @param created_at Original creation timestamp (for bucket lookup)
 * @return 0 on success, negative on error
 */
int dna_feed_index_update_deleted(dht_context_t *dht_ctx,
                                   const char *topic_uuid,
                                   const char *author_fingerprint,
                                   const char *title,
                                   const char *category_id,
                                   uint64_t created_at);

/**
 * @brief Get topics for a category
 *
 * Fetches from category day buckets, merges and sorts by timestamp desc.
 *
 * @param dht_ctx DHT context
 * @param category Category name (will compute SHA256)
 * @param days_back Number of days to fetch (1-30, default 7)
 * @param entries_out Output: Array of index entries (caller frees)
 * @param count_out Output: Number of entries
 * @return 0 on success, -1 on error, -2 if no entries
 */
int dna_feed_index_get_category(dht_context_t *dht_ctx,
                                const char *category,
                                int days_back,
                                dna_feed_index_entry_t **entries_out,
                                size_t *count_out);

/**
 * @brief Get all topics (global index)
 *
 * Fetches from global day buckets, merges and sorts by timestamp desc.
 *
 * @param dht_ctx DHT context
 * @param days_back Number of days to fetch (1-30, default 7)
 * @param entries_out Output: Array of index entries (caller frees)
 * @param count_out Output: Number of entries
 * @return 0 on success, -1 on error, -2 if no entries
 */
int dna_feed_index_get_all(dht_context_t *dht_ctx,
                           int days_back,
                           dna_feed_index_entry_t **entries_out,
                           size_t *count_out);

/**
 * @brief Free array of index entries
 */
void dna_feed_index_entries_free(dna_feed_index_entry_t *entries, size_t count);

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

/**
 * @brief Generate category_id from name
 *
 * Computes SHA256(lowercase(name)) and returns as 64-char hex string.
 *
 * @param name Category name
 * @param category_id_out Output buffer (65 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_make_category_id(const char *name, char *category_id_out);

/**
 * @brief Get list of default categories
 *
 * @param categories_out Output: Array of category info (caller frees)
 * @param count_out Output: Number of categories
 * @return 0 on success
 */
int dna_feed_get_default_categories(dna_feed_category_t **categories_out,
                                    size_t *count_out);

/**
 * @brief Generate UUID v4
 *
 * @param uuid_out Output buffer (37 bytes: 36 chars + null)
 */
void dna_feed_generate_uuid(char *uuid_out);

/**
 * @brief Get today's date string
 *
 * @param date_out Output buffer (12 bytes for YYYYMMDD + null)
 */
void dna_feed_get_today_date(char *date_out);

/**
 * @brief Get date string for N days ago
 *
 * @param days_ago Number of days in the past (0 = today)
 * @param date_out Output buffer (12 bytes for YYYYMMDD + null)
 */
void dna_feed_get_date_offset(int days_ago, char *date_out);

/**
 * @brief Get date string from Unix timestamp
 *
 * @param timestamp Unix timestamp (seconds since epoch)
 * @param date_out Output buffer (12 bytes for YYYYMMDD + null)
 */
void dna_feed_get_date_from_timestamp(uint64_t timestamp, char *date_out);

/* ============================================================================
 * DHT Key Generation
 * ========================================================================== */

/**
 * @brief Get DHT key for topic
 *
 * Key: SHA256("dna:feeds:topic:" + uuid)
 *
 * @param uuid Topic UUID
 * @param key_out Output buffer (65 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_get_topic_key(const char *uuid, char *key_out);

/**
 * @brief Get DHT key for topic comments
 *
 * Key: SHA256("dna:feeds:topic:" + uuid + ":comments")
 *
 * @param uuid Topic UUID
 * @param key_out Output buffer (65 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_get_comments_key(const char *uuid, char *key_out);

/**
 * @brief Get DHT key for category day bucket
 *
 * Key: SHA256("dna:feeds:idx:cat:" + cat_id + ":" + date)
 *
 * @param category_id Category ID (SHA256 hex)
 * @param date Date string (YYYYMMDD)
 * @param key_out Output buffer (65 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_get_category_index_key(const char *category_id,
                                    const char *date,
                                    char *key_out);

/**
 * @brief Get DHT key for global day bucket
 *
 * Key: SHA256("dna:feeds:idx:all:" + date)
 *
 * @param date Date string (YYYYMMDD)
 * @param key_out Output buffer (65 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_get_global_index_key(const char *date, char *key_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_FEED_H */
