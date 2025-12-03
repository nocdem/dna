/*
 * DNA Feed - Topic-Based Public Feed System via DHT
 *
 * Distributed public feed with topic-based channels:
 * - Channel Registry: SHA256("dna:feed:registry") -> list of all channels
 * - Channel Metadata: SHA256("dna:feed:" + channel_id + ":meta") -> channel info
 * - Channel Index: SHA256("dna:feed:channel:" + channel_id + ":posts:" + YYYYMMDD) -> daily post IDs
 * - Posts: SHA256("dna:feed:post:" + post_id) -> individual post content
 * - Comments: SHA256("dna:feed:post:" + post_id + ":comments") -> multi-owner comments
 * - Post Votes: SHA256("dna:feed:post:" + post_id + ":votes") -> vote records
 * - Comment Votes: SHA256("dna:feed:comment:" + comment_id + ":votes") -> vote records
 *
 * Features:
 * - Anyone can create channels
 * - Identity-required posts (Dilithium5 signed)
 * - Flat comments (no nesting, use @mentions)
 * - Permanent voting (one vote per user per post/comment)
 * - 30-day TTL for all data
 * - Engagement-TTL: comments refresh parent post TTL
 */

#ifndef DNA_FEED_H
#define DNA_FEED_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants */
#define DNA_FEED_MAX_CHANNEL_NAME 64
#define DNA_FEED_MAX_CHANNEL_DESC 512
#define DNA_FEED_MAX_POST_TEXT 2048
#define DNA_FEED_MAX_POSTS_PER_BUCKET 500
#define DNA_FEED_TTL_SECONDS (30 * 24 * 60 * 60)  /* 30 days */
#define DNA_FEED_MAX_COMMENT_TEXT 2048            /* Max comment text length */
#define DNA_FEED_POST_VERSION 2                   /* Current post format version */

/* Default channel IDs (SHA256 of lowercase name) */
#define DNA_FEED_CHANNEL_GENERAL "general"
#define DNA_FEED_CHANNEL_ANNOUNCEMENTS "announcements"
#define DNA_FEED_CHANNEL_HELP "help"
#define DNA_FEED_CHANNEL_RANDOM "random"

/* ============================================================================
 * Data Structures
 * ========================================================================== */

/**
 * @brief Channel metadata
 *
 * Stored at: SHA256("dna:feed:" + channel_id + ":meta")
 */
typedef struct {
    char channel_id[65];                      /* SHA256 hex of channel name (64 + null) */
    char name[DNA_FEED_MAX_CHANNEL_NAME];     /* Display name */
    char description[DNA_FEED_MAX_CHANNEL_DESC]; /* Channel description */
    char creator_fingerprint[129];            /* Creator's SHA3-512 fingerprint */
    uint64_t created_at;                      /* Unix timestamp */
    int post_count;                           /* Approximate post count */
    int subscriber_count;                     /* Approximate subscriber count */
    uint64_t last_activity;                   /* Timestamp of last post */
} dna_feed_channel_t;

/**
 * @brief Channel registry (list of all channels)
 *
 * Stored at: SHA256("dna:feed:registry")
 */
typedef struct {
    dna_feed_channel_t *channels;
    size_t channel_count;
    size_t allocated_count;
    uint64_t updated_at;
} dna_feed_registry_t;

/**
 * @brief Single post
 *
 * Stored at: SHA256("dna:feed:post:" + post_id)
 */
typedef struct {
    char post_id[200];                        /* <fingerprint>_<timestamp_ms>_<random> */
    char channel_id[65];                      /* Channel this post belongs to */
    char author_fingerprint[129];             /* Author's SHA3-512 fingerprint */
    char text[DNA_FEED_MAX_POST_TEXT];        /* Post content */
    uint64_t timestamp;                       /* Unix timestamp (milliseconds) */
    uint64_t updated;                         /* Last activity timestamp (comment added) */
    int comment_count;                        /* Cached comment count */

    /* Signature */
    uint8_t signature[4627];                  /* Dilithium5 signature (NIST Cat 5) */
    size_t signature_len;

    /* Voting (populated separately) */
    int upvotes;
    int downvotes;
    int user_vote;                            /* Current user's vote: +1, -1, or 0 */
} dna_feed_post_t;

/**
 * @brief Single comment on a post
 *
 * Stored at: SHA256("dna:feed:post:" + post_id + ":comments") as multi-owner value
 */
typedef struct {
    char comment_id[200];                     /* <fingerprint>_<timestamp_ms>_<random> */
    char post_id[200];                        /* Parent post ID */
    char author_fingerprint[129];             /* Author's SHA3-512 fingerprint */
    char text[DNA_FEED_MAX_COMMENT_TEXT];     /* Comment content */
    uint64_t timestamp;                       /* Unix timestamp (milliseconds) */

    /* Signature */
    uint8_t signature[4627];                  /* Dilithium5 signature (NIST Cat 5) */
    size_t signature_len;

    /* Voting (populated separately) */
    int upvotes;
    int downvotes;
    int user_vote;                            /* Current user's vote: +1, -1, or 0 */
} dna_feed_comment_t;

/**
 * @brief Post with all its comments
 *
 * Used for fetching a complete post thread
 */
typedef struct {
    dna_feed_post_t post;                     /* The main post */
    dna_feed_comment_t *comments;             /* Array of comments */
    size_t comment_count;                     /* Number of comments */
    size_t allocated_count;                   /* Allocated array size */
} dna_feed_post_with_comments_t;

/**
 * @brief Daily post index bucket
 *
 * Stored at: SHA256("dna:feed:" + channel_id + ":posts:" + YYYYMMDD)
 */
typedef struct {
    char channel_id[65];
    char bucket_date[12];                     /* YYYYMMDD */
    char **post_ids;                          /* Array of post IDs */
    size_t post_count;
    size_t allocated_count;
} dna_feed_bucket_t;

/**
 * @brief Single vote record
 */
typedef struct {
    char voter_fingerprint[129];              /* Voter's SHA3-512 fingerprint */
    int8_t vote_value;                        /* +1 for upvote, -1 for downvote */
    uint64_t timestamp;                       /* When vote was cast */
    uint8_t signature[4627];                  /* Dilithium5 signature */
    size_t signature_len;
} dna_feed_vote_t;

/**
 * @brief Aggregated votes for a post
 *
 * Stored at: SHA256("dna:feed:post:" + post_id + ":votes")
 */
typedef struct {
    char post_id[200];
    int upvote_count;
    int downvote_count;
    dna_feed_vote_t *votes;
    size_t vote_count;
    size_t allocated_count;
} dna_feed_votes_t;

/* ============================================================================
 * Channel Operations (dna_feed_channels.c)
 * ========================================================================== */

/**
 * @brief Create a new channel
 *
 * Creates channel metadata and adds to global registry.
 *
 * @param dht_ctx DHT context
 * @param name Channel name (max 64 chars)
 * @param description Channel description (max 512 chars)
 * @param creator_fingerprint Creator's SHA3-512 fingerprint
 * @param private_key Creator's Dilithium5 private key for signing
 * @param channel_out Output: Created channel (caller frees)
 * @return 0 on success, -1 on error, -2 if channel already exists
 */
int dna_feed_channel_create(dht_context_t *dht_ctx,
                            const char *name,
                            const char *description,
                            const char *creator_fingerprint,
                            const uint8_t *private_key,
                            dna_feed_channel_t **channel_out);

/**
 * @brief Get channel metadata
 *
 * @param dht_ctx DHT context
 * @param channel_id Channel ID (SHA256 of name)
 * @param channel_out Output: Channel metadata (caller frees)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_feed_channel_get(dht_context_t *dht_ctx,
                         const char *channel_id,
                         dna_feed_channel_t **channel_out);

/**
 * @brief Get all channels from registry
 *
 * @param dht_ctx DHT context
 * @param registry_out Output: Channel registry (caller frees)
 * @return 0 on success, -1 on error, -2 if registry empty
 */
int dna_feed_registry_get(dht_context_t *dht_ctx,
                          dna_feed_registry_t **registry_out);

/**
 * @brief Initialize default channels
 *
 * Creates #general, #announcements, #help, #random if they don't exist.
 *
 * @param dht_ctx DHT context
 * @param creator_fingerprint Creator fingerprint for defaults
 * @param private_key Creator's private key
 * @return Number of channels created, -1 on error
 */
int dna_feed_init_default_channels(dht_context_t *dht_ctx,
                                   const char *creator_fingerprint,
                                   const uint8_t *private_key);

/**
 * @brief Generate channel_id from name
 *
 * @param name Channel name
 * @param channel_id_out Output buffer (65 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_make_channel_id(const char *name, char *channel_id_out);

/**
 * @brief Free channel structure
 */
void dna_feed_channel_free(dna_feed_channel_t *channel);

/**
 * @brief Free registry structure
 */
void dna_feed_registry_free(dna_feed_registry_t *registry);

/* ============================================================================
 * Post Operations (dna_feed_posts.c)
 * ========================================================================== */

/**
 * @brief Create a new post in a channel
 *
 * @param dht_ctx DHT context
 * @param channel_id Channel to post in
 * @param author_fingerprint Author's SHA3-512 fingerprint
 * @param text Post content (max 2048 chars)
 * @param private_key Author's Dilithium5 private key
 * @param post_out Output: Created post (caller frees)
 * @return 0 on success, -1 on error
 */
int dna_feed_post_create(dht_context_t *dht_ctx,
                         const char *channel_id,
                         const char *author_fingerprint,
                         const char *text,
                         const uint8_t *private_key,
                         dna_feed_post_t **post_out);

/**
 * @brief Get a single post by ID
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID
 * @param post_out Output: Post (caller frees)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_feed_post_get(dht_context_t *dht_ctx,
                      const char *post_id,
                      dna_feed_post_t **post_out);

/**
 * @brief Get posts for a channel (paginated by date)
 *
 * @param dht_ctx DHT context
 * @param channel_id Channel ID
 * @param date Date string (YYYYMMDD) or NULL for today
 * @param posts_out Output: Array of posts (caller frees)
 * @param count_out Output: Number of posts
 * @return 0 on success, -1 on error, -2 if no posts
 */
int dna_feed_posts_get_by_channel(dht_context_t *dht_ctx,
                                  const char *channel_id,
                                  const char *date,
                                  dna_feed_post_t **posts_out,
                                  size_t *count_out);

/**
 * @brief Get post with all its comments
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID
 * @param result_out Output: Post with comments (caller frees)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_feed_post_get_full(dht_context_t *dht_ctx,
                           const char *post_id,
                           dna_feed_post_with_comments_t **result_out);

/**
 * @brief Generate post_id
 *
 * Format: <fingerprint>_<timestamp_ms>_<random_hex>
 *
 * @param fingerprint Author fingerprint
 * @param post_id_out Output buffer (200 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_make_post_id(const char *fingerprint, char *post_id_out);

/**
 * @brief Verify post signature
 *
 * @param post Post to verify
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_feed_verify_post_signature(const dna_feed_post_t *post,
                                   const uint8_t *public_key);

/**
 * @brief Free post structure
 */
void dna_feed_post_free(dna_feed_post_t *post);

/**
 * @brief Free bucket structure
 */
void dna_feed_bucket_free(dna_feed_bucket_t *bucket);

/**
 * @brief Free post with comments structure
 */
void dna_feed_post_with_comments_free(dna_feed_post_with_comments_t *post_with_comments);

/* ============================================================================
 * Comment Operations (dna_feed_comments.c)
 * ========================================================================== */

/**
 * @brief Add a comment to a post
 *
 * Also refreshes the parent post TTL (engagement-TTL).
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID to comment on
 * @param author_fingerprint Author's SHA3-512 fingerprint
 * @param text Comment content (max 2048 chars)
 * @param private_key Author's Dilithium5 private key
 * @param comment_out Output: Created comment (caller frees)
 * @return 0 on success, -1 on error, -2 if post not found
 */
int dna_feed_comment_add(dht_context_t *dht_ctx,
                         const char *post_id,
                         const char *author_fingerprint,
                         const char *text,
                         const uint8_t *private_key,
                         dna_feed_comment_t **comment_out);

/**
 * @brief Get all comments for a post
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID
 * @param comments_out Output: Array of comments (caller frees)
 * @param count_out Output: Number of comments
 * @return 0 on success, -1 on error, -2 if no comments
 */
int dna_feed_comments_get(dht_context_t *dht_ctx,
                          const char *post_id,
                          dna_feed_comment_t **comments_out,
                          size_t *count_out);

/**
 * @brief Generate comment_id
 *
 * Format: <fingerprint>_<timestamp_ms>_<random_hex>
 *
 * @param fingerprint Author fingerprint
 * @param comment_id_out Output buffer (200 bytes)
 * @return 0 on success, -1 on error
 */
int dna_feed_make_comment_id(const char *fingerprint, char *comment_id_out);

/**
 * @brief Verify comment signature
 *
 * @param comment Comment to verify
 * @param public_key Author's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_feed_verify_comment_signature(const dna_feed_comment_t *comment,
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
 * Vote Operations (dna_feed_votes.c)
 * ========================================================================== */

/**
 * @brief Cast a vote on a post
 *
 * Votes are permanent - cannot be changed once cast.
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID to vote on
 * @param voter_fingerprint Voter's SHA3-512 fingerprint
 * @param vote_value +1 for upvote, -1 for downvote
 * @param private_key Voter's Dilithium5 private key
 * @return 0 on success, -1 on error, -2 if already voted
 */
int dna_feed_vote_cast(dht_context_t *dht_ctx,
                       const char *post_id,
                       const char *voter_fingerprint,
                       int8_t vote_value,
                       const uint8_t *private_key);

/**
 * @brief Get votes for a post
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID
 * @param votes_out Output: Votes structure (caller frees)
 * @return 0 on success, -1 on error, -2 if no votes
 */
int dna_feed_votes_get(dht_context_t *dht_ctx,
                       const char *post_id,
                       dna_feed_votes_t **votes_out);

/**
 * @brief Check if user has voted on a post
 *
 * @param votes Votes structure
 * @param voter_fingerprint Voter fingerprint
 * @return +1 if upvoted, -1 if downvoted, 0 if not voted
 */
int8_t dna_feed_get_user_vote(const dna_feed_votes_t *votes,
                              const char *voter_fingerprint);

/**
 * @brief Verify vote signature
 *
 * @param vote Vote to verify
 * @param post_id Post ID the vote is for
 * @param public_key Voter's Dilithium5 public key
 * @return 0 if valid, -1 if invalid
 */
int dna_feed_verify_vote_signature(const dna_feed_vote_t *vote,
                                   const char *post_id,
                                   const uint8_t *public_key);

/**
 * @brief Free votes structure
 */
void dna_feed_votes_free(dna_feed_votes_t *votes);

/**
 * @brief Cast a vote on a comment
 *
 * Votes are permanent - cannot be changed once cast.
 *
 * @param dht_ctx DHT context
 * @param comment_id Comment ID to vote on
 * @param voter_fingerprint Voter's SHA3-512 fingerprint
 * @param vote_value +1 for upvote, -1 for downvote
 * @param private_key Voter's Dilithium5 private key
 * @return 0 on success, -1 on error, -2 if already voted
 */
int dna_feed_comment_vote_cast(dht_context_t *dht_ctx,
                               const char *comment_id,
                               const char *voter_fingerprint,
                               int8_t vote_value,
                               const uint8_t *private_key);

/**
 * @brief Get votes for a comment
 *
 * @param dht_ctx DHT context
 * @param comment_id Comment ID
 * @param votes_out Output: Votes structure (caller frees)
 * @return 0 on success, -1 on error, -2 if no votes
 */
int dna_feed_comment_votes_get(dht_context_t *dht_ctx,
                               const char *comment_id,
                               dna_feed_votes_t **votes_out);

/* ============================================================================
 * DHT Key Generation
 * ========================================================================== */

/**
 * @brief Get DHT key for channel registry
 *
 * Key: SHA256("dna:feed:registry")
 *
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_registry_key(char *key_out);

/**
 * @brief Get DHT key for channel metadata
 *
 * Key: SHA256("dna:feed:" + channel_id + ":meta")
 *
 * @param channel_id Channel ID
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_channel_key(const char *channel_id, char *key_out);

/**
 * @brief Get DHT key for daily post bucket
 *
 * Key: SHA256("dna:feed:" + channel_id + ":posts:" + date)
 *
 * @param channel_id Channel ID
 * @param date Date string (YYYYMMDD)
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_bucket_key(const char *channel_id, const char *date, char *key_out);

/**
 * @brief Get DHT key for individual post
 *
 * Key: SHA256("dna:feed:post:" + post_id)
 *
 * @param post_id Post ID
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_post_key(const char *post_id, char *key_out);

/**
 * @brief Get DHT key for post votes
 *
 * Key: SHA256("dna:feed:post:" + post_id + ":votes")
 *
 * @param post_id Post ID
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_votes_key(const char *post_id, char *key_out);

/**
 * @brief Get DHT key for post comments
 *
 * Key: SHA256("dna:feed:post:" + post_id + ":comments")
 *
 * @param post_id Post ID
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_comments_key(const char *post_id, char *key_out);

/**
 * @brief Get DHT key for comment votes
 *
 * Key: SHA256("dna:feed:comment:" + comment_id + ":votes")
 *
 * @param comment_id Comment ID
 * @param key_out Output buffer (65 bytes)
 */
int dna_feed_get_comment_votes_key(const char *comment_id, char *key_out);

/**
 * @brief Get today's date string
 *
 * @param date_out Output buffer (12 bytes for YYYYMMDD + null)
 */
void dna_feed_get_today_date(char *date_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_FEED_H */
