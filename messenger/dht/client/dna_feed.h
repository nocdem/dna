/*
 * DNA Feed - Topic-Based Public Feed System via DHT
 *
 * Distributed public feed with topic-based channels:
 * - Channel Registry: SHA256("dna:feed:registry") -> list of all channels
 * - Channel Metadata: SHA256("dna:feed:" + channel_id + ":meta") -> channel info
 * - Post Index: SHA256("dna:feed:" + channel_id + ":posts:" + YYYYMMDD) -> daily post IDs
 * - Posts: SHA256("dna:feed:post:" + post_id) -> individual post content
 * - Votes: SHA256("dna:feed:post:" + post_id + ":votes") -> vote records
 *
 * Features:
 * - Anyone can create channels
 * - Identity-required posts (Dilithium5 signed)
 * - 3-level threading (post -> comment -> reply)
 * - Permanent voting (one vote per user per post)
 * - 30-day TTL for all data
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
#define DNA_FEED_MAX_THREAD_DEPTH 2               /* 0=post, 1=comment, 2=reply */

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

    /* Threading */
    char reply_to[200];                       /* Parent post_id (empty for top-level) */
    int reply_depth;                          /* 0=post, 1=comment, 2=reply */
    int reply_count;                          /* Number of direct replies */

    /* Signature */
    uint8_t signature[4627];                  /* Dilithium5 signature (NIST Cat 5) */
    size_t signature_len;

    /* Voting (populated separately) */
    int upvotes;
    int downvotes;
    int user_vote;                            /* Current user's vote: +1, -1, or 0 */
} dna_feed_post_t;

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
 * @param reply_to Parent post_id for replies (NULL for top-level)
 * @param post_out Output: Created post (caller frees)
 * @return 0 on success, -1 on error, -2 if max depth exceeded
 */
int dna_feed_post_create(dht_context_t *dht_ctx,
                         const char *channel_id,
                         const char *author_fingerprint,
                         const char *text,
                         const uint8_t *private_key,
                         const char *reply_to,
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
 * @brief Get replies to a post
 *
 * @param dht_ctx DHT context
 * @param post_id Parent post ID
 * @param replies_out Output: Array of replies
 * @param count_out Output: Number of replies
 * @return 0 on success, -1 on error
 */
int dna_feed_post_get_replies(dht_context_t *dht_ctx,
                              const char *post_id,
                              dna_feed_post_t **replies_out,
                              size_t *count_out);

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
 * @brief Get today's date string
 *
 * @param date_out Output buffer (12 bytes for YYYYMMDD + null)
 */
void dna_feed_get_today_date(char *date_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_FEED_H */
