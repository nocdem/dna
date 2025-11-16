/*
 * DNA Wall Votes - Community Voting System for Wall Posts
 *
 * Each wall post can have votes stored in DHT:
 * - Key: SHA256(post_id + ":votes")
 * - Value: JSON with aggregated counts + individual vote records
 * - TTL: 30 days (same as wall posts)
 * - Votes are permanent (cannot be changed once cast)
 * - One vote per fingerprint per post
 * - Dilithium5 signatures for authenticity
 */

#ifndef DNA_WALL_VOTES_H
#define DNA_WALL_VOTES_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNA_WALL_VOTES_TTL_SECONDS (30 * 24 * 60 * 60)  // 30 days

/**
 * @brief Single vote record
 *
 * Represents an individual user's vote on a post. Signed with Dilithium5
 * to prevent tampering and verify voter identity.
 */
typedef struct {
    char voter_fingerprint[129];  // SHA3-512 hex (128 chars + null)
    int8_t vote_value;            // +1 for upvote, -1 for downvote
    uint64_t timestamp;           // When vote was cast (Unix epoch)
    uint8_t signature[4627];      // Dilithium5 signature (Category 5)
    size_t signature_len;         // Actual signature length
} dna_wall_vote_t;

/**
 * @brief Aggregated votes for a post
 *
 * Contains vote counts plus all individual vote records for verification.
 */
typedef struct {
    char post_id[160];            // Post being voted on (fingerprint_timestamp)
    int upvote_count;             // Total upvotes
    int downvote_count;           // Total downvotes
    dna_wall_vote_t *votes;       // Array of individual votes
    size_t vote_count;            // Number of votes in array
    size_t allocated_count;       // Allocated capacity
} dna_wall_votes_t;

/**
 * @brief Cast a vote on a wall post
 *
 * This function:
 * 1. Loads existing votes from DHT (if any)
 * 2. Checks if user already voted (rejects if yes - votes are permanent)
 * 3. Adds new vote with Dilithium5 signature
 * 4. Updates vote counts (upvote_count or downvote_count)
 * 5. Re-publishes to DHT with 30-day TTL
 *
 * Vote permanence: Once cast, votes cannot be changed or removed.
 * One vote per fingerprint per post.
 *
 * Signature: Dilithium5_sign(post_id + vote_value + timestamp, voter_private_key)
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID to vote on (fingerprint_timestamp format)
 * @param voter_fingerprint Voter's SHA3-512 fingerprint (128 hex chars)
 * @param vote_value +1 for upvote, -1 for downvote
 * @param private_key Dilithium5 private key for signing (4896 bytes)
 * @return 0 on success, -1 on error, -2 if already voted
 */
int dna_cast_vote(dht_context_t *dht_ctx,
                  const char *post_id,
                  const char *voter_fingerprint,
                  int8_t vote_value,
                  const uint8_t *private_key);

/**
 * @brief Load votes for a wall post from DHT
 *
 * This function:
 * 1. Queries DHT for votes at SHA256(post_id + ":votes")
 * 2. Parses JSON with vote data
 * 3. Verifies all Dilithium5 signatures
 * 4. Returns aggregated votes structure (caller must free)
 *
 * @param dht_ctx DHT context
 * @param post_id Post ID to load votes for
 * @param votes_out Output: Allocated votes structure (caller frees with dna_wall_votes_free)
 * @return 0 on success, -1 on error, -2 if no votes found
 */
int dna_load_votes(dht_context_t *dht_ctx,
                   const char *post_id,
                   dna_wall_votes_t **votes_out);

/**
 * @brief Get user's vote on a post
 *
 * Checks if a user has already voted on a post and returns their vote value.
 *
 * @param votes Votes structure (from dna_load_votes)
 * @param voter_fingerprint Voter's SHA3-512 fingerprint
 * @return +1 if upvoted, -1 if downvoted, 0 if not voted
 */
int8_t dna_get_user_vote(const dna_wall_votes_t *votes, const char *voter_fingerprint);

/**
 * @brief Free votes structure
 *
 * @param votes Votes structure to free (can be NULL)
 */
void dna_wall_votes_free(dna_wall_votes_t *votes);

/**
 * @brief Verify vote signature
 *
 * Verifies that a vote was signed by the claimed voter.
 *
 * @param vote Vote to verify
 * @param post_id Post ID the vote is for
 * @param public_key Voter's Dilithium5 public key (2592 bytes)
 * @return 0 if valid, -1 if invalid
 */
int dna_verify_vote_signature(const dna_wall_vote_t *vote,
                               const char *post_id,
                               const uint8_t *public_key);

#ifdef __cplusplus
}
#endif

#endif /* DNA_WALL_VOTES_H */
