/*
 * DNA Wall Votes - Community Voting System Implementation
 */

#include "dna_wall_votes.h"
#include "../../crypto/utils/qgp_dilithium.h"
#include "../../crypto/utils/qgp_types.h"
#include "../core/dht_context.h"
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

// Network byte order conversion for uint64_t
static uint64_t htonll(uint64_t value) {
    static const int num = 42;
    if (*(char *)&num == 42) {  // Little endian
        uint32_t high = htonl((uint32_t)(value >> 32));
        uint32_t low = htonl((uint32_t)(value & 0xFFFFFFFF));
        return ((uint64_t)low << 32) | high;
    }
    return value;  // Big endian
}

static uint64_t ntohll(uint64_t value) {
    return htonll(value);  // Same operation
}

/**
 * Generate DHT key for votes
 */
static int dna_wall_votes_get_dht_key(const char *post_id, char *dht_key_out) {
    if (!post_id || !dht_key_out) {
        return -1;
    }

    // Key format: SHA256(post_id + ":votes")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:votes", post_id);

    // SHA256 hash using OpenSSL EVP
    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[DNA_VOTES] Failed to create EVP context\n");
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, key_input, strlen(key_input)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fprintf(stderr, "[DNA_VOTES] Failed to compute SHA256\n");
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    // Convert to hex
    for (int i = 0; i < 32; i++) {
        sprintf(dht_key_out + (i * 2), "%02x", hash[i]);
    }
    dht_key_out[64] = '\0';

    return 0;
}

/**
 * Serialize votes to JSON
 */
static char* dna_wall_votes_to_json(const dna_wall_votes_t *votes) {
    if (!votes) {
        return NULL;
    }

    json_object *j_root = json_object_new_object();
    json_object_object_add(j_root, "post_id", json_object_new_string(votes->post_id));
    json_object_object_add(j_root, "upvote_count", json_object_new_int(votes->upvote_count));
    json_object_object_add(j_root, "downvote_count", json_object_new_int(votes->downvote_count));

    // Individual votes array
    json_object *j_votes_array = json_object_new_array();
    for (size_t i = 0; i < votes->vote_count; i++) {
        const dna_wall_vote_t *vote = &votes->votes[i];
        json_object *j_vote = json_object_new_object();

        json_object_object_add(j_vote, "voter", json_object_new_string(vote->voter_fingerprint));
        json_object_object_add(j_vote, "vote", json_object_new_int(vote->vote_value));
        json_object_object_add(j_vote, "timestamp", json_object_new_int64(vote->timestamp));

        // Base64 encode signature
        size_t sig_b64_len = 0;
        char *sig_b64 = qgp_base64_encode(vote->signature, vote->signature_len, &sig_b64_len);
        if (sig_b64) {
            json_object_object_add(j_vote, "signature", json_object_new_string(sig_b64));
            free(sig_b64);
        }

        json_object_array_add(j_votes_array, j_vote);
    }
    json_object_object_add(j_root, "votes", j_votes_array);

    const char *json_str = json_object_to_json_string_ext(j_root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);
    json_object_put(j_root);

    return result;
}

/**
 * Parse votes from JSON
 */
static int dna_wall_votes_from_json(const char *json, dna_wall_votes_t **votes_out) {
    if (!json || !votes_out) {
        return -1;
    }

    json_object *j_root = json_tokener_parse(json);
    if (!j_root) {
        fprintf(stderr, "[DNA_VOTES] Failed to parse JSON\n");
        return -1;
    }

    dna_wall_votes_t *votes = calloc(1, sizeof(dna_wall_votes_t));
    if (!votes) {
        json_object_put(j_root);
        return -1;
    }

    // Parse post_id
    json_object *j_post_id = NULL;
    if (json_object_object_get_ex(j_root, "post_id", &j_post_id)) {
        strncpy(votes->post_id, json_object_get_string(j_post_id), sizeof(votes->post_id) - 1);
    }

    // Parse counts
    json_object *j_upvote_count = NULL, *j_downvote_count = NULL;
    if (json_object_object_get_ex(j_root, "upvote_count", &j_upvote_count)) {
        votes->upvote_count = json_object_get_int(j_upvote_count);
    }
    if (json_object_object_get_ex(j_root, "downvote_count", &j_downvote_count)) {
        votes->downvote_count = json_object_get_int(j_downvote_count);
    }

    // Parse individual votes
    json_object *j_votes_array = NULL;
    if (json_object_object_get_ex(j_root, "votes", &j_votes_array)) {
        size_t array_len = json_object_array_length(j_votes_array);
        votes->votes = calloc(array_len, sizeof(dna_wall_vote_t));
        if (!votes->votes) {
            free(votes);
            json_object_put(j_root);
            return -1;
        }
        votes->allocated_count = array_len;

        for (size_t i = 0; i < array_len; i++) {
            json_object *j_vote = json_object_array_get_idx(j_votes_array, i);
            dna_wall_vote_t *vote = &votes->votes[votes->vote_count];

            // Voter fingerprint
            json_object *j_voter = NULL;
            if (json_object_object_get_ex(j_vote, "voter", &j_voter)) {
                strncpy(vote->voter_fingerprint, json_object_get_string(j_voter),
                       sizeof(vote->voter_fingerprint) - 1);
            }

            // Vote value
            json_object *j_value = NULL;
            if (json_object_object_get_ex(j_vote, "vote", &j_value)) {
                vote->vote_value = (int8_t)json_object_get_int(j_value);
            }

            // Timestamp
            json_object *j_timestamp = NULL;
            if (json_object_object_get_ex(j_vote, "timestamp", &j_timestamp)) {
                vote->timestamp = (uint64_t)json_object_get_int64(j_timestamp);
            }

            // Signature (base64 decode)
            json_object *j_signature = NULL;
            if (json_object_object_get_ex(j_vote, "signature", &j_signature)) {
                const char *sig_b64 = json_object_get_string(j_signature);
                size_t sig_len = 0;
                uint8_t *sig_data = qgp_base64_decode(sig_b64, &sig_len);
                if (sig_data && sig_len <= sizeof(vote->signature)) {
                    memcpy(vote->signature, sig_data, sig_len);
                    vote->signature_len = sig_len;
                    free(sig_data);
                    votes->vote_count++;
                }
            }
        }
    }

    json_object_put(j_root);
    *votes_out = votes;
    return 0;
}

/**
 * Verify vote signature
 */
int dna_verify_vote_signature(const dna_wall_vote_t *vote,
                               const char *post_id,
                               const uint8_t *public_key) {
    if (!vote || !post_id || !public_key) {
        return -1;
    }

    // Build signature data: post_id + vote_value + timestamp
    size_t post_id_len = strlen(post_id);
    size_t data_len = post_id_len + sizeof(int8_t) + sizeof(uint64_t);
    uint8_t *sign_data = malloc(data_len);
    if (!sign_data) {
        return -1;
    }

    memcpy(sign_data, post_id, post_id_len);
    memcpy(sign_data + post_id_len, &vote->vote_value, sizeof(int8_t));
    uint64_t ts_net = htonll(vote->timestamp);
    memcpy(sign_data + post_id_len + sizeof(int8_t), &ts_net, sizeof(uint64_t));

    // Verify signature
    int result = qgp_dsa87_verify(vote->signature, vote->signature_len,
                                  sign_data, data_len,
                                  public_key);

    free(sign_data);
    return result;
}

/**
 * Get user's vote on a post
 */
int8_t dna_get_user_vote(const dna_wall_votes_t *votes, const char *voter_fingerprint) {
    if (!votes || !voter_fingerprint) {
        return 0;
    }

    for (size_t i = 0; i < votes->vote_count; i++) {
        if (strcmp(votes->votes[i].voter_fingerprint, voter_fingerprint) == 0) {
            return votes->votes[i].vote_value;
        }
    }

    return 0;  // Not voted
}

/**
 * Load votes from DHT
 */
int dna_load_votes(dht_context_t *dht_ctx,
                   const char *post_id,
                   dna_wall_votes_t **votes_out) {
    if (!dht_ctx || !post_id || !votes_out) {
        return -1;
    }

    // Get DHT key
    char dht_key[65];
    if (dna_wall_votes_get_dht_key(post_id, dht_key) != 0) {
        return -1;
    }

    printf("[DNA_VOTES] → DHT GET: Loading votes for post\n");

    // Query DHT
    uint8_t *value_data = NULL;
    size_t value_size = 0;
    int ret = dht_get(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                      &value_data, &value_size);

    if (ret != 0) {
        printf("[DNA_VOTES] No votes found in DHT\n");
        return -2;  // No votes
    }

    printf("[DNA_VOTES] ✓ Found votes in DHT (%zu bytes)\n", value_size);

    // Parse JSON
    char *json_str = strndup((const char *)value_data, value_size);
    free(value_data);

    ret = dna_wall_votes_from_json(json_str, votes_out);
    free(json_str);

    if (ret != 0) {
        fprintf(stderr, "[DNA_VOTES] Failed to parse votes JSON\n");
        return -1;
    }

    printf("[DNA_VOTES] ✓ Loaded votes (up=%d, down=%d, total=%zu)\n",
           (*votes_out)->upvote_count, (*votes_out)->downvote_count, (*votes_out)->vote_count);

    return 0;
}

/**
 * Cast a vote on a wall post
 */
int dna_cast_vote(dht_context_t *dht_ctx,
                  const char *post_id,
                  const char *voter_fingerprint,
                  int8_t vote_value,
                  const uint8_t *private_key) {
    if (!dht_ctx || !post_id || !voter_fingerprint || !private_key) {
        return -1;
    }

    if (vote_value != 1 && vote_value != -1) {
        fprintf(stderr, "[DNA_VOTES] Invalid vote value (must be +1 or -1)\n");
        return -1;
    }

    // Load existing votes (or create new)
    dna_wall_votes_t *votes = NULL;
    int ret = dna_load_votes(dht_ctx, post_id, &votes);
    if (ret == -2) {
        // No votes yet, create new structure
        votes = calloc(1, sizeof(dna_wall_votes_t));
        if (!votes) {
            return -1;
        }
        strncpy(votes->post_id, post_id, sizeof(votes->post_id) - 1);
        votes->upvote_count = 0;
        votes->downvote_count = 0;
        votes->votes = NULL;
        votes->vote_count = 0;
        votes->allocated_count = 0;
    } else if (ret != 0) {
        fprintf(stderr, "[DNA_VOTES] Failed to load existing votes\n");
        return -1;
    }

    // Check if user already voted (votes are permanent)
    int8_t existing_vote = dna_get_user_vote(votes, voter_fingerprint);
    if (existing_vote != 0) {
        fprintf(stderr, "[DNA_VOTES] User already voted (votes are permanent)\n");
        dna_wall_votes_free(votes);
        return -2;  // Already voted
    }

    // Add vote to array
    if (votes->vote_count >= votes->allocated_count) {
        size_t new_capacity = votes->allocated_count == 0 ? 16 : votes->allocated_count * 2;
        dna_wall_vote_t *new_votes = realloc(votes->votes, new_capacity * sizeof(dna_wall_vote_t));
        if (!new_votes) {
            dna_wall_votes_free(votes);
            return -1;
        }
        votes->votes = new_votes;
        votes->allocated_count = new_capacity;
    }

    dna_wall_vote_t *new_vote = &votes->votes[votes->vote_count];
    memset(new_vote, 0, sizeof(dna_wall_vote_t));

    strncpy(new_vote->voter_fingerprint, voter_fingerprint, sizeof(new_vote->voter_fingerprint) - 1);
    new_vote->vote_value = vote_value;
    new_vote->timestamp = (uint64_t)time(NULL);

    // Sign vote: Dilithium5_sign(post_id + vote_value + timestamp)
    size_t post_id_len = strlen(post_id);
    size_t data_len = post_id_len + sizeof(int8_t) + sizeof(uint64_t);
    uint8_t *sign_data = malloc(data_len);
    if (!sign_data) {
        dna_wall_votes_free(votes);
        return -1;
    }

    memcpy(sign_data, post_id, post_id_len);
    memcpy(sign_data + post_id_len, &vote_value, sizeof(int8_t));
    uint64_t ts_net = htonll(new_vote->timestamp);
    memcpy(sign_data + post_id_len + sizeof(int8_t), &ts_net, sizeof(uint64_t));

    size_t sig_len = sizeof(new_vote->signature);
    ret = qgp_dsa87_sign(new_vote->signature, &sig_len,
                         sign_data, data_len,
                         private_key);
    free(sign_data);

    if (ret != 0) {
        fprintf(stderr, "[DNA_VOTES] Failed to sign vote\n");
        dna_wall_votes_free(votes);
        return -1;
    }

    new_vote->signature_len = sig_len;
    votes->vote_count++;

    // Update counts
    if (vote_value == 1) {
        votes->upvote_count++;
    } else {
        votes->downvote_count++;
    }

    // Serialize to JSON
    char *json_data = dna_wall_votes_to_json(votes);
    if (!json_data) {
        dna_wall_votes_free(votes);
        return -1;
    }

    // Publish to DHT
    char dht_key[65];
    if (dna_wall_votes_get_dht_key(post_id, dht_key) != 0) {
        free(json_data);
        dna_wall_votes_free(votes);
        return -1;
    }

    printf("[DNA_VOTES] → DHT PUT: Publishing votes (up=%d, down=%d, total=%zu)\n",
           votes->upvote_count, votes->downvote_count, votes->vote_count);

    ret = dht_put(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                  (const uint8_t *)json_data, strlen(json_data));

    free(json_data);
    dna_wall_votes_free(votes);

    if (ret != 0) {
        fprintf(stderr, "[DNA_VOTES] Failed to publish votes to DHT\n");
        return -1;
    }

    printf("[DNA_VOTES] ✓ Vote cast successfully (post=%s, voter=%s, value=%+d)\n",
           post_id, voter_fingerprint, vote_value);

    return 0;
}

/**
 * Free votes structure
 */
void dna_wall_votes_free(dna_wall_votes_t *votes) {
    if (!votes) {
        return;
    }

    if (votes->votes) {
        free(votes->votes);
    }

    free(votes);
}
