/*
 * DNA Feed - Vote Operations
 *
 * Implements voting system for the public feed.
 * Votes are permanent - once cast, they cannot be changed.
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 */

#include "dna_feed.h"
#include "../shared/dht_chunked.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"
#define LOG_TAG "DNA_VOTES"

/* Dilithium5 functions */
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

/* Network byte order helpers */
static inline uint64_t htonll_vote(uint64_t value) {
    static const int num = 1;
    if (*(char *)&num == 1) {
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    }
    return value;
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int votes_to_json(const dna_feed_votes_t *votes, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "post_id", json_object_new_string(votes->post_id));
    json_object_object_add(root, "upvote_count", json_object_new_int(votes->upvote_count));
    json_object_object_add(root, "downvote_count", json_object_new_int(votes->downvote_count));

    json_object *votes_arr = json_object_new_array();
    for (size_t i = 0; i < votes->vote_count; i++) {
        json_object *vote_obj = json_object_new_object();
        json_object_object_add(vote_obj, "voter",
            json_object_new_string(votes->votes[i].voter_fingerprint));
        json_object_object_add(vote_obj, "value",
            json_object_new_int(votes->votes[i].vote_value));
        json_object_object_add(vote_obj, "timestamp",
            json_object_new_int64(votes->votes[i].timestamp));

        if (votes->votes[i].signature_len > 0) {
            char *sig_b64 = qgp_base64_encode(votes->votes[i].signature, votes->votes[i].signature_len, NULL);
            if (sig_b64) {
                json_object_object_add(vote_obj, "signature", json_object_new_string(sig_b64));
                free(sig_b64);
            }
        }

        json_object_array_add(votes_arr, vote_obj);
    }
    json_object_object_add(root, "votes", votes_arr);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int votes_from_json(const char *json_str, dna_feed_votes_t **votes_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_feed_votes_t *votes = calloc(1, sizeof(dna_feed_votes_t));
    if (!votes) {
        json_object_put(root);
        return -1;
    }

    json_object *j_val;
    if (json_object_object_get_ex(root, "post_id", &j_val))
        strncpy(votes->post_id, json_object_get_string(j_val), sizeof(votes->post_id) - 1);
    if (json_object_object_get_ex(root, "upvote_count", &j_val))
        votes->upvote_count = json_object_get_int(j_val);
    if (json_object_object_get_ex(root, "downvote_count", &j_val))
        votes->downvote_count = json_object_get_int(j_val);

    json_object *j_votes;
    if (json_object_object_get_ex(root, "votes", &j_votes)) {
        size_t count = json_object_array_length(j_votes);
        if (count > 0) {
            votes->votes = calloc(count, sizeof(dna_feed_vote_t));
            votes->allocated_count = count;

            for (size_t i = 0; i < count; i++) {
                json_object *vote_obj = json_object_array_get_idx(j_votes, i);
                if (!vote_obj) continue;

                if (json_object_object_get_ex(vote_obj, "voter", &j_val))
                    strncpy(votes->votes[i].voter_fingerprint, json_object_get_string(j_val),
                            sizeof(votes->votes[i].voter_fingerprint) - 1);
                if (json_object_object_get_ex(vote_obj, "value", &j_val))
                    votes->votes[i].vote_value = (int8_t)json_object_get_int(j_val);
                if (json_object_object_get_ex(vote_obj, "timestamp", &j_val))
                    votes->votes[i].timestamp = json_object_get_int64(j_val);

                if (json_object_object_get_ex(vote_obj, "signature", &j_val)) {
                    const char *sig_b64 = json_object_get_string(j_val);
                    if (sig_b64) {
                        size_t sig_len = 0;
                        uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
                        if (sig_bytes && sig_len <= sizeof(votes->votes[i].signature)) {
                            memcpy(votes->votes[i].signature, sig_bytes, sig_len);
                            votes->votes[i].signature_len = sig_len;
                        }
                        free(sig_bytes);
                    }
                }

                votes->vote_count++;
            }
        }
    }

    json_object_put(root);
    *votes_out = votes;
    return 0;
}

/* ============================================================================
 * Vote Operations
 * ========================================================================== */

void dna_feed_votes_free(dna_feed_votes_t *votes) {
    if (!votes) return;
    free(votes->votes);
    free(votes);
}

int8_t dna_feed_get_user_vote(const dna_feed_votes_t *votes, const char *voter_fingerprint) {
    if (!votes || !voter_fingerprint) return 0;

    for (size_t i = 0; i < votes->vote_count; i++) {
        if (strcmp(votes->votes[i].voter_fingerprint, voter_fingerprint) == 0) {
            return votes->votes[i].vote_value;
        }
    }
    return 0;
}

int dna_feed_verify_vote_signature(const dna_feed_vote_t *vote,
                                   const char *post_id,
                                   const uint8_t *public_key) {
    if (!vote || !post_id || !public_key || vote->signature_len == 0) return -1;

    /* Build signed data: post_id || vote_value || timestamp */
    size_t post_id_len = strlen(post_id);
    size_t data_len = post_id_len + sizeof(int8_t) + sizeof(uint64_t);
    uint8_t *data = malloc(data_len);
    if (!data) return -1;

    memcpy(data, post_id, post_id_len);
    data[post_id_len] = (uint8_t)vote->vote_value;
    uint64_t ts_net = htonll_vote(vote->timestamp);
    memcpy(data + post_id_len + 1, &ts_net, sizeof(uint64_t));

    int ret = pqcrystals_dilithium5_ref_verify(vote->signature, vote->signature_len,
                                                data, data_len, NULL, 0, public_key);
    free(data);
    return (ret == 0) ? 0 : -1;
}

int dna_feed_votes_get(dht_context_t *dht_ctx, const char *post_id, dna_feed_votes_t **votes_out) {
    if (!dht_ctx || !post_id || !votes_out) return -1;

    /* Generate base key for votes */
    char base_key[512];
    snprintf(base_key, sizeof(base_key), "dna:feed:post:%s:votes", post_id);

    QGP_LOG_INFO(LOG_TAG, "Fetching votes for post %s...\n", post_id);

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);

    if (ret != DHT_CHUNK_OK || !value || value_len == 0) {
        /* No votes yet - create empty structure */
        dna_feed_votes_t *votes = calloc(1, sizeof(dna_feed_votes_t));
        if (!votes) return -1;
        strncpy(votes->post_id, post_id, sizeof(votes->post_id) - 1);
        *votes_out = votes;
        return -2;
    }

    char *json_str = malloc(value_len + 1);
    if (!json_str) {
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    ret = votes_from_json(json_str, votes_out);
    free(json_str);

    if (ret == 0) {
        QGP_LOG_INFO(LOG_TAG, "Loaded %zu votes (up=%d, down=%d)\n",
               (*votes_out)->vote_count, (*votes_out)->upvote_count, (*votes_out)->downvote_count);
    }

    return ret;
}

int dna_feed_vote_cast(dht_context_t *dht_ctx,
                       const char *post_id,
                       const char *voter_fingerprint,
                       int8_t vote_value,
                       const uint8_t *private_key) {
    if (!dht_ctx || !post_id || !voter_fingerprint || !private_key) return -1;

    /* Validate vote value */
    if (vote_value != 1 && vote_value != -1) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid vote value (must be +1 or -1)\n");
        return -1;
    }

    /* Load existing votes */
    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_votes_get(dht_ctx, post_id, &votes);
    if (ret == -1) return -1;  /* Error */

    /* Check if user already voted */
    if (dna_feed_get_user_vote(votes, voter_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "User already voted on this post\n");
        dna_feed_votes_free(votes);
        return -2;
    }

    /* Create new vote */
    dna_feed_vote_t new_vote = {0};
    strncpy(new_vote.voter_fingerprint, voter_fingerprint, sizeof(new_vote.voter_fingerprint) - 1);
    new_vote.vote_value = vote_value;
    new_vote.timestamp = (uint64_t)time(NULL);

    /* Sign vote: post_id || vote_value || timestamp */
    size_t post_id_len = strlen(post_id);
    size_t data_len = post_id_len + sizeof(int8_t) + sizeof(uint64_t);
    uint8_t *sign_data = malloc(data_len);
    if (!sign_data) {
        dna_feed_votes_free(votes);
        return -1;
    }

    memcpy(sign_data, post_id, post_id_len);
    sign_data[post_id_len] = (uint8_t)vote_value;
    uint64_t ts_net = htonll_vote(new_vote.timestamp);
    memcpy(sign_data + post_id_len + 1, &ts_net, sizeof(uint64_t));

    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(new_vote.signature, &sig_len,
                                               sign_data, data_len,
                                               NULL, 0, private_key);
    free(sign_data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign vote\n");
        dna_feed_votes_free(votes);
        return -1;
    }
    new_vote.signature_len = sig_len;

    /* Add vote to structure */
    size_t new_count = votes->vote_count + 1;
    dna_feed_vote_t *new_votes = realloc(votes->votes, new_count * sizeof(dna_feed_vote_t));
    if (!new_votes) {
        dna_feed_votes_free(votes);
        return -1;
    }

    votes->votes = new_votes;
    votes->votes[votes->vote_count] = new_vote;
    votes->vote_count = new_count;
    votes->allocated_count = new_count;

    /* Update counts */
    if (vote_value == 1) {
        votes->upvote_count++;
    } else {
        votes->downvote_count++;
    }

    /* Serialize and publish using chunked layer */
    char *json_data = NULL;
    if (votes_to_json(votes, &json_data) != 0) {
        dna_feed_votes_free(votes);
        return -1;
    }

    char base_key[512];
    snprintf(base_key, sizeof(base_key), "dna:feed:post:%s:votes", post_id);

    QGP_LOG_INFO(LOG_TAG, "Publishing vote to DHT...\n");
    ret = dht_chunked_publish(dht_ctx, base_key,
                              (const uint8_t *)json_data, strlen(json_data),
                              DNA_FEED_TTL_SECONDS);
    free(json_data);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish vote: %s\n", dht_chunked_strerror(ret));
        dna_feed_votes_free(votes);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully cast %s on post %s\n",
           vote_value == 1 ? "upvote" : "downvote", post_id);

    dna_feed_votes_free(votes);
    return 0;
}
