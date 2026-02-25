/*
 * DNA Wall - Personal wall posts stored on DHT
 *
 * Each user's wall posts are stored under a per-user DHT key:
 *   SHA3-512("dna:wall:<fingerprint>")
 *
 * Posts are signed with Dilithium5 for authenticity.
 * Max 50 posts per user, 30-day TTL, text-only (MVP).
 */

#ifndef DNA_WALL_H
#define DNA_WALL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/dht_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ── */
#define DNA_WALL_MAX_TEXT_LEN    2048
#define DNA_WALL_MAX_POSTS       50
#define DNA_WALL_TTL_DAYS        30
#define DNA_WALL_KEY_PREFIX      "dna:wall:"

/* ── Data Structures ── */

/**
 * Single wall post
 */
typedef struct {
    char uuid[37];                      /* UUID v4 */
    char author_fingerprint[129];       /* SHA3-512 hex */
    char text[DNA_WALL_MAX_TEXT_LEN];   /* Post content */
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
int dna_wall_post(dht_context_t *dht,
                  const char *fingerprint,
                  const uint8_t *private_key,
                  const char *text,
                  dna_wall_post_t *out_post);

/**
 * Delete a post from own wall
 * @param dht          DHT context
 * @param fingerprint  Owner's SHA3-512 fingerprint
 * @param private_key  Owner's Dilithium5 private key
 * @param post_uuid    UUID of post to delete
 * @return 0 on success, negative on error
 */
int dna_wall_delete(dht_context_t *dht,
                    const char *fingerprint,
                    const uint8_t *private_key,
                    const char *post_uuid);

/**
 * Load a user's wall posts from DHT
 * @param dht          DHT context
 * @param fingerprint  Wall owner's fingerprint
 * @param wall         Output wall structure (caller must free with dna_wall_free)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_wall_load(dht_context_t *dht, const char *fingerprint,
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

#ifdef __cplusplus
}
#endif

#endif /* DNA_WALL_H */
