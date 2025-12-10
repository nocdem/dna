/**
 * DHT Contact Request System for DNA Messenger
 *
 * ICQ-style contact request system where:
 * - Alice sends a contact request to Bob
 * - Bob sees "Alice wants to connect" with optional message
 * - Bob can Accept (mutual contact), Deny (ignorable), or Block (permanent)
 * - Messages from pending requests are hidden until approved
 *
 * Architecture:
 * - Storage Key: SHA3-512(recipient_fingerprint + ":requests")
 * - Each requester writes a signed value with their own value_id
 * - Multiple requesters can write to the same inbox key
 * - Uses dht_get_all() to retrieve all pending requests
 * - TTL: 7 days (request expires if not acted upon)
 *
 * Request Format (signed with Dilithium5):
 * [4-byte magic "DNAR"][1-byte version][8-byte timestamp][8-byte expiry]
 * [129-byte sender_fingerprint][64-byte sender_name][2592-byte dilithium_pubkey]
 * [256-byte message][variable signature]
 *
 * @file dht_contact_request.h
 * @author DNA Messenger Team
 * @date 2025-12-10
 */

#ifndef DHT_CONTACT_REQUEST_H
#define DHT_CONTACT_REQUEST_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic bytes for request format validation */
#define DHT_CONTACT_REQUEST_MAGIC 0x444E4152  /* "DNAR" (DNA Request) */
#define DHT_CONTACT_REQUEST_VERSION 1

/* Default TTL: 7 days */
#define DHT_CONTACT_REQUEST_DEFAULT_TTL 604800

/* Dilithium5 key sizes */
#define DHT_DILITHIUM5_PUBKEY_SIZE 2592
#define DHT_DILITHIUM5_SIG_MAX_SIZE 4627

/**
 * Contact request structure
 */
typedef struct {
    uint32_t magic;                                   /* "DNAR" */
    uint8_t version;                                  /* Request format version */
    uint64_t timestamp;                               /* Unix timestamp when request sent */
    uint64_t expiry;                                  /* Unix timestamp when request expires */
    char sender_fingerprint[129];                     /* Requester's SHA3-512 fingerprint */
    char sender_name[64];                             /* Display name (if registered) */
    uint8_t sender_dilithium_pubkey[DHT_DILITHIUM5_PUBKEY_SIZE]; /* For verification */
    char message[256];                                /* Optional "Hey, add me!" message */
    uint8_t signature[DHT_DILITHIUM5_SIG_MAX_SIZE];   /* Dilithium5 signature over all above */
    size_t signature_len;                             /* Actual signature length */
} dht_contact_request_t;

/**
 * Generate DHT key for user's contact requests inbox
 *
 * Key format: SHA3-512(fingerprint + ":requests")
 *
 * Example:
 *   fingerprint = "a3f9e2d1c5b8a7f6..."  (128-char fingerprint)
 *   input = "a3f9e2d1c5b8a7f6...:requests"
 *   output = SHA3-512(input) = 64-byte hash
 *
 * @param fingerprint User's fingerprint (128 hex chars)
 * @param key_out Output buffer (64 bytes for SHA3-512)
 */
void dht_generate_requests_inbox_key(
    const char *fingerprint,
    uint8_t *key_out
);

/**
 * Send a contact request to recipient
 *
 * Workflow:
 * 1. Build dht_contact_request_t structure
 * 2. Sign with sender's Dilithium5 private key
 * 3. Serialize to binary format
 * 4. Generate recipient's inbox key: SHA3-512(recipient + ":requests")
 * 5. Publish with dht_put_signed() using sender-specific value_id
 *
 * Note: Uses signed put with value_id derived from sender's fingerprint
 *       to allow multiple requesters to write to same inbox.
 *
 * @param ctx DHT context
 * @param sender_fingerprint Sender's fingerprint (128 hex chars)
 * @param sender_name Sender's display name (can be empty)
 * @param sender_dilithium_pubkey Sender's Dilithium5 public key (2592 bytes)
 * @param sender_dilithium_privkey Sender's Dilithium5 private key for signing
 * @param recipient_fingerprint Recipient's fingerprint (128 hex chars)
 * @param optional_message Optional message (can be NULL, max 255 chars)
 * @return 0 on success, -1 on failure
 */
int dht_send_contact_request(
    dht_context_t *ctx,
    const char *sender_fingerprint,
    const char *sender_name,
    const uint8_t *sender_dilithium_pubkey,
    const uint8_t *sender_dilithium_privkey,
    const char *recipient_fingerprint,
    const char *optional_message
);

/**
 * Fetch all pending contact requests from my inbox
 *
 * Workflow:
 * 1. Generate my inbox key: SHA3-512(my_fingerprint + ":requests")
 * 2. Query DHT with dht_get_all() to get all values from all requesters
 * 3. Deserialize and verify each request signature
 * 4. Filter out expired requests
 * 5. Return valid requests array
 *
 * @param ctx DHT context
 * @param my_fingerprint My fingerprint (128 hex chars)
 * @param requests_out Output array (caller must free with dht_contact_requests_free)
 * @param count_out Output count of requests
 * @return 0 on success, -1 on failure
 */
int dht_fetch_contact_requests(
    dht_context_t *ctx,
    const char *my_fingerprint,
    dht_contact_request_t **requests_out,
    size_t *count_out
);

/**
 * Verify a contact request signature
 *
 * Checks:
 * 1. Magic bytes == "DNAR"
 * 2. Version is supported
 * 3. Request not expired
 * 4. Dilithium5 signature is valid
 * 5. Fingerprint matches SHA3-512(pubkey)
 *
 * @param request Request to verify
 * @return 0 if valid, -1 if invalid/forged
 */
int dht_verify_contact_request(const dht_contact_request_t *request);

/**
 * Cancel a previously sent contact request
 *
 * Removes the request from recipient's inbox by publishing
 * an empty/expired value with same value_id.
 *
 * @param ctx DHT context
 * @param sender_fingerprint Sender's fingerprint (must match original request)
 * @param recipient_fingerprint Recipient's fingerprint
 * @return 0 on success, -1 on failure
 */
int dht_cancel_contact_request(
    dht_context_t *ctx,
    const char *sender_fingerprint,
    const char *recipient_fingerprint
);

/**
 * Serialize contact request to binary format
 *
 * Format:
 * [4-byte magic][1-byte version][8-byte timestamp][8-byte expiry]
 * [129-byte sender_fp][64-byte sender_name][2592-byte pubkey]
 * [256-byte message][2-byte sig_len][signature bytes]
 *
 * @param request Request to serialize
 * @param out Output buffer (caller must free)
 * @param len_out Output length
 * @return 0 on success, -1 on failure
 */
int dht_serialize_contact_request(
    const dht_contact_request_t *request,
    uint8_t **out,
    size_t *len_out
);

/**
 * Deserialize contact request from binary format
 *
 * @param data Serialized data
 * @param len Length of data
 * @param request_out Output request structure
 * @return 0 on success, -1 on failure
 */
int dht_deserialize_contact_request(
    const uint8_t *data,
    size_t len,
    dht_contact_request_t *request_out
);

/**
 * Free array of contact requests
 *
 * @param requests Array to free
 * @param count Number of requests in array
 */
void dht_contact_requests_free(dht_contact_request_t *requests, size_t count);

/**
 * Generate value_id for DHT signed put from fingerprint
 *
 * Converts first 8 bytes of fingerprint to uint64_t for use as value_id.
 * This ensures each sender has a unique value_id for their request.
 *
 * @param fingerprint Fingerprint string (128 hex chars)
 * @return Value ID for DHT put
 */
uint64_t dht_fingerprint_to_value_id(const char *fingerprint);

#ifdef __cplusplus
}
#endif

#endif /* DHT_CONTACT_REQUEST_H */
