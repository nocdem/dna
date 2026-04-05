#ifndef DNA_DEBUG_LOG_WIRE_H
#define DNA_DEBUG_LOG_WIRE_H

#include <stddef.h>
#include <stdint.h>

/* Wire format version */
#define DNA_DEBUG_LOG_WIRE_VERSION 0x01

/* Limits (enforced at encode/decode) */
#define DNA_DEBUG_LOG_MAX_HINT_LEN   128u
#define DNA_DEBUG_LOG_MAX_BODY_LEN   (3u * 1024u * 1024u)   /* 3 MB */

/* Fixed-size components */
#define DNA_DEBUG_LOG_KYBER_CT_LEN   1568u
#define DNA_DEBUG_LOG_GCM_NONCE_LEN  12u
#define DNA_DEBUG_LOG_GCM_TAG_LEN    16u

/* Inner plaintext header: 2B hint_len + 4B log_len */
#define DNA_DEBUG_LOG_INNER_HDR_LEN  6u

/* Max outer payload = version(1) + kyber_ct(1568) + nonce(12) + inner_hdr(6)
 *                   + max_hint(128) + max_body(3MB) + gcm_tag(16)
 */
#define DNA_DEBUG_LOG_MAX_OUTER_LEN \
    (1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN + \
     DNA_DEBUG_LOG_INNER_HDR_LEN + DNA_DEBUG_LOG_MAX_HINT_LEN + \
     DNA_DEBUG_LOG_MAX_BODY_LEN + DNA_DEBUG_LOG_GCM_TAG_LEN)

/* Return codes */
#define DNA_DEBUG_LOG_OK                  0
#define DNA_DEBUG_LOG_ERR_NULL           -1
#define DNA_DEBUG_LOG_ERR_OVERSIZE       -2
#define DNA_DEBUG_LOG_ERR_VERSION        -3
#define DNA_DEBUG_LOG_ERR_TRUNCATED      -4
#define DNA_DEBUG_LOG_ERR_HINT_INVALID   -5
#define DNA_DEBUG_LOG_ERR_BODY_INVALID   -6
#define DNA_DEBUG_LOG_ERR_KEM_FAIL       -7
#define DNA_DEBUG_LOG_ERR_GCM_FAIL       -8

/* Encode inner plaintext (does NOT encrypt) — caller passes this to AES-GCM.
 * inner_out buffer must be >= DNA_DEBUG_LOG_INNER_HDR_LEN + hint_len + log_len.
 */
int dna_debug_log_encode_inner(
    const char *hint, size_t hint_len,
    const uint8_t *log_body, size_t log_len,
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out);

/* Decode inner plaintext. Populates hint_out (NUL-terminated, copied) and
 * body_out_ptr/body_len_out (points into inner, NOT copied).
 */
int dna_debug_log_decode_inner(
    const uint8_t *inner, size_t inner_len,
    char *hint_out, size_t hint_cap,   /* must be >= 129 */
    const uint8_t **body_out_ptr, size_t *body_len_out);

/* Encode outer: version byte + kyber_ct + nonce + encrypted_inner + gcm_tag.
 * outer_out buffer must be >= 1 + 1568 + 12 + enc_inner_len + 16.
 */
int dna_debug_log_encode_outer(
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *outer_out, size_t outer_cap, size_t *outer_len_out);

/* Decode outer. On success, populates pointers into outer (no allocation). */
int dna_debug_log_decode_outer(
    const uint8_t *outer, size_t outer_len,
    const uint8_t **kyber_ct_ptr,
    const uint8_t **nonce_ptr,
    const uint8_t **enc_inner_ptr, size_t *enc_inner_len_out,
    const uint8_t **gcm_tag_ptr);

/* ============================================================================
 * Hybrid encryption helpers (Kyber1024 + AES-256-GCM)
 * ============================================================================ */

/* Encrypt inner plaintext for a receiver's Kyber1024 public key.
 * enc_inner_out capacity: >= inner_len (GCM tag is separate, 16 bytes).
 * Outputs: kyber_ct (1568), nonce (12), enc_inner_out (inner_len), gcm_tag (16).
 */
int dna_debug_log_encrypt_inner(
    const uint8_t receiver_kyber_pub[1568],
    const uint8_t *inner, size_t inner_len,
    uint8_t kyber_ct_out[DNA_DEBUG_LOG_KYBER_CT_LEN],
    uint8_t nonce_out[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    uint8_t *enc_inner_out, size_t enc_inner_cap,
    uint8_t gcm_tag_out[DNA_DEBUG_LOG_GCM_TAG_LEN]);

/* Decrypt. Returns DNA_DEBUG_LOG_ERR_* on MAC failure or bad inputs. */
int dna_debug_log_decrypt_inner(
    const uint8_t *receiver_kyber_sk, size_t receiver_kyber_sk_len,
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out);

#endif /* DNA_DEBUG_LOG_WIRE_H */
