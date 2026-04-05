#include "dna_debug_log_wire.h"
#include <string.h>
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_aes.h"
#include "crypto/utils/qgp_random.h"

static void write_be16(uint8_t *dst, uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v & 0xFF);
}
static uint16_t read_be16(const uint8_t *src) {
    return ((uint16_t)src[0] << 8) | (uint16_t)src[1];
}
static void write_be32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v & 0xFF);
}
static uint32_t read_be32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

int dna_debug_log_encode_inner(
    const char *hint, size_t hint_len,
    const uint8_t *log_body, size_t log_len,
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out)
{
    if (!log_body || !inner_out || !inner_len_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (hint_len > 0 && !hint) return DNA_DEBUG_LOG_ERR_NULL;
    if (hint_len > DNA_DEBUG_LOG_MAX_HINT_LEN) return DNA_DEBUG_LOG_ERR_HINT_INVALID;
    if (log_len > DNA_DEBUG_LOG_MAX_BODY_LEN) return DNA_DEBUG_LOG_ERR_OVERSIZE;

    size_t need = DNA_DEBUG_LOG_INNER_HDR_LEN + hint_len + log_len;
    if (inner_cap < need) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    write_be16(inner_out + 0, (uint16_t)hint_len);
    if (hint_len) memcpy(inner_out + 2, hint, hint_len);
    write_be32(inner_out + 2 + hint_len, (uint32_t)log_len);
    memcpy(inner_out + 6 + hint_len, log_body, log_len);
    *inner_len_out = need;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_decode_inner(
    const uint8_t *inner, size_t inner_len,
    char *hint_out, size_t hint_cap,
    const uint8_t **body_out_ptr, size_t *body_len_out)
{
    if (!inner || !hint_out || !body_out_ptr || !body_len_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (hint_cap < DNA_DEBUG_LOG_MAX_HINT_LEN + 1) return DNA_DEBUG_LOG_ERR_HINT_INVALID;
    if (inner_len < DNA_DEBUG_LOG_INNER_HDR_LEN) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint16_t hint_len = read_be16(inner);
    if (hint_len > DNA_DEBUG_LOG_MAX_HINT_LEN) return DNA_DEBUG_LOG_ERR_HINT_INVALID;
    if (inner_len < 2u + hint_len + 4u) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint32_t body_len = read_be32(inner + 2 + hint_len);
    if (body_len > DNA_DEBUG_LOG_MAX_BODY_LEN) return DNA_DEBUG_LOG_ERR_BODY_INVALID;
    if (inner_len != (size_t)(2u + hint_len + 4u + body_len)) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    if (hint_len) memcpy(hint_out, inner + 2, hint_len);
    hint_out[hint_len] = 0;
    *body_out_ptr = inner + 2 + hint_len + 4;
    *body_len_out = body_len;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_encode_outer(
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *outer_out, size_t outer_cap, size_t *outer_len_out)
{
    if (!kyber_ct || !nonce || !enc_inner || !gcm_tag || !outer_out || !outer_len_out)
        return DNA_DEBUG_LOG_ERR_NULL;
    size_t need = 1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN
                + enc_inner_len + DNA_DEBUG_LOG_GCM_TAG_LEN;
    if (need > DNA_DEBUG_LOG_MAX_OUTER_LEN) return DNA_DEBUG_LOG_ERR_OVERSIZE;
    if (outer_cap < need) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    size_t off = 0;
    outer_out[off++] = DNA_DEBUG_LOG_WIRE_VERSION;
    memcpy(outer_out + off, kyber_ct, DNA_DEBUG_LOG_KYBER_CT_LEN); off += DNA_DEBUG_LOG_KYBER_CT_LEN;
    memcpy(outer_out + off, nonce, DNA_DEBUG_LOG_GCM_NONCE_LEN);   off += DNA_DEBUG_LOG_GCM_NONCE_LEN;
    memcpy(outer_out + off, enc_inner, enc_inner_len);             off += enc_inner_len;
    memcpy(outer_out + off, gcm_tag, DNA_DEBUG_LOG_GCM_TAG_LEN);   off += DNA_DEBUG_LOG_GCM_TAG_LEN;
    *outer_len_out = off;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_decode_outer(
    const uint8_t *outer, size_t outer_len,
    const uint8_t **kyber_ct_ptr, const uint8_t **nonce_ptr,
    const uint8_t **enc_inner_ptr, size_t *enc_inner_len_out,
    const uint8_t **gcm_tag_ptr)
{
    if (!outer || !kyber_ct_ptr || !nonce_ptr || !enc_inner_ptr ||
        !enc_inner_len_out || !gcm_tag_ptr) return DNA_DEBUG_LOG_ERR_NULL;
    size_t fixed = 1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN
                 + DNA_DEBUG_LOG_GCM_TAG_LEN;
    if (outer_len < fixed + 1u) return DNA_DEBUG_LOG_ERR_TRUNCATED;
    if (outer[0] != DNA_DEBUG_LOG_WIRE_VERSION) return DNA_DEBUG_LOG_ERR_VERSION;

    *kyber_ct_ptr = outer + 1;
    *nonce_ptr    = outer + 1 + DNA_DEBUG_LOG_KYBER_CT_LEN;
    *enc_inner_ptr = outer + 1 + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN;
    *enc_inner_len_out = outer_len - fixed;
    *gcm_tag_ptr  = outer + outer_len - DNA_DEBUG_LOG_GCM_TAG_LEN;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_encrypt_inner(
    const uint8_t receiver_kyber_pub[1568],
    const uint8_t *inner, size_t inner_len,
    uint8_t kyber_ct_out[DNA_DEBUG_LOG_KYBER_CT_LEN],
    uint8_t nonce_out[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    uint8_t *enc_inner_out, size_t enc_inner_cap,
    uint8_t gcm_tag_out[DNA_DEBUG_LOG_GCM_TAG_LEN])
{
    if (!receiver_kyber_pub || !inner || !kyber_ct_out || !nonce_out ||
        !enc_inner_out || !gcm_tag_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (enc_inner_cap < inner_len) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint8_t shared_secret[QGP_KEM1024_SHAREDSECRET_BYTES];
    if (qgp_kem1024_encapsulate(kyber_ct_out, shared_secret, receiver_kyber_pub) != 0) {
        memset(shared_secret, 0, sizeof(shared_secret));
        return DNA_DEBUG_LOG_ERR_KEM_FAIL;
    }

    /* qgp_aes256_encrypt generates a random 12-byte nonce and writes it to nonce_out. */
    size_t ct_len = 0;
    int rc = qgp_aes256_encrypt(shared_secret,
                                inner, inner_len,
                                NULL, 0,
                                enc_inner_out, &ct_len,
                                nonce_out, gcm_tag_out);
    memset(shared_secret, 0, sizeof(shared_secret));
    if (rc != 0 || ct_len != inner_len) return DNA_DEBUG_LOG_ERR_GCM_FAIL;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_decrypt_inner(
    const uint8_t *receiver_kyber_sk, size_t receiver_kyber_sk_len,
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out)
{
    if (!receiver_kyber_sk || !kyber_ct || !nonce || !enc_inner || !gcm_tag ||
        !inner_out || !inner_len_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (receiver_kyber_sk_len < QGP_KEM1024_SECRETKEYBYTES) return DNA_DEBUG_LOG_ERR_TRUNCATED;
    if (inner_cap < enc_inner_len) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint8_t shared_secret[QGP_KEM1024_SHAREDSECRET_BYTES];
    if (qgp_kem1024_decapsulate(shared_secret, kyber_ct, receiver_kyber_sk) != 0) {
        memset(shared_secret, 0, sizeof(shared_secret));
        return DNA_DEBUG_LOG_ERR_KEM_FAIL;
    }

    size_t pt_len = 0;
    int rc = qgp_aes256_decrypt(shared_secret,
                                enc_inner, enc_inner_len,
                                NULL, 0,
                                nonce, gcm_tag,
                                inner_out, &pt_len);
    memset(shared_secret, 0, sizeof(shared_secret));
    if (rc != 0) return DNA_DEBUG_LOG_ERR_GCM_FAIL;
    *inner_len_out = pt_len;
    return DNA_DEBUG_LOG_OK;
}
