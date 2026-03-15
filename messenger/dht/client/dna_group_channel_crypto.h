/**
 * @file dna_group_channel_crypto.h
 * @brief Encrypted Post Wire Format for Group Channel Messages
 *
 * Wire format for encrypted group message posts sent through nodus channels.
 * Each post is encrypted with GEK (AES-256-GCM) and signed with Dilithium5.
 *
 * Wire Format:
 *   [magic: "GMSG" (4 bytes)]
 *   [format_version: uint8 = 1]
 *   [gek_version: uint32 LE]
 *   [sender_fp: 64 bytes — SHA3-512 fingerprint of sender (binary)]
 *   [timestamp: uint64 LE — Unix timestamp (seconds)]
 *   [nonce: 12 bytes — AES-256-GCM nonce]
 *   [tag: 16 bytes — AES-256-GCM auth tag]
 *   [ciphertext_len: uint32 LE]
 *   [ciphertext: variable — AES-256-GCM(GEK, plaintext)]
 *   [signature: QGP_DSA87_SIGNATURE_BYTES — Dilithium5 over everything above]
 *
 * Part of DNA Connect - Group Channel System (Phase 2)
 *
 * @date 2026-03-15
 */

#ifndef DNA_GROUP_CHANNEL_CRYPTO_H
#define DNA_GROUP_CHANNEL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "../../messenger/gek.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Wire format magic bytes */
#define DNA_GCH_MAGIC           "GMSG"
#define DNA_GCH_MAGIC_SIZE      4

/** Current wire format version */
#define DNA_GCH_FORMAT_VERSION  1

/** AES-256-GCM parameters */
#define DNA_GCH_NONCE_SIZE      12
#define DNA_GCH_TAG_SIZE        16

/** SHA3-512 fingerprint in binary */
#define DNA_GCH_FP_SIZE         64

/** Dilithium5 signature size */
#define DNA_GCH_SIG_SIZE        4627

/** Fixed header size (before ciphertext):
 *  magic(4) + version(1) + gek_version(4) + sender_fp(64) +
 *  timestamp(8) + nonce(12) + tag(16) + ciphertext_len(4) = 113 bytes
 */
#define DNA_GCH_HEADER_SIZE     113

/** Minimum blob size: header + 0 ciphertext + signature */
#define DNA_GCH_MIN_BLOB_SIZE   (DNA_GCH_HEADER_SIZE + DNA_GCH_SIG_SIZE)

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum {
    DNA_GCH_OK              =  0,
    DNA_GCH_ERR_NULL_PARAM  = -1,
    DNA_GCH_ERR_ALLOC       = -2,
    DNA_GCH_ERR_ENCRYPT     = -3,
    DNA_GCH_ERR_DECRYPT     = -4,
    DNA_GCH_ERR_SIGN        = -5,
    DNA_GCH_ERR_VERIFY      = -6,
    DNA_GCH_ERR_BAD_MAGIC   = -7,
    DNA_GCH_ERR_BAD_VERSION = -8,
    DNA_GCH_ERR_BAD_SIZE    = -9,
    DNA_GCH_ERR_BAD_FP      = -10
} dna_gch_error_t;

/*============================================================================
 * Functions
 *============================================================================*/

/**
 * Encrypt and pack a group message for channel posting.
 *
 * Builds the complete wire format blob: header + ciphertext + signature.
 * The entire blob (header + ciphertext) is signed with Dilithium5.
 *
 * @param group_uuid    Group UUID string (used as AAD context, 36 chars)
 * @param plaintext     Message plaintext bytes
 * @param plaintext_len Length of plaintext
 * @param gek           AES-256 group encryption key (GEK_KEY_SIZE bytes)
 * @param gek_version   GEK version number
 * @param sender_fp     Sender fingerprint as 128-char hex string
 * @param sign_sk       Dilithium5 secret key (QGP_DSA87_SECRETKEYBYTES)
 * @param blob_out      Output: heap-allocated blob (caller must free)
 * @param blob_len_out  Output: blob length
 * @return DNA_GCH_OK on success, error code on failure
 */
int dna_group_channel_encrypt(const char *group_uuid,
                               const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t gek[GEK_KEY_SIZE],
                               uint32_t gek_version,
                               const char *sender_fp,
                               const uint8_t *sign_sk,
                               uint8_t **blob_out, size_t *blob_len_out);

/**
 * Decrypt and verify a received group channel message.
 *
 * Verifies Dilithium5 signature, then decrypts the ciphertext with GEK.
 *
 * @param blob           Received wire format blob
 * @param blob_len       Blob length
 * @param gek            AES-256 group encryption key (GEK_KEY_SIZE bytes)
 * @param sender_pk      Dilithium5 public key for signature verification
 *                       (QGP_DSA87_PUBLICKEYBYTES). May be NULL to skip verify.
 * @param sender_fp_out  Output: sender fingerprint as hex string (129 bytes)
 * @param timestamp_out  Output: message timestamp (Unix seconds)
 * @param plaintext_out  Output: heap-allocated decrypted plaintext (caller frees)
 * @param plaintext_len_out Output: plaintext length
 * @return DNA_GCH_OK on success, error code on failure
 */
int dna_group_channel_decrypt(const uint8_t *blob, size_t blob_len,
                               const uint8_t gek[GEK_KEY_SIZE],
                               const uint8_t *sender_pk,
                               char *sender_fp_out,
                               uint64_t *timestamp_out,
                               uint8_t **plaintext_out,
                               size_t *plaintext_len_out);

/**
 * Extract metadata from a blob without decrypting.
 *
 * Useful for determining which GEK version is needed before decryption.
 *
 * @param blob          Wire format blob
 * @param blob_len      Blob length
 * @param gek_version_out  Output: GEK version used
 * @param sender_fp_out    Output: sender fingerprint hex (129 bytes, optional)
 * @param timestamp_out    Output: timestamp (optional)
 * @return DNA_GCH_OK on success, error code on failure
 */
int dna_group_channel_peek(const uint8_t *blob, size_t blob_len,
                            uint32_t *gek_version_out,
                            char *sender_fp_out,
                            uint64_t *timestamp_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_GROUP_CHANNEL_CRYPTO_H */
