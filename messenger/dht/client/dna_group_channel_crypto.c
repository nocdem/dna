/**
 * @file dna_group_channel_crypto.c
 * @brief Encrypted Post Wire Format for Group Channel Messages
 *
 * Implements encrypt/pack and decrypt/verify for group channel messages.
 * Uses AES-256-GCM for encryption and Dilithium5 for signatures.
 *
 * Part of DNA Connect - Group Channel System (Phase 2)
 *
 * @date 2026-03-15
 */

#include "dna_group_channel_crypto.h"
#include "crypto/enc/qgp_aes.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define LOG_TAG "GCH_CRYPTO"

/*============================================================================
 * Internal helpers
 *============================================================================*/

/** Write uint32 little-endian */
static inline void write_u32_le(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

/** Read uint32 little-endian */
static inline uint32_t read_u32_le(const uint8_t *buf) {
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/** Write uint64 little-endian */
static inline void write_u64_le(uint8_t *buf, uint64_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
    buf[4] = (uint8_t)(val >> 32);
    buf[5] = (uint8_t)(val >> 40);
    buf[6] = (uint8_t)(val >> 48);
    buf[7] = (uint8_t)(val >> 56);
}

/** Read uint64 little-endian */
static inline uint64_t read_u64_le(const uint8_t *buf) {
    return (uint64_t)buf[0]
         | ((uint64_t)buf[1] << 8)
         | ((uint64_t)buf[2] << 16)
         | ((uint64_t)buf[3] << 24)
         | ((uint64_t)buf[4] << 32)
         | ((uint64_t)buf[5] << 40)
         | ((uint64_t)buf[6] << 48)
         | ((uint64_t)buf[7] << 56);
}

/**
 * Convert 128-char hex fingerprint string to 64-byte binary.
 * @return 0 on success, -1 on error
 */
static int fp_hex_to_bin(const char *hex, uint8_t bin[64]) {
    if (!hex || strlen(hex) < 128) return -1;
    for (int i = 0; i < 64; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/**
 * Convert 64-byte binary fingerprint to 128-char hex string.
 */
static void fp_bin_to_hex(const uint8_t bin[64], char hex[129]) {
    for (int i = 0; i < 64; i++)
        snprintf(hex + i * 2, 3, "%02x", bin[i]);
    hex[128] = '\0';
}

/*============================================================================
 * Encrypt and pack
 *============================================================================*/

int dna_group_channel_encrypt(const char *group_uuid,
                               const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t gek[GEK_KEY_SIZE],
                               uint32_t gek_version,
                               const char *sender_fp,
                               const uint8_t *sign_sk,
                               uint8_t **blob_out, size_t *blob_len_out) {
    if (!group_uuid || !plaintext || !gek || !sender_fp || !sign_sk ||
        !blob_out || !blob_len_out) {
        return DNA_GCH_ERR_NULL_PARAM;
    }

    /* Convert sender fingerprint hex -> binary */
    uint8_t sender_fp_bin[DNA_GCH_FP_SIZE];
    if (fp_hex_to_bin(sender_fp, sender_fp_bin) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid sender fingerprint hex");
        return DNA_GCH_ERR_BAD_FP;
    }

    /* Encrypt plaintext with AES-256-GCM */
    size_t ciphertext_size = qgp_aes256_encrypt_size(plaintext_len);
    uint8_t *ciphertext = malloc(ciphertext_size > 0 ? ciphertext_size : 1);
    if (!ciphertext) return DNA_GCH_ERR_ALLOC;

    uint8_t nonce[DNA_GCH_NONCE_SIZE];
    uint8_t tag[DNA_GCH_TAG_SIZE];
    size_t ciphertext_len = 0;

    /* No AAD — GEK is group-specific so ciphertext is inherently bound.
     * The Dilithium5 signature over the entire blob prevents tampering.
     * Cross-group replay is impossible since different groups have different GEKs. */
    if (qgp_aes256_encrypt(gek, plaintext, plaintext_len,
                           NULL, 0,
                           ciphertext, &ciphertext_len,
                           nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        free(ciphertext);
        return DNA_GCH_ERR_ENCRYPT;
    }

    /* Calculate blob size: header + ciphertext + signature */
    size_t data_size = DNA_GCH_HEADER_SIZE + ciphertext_len;
    size_t blob_size = data_size + DNA_GCH_SIG_SIZE;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        free(ciphertext);
        return DNA_GCH_ERR_ALLOC;
    }

    /* Build header */
    size_t off = 0;

    /* Magic: "GMSG" */
    memcpy(blob + off, DNA_GCH_MAGIC, DNA_GCH_MAGIC_SIZE);
    off += DNA_GCH_MAGIC_SIZE;

    /* Format version */
    blob[off++] = DNA_GCH_FORMAT_VERSION;

    /* GEK version (uint32 LE) */
    write_u32_le(blob + off, gek_version);
    off += 4;

    /* Sender fingerprint (64 bytes binary) */
    memcpy(blob + off, sender_fp_bin, DNA_GCH_FP_SIZE);
    off += DNA_GCH_FP_SIZE;

    /* Timestamp (uint64 LE, Unix seconds) */
    uint64_t timestamp = (uint64_t)time(NULL);
    write_u64_le(blob + off, timestamp);
    off += 8;

    /* Nonce (12 bytes) */
    memcpy(blob + off, nonce, DNA_GCH_NONCE_SIZE);
    off += DNA_GCH_NONCE_SIZE;

    /* Tag (16 bytes) */
    memcpy(blob + off, tag, DNA_GCH_TAG_SIZE);
    off += DNA_GCH_TAG_SIZE;

    /* Ciphertext length (uint32 LE) */
    write_u32_le(blob + off, (uint32_t)ciphertext_len);
    off += 4;

    /* Ciphertext */
    memcpy(blob + off, ciphertext, ciphertext_len);
    off += ciphertext_len;
    free(ciphertext);

    /* Sign everything above (header + ciphertext) with Dilithium5 */
    uint8_t sig[DNA_GCH_SIG_SIZE];
    size_t sig_len = 0;
    if (qgp_dsa87_sign(sig, &sig_len, blob, data_size, sign_sk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Dilithium5 signing failed");
        free(blob);
        return DNA_GCH_ERR_SIGN;
    }

    /* Append signature */
    memcpy(blob + off, sig, DNA_GCH_SIG_SIZE);

    *blob_out = blob;
    *blob_len_out = blob_size;
    return DNA_GCH_OK;
}

/*============================================================================
 * Decrypt and verify
 *============================================================================*/

int dna_group_channel_decrypt(const uint8_t *blob, size_t blob_len,
                               const uint8_t gek[GEK_KEY_SIZE],
                               const uint8_t *sender_pk,
                               char *sender_fp_out,
                               uint64_t *timestamp_out,
                               uint8_t **plaintext_out,
                               size_t *plaintext_len_out) {
    if (!blob || !gek || !plaintext_out || !plaintext_len_out) {
        return DNA_GCH_ERR_NULL_PARAM;
    }

    /* Minimum size check */
    if (blob_len < DNA_GCH_MIN_BLOB_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Blob too small: %zu < %d", blob_len, DNA_GCH_MIN_BLOB_SIZE);
        return DNA_GCH_ERR_BAD_SIZE;
    }

    /* Parse header */
    size_t off = 0;

    /* Verify magic */
    if (memcmp(blob + off, DNA_GCH_MAGIC, DNA_GCH_MAGIC_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Bad magic bytes");
        return DNA_GCH_ERR_BAD_MAGIC;
    }
    off += DNA_GCH_MAGIC_SIZE;

    /* Check format version */
    uint8_t version = blob[off++];
    if (version != DNA_GCH_FORMAT_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported format version: %u", version);
        return DNA_GCH_ERR_BAD_VERSION;
    }

    /* GEK version (skip — caller already has the right GEK) */
    /* uint32_t gek_ver = read_u32_le(blob + off); */
    off += 4;

    /* Sender fingerprint (64 bytes binary) */
    const uint8_t *sender_fp_bin = blob + off;
    off += DNA_GCH_FP_SIZE;

    if (sender_fp_out) {
        fp_bin_to_hex(sender_fp_bin, sender_fp_out);
    }

    /* Timestamp */
    uint64_t timestamp = read_u64_le(blob + off);
    off += 8;
    if (timestamp_out) *timestamp_out = timestamp;

    /* Nonce */
    const uint8_t *nonce = blob + off;
    off += DNA_GCH_NONCE_SIZE;

    /* Tag */
    const uint8_t *tag = blob + off;
    off += DNA_GCH_TAG_SIZE;

    /* Ciphertext length */
    uint32_t ct_len = read_u32_le(blob + off);
    off += 4;

    /* Validate total size */
    size_t expected_size = DNA_GCH_HEADER_SIZE + ct_len + DNA_GCH_SIG_SIZE;
    if (blob_len < expected_size) {
        QGP_LOG_ERROR(LOG_TAG, "Blob size mismatch: %zu < %zu", blob_len, expected_size);
        return DNA_GCH_ERR_BAD_SIZE;
    }

    /* Ciphertext */
    const uint8_t *ciphertext = blob + off;
    off += ct_len;

    /* Signature */
    const uint8_t *sig = blob + off;
    size_t data_size = DNA_GCH_HEADER_SIZE + ct_len;

    /* Verify signature if public key provided */
    if (sender_pk) {
        if (qgp_dsa87_verify(sig, DNA_GCH_SIG_SIZE,
                             blob, data_size, sender_pk) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Dilithium5 signature verification failed");
            return DNA_GCH_ERR_VERIFY;
        }
    }

    /* Decrypt ciphertext with GEK (no AAD — matches encrypt) */
    uint8_t *pt = malloc(ct_len > 0 ? ct_len : 1);
    if (!pt) return DNA_GCH_ERR_ALLOC;

    size_t pt_len = 0;
    if (qgp_aes256_decrypt(gek, ciphertext, ct_len,
                           NULL, 0,  /* No AAD in decrypt — see note above */
                           nonce, tag,
                           pt, &pt_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM decryption failed (wrong GEK or tampered)");
        free(pt);
        return DNA_GCH_ERR_DECRYPT;
    }

    *plaintext_out = pt;
    *plaintext_len_out = pt_len;
    return DNA_GCH_OK;
}

/*============================================================================
 * Peek (metadata extraction without decryption)
 *============================================================================*/

int dna_group_channel_peek(const uint8_t *blob, size_t blob_len,
                            uint32_t *gek_version_out,
                            char *sender_fp_out,
                            uint64_t *timestamp_out) {
    if (!blob) return DNA_GCH_ERR_NULL_PARAM;

    if (blob_len < DNA_GCH_MIN_BLOB_SIZE) {
        return DNA_GCH_ERR_BAD_SIZE;
    }

    /* Verify magic */
    if (memcmp(blob, DNA_GCH_MAGIC, DNA_GCH_MAGIC_SIZE) != 0) {
        return DNA_GCH_ERR_BAD_MAGIC;
    }

    /* Check version */
    if (blob[4] != DNA_GCH_FORMAT_VERSION) {
        return DNA_GCH_ERR_BAD_VERSION;
    }

    size_t off = DNA_GCH_MAGIC_SIZE + 1; /* past magic + version */

    /* GEK version */
    if (gek_version_out) {
        *gek_version_out = read_u32_le(blob + off);
    }
    off += 4;

    /* Sender fingerprint */
    if (sender_fp_out) {
        fp_bin_to_hex(blob + off, sender_fp_out);
    }
    off += DNA_GCH_FP_SIZE;

    /* Timestamp */
    if (timestamp_out) {
        *timestamp_out = read_u64_le(blob + off);
    }

    return DNA_GCH_OK;
}
