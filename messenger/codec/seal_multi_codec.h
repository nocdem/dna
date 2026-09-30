/*
 * DNA Connect - Multi-recipient Seal encoder (codec unit)
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * moved verbatim out of messenger/messages.c so that the native library and
 * the web thin core compile the same encoder. This unit does no network I/O
 * and touches no database; it depends only on shared/crypto.
 */

#ifndef DNA_CODEC_SEAL_MULTI_CODEC_H
#define DNA_CODEC_SEAL_MULTI_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include "crypto/utils/qgp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Multi-recipient encryption (adapted from encrypt.c)
 *
 * Seal v0.08: header "PQSIGENC", version 0x08, enc_key_type = alg,
 * payload = sender fingerprint(64) || timestamp(8, BE) || plaintext.
 *
 * @param plaintext: Message to encrypt
 * @param plaintext_len: Message length
 * @param recipient_enc_pubkeys: Array of recipient public keys (1568 bytes
 *        each) OF THE GIVEN alg — round-3 Kyber1024 pubkeys for alg 2, or
 *        ML-KEM-1024 pubkeys for alg 3 (KEM Faz 1, R7)
 * @param recipient_count: Number of recipients (including sender)
 * @param sender_sign_key: Sender's Dilithium5 signing key (ML-DSA-87)
 * @param alg: QGP_KEY_TYPE_KEM1024 (2) or QGP_KEY_TYPE_MLKEM1024 (3)
 * @param ciphertext_out: Output ciphertext (caller must free)
 * @param ciphertext_len_out: Output ciphertext length
 * @return: 0 on success, -1 on error
 */
int messenger_encrypt_multi_recipient(
    const char *plaintext,
    size_t plaintext_len,
    uint8_t **recipient_enc_pubkeys,
    size_t recipient_count,
    qgp_key_t *sender_sign_key,
    uint64_t timestamp,
    uint8_t alg,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
);

#ifdef __cplusplus
}
#endif

#endif /* DNA_CODEC_SEAL_MULTI_CODEC_H */
