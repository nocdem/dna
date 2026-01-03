/**
 * @file gsk_encryption.h
 * @brief GSK Encryption using Kyber1024 KEM + AES-256-GCM
 *
 * Encrypts Group Symmetric Keys (GSK) for secure storage in SQLite database.
 * Uses the same encryption scheme as seed_storage.h for consistency.
 *
 * Encryption Scheme:
 *   Encrypt: KEM_Encapsulate(pubkey) -> shared_secret + ciphertext
 *            AES-256-GCM(shared_secret, gsk) -> encrypted_gsk
 *            Store: kem_ciphertext || nonce || tag || encrypted_gsk
 *
 *   Decrypt: KEM_Decapsulate(privkey, ciphertext) -> shared_secret
 *            AES-256-GCM-Decrypt(shared_secret, encrypted_gsk) -> gsk
 *
 * Storage Format (1628 bytes total):
 *   - KEM ciphertext: 1568 bytes (Kyber1024)
 *   - AES nonce:      12 bytes
 *   - AES tag:        16 bytes
 *   - Encrypted GSK:  32 bytes (AES-256 key)
 *
 * Security:
 *   - Post-quantum secure (Kyber1024 = NIST Category 5)
 *   - Fresh KEM encapsulation per GSK (forward secrecy)
 *   - Database compromise doesn't expose GSKs without KEM private key
 *
 * @author DNA Messenger Team
 * @date 2026-01-03
 */

#ifndef GSK_ENCRYPTION_H
#define GSK_ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define GSK_ENC_KEM_CT_SIZE     1568    /* Kyber1024 ciphertext */
#define GSK_ENC_NONCE_SIZE      12      /* AES-256-GCM nonce */
#define GSK_ENC_TAG_SIZE        16      /* AES-256-GCM tag */
#define GSK_ENC_KEY_SIZE        32      /* GSK size (AES-256 key) */
#define GSK_ENC_TOTAL_SIZE      (GSK_ENC_KEM_CT_SIZE + \
                                 GSK_ENC_NONCE_SIZE + \
                                 GSK_ENC_TAG_SIZE + \
                                 GSK_ENC_KEY_SIZE)  /* 1628 bytes */

/* ============================================================================
 * FUNCTIONS
 * ============================================================================ */

/**
 * Encrypt GSK with Kyber1024 KEM + AES-256-GCM
 *
 * @param gsk           32-byte GSK to encrypt
 * @param kem_pubkey    1568-byte Kyber1024 public key
 * @param encrypted_out Output buffer (must be GSK_ENC_TOTAL_SIZE = 1628 bytes)
 * @return              0 on success, -1 on error
 */
int gsk_encrypt(
    const uint8_t gsk[32],
    const uint8_t kem_pubkey[1568],
    uint8_t encrypted_out[GSK_ENC_TOTAL_SIZE]
);

/**
 * Decrypt GSK with Kyber1024 KEM + AES-256-GCM
 *
 * @param encrypted     1628-byte encrypted blob from database
 * @param encrypted_len Size of encrypted blob (must be GSK_ENC_TOTAL_SIZE)
 * @param kem_privkey   3168-byte Kyber1024 private key
 * @param gsk_out       Output buffer for decrypted GSK (32 bytes)
 * @return              0 on success, -1 on error
 */
int gsk_decrypt(
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t kem_privkey[3168],
    uint8_t gsk_out[32]
);

#ifdef __cplusplus
}
#endif

#endif /* GSK_ENCRYPTION_H */
