/**
 * @file seed_storage.h
 * @brief Encrypted Master Seed Storage using Kyber1024 KEM
 *
 * Stores the 64-byte BIP39 master seed encrypted with Kyber1024 KEM + AES-256-GCM.
 * This allows automatic wallet creation for new blockchain networks without
 * requiring the user to re-enter their seed phrase.
 *
 * Encryption Scheme:
 *   Save: KEM_Encapsulate(pubkey) -> shared_secret + ciphertext
 *         AES-256-GCM(shared_secret, master_seed) -> encrypted_seed
 *         Store: kem_ciphertext || nonce || tag || encrypted_seed
 *
 *   Load: KEM_Decapsulate(privkey, ciphertext) -> shared_secret
 *         AES-256-GCM-Decrypt(shared_secret, encrypted_seed) -> master_seed
 *
 * File Format (1660 bytes total):
 *   - KEM ciphertext: 1568 bytes (Kyber1024)
 *   - AES nonce:      12 bytes
 *   - AES tag:        16 bytes
 *   - Encrypted seed: 64 bytes
 *
 * Security:
 *   - Post-quantum secure (Kyber1024 = NIST Category 5)
 *   - Fresh KEM encapsulation on each save (forward secrecy per-save)
 *   - File permissions 0600 (owner-only)
 *   - Memory wiped after use
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#ifndef SEED_STORAGE_H
#define SEED_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define SEED_STORAGE_FILE           "master_seed.enc"
#define SEED_STORAGE_KEM_CT_SIZE    1568    /* Kyber1024 ciphertext */
#define SEED_STORAGE_NONCE_SIZE     12      /* AES-256-GCM nonce */
#define SEED_STORAGE_TAG_SIZE       16      /* AES-256-GCM tag */
#define SEED_STORAGE_SEED_SIZE      64      /* BIP39 master seed */
#define SEED_STORAGE_TOTAL_SIZE     (SEED_STORAGE_KEM_CT_SIZE + \
                                     SEED_STORAGE_NONCE_SIZE + \
                                     SEED_STORAGE_TAG_SIZE + \
                                     SEED_STORAGE_SEED_SIZE)  /* 1660 bytes */

/* ============================================================================
 * FUNCTIONS
 * ============================================================================ */

/**
 * Save master seed encrypted with Kyber1024 KEM
 *
 * Encrypts the 64-byte master seed using:
 * 1. Kyber1024 encapsulation to generate shared secret
 * 2. AES-256-GCM encryption with the shared secret
 *
 * File is saved to: <identity_dir>/master_seed.enc
 * File permissions are set to 0600 (owner read/write only).
 *
 * @param master_seed   64-byte BIP39 master seed to encrypt
 * @param kem_pubkey    1568-byte Kyber1024 public key
 * @param identity_dir  Directory path (e.g., ~/.dna/<fingerprint>)
 * @return              0 on success, -1 on error
 */
int seed_storage_save(
    const uint8_t master_seed[64],
    const uint8_t kem_pubkey[1568],
    const char *identity_dir
);

/**
 * Load master seed decrypted with Kyber1024 KEM
 *
 * Decrypts the master seed using:
 * 1. Kyber1024 decapsulation to recover shared secret
 * 2. AES-256-GCM decryption with the shared secret
 *
 * IMPORTANT: Caller must securely wipe master_seed_out after use!
 *
 * @param master_seed_out   Output: 64-byte decrypted master seed
 * @param kem_privkey       3168-byte Kyber1024 private key
 * @param identity_dir      Directory path (e.g., ~/.dna/<fingerprint>)
 * @return                  0 on success, -1 on error (file not found, decryption failed, etc.)
 */
int seed_storage_load(
    uint8_t master_seed_out[64],
    const uint8_t kem_privkey[3168],
    const char *identity_dir
);

/**
 * Check if encrypted seed file exists
 *
 * @param identity_dir  Directory path (e.g., ~/.dna/<fingerprint>)
 * @return              true if master_seed.enc exists, false otherwise
 */
bool seed_storage_exists(const char *identity_dir);

/**
 * Delete encrypted seed file
 *
 * Securely removes the encrypted seed file.
 *
 * @param identity_dir  Directory path (e.g., ~/.dna/<fingerprint>)
 * @return              0 on success, -1 on error
 */
int seed_storage_delete(const char *identity_dir);

/* ============================================================================
 * MNEMONIC STORAGE
 * ============================================================================
 * Stores the human-readable BIP39 mnemonic phrase (24 words) so users can
 * view their recovery phrase in settings.
 *
 * File Format (1852 bytes total):
 *   - KEM ciphertext: 1568 bytes (Kyber1024)
 *   - AES nonce:      12 bytes
 *   - AES tag:        16 bytes
 *   - Encrypted data: 256 bytes (mnemonic + null padding)
 * ============================================================================ */

#define MNEMONIC_STORAGE_FILE           "mnemonic.enc"
#define MNEMONIC_STORAGE_DATA_SIZE      256     /* BIP39_MAX_MNEMONIC_LENGTH */
#define MNEMONIC_STORAGE_TOTAL_SIZE     (SEED_STORAGE_KEM_CT_SIZE + \
                                         SEED_STORAGE_NONCE_SIZE + \
                                         SEED_STORAGE_TAG_SIZE + \
                                         MNEMONIC_STORAGE_DATA_SIZE)  /* 1852 bytes */

/**
 * Save mnemonic encrypted with Kyber1024 KEM
 *
 * @param mnemonic      Null-terminated mnemonic string (max 255 chars)
 * @param kem_pubkey    1568-byte Kyber1024 public key
 * @param identity_dir  Directory path (e.g., ~/.dna/<fingerprint>)
 * @return              0 on success, -1 on error
 */
int mnemonic_storage_save(
    const char *mnemonic,
    const uint8_t kem_pubkey[1568],
    const char *identity_dir
);

/**
 * Load mnemonic decrypted with Kyber1024 KEM
 *
 * @param mnemonic_out      Output buffer (at least 256 bytes)
 * @param mnemonic_size     Size of output buffer
 * @param kem_privkey       3168-byte Kyber1024 private key
 * @param identity_dir      Directory path (e.g., ~/.dna/<fingerprint>)
 * @return                  0 on success, -1 on error
 */
int mnemonic_storage_load(
    char *mnemonic_out,
    size_t mnemonic_size,
    const uint8_t kem_privkey[3168],
    const char *identity_dir
);

/**
 * Check if encrypted mnemonic file exists
 *
 * @param identity_dir  Directory path (e.g., ~/.dna/<fingerprint>)
 * @return              true if mnemonic.enc exists, false otherwise
 */
bool mnemonic_storage_exists(const char *identity_dir);

#ifdef __cplusplus
}
#endif

#endif /* SEED_STORAGE_H */
