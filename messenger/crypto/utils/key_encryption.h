/**
 * @file key_encryption.h
 * @brief Password-based Key Encryption using PBKDF2 + AES-256-GCM
 *
 * Encrypts private key files (.kem, .dsa) with user password.
 * Uses PBKDF2-SHA256 for key derivation and AES-256-GCM for encryption.
 *
 * File Format (encrypted key):
 *   - Magic:      4 bytes  "DNAK"
 *   - Version:    1 byte   (0x01)
 *   - Salt:       32 bytes (random, for PBKDF2)
 *   - Nonce:      12 bytes (random, for AES-GCM)
 *   - Tag:        16 bytes (AES-GCM auth tag)
 *   - Ciphertext: N bytes  (encrypted key data)
 *
 * Total overhead: 65 bytes + original key size
 *
 * Security:
 *   - PBKDF2 iterations: 210,000 (OWASP 2023 recommendation for SHA256)
 *   - Random salt per file (prevents rainbow tables)
 *   - AES-256-GCM provides authenticated encryption
 *   - Memory wiped after use
 *
 * @author DNA Messenger Team
 * @date 2025-12-15
 */

#ifndef KEY_ENCRYPTION_H
#define KEY_ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define KEY_ENC_MAGIC           "DNAK"
#define KEY_ENC_MAGIC_SIZE      4
#define KEY_ENC_VERSION         0x01
#define KEY_ENC_SALT_SIZE       32
#define KEY_ENC_NONCE_SIZE      12
#define KEY_ENC_TAG_SIZE        16
#define KEY_ENC_HEADER_SIZE     (KEY_ENC_MAGIC_SIZE + 1 + KEY_ENC_SALT_SIZE + \
                                 KEY_ENC_NONCE_SIZE + KEY_ENC_TAG_SIZE)  /* 65 bytes */

#define KEY_ENC_PBKDF2_ITERATIONS   210000  /* OWASP 2023 recommendation */

/* File extensions */
#define KEY_ENC_DSA_EXTENSION   ".dsa.enc"
#define KEY_ENC_KEM_EXTENSION   ".kem.enc"

/* ============================================================================
 * FUNCTIONS
 * ============================================================================ */

/**
 * Encrypt key data with password
 *
 * Derives AES-256 key using PBKDF2(password, salt) and encrypts with AES-GCM.
 *
 * @param key_data          Raw key data to encrypt
 * @param key_data_size     Size of key data
 * @param password          User password (null-terminated)
 * @param encrypted_out     Output buffer (must be key_data_size + KEY_ENC_HEADER_SIZE)
 * @param encrypted_size    Output: actual encrypted size
 * @return                  0 on success, -1 on error
 */
int key_encrypt(
    const uint8_t *key_data,
    size_t key_data_size,
    const char *password,
    uint8_t *encrypted_out,
    size_t *encrypted_size
);

/**
 * Decrypt key data with password
 *
 * Derives AES-256 key using PBKDF2(password, salt) and decrypts with AES-GCM.
 *
 * @param encrypted_data    Encrypted key data (with header)
 * @param encrypted_size    Size of encrypted data
 * @param password          User password (null-terminated)
 * @param key_out           Output buffer for decrypted key
 * @param key_size          Output: actual key size
 * @return                  0 on success, -1 on error (wrong password or corruption)
 */
int key_decrypt(
    const uint8_t *encrypted_data,
    size_t encrypted_size,
    const char *password,
    uint8_t *key_out,
    size_t *key_size
);

/**
 * Save encrypted key to file
 *
 * @param key_data          Raw key data to encrypt and save
 * @param key_data_size     Size of key data
 * @param password          User password (null-terminated), NULL for unencrypted
 * @param file_path         Output file path
 * @return                  0 on success, -1 on error
 */
int key_save_encrypted(
    const uint8_t *key_data,
    size_t key_data_size,
    const char *password,
    const char *file_path
);

/**
 * Load and decrypt key from file
 *
 * @param file_path         Input file path
 * @param password          User password (null-terminated), NULL if unencrypted
 * @param key_out           Output buffer for decrypted key
 * @param key_out_size      Size of output buffer
 * @param key_size          Output: actual key size
 * @return                  0 on success, -1 on error
 */
int key_load_encrypted(
    const char *file_path,
    const char *password,
    uint8_t *key_out,
    size_t key_out_size,
    size_t *key_size
);

/**
 * Check if a key file is password-protected
 *
 * @param file_path         Key file path
 * @return                  true if encrypted with password, false otherwise
 */
bool key_file_is_encrypted(const char *file_path);

/**
 * Change password on an encrypted key file
 *
 * @param file_path         Key file path
 * @param old_password      Current password (NULL if unencrypted)
 * @param new_password      New password (NULL to remove encryption - not recommended)
 * @return                  0 on success, -1 on error
 */
int key_change_password(
    const char *file_path,
    const char *old_password,
    const char *new_password
);

/**
 * Verify password against an encrypted key file
 *
 * Attempts to decrypt the file to verify password is correct.
 *
 * @param file_path         Key file path
 * @param password          Password to verify
 * @return                  0 if password is correct, -1 if wrong or error
 */
int key_verify_password(
    const char *file_path,
    const char *password
);

#ifdef __cplusplus
}
#endif

#endif /* KEY_ENCRYPTION_H */
