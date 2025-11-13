/**
 * @file bip39.h
 * @brief BIP39 Mnemonic Code implementation for QGP
 *
 * Implements BIP-39 standard for generating deterministic mnemonic phrases
 * from entropy and deriving seeds for hierarchical deterministic keys.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * @author QGP Development Team
 * @date 2025-10-12
 */

#ifndef QGP_BIP39_H
#define QGP_BIP39_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * BIP39 mnemonic word count options
 */
#define BIP39_WORDS_12  12  // 128 bits entropy
#define BIP39_WORDS_15  15  // 160 bits entropy
#define BIP39_WORDS_18  18  // 192 bits entropy
#define BIP39_WORDS_21  21  // 224 bits entropy
#define BIP39_WORDS_24  24  // 256 bits entropy (recommended)

/**
 * BIP39 English wordlist size
 */
#define BIP39_WORDLIST_SIZE 2048

/**
 * Maximum mnemonic length in characters (24 words * 8 chars + spaces)
 */
#define BIP39_MAX_MNEMONIC_LENGTH 256

/**
 * BIP39 seed size (output of PBKDF2)
 */
#define BIP39_SEED_SIZE 64  // 512 bits

/**
 * BIP39 PBKDF2 iterations (BIP39 standard)
 */
#define BIP39_PBKDF2_ROUNDS 2048

/**
 * Generate BIP39 mnemonic from entropy
 *
 * @param entropy Input entropy bytes
 * @param entropy_len Length of entropy (16, 20, 24, 28, or 32 bytes)
 * @param mnemonic Output buffer for mnemonic phrase (space-separated words)
 * @param mnemonic_size Size of output buffer (at least BIP39_MAX_MNEMONIC_LENGTH)
 * @return 0 on success, -1 on error
 *
 * Generates a BIP39 mnemonic phrase from the provided entropy.
 * The entropy length determines the number of mnemonic words:
 * - 16 bytes (128 bits) → 12 words
 * - 20 bytes (160 bits) → 15 words
 * - 24 bytes (192 bits) → 18 words
 * - 28 bytes (224 bits) → 21 words
 * - 32 bytes (256 bits) → 24 words (recommended)
 */
int bip39_mnemonic_from_entropy(
    const uint8_t *entropy,
    size_t entropy_len,
    char *mnemonic,
    size_t mnemonic_size
);

/**
 * Generate random BIP39 mnemonic
 *
 * @param word_count Number of words (12, 15, 18, 21, or 24)
 * @param mnemonic Output buffer for mnemonic phrase
 * @param mnemonic_size Size of output buffer
 * @return 0 on success, -1 on error
 *
 * Generates a random BIP39 mnemonic with the specified word count.
 * Uses cryptographically secure random number generator.
 */
int bip39_generate_mnemonic(
    int word_count,
    char *mnemonic,
    size_t mnemonic_size
);

/**
 * Validate BIP39 mnemonic
 *
 * @param mnemonic Space-separated mnemonic phrase
 * @return true if valid, false otherwise
 *
 * Validates a BIP39 mnemonic by:
 * 1. Checking word count (12, 15, 18, 21, or 24)
 * 2. Verifying all words exist in BIP39 wordlist
 * 3. Verifying checksum bits
 */
bool bip39_validate_mnemonic(const char *mnemonic);

/**
 * Derive BIP39 seed from mnemonic
 *
 * @param mnemonic Space-separated mnemonic phrase
 * @param passphrase Optional passphrase (can be NULL or "")
 * @param seed Output buffer for 64-byte seed
 * @return 0 on success, -1 on error
 *
 * Derives a 512-bit seed from the mnemonic using PBKDF2-HMAC-SHA512
 * with salt = "mnemonic" + passphrase and 2048 iterations (BIP39 standard).
 */
int bip39_mnemonic_to_seed(
    const char *mnemonic,
    const char *passphrase,
    uint8_t seed[BIP39_SEED_SIZE]
);

/**
 * Get BIP39 wordlist
 *
 * @return Pointer to BIP39 English wordlist (2048 words)
 *
 * Returns a pointer to the embedded BIP39 English wordlist.
 * The wordlist is sorted alphabetically.
 */
const char **bip39_get_wordlist(void);

/**
 * Get word index in BIP39 wordlist
 *
 * @param word Word to search for
 * @return Index (0-2047) if found, -1 if not found
 */
int bip39_word_index(const char *word);

/**
 * PBKDF2-HMAC-SHA512 implementation for BIP39
 *
 * @param password Password (mnemonic)
 * @param password_len Password length
 * @param salt Salt ("mnemonic" + passphrase)
 * @param salt_len Salt length
 * @param iterations Number of iterations (2048 for BIP39)
 * @param output Output buffer
 * @param output_len Output length (64 for BIP39)
 * @return 0 on success, -1 on error
 */
int bip39_pbkdf2_hmac_sha512(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *output, size_t output_len
);

/**
 * Derive QGP signing and encryption seeds from BIP39 mnemonic
 *
 * @param mnemonic BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
 * @param passphrase Optional passphrase (empty string if none)
 * @param signing_seed Output buffer for signing seed (32 bytes)
 * @param encryption_seed Output buffer for encryption seed (32 bytes)
 * @return 0 on success, -1 on error
 *
 * Uses BIP39 to generate a 64-byte master seed, then derives:
 * - signing_seed = SHAKE256(master_seed || "qgp-signing-v1", 32)
 * - encryption_seed = SHAKE256(master_seed || "qgp-encryption-v1", 32)
 */
int qgp_derive_seeds_from_mnemonic(
    const char *mnemonic,
    const char *passphrase,
    uint8_t signing_seed[32],
    uint8_t encryption_seed[32]
);

/**
 * Display BIP39 mnemonic in a user-friendly format
 *
 * @param mnemonic BIP39 mnemonic phrase
 *
 * Prints mnemonic with word numbers for easy verification and backup.
 */
void qgp_display_mnemonic(const char *mnemonic);

/**
 * Test HMAC-SHA512 (for debugging)
 */
void test_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t output[64]);

#endif /* QGP_BIP39_H */
