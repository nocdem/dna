/**
 * @file bip39.c
 * @brief BIP39 Mnemonic Code implementation for QGP
 *
 * Implements BIP-39 standard for generating deterministic mnemonic phrases.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * @author QGP Development Team
 * @date 2025-10-12
 */

#include "bip39.h"
#include "bip39_wordlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


#include <openssl/sha.h>

/**
 * Get random bytes for entropy generation
 * Uses /dev/urandom for cryptographically secure random bytes
 */
static int get_random_bytes(uint8_t *output, size_t len) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return -1;
    }

    size_t read = fread(output, 1, len, urandom);
    fclose(urandom);

    if (read != len) {
        return -1;
    }

    return 0;
}

/**
 * Convert entropy to mnemonic following BIP39 algorithm
 */
int bip39_mnemonic_from_entropy(
    const uint8_t *entropy,
    size_t entropy_len,
    char *mnemonic,
    size_t mnemonic_size
) {
    if (!entropy || !mnemonic) {
        return -1;
    }

    // Validate entropy length (16, 20, 24, 28, or 32 bytes)
    if (entropy_len != 16 && entropy_len != 20 && entropy_len != 24 &&
        entropy_len != 28 && entropy_len != 32) {
        return -1;
    }

    // Calculate checksum bits needed
    size_t checksum_bits = entropy_len / 4;  // entropy_bits / 32

    // Calculate SHA256 checksum of entropy
    uint8_t hash[32];
    SHA256(entropy, entropy_len, hash);

    // Combine entropy + checksum into bit array
    size_t total_bits = (entropy_len * 8) + checksum_bits;
    size_t word_count = total_bits / 11;

    // Build mnemonic string
    mnemonic[0] = '\0';
    size_t mnemonic_len = 0;

    for (size_t i = 0; i < word_count; i++) {
        // Extract 11 bits for this word
        size_t bit_index = i * 11;
        uint16_t word_index = 0;

        for (int bit = 0; bit < 11; bit++) {
            size_t byte_index = (bit_index + bit) / 8;
            size_t bit_in_byte = 7 - ((bit_index + bit) % 8);

            uint8_t byte_val;
            if (byte_index < entropy_len) {
                byte_val = entropy[byte_index];
            } else {
                // Checksum bits from hash
                byte_val = hash[byte_index - entropy_len];
            }

            if (byte_val & (1 << bit_in_byte)) {
                word_index |= (1 << (10 - bit));
            }
        }

        // Validate word index
        if (word_index >= 2048) {
            return -1;
        }

        // Append word to mnemonic
        const char *word = BIP39_WORDLIST[word_index];
        size_t word_len = strlen(word);

        // Check buffer space
        if (mnemonic_len + word_len + 2 > mnemonic_size) {
            return -1;
        }

        if (i > 0) {
            mnemonic[mnemonic_len++] = ' ';
        }

        strcpy(mnemonic + mnemonic_len, word);
        mnemonic_len += word_len;
    }

    return 0;
}

/**
 * Generate random BIP39 mnemonic
 */
int bip39_generate_mnemonic(
    int word_count,
    char *mnemonic,
    size_t mnemonic_size
) {
    // Map word count to entropy length
    size_t entropy_len;
    switch (word_count) {
        case 12: entropy_len = 16; break;  // 128 bits
        case 15: entropy_len = 20; break;  // 160 bits
        case 18: entropy_len = 24; break;  // 192 bits
        case 21: entropy_len = 28; break;  // 224 bits
        case 24: entropy_len = 32; break;  // 256 bits
        default:
            return -1;
    }

    // Generate random entropy
    uint8_t entropy[32];
    if (get_random_bytes(entropy, entropy_len) != 0) {
        return -1;
    }

    // Convert entropy to mnemonic
    return bip39_mnemonic_from_entropy(entropy, entropy_len, mnemonic, mnemonic_size);
}

/**
 * Find word index in BIP39 wordlist using binary search
 */
int bip39_word_index(const char *word) {
    if (!word) {
        return -1;
    }

    // Binary search in sorted wordlist
    int left = 0;
    int right = 2047;

    while (left <= right) {
        int mid = (left + right) / 2;
        int cmp = strcmp(word, BIP39_WORDLIST[mid]);

        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return -1;  // Not found
}

/**
 * Validate BIP39 mnemonic
 */
bool bip39_validate_mnemonic(const char *mnemonic) {
    if (!mnemonic) {
        return false;
    }

    // Split mnemonic into words
    char *mnemonic_copy = strdup(mnemonic);
    if (!mnemonic_copy) {
        return false;
    }

    // Count words and validate each
    uint16_t word_indices[24];
    int word_count = 0;

    char *token = strtok(mnemonic_copy, " ");
    while (token != NULL && word_count < 24) {
        int index = bip39_word_index(token);
        if (index < 0) {
            free(mnemonic_copy);
            return false;
        }

        word_indices[word_count++] = index;
        token = strtok(NULL, " ");
    }

    free(mnemonic_copy);

    // Validate word count
    if (word_count != 12 && word_count != 15 && word_count != 18 &&
        word_count != 21 && word_count != 24) {
        return false;
    }

    // Calculate entropy length
    size_t total_bits = word_count * 11;
    size_t checksum_bits = total_bits / 33;  // total_bits / (entropy_bits + checksum_bits) * checksum_bits
    size_t entropy_bits = total_bits - checksum_bits;
    size_t entropy_len = entropy_bits / 8;

    // Extract entropy from word indices
    uint8_t entropy[32] = {0};

    for (int i = 0; i < word_count; i++) {
        uint16_t index = word_indices[i];

        // Write 11 bits from this word index
        size_t bit_index = i * 11;
        for (int bit = 0; bit < 11; bit++) {
            if (index & (1 << (10 - bit))) {
                size_t byte_index = (bit_index + bit) / 8;
                size_t bit_in_byte = 7 - ((bit_index + bit) % 8);

                if (byte_index < 32) {
                    entropy[byte_index] |= (1 << bit_in_byte);
                }
            }
        }
    }

    // Calculate expected checksum
    uint8_t hash[32];
    SHA256(entropy, entropy_len, hash);

    // Extract actual checksum from word indices (last checksum_bits of the mnemonic bits)
    uint8_t actual_checksum = 0;
    for (size_t i = 0; i < checksum_bits; i++) {
        size_t bit_index = entropy_bits + i;
        size_t byte_index = bit_index / 8;
        size_t bit_in_byte = 7 - (bit_index % 8);

        if (entropy[byte_index] & (1 << bit_in_byte)) {
            actual_checksum |= (1 << (checksum_bits - 1 - i));
        }
    }

    // Expected checksum: top checksum_bits of SHA256 hash
    uint8_t expected_checksum = hash[0] >> (8 - checksum_bits);

    return actual_checksum == expected_checksum;
}

/**
 * Get BIP39 wordlist
 */
const char **bip39_get_wordlist(void) {
    return BIP39_WORDLIST;
}
