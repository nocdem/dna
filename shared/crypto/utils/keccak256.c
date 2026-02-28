/**
 * @file keccak256.c
 * @brief Keccak-256 hash function implementation (Ethereum variant)
 *
 * Uses original Keccak padding (0x01), not NIST SHA3 padding (0x06).
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "keccak256.h"
#include "qgp_log.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define LOG_TAG "KECCAK"

/* Keccak parameters for 256-bit output */
#define KECCAK256_RATE 136   /* (1600 - 2*256) / 8 = 136 bytes */
#define KECCAK_ROUNDS 24

/* Keccak round constants */
static const uint64_t keccak_round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotation offsets */
static const int keccak_rotation_offsets[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

/* Pi permutation indices */
static const int keccak_pi_indices[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

/**
 * 64-bit rotation left
 */
static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

/**
 * Load 64-bit little-endian value
 */
static inline uint64_t load64_le(const uint8_t *p) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) {
        r |= (uint64_t)p[i] << (8 * i);
    }
    return r;
}

/**
 * Store 64-bit little-endian value
 */
static inline void store64_le(uint8_t *p, uint64_t x) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(x >> (8 * i));
    }
}

/**
 * Keccak-f[1600] permutation
 */
static void keccak_f1600(uint64_t state[25]) {
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta step */
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        /* Rho and Pi steps */
        B[0] = state[0];
        for (int i = 0; i < 24; i++) {
            B[keccak_pi_indices[i]] = rotl64(state[(i == 0) ? 1 : keccak_pi_indices[i - 1]],
                                              keccak_rotation_offsets[i]);
        }

        /* Chi step */
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                state[y * 5 + x] = B[y * 5 + x] ^ ((~B[y * 5 + ((x + 1) % 5)]) & B[y * 5 + ((x + 2) % 5)]);
            }
        }

        /* Iota step */
        state[0] ^= keccak_round_constants[round];
    }
}

/**
 * Keccak sponge absorb and squeeze (single call)
 */
static void keccak_sponge(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len,
    uint8_t padding_byte,
    size_t rate
) {
    uint64_t state[25] = {0};
    uint8_t block[200];

    /* Absorb phase */
    while (input_len >= rate) {
        for (size_t i = 0; i < rate / 8; i++) {
            state[i] ^= load64_le(input + i * 8);
        }
        keccak_f1600(state);
        input += rate;
        input_len -= rate;
    }

    /* Pad and absorb final block */
    memset(block, 0, sizeof(block));
    memcpy(block, input, input_len);
    block[input_len] = padding_byte;
    block[rate - 1] |= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(state);

    /* Squeeze phase */
    size_t offset = 0;
    while (output_len > 0) {
        size_t chunk = (output_len < rate) ? output_len : rate;

        for (size_t i = 0; i < (chunk + 7) / 8; i++) {
            store64_le(block + i * 8, state[i]);
        }
        memcpy(output + offset, block, chunk);

        output_len -= chunk;
        offset += chunk;

        if (output_len > 0) {
            keccak_f1600(state);
        }
    }

    /* Clear sensitive data */
    memset(state, 0, sizeof(state));
    memset(block, 0, sizeof(block));
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32]) {
    if (!data && len > 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid data pointer");
        return -1;
    }
    if (!hash_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid output pointer");
        return -1;
    }

    /* Keccak-256 uses padding byte 0x01 (original Keccak, NOT SHA3's 0x06) */
    keccak_sponge(data, len, hash_out, 32, 0x01, KECCAK256_RATE);

    return 0;
}

int keccak256_hex(const uint8_t *data, size_t len, char hex_out[65]) {
    if (!hex_out) {
        return -1;
    }

    uint8_t hash[32];
    if (keccak256(data, len, hash) != 0) {
        return -1;
    }

    for (int i = 0; i < 32; i++) {
        snprintf(hex_out + i * 2, 3, "%02x", hash[i]);
    }
    hex_out[64] = '\0';

    return 0;
}

int eth_address_from_pubkey(
    const uint8_t pubkey_uncompressed[65],
    uint8_t address_out[20]
) {
    if (!pubkey_uncompressed || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to eth_address_from_pubkey");
        return -1;
    }

    /* Verify it's an uncompressed public key (starts with 0x04) */
    if (pubkey_uncompressed[0] != 0x04) {
        QGP_LOG_ERROR(LOG_TAG, "Public key must be uncompressed (start with 0x04)");
        return -1;
    }

    /* Hash the public key without the 0x04 prefix (64 bytes) */
    uint8_t hash[32];
    if (keccak256(pubkey_uncompressed + 1, 64, hash) != 0) {
        return -1;
    }

    /* Take last 20 bytes as address */
    memcpy(address_out, hash + 12, 20);

    return 0;
}

int eth_address_checksum(
    const char *address_lowercase,
    char address_checksummed[41]
) {
    if (!address_lowercase || !address_checksummed) {
        return -1;
    }

    /* Verify input is 40 hex characters */
    size_t len = strlen(address_lowercase);
    if (len != 40) {
        QGP_LOG_ERROR(LOG_TAG, "Address must be 40 hex chars, got %zu", len);
        return -1;
    }

    /* Convert to lowercase for hashing */
    char lowercase[41];
    for (int i = 0; i < 40; i++) {
        lowercase[i] = (char)tolower((unsigned char)address_lowercase[i]);
    }
    lowercase[40] = '\0';

    /* Hash the lowercase address */
    uint8_t hash[32];
    if (keccak256((const uint8_t *)lowercase, 40, hash) != 0) {
        return -1;
    }

    /* Apply checksum: uppercase if corresponding hash nibble >= 8 */
    for (int i = 0; i < 40; i++) {
        char c = lowercase[i];

        if (c >= 'a' && c <= 'f') {
            /* Get corresponding nibble from hash */
            int hash_byte = i / 2;
            int hash_nibble = (i % 2 == 0) ? (hash[hash_byte] >> 4) : (hash[hash_byte] & 0x0F);

            if (hash_nibble >= 8) {
                c = (char)toupper((unsigned char)c);
            }
        }

        address_checksummed[i] = c;
    }
    address_checksummed[40] = '\0';

    return 0;
}

int eth_address_from_pubkey_hex(
    const uint8_t pubkey_uncompressed[65],
    char address_hex_out[43]
) {
    if (!pubkey_uncompressed || !address_hex_out) {
        return -1;
    }

    /* Get raw address */
    uint8_t address[20];
    if (eth_address_from_pubkey(pubkey_uncompressed, address) != 0) {
        return -1;
    }

    /* Convert to lowercase hex */
    char lowercase[41];
    for (int i = 0; i < 20; i++) {
        snprintf(lowercase + i * 2, 3, "%02x", address[i]);
    }
    lowercase[40] = '\0';

    /* Apply EIP-55 checksum */
    char checksummed[41];
    if (eth_address_checksum(lowercase, checksummed) != 0) {
        return -1;
    }

    /* Format with 0x prefix */
    snprintf(address_hex_out, 43, "0x%s", checksummed);

    return 0;
}

int eth_address_verify_checksum(const char *address) {
    if (!address) {
        return 0;
    }

    /* Skip 0x prefix if present */
    const char *hex = address;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    /* Must be 40 chars */
    if (strlen(hex) != 40) {
        return 0;
    }

    /* Compute expected checksum */
    char expected[41];
    if (eth_address_checksum(hex, expected) != 0) {
        return 0;
    }

    /* Compare */
    return (strcmp(hex, expected) == 0) ? 1 : 0;
}
