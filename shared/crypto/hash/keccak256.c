/**
 * @file keccak256.c
 * @brief Keccak-256 hash function implementation (Ethereum variant)
 *
 * Uses original Keccak padding (0x01), not NIST SHA3 padding (0x06).
 *
 * @author DNA Connect Team
 * @date 2025-12-08
 */

#include "crypto/hash/keccak256.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"  /* qgp_secure_memzero */
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "KECCAK"

/* Keccak parameters for 256-bit output */
#define KECCAK256_RATE 136   /* (1600 - 2*256) / 8 = 136 bytes */

/* ── Keccak-f[1600]: XKCP's generic 64-bit implementation ─────────────
 *
 * Source (pinned): XKCP commit 4affab454735d54e78156880b3b44e38dcbf765c,
 * lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
 * (KeccakP1600_plain64_Permute_24rounds, lines 332-343, and the round
 * constants KeccakF1600RoundConstants, lines 58-82) over the two macro
 * files copied byte-identical into crypto/hash/third_party/xkcp/ (see its
 * PINNED.md). Configuration = that file's default
 * (KeccakP-1600-plain64.h: KeccakP1600_plain64_fullUnrolling, no lane
 * complementing): all 24 rounds unrolled, the 25 lanes in locals. It
 * replaces the loop with modulo indexing that ran at about 43 MB/s on the
 * red-team 1 bench host. The API, the sponge and the padding below are
 * unchanged; the permutation acts on a uint64_t[25] lane array, so it is
 * byte-order independent — load64_le / store64_le keep the byte <-> lane
 * mapping little-endian on every platform. */
#define ROL64(a, offset) \
    ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64 - offset)))
#include "crypto/hash/third_party/xkcp/KeccakP-1600-64.macros"
#define FullUnrolling
#include "crypto/hash/third_party/xkcp/KeccakP-1600-unrolling.macros"

/* Keccak round constants (XKCP KeccakP-1600-opt64.c:58-82; the macros
 * above read them under this name) */
static const uint64_t KeccakF1600RoundConstants[24] = {
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
 * Keccak-f[1600] permutation — XKCP KeccakP-1600-opt64.c:332-343
 * (KeccakP1600_plain64_Permute_24rounds, full unrolling: no loop counter)
 * on a plain lane array.
 */
static void keccak_f1600(uint64_t state[25]) {
    declareABCDE
    uint64_t *stateAsLanes = state;

    copyFromState(A, stateAsLanes)
    rounds24
    copyToState(stateAsLanes, A)
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

    /* L-07: Clear sensitive data with secure wipe */
    qgp_secure_memzero(state, sizeof(state));
    qgp_secure_memzero(block, sizeof(block));
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
