/**
 * @file crypto_helpers.c
 * @brief Shared DNAC crypto helper functions
 */

#include "dnac/crypto_helpers.h"
#include "dnac/dnac.h"
#include "crypto/hash/qgp_sha3.h"
#include <string.h>

/* Helper: convert single hex char to nibble value, -1 on error */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int dnac_derive_chain_id(const char *genesis_fp,
                          const uint8_t *tx_hash,
                          uint8_t *chain_id_out) {
    if (!genesis_fp || !tx_hash || !chain_id_out) return -1;

    /* Fingerprint must be exactly 128 hex chars (64 bytes) */
    size_t fp_len = strlen(genesis_fp);
    if (fp_len != 128) return -1;

    /* Convert fingerprint hex to binary (64 bytes) */
    uint8_t fp_bytes[64];
    for (size_t i = 0; i < 64; i++) {
        int hi = hex_nibble(genesis_fp[i * 2]);
        int lo = hex_nibble(genesis_fp[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        fp_bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    /* Concatenate: fp_bytes (64) || tx_hash (DNAC_TX_HASH_SIZE = 64) */
    uint8_t data[64 + DNAC_TX_HASH_SIZE];
    memcpy(data, fp_bytes, 64);
    memcpy(data + 64, tx_hash, DNAC_TX_HASH_SIZE);

    /* chain_id = SHA3-256(data) */
    return qgp_sha3_256(data, sizeof(data), chain_id_out);
}

int dnac_build_inbox_key(const char *owner_fp, const uint8_t *chain_id,
                          uint8_t *key_out) {
    uint8_t key_data[384];
    size_t offset = 0;

    const char *prefix = "dnac:inbox:";
    memcpy(key_data, prefix, strlen(prefix));
    offset = strlen(prefix);

    /* v0.10.0: Include chain_id hex in key for zone scoping */
    if (chain_id) {
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            key_data[offset++] = hex[(chain_id[i] >> 4) & 0xF];
            key_data[offset++] = hex[chain_id[i] & 0xF];
        }
        key_data[offset++] = ':';
    }

    size_t fp_len = strlen(owner_fp);
    memcpy(key_data + offset, owner_fp, fp_len);
    offset += fp_len;

    return qgp_sha3_512(key_data, offset, key_out);
}
