/**
 * @file crypto_helpers.c
 * @brief Shared DNAC crypto helper functions
 */

#include "dnac/crypto_helpers.h"
#include "crypto/hash/qgp_sha3.h"
#include <string.h>

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
