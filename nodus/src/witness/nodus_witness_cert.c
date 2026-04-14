/**
 * Nodus — Witness Sync Cert Preimage Signing — Implementation
 *
 * See nodus_witness_cert.h for the layout spec.
 *
 * @file nodus_witness_cert.c
 */

#include "witness/nodus_witness_cert.h"

#include <assert.h>
#include <string.h>

const uint8_t NODUS_WITNESS_CERT_DOMAIN_TAG[8] = {
    'c', 'e', 'r', 't', 0x00, 0x00, 0x00, 0x00
};

_Static_assert(sizeof(NODUS_WITNESS_CERT_DOMAIN_TAG) == 8,
               "cert domain tag must be exactly 8 bytes");

int nodus_witness_compute_cert_preimage(const uint8_t *block_hash,
                                          const uint8_t *voter_id,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          uint8_t *out_buf) {
    if (!block_hash || !voter_id || !chain_id || !out_buf) return -1;

    /* [0..7] domain tag */
    memcpy(out_buf, NODUS_WITNESS_CERT_DOMAIN_TAG,
           sizeof(NODUS_WITNESS_CERT_DOMAIN_TAG));

    /* [8..71] block_hash (64 bytes) */
    memcpy(out_buf + 8, block_hash, NODUS_T3_TX_HASH_LEN);

    /* [72..103] voter_id (32 bytes) */
    memcpy(out_buf + 72, voter_id, NODUS_T3_WITNESS_ID_LEN);

    /* [104..111] height (little-endian uint64) */
    for (int i = 0; i < 8; i++)
        out_buf[104 + i] = (uint8_t)((height >> (i * 8)) & 0xFF);

    /* [112..143] chain_id (32 bytes) */
    memcpy(out_buf + 112, chain_id, 32);

    return 0;
}
