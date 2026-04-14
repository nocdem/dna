/**
 * Nodus — DNAC spend_result preimage builder — implementation
 *
 * See nodus_witness_spend_preimage.h for the layout spec.
 *
 * @file nodus_witness_spend_preimage.c
 */

#include "witness/nodus_witness_spend_preimage.h"

#include <assert.h>
#include <string.h>

const uint8_t DNAC_SPEND_RESULT_DOMAIN_TAG[8] = {
    's', 'p', 'n', 'd', 'r', 's', 'l', 't'
};

_Static_assert(sizeof(DNAC_SPEND_RESULT_DOMAIN_TAG) == 8,
               "spend_result domain tag must be exactly 8 bytes");

int dnac_compute_spend_result_preimage(const uint8_t *tx_hash,
                                         const uint8_t *witness_id,
                                         const uint8_t *wpk_hash,
                                         const uint8_t *chain_id,
                                         uint64_t timestamp,
                                         uint64_t block_height,
                                         uint32_t tx_index,
                                         uint8_t status,
                                         uint8_t *out_buf) {
    if (!tx_hash || !witness_id || !wpk_hash || !chain_id || !out_buf)
        return -1;

    memcpy(out_buf,        DNAC_SPEND_RESULT_DOMAIN_TAG, 8);
    memcpy(out_buf + 8,    tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(out_buf + 72,   witness_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(out_buf + 104,  wpk_hash, 64);
    memcpy(out_buf + 168,  chain_id, 32);

    for (int i = 0; i < 8; i++)
        out_buf[200 + i] = (uint8_t)((timestamp >> (i * 8)) & 0xFF);
    for (int i = 0; i < 8; i++)
        out_buf[208 + i] = (uint8_t)((block_height >> (i * 8)) & 0xFF);
    for (int i = 0; i < 4; i++)
        out_buf[216 + i] = (uint8_t)((tx_index >> (i * 8)) & 0xFF);

    out_buf[220] = status;
    return 0;
}
