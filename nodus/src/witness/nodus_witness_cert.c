/**
 * Nodus — Witness Sync Cert Preimage Signing — Implementation
 *
 * See nodus_witness_cert.h for the layout spec.
 *
 * @file nodus_witness_cert.c
 */

#include "witness/nodus_witness_cert.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "WITNESS-CERT"

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

int nodus_witness_verify_sync_certs(const uint8_t *block_hash,
                                      uint64_t height,
                                      const uint8_t *chain_id,
                                      const nodus_witness_roster_t *roster,
                                      const nodus_t3_sync_cert_t *certs,
                                      uint32_t cert_count,
                                      uint32_t quorum) {
    if (!block_hash || !chain_id || !roster || !certs) return -1;

    int verified = 0;
    for (uint32_t i = 0; i < cert_count; i++) {
        const nodus_t3_sync_cert_t *c = &certs[i];

        /* Resolve voter pubkey from roster — drop unknown voters */
        const nodus_witness_roster_entry_t *voter = NULL;
        for (uint32_t r = 0; r < roster->n_witnesses; r++) {
            if (memcmp(roster->witnesses[r].witness_id, c->voter_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                voter = &roster->witnesses[r];
                break;
            }
        }
        if (!voter) continue;

        /* Reconstruct cert preimage with this cert's voter_id */
        uint8_t preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(block_hash, c->voter_id,
                                                  height, chain_id,
                                                  preimage) != 0)
            continue;

        if (qgp_dsa87_verify(c->signature, NODUS_SIG_BYTES,
                              preimage, sizeof(preimage),
                              voter->pubkey) != 0) {
            QGP_LOG_WARN(LOG_TAG, "cert verify failed for voter %02x%02x..%02x%02x at height %llu",
                         c->voter_id[0], c->voter_id[1],
                         c->voter_id[30], c->voter_id[31],
                         (unsigned long long)height);
            continue;
        }
        verified++;
    }

    if ((uint32_t)verified < quorum)
        return -1;
    return verified;
}
