/**
 * Nodus — DNAC spend_result preimage builder (Phase 12 / Task 12.6)
 *
 * Pure helper that builds the 221-byte preimage that the witness
 * Dilithium5-signs as the dnac_spend response attestation. Documented
 * spec lives in nodus_witness_handlers.c next to the live signer; this
 * helper is the testable surface used by both the live path and the
 * regression tests in test_spend_preimage.c.
 *
 * Layout (221 bytes total):
 *   [0..7]      'spndrslt' domain tag        (8)
 *   [8..71]     tx_hash                       (64)
 *   [72..103]   witness_id                    (32)
 *   [104..167]  SHA3-512(witness_pubkey)      (64)
 *   [168..199]  chain_id                      (32)
 *   [200..207]  timestamp (LE uint64)         (8)
 *   [208..215]  block_height (LE uint64)      (8)
 *   [216..219]  tx_index (LE uint32)          (4)
 *   [220]       status                        (1)
 *
 * @file nodus_witness_spend_preimage.h
 */

#ifndef NODUS_WITNESS_SPEND_PREIMAGE_H
#define NODUS_WITNESS_SPEND_PREIMAGE_H

#include "nodus/nodus_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNAC_SPEND_RESULT_PREIMAGE_LEN  221

/** 8-byte domain tag — declared extern so callers and tests bind to
 * the same authoritative copy. */
extern const uint8_t DNAC_SPEND_RESULT_DOMAIN_TAG[8];

/**
 * Build the 221-byte spend_result preimage into out_buf.
 *
 * @param tx_hash        64-byte committed TX hash (mempool entry hash)
 * @param witness_id     32-byte witness ID of the signer
 * @param wpk_hash       64-byte SHA3-512(witness Dilithium5 public key)
 * @param chain_id       32-byte chain identifier
 * @param timestamp      witness wall clock at sign time (LE)
 * @param block_height   block height the TX was committed at (LE)
 * @param tx_index       per-block tx_index (LE uint32)
 * @param status         spend status byte (0 = approved, ...)
 * @param out_buf        caller-owned 221-byte buffer
 * @return 0 on success, -1 on NULL input
 */
int dnac_compute_spend_result_preimage(const uint8_t *tx_hash,
                                         const uint8_t *witness_id,
                                         const uint8_t *wpk_hash,
                                         const uint8_t *chain_id,
                                         uint64_t timestamp,
                                         uint64_t block_height,
                                         uint32_t tx_index,
                                         uint8_t status,
                                         uint8_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_SPEND_PREIMAGE_H */
