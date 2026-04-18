/**
 * @file chain_def_codec.h
 * @brief Deterministic encode/decode for dnac_chain_definition_t
 *
 * The byte format produced by dnac_chain_def_encode is identical to the
 * sub-sequence used by dnac_block_compute_hash when building the genesis
 * preimage. This ensures witness DB storage, wire serialization, and
 * hash computation all agree byte-for-byte.
 *
 * Use case 1 (Task 11): witness DB stores encoded bytes as a BLOB column
 *                       for genesis blocks.
 * Use case 2 (Phase 5): client fetches genesis bytes from a peer and
 *                       decodes to populate trusted_state.
 */

#ifndef DNAC_CHAIN_DEF_CODEC_H
#define DNAC_CHAIN_DEF_CODEC_H

#include "dnac/block.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum possible serialized chain_def size (when witness_count ==
 * DNAC_MAX_WITNESSES_COMPILE_CAP AND initial_validator_count ==
 * DNAC_COMMITTEE_SIZE). Caller can use this to pre-allocate.
 */
size_t dnac_chain_def_max_size(void);

/**
 * Actual serialized size for a specific chain_def (depends on witness_count).
 * @return size in bytes, or 0 on invalid input.
 */
size_t dnac_chain_def_encoded_size(const dnac_chain_definition_t *cd);

/**
 * Encode chain_def into a byte buffer in genesis-preimage order.
 *
 * @param cd     Source chain definition (must not be NULL).
 * @param out    [out] Caller-allocated buffer.
 * @param cap    Buffer capacity in bytes.
 * @param len    [out] Bytes written on success.
 * @return 0 on success, -1 on error (cap too small, NULL inputs,
 *         witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP).
 */
int dnac_chain_def_encode(const dnac_chain_definition_t *cd,
                           uint8_t *out, size_t cap, size_t *len);

/**
 * Decode a chain_def from a byte buffer. Strict — rejects wrong-size
 * input and out-of-range witness_count.
 *
 * @param bytes  Input buffer.
 * @param len    Number of bytes in buffer (must exactly match
 *               dnac_chain_def_encoded_size of the decoded result).
 * @param cd_out [out] Caller-allocated destination. Must be zero-
 *               initialized by caller (unused witness slots will remain
 *               zero to match the genesis_preimage convention).
 * @return 0 on success, -1 on error.
 */
int dnac_chain_def_decode(const uint8_t *bytes, size_t len,
                           dnac_chain_definition_t *cd_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_CHAIN_DEF_CODEC_H */
