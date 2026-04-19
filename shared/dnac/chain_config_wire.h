/**
 * @file shared/dnac/chain_config_wire.h
 * @brief Shared wire format for the CHAIN_CONFIG transaction extension block.
 *
 * Hard-Fork v1. Defines the byte layout of the appended chain_config fields
 * that sit after the generic TX body (inputs/outputs/witnesses/signers).
 * Used by:
 *   - dnac/src/transaction/serialize.c (encode on the client)
 *   - nodus/src/witness/nodus_witness_chain_config.c (decode on the witness)
 *   - nodus/tools/nodus-cli.c chain-config verb (encode from an operator)
 *
 * Drift between encoder and decoder is a silent consensus break, so all
 * three call sites route through dnac_cc_wire_encode / dnac_cc_wire_decode.
 *
 * Layout (big-endian multi-byte integers):
 *   param_id(u8) || new_value(u64) || effective_block_height(u64) ||
 *   proposal_nonce(u64) || signed_at_block(u64) || valid_before_block(u64) ||
 *   committee_sig_count(u8) ||
 *   votes[committee_sig_count] × { witness_id(32), signature(4627) }
 *
 * Header always 42 bytes. Per-vote 4659 bytes. Max block = 42 + 7*4659 = 32655.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CHAIN_CONFIG_WIRE_H
#define SHARED_DNAC_CHAIN_CONFIG_WIRE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNAC_CC_WIRE_WITNESS_ID_SIZE   32
#define DNAC_CC_WIRE_SIGNATURE_SIZE    4627  /* Dilithium5 */
#define DNAC_CC_WIRE_COMMITTEE_SIZE    7     /* max occupied vote slots */
#define DNAC_CC_WIRE_MIN_SIGS          5     /* quorum threshold */
#define DNAC_CC_WIRE_FIXED_LEN         42    /* bytes before votes[] */
#define DNAC_CC_WIRE_PER_VOTE          (DNAC_CC_WIRE_WITNESS_ID_SIZE + \
                                         DNAC_CC_WIRE_SIGNATURE_SIZE)
#define DNAC_CC_WIRE_MAX_LEN           (DNAC_CC_WIRE_FIXED_LEN + \
                                         DNAC_CC_WIRE_COMMITTEE_SIZE * \
                                         DNAC_CC_WIRE_PER_VOTE)

/** One collected committee vote — matches the on-wire layout. */
typedef struct {
    uint8_t witness_id[DNAC_CC_WIRE_WITNESS_ID_SIZE];
    uint8_t signature[DNAC_CC_WIRE_SIGNATURE_SIZE];
} dnac_cc_wire_vote_t;

/** Parsed / to-encode CHAIN_CONFIG extension fields. */
typedef struct {
    uint8_t  param_id;
    uint64_t new_value;
    uint64_t effective_block_height;
    uint64_t proposal_nonce;
    uint64_t signed_at_block;
    uint64_t valid_before_block;
    uint8_t  committee_sig_count;                 /* occupied entries in votes[] */
    dnac_cc_wire_vote_t votes[DNAC_CC_WIRE_COMMITTEE_SIZE];
} dnac_cc_wire_ext_t;

/**
 * Exact byte count the encoder will emit for `fields`.
 * committee_sig_count above the committee size cap is clamped to the cap.
 * Returns 0 on null input.
 */
size_t dnac_cc_wire_encoded_size(const dnac_cc_wire_ext_t *fields);

/**
 * Encode extension bytes into `dst`. `dst_cap` must be at least the value
 * returned by dnac_cc_wire_encoded_size(fields). Trailing vote slots beyond
 * committee_sig_count are NOT written. Writes bytes_written_out on success.
 *
 * @return 0 on success, -1 on null arg / short buffer.
 */
int dnac_cc_wire_encode(const dnac_cc_wire_ext_t *fields,
                         uint8_t *dst, size_t dst_cap,
                         size_t *bytes_written_out);

/**
 * Decode extension bytes starting at `src`. Validates:
 *   - src_len >= fixed_len
 *   - committee_sig_count <= committee cap
 *   - src_len >= fixed_len + committee_sig_count * per_vote
 *
 * Does NOT enforce the [MIN_SIGS, MAX_SIGS] range or any semantic rule —
 * callers layer those on top (dnac_tx_verify_chain_config_rules on the
 * client, verify_cc_local_rules on the witness). Writes bytes_consumed_out
 * on success; unused trailing vote slots in `out` are zeroed.
 *
 * @return 0 on success, -1 on null arg / truncated / invalid count.
 */
int dnac_cc_wire_decode(const uint8_t *src, size_t src_len,
                         dnac_cc_wire_ext_t *out,
                         size_t *bytes_consumed_out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CHAIN_CONFIG_WIRE_H */
