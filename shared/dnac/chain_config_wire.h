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
 * Header always 42 bytes. Per-vote 4659 bytes.
 * Max block = 42 + 128*4659 = 596394 (Ledger V2 S3; was 42 + 7*4659 = 32655).
 *
 * S3 GENERALIZATION (Ledger V2): the vote-slot cap moved from the hardcoded
 * 7-seat committee to DNA_MAX_ACTIVE_VALIDATORS. This is a STRICT WIRE
 * SUPERSET — not a format change:
 *   - Field order, field widths and offsets are untouched.
 *   - committee_sig_count stays u8 (128 <= 255), so the fixed 42-byte header
 *     is byte-identical for every transaction the live chain has ever seen.
 *   - Every historical CHAIN_CONFIG tx (5..7 votes) encodes and decodes to
 *     exactly the same bytes as before; only counts in 8..128 — which no
 *     encoder could previously produce and no decoder previously accepted —
 *     become representable.
 * The SEMANTIC threshold is NOT on this wire: it is the witness-side
 * "quorum of the committee that governs the signing height" check in
 * nodus_witness_chain_config.c (dna_bft_quorum over the actual committee
 * count). This header only bounds the shape.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CHAIN_CONFIG_WIRE_H
#define SHARED_DNAC_CHAIN_CONFIG_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/ledger_ids.h"   /* DNA_MAX_ACTIVE_VALIDATORS (S3 release cap) */

#ifdef __cplusplus
extern "C" {
#endif

#define DNAC_CC_WIRE_WITNESS_ID_SIZE   32
#define DNAC_CC_WIRE_SIGNATURE_SIZE    4627  /* Dilithium5 */

/** Maximum occupied vote slots. Tracks the release's active-validator
 *  ceiling — NOT a permanent protocol maximum (see ledger_ids.h). */
#define DNAC_CC_WIRE_MAX_SLOTS         DNA_MAX_ACTIVE_VALIDATORS

/** Cheap SHAPE floor, not the quorum rule.
 *
 *  5 remains a valid floor for this release because the committee can never
 *  be smaller than the 7 initial seats (DNAC_COMMITTEE_SIZE), and
 *  dna_bft_quorum(7) == 5 — so no honest proposal with fewer than 5 votes
 *  can ever reach quorum, whatever the active-set size. Rejecting <5 early
 *  therefore costs nothing and saves the decoder/verifier work.
 *
 *  The ACTUAL threshold is dna_bft_quorum(committee_count) evaluated
 *  witness-side against the committee governing the signing height. If a
 *  future release ever allows a committee smaller than 7 seats, this floor
 *  must be revisited together with that change. */
#define DNAC_CC_WIRE_MIN_SIGS          5
#define DNAC_CC_WIRE_FIXED_LEN         42    /* bytes before votes[] */
#define DNAC_CC_WIRE_PER_VOTE          (DNAC_CC_WIRE_WITNESS_ID_SIZE + \
                                         DNAC_CC_WIRE_SIGNATURE_SIZE)
#define DNAC_CC_WIRE_MAX_LEN           (DNAC_CC_WIRE_FIXED_LEN + \
                                         DNAC_CC_WIRE_MAX_SLOTS * \
                                         DNAC_CC_WIRE_PER_VOTE)

/* NOTE: the cap invariants (slot count fits the u8 count byte; the sig floor
 * sits below the cap) are asserted in chain_config_wire.c rather than here —
 * this header carries an extern "C" guard, and _Static_assert is not a C++
 * keyword, so a C++ consumer would fail to compile it. */

/** One collected committee vote — matches the on-wire layout. */
typedef struct {
    uint8_t witness_id[DNAC_CC_WIRE_WITNESS_ID_SIZE];
    uint8_t signature[DNAC_CC_WIRE_SIGNATURE_SIZE];
} dnac_cc_wire_vote_t;

/** Parsed / to-encode CHAIN_CONFIG extension fields.
 *
 * ⚠ SIZE: ~583 KiB since the S3 slot-cap generalization (128 × 4659 B).
 * This struct MUST NOT be placed on the stack — heap-allocate it (calloc)
 * and free it on every path, error paths included. */
typedef struct {
    uint8_t  param_id;
    uint64_t new_value;
    uint64_t effective_block_height;
    uint64_t proposal_nonce;
    uint64_t signed_at_block;
    uint64_t valid_before_block;
    uint8_t  committee_sig_count;                 /* occupied entries in votes[] */
    dnac_cc_wire_vote_t votes[DNAC_CC_WIRE_MAX_SLOTS];
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
 *   - committee_sig_count <= DNAC_CC_WIRE_MAX_SLOTS
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
