/**
 * @file nodus/src/witness/nodus_witness_v2_qc.h
 * @brief Ledger V2 O13 — QC verification bound to COMMITTED authority
 *        (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Nothing in live consensus calls this. The legacy 144-byte certificate
 * path (nodus_witness_cert.{h,c}) remains the live finalization mechanism
 * and is byte-identically untouched. Wiring this into the BFT state
 * machine is O14 work and requires its own authorization.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHY THIS LAYER EXISTS ──────────────────────────────────────────────
 * `dna_qc_v2_verify` (shared/dnac/qc_v2.h) is a PURE function: it cannot
 * reach a database, so it must be handed the governing snapshot and the
 * expected snapshot hash. That is correct layering — shared/ must not
 * depend on nodus_witness_t — but it means the SHARED function alone
 * cannot answer "is this the right validator set?". It only answers "is
 * this QC valid *under the set you gave me*?".
 *
 * A caller that supplies both the snapshot and the hash it is checked
 * against supplies its own authority. This file removes that possibility:
 * every authority input is DERIVED from committed state here, and the
 * function takes no snapshot, no set hash, no N and no quorum parameter.
 * There is no argument through which a caller, a peer message, a header
 * or a QC can propose any of them.
 *
 * ── WHAT THE HEADER'S validator_set_hash IS ────────────────────────────
 * A COMMITMENT, never a source. The resolved snapshot is re-hashed and the
 * header must MATCH it. A header naming a set it likes is rejected, not
 * obeyed.
 *
 * ── FAULT vs VERDICT ───────────────────────────────────────────────────
 * Follows the established engine convention:
 *   -1 = VERDICT  — this block/QC is invalid. Every node sees this.
 *   -2 = FAULT    — THIS NODE cannot decide (no committed snapshot for the
 *                   epoch, DB error, hash backend failure). The caller must
 *                   not vote and must not convert it into a rejection.
 * "No committed authority for that epoch" is deliberately a FAULT, not a
 * verdict: another node may hold the snapshot, and a node that cannot know
 * who was allowed to sign must stay silent rather than declare a valid
 * block invalid. Silence is survivable at f=2; a confident wrong answer
 * forks the chain.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_QC_H
#define NODUS_WITNESS_V2_QC_H

#include <stdint.h>

#include "dnac/block_v2.h"
#include "dnac/qc_v2.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify a QC V2 against the authority the CHAIN committed, for the block
 * the given v3 header describes.
 *
 * Side-effect free: reads committed state, writes nothing, votes nothing.
 *
 * Checks, in order, first failure wins:
 *   1. header_version == DNA_BH2_VERSION (retired/unknown fail closed).
 *   2. `hdr->epoch` EQUALS `nodus_v2_epoch_for_height(hdr->block_height)`.
 *      The header's epoch field is verified, never trusted — a header
 *      cannot select its own epoch and therefore cannot select its own
 *      validator set.
 *   3. `hdr->chain_id` EQUALS the chain's derived id
 *      (nodus_witness_v2_chain_id). Cross-chain replay dies here.
 *   4. The authoritative snapshot is resolved from committed state by
 *      HEIGHT (nodus_witness_v2_epoch_authority_for_height). N and the
 *      quorum come from that snapshot alone.
 *   5. The resolved snapshot is re-hashed; `hdr->validator_set_hash` MUST
 *      equal it.
 *   6. The BlockID is computed HERE from the header (dna_bh2_block_id) —
 *      the caller cannot name the id the QC certifies.
 *   7. dna_qc_v2_verify over that id, height, chain id, set hash and
 *      snapshot: membership, strict signer ordering (no duplicates),
 *      n_certs >= floor(2N/3)+1, n_certs <= N, and every ML-DSA-87
 *      signature over the 216-byte cert preimage against the pubkey
 *      COMMITTED IN THE SNAPSHOT. Stake is never consulted.
 *
 * @param w   witness handle (committed state source).
 * @param hdr the v3 block header describing the block being certified.
 * @param qc  the decoded QC.
 * @return 0 accept; -1 verdict (invalid); -2 node-local fault.
 */
int nodus_witness_v2_qc_verify(nodus_witness_t *w,
                               const dna_block_header_v2_t *hdr,
                               const dna_qc_v2_t *qc);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_QC_H */
