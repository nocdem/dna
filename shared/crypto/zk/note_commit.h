/**
 * @file note_commit.h
 * @brief Shielded note-commitment + note-tree Merkle compress (S0, dual-mode).
 *
 * Both primitives are the STOCK Plonky3 `PaddingFreeSponge<Perm,8,4,4>`
 * (symmetric/src/sponge.rs @ 82cfad73) instantiated over the byte-matched
 * width-8 Goldilocks Poseidon2 permutation (`poseidon2_goldilocks8_permute`):
 *
 *   - RATE  = 4, CAPACITY = 4  ⇒ collision resistance |F|^{c/2} = (2^64)^2
 *             = 2^128  [BDPA08], valid because inputs are PROTOCOL-FIXED length
 *             (never attacker-chosen length — the length-extension caveat in
 *             sponge.rs does not apply to fixed-length Merkle-leaf-style hashes).
 *   - OUT   = 4 lanes = 256-bit digest.
 *   - IV    = all-zero state (stock PaddingFreeSponge; NO capacity-IV wrapper —
 *             domain separation is carried as a preimage ELEMENT, DNAC_DOMSEP_NOTE,
 *             not a non-standard IV). This discharges the conf_root_air.h:47
 *             owed byte-match with a construction that IS a Plonky3 primitive.
 *
 * Absorb schedule for an 8-element input (exactly two rate-4 blocks):
 *     state=[0;8]; state[0..4]=in[0..4]; permute; state[0..4]=in[4..8]; permute;
 *     digest = state[0..4].
 * (Per the PaddingFreeSponge loop, after two full blocks the input is exhausted
 *  at i==0 on the next block, so NO third permutation runs — sponge.rs:180-200.)
 *
 * Ground truth: tools/vectors/note_commit_sponge.json (oracle
 * `dump-note-commit-sponge`), checked by test_note_commit.c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_NOTE_COMMIT_H
#define DNAC_ZK_NOTE_COMMIT_H

#include <stdint.h>

#include "shielded_domsep.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Digest width (lanes) squeezed from the sponge = 256-bit note-commitment. */
#define NOTE_COMMIT_LANES 4

/** Shielded address width (lanes): addr_pub = Poseidon2(ak,nk), full 256-bit
 *  (dm-c1 C-B1 — narrow width enables sender 2nd-preimage). */
#define NOTE_ADDR_LANES 4

/** Commitment randomness width (lanes). */
#define NOTE_RCM_LANES 2

/**
 * @brief Core fixed-length PaddingFreeSponge<8,4,4> over an 8-element message.
 *
 * The single primitive both note_commit() and note_merkle_compress() wrap.
 * @param in   8 field elements (each MUST be canonical, < GOLDILOCKS_P).
 * @param out  4-lane (256-bit) digest.
 */
void note_sponge_hash8(const uint64_t in[8], uint64_t out[NOTE_COMMIT_LANES]);

/**
 * @brief Note-commitment cm = PaddingFreeSponge(value, addr_pub[4], rcm[2],
 *        DNAC_DOMSEP_NOTE) — the shielded-note leaf (dm-c1 condition 1).
 * @param value     note value (native base units; caller ensures < 2^52 range).
 * @param addr_pub  4 lanes (recipient shielded address).
 * @param rcm       2 lanes (commitment randomness).
 * @param cm_out    4-lane commitment.
 * All field inputs MUST be canonical (< GOLDILOCKS_P).
 */
void note_commit(uint64_t value, const uint64_t addr_pub[NOTE_ADDR_LANES],
                 const uint64_t rcm[NOTE_RCM_LANES],
                 uint64_t cm_out[NOTE_COMMIT_LANES]);

/**
 * @brief Note-tree 2-to-1 Merkle compress = PaddingFreeSponge(left[4], right[4])
 *        — capacity-preserving (the SPONGE has CR 2^128; NOT a zero-capacity
 *        TruncatedPermutation, dm-c3 F1). Child order is caller-fixed (Merkle
 *        walk pins it by pos bit). NOTE: the 2^128 figure is the sponge's
 *        collision resistance; full LEAF/INTERNAL-node separation for the tree is
 *        NOT provided by this function NOR by the standalone C3 gate — it is
 *        discharged structurally at S4 composition (D pinned as a constant + C1
 *        leaf==cm_carry), see shielded_domsep.h DNAC_DOMSEP_MERKLE (red-team
 *        C3-HIGH).
 * @param left   4-lane left child digest.
 * @param right  4-lane right child digest.
 * @param out    4-lane parent digest.
 * All inputs MUST be canonical (< GOLDILOCKS_P) — they are Poseidon2 outputs.
 */
void note_merkle_compress(const uint64_t left[NOTE_COMMIT_LANES],
                          const uint64_t right[NOTE_COMMIT_LANES],
                          uint64_t out[NOTE_COMMIT_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_NOTE_COMMIT_H */
