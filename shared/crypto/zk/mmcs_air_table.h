/**
 * @file mmcs_air_table.h
 * @brief P2b PIN slice — the preprocessed ROW-TYPE table for the MMCS-verify
 *        AIR: deterministic generator + the PIN-1 root constant + its
 *        fail-close comparator.
 *
 * Design: dnac/docs/plans/2026-07-28-p2b-mmcs-in-air-design.md (local-only)
 *   §0.5 "Row-type selectors: PREPROCESSED — and the table's root PINNED at
 *   the verify entry" (:110-161 PIN-1, :163-173 PIN-2), §4 item 2.
 * NO AIR is built here. This module builds only what PIN-1 and PIN-2 need, and
 * the accompanying test proves both pins can actually be established
 * (tests/test_mmcs_air_table.c).
 *
 * ── WHAT THE TABLE IS ──────────────────────────────────────────────────────
 * One row per step of ONE same-height binary MMCS opening
 * (`dnac_p2_mmcs_verify`, poseidon2_mmcs.c:533-596), three selector columns:
 *
 *   col 0 = is_leaf      one row per Poseidon2 permutation of the leaf hash
 *   col 1 = is_compress  one row per Merkle level (`depth` of them)
 *   col 2 = is_final     exactly one row (root equality)
 *
 * Cells are 0 or 1; the three are mutually exclusive by generation and every
 * padding row is all-zero.
 *
 * ⚠ Mutual exclusivity / booleanity is a GENERATOR obligation, not a property
 * of the medium (design §0.5 columns, round-1 A2-F5): NOTHING on the verify
 * path checks booleanity, exclusivity or sum-to-one on preprocessed cells —
 * `batch_verify.c:722-727` hands the decoded preprocessed window to `air_eval`
 * raw. Under PIN-1 the generator is what guarantees it, and the generator KAT
 * (T2/T3 in tests/test_mmcs_air_table.c) is what checks the generator.
 *
 * ── LEAF-ROW COUNT: DERIVED FROM THE SHIPPED SPONGE, NOT ASSUMED ───────────
 * The leaf hash is `dnac_p2_mmcs_hash_iter` over the CONCATENATED opened rows
 * of every matrix, total_width = Σ widths[m] elements
 * (poseidon2_mmcs.c:105-119 `p2m_leaf_digest`). Its schedule
 * (poseidon2_mmcs.c:41-72, the C port of PaddingFreeSponge<Perm,8,4,4>
 * `hash_iter`, Plonky3 11cc5849 symmetric/src/sponge.rs:172-204 — READ at the
 * pin, both sides, for this file) is:
 *   - zero state, RATE = 4 slots OVERWRITTEN one element at a time
 *     (poseidon2_mmcs.c:55-59 / sponge.rs:182-188);
 *   - a FULL block ⇒ permute, then continue (poseidon2_mmcs.c:60-62 /
 *     sponge.rs:198-199);
 *   - input exhausted AT a block boundary ⇒ break with NO extra permutation
 *     (poseidon2_mmcs.c:63 / sponge.rs:182-194 re-entering the `for` with
 *     `i == 0` and no input left);
 *   - input exhausted MID-block ⇒ permute iff i > 0, then stop
 *     (poseidon2_mmcs.c:64-68 / sponge.rs:189-195).
 * Therefore the permutation count — hence the number of is_leaf rows — is
 *
 *     total_width == 0            → 0
 *     total_width %  4 == 0       → total_width / 4
 *     otherwise                   → total_width / 4 + 1
 *
 * i.e. ceil(total_width / RATE) for total_width > 0, with NO trailing
 * permutation on the exact-multiple case.
 * ⚠ CORRECTED (red-verify A2-F2): an earlier revision claimed the schedule
 * "encodes total_width AND its residue class" — FALSE, ceil is not injective
 * (leaf == 4 for total_width 13, 14, 15 AND 16). What the pinned table
 * encodes is the ROW COUNT ONLY. total_width and its residue are pinned by
 * the cfg plus the AIR's `num_publics` fail-close at its eval entry
 * (mmcs_air.c), and the cfg itself must be pinned by the composition
 * INDEPENDENTLY of the table root (mmcs_air.h OBL-4 — two configs can share
 * one root). The A1-F6 requirement that stands: the row count comes from the
 * pinned table, never from a witnessed length.
 *
 * ── SCHEDULE ───────────────────────────────────────────────────────────────
 *   [leaf rows] [`depth` compress rows] [1 final row] [all-zero padding]
 * padded to the next power of two, minimum 2. The minimum is not cosmetic:
 * `dnac_batch_prove` rejects degree_bits < is_zk + 1 (batch_prover.c:611) and
 * `dnac_prover_coset_lde_bitrev` requires height >= 2 (stark_prover.h:185), so
 * a height-1 table cannot be committed at all.
 *
 * ── PIN-1: DNAC_P2B_PREP_ROOT ──────────────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA: the
 * prover commits its own table (batch_prover.c:820-825) and exports the lanes
 * (batch_prover.c:161), and `dnac_batch_verify` checks only its PRESENCE
 * against the declared matrix count (batch_verify.c:149). Nothing in the tree
 * compares that root to a pinned value. An all-zero selector table would then
 * satisfy every gated P2b constraint vacuously (design §0.5).
 *
 * UPSTREAM DOES NOT HAVE THIS HOLE, and the difference is structural — VERIFIED
 * at the pinned commit for this file, not quoted from the design doc:
 * `BatchCommitments` carries only main / permutation / quotient_chunks / random
 * (Plonky3 11cc5849 batch-stark/src/proof.rs:30-39 — no preprocessed field),
 * because the preprocessed commitment lives VERIFIER-SIDE in `CommonData`
 * (`GlobalPreprocessed.commitment`, 11cc5849 batch-stark/src/common.rs:47-50).
 * Upstream commits it at setup time; DNAC has no setup time — which is also
 * why `batch_prover.c:581-584` calls preprocessed a setup-time artifact whose
 * "stream position would be invented" and fail-closes salted+preprocessed
 * (batch_prover.c:575-590).
 *
 * So the pin is a DNAC-OWNED CONSENSUS ARTIFACT, not a port. The future P2b
 * verify entry compares the decoded preprocessed root against
 * DNAC_P2B_PREP_ROOT and fails closed (`dnac_p2b_prep_root_check`), the S2'-d
 * precedent: `dnac_batch_verify`'s signature does NOT change; the pin lives
 * caller-side exactly like the DNAC_SHIELDED_* constants
 * (shielded_fri_params.h). The constant is bound to its derivation by a
 * runtime KAT (test_mmcs_air_table T3), the shielded_domsep.h /
 * test_shielded_domsep.c practice — a hand-edited literal that drifts from the
 * generator fails there.
 *
 * DERIVATION (exactly the pipeline the SHIPPED prover runs on a preprocessed
 * matrix, batch_prover.c:787-826, so the pin equals the root that appears in a
 * real proof — proved by T4, which reads it back out of a real
 * `dnac_batch_prove` proof via `dnac_batch_proof_commits`):
 *
 *   table = dnac_p2b_table_generate(REFERENCE CONFIG)   // H x 3, H = 16
 *   lde   = dnac_prover_coset_lde_bitrev(table, H, 3,
 *               DNAC_P2B_PREP_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *                                                        // (H << lb) x 3
 *   root  = dnac_p2_mmcs_commit_mixed({lde}, {3}, {H << lb}, 1, ·, NULL)
 *   DNAC_P2B_PREP_ROOT = root.lanes
 *
 * with is_zk = 0 (no ZERO-row padding step, batch_prover.c:795-806) and
 * salt_elems = 0 — MANDATORY, since salted+preprocessed is fail-closed at
 * batch_prover.c:585-589, and the recursion envelope is non-hiding by user
 * lock.
 *
 * ⚠ HONEST LABEL: this is a MECHANISM pin against a REFERENCE schedule, not
 * the production circuit. It proves the pin can be established and that it
 * binds table CONTENTS (T3/N3). The production constant re-pins when P2c fixes
 * the real recursion schedule (num_matrices / widths / depth of the FRI query
 * openings being verified in-circuit).
 *
 * ── PIN-2: prep_next = 1 ───────────────────────────────────────────────────
 * The P2b descriptor MUST set `prep_next = 1`. With `prep_next = 0` the
 * verifier substitutes an ALL-ZERO next-row preprocessed window
 * (batch_verify.c:696-707) while the shipped prover folds the REAL next values
 * unconditionally (batch_prover.c:311-313) — silent vacuity for any gate that
 * reads the next row. This module cannot enforce a descriptor field; the
 * enforcement belongs to the future P2b entry. What lives here is the
 * EVIDENCE: test_mmcs_air_table T4/N2 proves the flip is detectable — one
 * proof over this very table, verified with an otherwise-identical descriptor
 * whose `prep_next` is 0, is REJECTED.
 *
 * Determinism: pure functions of (num_matrices, widths, depth). No clock, no
 * RNG, no allocation, no iteration over anything unordered — two provers
 * building the table from this definition produce the same root
 * (design §1 G-DET-P2b-4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MMCS_AIR_TABLE_H
#define DNAC_ZK_MMCS_AIR_TABLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── table shape ─────────────────────────────────────────────────────────── */

/** Selector columns per row. */
#define DNAC_P2B_TABLE_COLS 3

/** Column indices (col-major meaning of the row-major cells). */
#define DNAC_P2B_COL_IS_LEAF     0
#define DNAC_P2B_COL_IS_COMPRESS 1
#define DNAC_P2B_COL_IS_FINAL    2

/** Leaf-hash sponge rate (PaddingFreeSponge<Perm,8,4,4>, poseidon2_mmcs.c:21). */
#define DNAC_P2B_SPONGE_RATE 4

/** Smallest committable table height (batch_prover.c:611, stark_prover.h:185). */
#define DNAC_P2B_MIN_ROWS ((size_t)2)

/** Fail-close bounds on a config. `depth` is a Merkle height, so it is bounded
 *  by the field's two-adicity exactly as the FRI verifier bounds its global max
 *  height (fri_verifier.c:689, GOLDILOCKS_TWO_ADICITY == 32); past that the
 *  two-adic generator degenerates and no such tree can be committed. */
#define DNAC_P2B_MAX_MATRICES   ((size_t)64)
#define DNAC_P2B_MAX_DEPTH      ((size_t)32)
#define DNAC_P2B_MAX_TOTAL_WIDTH ((size_t)1u << 20)

typedef enum {
    DNAC_P2B_TABLE_OK = 0,
    DNAC_P2B_TABLE_ERR_PARAM = -1,        /**< NULL / out-of-range config    */
    DNAC_P2B_TABLE_ERR_CAPACITY = -2,     /**< out_cells < rows * COLS       */
    DNAC_P2B_TABLE_ERR_ROOT_MISMATCH = -3 /**< root != DNAC_P2B_PREP_ROOT    */
} dnac_p2b_table_status_t;

/** One same-height binary MMCS opening's shape. */
typedef struct {
    size_t        num_matrices; /**< 1 .. DNAC_P2B_MAX_MATRICES              */
    const size_t *widths;       /**< [num_matrices], each >= 1               */
    size_t        depth;        /**< Merkle levels, 1 .. DNAC_P2B_MAX_DEPTH  */
} dnac_p2b_table_cfg_t;

/* ── PIN-1 reference config + constant ───────────────────────────────────── */

/* REFERENCE CONFIG (pinned): num_matrices = 2, widths = {8, 5}, depth = 4.
 * total_width = 13 ⇒ 13 % 4 != 0 ⇒ 3 full blocks + a partial one ⇒ 4 leaf
 * rows; + 4 compress + 1 final = 9 rows ⇒ padded height 16. Chosen to exercise
 * multi-block absorb, a NON-ZERO residue class, and real padding at once. */
#define DNAC_P2B_REF_NUM_MATRICES ((size_t)2)
#define DNAC_P2B_REF_WIDTH_0      ((size_t)8)
#define DNAC_P2B_REF_WIDTH_1      ((size_t)5)
#define DNAC_P2B_REF_DEPTH        ((size_t)4)
#define DNAC_P2B_REF_ROWS         ((size_t)16)

/* Coset-LDE blowup the pin is derived at. Mirrors the shipped consensus FRI
 * blowup DNAC_SHIELDED_FRI_LOG_BLOWUP == 2 (shielded_fri_params.h:138) — the
 * recursion envelope. Kept as its OWN macro so this module does not drag the
 * FRI-verifier header chain in; the test static-asserts the two are equal, so
 * they cannot drift. The coset shift is GOLDILOCKS_GENERATOR == 7
 * (field_goldilocks.h:48), the shift batch_prover.c:810-811 passes. */
#define DNAC_P2B_PREP_LOG_BLOWUP ((unsigned)2)

/* PIN-1 — the preprocessed root of the REFERENCE table, 4 Goldilocks lanes.
 * Value produced by the derivation above and LOCKED by the runtime KAT
 * test_mmcs_air_table T3 (constant vs generator, the shielded_domsep.h
 * practice). Not a magic number: re-derivable from this header alone. */
#define DNAC_P2B_PREP_ROOT_LANE0 UINT64_C(0xfcc92a4ebbd79fc4)
#define DNAC_P2B_PREP_ROOT_LANE1 UINT64_C(0xb0c4a93617190754)
#define DNAC_P2B_PREP_ROOT_LANE2 UINT64_C(0x3034244cd5325682)
#define DNAC_P2B_PREP_ROOT_LANE3 UINT64_C(0xa5c49b90e07500b9)

/** Brace-initializer form for a `uint64_t[4]`. */
#define DNAC_P2B_PREP_ROOT                                                    \
    {                                                                         \
        DNAC_P2B_PREP_ROOT_LANE0, DNAC_P2B_PREP_ROOT_LANE1,                   \
        DNAC_P2B_PREP_ROOT_LANE2, DNAC_P2B_PREP_ROOT_LANE3                    \
    }

/* ── API ─────────────────────────────────────────────────────────────────── */

/** The pinned reference config DNAC_P2B_PREP_ROOT is derived from. Never NULL. */
const dnac_p2b_table_cfg_t *dnac_p2b_ref_cfg(void);

/**
 * Padded row count for `cfg` (leaf + compress + final, rounded up to a power of
 * two, minimum DNAC_P2B_MIN_ROWS). Returns 0 for a NULL or out-of-range config
 * — callers treat 0 as "reject", there is no valid zero-height table.
 */
size_t dnac_p2b_table_rows(const dnac_p2b_table_cfg_t *cfg);

/**
 * Generate the table into `out` (row-major, rows x DNAC_P2B_TABLE_COLS cells).
 * Fail-close: a bad config or an `out_cells` smaller than the requirement
 * leaves `out` untouched and returns an error.
 */
dnac_p2b_table_status_t dnac_p2b_table_generate(
    const dnac_p2b_table_cfg_t *cfg, uint64_t *out, size_t out_cells);

/**
 * PIN-1 comparator, fail-close. Returns DNAC_P2B_TABLE_OK iff `lanes` equals
 * DNAC_P2B_PREP_ROOT lane for lane; DNAC_P2B_TABLE_ERR_ROOT_MISMATCH on any
 * difference and DNAC_P2B_TABLE_ERR_PARAM on NULL. This is the call the future
 * P2b verify entry makes on the DECODED preprocessed commitment before it
 * trusts a single gated constraint.
 */
dnac_p2b_table_status_t dnac_p2b_prep_root_check(const uint64_t lanes[4]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MMCS_AIR_TABLE_H */
