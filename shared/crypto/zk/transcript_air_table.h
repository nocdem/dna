/**
 * @file transcript_air_table.h
 * @brief s3a — the preprocessed OP-SCHEDULE table for the P2a transcript
 *        control-AIR: deterministic generator + static validator + the
 *        PIN-1-P2a root constant + its fail-close comparator.
 *
 * Build spec (authoritative): dnac/docs/plans/2026-07-30-composition-s3a-tair-
 * table-BUILDABLE.md (local-only) — §2 module, §3 AIR changes, §4 tests.
 * Precedent this file mirrors 1:1: `fri_air_table.{c,h}` (P2c) and
 * `mmcs_air_table.{c,h}` (P2b) — same structure, same pin story, same honest
 * label.
 *
 * ── WHY IT EXISTS (spec §1) ────────────────────────────────────────────────
 * `transcript_air.{c,h}` shipped with NO publics and NO preprocessed table: the
 * row TYPE was a MAIN-trace one-hot (`TAIR_SEL_*`) and `is_pow` a free main
 * column. P2a-i3 carried both forward as open obligations — the AIR bound the
 * SHAPE of a transcript run (transition legality, DS prefix, terminality) but
 * not WHICH ops the verifier issues, and nothing tied the observed/popped lane
 * to anything a consumer could read. This module closes the first half: the op
 * SCHEDULE of the pinned statement is deterministic, so it can be preprocessed.
 *
 * ── WHAT THE TABLE IS ──────────────────────────────────────────────────────
 * One row per row of the AIR's trace, in the schedule the native challenger
 * actually produces:
 *
 *     [ instance-start row ] [ one row per op ] ... [ padding = filler rows ]
 *     n_rows = next_pow2(n_start_rows + n_op_rows + 1)
 *
 * The `+1` is the mandatory terminal padding row: the AIR's last row gets no
 * transition constraints, so it MUST be a filler (transcript_air.c:444-460, the
 * i3 shipped-HIGH). The padding rule is byte-for-byte the one the shipped
 * honest trace builder already used (tests/test_transcript_air.c:473-475).
 *
 * Columns:
 *   [0, TAIR_NUM_SEL)   row-TYPE one-hot, index == the MAIN selector index
 *                       (TAIR_SEL_START / _OBS / _OBS_DUP / _SAMPLE /
 *                        _SAMPLE_DUP / _FILLER — transcript_air.h:91-97).
 *                       Padding rows are typed FILLER, not all-zero, because
 *                       CT-1 equates this block with the main selectors on
 *                       EVERY row.
 *   TAIR_TBL_COL_IS_POW is_pow modifier (PoW-check sampling rows only)
 *   [POS_OFF, +MAX_STEPS) GLOBAL op-step one-hot: `pos[k] = 1` iff this row is
 *                       op k of the script. ALL-ZERO on start and filler rows.
 *                       `k` is ALSO the row's public slot — see below.
 *
 * ⚠ Booleanity / exclusivity / one-hotness of a preprocessed cell is a
 * GENERATOR obligation, never a verify-path check: `batch_verify.c:722-727`
 * hands the decoded preprocessed window to `air_eval` RAW (the P2b round-1
 * A2-F5 finding, mmcs_air_table.h:26-30). Under PIN-1-P2a the generator is what
 * guarantees those properties, `dnac_tair_table_validate` is what checks the
 * generator, and the root KAT is what freezes the pair.
 *
 * ── WHY `pos` IS A ONE-HOT AND NOT A SCALAR ────────────────────────────────
 * A scalar index cannot select a public value inside an AIR; CT-3 and CT-4
 * require exactly that (`lane == publics[pub_slot]`, `bit[j] == publics[bit_off
 * + j]`). This is the FLEET 020 A2-F2 class ("a scalar would leave the publics
 * unread") and the resolution is the one P2c already took
 * (fri_air_table.h:86-106). `pub_slot == step`: the public block is DENSE in op
 * order, so the one-hot lane index IS the public index and no second column is
 * needed.
 *
 * ── PUBLIC-VALUE LAYOUT (the AIR and the composition bind to THESE) ────────
 *   [0, n_ops)                        payload lane of op k, in script order.
 *                                     For an observe row that is the OBSERVED
 *                                     value; for a sampling row the POPPED
 *                                     challenge.
 *   [n_ops, n_ops + total_bits)       exported index bits, ops in script order,
 *                                     op k contributing `ops[k].num_bits` lanes
 *                                     LSB-first at `dnac_tair_op_bit_off(k)`.
 *   total = `dnac_tair_num_publics()`; any other length fails closed.
 *
 * ── THE SCHEDULE IS A SIMULATION OF THE NATIVE CHALLENGER ──────────────────
 * Whether an observe is a plain `sel_obs` or the eager-duplex `sel_obs_dup`, and
 * whether a sample is `sel_sample` or `sel_sample_dup`, is NOT free: it is a
 * function of the challenger's `input_len` / `output_len` at that point. The
 * generator therefore SIMULATES `duplex_challenger.c` exactly (see
 * transcript_air_table.c `tair_sim_step`, whose every branch cites its native
 * line):
 *   - `dnac_duplex_init` zeroes the whole struct (duplex_challenger.c:91-94) —
 *     an instance-start row resets input_len = output_len = 0;
 *   - observe invalidates the output buffer (:108), appends at input_len (:110)
 *     and duplexes EAGERLY when the buffer reaches RATE (:112-114), which
 *     drains input_len to 0 and refills output_len to RATE (:73, :85-88);
 *   - sample duplexes iff `input_len > 0 || output_len == 0` (:127-129) and
 *     then pops ONE lane, LIFO (:131).
 * The state the simulation tracks is only the two LENGTHS — the values never
 * enter the schedule, which is what makes the table a pure function of the cfg
 * (determinism, below).
 *
 * ── THE FRI-TAIL REFERENCE SCRIPT ──────────────────────────────────────────
 * `dnac_tair_fri_build_script` expands the pinned FRI-tail cfg into the op
 * sequence, in the ORDER `fri_verify_impl` issues it (fri_verifier.c:693-737):
 *
 *   1. 4 x OBSERVE   the DS prefix — `dnac_duplex_init_default` absorbs the
 *                    four DNAC_DUPLEX_DS_PREFIX limbs FIRST, and the 4th fires
 *                    the single prefix permutation (duplex_challenger.c:96-103)
 *   2. 2 x SAMPLE    alpha = sample_fp2 (fri_verifier.c:694 ->
 *                    transcript.c:99-102 -> duplex_challenger.c:134-140: c0
 *                    then c1, TWO base pops)
 *   3. per round r < R (fri_verifier.c:700-708):
 *        4 x OBSERVE observe_digest = DNAC_P2M_DIGEST_LANES lane-by-lane base
 *                    observes (fri_verifier.c:702 -> transcript.c:84-92)
 *        check_witness(commit_pow_bits) (fri_verifier.c:703):
 *          bits == 0 -> ZERO OPS. `dnac_duplex_check_witness` returns true at
 *                    :153-155 BEFORE touching the sponge — read, not assumed.
 *          bits >  0 -> 1 x OBSERVE (the witness, :156) + 1 x SAMPLE with
 *                    is_pow = 1 (sample_bits -> ONE base pop, :146-148)
 *        2 x SAMPLE  beta = sample_fp2 (fri_verifier.c:707)
 *   4. 2*(1 << log_final_poly_len) x OBSERVE — the final poly, each coefficient
 *      an fp2 = two base observes (fri_verifier.c:711-713; num_final_poly ==
 *      1 << log_final_poly_len, fri_verifier.c:58-60 + the :112 shape check)
 *   5. R x OBSERVE   the per-round log_arity (fri_verifier.c:717-720; one per
 *                    commit-phase opening, and num_commit_phase_openings == R)
 *   6. check_witness(query_pow_bits) (fri_verifier.c:723) — same rule as 3
 *   7. per query q < num_queries: 1 x SAMPLE with num_bits = lgmh
 *      (fri_verifier.c:737, `extra_query_index_bits == 0` at :651)
 *
 * ⚠ SCOPE, honestly labelled: this is the FRI TAIL only. The transcript the
 * native `fri_verify_impl` receives has ALREADY absorbed the batch-STARK
 * priming (`dnac_batch_observe_main` etc.); those ops are NOT in this script and
 * the composition entry must prepend them (or pin a different script). What the
 * REF pin proves is that the mechanism works, not that this is the production
 * schedule.
 *
 * ── PIN-1-P2a: DNAC_P2A_PREP_ROOT ──────────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA: the prover
 * commits its own table (batch_prover.c:810-848) and `dnac_batch_verify` checks
 * only its PRESENCE against the declared matrix count (batch_verify.c:149).
 * Nothing in the tree compares that root to a pinned value, so an all-zero
 * table would satisfy every CT-* constraint vacuously. Upstream does not have
 * the hole because its preprocessed commitment lives VERIFIER-SIDE in
 * `CommonData` (Plonky3 11cc5849 batch-stark/src/common.rs:47-50) — the full
 * argument is at mmcs_air_table.h:73-100 and is not repeated here.
 *
 * DERIVATION (exactly the pipeline the SHIPPED prover runs on a preprocessed
 * matrix, batch_prover.c:810-848 with is_zk = 0, so the pin equals the root
 * that appears in a real proof):
 *
 *   table = dnac_tair_table_generate(REFERENCE SCRIPT)   // H x COLS, H = 64
 *   lde   = dnac_prover_coset_lde_bitrev(table, H, COLS,
 *               DNAC_P2A_PREP_LOG_BLOWUP, GOLDILOCKS_GENERATOR, .)
 *   root  = dnac_p2_mmcs_commit_mixed({lde}, {COLS}, {H << lb}, 1, ., NULL)
 *   DNAC_P2A_PREP_ROOT = root.lanes
 *
 * salt_elems = 0 is MANDATORY (salted+preprocessed is fail-closed at
 * batch_prover.c:608-611) and the recursion envelope is non-hiding by user lock.
 *
 * ⚠ HONEST LABEL — SAME CAVEAT AS DNAC_P2B_PREP_ROOT (mmcs_air_table.h:119-123)
 * AND DNAC_P2C_PREP_ROOT (fri_air_table.h:134-138): a MECHANISM pin against a
 * REFERENCE script, NOT the production circuit. The production constant RE-PINS
 * at the composition entry together with the production script.
 *
 * ⚠ OBL-P2a-T1 — the root binds the TABLE, never the verifier's separate SCRIPT
 * argument. Under collision resistance the root determines the row-type
 * sequence, the is_pow placement and n_ops (all table content); it does NOT
 * determine `ops[k].num_bits` (which shapes the public block) nor the script's
 * op KINDS beyond what the row types already reveal. A root-checked table paired
 * with a MISMATCHED script leaves the AIR's public-slot arithmetic aimed at the
 * wrong lanes. The COMPOSITION entry MUST pin the script INDEPENDENTLY of
 * DNAC_P2A_PREP_ROOT. (Same shape as OBL-4c, fri_air_table.h:140-148.)
 *
 * ⚠⚠ AND IT MUST PIN `pow_bits` (FLEET 032 red-verify #30, HIGH — the earlier
 * text named only `num_bits` and MISSED this). There is NO pow-width column in
 * the table: the columns are TYPE(6) + IS_POW(1) + POS(64) and the generator
 * branches on zero-vs-nonzero only (`dnac_tair_fri_num_ops`). So a script with
 * `commit/query_pow_bits = 16` and one with `= 8` — or `= 1` — produce a
 * BYTE-IDENTICAL table and the SAME root. The grinding width is what block D
 * turns into constraints ("the low `pow_bits` of the challenge are zero",
 * transcript_air.c PoW block), so an entry that pins only the root can be handed
 * a 1-bit script where 16 bits were intended and will constrain ONE low bit.
 * That is a soundness-relevant under-binding, not a shape nit. Same class as
 * the lb escape recorded at fri_oi_air_table.h (FLEET 029 #F8): a cfg scalar
 * with no table imprint must be pinned by the entry, independently.
 *
 * ⚠ OBL-P2a-T2 — PIN-2. This AIR reads only the LOCAL preprocessed window (no
 * CT-* form reads the next row's table cells), so `prep_next` is not
 * load-bearing for P2a. It must still be pinned at the composition entry,
 * because at THIS width `prep_next = 0` is rejected on SHAPE rather than
 * silently zeroed: `preprocessed_width > 64` returns DNAC_BV_ERR_SHAPE
 * (batch_verify.c:696-701), and TAIR_TBL_COLS is 71. Fail-closed harder
 * than the P2b path, but the composition must confirm the full prove/verify
 * pipeline handles a 71-wide preprocessed matrix.
 *
 * Determinism: every function here is a pure function of the SCRIPT scalars —
 * fixed-bound loops only, no allocation, no clock, no RNG, no iteration over
 * anything unordered. The challenger simulation reads only op kinds, never a
 * field value, so no wire data can enter the schedule.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TRANSCRIPT_AIR_TABLE_H
#define DNAC_ZK_TRANSCRIPT_AIR_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "duplex_challenger.h" /* DNAC_DUPLEX_RATE */

#ifdef __cplusplus
extern "C" {
#endif

/* ── fail-close bounds ───────────────────────────────────────────────────── */

/**
 * Upper bound on op steps, and therefore the width of the op-step one-hot.
 * 64 covers the REF FRI-tail script (31 ops) with room for the composition's
 * priming prefix. Same MECHANISM-pin caveat as MAIR_MAX_STEPS (mmcs_air.h:
 * 140-145) and DNAC_P2C_MAX_STEPS (fri_air_table.h:187-193): re-pinned with the
 * production script. A script that exceeds it fails CLOSED.
 */
#define TAIR_TBL_MAX_STEPS ((size_t)64)

/** Upper bound on instance-start rows in one script. */
#define TAIR_TBL_MAX_STARTS ((size_t)8)

/**
 * Upper bound on the PADDED row count. The extremal script (64 ops + 8 starts
 * = 72 scheduled rows, +1 terminal) pads to 128, so this is exactly reachable
 * and not a guess.
 */
#define TAIR_TBL_MAX_ROWS ((size_t)128)

/** Smallest committable table height (stark_prover.h:185: power of two, >= 2).
 *  Unreachable for any accepted script (>= 1 start + >= 1 op + >= 1 pad ⇒ 4),
 *  kept fail-close. */
#define TAIR_TBL_MIN_ROWS ((size_t)2)

/** Largest exported bit count per op. Mirrors TAIR_MAX_NUM_BITS
 *  (transcript_air.h:120-126), the AIR's own pinned `num_bits` bound; kept as
 *  its own macro so this header does not depend on the AIR, and static-asserted
 *  equal in the test so the two cannot drift. */
#define TAIR_TBL_MAX_OP_BITS ((size_t)32)

/* ── preprocessed column layout (the binding contract; transcript_air.c reads
 *    THESE) ─────────────────────────────────────────────────────────────────
 * The type block's indices ARE the main selector indices, so CT-1 is a plain
 * per-index equality with no permutation in between. The test static-asserts
 * TAIR_TBL_NUM_TYPES == TAIR_NUM_SEL. */

/** Row-type one-hot base. Index == TAIR_SEL_* (transcript_air.h:91-97). */
#define TAIR_TBL_COL_TYPE_OFF ((size_t)0)

/** Number of row types == TAIR_NUM_SEL. Declared here to keep this header
 *  independent of transcript_air.h (the include runs the OTHER way — the AIR
 *  includes this file, as mmcs_air.h includes mmcs_air_table.h); the equality
 *  is static-asserted in transcript_air.c, which sees both headers. */
#define TAIR_TBL_NUM_TYPES ((size_t)6)

/* Row-type indices. MUST equal TAIR_SEL_* (transcript_air.h:91-97) index for
 * index — CT-1 is a per-index equality against the MAIN selector block, so a
 * silent re-ordering would swap two archetypes. Static-asserted in
 * transcript_air.c (`tair_type_index_assert`). */
#define TAIR_TBL_TYPE_START      ((size_t)0)
#define TAIR_TBL_TYPE_OBS        ((size_t)1)
#define TAIR_TBL_TYPE_OBS_DUP    ((size_t)2)
#define TAIR_TBL_TYPE_SAMPLE     ((size_t)3)
#define TAIR_TBL_TYPE_SAMPLE_DUP ((size_t)4)
#define TAIR_TBL_TYPE_FILLER     ((size_t)5)

/** is_pow modifier (PoW-check sampling rows). */
#define TAIR_TBL_COL_IS_POW (TAIR_TBL_COL_TYPE_OFF + TAIR_TBL_NUM_TYPES)

/** Op-step one-hot base: [POS_OFF, POS_OFF + TAIR_TBL_MAX_STEPS). */
#define TAIR_TBL_COL_POS_OFF (TAIR_TBL_COL_IS_POW + 1)

/** Total preprocessed width == 71 (6 type + is_pow + 64 one-hot lanes). */
#define TAIR_TBL_COLS (TAIR_TBL_COL_POS_OFF + TAIR_TBL_MAX_STEPS)

/** type[t], t < TAIR_TBL_NUM_TYPES. */
static inline size_t tair_tbl_col_type(size_t t) {
    return TAIR_TBL_COL_TYPE_OFF + t;
}

/** pos[k], k < TAIR_TBL_MAX_STEPS — the GLOBAL op-step one-hot. */
static inline size_t tair_tbl_col_pos(size_t k) {
    return TAIR_TBL_COL_POS_OFF + k;
}

/* ── status / defect taxonomy ────────────────────────────────────────────── */

typedef enum {
    DNAC_TAIR_TABLE_OK = 0,
    DNAC_TAIR_TABLE_ERR_PARAM = -1,         /**< NULL / out-of-range script  */
    DNAC_TAIR_TABLE_ERR_CAPACITY = -2,      /**< out_cells < rows * COLS     */
    DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH = -3, /**< root != DNAC_P2A_PREP_ROOT  */
    DNAC_TAIR_TABLE_ERR_SCHEDULE = -4       /**< static validator rejected   */
} dnac_tair_table_status_t;

/**
 * Which schedule invariant the static validator tripped. Reported through the
 * optional out-parameter so a negative test can isolate ONE check per tamper
 * (the P2b N4/N11 / P2c N3 exact-isolation pattern).
 *
 * ⚠ The validator evaluates the checks in the ORDER LISTED and returns the
 * FIRST defect. The order is part of the contract.
 *
 * ⚠ TERMINAL precedes MACHINE deliberately: under the opposite order TERMINAL
 * is unreachable FOR THE INPUT CLASS THAT MATTERS. MACHINE's walk enforces
 * filler terminality mid-trace ("once padding starts it never stops"), so a
 * typed row at the very end of a trace that HAS filler rows trips MACHINE
 * first. With TERMINAL first, a typed LAST row trips TERMINAL and a typed row
 * after an EARLIER filler trips MACHINE — both reachable, both tested
 * (tests/test_transcript_air_table.c N3). Found by the N3 gate itself.
 *
 * ⚠ PRECISION (FLEET 032 red-verify #27): "DEAD" was an over-claim, corrected
 * here. A trace with ZERO filler rows passes MACHINE, so TERMINAL would still
 * fire under either order for that input (SCRIPT, which runs later, would also
 * catch it). The ordering is therefore about DIAGNOSTIC REACHABILITY of the
 * common case, not about a rule that can never fire; both orders reject the
 * same set of inputs. Stated exactly, because a validator's defect-ordering
 * contract is read as a soundness argument if it is written like one.
 */
typedef enum {
    DNAC_TAIR_DEFECT_NONE = 0,
    DNAC_TAIR_DEFECT_CANONICAL,      /**< a cell >= p                        */
    DNAC_TAIR_DEFECT_BOOLEAN,        /**< a cell not in {0,1}                */
    DNAC_TAIR_DEFECT_TYPE_EXCLUSIVE, /**< not exactly one row type set       */
    DNAC_TAIR_DEFECT_TERMINAL,       /**< last row is not a filler row       */
    DNAC_TAIR_DEFECT_MACHINE,        /**< the type sequence is not a legal
                                          run of the native challenger       */
    DNAC_TAIR_DEFECT_SCRIPT,         /**< the run does not match the script
                                          (op count / kind / start places)   */
    DNAC_TAIR_DEFECT_POS_ONEHOT,     /**< op-step one-hot missing/extra/moved */
    DNAC_TAIR_DEFECT_ISPOW           /**< is_pow placement wrong             */
} dnac_tair_table_defect_t;

/* ── the script (the schedule authority) ─────────────────────────────────── */

typedef enum {
    DNAC_TAIR_OP_OBSERVE = 0, /**< dnac_duplex_observe_fp, :105-115 */
    DNAC_TAIR_OP_SAMPLE = 1   /**< dnac_duplex_sample_fp,  :124-132 */
} dnac_tair_op_kind_t;

/**
 * ONE transcript op. A `check_witness(bits > 0)` is TWO ops — an OBSERVE of the
 * witness then a SAMPLE with `is_pow = 1` (duplex_challenger.c:156-157) — and a
 * `check_witness(0)` is ZERO ops (:153-155). Callers expand it; this struct has
 * no PoW op kind, deliberately, because the AIR has no PoW row archetype either
 * (transcript_air.c:153-157: `is_pow` is a MODIFIER on a sampling row).
 */
typedef struct {
    dnac_tair_op_kind_t kind;
    int    is_pow;   /**< SAMPLE only; 1 iff this pop is the PoW check       */
    size_t pow_bits; /**< SAMPLE && is_pow: the low bits the AIR forces to
                          zero. MUST equal the AIR cfg's `pow_bits`; the AIR
                          fail-closes otherwise. 0 elsewhere.                */
    size_t num_bits; /**< SAMPLE: exported index bits, 0 .. MAX_OP_BITS.
                          0 = this op exports no bits. 0 for OBSERVE.        */
} dnac_tair_op_t;

/**
 * The PINNED op script one table instance is generated from. Nothing here may
 * ever come off the wire.
 *
 * `instance_starts` are OP INDICES: a start row is emitted immediately BEFORE
 * the named op. They must be strictly ascending, all < n_ops, and the first
 * MUST be 0 — trace row 0 is a `sel_start` row by the AIR's own boundary
 * constraint (transcript_air.c:166-167).
 */
typedef struct {
    const dnac_tair_op_t *ops;
    size_t                n_ops;           /**< 1 .. TAIR_TBL_MAX_STEPS     */
    const size_t         *instance_starts; /**< [n_starts], ascending, [0]=0 */
    size_t                n_starts;        /**< 1 .. TAIR_TBL_MAX_STARTS    */
} dnac_tair_script_t;

/** Decoded form of ONE table row — the single source the cell writer, the
 *  validator and the tests all read, so a "row means X" claim cannot drift from
 *  the cells. */
typedef struct {
    size_t type;     /**< TAIR_SEL_* row type                                */
    size_t step;     /**< op index == one-hot position == public slot;
                          SIZE_MAX on start / filler rows                    */
    int    is_pow;
    size_t bit_off;  /**< public index of exported bit 0; SIZE_MAX if none   */
    size_t num_bits; /**< exported bits on this row; 0 if none               */
} dnac_tair_row_t;

/* ── the FRI-tail reference cfg ──────────────────────────────────────────── */

/**
 * The FRI-tail scalars the reference script is expanded from. Every field is a
 * consensus/cfg scalar. See the header preamble for the op sequence and its
 * `fri_verifier.c` line-by-line grounding.
 */
typedef struct {
    size_t R;                  /**< commit-phase rounds (fri_verifier.c:700) */
    size_t log_final_poly_len; /**< num_final_poly == 1 << this (:58-60)     */
    size_t num_queries;        /**< query index samples (:736-737)           */
    size_t lgmh;               /**< bits per query index sample (:737)       */
    size_t commit_pow_bits;    /**< per-round check_witness bits (:703)      */
    size_t query_pow_bits;     /**< the single query check_witness (:723)    */
} dnac_tair_fri_cfg_t;

/* REFERENCE CONFIG (pinned, spec §2): R = 3, lfpl = 0, Q = 2, lgmh = 5,
 * commit/query PoW 0/0.
 *
 * Deliberately SMALL — this is a mechanism pin, and a small script keeps the
 * table inside one 64-row power of two while still exercising every op form:
 * multi-round digest observes, fp2 pops (alpha + betas), the final-poly and
 * log_arity observes, and TWO bit-exporting query samples. PoW is 0/0 so the
 * ZERO-OP `check_witness` branch (duplex_challenger.c:153-155) is the one on the
 * reference path; the non-zero branch is covered by the `pow_nonzero` oracle
 * scenario in tests/test_transcript_air.c. */
#define DNAC_P2A_REF_R                  ((size_t)3)
#define DNAC_P2A_REF_LOG_FINAL_POLY_LEN ((size_t)0)
#define DNAC_P2A_REF_NUM_QUERIES        ((size_t)2)
#define DNAC_P2A_REF_LGMH               ((size_t)5)
#define DNAC_P2A_REF_COMMIT_POW_BITS    ((size_t)0)
#define DNAC_P2A_REF_QUERY_POW_BITS     ((size_t)0)

/* Derived, and re-derived by the test from the accessors rather than trusted:
 *   ops  = 4 (DS) + 2 (alpha) + R*(4 + 0 + 2) + 2*(1<<lfpl) + R + 0 + Q
 *        = 4 + 2 + 18 + 2 + 3 + 2 = 31
 *   rows = next_pow2(1 start + 31 ops + 1 terminal) = 64
 *   publics = 31 payload + Q*lgmh = 31 + 10 = 41 */
#define DNAC_P2A_REF_OPS     ((size_t)31)
#define DNAC_P2A_REF_ROWS    ((size_t)64)
#define DNAC_P2A_REF_PUBLICS ((size_t)41)

/* Coset-LDE blowup the pin is derived at. Mirrors the shipped consensus FRI
 * blowup DNAC_SHIELDED_FRI_LOG_BLOWUP == 2 — the recursion envelope. Kept as its
 * OWN macro so this module does not drag the FRI-verifier header chain in; the
 * test static-asserts the two are equal, so they cannot drift. The coset shift
 * is GOLDILOCKS_GENERATOR == 7, the shift batch_prover.c:833-834 passes. */
#define DNAC_P2A_PREP_LOG_BLOWUP ((unsigned)2)

/* PIN-1-P2a — the preprocessed root of the REFERENCE table, 4 Goldilocks lanes.
 *
 * PLACEHOLDER {0,0,0,0}: filled by the ORCHESTRATOR from
 * `build/test_transcript_air_table --print-roots`, whose output is pasted
 * verbatim. While unfilled the KAT in that test FAILS BY DESIGN and the
 * comparator rejects EVERYTHING (including an all-zero root — a placeholder pin
 * that accepted zero would be strictly worse than no pin). Do NOT hand-edit:
 * re-derive via --print-roots (the shielded_domsep.h practice). */
#define DNAC_P2A_PREP_ROOT_LANE0 UINT64_C(0xb689a4e626921aa3)
#define DNAC_P2A_PREP_ROOT_LANE1 UINT64_C(0x9a08256aa5794c1d)
#define DNAC_P2A_PREP_ROOT_LANE2 UINT64_C(0xdb86740992ed646d)
#define DNAC_P2A_PREP_ROOT_LANE3 UINT64_C(0x443190c5257d97ea)

/** Brace-initializer form for a `uint64_t[4]`. */
#define DNAC_P2A_PREP_ROOT                                                    \
    {                                                                         \
        DNAC_P2A_PREP_ROOT_LANE0, DNAC_P2A_PREP_ROOT_LANE1,                   \
        DNAC_P2A_PREP_ROOT_LANE2, DNAC_P2A_PREP_ROOT_LANE3                    \
    }

/** 1 while the pin above is still the unfilled placeholder. */
#define DNAC_P2A_PREP_ROOT_UNFILLED                                           \
    (DNAC_P2A_PREP_ROOT_LANE0 == 0 && DNAC_P2A_PREP_ROOT_LANE1 == 0 &&        \
     DNAC_P2A_PREP_ROOT_LANE2 == 0 && DNAC_P2A_PREP_ROOT_LANE3 == 0)

/* ── API ─────────────────────────────────────────────────────────────────── */

/** The pinned reference FRI-tail cfg DNAC_P2A_PREP_ROOT is derived from.
 *  Never NULL. */
const dnac_tair_fri_cfg_t *dnac_tair_ref_fri_cfg(void);

/**
 * Number of ops the FRI-tail `cfg` expands to, or 0 for a rejected cfg. Pure
 * function of the cfg scalars; the expansion itself is
 * `dnac_tair_fri_build_script`.
 */
size_t dnac_tair_fri_num_ops(const dnac_tair_fri_cfg_t *cfg);

/**
 * Expand a FRI-tail cfg into an op script.
 *
 * @param cfg        the FRI-tail scalars.
 * @param ops_out    caller-owned buffer, `ops_cap` entries.
 * @param ops_cap    must be >= `dnac_tair_fri_num_ops(cfg)`.
 * @param starts_out caller-owned buffer, at least 1 entry (one instance).
 * @param out        filled to point AT `ops_out` / `starts_out` on success;
 *                   UNTOUCHED on failure.
 * @return DNAC_TAIR_TABLE_OK, or ERR_PARAM / ERR_CAPACITY (fail-close).
 */
dnac_tair_table_status_t dnac_tair_fri_build_script(
    const dnac_tair_fri_cfg_t *cfg, dnac_tair_op_t *ops_out, size_t ops_cap,
    size_t *starts_out, dnac_tair_script_t *out);

/**
 * The REFERENCE script (the pinned FRI-tail cfg, expanded). Writes into the
 * caller's buffers exactly like `dnac_tair_fri_build_script`; `ops_cap` must be
 * >= DNAC_P2A_REF_OPS.
 */
dnac_tair_table_status_t dnac_tair_ref_script(dnac_tair_op_t *ops_out,
                                              size_t ops_cap,
                                              size_t *starts_out,
                                              dnac_tair_script_t *out);

/** Scheduled (non-padding) rows == n_starts + n_ops. 0 on a rejected script. */
size_t dnac_tair_sched_rows(const dnac_tair_script_t *s);

/**
 * Padded row count: next_pow2(sched + 1), minimum TAIR_TBL_MIN_ROWS. The `+1`
 * is the mandatory terminal filler row (transcript_air.c:444-460). Returns 0
 * for a NULL or out-of-range script — callers treat 0 as "reject". This is the
 * value the AIR's schedule-conformance gate compares `n_rows` against.
 */
size_t dnac_tair_table_rows(const dnac_tair_script_t *s);

/** Total exported bits == Σ ops[k].num_bits. 0 is a legal answer (no op
 *  exports bits); `dnac_tair_num_publics` is what a caller checks for reject. */
size_t dnac_tair_total_bits(const dnac_tair_script_t *s);

/** Required public-value count == n_ops + total_bits. 0 on a rejected script. */
size_t dnac_tair_num_publics(const dnac_tair_script_t *s);

/**
 * Public index of op `k`'s exported bit 0, or SIZE_MAX when op k exports none
 * (or the script / index is out of range). Bits are laid out in op order after
 * the payload block.
 */
size_t dnac_tair_op_bit_off(const dnac_tair_script_t *s, size_t k);

/**
 * The `pow_bits` every `is_pow` op in the script agrees on, written to
 * `*out_bits`; 0 when the script has NO PoW op. Returns DNAC_TAIR_TABLE_OK on
 * agreement and ERR_PARAM on a rejected script or on DISAGREEING PoW ops — the
 * AIR carries ONE `cfg->pow_bits` (transcript_air.c:204-205), so two different
 * grinding widths in one instance are out of contract and fail closed rather
 * than silently binding the first.
 */
dnac_tair_table_status_t dnac_tair_script_pow_bits(const dnac_tair_script_t *s,
                                                   size_t *out_bits);

/**
 * Decode row `row` of `s`'s schedule. Pure function of (s, row); the cell
 * writer is built on it, so the record and the cells cannot disagree.
 * Fail-close on a bad script or `row >= dnac_tair_table_rows(s)`.
 */
dnac_tair_table_status_t dnac_tair_table_row(const dnac_tair_script_t *s,
                                             size_t row, dnac_tair_row_t *out);

/**
 * Generate the table into `out` (row-major, rows x TAIR_TBL_COLS cells).
 * Fail-close: a bad script or an `out_cells` smaller than the requirement
 * leaves `out` untouched and returns an error.
 */
dnac_tair_table_status_t dnac_tair_table_generate(const dnac_tair_script_t *s,
                                                  uint64_t *out,
                                                  size_t out_cells);

/**
 * STATIC VALIDATOR — re-checks every schedule invariant the AIR relies on,
 * against the CELLS, structurally (it does NOT memcmp against the generator,
 * which would be circular). Under PIN-1-P2a nothing on the verify path
 * re-checks a preprocessed cell, so this validator plus the root pin are the
 * whole guarantee.
 *
 * Checks, in evaluation order (see dnac_tair_table_defect_t):
 *   1 canonicality  every cell < p
 *   2 booleanity    every cell in {0,1} (this table has no field literals)
 *   3 exclusivity   exactly one row type per row
 *   4 terminal      the LAST row is a filler row (the AIR's final row gets NO
 *                   transition constraints — transcript_air.c:444-460)
 *   5 machine       the type sequence is a LEGAL RUN of the native challenger:
 *                   re-simulating `input_len`/`output_len` from the cells,
 *                   every `_OBS` vs `_OBS_DUP` and `_SAMPLE` vs `_SAMPLE_DUP`
 *                   label is the one duplex_challenger.c would produce, filler
 *                   rows are terminal, and start rows reset
 *   6 script        the run matches the SCRIPT: same op count, same op kinds in
 *                   order, start rows exactly before the named op indices
 *   7 pos one-hot   op row k carries pos[k] = 1 and nothing else; start and
 *                   filler rows carry an all-zero one-hot
 *   8 is_pow        set exactly on the script's `is_pow` sampling rows
 *
 * @param out_defect optional; set to the FIRST defect found (or
 *                   DNAC_TAIR_DEFECT_NONE on success). May be NULL.
 * @return DNAC_TAIR_TABLE_OK, DNAC_TAIR_TABLE_ERR_PARAM (NULL / bad script /
 *         wrong `rows`) or DNAC_TAIR_TABLE_ERR_SCHEDULE.
 */
dnac_tair_table_status_t dnac_tair_table_validate(
    const dnac_tair_script_t *s, const uint64_t *cells, size_t rows,
    dnac_tair_table_defect_t *out_defect);

/**
 * PIN-1-P2a comparator, fail-close. Returns DNAC_TAIR_TABLE_OK iff `lanes`
 * equals DNAC_P2A_PREP_ROOT lane for lane; ERR_ROOT_MISMATCH on any difference
 * and ERR_PARAM on NULL. The pin lives CALLER-side exactly like the
 * DNAC_SHIELDED_* constants — `dnac_batch_verify`'s signature does not change.
 * This is the call the future P2a verify entry makes on the DECODED
 * preprocessed commitment before it trusts a single gated constraint.
 *
 * ⚠ While DNAC_P2A_PREP_ROOT_UNFILLED this ALWAYS returns ERR_ROOT_MISMATCH,
 * the all-zero root included.
 */
dnac_tair_table_status_t dnac_tair_prep_root_check(const uint64_t lanes[4]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_TRANSCRIPT_AIR_TABLE_H */
