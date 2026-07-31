/**
 * @file fri_statement.c
 * @brief Composition s1b + s1c + s2 + s3b + MULTI-QUERY + COMMIT-ROUND +
 *        INPUT-BATCH REPLICATION — the FRI-verify statement entry (see
 *        fri_statement.h for the pinned cfg derivation, the instance map, the
 *        shared/per-query, per-round and per-batch splits that discharge
 *        OBL-P2c-2 and HONEST LABELS 2 and 3, the transcript digest alias that
 *        closes HONEST LABEL 6, the seams still declared, and the one-pin
 *        correction).
 *
 * This file CONSTRUCTS and REJECTS. It contains no constraint, no column and no
 * field arithmetic beyond a canonicality comparison: every constraint it relies
 * on is emitted by the s1a fold modules it binds, and every structural check
 * beyond the seven steps is `dnac_batch_verify`'s.
 *
 * ⚠ NO LOGGING, deliberately. Root CLAUDE.md mandates the QGP_LOG_* macros for
 * C code, but `crypto/utils/qgp_log.c` is a translation unit that has to be
 * LINKED, and no module in shared/crypto/zk links it — the whole subtree builds
 * from its own Makefile against qgp_sha3.c + libcrypto only, and reports every
 * failure through a status enum instead (batch_verify.c, fri_verifier.c and
 * mmcs_air.c contain zero QGP_LOG calls between them). Adding the macros here
 * would force qgp_log.c onto every recipe that links this file. The status codes
 * below discriminate each failing step, which is the subtree's convention.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_statement.h"

#include <string.h>

#include "field_goldilocks.h" /* GOLDILOCKS_P / gold_fp_from_u64 / _to_u64 */

/* ==========================================================================
 * The pinned cfgs. Every scalar comes from fri_statement.h — nothing here is
 * read from a proof (OBL-P2c-1) and nothing is derived from the preprocessed
 * root (OBL-4c / OBL-4-MMIX).
 * ======================================================================== */

/* ONE cfg per INPUT BATCH. Only the opened WIDTH differs — the matrix count,
 * the heights, the depth and the salt are the batch-independent shape of this
 * pin (fri_statement.h's cfg derivation, MEASURED per batch by T-REF). Written
 * as an explicit per-batch initializer rather than a loop-filled array so the
 * cfgs keep static storage AND remain `const`, which is what lets the accessors
 * hand out pointers with no initialisation order to reason about — the same
 * shape the per-round mmcs list below has.
 *
 * ⚠ The heights array is SHARED by all B cfgs. That is not a shortcut, but the
 * reason is narrower than "one matrix per instance per round": the MAIN and
 * PREPROCESSED rounds do carry one matrix per inner instance at that instance's
 * `log_ext_degree` (batch_verify.c:549 / :587), while the QUOTIENT round carries
 * one matrix per CHUNK (:567-573). The two coincide here only because this pin
 * has `num_quotient_chunks == 1`. It fails CLOSED if that ever changes —
 * `p2s_mmix_matrix_at_height` rejects a height that names anything other than
 * exactly one matrix — so a chunkier pin gets an ERR_CFG, not a wrong binding.
 * The WIDTHS are what the rounds disagree on, and those are per batch. */
static const size_t P2S_MMIX_HEIGHTS[DNAC_P2S_MMIX_NUM_MATRICES] = {
    (size_t)1u << DNAC_P2S_MMIX_LH0, (size_t)1u << DNAC_P2S_MMIX_LH1
};
static const size_t P2S_MMIX_WIDTHS_MAIN[DNAC_P2S_MMIX_NUM_MATRICES] = {
    DNAC_P2S_MMIX_BW0, DNAC_P2S_MMIX_BW0
};
static const size_t P2S_MMIX_WIDTHS_QUOT[DNAC_P2S_MMIX_NUM_MATRICES] = {
    DNAC_P2S_MMIX_BW1, DNAC_P2S_MMIX_BW1
};
static const size_t P2S_MMIX_WIDTHS_PREP[DNAC_P2S_MMIX_NUM_MATRICES] = {
    DNAC_P2S_MMIX_BW2, DNAC_P2S_MMIX_BW2
};
static const dnac_p2c_mmix_table_cfg_t
    P2S_MMIX_CFG[DNAC_P2S_OI_NUM_BATCHES] = {
        { DNAC_P2S_MMIX_NUM_MATRICES, P2S_MMIX_WIDTHS_MAIN, P2S_MMIX_HEIGHTS,
          DNAC_P2S_MMIX_DEPTH, DNAC_P2S_MMIX_SALT_ELEMS },
        { DNAC_P2S_MMIX_NUM_MATRICES, P2S_MMIX_WIDTHS_QUOT, P2S_MMIX_HEIGHTS,
          DNAC_P2S_MMIX_DEPTH, DNAC_P2S_MMIX_SALT_ELEMS },
        { DNAC_P2S_MMIX_NUM_MATRICES, P2S_MMIX_WIDTHS_PREP, P2S_MMIX_HEIGHTS,
          DNAC_P2S_MMIX_DEPTH, DNAC_P2S_MMIX_SALT_ELEMS }
    };

/* The pinned batch count is what the initializer above — and the B-term sum
 * DNAC_P2S_MMIX_ALL_OPENED, and the three-way ternaries DNAC_P2S_MMIX_BW /
 * DNAC_P2S_OI_BNP / _BNC — are written out for. If B ever moves, this stops the
 * build instead of silently leaving a batch's cfg zeroed or a ternary chain
 * folding every batch past 1 onto the preprocessed one. */
typedef char p2s_mmix_batch_list_matches_b_assert
    [(DNAC_P2S_OI_NUM_BATCHES == 3) ? 1 : -1];

/* The "no slot" sentinel must not decode as a batch: DNAC_P2S_SLOT_IS_MMIX is
 * a bare `< SLOT_MMCS0` test, so this is what makes `dnac_p2s_inst_batch`'s
 * out-of-range and transcript answers correct rather than merely likely. */
typedef char p2s_slot_sentinel_is_not_a_batch_assert
    [(!DNAC_P2S_SLOT_IS_MMIX(DNAC_P2S_SLOTS)) ? 1 : -1];

/* Per batch, the two descriptions of one block must agree: BNP(b) points times
 * BNC(b) columns IS the acc-row count the uniform group descriptor gives every
 * batch (HONEST LABEL 5). Step 3a re-checks it at runtime; this names the
 * failure at build time. */
typedef char p2s_oi_batch0_split_assert
    [(DNAC_P2S_OI_BNP0 * DNAC_P2S_OI_BNC0 == DNAC_P2S_OI_ACC_PER_BATCH) ? 1
                                                                       : -1];
typedef char p2s_oi_batch1_split_assert
    [(DNAC_P2S_OI_BNP1 * DNAC_P2S_OI_BNC1 == DNAC_P2S_OI_ACC_PER_BATCH) ? 1
                                                                       : -1];
typedef char p2s_oi_batch2_split_assert
    [(DNAC_P2S_OI_BNP2 * DNAC_P2S_OI_BNC2 == DNAC_P2S_OI_ACC_PER_BATCH) ? 1
                                                                       : -1];

/* And the two descriptions of one batch's opened row must agree: the MMCS leaf
 * width and the accumulation loop's column count are the SAME quantity by the
 * native's own rule (fri_verifier.c:333 rejects a batch whose opened row length
 * differs from its claimed-eval count; :469-471 indexes the row BY that
 * ordinal). Pinned as two constants, compared here — a mismatch would make the
 * p_x alias read a column the opened row does not have. */
typedef char p2s_mmix_bw0_is_bnc0_assert
    [(DNAC_P2S_MMIX_BW0 == DNAC_P2S_OI_BNC0) ? 1 : -1];
typedef char p2s_mmix_bw1_is_bnc1_assert
    [(DNAC_P2S_MMIX_BW1 == DNAC_P2S_OI_BNC1) ? 1 : -1];
typedef char p2s_mmix_bw2_is_bnc2_assert
    [(DNAC_P2S_MMIX_BW2 == DNAC_P2S_OI_BNC2) ? 1 : -1];

/* ONE cfg per commit round. Only the DEPTH differs — the leaf width is the
 * arity's, which every round shares (fri_statement.h). Written as an explicit
 * per-round initializer rather than a loop-filled array so the cfgs keep static
 * storage AND remain `const`, which is what lets the accessors hand out
 * pointers with no initialisation order to reason about.
 *
 * ⚠ The initializer list is DNAC_P2S_FRI_R long by construction: the assert
 * below compares the last round's depth against the walk's closing height, and
 * a shorter list would zero-fill a depth (which every table module rejects) —
 * but the assert names the failure instead of leaving it to a runtime reject. */
static const size_t P2S_MMCS_WIDTHS[1] = { DNAC_P2S_MMCS_TOTAL_WIDTH };
static const dnac_p2b_table_cfg_t P2S_MMCS_CFG[DNAC_P2S_FRI_R] = {
    { 1, P2S_MMCS_WIDTHS, DNAC_P2S_MMCS_DEPTH(0) },
    { 1, P2S_MMCS_WIDTHS, DNAC_P2S_MMCS_DEPTH(1) },
    { 1, P2S_MMCS_WIDTHS, DNAC_P2S_MMCS_DEPTH(2) }
};

/* The pinned round count is what the initializer above is written out for; if R
 * ever moves, this stops the build instead of silently leaving a round's cfg
 * zeroed (num_matrices 0 / depth 0, which p2b_total_width rejects at runtime —
 * a reject, but one that names nothing). */
typedef char p2s_mmcs_cfg_list_matches_r_assert
    [(DNAC_P2S_FRI_R == 3) ? 1 : -1];

/* The walk closes at log_final_height (fri_verifier.c:609-611), so the LAST
 * round's folded height must BE that height. Equivalent to "R rounds of
 * log_arity each consume exactly lgmh - lb - lfpl levels", i.e. the
 * arity-equality assumption of HONEST LABEL 4 stated as a build gate. */
typedef char p2s_mmcs_last_depth_is_final_height_assert
    [(DNAC_P2S_MMCS_DEPTH(DNAC_P2S_FRI_R - 1) ==
      DNAC_P2S_LOG_BLOWUP + DNAC_P2S_LFPL)
         ? 1
         : -1];

static const size_t P2S_FRI_ROLLIN[DNAC_P2S_NUM_ROLLIN] = { DNAC_P2S_ROLLIN_0 };
static const dnac_p2c_table_cfg_t P2S_FRI_CFG = {
    DNAC_P2S_LGMH, DNAC_P2S_LOG_BLOWUP, DNAC_P2S_LFPL, DNAC_P2S_MAX_LOG_ARITY,
    DNAC_P2S_NUM_ROLLIN, P2S_FRI_ROLLIN, DNAC_P2S_NUM_QUERIES
};

/* oi: the height groups, STRICTLY DESCENDING, heights[0] == lgmh. The (m,p,c)
 * split is the labelled factorization documented in fri_statement.h; only the
 * product and the group boundary are load-bearing. */
static const dnac_p2c_oi_height_desc_t
    P2S_OI_HEIGHTS[DNAC_P2S_OI_NUM_HEIGHTS] = {
        { DNAC_P2S_OI_H0, DNAC_P2S_OI_NUM_BATCHES, DNAC_P2S_OI_NUM_MATRICES,
          DNAC_P2S_OI_NUM_POINTS, DNAC_P2S_OI_NUM_COLUMNS },
        { DNAC_P2S_OI_H1, DNAC_P2S_OI_NUM_BATCHES, DNAC_P2S_OI_NUM_MATRICES,
          DNAC_P2S_OI_NUM_POINTS, DNAC_P2S_OI_NUM_COLUMNS }
    };
static const dnac_p2c_oi_table_cfg_t P2S_OI_CFG = {
    DNAC_P2S_LGMH, DNAC_P2S_LOG_BLOWUP, DNAC_P2S_OI_NUM_HEIGHTS,
    P2S_OI_HEIGHTS, DNAC_P2S_NUM_QUERIES
};

/* The OUTER FRI parameters (MECHANISM pin — fri_statement.h's production
 * caveat). Shaped after the fixture family these cfgs were derived from:
 * binary folding, no final-poly coefficients, no grinding. The two PoW widths
 * come from the header macros, NOT from literals here: the transcript script
 * and the `pow_bits` pin read the same two constants, so the params and the
 * script cannot drift apart (s3b). */
static const dnac_fri_params_t P2S_FRI_PARAMS = {
    DNAC_P2S_LOG_BLOWUP,      /* log_blowup                */
    DNAC_P2S_LFPL,            /* log_final_poly_len        */
    DNAC_P2S_MAX_LOG_ARITY,   /* max_log_arity             */
    DNAC_P2S_NUM_QUERIES,     /* num_queries               */
    DNAC_P2S_COMMIT_POW_BITS, /* commit_proof_of_work_bits */
    DNAC_P2S_QUERY_POW_BITS   /* query_proof_of_work_bits  */
};

/* ── tair (s3b): the FRI-tail cfg is DERIVED from the statement constants, and
 * the SCRIPT is expanded from it by the shipped builder — never written out
 * here. `dnac_tair_ref_script` expands the SAME function, which is why the test
 * can compare the two op for op. */
static const dnac_tair_fri_cfg_t P2S_TAIR_FRI_CFG = {
    DNAC_P2S_FRI_R,          /* R                  */
    DNAC_P2S_LFPL,           /* log_final_poly_len */
    DNAC_P2S_NUM_QUERIES,    /* num_queries        */
    DNAC_P2S_LGMH,           /* lgmh               */
    DNAC_P2S_COMMIT_POW_BITS,
    DNAC_P2S_QUERY_POW_BITS
};

/** The AIR's own cfg. `pow_bits` is the ONE width the AIR can carry
 *  (transcript_air.c:204-205); which of the two FRI widths that is — and that
 *  they do not conflict — is decided by `dnac_p2s_check_tair_pow_pin`. */
static const dnac_tair_config_t P2S_TAIR_CFG = {
    DNAC_P2S_COMMIT_POW_BITS != 0 ? DNAC_P2S_COMMIT_POW_BITS
                                  : DNAC_P2S_QUERY_POW_BITS
};

const dnac_p2c_mmix_table_cfg_t *dnac_p2s_mmix_cfg(size_t batch)
{
    if (batch >= DNAC_P2S_OI_NUM_BATCHES) return NULL;
    return &P2S_MMIX_CFG[batch];
}

size_t dnac_p2s_mmix_opened_off(size_t batch)
{
    size_t off = 0;
    if (batch >= DNAC_P2S_OI_NUM_BATCHES) return (size_t)-1;
    for (size_t b = 0; b < batch; b++) {
        off += DNAC_P2S_MMIX_TOTAL_OPENED(b);
    }
    return off;
}

const dnac_p2b_table_cfg_t *dnac_p2s_mmcs_cfg(size_t round)
{
    if (round >= DNAC_P2S_FRI_R) return NULL;
    return &P2S_MMCS_CFG[round];
}
const dnac_p2c_table_cfg_t      *dnac_p2s_fri_cfg(void)  { return &P2S_FRI_CFG;  }
const dnac_p2c_oi_table_cfg_t   *dnac_p2s_oi_cfg(void)   { return &P2S_OI_CFG;   }
const dnac_fri_params_t         *dnac_p2s_fri_params(void) { return &P2S_FRI_PARAMS; }
const dnac_tair_config_t        *dnac_p2s_tair_cfg(void) { return &P2S_TAIR_CFG; }
const dnac_tair_fri_cfg_t *dnac_p2s_tair_fri_cfg(void)
{
    return &P2S_TAIR_FRI_CFG;
}

/* ── The pinned transcript script ────────────────────────────────────────────
 * Expanded ONCE into module-static storage by the shipped builder. Pure
 * function of compile-time constants: no wire data, no clock, no RNG, so every
 * node expands the identical script (the determinism claim). Single-threaded,
 * like every other binding this entry makes.
 *
 * `ops` is sized by the header's op-count arithmetic; the builder is ALSO asked
 * for its own count and the two are compared, so a drift between the macro and
 * `dnac_tair_fri_num_ops` fails closed instead of overflowing the buffer. */
static dnac_tair_op_t     P2S_TAIR_OPS[DNAC_P2S_TAIR_NUM_OPS];
static size_t             P2S_TAIR_STARTS[1];
static dnac_tair_script_t P2S_TAIR_SCRIPT;
static int                P2S_TAIR_SCRIPT_STATE; /* 0 unbuilt, 1 ok, -1 failed */

const dnac_tair_script_t *dnac_p2s_tair_script(void)
{
    if (P2S_TAIR_SCRIPT_STATE == 0) {
        P2S_TAIR_SCRIPT_STATE = -1;
        if (dnac_tair_fri_num_ops(&P2S_TAIR_FRI_CFG) == DNAC_P2S_TAIR_NUM_OPS &&
            dnac_tair_fri_build_script(&P2S_TAIR_FRI_CFG, P2S_TAIR_OPS,
                                       DNAC_P2S_TAIR_NUM_OPS, P2S_TAIR_STARTS,
                                       &P2S_TAIR_SCRIPT) ==
                DNAC_TAIR_TABLE_OK) {
            P2S_TAIR_SCRIPT_STATE = 1;
        }
    }
    return (P2S_TAIR_SCRIPT_STATE == 1) ? &P2S_TAIR_SCRIPT : NULL;
}

dnac_p2s_status_t dnac_p2s_check_tair_pow_pin(const dnac_tair_script_t *s)
{
    size_t want = 0, got = 0;

    if (s == NULL) return DNAC_P2S_ERR_NULL;

    /* The AIR carries ONE `pow_bits`, so two DIFFERENT non-zero FRI widths are
     * out of contract for this composition — reject rather than silently bind
     * whichever the script happened to emit first. */
    if (DNAC_P2S_COMMIT_POW_BITS != 0) want = DNAC_P2S_COMMIT_POW_BITS;
    if (DNAC_P2S_QUERY_POW_BITS != 0) {
        if (want != 0 && want != DNAC_P2S_QUERY_POW_BITS) {
            return DNAC_P2S_ERR_CFG;
        }
        want = DNAC_P2S_QUERY_POW_BITS;
    }

    /* `dnac_tair_script_pow_bits` itself fails closed when the script's own PoW
     * ops disagree (transcript_air_table.h:520-528). */
    if (dnac_tair_script_pow_bits(s, &got) != DNAC_TAIR_TABLE_OK) {
        return DNAC_P2S_ERR_CFG;
    }
    if (got != want) return DNAC_P2S_ERR_CFG;
    /* And the width the AIR will actually constrain is that same number. */
    if (P2S_TAIR_CFG.pow_bits != want) return DNAC_P2S_ERR_CFG;
    return DNAC_P2S_OK;
}

/* ==========================================================================
 * Small derivations
 * ======================================================================== */

/** log2 of an EXACT power of two, else SIZE_MAX. A table height that is not a
 *  power of two has no `degree_bits`, which is a fail-close, not a rounding. */
static size_t p2s_log2_exact(size_t x)
{
    size_t l = 0;
    if (x == 0) return (size_t)-1;
    while ((x & 1u) == 0) { x >>= 1; l++; }
    return (x == 1) ? l : (size_t)-1;
}

/** log2_ceil for x >= 1 (p3_util::log2_ceil_usize). */
static size_t p2s_log2_ceil(size_t x)
{
    size_t l = 0, v = 1;
    if (x == 0) return (size_t)-1;
    while (v < x) { v <<= 1; l++; }
    return l;
}

size_t dnac_p2s_log_num_qc(size_t max_symbolic_degree, int is_zk)
{
    /* batch-stark/src/symbolic.rs:70-78 (v0.6.2). The lookup term is 0 here —
     * none of the five fold AIRs declares a lookup — so `max_degree` is the
     * AIR degree hint and the `.max(2)` floor is what keeps `- 1` >= 1. */
    size_t cd;
    if (is_zk != 0 && is_zk != 1) return (size_t)-1;
    if (max_symbolic_degree == 0) return (size_t)-1;
    cd = max_symbolic_degree + (size_t)is_zk;
    if (cd < 2) cd = 2;
    return p2s_log2_ceil(cd - 1);
}

/* ── instance -> (query, slot, batch, round) ─────────────────────────────────
 * The ONE place the instance map is decoded. Instance 0 is the transcript (no
 * query, no slot, no batch, no round); every other instance is 1 + SLOTS*q +
 * slot, a slot in [SLOT_MMIX0, SLOT_MMCS0) additionally names an INPUT BATCH,
 * and a slot in [SLOT_MMCS0, SLOT_FRI) additionally names a COMMIT ROUND. The
 * two ranges are disjoint by construction (SLOT_MMCS0 is the boundary). */

uint32_t dnac_p2s_inst_slot(uint32_t instance)
{
    if (instance == DNAC_P2S_INST_TAIR ||
        instance >= DNAC_P2S_NUM_INSTANCES) {
        return DNAC_P2S_SLOTS;
    }
    return (instance - 1u) % DNAC_P2S_SLOTS;
}

size_t dnac_p2s_inst_query(uint32_t instance)
{
    if (instance == DNAC_P2S_INST_TAIR ||
        instance >= DNAC_P2S_NUM_INSTANCES) {
        return (size_t)-1;
    }
    return (size_t)((instance - 1u) / DNAC_P2S_SLOTS);
}

size_t dnac_p2s_inst_round(uint32_t instance)
{
    const uint32_t slot = dnac_p2s_inst_slot(instance);
    /* `dnac_p2s_inst_slot` already returns SLOTS (not an mmcs slot) for the
     * transcript instance and for an out-of-range index, so the predicate
     * covers both without repeating their tests. */
    if (!DNAC_P2S_SLOT_IS_MMCS(slot)) return (size_t)-1;
    return DNAC_P2S_SLOT_ROUND(slot);
}

size_t dnac_p2s_inst_batch(uint32_t instance)
{
    const uint32_t slot = dnac_p2s_inst_slot(instance);
    /* Same reasoning as the round decoder, plus the sentinel: `inst_slot`
     * returns SLOTS for the transcript instance and for an out-of-range index,
     * and `p2s_slot_sentinel_is_not_a_batch_assert` above is what makes
     * DNAC_P2S_SLOT_IS_MMIX(SLOTS) false rather than a coincidence. */
    if (!DNAC_P2S_SLOT_IS_MMIX(slot)) return (size_t)-1;
    return DNAC_P2S_SLOT_BATCH(slot);
}

/* The pinned cfgs are per SLOT, not per query (the file header's honest note:
 * a table encodes the AIR's SCHEDULE and every query runs the same one), so the
 * geometry accessors below dispatch on the slot: the Q copies of a slot are
 * byte-identical, while the B mmix SLOTS and the R mmcs SLOTS are B and R
 * different cfgs. Both are `if`s rather than `case`s because their slots are
 * RANGES. */

size_t dnac_p2s_prep_cols(uint32_t instance)
{
    const uint32_t slot = dnac_p2s_inst_slot(instance);
    if (instance == DNAC_P2S_INST_TAIR) return (size_t)TAIR_TBL_COLS;
    if (DNAC_P2S_SLOT_IS_MMIX(slot)) return (size_t)DNAC_P2C_MMIX_TABLE_COLS;
    if (DNAC_P2S_SLOT_IS_MMCS(slot)) return (size_t)DNAC_P2B_TABLE_COLS;
    switch (slot) {
    case DNAC_P2S_SLOT_FRI:  return (size_t)DNAC_P2C_TABLE_COLS;
    case DNAC_P2S_SLOT_OI:   return (size_t)DNAC_P2C_OI_TABLE_COLS;
    default: return 0;
    }
}

size_t dnac_p2s_prep_rows(uint32_t instance)
{
    const uint32_t slot = dnac_p2s_inst_slot(instance);
    if (instance == DNAC_P2S_INST_TAIR) {
        return dnac_tair_table_rows(dnac_p2s_tair_script());
    }
    if (DNAC_P2S_SLOT_IS_MMIX(slot)) {
        /* PER BATCH: the cfgs differ in opened WIDTH. At this pin the SCHEDULE
         * — and therefore the row count and the whole table — does NOT move
         * with the width, because the mixed schedule sees it only through
         * `leaf_rows = ceil(concat / 4)` and every pinned width rounds to 1
         * (fri_statement.h's honest note). A NULL cfg would be an out-of-range
         * batch, which the slot predicate has already excluded — the guard is
         * the fail-close rail. */
        const dnac_p2c_mmix_table_cfg_t *c =
            dnac_p2s_mmix_cfg(DNAC_P2S_SLOT_BATCH(slot));
        return (c == NULL) ? 0 : dnac_p2c_mmix_table_rows(c);
    }
    if (DNAC_P2S_SLOT_IS_MMCS(slot)) {
        /* PER ROUND: the depth differs (4/3/2), so the row CONTENT does. The
         * heights happen to coincide at 8/8/8 here — leaf == 1 makes
         * `pad(used + 1)` land on the same power of two for all three — so the
         * content, not the height, is what separates these commitments.
         * A NULL cfg would be an out-of-range round, which the slot
         * predicate has already excluded — the guard is the fail-close rail. */
        const dnac_p2b_table_cfg_t *c =
            dnac_p2s_mmcs_cfg(DNAC_P2S_SLOT_ROUND(slot));
        return (c == NULL) ? 0 : dnac_p2b_table_rows(c);
    }
    switch (slot) {
    case DNAC_P2S_SLOT_FRI:  return dnac_p2c_table_rows(&P2S_FRI_CFG);
    case DNAC_P2S_SLOT_OI:   return dnac_p2c_oi_table_rows(&P2S_OI_CFG);
    default: return 0;
    }
}

size_t dnac_p2s_num_publics(uint32_t instance)
{
    const uint32_t slot = dnac_p2s_inst_slot(instance);
    if (instance == DNAC_P2S_INST_TAIR) return DNAC_P2S_TAIR_NUM_PUBLICS;
    if (DNAC_P2S_SLOT_IS_MMIX(slot)) {
        return DNAC_P2S_MMIX_NUM_PUBLICS(DNAC_P2S_SLOT_BATCH(slot));
    }
    if (DNAC_P2S_SLOT_IS_MMCS(slot)) {
        return DNAC_P2S_MMCS_NUM_PUBLICS(DNAC_P2S_SLOT_ROUND(slot));
    }
    switch (slot) {
    case DNAC_P2S_SLOT_FRI:  return DNAC_P2S_FRI_NUM_PUBLICS;
    case DNAC_P2S_SLOT_OI:   return DNAC_P2S_OI_NUM_PUBLICS;
    default: return 0;
    }
}

size_t dnac_p2s_pub_off(uint32_t instance)
{
    size_t off;
    uint32_t s;

    if (instance >= DNAC_P2S_NUM_INSTANCES) return (size_t)-1;
    if (instance == DNAC_P2S_INST_TAIR) return 0;

    off = DNAC_P2S_TAIR_NUM_PUBLICS +
          dnac_p2s_inst_query(instance) * DNAC_P2S_QUERY_PUBLICS;
    /* the slots BEFORE this one, inside the query's block */
    for (s = 0; s < dnac_p2s_inst_slot(instance); s++) {
        off += dnac_p2s_num_publics(DNAC_P2S_INST(0, s));
    }
    return off;
}

size_t dnac_p2s_prep_cells(uint32_t instance)
{
    const size_t rows = dnac_p2s_prep_rows(instance);
    const size_t cols = dnac_p2s_prep_cols(instance);
    if (rows == 0 || cols == 0) return 0;
    if (rows > (size_t)-1 / cols) return 0;
    return rows * cols;
}

/* ==========================================================================
 * Step 1 — G6 canonicality (the ONE checkpoint; every s1a header defers it)
 * ======================================================================== */

static int p2s_canon_span(const uint64_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (v[i] >= GOLDILOCKS_P) return 0;
    }
    return 1;
}

static dnac_p2s_status_t p2s_check_canonical(const dnac_p2s_statement_t *s)
{
    /* Every region, so a field cannot be forgotten as the struct grows: the
     * total is static-asserted against sizeof below. The per-query regions are
     * spanned as ONE flat run each — they are C arrays of arrays, so the whole
     * block is contiguous and no query can be skipped by an off-by-one. */
    if (!p2s_canon_span(&s->index_bits[0][0],
                        DNAC_P2S_NUM_QUERIES * DNAC_P2S_LGMH) ||
        !p2s_canon_span(s->tair_payload, DNAC_P2S_TAIR_NUM_OPS) ||
        !p2s_canon_span(s->final_poly0, 2) ||
        !p2s_canon_span(s->pz_shared, 2 * DNAC_P2S_OI_TOTAL_ACC) ||
        !p2s_canon_span(&s->z_pq[0][0],
                        DNAC_P2S_NUM_QUERIES * 2 * DNAC_P2S_OI_TOTAL_ACC) ||
        !p2s_canon_span(&s->ro_export[0][0],
                        DNAC_P2S_NUM_QUERIES * 2 * DNAC_P2S_OI_NUM_HEIGHTS) ||
        !p2s_canon_span(&s->mmix_root[0][0],
                        DNAC_P2S_OI_NUM_BATCHES * (size_t)MMIX_DIGEST_LANES) ||
        !p2s_canon_span(&s->mmcs_root[0][0],
                        DNAC_P2S_FRI_R * (size_t)MAIR_DIGEST_LANES) ||
        !p2s_canon_span(&s->mmix_opened[0][0],
                        DNAC_P2S_NUM_QUERIES * DNAC_P2S_MMIX_ALL_OPENED) ||
        !p2s_canon_span(&s->mmcs_opened[0][0][0],
                        DNAC_P2S_NUM_QUERIES * DNAC_P2S_FRI_R *
                            DNAC_P2S_MMCS_TOTAL_WIDTH)) {
        return DNAC_P2S_ERR_CANON;
    }

    /* STRICTER THAN SPEC §3.1, deliberately: the index bits are not merely
     * publics, they are this entry's own CONSTRUCTION INPUT (step 6 slices each
     * query's row into that query's four bit / direction regions AND into the
     * transcript instance's q-th exported-bit block). A value outside {0,1}
     * would still be rejected downstream — every consumer AIR asserts
     * booleanity of the trace cell it binds to the public, and CT-4 does the
     * same on the transcript side (transcript_air.c block D) — but only as an
     * OOD mismatch several hundred constraints later, with nothing naming the
     * cause. Rejecting here is a rejection, not a new constraint.
     *
     * All Q rows, because all Q are consumed now: the `tair_bits_rest` rail
     * this loop used to need alongside it is gone with the field. */
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
            if (s->index_bits[q][l] > 1) return DNAC_P2S_ERR_CANON;
        }
    }
    return DNAC_P2S_OK;
}

/* The struct is all-uint64_t and every member is spanned above; if a region is
 * added without extending p2s_check_canonical, this stops the build. */
typedef char p2s_statement_fully_spanned_assert
    [(sizeof(dnac_p2s_statement_t) ==
      sizeof(uint64_t) *
          (DNAC_P2S_NUM_QUERIES *
               (DNAC_P2S_LGMH + 2 * DNAC_P2S_OI_TOTAL_ACC +
                2 * DNAC_P2S_OI_NUM_HEIGHTS + DNAC_P2S_MMIX_ALL_OPENED +
                DNAC_P2S_FRI_R * DNAC_P2S_MMCS_TOTAL_WIDTH) +
           DNAC_P2S_TAIR_NUM_OPS + 2 + 2 * DNAC_P2S_OI_TOTAL_ACC +
           DNAC_P2S_OI_NUM_BATCHES * (size_t)MMIX_DIGEST_LANES +
           DNAC_P2S_FRI_R * (size_t)MAIR_DIGEST_LANES))
         ? 1
         : -1];

/* At least one query, or the per-query C arrays would have length zero, which
 * is not valid C. (The old `Q >= 2` rail existed only because `tair_bits_rest`
 * held queries 1..Q-1; with every query consumed, Q == 1 is a legal pin again
 * and this is the honest bound.) */
typedef char p2s_num_queries_nonzero_assert
    [(DNAC_P2S_NUM_QUERIES >= 1) ? 1 : -1];

/* At least one commit round, or the per-round C arrays (mmcs_root, the fold
 * states, the cfg list) would have length zero, which is not valid C. R == 0
 * would also mean a FRI walk with no folds at all. */
typedef char p2s_fri_r_nonzero_assert [(DNAC_P2S_FRI_R >= 1) ? 1 : -1];

/* Same rail on the batch axis: B == 0 would give `mmix_root`, the per-batch
 * fold states and the cfg list length zero, and would mean a FRI verification
 * with no input at all. (The old `p2s_px_rest_nonempty_assert` guarded the
 * OPPOSITE hazard — that `px_rest` might become zero-length — and went with the
 * field it guarded: every acc row is mmix-aliased now, so there is no
 * "remainder" array left to be empty.) */
typedef char p2s_num_batches_nonzero_assert
    [(DNAC_P2S_OI_NUM_BATCHES >= 1) ? 1 : -1];

/* The Q CEILING. `dnac_batch_verify` / `dnac_batch_prove` reject an instance
 * count past their (unexported) cap — batch_verify.c:20 + :86 and
 * batch_prover.c:22 + :572, both 32 — so a Q whose 1 + (B+R+2)*Q overruns it
 * would be a RUNTIME reject on every honest proof. Fail at BUILD time instead.
 * DNAC_P2S_MAX_QUERIES is derived from the mirrored cap and the slot count, so
 * the ceiling follows B and R as well as the cap; none is written out. */
typedef char p2s_num_queries_fits_batch_assert
    [(DNAC_P2S_NUM_QUERIES <= DNAC_P2S_MAX_QUERIES) ? 1 : -1];
typedef char p2s_instance_count_fits_batch_assert
    [(DNAC_P2S_NUM_INSTANCES <= DNAC_P2S_BATCH_MAX_INSTANCES) ? 1 : -1];

/* ==========================================================================
 * Step 2 — the preprocessed root pin
 * ======================================================================== */

static dnac_p2s_status_t p2s_check_prep_root(
    const dnac_batch_vcommits_t *commits,
    const uint32_t              *prep_matrix_to_instance,
    uint32_t                     num_prep_matrices)
{
    static const uint64_t pinned[4] = DNAC_P2S_PREP_ROOT;

    if (commits->preprocessed_commit == NULL) return DNAC_P2S_ERR_PREP_ROOT;

    /* The pin is a commitment over the tables IN prep_map ORDER, so the map is
     * part of what has to match: the same tables committed in a different order
     * give a different root, and a map naming other instances would leave a
     * gated AIR reading someone else's selector cells.
     *
     * ⚠ HONEST SCOPE with Q copies present. A permutation that swaps two
     * instances of the SAME slot (query 0's mmix matrix for query 1's) is
     * semantically a no-op — the two matrices are byte-identical, so it moves
     * neither the root nor any AIR's window. This identity check rejects it
     * anyway, which is STRICTER than necessary rather than load-bearing; what
     * IS load-bearing is that a map crossing slots (an oi instance handed the
     * fri table) cannot pass. Stated so the check is not read as carrying a
     * separation it does not carry. */
    if (num_prep_matrices != DNAC_P2S_NUM_INSTANCES ||
        prep_matrix_to_instance == NULL) {
        return DNAC_P2S_ERR_PREP_ROOT;
    }
    for (uint32_t m = 0; m < DNAC_P2S_NUM_INSTANCES; m++) {
        if (prep_matrix_to_instance[m] != m) return DNAC_P2S_ERR_PREP_ROOT;
    }

    /* While the pin is the unfilled placeholder this rejects EVERYTHING,
     * including the all-zero root an adversary supplying an all-zero table
     * would present (fri_air_table.h:486-489). */
    if (DNAC_P2S_PREP_ROOT_UNFILLED) return DNAC_P2S_ERR_PREP_ROOT;

    for (size_t k = 0; k < 4; k++) {
        if (gold_fp_to_u64(commits->preprocessed_commit[k]) != pinned[k]) {
            return DNAC_P2S_ERR_PREP_ROOT;
        }
    }
    return DNAC_P2S_OK;
}

/* ==========================================================================
 * Step 3a — STATIC cross-cfg consistency (constants only; no witness, no
 * proof). These are the obligations the per-module headers hand to the
 * composition entry by name, and they run BEFORE any bind so a mismatched cfg
 * pair can never reach a constraint system.
 * ======================================================================== */

/* ── s2 + INPUT-BATCH REPLICATION: the (batch, height) -> matrix map ─────────
 * Batch b is the batch mmix instance DNAC_P2S_SLOT_MMIX(b) describes, and its
 * opened region is flattened in MATRIX order using the SEMANTIC widths
 * (mmcs_mixed_air.h "Public values": root ‖ dir ‖ opened rows per matrix). So a
 * (batch, oi height) pair picks out the mmix matrix batch b committed at that
 * height and, with it, the offset of that matrix's opened row inside batch b's
 * span of `stmt.mmix_opened`.
 *
 * Nothing here is read from a proof and nothing is hard-coded: the heights and
 * widths are the same pinned arrays the per-batch mmix cfgs are built from.
 */

/** Compile-time: the p_x map needs ONE matrix per batch per height, so that the
 *  (batch, height) pair alone determines the matrix. The pinned oi group
 *  descriptor says so (DNAC_P2S_OI_NUM_MATRICES); this stops the build if it
 *  ever stops saying so, rather than letting the mapping below quietly pick the
 *  wrong lane. */
typedef char p2s_oi_one_matrix_per_batch_assert
    [(DNAC_P2S_OI_NUM_MATRICES == 1) ? 1 : -1];

/**
 * Offset (WITHIN BATCH `batch`'s span) + semantic width of the mmix matrix
 * batch `batch` commits at `log_height`.
 * @return 1 iff `batch` is in range and EXACTLY ONE of its pinned matrices sits
 *         at that height (fail-close: zero or several make the map ambiguous).
 */
static int p2s_mmix_matrix_at_height(size_t batch, size_t log_height,
                                     size_t *out_off, size_t *out_width)
{
    const dnac_p2c_mmix_table_cfg_t *cfg = dnac_p2s_mmix_cfg(batch);
    const size_t want = (size_t)1u << log_height;
    size_t off = 0, found_off = 0, found_w = 0, n = 0;

    if (cfg == NULL) return 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->heights[m] == want) {
            found_off = off;
            found_w = cfg->widths[m];
            n++;
        }
        off += cfg->widths[m];
    }
    if (n != 1) return 0;
    *out_off = found_off;
    *out_width = found_w;
    return 1;
}

/** Descending-H index of `log_height` in the pinned oi cfg, or SIZE_MAX. */
static size_t p2s_oi_height_index(size_t log_height)
{
    for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
        if (P2S_OI_HEIGHTS[i].log_height == log_height) return i;
    }
    return (size_t)-1;
}

/* ── s3b: the transcript script's pop sequence ───────────────────────────────
 * `dnac_tair_fri_build_script` emits, in this order (transcript_air_table.c
 * :296-324): the DS-prefix observes, then TWO non-PoW pops (alpha, c0 then c1),
 * then per round r the digest observes, an OPTIONAL PoW pair, and TWO non-PoW
 * pops (beta_r, c0 then c1), then the final-poly and log_arity observes, an
 * OPTIONAL PoW pair, and finally ONE non-PoW pop per query.
 *
 * So the NON-PoW pops, numbered in script order, are exactly
 *     0, 1                  alpha.c0, alpha.c1
 *     2 + 2r, 3 + 2r        beta_r.c0, beta_r.c1        (r < R)
 *     2 + 2R + q            the query-q index sample     (q < Q)
 * and this function maps that ordinal back to an OP INDEX by walking the
 * script. The aliases below index by ORDINAL, never by a hard-coded op number,
 * so the map stays correct if a PoW pair is ever switched on (which inserts an
 * `is_pow` pop the ordinal deliberately skips).
 *
 * @return the op index, or SIZE_MAX if the script has fewer non-PoW pops.
 */
static size_t p2s_tair_pop_op(const dnac_tair_script_t *s, size_t ordinal)
{
    size_t seen = 0;
    if (s == NULL) return (size_t)-1;
    for (size_t k = 0; k < s->n_ops; k++) {
        if (s->ops[k].kind != DNAC_TAIR_OP_SAMPLE || s->ops[k].is_pow) continue;
        if (seen == ordinal) return k;
        seen++;
    }
    return (size_t)-1;
}

/**
 * The same walk for OBSERVE ops — the map HONEST LABEL 6's closure indexes
 * through. Ordinals are given by DNAC_P2S_OBS_DIGEST (fri_statement.h), which
 * mirrors the builder's emission order at transcript_air_table.c:296-324; this
 * function turns an ordinal into an OP INDEX by scanning, so a PoW witness
 * observe switched on later shifts the map instead of corrupting it.
 *
 * @return the op index, or SIZE_MAX if the script has fewer observes.
 */
static size_t p2s_tair_obs_op(const dnac_tair_script_t *s, size_t ordinal)
{
    size_t seen = 0;
    if (s == NULL) return (size_t)-1;
    for (size_t k = 0; k < s->n_ops; k++) {
        if (s->ops[k].kind != DNAC_TAIR_OP_OBSERVE) continue;
        if (seen == ordinal) return k;
        seen++;
    }
    return (size_t)-1;
}

/** Ordinal of alpha's c0 pop, and of the round-r / query-q pops. Named rather
 *  than inlined so the two consumers below and the test read the SAME map. */
#define P2S_POP_ALPHA        ((size_t)0)
#define P2S_POP_BETA(r)      ((size_t)2 + 2 * (r))
#define P2S_POP_QUERY(q)     ((size_t)2 + 2 * DNAC_P2S_FRI_R + (q))
/** Total non-PoW pops the aliases account for. A script with MORE would have a
 *  challenge nothing consumes and nothing pins — rejected below. */
#define P2S_POP_TOTAL        (P2S_POP_QUERY(DNAC_P2S_NUM_QUERIES))

/**
 * s3b step 3a(d): the pinned script has the SHAPE the aliases index into.
 * Every check is against the script the entry itself expanded — the point is
 * that the ALIAS ARITHMETIC and the SCRIPT cannot disagree, which is the half
 * of OBL-P2a-T1 the preprocessed root does not cover.
 */
static dnac_p2s_status_t p2s_check_tair_script(const dnac_tair_script_t *s)
{
    size_t npops = 0, nobs = 0;

    if (s == NULL) return DNAC_P2S_ERR_CFG; /* the builder rejected the cfg */

    /* Two independent derivations of the same two counts (count-KAFADAN). */
    if (s->n_ops != DNAC_P2S_TAIR_NUM_OPS ||
        dnac_tair_num_publics(s) != DNAC_P2S_TAIR_NUM_PUBLICS ||
        dnac_tair_total_bits(s) != DNAC_P2S_TAIR_TOTAL_BITS) {
        return DNAC_P2S_ERR_CFG;
    }
    /* ONE transcript instance: a second `sel_start` would reset the sponge
     * mid-script, and the ordinal map above assumes one continuous run. */
    if (s->n_starts != 1 || s->instance_starts[0] != 0) {
        return DNAC_P2S_ERR_CFG;
    }

    for (size_t k = 0; k < s->n_ops; k++) {
        if (s->ops[k].kind == DNAC_TAIR_OP_SAMPLE && !s->ops[k].is_pow) npops++;
        if (s->ops[k].kind == DNAC_TAIR_OP_OBSERVE) nobs++;
    }
    if (npops != P2S_POP_TOTAL) return DNAC_P2S_ERR_CFG;
    /* The observe count the digest ordinals are indexed against — an ordinal
     * past the end would resolve to SIZE_MAX below, but comparing the totals
     * catches a script SHAPE change before any ordinal is formed. */
    if (nobs != DNAC_P2S_TAIR_NUM_OBS) return DNAC_P2S_ERR_CFG;

    /* ── HONEST LABEL 6's structural rail: the block DNAC_P2S_OBS_DIGEST names
     * for round r really IS round r's commit-digest block.
     *
     * The native observes round r's digest and then samples beta_r, inside one
     * loop iteration (fri_verifier.c:702 then :707), so in SCRIPT ORDER round
     * r's digest block lies strictly AFTER round r-1's beta pops and strictly
     * BEFORE round r's. Checking that bracket is what turns the ordinal formula
     * from an assumption into a verified property: an ordinal that pointed at
     * the final-poly observes, or at the previous round's block, would fail it.
     * The lanes must also be contiguous and ascending, since the alias writes
     * them as a run. ── */
    for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
        const size_t beta_k = p2s_tair_pop_op(s, P2S_POP_BETA(r));
        /* The pop the block must come AFTER: round r-1's beta c1, or — for
         * round 0, which has no predecessor round — alpha's c1, sampled at
         * fri_verifier.c:694 before the commit loop opens at :700. */
        const size_t prev_k = p2s_tair_pop_op(
            s, (r > 0) ? P2S_POP_BETA(r - 1) + 1 : P2S_POP_ALPHA + 1);
        size_t first = 0, last = 0;

        if (beta_k == (size_t)-1 || prev_k == (size_t)-1) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) {
            const size_t k = p2s_tair_obs_op(s, DNAC_P2S_OBS_DIGEST(r, i));
            if (k == (size_t)-1 || k >= DNAC_P2S_TAIR_NUM_OPS) {
                return DNAC_P2S_ERR_CFG;
            }
            if (i == 0) {
                first = k;
            } else if (k != last + 1) {
                return DNAC_P2S_ERR_CFG; /* not one contiguous run */
            }
            last = k;
        }
        if (last >= beta_k || first <= prev_k) return DNAC_P2S_ERR_CFG;
    }

    /* alpha + the betas are BASE pops: they must export no bits, or the public
     * block would carry lanes the fp2 aliases below silently ignore. */
    for (size_t o = 0; o < P2S_POP_QUERY(0); o++) {
        const size_t k = p2s_tair_pop_op(s, o);
        if (k == (size_t)-1 || s->ops[k].num_bits != 0) return DNAC_P2S_ERR_CFG;
    }
    /* Each query pop exports EXACTLY lgmh bits — that is what makes a query's
     * bit block the same width as `index_bits` (fri_verifier.c:737 with
     * `extra_query_index_bits == 0` at :651). */
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        const size_t k = p2s_tair_pop_op(s, P2S_POP_QUERY(q));
        if (k == (size_t)-1 || s->ops[k].num_bits != DNAC_P2S_LGMH) {
            return DNAC_P2S_ERR_CFG;
        }
        if (dnac_tair_op_bit_off(s, k) == (size_t)-1) return DNAC_P2S_ERR_CFG;
    }

    /* The grinding-width pin (OBL-P2a-T1's second half). */
    return dnac_p2s_check_tair_pow_pin(s);
}

static dnac_p2s_status_t p2s_check_static_consistency(void)
{
    const size_t final_h = DNAC_P2S_LOG_BLOWUP + DNAC_P2S_LFPL;
    int has_lb_group = 0;

    /* (c) The two cfgs must describe the SAME inner FRI: same global max
     * height, same blowup, and the oi schedule's tallest group is that height
     * (fri_oi_air_table.h:362-364 makes heights[0] == lgmh a cfg gate; asserted
     * here as well because it is what makes ro_export[0] the walk's SEED —
     * fri_verifier.c:524-527 requires ro[0].log_height == lgmh). */
    if (P2S_OI_CFG.lgmh != P2S_FRI_CFG.lgmh ||
        P2S_OI_CFG.log_blowup != P2S_FRI_CFG.log_blowup ||
        P2S_OI_CFG.num_heights == 0 ||
        P2S_OI_HEIGHTS[0].log_height != P2S_FRI_CFG.lgmh) {
        return DNAC_P2S_ERR_CFG;
    }

    /* Strict descent + the lb-group presence flag, read off the same array the
     * cfg exports (a duplicate of the table module's own gate; cheap, and it is
     * what (a)/(b) below stand on). */
    for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
        if (i > 0 &&
            P2S_OI_HEIGHTS[i].log_height >= P2S_OI_HEIGHTS[i - 1].log_height) {
            return DNAC_P2S_ERR_CFG;
        }
        if (P2S_OI_HEIGHTS[i].log_height == P2S_OI_CFG.log_blowup) {
            has_lb_group = 1;
        }
    }

    for (size_t k = 0; k < P2S_FRI_CFG.num_rollin; k++) {
        const size_t h = P2S_FRI_CFG.rollin_heights[k];
        const size_t i = p2s_oi_height_index(h);

        /* (a) ROLL-IN SET CONTAINMENT (fri_oi_air.h:90-99, FLEET 029 F9): every
         * height the fold walk rolls in MUST be an exported oi ro slot,
         * otherwise the entry would have no single source for that public and
         * the native's `ro_i` sweep (fri_verifier.c:600-605) and the oi export
         * would describe different sets. `\ {lgmh}` because ro_export[0] is
         * already consumed as f_init, and a second consumption would double-
         * count it — the fri cfg gate independently caps roll-ins at lgmh-1
         * (fri_air_table.c:89), so this is a belt on that braces. */
        if (i == (size_t)-1 || i == 0) return DNAC_P2S_ERR_CFG;

        /* (b) A roll-in at the FINAL height is only meaningful when the oi cfg
         * actually has a group there: C4b pins that ro to zero only when a
         * height at log_blowup exists (fri_oi_air.c:428-433 mirroring the
         * native's CONDITIONAL check, fri_verifier.c:482-487). fri_air's own
         * gate admits final_h as a roll-in height (fri_air_table.c:89), so this
         * cross-check is load-bearing, not decorative. */
        if (h == final_h && !has_lb_group) return DNAC_P2S_ERR_CFG;
    }

    /* ── (e) INPUT-BATCH REPLICATION: the B mmix cfgs and the oi schedule
     * describe the SAME input side. HONEST LABEL 3's closure rests on this, so
     * it is checked once, statically, before any bind — a batch whose opened
     * row does not have a lane per acc row of its own block would leave the
     * p_x alias reading someone else's column, or reading past the row.
     *
     * Per batch b:
     *   - the group descriptor's per-batch block and the REAL (points, columns)
     *     split must agree on the block SIZE. The descriptor is uniform and the
     *     real split is not (HONEST LABEL 5), so this is the one place the two
     *     descriptions are reconciled;
     *   - batch b must name EXACTLY ONE matrix at every pinned oi height, and
     *     that matrix's SEMANTIC width must be batch b's column count — the
     *     native's own equality (fri_verifier.c:333 pins the opened row length
     *     to the claimed-eval count, :469-471 indexes the row by that ordinal).
     *     Compile-time asserts pin the two CONSTANTS to each other; this pins
     *     the constant to the CFG the bind will actually receive, which is a
     *     different claim (OBL-4-MMIX: the cfg is a separate argument);
     *   - the matrix's opened row must lie inside batch b's span. ── */
    for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
        const dnac_p2c_mmix_table_cfg_t *mc = dnac_p2s_mmix_cfg(b);
        const size_t nc = DNAC_P2S_OI_BNC(b);
        const size_t off = dnac_p2s_mmix_opened_off(b);

        if (mc == NULL || off == (size_t)-1) return DNAC_P2S_ERR_CFG;
        if (nc == 0 || DNAC_P2S_OI_BNP(b) * nc != DNAC_P2S_OI_ACC_PER_BATCH) {
            return DNAC_P2S_ERR_CFG;
        }
        if (off + DNAC_P2S_MMIX_TOTAL_OPENED(b) > DNAC_P2S_MMIX_ALL_OPENED) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
            size_t moff = 0, mw = 0;
            if (!p2s_mmix_matrix_at_height(b, P2S_OI_HEIGHTS[i].log_height,
                                           &moff, &mw)) {
                return DNAC_P2S_ERR_CFG;
            }
            if (mw != nc) return DNAC_P2S_ERR_CFG;
            if (moff + mw > DNAC_P2S_MMIX_TOTAL_OPENED(b)) {
                return DNAC_P2S_ERR_CFG;
            }
        }
    }
    /* The B spans must PARTITION the row exactly — no gap, no overlap, nothing
     * left over. A leftover lane would be dead statement input; an overlap
     * would silently alias two batches' opened rows onto each other, which is
     * precisely what N-BSEP forbids. */
    {
        size_t sum = 0;
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            if (dnac_p2s_mmix_opened_off(b) != sum) return DNAC_P2S_ERR_CFG;
            sum += DNAC_P2S_MMIX_TOTAL_OPENED(b);
        }
        if (sum != DNAC_P2S_MMIX_ALL_OPENED) return DNAC_P2S_ERR_CFG;
    }

    /* (d) s3b — the transcript script's shape + the pow_bits pin. */
    return p2s_check_tair_script(dnac_p2s_tair_script());
}

/* ==========================================================================
 * Steps 3-6 — cfgs, binds, degree_bits, log_num_qc, publics
 * ======================================================================== */

/** Common tail of steps 4+5 for one instance. */
static dnac_p2s_status_t p2s_fill_geometry(dnac_batch_vinstance_t *vi,
                                           uint32_t instance,
                                           size_t   want_publics)
{
    const size_t rows = dnac_p2s_prep_rows(instance);
    const size_t cols = dnac_p2s_prep_cols(instance);
    const size_t db = p2s_log2_exact(rows);
    const size_t lq = dnac_p2s_log_num_qc(DNAC_P2S_MAX_SYMBOLIC_DEGREE, 0);

    /* Step 4 (G4a): degree_bits comes from the TABLE's own row count, never
     * from the proof. A cfg the table module rejects reports rows == 0 and is
     * caught here even though its bind already passed. */
    if (rows == 0 || db == (size_t)-1 || db > 30) return DNAC_P2S_ERR_SHAPE;
    if (lq == (size_t)-1) return DNAC_P2S_ERR_SHAPE;

    /* The bind filled `air`; its public count must be the pinned one. The two
     * are independent derivations (module accessor vs this header's region
     * arithmetic), which is the whole point of comparing them. */
    if (vi->air.num_public_values != want_publics) return DNAC_P2S_ERR_CFG;

    vi->degree_bits = (uint32_t)db;
    vi->log_num_qc = (uint32_t)lq;
    vi->preprocessed_width = (uint32_t)cols;
    /* PIN-2 (gate G5): HARD-CODED. Four of the five AIRs read the NEXT row's
     * preprocessed cells — the fri chain transition reads g_pow2'
     * (fri_air_table.h:150-152), both MMCS AIRs thread state across a
     * preprocessed-gated pair, and the oi evaluator refuses a
     * next-MAIN-without-next-PREP call outright (fri_oi_air.h:44-46, and its
     * fold form reads PN in C1b / C2b / C2d). The transcript AIR does NOT
     * (no CT-* form reads the next row's table cells), but OBL-P2a-T2
     * (transcript_air_table.h:175-182) hands the entry the duty of pinning it
     * anyway, and at TAIR_TBL_COLS = 71 a zero window is rejected on SHAPE
     * rather than silently substituted — so a `prep_next = 0` descriptor
     * would hand them a zero window. Not a caller option, hence no parameter. */
    vi->prep_next = 1;
    vi->num_publics = (uint32_t)want_publics;
    return DNAC_P2S_OK;
}

/* ── Step 6, one query's B + R + 2 consumers ─────────────────────────────────
 * Every module's own offset accessors place the regions — this file never
 * hard-codes an offset — and every accessor is cross-checked against the pinned
 * arithmetic, so a layout change in a module surfaces as a reject, not as a
 * silent misalignment.
 *
 * ⚠ THE WHOLE POINT OF THE MULTI-QUERY SLICE IS THE `q` IN THIS FUNCTION'S
 * SIGNATURE. Everything read out of `stmt` here is either
 *   - a PER-QUERY region indexed by `q` (index_bits, ro_export, mmix_opened,
 *     mmcs_opened, z_pq), or
 *   - a SHARED region with no query index at all (tair_payload, final_poly0,
 *     pz_shared, the B + R roots),
 * and the split is the native's: the shared ones are sampled or observed BEFORE
 * the per-query loop at fri_verifier.c:736, the per-query ones inside it.
 * Feeding `q = 0` to every call would put Q identical instances in the batch —
 * the `lb*Q -> lb` collapse OBL-P2c-2 names (fri_air.h). */
static dnac_p2s_status_t p2s_build_query_publics(
    const dnac_p2s_statement_t *stmt, size_t q,
    const dnac_tair_script_t *tsc, dnac_batch_vinstance_t *insts,
    gold_fp_t *pub)
{
    gold_fp_t *pub_fri, *pub_oi;

    /* BEFORE any offset is formed: `dnac_p2s_pub_off` reports SIZE_MAX for an
     * out-of-range instance, and `pub + SIZE_MAX` would be undefined behaviour
     * rather than a rejected pointer. */
    if (q >= DNAC_P2S_NUM_QUERIES) return DNAC_P2S_ERR_CFG;

    pub_fri = pub + dnac_p2s_pub_off(DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI));
    pub_oi = pub + dnac_p2s_pub_off(DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI));

    /* ── mmix, ONE INSTANCE PER INPUT BATCH: root ‖ dir ‖ opened.
     *
     * BATCH b's three regions and where each comes from:
     *   root    stmt->mmix_root[b]   — SHARED across q, DISTINCT across b
     *                                  (`commitments[batch].commitment`,
     *                                  fri_verifier.c:209 -> :383/:392)
     *   dir[l]  index_bits[q][(lgmh - max_lh) + l] — the mixed MMCS walks the
     *           REDUCED index `index >> (log_global_max_height -
     *           max_log_height)` (fri_verifier.c:252-255). Here max_lh == lgmh
     *           for every batch, so the shift is 0 and the full index is
     *           consumed — written as the general expression so the alias stays
     *           correct if the pinned heights ever change. Batch-independent at
     *           this pin BECAUSE the depths are; it is recomputed per batch
     *           from that batch's own cfg rather than assumed.
     *   opened  mmix_opened[q] at batch b's span — per query AND per batch
     *
     * Written as a loop over batches rather than B copies: the ONLY thing that
     * varies is the cfg, and each batch re-checks its own module accessors
     * against its own pinned arithmetic, so a per-batch layout drift is a
     * reject rather than a misaligned write. Same shape as the round loop
     * below. ── */
    for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
        const dnac_p2c_mmix_table_cfg_t *cfg = dnac_p2s_mmix_cfg(b);
        const uint32_t inst = DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX(b));
        const size_t base = dnac_p2s_mmix_opened_off(b);
        gold_fp_t *pub_mmix;
        size_t opened_off, npub, shift;

        if (cfg == NULL || base == (size_t)-1) return DNAC_P2S_ERR_CFG;
        pub_mmix = pub + dnac_p2s_pub_off(inst);
        opened_off = dnac_mmix_air_pub_opened_off(cfg);
        npub = dnac_mmix_air_num_publics(cfg);
        if (npub != DNAC_P2S_MMIX_NUM_PUBLICS(b) ||
            cfg->depth != DNAC_P2S_MMIX_DEPTH ||
            dnac_mmix_air_total_opened(cfg) != DNAC_P2S_MMIX_TOTAL_OPENED(b) ||
            opened_off != (size_t)MMIX_PUB_DIR_OFF + DNAC_P2S_MMIX_DEPTH) {
            return DNAC_P2S_ERR_CFG;
        }
        shift = DNAC_P2S_LGMH - cfg->depth;
        for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
            pub_mmix[(size_t)MMIX_PUB_ROOT_OFF + k] =
                gold_fp_from_u64(stmt->mmix_root[b][k]); /* SHARED across q */
        }
        for (size_t l = 0; l < cfg->depth; l++) {
            pub_mmix[(size_t)MMIX_PUB_DIR_OFF + l] =
                gold_fp_from_u64(stmt->index_bits[q][shift + l]);
        }
        for (size_t c = 0; c < DNAC_P2S_MMIX_TOTAL_OPENED(b); c++) {
            pub_mmix[opened_off + c] =
                gold_fp_from_u64(stmt->mmix_opened[q][base + c]);
        }
        insts[inst].public_values = pub_mmix;
    }

    /* ── mmcs, ONE INSTANCE PER COMMIT ROUND: root ‖ dir ‖ opened.
     *
     * ROUND r's three regions and where each comes from:
     *   root    stmt->mmcs_root[r]   — SHARED across q, DISTINCT across r
     *                                  (`commit_phase_commits[round]`,
     *                                  fri_verifier.c:585)
     *   dir[l]  index_bits[q][BIT_OFF(r) + l] — `verify_query` shifts the index
     *           DOWN by log_arity once per round (fri_verifier.c:558) BEFORE
     *           handing it to that round's MMCS together with height
     *           2^log_folded_height (:585-588), so after r+1 shifts the walk
     *           reads the index from bit (r+1)*log_arity upward, over that
     *           round's own `depth` levels. BIT_OFF(r) + DEPTH(r) == lgmh, so
     *           the window is exactly the index's remaining high bits and the
     *           bounds check below can never be a silent clamp.
     *   opened  mmcs_opened[q][r]    — per query AND per round
     *
     * Written as a loop over rounds rather than R copies: the ONLY thing that
     * varies is the cfg, and each round re-checks its own module accessors
     * against its own pinned arithmetic, so a per-round layout drift is a
     * reject rather than a misaligned write. ── */
    for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
        const dnac_p2b_table_cfg_t *cfg = dnac_p2s_mmcs_cfg(r);
        const uint32_t inst = DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS(r));
        gold_fp_t *pub_mmcs;
        size_t opened_off, npub, total;

        if (cfg == NULL) return DNAC_P2S_ERR_CFG;
        pub_mmcs = pub + dnac_p2s_pub_off(inst);
        opened_off = dnac_mmcs_air_pub_opened_off(cfg);
        npub = dnac_mmcs_air_num_publics(cfg);
        total = dnac_mmcs_air_total_width(cfg);
        if (npub != DNAC_P2S_MMCS_NUM_PUBLICS(r) ||
            total != DNAC_P2S_MMCS_TOTAL_WIDTH ||
            cfg->depth != DNAC_P2S_MMCS_DEPTH(r) ||
            opened_off != (size_t)MAIR_PUB_DIR_OFF + DNAC_P2S_MMCS_DEPTH(r)) {
            return DNAC_P2S_ERR_CFG;
        }
        /* The window must END at the last index bit — the BIT_OFF/DEPTH
         * invariant, asserted here because it is what makes the bit index below
         * in range for every round. */
        if (DNAC_P2S_MMCS_BIT_OFF(r) + DNAC_P2S_MMCS_DEPTH(r) !=
            DNAC_P2S_LGMH) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
            pub_mmcs[(size_t)MAIR_PUB_ROOT_OFF + k] =
                gold_fp_from_u64(stmt->mmcs_root[r][k]);
        }
        for (size_t l = 0; l < DNAC_P2S_MMCS_DEPTH(r); l++) {
            pub_mmcs[(size_t)MAIR_PUB_DIR_OFF + l] = gold_fp_from_u64(
                stmt->index_bits[q][DNAC_P2S_MMCS_BIT_OFF(r) + l]);
        }
        for (size_t c = 0; c < DNAC_P2S_MMCS_TOTAL_WIDTH; c++) {
            pub_mmcs[opened_off + c] =
                gold_fp_from_u64(stmt->mmcs_opened[q][r][c]);
        }
        insts[inst].public_values = pub_mmcs;
    }

    /* fri: bits ‖ beta ‖ f_init ‖ ro ‖ final. bits are query q's FULL index,
     * LSB-first, exactly as the fold walk consumes them (fold row r reads bit
     * r) and as the MSB-first chain reads them from the other end.
     *
     * f_init and the roll-in slots are ALIASES of `ro_export[q]`, not statement
     * fields — the s1c seam closure, now per query. f_init takes the
     * height-lgmh export (the native seeds the walk with ro[0], whose height
     * MUST be lgmh, fri_verifier.c:524-527); roll-in slot k takes the export of
     * `rollin_heights[k]`, which step 3a has already proved is an oi height
     * other than index 0. Both descending, so the k-th slot and the native's
     * k-th `ro_i` advance (fri_verifier.c:600-605) name the same opening.
     *
     * The betas and final_poly are the SHARED lanes — see the block below and
     * the field comments. */
    {
        const size_t beta_off = dnac_fair_pub_beta_off(&P2S_FRI_CFG);
        const size_t finit_off = dnac_fair_pub_finit_off(&P2S_FRI_CFG);
        const size_t ro_off = dnac_fair_pub_ro_off(&P2S_FRI_CFG);
        const size_t final_off = dnac_fair_pub_final_off(&P2S_FRI_CFG);
        const size_t npub = dnac_fair_num_publics(&P2S_FRI_CFG);
        if (npub != DNAC_P2S_FRI_NUM_PUBLICS ||
            beta_off != (size_t)FAIR_PUB_BITS_OFF + DNAC_P2S_LGMH ||
            finit_off != beta_off + 2 * DNAC_P2S_FRI_R ||
            ro_off != finit_off + 2 ||
            final_off != ro_off + 2 * DNAC_P2S_NUM_ROLLIN) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
            pub_fri[(size_t)FAIR_PUB_BITS_OFF + l] =
                gold_fp_from_u64(stmt->index_bits[q][l]);
        }
        /* s3b — beta_r is ALIASED off the transcript payload, not a statement
         * field: the two lanes of round r's fp2 challenge are the (2+2r)-th and
         * (3+2r)-th non-PoW pops of the pinned script, c0 first
         * (transcript_air_table.c:308-309, the order duplex_challenger.c
         * :134-140 pops an fp2 in). There is no second field for the fri
         * instance and the transcript instance to disagree over — and no
         * per-query copy either, so EVERY query's walk folds with the SAME
         * beta, which is what the native does (:707 is outside the query loop
         * at :736). */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const size_t k0 = p2s_tair_pop_op(tsc, P2S_POP_BETA(r));
            const size_t k1 = p2s_tair_pop_op(tsc, P2S_POP_BETA(r) + 1);
            if (k0 == (size_t)-1 || k1 == (size_t)-1 ||
                k0 >= DNAC_P2S_TAIR_NUM_OPS || k1 >= DNAC_P2S_TAIR_NUM_OPS) {
                return DNAC_P2S_ERR_CFG;
            }
            pub_fri[beta_off + 2 * r] =
                gold_fp_from_u64(stmt->tair_payload[k0]);
            pub_fri[beta_off + 2 * r + 1] =
                gold_fp_from_u64(stmt->tair_payload[k1]);
        }
        pub_fri[finit_off] = gold_fp_from_u64(stmt->ro_export[q][0]);
        pub_fri[finit_off + 1] = gold_fp_from_u64(stmt->ro_export[q][1]);
        for (size_t k = 0; k < DNAC_P2S_NUM_ROLLIN; k++) {
            const size_t i = p2s_oi_height_index(P2S_FRI_ROLLIN[k]);
            if (i == (size_t)-1 || i == 0) return DNAC_P2S_ERR_CFG;
            pub_fri[ro_off + 2 * k] =
                gold_fp_from_u64(stmt->ro_export[q][2 * i]);
            pub_fri[ro_off + 2 * k + 1] =
                gold_fp_from_u64(stmt->ro_export[q][2 * i + 1]);
        }
        /* SHARED: observed once at fri_verifier.c:710-713, and a single fp2
         * because log_final_poly_len == 0 is pinned. */
        pub_fri[final_off] = gold_fp_from_u64(stmt->final_poly0[0]);
        pub_fri[final_off + 1] = gold_fp_from_u64(stmt->final_poly0[1]);
        insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI)].public_values = pub_fri;
    }

    /* oi: bits ‖ alpha ‖ (z, p_z)*total_acc ‖ ro*num_heights ‖ p_x*total_acc.
     * bits are query q's index, LSB-first and unshifted: the oi chain reads bit
     * lgmh-1-j on chain row j out of publics[bits_off + (lgmh-1-j)]
     * (fri_oi_air.c:155 maps the step to the BIT INDEX, and the honest builder
     * publishes `(index >> i) & 1` at slot i), which is the same convention the
     * fri instance uses — hence a direct alias with no shift.
     * The ro region is `ro_export[q]`, i.e. exactly the lanes the fri f_init /
     * roll-ins above were built from, for the SAME query. */
    {
        const size_t alpha_off = dnac_foi_pub_alpha_off(&P2S_OI_CFG);
        const size_t zpz_off = dnac_foi_pub_zpz_off(&P2S_OI_CFG);
        const size_t ro_off = dnac_foi_pub_ro_off(&P2S_OI_CFG);
        const size_t px_off = dnac_foi_pub_px_off(&P2S_OI_CFG);
        const size_t npub = dnac_foi_num_publics(&P2S_OI_CFG);
        const size_t tacc = dnac_foi_total_acc(&P2S_OI_CFG);
        if (npub != DNAC_P2S_OI_NUM_PUBLICS ||
            tacc != DNAC_P2S_OI_TOTAL_ACC ||
            alpha_off != (size_t)FOI_PUB_BITS_OFF + DNAC_P2S_LGMH ||
            zpz_off != alpha_off + 2 ||
            ro_off != zpz_off + 4 * DNAC_P2S_OI_TOTAL_ACC ||
            px_off != ro_off + 2 * DNAC_P2S_OI_NUM_HEIGHTS) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
            pub_oi[(size_t)FOI_PUB_BITS_OFF + l] =
                gold_fp_from_u64(stmt->index_bits[q][l]);
        }
        /* s3b — alpha is ALIASED off the transcript payload: the FIRST two
         * non-PoW pops of the pinned script, c0 first (fri_verifier.c:694 ->
         * transcript_air_table.c:299-300). SHARED across q for the same reason
         * the betas are: :694 runs once, before the query loop. */
        {
            const size_t k0 = p2s_tair_pop_op(tsc, P2S_POP_ALPHA);
            const size_t k1 = p2s_tair_pop_op(tsc, P2S_POP_ALPHA + 1);
            if (k0 == (size_t)-1 || k1 == (size_t)-1 ||
                k0 >= DNAC_P2S_TAIR_NUM_OPS || k1 >= DNAC_P2S_TAIR_NUM_OPS) {
                return DNAC_P2S_ERR_CFG;
            }
            pub_oi[alpha_off] = gold_fp_from_u64(stmt->tair_payload[k0]);
            pub_oi[alpha_off + 1] = gold_fp_from_u64(stmt->tair_payload[k1]);
        }
        /* The (z, p_z) region: the AIR's layout is FOUR lanes per acc row —
         * z at 4a, p_z at 4a + 2 — but the two halves have DIFFERENT statement
         * sources, which is the whole point of the split (HONEST LABEL 8):
         *   z   <- z_pq[q]     PER-QUERY (the builder ties z to x; x moves)
         *   p_z <- pz_shared   SHARED    (native :470 reads the claimed evals
         *                                 through `commitments`, and :743 hands
         *                                 the query loop the same pointer every
         *                                 time — so Q oi instances read the SAME
         *                                 lanes, exactly as `ro_export` is one
         *                                 source for two consumers)
         * Written as one walk over acc rows so the interleaving is stated once
         * and neither half can drift out of step with the other. */
        for (size_t a = 0; a < DNAC_P2S_OI_TOTAL_ACC; a++) {
            pub_oi[zpz_off + 4 * a] = gold_fp_from_u64(stmt->z_pq[q][2 * a]);
            pub_oi[zpz_off + 4 * a + 1] =
                gold_fp_from_u64(stmt->z_pq[q][2 * a + 1]);
            pub_oi[zpz_off + 4 * a + 2] =
                gold_fp_from_u64(stmt->pz_shared[2 * a]);
            pub_oi[zpz_off + 4 * a + 3] =
                gold_fp_from_u64(stmt->pz_shared[2 * a + 1]);
        }
        for (size_t i = 0; i < 2 * DNAC_P2S_OI_NUM_HEIGHTS; i++) {
            pub_oi[ro_off + i] = gold_fp_from_u64(stmt->ro_export[q][i]);
        }

        /* ── HONEST LABEL 3's CLOSURE: the p_x region, ONE base lane per acc
         * row in SCHEDULE order, EVERY lane an mmix opened lane.
         *
         * The walk is the schedule's own: height groups in DESCENDING order,
         * each group B consecutive blocks of `batch_sz` rows, block b belonging
         * to input batch b (fri_oi_air_table.h:104-114 — the native's nesting
         * at fri_verifier.c:207/400/436/469). So the row at block-offset `a` of
         * batch b's block takes its p_x from batch b's mmix opened row at that
         * height, FOR THIS QUERY.
         *
         * WHICH LANE OF THAT ROW: the native's innermost loop index is the
         * claimed-eval / COLUMN ordinal `j` in `p_at_x = opened_values[m][j]`
         * (fri_verifier.c:469-476, read at the query's own index), and the
         * point loop sits OUTSIDE it (:436), so under batch-major emission the
         * column of block row `a` is `a % nc_b` and the point is `a / nc_b`.
         * `nc_b` is the REAL per-batch column count, NOT the uniform
         * descriptor's — with the descriptor's nc = 1 the quotient batch's two
         * acc rows would both read column 0, dropping its second claimed
         * evaluation and duplicating the first (HONEST LABEL 5).
         *
         * `batch_sz` is read the way the AIR reads it — matrices*points*columns
         * (fri_oi_air.c's schedule walk) — and the group's total the way the
         * table module reports it, so a cfg whose descriptor changed shape
         * cannot silently re-partition this loop. Step 3a(e) has ALREADY proved
         * every (batch, height) names one matrix whose width is `nc_b` and that
         * the spans partition the row; the checks are repeated here because
         * this is where the indices are formed. ── */
        {
            size_t g = 0;
            for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
                const dnac_p2c_oi_height_desc_t *d = &P2S_OI_HEIGHTS[i];
                const size_t n_acc = dnac_p2c_oi_acc_count(d);
                const size_t batch_sz =
                    d->num_matrices * d->num_points * d->num_columns;

                if (n_acc == 0 || batch_sz == 0 ||
                    batch_sz * DNAC_P2S_OI_NUM_BATCHES != n_acc ||
                    d->num_batches != DNAC_P2S_OI_NUM_BATCHES) {
                    return DNAC_P2S_ERR_CFG;
                }
                for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
                    const size_t base = dnac_p2s_mmix_opened_off(b);
                    const size_t nc = DNAC_P2S_OI_BNC(b);
                    size_t moff = 0, mw = 0;

                    if (base == (size_t)-1 || nc == 0 ||
                        DNAC_P2S_OI_BNP(b) * nc != batch_sz) {
                        return DNAC_P2S_ERR_CFG;
                    }
                    /* Batch b MUST name exactly one matrix at this height, and
                     * that matrix's SEMANTIC width must be batch b's column
                     * count — otherwise batch b's opened row does not have a
                     * lane per acc row of its block and the alias would be
                     * reading someone else's column. */
                    if (!p2s_mmix_matrix_at_height(b, d->log_height, &moff,
                                                   &mw) ||
                        mw != nc) {
                        return DNAC_P2S_ERR_CFG;
                    }
                    if (moff + mw > DNAC_P2S_MMIX_TOTAL_OPENED(b) ||
                        base + moff + mw > DNAC_P2S_MMIX_ALL_OPENED) {
                        return DNAC_P2S_ERR_CFG;
                    }
                    for (size_t a = 0; a < batch_sz; a++, g++) {
                        if (g >= tacc) return DNAC_P2S_ERR_CFG;
                        pub_oi[px_off + g] = gold_fp_from_u64(
                            stmt->mmix_opened[q][base + moff + (a % nc)]);
                    }
                }
            }
            /* Exact partition: every acc row written exactly once. A mismatch
             * means the pinned constants and the schedule disagree — fail
             * closed rather than leave a slot unset. */
            if (g != tacc) return DNAC_P2S_ERR_CFG;
        }
        insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI)].public_values = pub_oi;
    }

    return DNAC_P2S_OK;
}

dnac_p2s_status_t dnac_p2_fri_statement_build_instances(
    const dnac_p2s_statement_t *stmt,
    dnac_batch_vinstance_t     *insts,
    dnac_p2s_fold_states_t     *states,
    gold_fp_t                  *pub)
{
    dnac_p2s_status_t st;
    const dnac_tair_script_t *tsc;

    if (!insts) return DNAC_P2S_ERR_NULL;
    /* DISARM FIRST, before any other validation: every failure path below then
     * leaves EVERY descriptor with `ctx == NULL` and `air_eval == NULL`, so
     * a caller that ignores the return code cannot keep evaluating a binding an
     * EARLIER successful call left on this array. Same discipline as each fold
     * module's bind (which disarms its descriptor on entry), applied at the
     * statement layer. */
    memset(insts, 0, DNAC_P2S_NUM_INSTANCES * sizeof(*insts));

    if (!stmt || !states || !pub) return DNAC_P2S_ERR_NULL;

    /* ── Step 3a: the cfg SET's internal consistency, before any bind. ── */
    st = p2s_check_static_consistency();
    if (st != DNAC_P2S_OK) return st;
    /* Step 3a passed, so the script exists and has the pinned shape. */
    tsc = dnac_p2s_tair_script();
    if (tsc == NULL) return DNAC_P2S_ERR_CFG;

    /* ── Step 3b: bind the PINNED cfgs into the CALLER'S state storage
     * (FLEET 034: the fold modules keep no module-static binding; each snapshot
     * is caller-owned and reached through `dnac_stark_air_t::ctx`). A bind runs
     * each module's own cfg gate, so a cfg its u64 evaluator would fail closed
     * on is rejected here by construction. Every bind is checked; a rejected
     * bind also disarms its own state.
     *
     * ⚠ Q instances of the SAME AIR share a cfg but NOT a state: query q binds
     * into `states->q[q]`. That is exactly the property FLEET 034's caller-owned
     * states bought — with the retired module-static binding, query 1's bind
     * would have clobbered query 0's and both instances would have evaluated
     * the last one bound. The R mmcs and B mmix instances of ONE query push
     * that further: they share neither a state NOR a cfg, so this is the case
     * the ctx redesign was actually built for (N-CTX-TWO). ── */
    if (dnac_transcript_air_fold_bind(&P2S_TAIR_CFG, tsc, &states->tair,
                                      &insts[DNAC_P2S_INST_TAIR].air) != 0) {
        return DNAC_P2S_ERR_CFG;
    }
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        dnac_p2s_query_fold_states_t *qs = &states->q[q];
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const dnac_p2c_mmix_table_cfg_t *cfg = dnac_p2s_mmix_cfg(b);
            if (cfg == NULL) return DNAC_P2S_ERR_CFG;
            if (dnac_mmix_air_fold_bind(
                    cfg, &qs->mmix[b],
                    &insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX(b))].air) != 0) {
                return DNAC_P2S_ERR_CFG;
            }
        }
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const dnac_p2b_table_cfg_t *cfg = dnac_p2s_mmcs_cfg(r);
            if (cfg == NULL) return DNAC_P2S_ERR_CFG;
            if (dnac_mmcs_air_fold_bind(
                    cfg, &qs->mmcs[r],
                    &insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS(r))].air) != 0) {
                return DNAC_P2S_ERR_CFG;
            }
        }
        if (dnac_fair_fold_bind(
                &P2S_FRI_CFG, &qs->fri,
                &insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI)].air) !=
            DNAC_FAIR_FOLD_OK) {
            return DNAC_P2S_ERR_CFG;
        }
        if (dnac_foi_fold_bind(
                &P2S_OI_CFG, &qs->oi,
                &insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI)].air) !=
            DNAC_FOI_FOLD_OK) {
            return DNAC_P2S_ERR_CFG;
        }
    }

    /* ── Steps 4+5, every instance, through the same slot-keyed accessors ── */
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        st = p2s_fill_geometry(&insts[i], i, dnac_p2s_num_publics(i));
        if (st != DNAC_P2S_OK) return st;
    }

    /* ── Step 6a: the transcript instance — payload ‖ exported bits[Q * lgmh].
     *
     * The payload region is the statement's own — it is the SOURCE every fri
     * instance's betas and every oi instance's alpha are aliased from, so
     * writing it here is what makes those instances and this one read the same
     * lanes.
     *
     * The exported-bit region is where the seam closes in the other direction,
     * and where OBL-P2c-2 is discharged: query q's block is `index_bits[q]`,
     * the SAME row query q's four consumers take their bit and direction
     * publics from. The transcript instance proves each block holds the low
     * lgmh bits of a challenge its own sponge produced (CT-4 + block D), and
     * query q's four consumers prove the walk that row drives. No block is left
     * unconsumed — `tair_bits_rest` is gone with the last of them.
     *
     * Offsets come from the module's own accessors (`dnac_tair_op_bit_off`),
     * never from arithmetic in this file, and each is bounds-checked against
     * the pinned public count before it is written. ── */
    {
        gold_fp_t *const pub_tair = pub + dnac_p2s_pub_off(DNAC_P2S_INST_TAIR);
        const size_t npub = dnac_tair_num_publics(tsc);
        if (npub != DNAC_P2S_TAIR_NUM_PUBLICS) return DNAC_P2S_ERR_CFG;

        for (size_t k = 0; k < DNAC_P2S_TAIR_NUM_OPS; k++) {
            pub_tair[k] = gold_fp_from_u64(stmt->tair_payload[k]);
        }
        /* ── HONEST LABEL 6's CLOSURE: the round-r digest observe lanes are
         * OVERWRITTEN from `mmcs_root[r]`.
         *
         * The native observes exactly this object — `dnac_transcript_observe_
         * digest(transcript, &proof->commit_phase_commits[round])`
         * (fri_verifier.c:702) — and the SAME array element is what round r's
         * Merkle walk is checked against (:585). Sourcing both from ONE
         * statement field is what makes "the challenger absorbed the root this
         * round verifies against" true BY CONSTRUCTION: there is no second
         * field for them to disagree in, exactly as `ro_export` leaves no room
         * between the oi export and the fri seed.
         *
         * Written AFTER the payload loop, deliberately: the payload is indexed
         * by op and copied wholesale, and these lanes are then replaced. That
         * is why `tair_payload`'s digest lanes are DEAD INPUT (field comment;
         * gate N-OBSDEAD). Step 3a has already proved each block sits between
         * the surrounding rounds' beta pops, so the ordinal really names round
         * r's digest and not some other observe run. ── */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) {
                const size_t k = p2s_tair_obs_op(tsc, DNAC_P2S_OBS_DIGEST(r, i));
                if (k == (size_t)-1 || k >= DNAC_P2S_TAIR_NUM_OPS) {
                    return DNAC_P2S_ERR_CFG;
                }
                pub_tair[k] = gold_fp_from_u64(stmt->mmcs_root[r][i]);
            }
        }
        for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
            const size_t k = p2s_tair_pop_op(tsc, P2S_POP_QUERY(q));
            size_t off;
            if (k == (size_t)-1) return DNAC_P2S_ERR_CFG;
            off = dnac_tair_op_bit_off(tsc, k);
            if (off == (size_t)-1 || off < DNAC_P2S_TAIR_NUM_OPS ||
                off + DNAC_P2S_LGMH > npub) {
                return DNAC_P2S_ERR_CFG;
            }
            for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
                /* THE alias, per query: the transcript's q-th exported index
                 * bits ARE the index query q's instances consume. LSB-first on
                 * both sides — the AIR publishes `(challenge >> l) & 1` at bit
                 * slot l (transcript_air_table.h:67-69), which is the
                 * convention `index_bits` already carries. */
                pub_tair[off + l] = gold_fp_from_u64(stmt->index_bits[q][l]);
            }
        }
        insts[DNAC_P2S_INST_TAIR].public_values = pub_tair;
    }

    /* ── Step 6b: each query's B + R + 2 consumers. ── */
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        st = p2s_build_query_publics(stmt, q, tsc, insts, pub);
        if (st != DNAC_P2S_OK) return st;
    }

    return DNAC_P2S_OK;
}

/* ==========================================================================
 * The entry
 * ======================================================================== */

dnac_p2s_status_t dnac_p2_fri_statement_verify(
    const dnac_p2s_statement_t   *stmt,
    const dnac_batch_vopened_t   *opened,
    const dnac_batch_vcommits_t  *commits,
    const uint32_t               *prep_matrix_to_instance,
    uint32_t                      num_prep_matrices,
    const dnac_fri_proof_t       *fri_proof,
    dnac_batch_verify_out_t      *out)
{
    dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
    /* FLEET 034: the fold-state snapshots the descriptors' `ctx` fields point
     * at, one per instance (1 + (B+R+2)*Q since input-batch replication).
     * SCOPE-LOCAL on purpose — it must outlive `insts`, and `insts` dies with
     * this frame, so the two lifetimes are identical by construction. Same rule
     * as the publics block below (fri_statement.h, which also states the
     * measured size and why this is neither file-scope nor heap).
     * ZERO-INITIALISED: a step-3a reject returns before any bind runs, so
     * without this the untouched states would hold indeterminate bytes. Zeroed
     * means UNBOUND, which is the fail-close value. */
    dnac_p2s_fold_states_t states;
    /* ONE flat block, sliced by `dnac_p2s_pub_off` (fri_statement.h): with
     * 1 + (B+R+2)*Q instances there is no per-AIR parameter list to write. */
    gold_fp_t pub[DNAC_P2S_TOTAL_PUBLICS];
    dnac_p2s_status_t st;
    dnac_batch_verify_status_t bs;

    memset(&states, 0, sizeof(states));

    if (!stmt || !opened || !commits || !fri_proof) return DNAC_P2S_ERR_NULL;

    /* Step 1 — before ANYTHING is derived from the statement. */
    st = p2s_check_canonical(stmt);
    if (st != DNAC_P2S_OK) return st;

    /* Step 2 — before a single gated constraint is trusted. */
    st = p2s_check_prep_root(commits, prep_matrix_to_instance,
                             num_prep_matrices);
    if (st != DNAC_P2S_OK) return st;

    /* Steps 3-6. `states` is left ARMED on success and stays valid for the
     * `dnac_batch_verify` call below — that is the whole lifetime it needs. */
    st = dnac_p2_fri_statement_build_instances(stmt, insts, &states, pub);
    if (st != DNAC_P2S_OK) return st;

    /* Step 7. is_zk / num_random_codewords / salt_elems are all zero: the
     * recursion envelope is NON-HIDING by user lock (G-DET-3, decided at P2a),
     * and dnac_batch_verify REQUIRES both counts to be stated rather than
     * defaulted precisely so a second consumer of the decode->verify pair
     * cannot inherit the repartition hole (batch_verify.h:243-268). */
    bs = dnac_batch_verify(insts, opened, DNAC_P2S_NUM_INSTANCES,
                           /* is_zk */ 0, commits, prep_matrix_to_instance,
                           num_prep_matrices, &P2S_FRI_PARAMS,
                           /* num_random_codewords */ 0, /* salt_elems */ 0,
                           fri_proof, /* rand_openings */ NULL, out);
    if (bs != DNAC_BV_OK) return DNAC_P2S_ERR_BATCH;
    return DNAC_P2S_OK;
}

/* ==========================================================================
 * The preprocessed tables, in the order the pin commits to. The LDE + commit
 * half of that pipeline is test-side (see fri_statement.h) so this module never
 * pulls in stark_prover.c.
 *
 * One table per INSTANCE, generated from the SLOT's pinned cfg — so the Q
 * copies of ONE slot come out byte-identical while the R mmcs slots do not,
 * which is what the file header's honest note describes. (The B mmix slots do
 * too at this pin, for the reason that note gives: their widths do not reach
 * the schedule. Their CFGS still differ, which is why each is generated from
 * its own rather than from batch 0's.) Written as a loop over instances rather
 * than a fixed list, so the order lives in `dnac_p2s_inst_slot` /
 * `dnac_p2s_inst_batch` / `dnac_p2s_inst_round` alone.
 * ======================================================================== */

dnac_p2s_status_t dnac_p2_fri_statement_prep_tables(uint64_t *const *out)
{
    if (!out) return DNAC_P2S_ERR_NULL;
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        if (!out[i]) return DNAC_P2S_ERR_NULL;
    }

    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        const size_t cells = dnac_p2s_prep_cells(i);
        const size_t batch = dnac_p2s_inst_batch(i);
        const size_t round = dnac_p2s_inst_round(i);

        if (i == DNAC_P2S_INST_TAIR) {
            if (dnac_tair_table_generate(dnac_p2s_tair_script(), out[i],
                                         cells) != DNAC_TAIR_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            continue;
        }
        if (batch != (size_t)-1) {
            const dnac_p2c_mmix_table_cfg_t *cfg = dnac_p2s_mmix_cfg(batch);
            if (cfg == NULL ||
                dnac_p2c_mmix_table_generate(cfg, out[i], cells) !=
                    DNAC_P2C_MMIX_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            continue;
        }
        if (round != (size_t)-1) {
            const dnac_p2b_table_cfg_t *cfg = dnac_p2s_mmcs_cfg(round);
            if (cfg == NULL ||
                dnac_p2b_table_generate(cfg, out[i], cells) !=
                    DNAC_P2B_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            continue;
        }
        switch (dnac_p2s_inst_slot(i)) {
        case DNAC_P2S_SLOT_FRI:
            if (dnac_p2c_table_generate(&P2S_FRI_CFG, out[i], cells) !=
                DNAC_P2C_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            break;
        case DNAC_P2S_SLOT_OI:
            if (dnac_p2c_oi_table_generate(&P2S_OI_CFG, out[i], cells) !=
                DNAC_P2C_OI_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            break;
        default:
            return DNAC_P2S_ERR_CFG;
        }
    }
    return DNAC_P2S_OK;
}
