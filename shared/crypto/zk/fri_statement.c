/**
 * @file fri_statement.c
 * @brief Composition s1b + s1c + s2 + s3b + MULTI-QUERY — the FRI-verify
 *        statement entry (see fri_statement.h for the pinned cfg derivation,
 *        the instance map, the shared/per-query split that discharges
 *        OBL-P2c-2, the seams still declared, and the one-pin correction).
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

static const size_t P2S_MMIX_WIDTHS[DNAC_P2S_MMIX_NUM_MATRICES] = {
    DNAC_P2S_MMIX_W0, DNAC_P2S_MMIX_W1
};
static const size_t P2S_MMIX_HEIGHTS[DNAC_P2S_MMIX_NUM_MATRICES] = {
    (size_t)1u << DNAC_P2S_MMIX_LH0, (size_t)1u << DNAC_P2S_MMIX_LH1
};
static const dnac_p2c_mmix_table_cfg_t P2S_MMIX_CFG = {
    DNAC_P2S_MMIX_NUM_MATRICES, P2S_MMIX_WIDTHS, P2S_MMIX_HEIGHTS,
    DNAC_P2S_MMIX_DEPTH, DNAC_P2S_MMIX_SALT_ELEMS
};

static const size_t P2S_MMCS_WIDTHS[1] = { DNAC_P2S_MMCS_TOTAL_WIDTH };
static const dnac_p2b_table_cfg_t P2S_MMCS_CFG = {
    1, P2S_MMCS_WIDTHS, DNAC_P2S_MMCS_DEPTH
};

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

const dnac_p2c_mmix_table_cfg_t *dnac_p2s_mmix_cfg(void) { return &P2S_MMIX_CFG; }
const dnac_p2b_table_cfg_t      *dnac_p2s_mmcs_cfg(void) { return &P2S_MMCS_CFG; }
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

/* ── instance -> (query, slot) ───────────────────────────────────────────────
 * The ONE place the instance map is decoded. Instance 0 is the transcript (no
 * query, no slot); every other instance is 1 + 4*q + slot. */

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

/* The pinned cfgs are per SLOT, not per query (the file header's honest note:
 * a table encodes the AIR's SCHEDULE and every query runs the same one), so the
 * geometry accessors below dispatch on the slot and the Q copies of a slot are
 * byte-identical. */

size_t dnac_p2s_prep_cols(uint32_t instance)
{
    if (instance == DNAC_P2S_INST_TAIR) return (size_t)TAIR_TBL_COLS;
    switch (dnac_p2s_inst_slot(instance)) {
    case DNAC_P2S_SLOT_MMIX: return (size_t)DNAC_P2C_MMIX_TABLE_COLS;
    case DNAC_P2S_SLOT_MMCS: return (size_t)DNAC_P2B_TABLE_COLS;
    case DNAC_P2S_SLOT_FRI:  return (size_t)DNAC_P2C_TABLE_COLS;
    case DNAC_P2S_SLOT_OI:   return (size_t)DNAC_P2C_OI_TABLE_COLS;
    default: return 0;
    }
}

size_t dnac_p2s_prep_rows(uint32_t instance)
{
    if (instance == DNAC_P2S_INST_TAIR) {
        return dnac_tair_table_rows(dnac_p2s_tair_script());
    }
    switch (dnac_p2s_inst_slot(instance)) {
    case DNAC_P2S_SLOT_MMIX: return dnac_p2c_mmix_table_rows(&P2S_MMIX_CFG);
    case DNAC_P2S_SLOT_MMCS: return dnac_p2b_table_rows(&P2S_MMCS_CFG);
    case DNAC_P2S_SLOT_FRI:  return dnac_p2c_table_rows(&P2S_FRI_CFG);
    case DNAC_P2S_SLOT_OI:   return dnac_p2c_oi_table_rows(&P2S_OI_CFG);
    default: return 0;
    }
}

size_t dnac_p2s_num_publics(uint32_t instance)
{
    if (instance == DNAC_P2S_INST_TAIR) return DNAC_P2S_TAIR_NUM_PUBLICS;
    switch (dnac_p2s_inst_slot(instance)) {
    case DNAC_P2S_SLOT_MMIX: return DNAC_P2S_MMIX_NUM_PUBLICS;
    case DNAC_P2S_SLOT_MMCS: return DNAC_P2S_MMCS_NUM_PUBLICS;
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
        !p2s_canon_span(&s->px_rest[0][0],
                        DNAC_P2S_NUM_QUERIES * DNAC_P2S_OI_PX_REST) ||
        !p2s_canon_span(s->mmix_root, (size_t)MMIX_DIGEST_LANES) ||
        !p2s_canon_span(s->mmcs_root, (size_t)MAIR_DIGEST_LANES) ||
        !p2s_canon_span(&s->mmix_opened[0][0],
                        DNAC_P2S_NUM_QUERIES * DNAC_P2S_MMIX_TOTAL_OPENED) ||
        !p2s_canon_span(&s->mmcs_opened[0][0],
                        DNAC_P2S_NUM_QUERIES * DNAC_P2S_MMCS_TOTAL_WIDTH)) {
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
                2 * DNAC_P2S_OI_NUM_HEIGHTS + DNAC_P2S_OI_PX_REST +
                DNAC_P2S_MMIX_TOTAL_OPENED + DNAC_P2S_MMCS_TOTAL_WIDTH) +
           DNAC_P2S_TAIR_NUM_OPS + 2 + 2 * DNAC_P2S_OI_TOTAL_ACC +
           (size_t)MMIX_DIGEST_LANES + (size_t)MAIR_DIGEST_LANES))
         ? 1
         : -1];

/* At least one query, or the per-query C arrays would have length zero, which
 * is not valid C. (The old `Q >= 2` rail existed only because `tair_bits_rest`
 * held queries 1..Q-1; with every query consumed, Q == 1 is a legal pin again
 * and this is the honest bound.) */
typedef char p2s_num_queries_nonzero_assert
    [(DNAC_P2S_NUM_QUERIES >= 1) ? 1 : -1];

/* Same hazard, one field down: `px_rest` is a C array whose length is the acc
 * rows the MAIN batch does NOT cover. A pinned oi cfg with only the main batch
 * would make it zero-length. */
typedef char p2s_px_rest_nonempty_assert
    [(DNAC_P2S_OI_PX_REST >= 1) ? 1 : -1];

/* The Q CEILING. `dnac_batch_verify` / `dnac_batch_prove` reject an instance
 * count past their (unexported) cap — batch_verify.c:20 + :86 and
 * batch_prover.c:22 + :210/:247, both 32 — so a Q whose 1 + 4*Q overruns it
 * would be a RUNTIME reject on every honest proof. Fail at BUILD time instead.
 * DNAC_P2S_MAX_QUERIES is derived from the mirrored cap, never written out. */
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

/* ── s2: the height -> main-batch-matrix map, DERIVED from the mmix cfg ──────
 * The main input batch is the batch the mmix instance describes, and its opened
 * region is flattened in MATRIX order using the SEMANTIC widths
 * (mmcs_mixed_air.h "Public values": root ‖ dir ‖ opened rows per matrix). So
 * an oi height picks out the mmix matrix committed at that height and, with it,
 * the offset of that matrix's opened row inside `stmt.mmix_opened`.
 *
 * Nothing here is read from a proof and nothing is hard-coded: the heights and
 * widths are the same pinned arrays the mmix cfg is built from.
 */

/** Compile-time: the p_x map needs ONE matrix per batch per height, so that the
 *  height alone determines the matrix. The pinned oi group descriptor says so
 *  (DNAC_P2S_OI_NUM_MATRICES); this stops the build if it ever stops saying so,
 *  rather than letting the mapping below quietly pick the wrong lane. */
typedef char p2s_oi_one_matrix_per_batch_assert
    [(DNAC_P2S_OI_NUM_MATRICES == 1) ? 1 : -1];

/**
 * Offset + semantic width of the mmix matrix at `log_height`.
 * @return 1 iff EXACTLY ONE pinned mmix matrix sits at that height (fail-close:
 *         zero or several make the height->matrix map ambiguous).
 */
static int p2s_mmix_matrix_at_height(size_t log_height, size_t *out_off,
                                     size_t *out_width)
{
    const size_t want = (size_t)1u << log_height;
    size_t off = 0, found_off = 0, found_w = 0, n = 0;

    for (size_t m = 0; m < DNAC_P2S_MMIX_NUM_MATRICES; m++) {
        if (P2S_MMIX_HEIGHTS[m] == want) {
            found_off = off;
            found_w = P2S_MMIX_WIDTHS[m];
            n++;
        }
        off += P2S_MMIX_WIDTHS[m];
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
    size_t npops = 0;

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
    }
    if (npops != P2S_POP_TOTAL) return DNAC_P2S_ERR_CFG;

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

/* ── Step 6, one query's four consumers ──────────────────────────────────────
 * Every module's own offset accessors place the regions — this file never
 * hard-codes an offset — and every accessor is cross-checked against the pinned
 * arithmetic, so a layout change in a module surfaces as a reject, not as a
 * silent misalignment.
 *
 * ⚠ THE WHOLE POINT OF THE MULTI-QUERY SLICE IS THE `q` IN THIS FUNCTION'S
 * SIGNATURE. Everything read out of `stmt` here is either
 *   - a PER-QUERY region indexed by `q` (index_bits, ro_export, mmix_opened,
 *     mmcs_opened, z_pq, px_rest), or
 *   - a SHARED region with no query index at all (tair_payload, final_poly0,
 *     pz_shared, the two roots),
 * and the split is the native's: the shared ones are sampled or observed BEFORE
 * the per-query loop at fri_verifier.c:736, the per-query ones inside it.
 * Feeding `q = 0` to every call would put Q identical instances in the batch —
 * the `lb*Q -> lb` collapse OBL-P2c-2 names (fri_air.h). */
static dnac_p2s_status_t p2s_build_query_publics(
    const dnac_p2s_statement_t *stmt, size_t q,
    const dnac_tair_script_t *tsc, dnac_batch_vinstance_t *insts,
    gold_fp_t *pub)
{
    gold_fp_t *pub_mmix, *pub_mmcs, *pub_fri, *pub_oi;

    /* BEFORE any offset is formed: `dnac_p2s_pub_off` reports SIZE_MAX for an
     * out-of-range instance, and `pub + SIZE_MAX` would be undefined behaviour
     * rather than a rejected pointer. */
    if (q >= DNAC_P2S_NUM_QUERIES) return DNAC_P2S_ERR_CFG;

    pub_mmix = pub + dnac_p2s_pub_off(DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX));
    pub_mmcs = pub + dnac_p2s_pub_off(DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS));
    pub_fri = pub + dnac_p2s_pub_off(DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI));
    pub_oi = pub + dnac_p2s_pub_off(DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI));

    /* mmix: root ‖ dir ‖ opened.
     * dir[l] = index_bits[q][(lgmh - max_lh) + l]: the mixed MMCS walks the
     * REDUCED index `index >> (log_global_max_height - max_log_height)`
     * (fri_verifier.c:252-255). Here max_lh == lgmh, so the shift is 0 and the
     * full index is consumed — written as the general expression so the alias
     * stays correct if the pinned heights ever change. */
    {
        const size_t opened_off = dnac_mmix_air_pub_opened_off(&P2S_MMIX_CFG);
        const size_t npub = dnac_mmix_air_num_publics(&P2S_MMIX_CFG);
        const size_t shift = DNAC_P2S_LGMH - DNAC_P2S_MMIX_DEPTH;
        if (npub != DNAC_P2S_MMIX_NUM_PUBLICS ||
            opened_off != (size_t)MMIX_PUB_DIR_OFF + DNAC_P2S_MMIX_DEPTH) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
            pub_mmix[(size_t)MMIX_PUB_ROOT_OFF + k] =
                gold_fp_from_u64(stmt->mmix_root[k]); /* SHARED */
        }
        for (size_t l = 0; l < DNAC_P2S_MMIX_DEPTH; l++) {
            pub_mmix[(size_t)MMIX_PUB_DIR_OFF + l] =
                gold_fp_from_u64(stmt->index_bits[q][shift + l]);
        }
        for (size_t c = 0; c < DNAC_P2S_MMIX_TOTAL_OPENED; c++) {
            pub_mmix[opened_off + c] =
                gold_fp_from_u64(stmt->mmix_opened[q][c]);
        }
        insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX)].public_values = pub_mmix;
    }

    /* mmcs (commit round 0): root ‖ dir ‖ opened.
     * dir[l] = index_bits[q][log_arity + l]: verify_query shifts the index DOWN
     * by log_arity (fri_verifier.c:558) BEFORE handing it to the MMCS together
     * with height 2^log_folded_height (:585-588), so round 0 consumes bits
     * starting at log_arity over `depth` levels. */
    {
        const size_t opened_off = dnac_mmcs_air_pub_opened_off(&P2S_MMCS_CFG);
        const size_t npub = dnac_mmcs_air_num_publics(&P2S_MMCS_CFG);
        const size_t total = dnac_mmcs_air_total_width(&P2S_MMCS_CFG);
        if (npub != DNAC_P2S_MMCS_NUM_PUBLICS ||
            total != DNAC_P2S_MMCS_TOTAL_WIDTH ||
            opened_off != (size_t)MAIR_PUB_DIR_OFF + DNAC_P2S_MMCS_DEPTH) {
            return DNAC_P2S_ERR_CFG;
        }
        for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
            pub_mmcs[(size_t)MAIR_PUB_ROOT_OFF + k] =
                gold_fp_from_u64(stmt->mmcs_root[k]); /* SHARED */
        }
        for (size_t l = 0; l < DNAC_P2S_MMCS_DEPTH; l++) {
            pub_mmcs[(size_t)MAIR_PUB_DIR_OFF + l] = gold_fp_from_u64(
                stmt->index_bits[q][DNAC_P2S_MAX_LOG_ARITY + l]);
        }
        for (size_t c = 0; c < DNAC_P2S_MMCS_TOTAL_WIDTH; c++) {
            pub_mmcs[opened_off + c] =
                gold_fp_from_u64(stmt->mmcs_opened[q][c]);
        }
        insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS)].public_values = pub_mmcs;
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

        /* ── s2: the p_x region, ONE base lane per acc row in SCHEDULE order.
         * The walk is the schedule's own: height groups in DESCENDING order,
         * each group's rows batch-major (fri_oi_air_table.h:104-114). Batch 0
         * is the MAIN round — the batch query q's mmix instance describes — so
         * the first `batch_sz` rows of each group take their p_x from that
         * height's mmix opened lane FOR THIS QUERY (native: p_at_x =
         * bo->opened_values[m][j], fri_verifier.c:469-476, read at the query's
         * own index), and the rest take it from `px_rest[q]`.
         *
         * `batch_sz` is read the way the AIR reads it — matrices*points*columns
         * (fri_oi_air.c's schedule walk) — and the group's total the way the
         * table module reports it, so a cfg whose descriptor changed shape
         * cannot silently re-partition this loop. ── */
        {
            size_t g = 0, rest = 0;
            for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
                const dnac_p2c_oi_height_desc_t *d = &P2S_OI_HEIGHTS[i];
                const size_t n_acc = dnac_p2c_oi_acc_count(d);
                const size_t batch_sz =
                    d->num_matrices * d->num_points * d->num_columns;
                size_t moff = 0, mw = 0;

                if (n_acc == 0 || batch_sz == 0 || batch_sz > n_acc) {
                    return DNAC_P2S_ERR_CFG;
                }
                /* The height MUST name exactly one mmix matrix, and that
                 * matrix's SEMANTIC width must be the claimed-eval count the oi
                 * group descriptor declares — otherwise `stmt.mmix_opened[q]`
                 * does not have a lane per main-batch acc row and the alias
                 * would be reading someone else's column. */
                if (!p2s_mmix_matrix_at_height(d->log_height, &moff, &mw) ||
                    mw != d->num_columns) {
                    return DNAC_P2S_ERR_CFG;
                }
                if (moff + mw > DNAC_P2S_MMIX_TOTAL_OPENED) {
                    return DNAC_P2S_ERR_CFG;
                }

                for (size_t a = 0; a < n_acc; a++, g++) {
                    if (g >= tacc) return DNAC_P2S_ERR_CFG;
                    if (a < batch_sz) {
                        /* main batch: (matrix 0, point a/columns, column
                         * a%columns) — the batch-major tuple order. */
                        pub_oi[px_off + g] = gold_fp_from_u64(
                            stmt->mmix_opened[q][moff + (a % d->num_columns)]);
                    } else {
                        if (rest >= DNAC_P2S_OI_PX_REST) {
                            return DNAC_P2S_ERR_CFG;
                        }
                        pub_oi[px_off + g] =
                            gold_fp_from_u64(stmt->px_rest[q][rest]);
                        rest++;
                    }
                }
            }
            /* Exact partition: every acc row written once, every px_rest lane
             * consumed once. A mismatch means the pinned constants and the
             * schedule disagree — fail closed rather than leave a slot unset. */
            if (g != tacc || rest != DNAC_P2S_OI_PX_REST) {
                return DNAC_P2S_ERR_CFG;
            }
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
     * the last one bound. ── */
    if (dnac_transcript_air_fold_bind(&P2S_TAIR_CFG, tsc, &states->tair,
                                      &insts[DNAC_P2S_INST_TAIR].air) != 0) {
        return DNAC_P2S_ERR_CFG;
    }
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        dnac_p2s_query_fold_states_t *qs = &states->q[q];
        if (dnac_mmix_air_fold_bind(
                &P2S_MMIX_CFG, &qs->mmix,
                &insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX)].air) != 0) {
            return DNAC_P2S_ERR_CFG;
        }
        if (dnac_mmcs_air_fold_bind(
                &P2S_MMCS_CFG, &qs->mmcs,
                &insts[DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS)].air) != 0) {
            return DNAC_P2S_ERR_CFG;
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

    /* ── Step 6b: each query's four consumers. ── */
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
     * at, one per instance (1 + 4*Q since the multi-query slice). SCOPE-LOCAL
     * on purpose — it must outlive `insts`, and `insts` dies with this frame,
     * so the two lifetimes are identical by construction. Same rule as the
     * publics block below (fri_statement.h, which also states the ~11.3 KB size
     * and why this is neither file-scope nor heap).
     * ZERO-INITIALISED: a step-3a reject returns before any bind runs, so
     * without this the untouched states would hold indeterminate bytes. Zeroed
     * means UNBOUND, which is the fail-close value. */
    dnac_p2s_fold_states_t states;
    /* ONE flat block, sliced by `dnac_p2s_pub_off` (fri_statement.h): with
     * 1 + 4*Q instances there is no per-AIR parameter list to write. */
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
 * copies of a slot come out byte-identical, which is what the file header's
 * honest note describes. Written as a loop over instances rather than a fixed
 * list, so the order lives in `dnac_p2s_inst_slot` alone.
 * ======================================================================== */

dnac_p2s_status_t dnac_p2_fri_statement_prep_tables(uint64_t *const *out)
{
    if (!out) return DNAC_P2S_ERR_NULL;
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        if (!out[i]) return DNAC_P2S_ERR_NULL;
    }

    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        const size_t cells = dnac_p2s_prep_cells(i);

        if (i == DNAC_P2S_INST_TAIR) {
            if (dnac_tair_table_generate(dnac_p2s_tair_script(), out[i],
                                         cells) != DNAC_TAIR_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            continue;
        }
        switch (dnac_p2s_inst_slot(i)) {
        case DNAC_P2S_SLOT_MMIX:
            if (dnac_p2c_mmix_table_generate(&P2S_MMIX_CFG, out[i], cells) !=
                DNAC_P2C_MMIX_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            break;
        case DNAC_P2S_SLOT_MMCS:
            if (dnac_p2b_table_generate(&P2S_MMCS_CFG, out[i], cells) !=
                DNAC_P2B_TABLE_OK) {
                return DNAC_P2S_ERR_CFG;
            }
            break;
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
