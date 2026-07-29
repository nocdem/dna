/**
 * @file fri_air_table.c
 * @brief P2c preprocessed row-type table generator + static validator + the
 *        PIN-1-P2c comparator.
 *
 * See fri_air_table.h for the full grounding contract (row schedule from design
 * §0.5 :229-266; R = lgmh - log_blowup - log_final_poly_len as the native round
 * count, fri_verifier.c:640-649; per-phase post-fold height and the roll-in
 * match, fri_verifier.c:594-605; the D3 lgmh bound, fri_verifier.c:689-691;
 * PIN-1 derivation from batch_prover.c:787-826).
 *
 * Determinism (design §1 D-1): every function is a pure function of the cfg
 * SCALARS — fixed-bound loops only, no allocation, no clock, no RNG, no
 * iteration over anything unordered.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_air_table.h"

#include <string.h>

#include "field_goldilocks.h"

/* The pinned reference config (fri_air_table.h DNAC_P2C_REF_*). */
static const size_t P2C_REF_ROLLIN[DNAC_P2C_REF_NUM_ROLLIN] = {
    DNAC_P2C_REF_ROLLIN_0, DNAC_P2C_REF_ROLLIN_1
};
static const dnac_p2c_table_cfg_t P2C_REF_CFG = {
    DNAC_P2C_REF_LGMH,          DNAC_P2C_REF_LOG_BLOWUP,
    DNAC_P2C_REF_LOG_FINAL_POLY_LEN, DNAC_P2C_REF_MAX_LOG_ARITY,
    DNAC_P2C_REF_NUM_ROLLIN,    P2C_REF_ROLLIN,
    DNAC_P2C_REF_NUM_QUERIES
};

const dnac_p2c_table_cfg_t *dnac_p2c_ref_cfg(void) { return &P2C_REF_CFG; }

/* ==========================================================================
 * Config gate — ONE place, so rows(), row(), generate() and validate() can
 * never disagree about what they accept. Mirrors the AIR's eval-entry gates
 * G1/G2/G3/G7 (design §0.5 :276-290); the AIR re-runs them at its own entry
 * because a table is not a proof.
 *
 * Returns 0 on reject; on accept writes n_chain = lgmh - 1 and R.
 * ======================================================================== */
static int p2c_cfg_check(const dnac_p2c_table_cfg_t *cfg, size_t *out_chain,
                         size_t *out_fold)
{
    if (cfg == NULL) return 0;

    /* G1 — only the arity-2 fold form is ported (design §0.1 :63-66). */
    if (cfg->max_log_arity != 1) return 0;
    /* G2 — lfpl = 0 makes the terminal x-independent; >0 needs new columns
     * (design §0.1 :67-72). */
    if (cfg->log_final_poly_len != 0) return 0;
    /* G3 / G7 — lgmh in [2, 32]: below 2 there is no chain anchor, above 32 the
     * two-adic generator degenerates (fri_verifier.c:689-691,
     * field_goldilocks.c:207-209). */
    if (cfg->lgmh < DNAC_P2C_MIN_LGMH || cfg->lgmh > DNAC_P2C_MAX_LGMH) return 0;

    /* G7 — R underflow. Written as an addition so it cannot wrap on size_t. */
    if (cfg->log_blowup > DNAC_P2C_MAX_LGMH) return 0;
    const size_t final_h = cfg->log_blowup + cfg->log_final_poly_len;
    if (cfg->lgmh < final_h + 1) return 0; /* R >= 1: at least one fold phase */

    const size_t n_chain = cfg->lgmh - 1;
    const size_t n_fold = cfg->lgmh - final_h;

    /* One-hot capacity (design §0.5 :262-263).
     * ⚠ UNREACHABLE at DNAC_P2C_MAX_LGMH == 32: the extremal shape
     * (lgmh 32, log_blowup 0, lfpl 0) gives 31 + 32 = 63 <= 64. Kept fail-close
     * so that lowering MAX_STEPS, raising MAX_LGMH, or generalizing the arity
     * cannot silently overflow the one-hot instead of rejecting. No negative
     * test can trip it; that is a property of the bounds, not a gap. */
    if (n_chain + n_fold > DNAC_P2C_MAX_STEPS) return 0;

    /* Roll-in schedule. Post-fold height of phase r is lgmh - 1 - r
     * (fri_verifier.c:596), so the reachable heights are exactly
     * [final_h, lgmh - 1]; the native consumes reduced openings in a single
     * monotone sweep (`ro_i` only advances, fri_verifier.c:600-605), which is
     * why STRICTLY DESCENDING is a requirement and not a convention. */
    if (cfg->num_rollin > DNAC_P2C_MAX_ROLLIN || cfg->num_rollin > n_fold) {
        return 0;
    }
    if (cfg->num_rollin > 0 && cfg->rollin_heights == NULL) return 0;
    for (size_t i = 0; i < cfg->num_rollin; i++) {
        const size_t h = cfg->rollin_heights[i];
        if (h < final_h || h > cfg->lgmh - 1) return 0;
        if (i > 0 && h >= cfg->rollin_heights[i - 1]) return 0;
    }

    /* D2 — the query count is EXACT (fri_verifier.c:116-118) and 0 is rejected
     * natively (fri_verifier.c:686-688). Does not enter the table. */
    if (cfg->num_queries == 0 || cfg->num_queries > DNAC_P2C_MAX_QUERIES) {
        return 0;
    }

    *out_chain = n_chain;
    *out_fold = n_fold;
    return 1;
}

/* Is fold phase `r`'s POST-FOLD height a cfg-pinned roll-in height? Fixed loop
 * over at most DNAC_P2C_MAX_ROLLIN entries — no container, no ordering
 * dependence beyond the descending invariant p2c_cfg_check already enforced. */
static int p2c_phase_has_rollin(const dnac_p2c_table_cfg_t *cfg, size_t r)
{
    const size_t post = cfg->lgmh - 1 - r;
    for (size_t i = 0; i < cfg->num_rollin; i++) {
        if (cfg->rollin_heights[i] == post) return 1;
    }
    return 0;
}

/* G_j = g_lgmh^{2^j}. The two-adic ladder gives g_{lgmh-j} = g_lgmh^{2^j}
 * directly (field_goldilocks.c:210-220 squaring ladder; design §0.5b :186-187),
 * so no exponentiation is needed here. j <= lgmh - 2 ⇒ the argument stays in
 * [2, 32] and never hits the degenerate bits == 0 / bits > 32 branch. */
static uint64_t p2c_g_pow2(size_t lgmh, size_t j)
{
    return gold_fp_to_u64(gold_fp_two_adic_generator((unsigned)(lgmh - j)));
}

/* Round up to a power of two, minimum DNAC_P2C_MIN_ROWS. Returns 0 on overflow
 * (unreachable at the bounds above — used + 1 <= 64; kept fail-close). */
static size_t p2c_pad_pow2(size_t used)
{
    size_t h = DNAC_P2C_MIN_ROWS;
    while (h < used) {
        if (h > (size_t)-1 / 2) return 0;
        h <<= 1;
    }
    return h;
}

/* ==========================================================================
 * Shape accessors
 * ======================================================================== */

size_t dnac_p2c_chain_rows(const dnac_p2c_table_cfg_t *cfg)
{
    size_t n_chain = 0, n_fold = 0;
    if (!p2c_cfg_check(cfg, &n_chain, &n_fold)) return 0;
    return n_chain;
}

size_t dnac_p2c_fold_rows(const dnac_p2c_table_cfg_t *cfg)
{
    size_t n_chain = 0, n_fold = 0;
    if (!p2c_cfg_check(cfg, &n_chain, &n_fold)) return 0;
    return n_fold;
}

size_t dnac_p2c_table_rows(const dnac_p2c_table_cfg_t *cfg)
{
    size_t n_chain = 0, n_fold = 0;
    if (!p2c_cfg_check(cfg, &n_chain, &n_fold)) return 0;
    /* +1 = the mandatory terminal padding row (design §0.5 :236). */
    return p2c_pad_pow2(n_chain + n_fold + 1);
}

/* ==========================================================================
 * Row record — the single source both the cell writer and the tests read
 * ======================================================================== */

dnac_p2c_table_status_t dnac_p2c_table_row(const dnac_p2c_table_cfg_t *cfg,
                                           size_t row, dnac_p2c_row_t *out)
{
    size_t n_chain = 0, n_fold = 0;
    if (out == NULL || !p2c_cfg_check(cfg, &n_chain, &n_fold)) {
        return DNAC_P2C_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2c_table_rows(cfg);
    if (rows == 0 || row >= rows) return DNAC_P2C_TABLE_ERR_PARAM;

    memset(out, 0, sizeof(*out));
    out->step = SIZE_MAX;
    out->type_step = SIZE_MAX;

    if (row < n_chain) {
        /* Chain rows absorb the index bits MSB-first: chain row j reads bit
         * public b_{lgmh-1-j} (design §0.5 C2 :331-338). */
        out->type = DNAC_P2C_ROW_CHAIN;
        out->step = row;
        out->type_step = row;
        out->is_chainpair = (row + 1 < n_chain) ? 1 : 0;
        out->is_handoff = (row + 1 == n_chain) ? 1 : 0;
        out->g_pow2 = p2c_g_pow2(cfg->lgmh, row);
    } else if (row < n_chain + n_fold) {
        /* Fold rows are the FRI phases, LSB-first: fold row r reads bit public
         * b_r and beta pair r (design §0.5 :258-262). */
        const size_t r = row - n_chain;
        out->type = DNAC_P2C_ROW_FOLD;
        out->step = row;
        out->type_step = r;
        out->is_foldpair = (r + 1 < n_fold) ? 1 : 0;
        out->is_rollin = p2c_phase_has_rollin(cfg, r);
    } else {
        /* Padding. is_terminal marks the FIRST padding row — the row C5's
         * `f == final_poly[0]` boundary lives on, reached by the last fold
         * row's C4 transition (design §0.5 :383-387). */
        out->type = DNAC_P2C_ROW_PAD;
        out->is_terminal = (row == n_chain + n_fold) ? 1 : 0;
    }
    return DNAC_P2C_TABLE_OK;
}

/* ==========================================================================
 * Generator
 * ======================================================================== */

dnac_p2c_table_status_t dnac_p2c_table_generate(
    const dnac_p2c_table_cfg_t *cfg, uint64_t *out, size_t out_cells)
{
    size_t n_chain = 0, n_fold = 0;
    if (out == NULL || !p2c_cfg_check(cfg, &n_chain, &n_fold)) {
        return DNAC_P2C_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2c_table_rows(cfg);
    if (rows == 0) return DNAC_P2C_TABLE_ERR_PARAM;
    if (out_cells < rows * (size_t)DNAC_P2C_TABLE_COLS) {
        return DNAC_P2C_TABLE_ERR_CAPACITY;
    }

    /* Every cell defaults to 0: padding rows carry no type, no pair gate, no
     * G literal and an all-zero step one-hot (design §0.5, P2b precedent
     * mmcs_air_table.c:99-100). */
    memset(out, 0, rows * (size_t)DNAC_P2C_TABLE_COLS * sizeof(uint64_t));

    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_row_t rec;
        const dnac_p2c_table_status_t st = dnac_p2c_table_row(cfg, r, &rec);
        if (st != DNAC_P2C_TABLE_OK) return st; /* unreachable; fail-close */

        uint64_t *row = &out[r * (size_t)DNAC_P2C_TABLE_COLS];
        switch (rec.type) {
        case DNAC_P2C_ROW_CHAIN: row[DNAC_P2C_COL_IS_CHAIN] = 1; break;
        case DNAC_P2C_ROW_FOLD:  row[DNAC_P2C_COL_IS_FOLD] = 1; break;
        case DNAC_P2C_ROW_PAD:   row[DNAC_P2C_COL_IS_PAD] = 1; break;
        }
        row[DNAC_P2C_COL_IS_CHAINPAIR] = (uint64_t)rec.is_chainpair;
        row[DNAC_P2C_COL_IS_HANDOFF] = (uint64_t)rec.is_handoff;
        row[DNAC_P2C_COL_IS_FOLDPAIR] = (uint64_t)rec.is_foldpair;
        row[DNAC_P2C_COL_IS_TERMINAL] = (uint64_t)rec.is_terminal;
        row[DNAC_P2C_COL_IS_ROLLIN] = (uint64_t)rec.is_rollin;
        row[DNAC_P2C_COL_G_POW2] = rec.g_pow2;
        if (rec.step != SIZE_MAX) {
            row[dnac_p2c_col_pos(rec.step)] = 1;
        }
    }
    return DNAC_P2C_TABLE_OK;
}

/* ==========================================================================
 * Static validator — structural, NOT a memcmp against the generator (that
 * would be circular). Check order is the header's contract.
 * ======================================================================== */

#define P2C_FAIL(d)                                                           \
    do {                                                                      \
        if (out_defect) *out_defect = (d);                                    \
        return DNAC_P2C_TABLE_ERR_SCHEDULE;                                   \
    } while (0)

dnac_p2c_table_status_t dnac_p2c_table_validate(
    const dnac_p2c_table_cfg_t *cfg, const uint64_t *cells, size_t rows,
    dnac_p2c_table_defect_t *out_defect)
{
    if (out_defect) *out_defect = DNAC_P2C_DEFECT_NONE;

    size_t n_chain = 0, n_fold = 0;
    if (cells == NULL || !p2c_cfg_check(cfg, &n_chain, &n_fold)) {
        return DNAC_P2C_TABLE_ERR_PARAM;
    }
    const size_t exp_rows = dnac_p2c_table_rows(cfg);
    if (exp_rows == 0 || rows != exp_rows) return DNAC_P2C_TABLE_ERR_PARAM;

    const size_t cols = (size_t)DNAC_P2C_TABLE_COLS;
    const size_t sched = n_chain + n_fold; /* scheduled (non-padding) rows */

    /* 1 — canonicality. Non-canonical preprocessed cells alias mod p, the
     *     OBL-2 class (mmcs_air.h:93-94). */
    for (size_t r = 0; r < rows; r++) {
        for (size_t k = 0; k < cols; k++) {
            if (cells[r * cols + k] >= GOLDILOCKS_P) {
                P2C_FAIL(DNAC_P2C_DEFECT_CANONICAL);
            }
        }
    }

    /* 2 — booleanity of every cell except the g_pow2 field literal. Nothing on
     *     the verify path checks this (batch_verify.c:722-727 hands the window
     *     to air_eval raw), so it is checked HERE and frozen by the root pin. */
    for (size_t r = 0; r < rows; r++) {
        for (size_t k = 0; k < cols; k++) {
            if (k == (size_t)DNAC_P2C_COL_G_POW2) continue;
            const uint64_t v = cells[r * cols + k];
            if (v > 1) P2C_FAIL(DNAC_P2C_DEFECT_BOOLEAN);
        }
    }

    /* 3 — exactly one row type per row. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        const uint64_t set = row[DNAC_P2C_COL_IS_CHAIN] +
                             row[DNAC_P2C_COL_IS_FOLD] +
                             row[DNAC_P2C_COL_IS_PAD];
        if (set != 1) P2C_FAIL(DNAC_P2C_DEFECT_TYPE_EXCLUSIVE);
    }

    /* 4 — TYPED-PREFIX order: chain rows, then fold rows, then padding, with no
     *     interleave (design §0.6 "Typed-prefix residual" :210, §4 item 3). */
    size_t n_chain_seen = 0, n_fold_seen = 0, n_pad_seen = 0;
    {
        unsigned prev = 0; /* 0 chain, 1 fold, 2 pad */
        for (size_t r = 0; r < rows; r++) {
            const uint64_t *row = &cells[r * cols];
            unsigned t;
            if (row[DNAC_P2C_COL_IS_CHAIN]) {
                t = 0;
                n_chain_seen++;
            } else if (row[DNAC_P2C_COL_IS_FOLD]) {
                t = 1;
                n_fold_seen++;
            } else {
                t = 2;
                n_pad_seen++;
            }
            if (t < prev) P2C_FAIL(DNAC_P2C_DEFECT_PREFIX_ORDER);
            prev = t;
        }
    }

    /* 5 — type counts. With 3+4 already green these pin the layout exactly:
     *     chain = [0, n_chain), fold = [n_chain, n_chain+R), pad = the rest,
     *     and the pad block is non-empty (terminality, design §0.5 :236). */
    if (n_chain_seen != n_chain || n_fold_seen != n_fold ||
        n_pad_seen != rows - sched || n_pad_seen == 0) {
        P2C_FAIL(DNAC_P2C_DEFECT_TYPE_COUNT);
    }

    /* 6 — step one-hot: scheduled row k carries pos[k] = 1 and nothing else;
     *     padding rows carry an all-zero one-hot. This is the "advance +1 /
     *     row-0 anchor / per-position type agreement" bundle P2b had to
     *     discharge in-AIR (mmcs_air.h:166-169) and P2c freezes in the table. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        for (size_t k = 0; k < DNAC_P2C_MAX_STEPS; k++) {
            const uint64_t want = (r < sched && k == r) ? 1u : 0u;
            if (row[dnac_p2c_col_pos(k)] != want) {
                P2C_FAIL(DNAC_P2C_DEFECT_POS_ONEHOT);
            }
        }
    }

    /* 7 — C3's MULTIPLICATION COUNT identity (design §0.5 :350-352, the A2-F4
     *     anchor): the row-0 multiply-from-1 plus one multiply per chain pair
     *     must absorb exactly lgmh - 1 bits. Checked BEFORE placement so a
     *     single flipped cell trips the COUNT and a moved cell trips 8. */
    {
        size_t pairs = 0;
        for (size_t r = 0; r < rows; r++) {
            pairs += (size_t)cells[r * cols + DNAC_P2C_COL_IS_CHAINPAIR];
        }
        if (1 + pairs != cfg->lgmh - 1) P2C_FAIL(DNAC_P2C_DEFECT_MULCOUNT);
    }

    /* 8 — is_chainpair placement: set iff this row AND its successor are chain
     *     rows (layout pinned by 4+5). */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t want = (r + 1 < n_chain) ? 1u : 0u;
        if (cells[r * cols + DNAC_P2C_COL_IS_CHAINPAIR] != want) {
            P2C_FAIL(DNAC_P2C_DEFECT_CHAINPAIR);
        }
    }

    /* 9 — exactly one is_handoff, on the LAST chain row. n_chain >= 1 is
     *     guaranteed by the lgmh >= 2 gate. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t want = (r + 1 == n_chain) ? 1u : 0u;
        if (cells[r * cols + DNAC_P2C_COL_IS_HANDOFF] != want) {
            P2C_FAIL(DNAC_P2C_DEFECT_HANDOFF);
        }
    }

    /* 10 — is_foldpair placement: set iff this row AND its successor are fold
     *      rows. The LAST fold row intentionally has no successor x0
     *      (design §0.5 :374-376) — stated there, enforced here. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t want = (r >= n_chain && r + 1 < sched) ? 1u : 0u;
        if (cells[r * cols + DNAC_P2C_COL_IS_FOLDPAIR] != want) {
            P2C_FAIL(DNAC_P2C_DEFECT_FOLDPAIR);
        }
    }

    /* 11 — exactly one is_terminal, on the FIRST padding row. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t want = (r == sched) ? 1u : 0u;
        if (cells[r * cols + DNAC_P2C_COL_IS_TERMINAL] != want) {
            P2C_FAIL(DNAC_P2C_DEFECT_TERMINAL);
        }
    }

    /* 12 — roll-in slots. Count first (a cleared or injected slot), then
     *      placement (a moved slot). Divergence D1 (design §0.3 :112-124): the
     *      AIR carries a roll-in slot ONLY where the cfg pins one, so an
     *      unconsumed reduced opening is structurally impossible — which is
     *      exactly what makes this check load-bearing. */
    {
        size_t seen = 0;
        for (size_t r = 0; r < rows; r++) {
            seen += (size_t)cells[r * cols + DNAC_P2C_COL_IS_ROLLIN];
        }
        if (seen != cfg->num_rollin) P2C_FAIL(DNAC_P2C_DEFECT_ROLLIN);
        for (size_t r = 0; r < rows; r++) {
            uint64_t want = 0;
            if (r >= n_chain && r < sched) {
                want = (uint64_t)p2c_phase_has_rollin(cfg, r - n_chain);
            }
            if (cells[r * cols + DNAC_P2C_COL_IS_ROLLIN] != want) {
                P2C_FAIL(DNAC_P2C_DEFECT_ROLLIN);
            }
        }
    }

    /* 13 — g_pow2: chain row j carries G_j = g_lgmh^{2^j}, every other row 0.
     *      This column is what makes the root lgmh-INJECTIVE (design §0.5
     *      :263-266) — but NOT cfg-injective, see OBL-4c in the header. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t want = (r < n_chain) ? p2c_g_pow2(cfg->lgmh, r) : 0u;
        if (cells[r * cols + DNAC_P2C_COL_G_POW2] != want) {
            P2C_FAIL(DNAC_P2C_DEFECT_GPOW2);
        }
    }

    return DNAC_P2C_TABLE_OK;
}

#undef P2C_FAIL

/* ==========================================================================
 * PIN-1-P2c comparator
 * ======================================================================== */

dnac_p2c_table_status_t dnac_p2c_prep_root_check(const uint64_t lanes[4])
{
    if (lanes == NULL) return DNAC_P2C_TABLE_ERR_PARAM;

    /* An UNFILLED placeholder pin must never accept anything — least of all the
     * all-zero root it would otherwise match (fri_air_table.h, the
     * DNAC_P2C_PREP_ROOT_UNFILLED contract). Compiles away once the
     * ORCHESTRATOR fills the constant from `--print-root`. */
    if (DNAC_P2C_PREP_ROOT_UNFILLED) {
        return DNAC_P2C_TABLE_ERR_ROOT_MISMATCH;
    }

    static const uint64_t pinned[4] = DNAC_P2C_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        if (lanes[k] != pinned[k]) return DNAC_P2C_TABLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_P2C_TABLE_OK;
}
