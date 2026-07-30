/**
 * @file fri_oi_air_table.c
 * @brief P2c open_input preprocessed row-type table generator + static
 *        validator + the PIN-1-OI comparator.
 *
 * See fri_oi_air_table.h for the full grounding contract (row schedule from the
 * BUILDABLE spec "Row schedule" :16-28; cum_h = lgmh - h; native batch-major
 * acc order fri_verifier.c:207/400/436/469; the h_max == lgmh gate FIX F7; the
 * D3 lgmh bound fri_verifier.c:689-691; PIN-1-OI derivation from
 * batch_prover.c:787-826).
 *
 * Determinism: every function is a pure function of the cfg SCALARS — fixed-
 * bound loops only, no allocation, no clock, no RNG, no iteration over anything
 * unordered.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_oi_air_table.h"

#include <string.h>

#include "field_goldilocks.h"

/* Upper bound on generated rows: sched <= MAX_STEPS = 64, rows =
 * next_pow2(sched + 1) <= next_pow2(65) = 128. The validator's independent
 * reconstruction buffer is sized to this. */
#define P2C_OI_MAX_TABLE_ROWS ((size_t)128)

/* ── the pinned reference config (fri_oi_air_table.h DNAC_P2C_OI_REF_*) ───── */
static const dnac_p2c_oi_height_desc_t P2C_OI_REF_HEIGHTS[DNAC_P2C_OI_REF_NUM_HEIGHTS] = {
    { 4, 1, 1, 1, 1 }, /* h_max == lgmh == 4, cum = 0 */
    { 2, 1, 1, 1, 1 }, /* h_min == lb   == 2, cum = 2 (an lb group is OPTIONAL
                        * in general; this REFERENCE cfg has one so the pin
                        * exercises the final-closeout path) */
};
static const dnac_p2c_oi_table_cfg_t P2C_OI_REF_CFG = {
    DNAC_P2C_OI_REF_LGMH,       DNAC_P2C_OI_REF_LOG_BLOWUP,
    DNAC_P2C_OI_REF_NUM_HEIGHTS, P2C_OI_REF_HEIGHTS,
    DNAC_P2C_OI_REF_NUM_QUERIES
};

const dnac_p2c_oi_table_cfg_t *dnac_p2c_oi_ref_cfg(void) { return &P2C_OI_REF_CFG; }

/* ==========================================================================
 * acc-row count — a product of four cfg counts, overflow-saturated to SIZE_MAX
 * so a huge descriptor is caught by the n_sched > MAX_STEPS gate rather than
 * wrapping. Public: sizes the acc groups.
 * ======================================================================== */
size_t dnac_p2c_oi_acc_count(const dnac_p2c_oi_height_desc_t *h)
{
    if (h == NULL) return 0;
    if (h->num_batches == 0 || h->num_matrices == 0 || h->num_points == 0 ||
        h->num_columns == 0) {
        return 0;
    }
    size_t p = h->num_batches;
    if (p > (size_t)-1 / h->num_matrices) return (size_t)-1;
    p *= h->num_matrices;
    if (p > (size_t)-1 / h->num_points) return (size_t)-1;
    p *= h->num_points;
    if (p > (size_t)-1 / h->num_columns) return (size_t)-1;
    p *= h->num_columns;
    return p;
}

/* ==========================================================================
 * Config gate — ONE place, so every accessor / row() / generate() / validate()
 * accepts exactly the same cfgs. Mirrors the AIR's eval-entry gates (spec
 * :110-115); the AIR re-runs them at its own entry because a table is not a
 * proof. Returns 0 on reject, 1 on accept.
 * ======================================================================== */
static int p2c_oi_cfg_check(const dnac_p2c_oi_table_cfg_t *cfg)
{
    if (cfg == NULL) return 0;

    /* lgmh in [2, 32]: below 2 a degenerate chain, above 32 the two-adic
     * generator degenerates (fri_verifier.c:689-691, field_goldilocks.c
     * :207-209). */
    if (cfg->lgmh < DNAC_P2C_OI_MIN_LGMH || cfg->lgmh > DNAC_P2C_OI_MAX_LGMH) {
        return 0;
    }
    /* lb <= lgmh: the height FLOOR must not exceed h_max == lgmh. */
    if (cfg->log_blowup > cfg->lgmh) return 0;

    if (cfg->num_heights < 1 || cfg->num_heights > DNAC_P2C_OI_MAX_HEIGHTS) {
        return 0;
    }
    if (cfg->heights == NULL) return 0;

    /* h_max == lgmh (FIX F7, spec :21). There is deliberately NO h_min rule:
     * a height AT lb is OPTIONAL (FLEET 029). The native lb-zero check is
     * CONDITIONAL on a reduced opening existing at log_blowup
     * (fri_verifier.c:482-487), and a real inner proof has none (a matrix at
     * log_height == log_blowup would be a degree-0 polynomial), so REQUIRING one
     * made this schedule unable to describe a real open_input walk. Position is
     * not a separate rule either: heights are STRICTLY DESCENDING, so if lb is
     * present it is necessarily the last group. */
    if (cfg->heights[0].log_height != cfg->lgmh) return 0;

    /* Per-height: in [lb, lgmh], STRICTLY DESCENDING, all four counts >= 1. */
    for (size_t i = 0; i < cfg->num_heights; i++) {
        const dnac_p2c_oi_height_desc_t *d = &cfg->heights[i];
        if (d->log_height < cfg->log_blowup || d->log_height > cfg->lgmh) {
            return 0;
        }
        if (i > 0 && d->log_height >= cfg->heights[i - 1].log_height) return 0;
        if (dnac_p2c_oi_acc_count(d) == 0) return 0; /* a zero count */
    }

    /* D2 — the query count is EXACT (fri_verifier.c:116-118) and 0 is rejected
     * natively (fri_verifier.c:686-688). Does not enter the table. */
    if (cfg->num_queries == 0 || cfg->num_queries > DNAC_P2C_OI_MAX_QUERIES) {
        return 0;
    }

    /* n_sched <= MAX_STEPS. Accumulated with a running cap so an oversized
     * descriptor rejects here instead of overflowing the step one-hot. */
    size_t sched = cfg->lgmh; /* chain rows */
    for (size_t i = 0; i < cfg->num_heights; i++) {
        const size_t h = cfg->heights[i].log_height;
        const size_t cap = (cfg->lgmh - h) + 2; /* seed + cum_h sq + store */
        const size_t acc = dnac_p2c_oi_acc_count(&cfg->heights[i]) + 1; /* +closeout */
        if (cap > DNAC_P2C_OI_MAX_STEPS || acc > DNAC_P2C_OI_MAX_STEPS) return 0;
        if (sched > DNAC_P2C_OI_MAX_STEPS - cap) return 0;
        sched += cap;
        if (sched > DNAC_P2C_OI_MAX_STEPS - acc) return 0;
        sched += acc;
    }
    if (sched == 0 || sched > DNAC_P2C_OI_MAX_STEPS) return 0;

    return 1;
}

/* Index of height `h` in the descending H array, or SIZE_MAX if absent. Fixed
 * loop over at most MAX_HEIGHTS entries. */
static size_t p2c_oi_index_of_height(const dnac_p2c_oi_table_cfg_t *cfg,
                                     size_t h)
{
    for (size_t i = 0; i < cfg->num_heights; i++) {
        if (cfg->heights[i].log_height == h) return i;
    }
    return (size_t)-1;
}

/* G_j = g_lgmh^{2^j}. The two-adic ladder gives g_{lgmh-j} = g_lgmh^{2^j}
 * directly (field_goldilocks.c:210-220), so no exponentiation is needed. For
 * the OI chain j <= lgmh - 1 ⇒ the argument (lgmh - j) stays in [1, 32], never
 * hitting the degenerate bits == 0 / bits > 32 branch. */
static uint64_t p2c_oi_g_pow2(size_t lgmh, size_t j)
{
    return gold_fp_to_u64(gold_fp_two_adic_generator((unsigned)(lgmh - j)));
}

/* Round up to a power of two, minimum DNAC_P2C_OI_MIN_ROWS. Returns 0 on
 * overflow (unreachable at the bounds above; kept fail-close). */
static size_t p2c_oi_pad_pow2(size_t used)
{
    size_t h = DNAC_P2C_OI_MIN_ROWS;
    while (h < used) {
        if (h > (size_t)-1 / 2) return 0;
        h <<= 1;
    }
    return h;
}

/* ==========================================================================
 * Shape accessors — each re-runs the cfg gate, so an invalid cfg returns 0.
 * For a VALID cfg every sum is <= MAX_STEPS = 64, so no overflow on this path.
 * ======================================================================== */

size_t dnac_p2c_oi_chain_rows(const dnac_p2c_oi_table_cfg_t *cfg)
{
    if (!p2c_oi_cfg_check(cfg)) return 0;
    return cfg->lgmh;
}

size_t dnac_p2c_oi_capture_rows(const dnac_p2c_oi_table_cfg_t *cfg)
{
    if (!p2c_oi_cfg_check(cfg)) return 0;
    size_t n = 0;
    for (size_t i = 0; i < cfg->num_heights; i++) {
        n += (cfg->lgmh - cfg->heights[i].log_height) + 2;
    }
    return n;
}

size_t dnac_p2c_oi_group_rows(const dnac_p2c_oi_table_cfg_t *cfg)
{
    if (!p2c_oi_cfg_check(cfg)) return 0;
    size_t n = 0;
    for (size_t i = 0; i < cfg->num_heights; i++) {
        n += dnac_p2c_oi_acc_count(&cfg->heights[i]) + 1;
    }
    return n;
}

size_t dnac_p2c_oi_sched_rows(const dnac_p2c_oi_table_cfg_t *cfg)
{
    if (!p2c_oi_cfg_check(cfg)) return 0;
    return dnac_p2c_oi_chain_rows(cfg) + dnac_p2c_oi_capture_rows(cfg) +
           dnac_p2c_oi_group_rows(cfg);
}

size_t dnac_p2c_oi_table_rows(const dnac_p2c_oi_table_cfg_t *cfg)
{
    const size_t sched = dnac_p2c_oi_sched_rows(cfg);
    if (sched == 0) return 0;
    /* +1 = the mandatory terminal padding row (spec :28). */
    return p2c_oi_pad_pow2(sched + 1);
}

/* ==========================================================================
 * Row record — the single source both the cell writer and the tests read.
 * Walks the PREFIX-ordered schedule to `row`. O(n_sched); n_sched <= 64.
 * ======================================================================== */

dnac_p2c_oi_table_status_t dnac_p2c_oi_table_row(
    const dnac_p2c_oi_table_cfg_t *cfg, size_t row, dnac_p2c_oi_row_t *out)
{
    if (out == NULL || !p2c_oi_cfg_check(cfg)) {
        return DNAC_P2C_OI_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    if (rows == 0 || row >= rows) return DNAC_P2C_OI_TABLE_ERR_PARAM;

    memset(out, 0, sizeof(*out));
    out->step = (size_t)-1;
    out->h_index = (size_t)-1;

    const size_t lgmh = cfg->lgmh;
    size_t cur = 0;

    /* item 1 — chain rows with INTERLEAVED capture blocks. */
    for (size_t j = 0; j < lgmh; j++) {
        if (cur == row) {
            out->type = DNAC_P2C_OI_ROW_CHAIN;
            out->step = row;
            out->g_pow2 = p2c_oi_g_pow2(lgmh, j);
            return DNAC_P2C_OI_TABLE_OK;
        }
        cur++;
        /* height h = j + 1 completes its prefix right after chain row j
         * (h bits consumed); insert its capture block, cum_h = lgmh - h. */
        const size_t h = j + 1;
        const size_t i = p2c_oi_index_of_height(cfg, h);
        if (i != (size_t)-1) {
            const size_t cum = lgmh - h;
            if (cur == row) { /* seed row (no sub-flag) */
                out->type = DNAC_P2C_OI_ROW_CAPTURE;
                out->step = row;
                out->h_index = i;
                return DNAC_P2C_OI_TABLE_OK;
            }
            cur++;
            for (size_t s = 0; s < cum; s++) {
                if (cur == row) { /* squaring row */
                    out->type = DNAC_P2C_OI_ROW_CAPTURE;
                    out->step = row;
                    out->h_index = i;
                    out->is_sqpair = 1;
                    return DNAC_P2C_OI_TABLE_OK;
                }
                cur++;
            }
            if (cur == row) { /* store row */
                out->type = DNAC_P2C_OI_ROW_CAPTURE;
                out->step = row;
                out->h_index = i;
                out->is_store = 1;
                return DNAC_P2C_OI_TABLE_OK;
            }
            cur++;
        }
    }

    /* item 2 — accumulation groups, DESCENDING (== the heights[] order). */
    for (size_t i = 0; i < cfg->num_heights; i++) {
        const size_t n_acc = dnac_p2c_oi_acc_count(&cfg->heights[i]);
        for (size_t a = 0; a < n_acc; a++) {
            if (cur == row) {
                out->type = DNAC_P2C_OI_ROW_ACC;
                out->step = row;
                out->h_index = i;
                out->is_group_start = (a == 0) ? 1 : 0;
                return DNAC_P2C_OI_TABLE_OK;
            }
            cur++;
        }
        if (cur == row) { /* the group's LAST row */
            out->type = DNAC_P2C_OI_ROW_CLOSEOUT;
            out->step = row;
            out->h_index = i;
            out->is_final_closeout =
                (cfg->heights[i].log_height == cfg->log_blowup) ? 1 : 0;
            return DNAC_P2C_OI_TABLE_OK;
        }
        cur++;
    }

    /* item 3 — padding (step / h_index stay SIZE_MAX). */
    out->type = DNAC_P2C_OI_ROW_PAD;
    return DNAC_P2C_OI_TABLE_OK;
}

/* ==========================================================================
 * Generator
 * ======================================================================== */

dnac_p2c_oi_table_status_t dnac_p2c_oi_table_generate(
    const dnac_p2c_oi_table_cfg_t *cfg, uint64_t *out, size_t out_cells)
{
    if (out == NULL || !p2c_oi_cfg_check(cfg)) {
        return DNAC_P2C_OI_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    if (rows == 0) return DNAC_P2C_OI_TABLE_ERR_PARAM;
    if (out_cells < rows * (size_t)DNAC_P2C_OI_TABLE_COLS) {
        return DNAC_P2C_OI_TABLE_ERR_CAPACITY;
    }

    /* Every cell defaults to 0: padding rows carry no type, no sub-flag, no G
     * literal and an all-zero h_sel/pos one-hot. */
    memset(out, 0, rows * (size_t)DNAC_P2C_OI_TABLE_COLS * sizeof(uint64_t));

    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_oi_row_t rec;
        const dnac_p2c_oi_table_status_t st = dnac_p2c_oi_table_row(cfg, r, &rec);
        if (st != DNAC_P2C_OI_TABLE_OK) return st; /* unreachable; fail-close */

        uint64_t *row = &out[r * (size_t)DNAC_P2C_OI_TABLE_COLS];
        switch (rec.type) {
        case DNAC_P2C_OI_ROW_CHAIN:    row[DNAC_P2C_OI_COL_IS_CHAIN] = 1; break;
        case DNAC_P2C_OI_ROW_CAPTURE:  row[DNAC_P2C_OI_COL_IS_CAPTURE] = 1; break;
        case DNAC_P2C_OI_ROW_ACC:      row[DNAC_P2C_OI_COL_IS_ACC] = 1; break;
        case DNAC_P2C_OI_ROW_CLOSEOUT: row[DNAC_P2C_OI_COL_IS_CLOSEOUT] = 1; break;
        case DNAC_P2C_OI_ROW_PAD:      row[DNAC_P2C_OI_COL_IS_PAD] = 1; break;
        }
        row[DNAC_P2C_OI_COL_IS_SQPAIR] = (uint64_t)rec.is_sqpair;
        row[DNAC_P2C_OI_COL_IS_STORE] = (uint64_t)rec.is_store;
        row[DNAC_P2C_OI_COL_IS_GROUP_START] = (uint64_t)rec.is_group_start;
        row[DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT] =
            (uint64_t)rec.is_final_closeout;
        row[DNAC_P2C_OI_COL_G_POW2] = rec.g_pow2;
        if (rec.h_index != (size_t)-1) {
            row[dnac_p2c_oi_col_hsel(rec.h_index)] = 1;
        }
        if (rec.step != (size_t)-1) {
            row[dnac_p2c_oi_col_pos(rec.step)] = 1;
        }
    }
    return DNAC_P2C_OI_TABLE_OK;
}

/* ==========================================================================
 * Static validator — structural, INDEPENDENT of the generator's decode. It
 * reconstructs the expected schedule from cfg semantics into a local array,
 * then checks the cells against it (plus the cell-local canonicality /
 * booleanity / exclusivity passes). NOT a memcmp against the generator.
 * Check order is the header's contract.
 * ======================================================================== */

/* One reconstructed row descriptor (validator-local; deliberately a SEPARATE
 * walk from dnac_p2c_oi_table_row so the two implementations cross-check). */
typedef struct {
    dnac_p2c_oi_row_type_t type;
    size_t   step;
    size_t   h_index;
    int      is_sqpair;
    int      is_store;
    int      is_group_start;
    int      is_final_closeout;
    uint64_t g_pow2;
} p2c_oi_exp_t;

/* Reconstruct the whole expected schedule into exp[0..rows). Returns 0 if the
 * schedule would exceed the buffer (unreachable for a valid cfg). */
static int p2c_oi_reconstruct(const dnac_p2c_oi_table_cfg_t *cfg, size_t rows,
                              p2c_oi_exp_t *exp)
{
    if (rows > P2C_OI_MAX_TABLE_ROWS) return 0;
    for (size_t r = 0; r < rows; r++) {
        exp[r].type = DNAC_P2C_OI_ROW_PAD;
        exp[r].step = (size_t)-1;
        exp[r].h_index = (size_t)-1;
        exp[r].is_sqpair = 0;
        exp[r].is_store = 0;
        exp[r].is_group_start = 0;
        exp[r].is_final_closeout = 0;
        exp[r].g_pow2 = 0;
    }

    const size_t lgmh = cfg->lgmh;
    size_t cur = 0;

    for (size_t j = 0; j < lgmh; j++) {
        if (cur >= rows) return 0;
        exp[cur].type = DNAC_P2C_OI_ROW_CHAIN;
        exp[cur].step = cur;
        exp[cur].g_pow2 = p2c_oi_g_pow2(lgmh, j);
        cur++;
        const size_t h = j + 1;
        const size_t i = p2c_oi_index_of_height(cfg, h);
        if (i != (size_t)-1) {
            const size_t cum = lgmh - h;
            if (cur >= rows) return 0;
            exp[cur].type = DNAC_P2C_OI_ROW_CAPTURE; /* seed */
            exp[cur].step = cur;
            exp[cur].h_index = i;
            cur++;
            for (size_t s = 0; s < cum; s++) {
                if (cur >= rows) return 0;
                exp[cur].type = DNAC_P2C_OI_ROW_CAPTURE;
                exp[cur].step = cur;
                exp[cur].h_index = i;
                exp[cur].is_sqpair = 1;
                cur++;
            }
            if (cur >= rows) return 0;
            exp[cur].type = DNAC_P2C_OI_ROW_CAPTURE; /* store */
            exp[cur].step = cur;
            exp[cur].h_index = i;
            exp[cur].is_store = 1;
            cur++;
        }
    }

    for (size_t i = 0; i < cfg->num_heights; i++) {
        const size_t n_acc = dnac_p2c_oi_acc_count(&cfg->heights[i]);
        for (size_t a = 0; a < n_acc; a++) {
            if (cur >= rows) return 0;
            exp[cur].type = DNAC_P2C_OI_ROW_ACC;
            exp[cur].step = cur;
            exp[cur].h_index = i;
            exp[cur].is_group_start = (a == 0) ? 1 : 0;
            cur++;
        }
        if (cur >= rows) return 0;
        exp[cur].type = DNAC_P2C_OI_ROW_CLOSEOUT;
        exp[cur].step = cur;
        exp[cur].h_index = i;
        exp[cur].is_final_closeout =
            (cfg->heights[i].log_height == cfg->log_blowup) ? 1 : 0;
        cur++;
    }
    /* remaining rows already initialised to PAD. */
    return 1;
}

/* Which of the 5 primary flags is set (assumes exclusivity already checked). */
static dnac_p2c_oi_row_type_t p2c_oi_actual_type(const uint64_t *row)
{
    if (row[DNAC_P2C_OI_COL_IS_CHAIN]) return DNAC_P2C_OI_ROW_CHAIN;
    if (row[DNAC_P2C_OI_COL_IS_CAPTURE]) return DNAC_P2C_OI_ROW_CAPTURE;
    if (row[DNAC_P2C_OI_COL_IS_ACC]) return DNAC_P2C_OI_ROW_ACC;
    if (row[DNAC_P2C_OI_COL_IS_CLOSEOUT]) return DNAC_P2C_OI_ROW_CLOSEOUT;
    return DNAC_P2C_OI_ROW_PAD;
}

#define P2C_OI_FAIL(d)                                                        \
    do {                                                                      \
        if (out_defect) *out_defect = (d);                                    \
        return DNAC_P2C_OI_TABLE_ERR_SCHEDULE;                                \
    } while (0)

dnac_p2c_oi_table_status_t dnac_p2c_oi_table_validate(
    const dnac_p2c_oi_table_cfg_t *cfg, const uint64_t *cells, size_t rows,
    dnac_p2c_oi_table_defect_t *out_defect)
{
    if (out_defect) *out_defect = DNAC_P2C_OI_DEFECT_NONE;

    if (cells == NULL || !p2c_oi_cfg_check(cfg)) {
        return DNAC_P2C_OI_TABLE_ERR_PARAM;
    }
    const size_t exp_rows = dnac_p2c_oi_table_rows(cfg);
    if (exp_rows == 0 || rows != exp_rows) return DNAC_P2C_OI_TABLE_ERR_PARAM;

    const size_t cols = (size_t)DNAC_P2C_OI_TABLE_COLS;

    /* 1 — canonicality. Non-canonical preprocessed cells alias mod p. */
    for (size_t r = 0; r < rows; r++) {
        for (size_t k = 0; k < cols; k++) {
            if (cells[r * cols + k] >= GOLDILOCKS_P) {
                P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_CANONICAL);
            }
        }
    }

    /* 2 — booleanity of every cell except the g_pow2 field literal. Nothing on
     *     the verify path checks this (batch_verify.c:722-727), so it is
     *     checked HERE and frozen by the root pin. */
    for (size_t r = 0; r < rows; r++) {
        for (size_t k = 0; k < cols; k++) {
            if (k == (size_t)DNAC_P2C_OI_COL_G_POW2) continue;
            if (cells[r * cols + k] > 1) P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_BOOLEAN);
        }
    }

    /* 3 — exactly one PRIMARY row type per row. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        const uint64_t set = row[DNAC_P2C_OI_COL_IS_CHAIN] +
                             row[DNAC_P2C_OI_COL_IS_CAPTURE] +
                             row[DNAC_P2C_OI_COL_IS_ACC] +
                             row[DNAC_P2C_OI_COL_IS_CLOSEOUT] +
                             row[DNAC_P2C_OI_COL_IS_PAD];
        if (set != 1) P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_TYPE_EXCLUSIVE);
    }

    /* Reconstruct the expected schedule INDEPENDENTLY of the generator. Stack-
     * local (~6 KB) so the validator stays re-entrant on the eventual verify
     * path — no shared mutable state. */
    p2c_oi_exp_t exp[P2C_OI_MAX_TABLE_ROWS];
    if (!p2c_oi_reconstruct(cfg, rows, exp)) {
        return DNAC_P2C_OI_TABLE_ERR_PARAM; /* unreachable for a valid cfg */
    }

    /* 4 — primary schedule: each row's primary type matches the reconstructed
     *     chain | interleaved-captures | descending-groups | pad layout. This
     *     subsumes every row-type COUNT (a miscount shows up as a mismatched
     *     type at the boundary). */
    for (size_t r = 0; r < rows; r++) {
        if (p2c_oi_actual_type(&cells[r * cols]) != exp[r].type) {
            P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_PRIMARY_SCHEDULE);
        }
    }

    /* 5 — capture sub-flags: seed / sq_{cum_h} / store per height. Non-capture
     *     rows carry neither sub-flag (exp has both 0). */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        if (row[DNAC_P2C_OI_COL_IS_SQPAIR] != (uint64_t)exp[r].is_sqpair ||
            row[DNAC_P2C_OI_COL_IS_STORE] != (uint64_t)exp[r].is_store) {
            P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_CAPTURE);
        }
    }

    /* 6 — group start: set iff the FIRST acc row of a group; 0 elsewhere. */
    for (size_t r = 0; r < rows; r++) {
        if (cells[r * cols + DNAC_P2C_OI_COL_IS_GROUP_START] !=
            (uint64_t)exp[r].is_group_start) {
            P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_GROUP_START);
        }
    }

    /* 7 — final closeout: set iff the h==lb group's closeout (spec C4b); 0
     *     elsewhere. CONDITIONAL (FLEET 029): at most one exists, and NONE at
     *     all when no height equals lb — the `exp` walk derives it from
     *     log_height == log_blowup, so a forged flag on an lb-less schedule is
     *     rejected here. */
    for (size_t r = 0; r < rows; r++) {
        if (cells[r * cols + DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT] !=
            (uint64_t)exp[r].is_final_closeout) {
            P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_FINAL_CLOSEOUT);
        }
    }

    /* 8 — height one-hot: exactly exp[r].h_index set on capture / acc /
     *     closeout rows; all-zero on chain / pad. Routes x_reg[h] and the
     *     ro_slot_h publics. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        for (size_t i = 0; i < DNAC_P2C_OI_MAX_HEIGHTS; i++) {
            const uint64_t want =
                (exp[r].h_index != (size_t)-1 && i == exp[r].h_index) ? 1u : 0u;
            if (row[dnac_p2c_oi_col_hsel(i)] != want) {
                P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_HSEL);
            }
        }
    }

    /* 9 — step one-hot: scheduled row k carries pos[k]=1 and nothing else;
     *     padding rows carry an all-zero one-hot. This also pins the
     *     batch-major acc ORDER inside a group (see the header note). */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        for (size_t k = 0; k < DNAC_P2C_OI_MAX_STEPS; k++) {
            const uint64_t want =
                (exp[r].step != (size_t)-1 && k == exp[r].step) ? 1u : 0u;
            if (row[dnac_p2c_oi_col_pos(k)] != want) {
                P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_POS_ONEHOT);
            }
        }
    }

    /* 10 — g_pow2: chain row j carries G_j = g_lgmh^{2^j}, every other row 0.
     *      Makes the root lgmh-INJECTIVE (OBL-4c-OI). */
    for (size_t r = 0; r < rows; r++) {
        if (cells[r * cols + DNAC_P2C_OI_COL_G_POW2] != exp[r].g_pow2) {
            P2C_OI_FAIL(DNAC_P2C_OI_DEFECT_GPOW2);
        }
    }

    return DNAC_P2C_OI_TABLE_OK;
}

#undef P2C_OI_FAIL

/* ==========================================================================
 * PIN-1-OI comparator
 * ======================================================================== */

dnac_p2c_oi_table_status_t dnac_p2c_oi_prep_root_check(const uint64_t lanes[4])
{
    if (lanes == NULL) return DNAC_P2C_OI_TABLE_ERR_PARAM;

    /* An UNFILLED placeholder pin must never accept anything — least of all the
     * all-zero root it would otherwise match (fri_oi_air_table.h, the
     * DNAC_P2C_OI_PREP_ROOT_UNFILLED contract). Compiles away once the
     * ORCHESTRATOR fills the constant from `--print-root`. */
    if (DNAC_P2C_OI_PREP_ROOT_UNFILLED) {
        return DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH;
    }

    static const uint64_t pinned[4] = DNAC_P2C_OI_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        if (lanes[k] != pinned[k]) return DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_P2C_OI_TABLE_OK;
}
