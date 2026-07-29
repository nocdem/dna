/**
 * @file mmcs_mixed_air_table.c
 * @brief P2b slice 2 preprocessed row-type table generator + static validator +
 *        the PIN-1-MMIX comparator.
 *
 * See mmcs_mixed_air_table.h for the full grounding contract (row schedule from
 * the BUILDABLE spec "Row schedule" :51-67 and the native
 * dnac_p2_mmcs_verify_mixed poseidon2_mmcs.c:454-529; leaf-row count from the
 * PaddingFreeSponge schedule poseidon2_mmcs.c:41-72; group order = descending
 * distinct height; PIN-1-MMIX derivation from batch_prover.c:807-825).
 *
 * Determinism: every function is a pure function of the cfg SCALARS — fixed-bound
 * loops only, no allocation, no clock, no RNG, no iteration over anything
 * unordered. Group order is derived by enumerating powers of two DESCENDING, a
 * reproducible total order.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmcs_mixed_air_table.h"

#include <string.h>

/* Upper bound on generated rows: sched <= MAX_STEPS = 64, rows =
 * next_pow2(sched + 1) <= next_pow2(65) = 128. The validator's independent
 * reconstruction buffer is sized to this. */
#define P2C_MMIX_MAX_TABLE_ROWS ((size_t)128)

/* ── the pinned reference config (mmcs_mixed_air_table.h DNAC_P2C_MMIX_REF_*) ── */
static const size_t P2C_MMIX_REF_HEIGHTS[DNAC_P2C_MMIX_REF_NUM_MATRICES] = {
    DNAC_P2C_MMIX_REF_HEIGHT_0, DNAC_P2C_MMIX_REF_HEIGHT_1
};
static const size_t P2C_MMIX_REF_WIDTHS[DNAC_P2C_MMIX_REF_NUM_MATRICES] = {
    DNAC_P2C_MMIX_REF_WIDTH_0, DNAC_P2C_MMIX_REF_WIDTH_1
};
static const dnac_p2c_mmix_table_cfg_t P2C_MMIX_REF_CFG = {
    DNAC_P2C_MMIX_REF_NUM_MATRICES, P2C_MMIX_REF_WIDTHS, P2C_MMIX_REF_HEIGHTS,
    DNAC_P2C_MMIX_REF_DEPTH, DNAC_P2C_MMIX_REF_SALT_ELEMS
};

const dnac_p2c_mmix_table_cfg_t *dnac_p2c_mmix_ref_cfg(void)
{
    return &P2C_MMIX_REF_CFG;
}

/* ==========================================================================
 * Pure helpers (assume the cfg fields have already been validated by
 * p2c_mmix_cfg_check — they are only reached through a checked entry).
 * ======================================================================== */

/* Max height across matrices. */
static size_t p2c_mmix_max_height(const dnac_p2c_mmix_table_cfg_t *cfg)
{
    size_t max_h = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->heights[m] > max_h) max_h = cfg->heights[m];
    }
    return max_h;
}

/* Is height `h` present among the matrices? */
static int p2c_mmix_present(const dnac_p2c_mmix_table_cfg_t *cfg, size_t h)
{
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->heights[m] == h) return 1;
    }
    return 0;
}

/* Descending-group index of present height `h` == the count of DISTINCT present
 * heights strictly greater than h (group 0 == max_h). SIZE_MAX if h absent. */
static size_t p2c_mmix_group_index_of(const dnac_p2c_mmix_table_cfg_t *cfg,
                                      size_t h)
{
    if (!p2c_mmix_present(cfg, h)) return (size_t)-1;
    const size_t max_h = p2c_mmix_max_height(cfg);
    size_t idx = 0;
    for (size_t hh = max_h; hh > h; hh >>= 1) {
        if (p2c_mmix_present(cfg, hh)) idx++;
    }
    return idx;
}

/* Group leaf-absorb concat = Σ_{m: heights[m]==h} (widths[m] + salt_elems). */
static size_t p2c_mmix_concat_width(const dnac_p2c_mmix_table_cfg_t *cfg,
                                    size_t h)
{
    size_t concat = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->heights[m] == h) concat += cfg->widths[m] + cfg->salt_elems;
    }
    return concat;
}

/* Permutation count of dnac_p2_mmcs_hash_iter over `concat` elements — one
 * (inject-)leaf row each. OVERWRITE absorb, permute on a full block, NO extra
 * permute at an exact block boundary, permute on a partial final block
 * (poseidon2_mmcs.c:53-69). concat > 0 for a present group. */
static size_t p2c_mmix_leaf_rows_h(size_t concat)
{
    const size_t full = concat / DNAC_P2C_MMIX_SPONGE_RATE;
    return (concat % DNAC_P2C_MMIX_SPONGE_RATE == 0) ? full : full + 1;
}

/* Round up to a power of two, minimum DNAC_P2C_MMIX_MIN_ROWS. Returns 0 on
 * overflow (unreachable at the bounds below; kept fail-close). */
static size_t p2c_mmix_pad_pow2(size_t used)
{
    size_t h = DNAC_P2C_MMIX_MIN_ROWS;
    while (h < used) {
        if (h > (size_t)-1 / 2) return 0;
        h <<= 1;
    }
    return h;
}

/* ==========================================================================
 * Config gate — ONE place, so every accessor / row() / generate() / validate()
 * accepts exactly the same cfgs. Mirrors the AIR's eval-entry gates (spec
 * :93-96); the AIR re-runs them at its own entry because a table is not a proof.
 * Returns 0 on reject, 1 on accept.
 * ======================================================================== */
static int p2c_mmix_cfg_check(const dnac_p2c_mmix_table_cfg_t *cfg)
{
    if (cfg == NULL || cfg->widths == NULL || cfg->heights == NULL) return 0;
    if (cfg->num_matrices == 0 || cfg->num_matrices > DNAC_P2C_MMIX_MAX_MATRICES) {
        return 0;
    }
    if (cfg->salt_elems > DNAC_P2C_MMIX_MAX_SALT) return 0;
    if (cfg->depth < 1 || cfg->depth > DNAC_P2C_MMIX_MAX_DEPTH) return 0;

    /* Per-matrix: width >= 1, height a power of two; accumulate max_h + total. */
    size_t max_h = 0, total = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        const size_t w = cfg->widths[m];
        const size_t h = cfg->heights[m];
        if (w == 0) return 0;
        if (h == 0 || (h & (h - 1)) != 0) return 0; /* not a power of two */
        if (w > DNAC_P2C_MMIX_MAX_TOTAL_WIDTH - total) return 0;
        total += w;
        if (h > max_h) max_h = h;
    }
    if (total == 0 || total > DNAC_P2C_MMIX_MAX_TOTAL_WIDTH) return 0;

    /* depth == log2(max_h): the WrongHeight/BAD_DEPTH pin (poseidon2_mmcs.c:484).
     * depth <= 32 < the size_t bit width, so the shift is defined. */
    if (max_h != ((size_t)1 << cfg->depth)) return 0;

    /* n_sched <= MAX_STEPS, accumulated with a running cap so an oversized shape
     * rejects here instead of overflowing the step one-hot. */
    const size_t g0 = p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, max_h));
    if (g0 == 0 || g0 > DNAC_P2C_MMIX_MAX_STEPS) return 0;
    size_t sched = g0;
    for (size_t l = 0; l < cfg->depth; l++) {
        if (sched > DNAC_P2C_MMIX_MAX_STEPS - 1) return 0;
        sched += 1; /* compress */
        const size_t cur = max_h >> (l + 1);
        if (p2c_mmix_present(cfg, cur)) {
            const size_t lg =
                p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, cur));
            if (lg == 0) return 0;
            const size_t add = lg + 1; /* inject-leaf rows + inject-compress */
            if (add > DNAC_P2C_MMIX_MAX_STEPS ||
                sched > DNAC_P2C_MMIX_MAX_STEPS - add) {
                return 0;
            }
            sched += add;
        }
    }
    if (sched > DNAC_P2C_MMIX_MAX_STEPS - 1) return 0;
    sched += 1; /* final */
    if (sched == 0 || sched > DNAC_P2C_MMIX_MAX_STEPS) return 0;

    /* Distinct group count bound (defensive; auto <= depth + 1 <= 33). */
    size_t ng = 0;
    for (size_t h = max_h; h != 0; h >>= 1) {
        if (p2c_mmix_present(cfg, h)) ng++;
    }
    if (ng == 0 || ng > DNAC_P2C_MMIX_MAX_GROUPS) return 0;

    return 1;
}

/* ==========================================================================
 * Shape accessors — each re-runs the cfg gate, so an invalid cfg returns 0.
 * For a VALID cfg every sum is <= MAX_STEPS, so no overflow on this path.
 * ======================================================================== */

size_t dnac_p2c_mmix_num_groups(const dnac_p2c_mmix_table_cfg_t *cfg)
{
    if (!p2c_mmix_cfg_check(cfg)) return 0;
    const size_t max_h = p2c_mmix_max_height(cfg);
    size_t n = 0;
    for (size_t h = max_h; h != 0; h >>= 1) {
        if (p2c_mmix_present(cfg, h)) n++;
    }
    return n;
}

size_t dnac_p2c_mmix_group_height(const dnac_p2c_mmix_table_cfg_t *cfg, size_t g)
{
    if (!p2c_mmix_cfg_check(cfg)) return 0;
    const size_t max_h = p2c_mmix_max_height(cfg);
    size_t idx = 0;
    for (size_t h = max_h; h != 0; h >>= 1) {
        if (p2c_mmix_present(cfg, h)) {
            if (idx == g) return h;
            idx++;
        }
    }
    return 0;
}

size_t dnac_p2c_mmix_group_leaf_rows(const dnac_p2c_mmix_table_cfg_t *cfg,
                                     size_t g)
{
    const size_t h = dnac_p2c_mmix_group_height(cfg, g); /* re-runs cfg gate */
    if (h == 0) return 0;
    return p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, h));
}

size_t dnac_p2c_mmix_sched_rows(const dnac_p2c_mmix_table_cfg_t *cfg)
{
    if (!p2c_mmix_cfg_check(cfg)) return 0;
    const size_t max_h = p2c_mmix_max_height(cfg);
    size_t s = p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, max_h));
    for (size_t l = 0; l < cfg->depth; l++) {
        s += 1; /* compress */
        const size_t cur = max_h >> (l + 1);
        if (p2c_mmix_present(cfg, cur)) {
            s += p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, cur)) + 1;
        }
    }
    s += 1; /* final */
    return s;
}

size_t dnac_p2c_mmix_table_rows(const dnac_p2c_mmix_table_cfg_t *cfg)
{
    const size_t sched = dnac_p2c_mmix_sched_rows(cfg);
    if (sched == 0) return 0;
    /* +1 = the mandatory terminal padding row (terminality gate). */
    return p2c_mmix_pad_pow2(sched + 1);
}

/* ==========================================================================
 * Row record — the single source both the cell writer and the tests read.
 * Walks the PREFIX-ordered schedule to `row`. O(n_sched); n_sched <= 64.
 * ======================================================================== */

dnac_p2c_mmix_table_status_t dnac_p2c_mmix_table_row(
    const dnac_p2c_mmix_table_cfg_t *cfg, size_t row, dnac_p2c_mmix_row_t *out)
{
    if (out == NULL || !p2c_mmix_cfg_check(cfg)) {
        return DNAC_P2C_MMIX_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2c_mmix_table_rows(cfg);
    if (rows == 0 || row >= rows) return DNAC_P2C_MMIX_TABLE_ERR_PARAM;

    memset(out, 0, sizeof(*out));
    out->step = (size_t)-1;
    out->level = (size_t)-1;
    out->group = (size_t)-1;

    const size_t max_h = p2c_mmix_max_height(cfg);
    const size_t depth = cfg->depth;
    size_t cur = 0;

    /* 1 — tallest-group (group 0) leaf-hash rows. */
    const size_t g0_rows =
        p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, max_h));
    for (size_t i = 0; i < g0_rows; i++) {
        if (cur == row) {
            out->type = DNAC_P2C_MMIX_ROW_LEAF;
            out->step = row;
            out->group = 0;
            return DNAC_P2C_MMIX_TABLE_OK;
        }
        cur++;
    }

    /* 2 — per level: compress, then an OPTIONAL inject block. */
    for (size_t l = 0; l < depth; l++) {
        const size_t cur_after = max_h >> (l + 1);
        const int inj = p2c_mmix_present(cfg, cur_after);
        if (cur == row) {
            out->type = DNAC_P2C_MMIX_ROW_COMPRESS;
            out->step = row;
            out->level = l;
            out->has_inject = inj ? 1 : 0;
            return DNAC_P2C_MMIX_TABLE_OK;
        }
        cur++;
        if (inj) {
            const size_t gi = p2c_mmix_group_index_of(cfg, cur_after);
            const size_t lg =
                p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, cur_after));
            for (size_t i = 0; i < lg; i++) {
                if (cur == row) {
                    out->type = DNAC_P2C_MMIX_ROW_INJECT_LEAF;
                    out->step = row;
                    out->level = l;
                    out->group = gi;
                    return DNAC_P2C_MMIX_TABLE_OK;
                }
                cur++;
            }
            if (cur == row) {
                out->type = DNAC_P2C_MMIX_ROW_INJECT_COMPRESS;
                out->step = row;
                out->level = l;
                out->group = gi;
                return DNAC_P2C_MMIX_TABLE_OK;
            }
            cur++;
        }
    }

    /* 3 — final root-equality row. */
    if (cur == row) {
        out->type = DNAC_P2C_MMIX_ROW_FINAL;
        out->step = row;
        return DNAC_P2C_MMIX_TABLE_OK;
    }
    cur++;

    /* 4 — padding (step / level / group stay SIZE_MAX). */
    out->type = DNAC_P2C_MMIX_ROW_PAD;
    return DNAC_P2C_MMIX_TABLE_OK;
}

/* ==========================================================================
 * Generator
 * ======================================================================== */

dnac_p2c_mmix_table_status_t dnac_p2c_mmix_table_generate(
    const dnac_p2c_mmix_table_cfg_t *cfg, uint64_t *out, size_t out_cells)
{
    if (out == NULL || !p2c_mmix_cfg_check(cfg)) {
        return DNAC_P2C_MMIX_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2c_mmix_table_rows(cfg);
    if (rows == 0) return DNAC_P2C_MMIX_TABLE_ERR_PARAM;
    if (out_cells < rows * (size_t)DNAC_P2C_MMIX_TABLE_COLS) {
        return DNAC_P2C_MMIX_TABLE_ERR_CAPACITY;
    }

    /* Every cell defaults to 0: padding rows carry no type, no sub-flag and an
     * all-zero lvl/gsel/pos one-hot. */
    memset(out, 0, rows * (size_t)DNAC_P2C_MMIX_TABLE_COLS * sizeof(uint64_t));

    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_mmix_row_t rec;
        const dnac_p2c_mmix_table_status_t st =
            dnac_p2c_mmix_table_row(cfg, r, &rec);
        if (st != DNAC_P2C_MMIX_TABLE_OK) return st; /* unreachable; fail-close */

        uint64_t *row = &out[r * (size_t)DNAC_P2C_MMIX_TABLE_COLS];
        switch (rec.type) {
        case DNAC_P2C_MMIX_ROW_LEAF:
            row[DNAC_P2C_MMIX_COL_IS_LEAF] = 1;
            break;
        case DNAC_P2C_MMIX_ROW_COMPRESS:
            row[DNAC_P2C_MMIX_COL_IS_COMPRESS] = 1;
            break;
        case DNAC_P2C_MMIX_ROW_INJECT_LEAF:
            row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF] = 1;
            break;
        case DNAC_P2C_MMIX_ROW_INJECT_COMPRESS:
            row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS] = 1;
            break;
        case DNAC_P2C_MMIX_ROW_FINAL:
            row[DNAC_P2C_MMIX_COL_IS_FINAL] = 1;
            break;
        case DNAC_P2C_MMIX_ROW_PAD:
            row[DNAC_P2C_MMIX_COL_IS_PAD] = 1;
            break;
        }
        row[DNAC_P2C_MMIX_COL_HAS_INJECT] = (uint64_t)rec.has_inject;
        if (rec.level != (size_t)-1) {
            row[dnac_p2c_mmix_col_lvl(rec.level)] = 1;
        }
        if (rec.group != (size_t)-1) {
            row[dnac_p2c_mmix_col_gsel(rec.group)] = 1;
        }
        if (rec.step != (size_t)-1) {
            row[dnac_p2c_mmix_col_pos(rec.step)] = 1;
        }
    }
    return DNAC_P2C_MMIX_TABLE_OK;
}

/* ==========================================================================
 * Static validator — structural, INDEPENDENT of the generator's decode. It
 * reconstructs the expected schedule from cfg semantics into a local array, then
 * checks the cells against it (plus the cell-local booleanity / exclusivity
 * passes). NOT a memcmp against the generator. Check order is the header's
 * contract.
 * ======================================================================== */

/* Reconstruct the whole expected schedule into exp[0..rows) — a SEPARATE walk
 * from dnac_p2c_mmix_table_row so the two implementations cross-check. Returns 0
 * if the schedule would exceed the buffer (unreachable for a valid cfg). */
static int p2c_mmix_reconstruct(const dnac_p2c_mmix_table_cfg_t *cfg,
                                size_t rows, dnac_p2c_mmix_row_t *exp)
{
    if (rows > P2C_MMIX_MAX_TABLE_ROWS) return 0;
    for (size_t r = 0; r < rows; r++) {
        exp[r].type = DNAC_P2C_MMIX_ROW_PAD;
        exp[r].step = (size_t)-1;
        exp[r].level = (size_t)-1;
        exp[r].group = (size_t)-1;
        exp[r].has_inject = 0;
    }

    const size_t max_h = p2c_mmix_max_height(cfg);
    const size_t depth = cfg->depth;
    size_t cur = 0;

    const size_t g0 = p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, max_h));
    for (size_t i = 0; i < g0; i++) {
        if (cur >= rows) return 0;
        exp[cur].type = DNAC_P2C_MMIX_ROW_LEAF;
        exp[cur].step = cur;
        exp[cur].group = 0;
        cur++;
    }

    for (size_t l = 0; l < depth; l++) {
        const size_t cur_after = max_h >> (l + 1);
        const int inj = p2c_mmix_present(cfg, cur_after);
        if (cur >= rows) return 0;
        exp[cur].type = DNAC_P2C_MMIX_ROW_COMPRESS;
        exp[cur].step = cur;
        exp[cur].level = l;
        exp[cur].has_inject = inj ? 1 : 0;
        cur++;
        if (inj) {
            const size_t gi = p2c_mmix_group_index_of(cfg, cur_after);
            const size_t lg =
                p2c_mmix_leaf_rows_h(p2c_mmix_concat_width(cfg, cur_after));
            for (size_t i = 0; i < lg; i++) {
                if (cur >= rows) return 0;
                exp[cur].type = DNAC_P2C_MMIX_ROW_INJECT_LEAF;
                exp[cur].step = cur;
                exp[cur].level = l;
                exp[cur].group = gi;
                cur++;
            }
            if (cur >= rows) return 0;
            exp[cur].type = DNAC_P2C_MMIX_ROW_INJECT_COMPRESS;
            exp[cur].step = cur;
            exp[cur].level = l;
            exp[cur].group = gi;
            cur++;
        }
    }

    if (cur >= rows) return 0;
    exp[cur].type = DNAC_P2C_MMIX_ROW_FINAL;
    exp[cur].step = cur;
    cur++;
    /* remaining rows already initialised to PAD. */
    return 1;
}

/* Which of the 6 primary flags is set (assumes exclusivity already checked). */
static dnac_p2c_mmix_row_type_t p2c_mmix_actual_type(const uint64_t *row)
{
    if (row[DNAC_P2C_MMIX_COL_IS_LEAF]) return DNAC_P2C_MMIX_ROW_LEAF;
    if (row[DNAC_P2C_MMIX_COL_IS_COMPRESS]) return DNAC_P2C_MMIX_ROW_COMPRESS;
    if (row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF]) return DNAC_P2C_MMIX_ROW_INJECT_LEAF;
    if (row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS]) {
        return DNAC_P2C_MMIX_ROW_INJECT_COMPRESS;
    }
    if (row[DNAC_P2C_MMIX_COL_IS_FINAL]) return DNAC_P2C_MMIX_ROW_FINAL;
    return DNAC_P2C_MMIX_ROW_PAD;
}

#define P2C_MMIX_FAIL(d)                                                      \
    do {                                                                      \
        if (out_defect) *out_defect = (d);                                    \
        return DNAC_P2C_MMIX_TABLE_ERR_SCHEDULE;                              \
    } while (0)

dnac_p2c_mmix_table_status_t dnac_p2c_mmix_table_validate(
    const dnac_p2c_mmix_table_cfg_t *cfg, const uint64_t *cells, size_t rows,
    dnac_p2c_mmix_table_defect_t *out_defect)
{
    if (out_defect) *out_defect = DNAC_P2C_MMIX_DEFECT_NONE;

    if (cells == NULL || !p2c_mmix_cfg_check(cfg)) {
        return DNAC_P2C_MMIX_TABLE_ERR_PARAM;
    }
    const size_t exp_rows = dnac_p2c_mmix_table_rows(cfg);
    if (exp_rows == 0 || rows != exp_rows) return DNAC_P2C_MMIX_TABLE_ERR_PARAM;

    const size_t cols = (size_t)DNAC_P2C_MMIX_TABLE_COLS;

    /* 1 — booleanity of every cell. There is NO field literal in this table, so
     *     a raw value not in {0,1} (incl. any >= p) is caught here; nothing on
     *     the verify path checks this (batch_verify.c:722-727), so it is frozen
     *     by the root pin. */
    for (size_t r = 0; r < rows; r++) {
        for (size_t k = 0; k < cols; k++) {
            if (cells[r * cols + k] > 1) P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_BOOLEAN);
        }
    }

    /* 2 — exactly one PRIMARY row type per row. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        const uint64_t set = row[DNAC_P2C_MMIX_COL_IS_LEAF] +
                             row[DNAC_P2C_MMIX_COL_IS_COMPRESS] +
                             row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF] +
                             row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS] +
                             row[DNAC_P2C_MMIX_COL_IS_FINAL] +
                             row[DNAC_P2C_MMIX_COL_IS_PAD];
        if (set != 1) P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_TYPE_EXCLUSIVE);
    }

    /* Reconstruct the expected schedule INDEPENDENTLY of the generator. Stack-
     * local so the validator stays re-entrant on the eventual verify path. */
    dnac_p2c_mmix_row_t exp[P2C_MMIX_MAX_TABLE_ROWS];
    if (!p2c_mmix_reconstruct(cfg, rows, exp)) {
        return DNAC_P2C_MMIX_TABLE_ERR_PARAM; /* unreachable for a valid cfg */
    }

    /* 3 — primary schedule: each row's primary type matches the reconstructed
     *     leaf | (compress [+ inject block])* | final | pad layout. Subsumes
     *     every row-type COUNT (a miscount shows up as a mismatched type at the
     *     boundary). */
    for (size_t r = 0; r < rows; r++) {
        if (p2c_mmix_actual_type(&cells[r * cols]) != exp[r].type) {
            P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_PRIMARY_SCHEDULE);
        }
    }

    /* 4 — has_inject: set iff a compress row at an injecting level. */
    for (size_t r = 0; r < rows; r++) {
        if (cells[r * cols + DNAC_P2C_MMIX_COL_HAS_INJECT] !=
            (uint64_t)exp[r].has_inject) {
            P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_HAS_INJECT);
        }
    }

    /* 5 — level one-hot: exp[r].level set on compress / inject rows; all-zero on
     *     the tallest leaf / final / pad. Routes the direction bit + sibling. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        for (size_t l = 0; l < DNAC_P2C_MMIX_MAX_LEVELS; l++) {
            const uint64_t want =
                (exp[r].level != (size_t)-1 && l == exp[r].level) ? 1u : 0u;
            if (row[dnac_p2c_mmix_col_lvl(l)] != want) {
                P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_LVL_ONEHOT);
            }
        }
    }

    /* 6 — group one-hot: exp[r].group set on leaf / inject rows; all-zero on
     *     compress / final / pad. Routes the group's opened-rows publics. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        for (size_t g = 0; g < DNAC_P2C_MMIX_MAX_GROUPS; g++) {
            const uint64_t want =
                (exp[r].group != (size_t)-1 && g == exp[r].group) ? 1u : 0u;
            if (row[dnac_p2c_mmix_col_gsel(g)] != want) {
                P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_GSEL_ONEHOT);
            }
        }
    }

    /* 7 — step one-hot: scheduled row k carries pos[k]=1 and nothing else;
     *     padding rows carry an all-zero one-hot. Also pins the prefix ORDER. */
    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &cells[r * cols];
        for (size_t k = 0; k < DNAC_P2C_MMIX_MAX_STEPS; k++) {
            const uint64_t want =
                (exp[r].step != (size_t)-1 && k == exp[r].step) ? 1u : 0u;
            if (row[dnac_p2c_mmix_col_pos(k)] != want) {
                P2C_MMIX_FAIL(DNAC_P2C_MMIX_DEFECT_POS_ONEHOT);
            }
        }
    }

    return DNAC_P2C_MMIX_TABLE_OK;
}

#undef P2C_MMIX_FAIL

/* ==========================================================================
 * PIN-1-MMIX comparator
 * ======================================================================== */

dnac_p2c_mmix_table_status_t dnac_p2c_mmix_prep_root_check(const uint64_t lanes[4])
{
    if (lanes == NULL) return DNAC_P2C_MMIX_TABLE_ERR_PARAM;

    /* An UNFILLED placeholder pin must never accept anything — least of all the
     * all-zero root it would otherwise match (mmcs_mixed_air_table.h, the
     * DNAC_P2C_MMIX_PREP_ROOT_UNFILLED contract). Compiles away once the
     * ORCHESTRATOR fills the constant from `--print-root`. */
    if (DNAC_P2C_MMIX_PREP_ROOT_UNFILLED) {
        return DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH;
    }

    static const uint64_t pinned[4] = DNAC_P2C_MMIX_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        if (lanes[k] != pinned[k]) return DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_P2C_MMIX_TABLE_OK;
}
