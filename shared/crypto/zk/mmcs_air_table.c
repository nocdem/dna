/**
 * @file mmcs_air_table.c
 * @brief P2b preprocessed row-type table generator + the PIN-1 comparator.
 *
 * See mmcs_air_table.h for the full grounding contract (row schedule derived
 * from poseidon2_mmcs.c:41-72 / Plonky3 11cc5849 symmetric/src/sponge.rs:
 * 172-204, PIN-1 derivation from batch_prover.c:787-826, PIN-2 from
 * batch_verify.c:696-707 vs batch_prover.c:311-313).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmcs_air_table.h"

#include <string.h>

/* The pinned reference config (mmcs_air_table.h DNAC_P2B_REF_*). */
static const size_t P2B_REF_WIDTHS[DNAC_P2B_REF_NUM_MATRICES] = {
    DNAC_P2B_REF_WIDTH_0, DNAC_P2B_REF_WIDTH_1
};
static const dnac_p2b_table_cfg_t P2B_REF_CFG = {
    DNAC_P2B_REF_NUM_MATRICES, P2B_REF_WIDTHS, DNAC_P2B_REF_DEPTH
};

const dnac_p2b_table_cfg_t *dnac_p2b_ref_cfg(void) { return &P2B_REF_CFG; }

/* Config validation + total_width, in one place so rows() and generate() can
 * never disagree about what they accept. Returns 0 on reject. */
static int p2b_total_width(const dnac_p2b_table_cfg_t *cfg, size_t *out_total)
{
    if (cfg == NULL || cfg->widths == NULL) return 0;
    if (cfg->num_matrices == 0 || cfg->num_matrices > DNAC_P2B_MAX_MATRICES) {
        return 0;
    }
    if (cfg->depth == 0 || cfg->depth > DNAC_P2B_MAX_DEPTH) return 0;

    size_t total = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->widths[m] == 0) return 0;
        if (cfg->widths[m] > DNAC_P2B_MAX_TOTAL_WIDTH - total) return 0;
        total += cfg->widths[m];
    }
    if (total == 0 || total > DNAC_P2B_MAX_TOTAL_WIDTH) return 0;

    *out_total = total;
    return 1;
}

/* Permutation count of dnac_p2_mmcs_hash_iter over `n` elements — one is_leaf
 * row each. OVERWRITE absorb, permute on a full block, NO extra permute when
 * the input is exhausted exactly at a block boundary, permute on a partial
 * final block (poseidon2_mmcs.c:53-69; sponge.rs:180-201 at 11cc5849). So:
 * n % RATE == 0 ⇒ n / RATE (no trailing permute), else n / RATE + 1.
 * `n` is > 0 here — p2b_total_width rejects an empty stream. */
static size_t p2b_leaf_rows(size_t n)
{
    const size_t full = n / DNAC_P2B_SPONGE_RATE;
    return (n % DNAC_P2B_SPONGE_RATE == 0) ? full : full + 1;
}

/* Round up to a power of two, minimum DNAC_P2B_MIN_ROWS. Returns 0 on
 * overflow (unreachable at the bounds above; kept fail-close). */
static size_t p2b_pad_pow2(size_t used)
{
    size_t h = DNAC_P2B_MIN_ROWS;
    while (h < used) {
        if (h > (size_t)-1 / 2) return 0;
        h <<= 1;
    }
    return h;
}

size_t dnac_p2b_table_rows(const dnac_p2b_table_cfg_t *cfg)
{
    size_t total = 0;
    if (!p2b_total_width(cfg, &total)) return 0;

    const size_t leaf = p2b_leaf_rows(total);
    /* leaf + depth + 1 (final). Bounded by MAX_TOTAL_WIDTH/RATE + MAX_DEPTH + 1,
     * so the sum cannot overflow at the accepted bounds. */
    const size_t used = leaf + cfg->depth + 1;
    return p2b_pad_pow2(used);
}

dnac_p2b_table_status_t dnac_p2b_table_generate(
    const dnac_p2b_table_cfg_t *cfg, uint64_t *out, size_t out_cells)
{
    size_t total = 0;
    if (out == NULL || !p2b_total_width(cfg, &total)) {
        return DNAC_P2B_TABLE_ERR_PARAM;
    }
    const size_t rows = dnac_p2b_table_rows(cfg);
    if (rows == 0) return DNAC_P2B_TABLE_ERR_PARAM;
    if (out_cells < rows * (size_t)DNAC_P2B_TABLE_COLS) {
        return DNAC_P2B_TABLE_ERR_CAPACITY;
    }

    /* Padding rows are all-zero (design §0.5: filler carries no row type). */
    memset(out, 0, rows * (size_t)DNAC_P2B_TABLE_COLS * sizeof(uint64_t));

    const size_t leaf = p2b_leaf_rows(total);
    size_t r = 0;
    for (size_t i = 0; i < leaf; i++, r++) {
        out[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_LEAF] = 1;
    }
    for (size_t i = 0; i < cfg->depth; i++, r++) {
        out[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_COMPRESS] = 1;
    }
    out[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_FINAL] = 1;

    return DNAC_P2B_TABLE_OK;
}

dnac_p2b_table_status_t dnac_p2b_prep_root_check(const uint64_t lanes[4])
{
    if (lanes == NULL) return DNAC_P2B_TABLE_ERR_PARAM;

    static const uint64_t pinned[4] = DNAC_P2B_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        if (lanes[k] != pinned[k]) return DNAC_P2B_TABLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_P2B_TABLE_OK;
}
