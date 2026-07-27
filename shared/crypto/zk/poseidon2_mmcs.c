/**
 * @file poseidon2_mmcs.c
 * @brief Poseidon2 Merkle MMCS over Goldilocks — 4-lane digests (P1b).
 *
 * See poseidon2_mmcs.h for the full grounding contract. Function bodies cite
 * the Plonky3 82cfad73 lines they port.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "poseidon2_mmcs.h"

#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "poseidon2_goldilocks.h"

#define P2M_WIDTH POSEIDON2_GOLD_WIDTH /* 8 */
#define P2M_RATE  4
#define P2M_OUT   DNAC_P2M_DIGEST_LANES /* 4 */

struct dnac_p2_mmcs_tree_s {
    size_t num_rows;
    size_t depth;              /* log2(num_rows) */
    dnac_p2_digest_t **layers; /* layers[0] = num_rows leaf digests;
                                * layers[l] has num_rows >> l digests;
                                * layers[depth][0] = root */
    /* Prover-side open support (merkle_smt batch-tree contract, ported):
     * internal row-major lane copies of the committed matrices, so
     * open_batch can hand out borrowed row pointers. */
    size_t     num_matrices;
    size_t    *widths;   /* [num_matrices] lane widths */
    uint64_t **mats;     /* [num_matrices][heights[m] * widths[m]] */
    /* MIXED-height trees only (P2L-d d1a): per-matrix heights; NULL for the
     * same-height form (all its paths unchanged). num_rows = max height. */
    size_t    *heights;
};

/* PaddingFreeSponge<Perm,8,4,4> hash_iter (sponge.rs:172-203): zero state;
 * absorb one block by OVERWRITING state[0..i] one element at a time; full
 * block => permute and continue; exhausted mid-block (i > 0) => permute and
 * stop; exhausted AT the block boundary (i == 0) => stop with NO extra
 * permute; squeeze state[0..OUT]. */
void dnac_p2_mmcs_hash_iter(const uint64_t *elems, size_t n,
                            uint64_t out[DNAC_P2M_DIGEST_LANES])
{
    uint64_t state[P2M_WIDTH];
    memset(state, 0, sizeof(state));

    size_t pos = 0;
    for (;;) {
        size_t i = 0;
        while (i < P2M_RATE && pos < n) {
            state[i] = elems[pos]; /* overwrite rate slot i */
            i++;
            pos++;
        }
        if (i == P2M_RATE) {
            /* full block absorbed — permute, continue (sponge.rs:198-199) */
            poseidon2_goldilocks8_permute(state);
            if (pos == n) break; /* boundary exhaustion: no extra permute */
        } else {
            /* input exhausted mid-block: permute iff i > 0 (sponge.rs:186-194) */
            if (i != 0) poseidon2_goldilocks8_permute(state);
            break;
        }
    }

    memcpy(out, state, P2M_OUT * sizeof(uint64_t));
}

/* TruncatedPermutation<Perm,2,4,8>::compress (compression.rs:40-48):
 * pre = left ‖ right (fills the full width), ONE permutation, out = pre[0..4]. */
void dnac_p2_mmcs_compress(const uint64_t left[DNAC_P2M_DIGEST_LANES],
                           const uint64_t right[DNAC_P2M_DIGEST_LANES],
                           uint64_t out[DNAC_P2M_DIGEST_LANES])
{
    uint64_t pre[P2M_WIDTH];
    memcpy(pre, left, P2M_OUT * sizeof(uint64_t));
    memcpy(pre + P2M_OUT, right, P2M_OUT * sizeof(uint64_t));
    poseidon2_goldilocks8_permute(pre);
    memcpy(out, pre, P2M_OUT * sizeof(uint64_t));
}

static int p2m_is_pow2(size_t x) { return x != 0 && (x & (x - 1)) == 0; }

static size_t p2m_log2(size_t x) {
    size_t d = 0;
    while (x > 1) {
        x >>= 1;
        d++;
    }
    return d;
}

/* Fail-close canonicality sweep (G-DET-P1-5): every lane must be < p. */
static int p2m_all_canonical(const uint64_t *v, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (v[i] >= GOLDILOCKS_P) return 0;
    return 1;
}

/* Leaf digest for row `r`: H over the concatenated rows of all matrices at r
 * (mmcs.rs:1097-1103 hash_iter_slices == flattened hash_iter). */
static void p2m_leaf_digest(const uint64_t *const *matrices,
                            const size_t *widths, size_t num_matrices,
                            size_t r, uint64_t *scratch, size_t total_width,
                            uint64_t out[P2M_OUT])
{
    size_t off = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        memcpy(scratch + off, matrices[m] + r * widths[m],
               widths[m] * sizeof(uint64_t));
        off += widths[m];
    }
    dnac_p2_mmcs_hash_iter(scratch, total_width, out);
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_commit(
    const uint64_t *const *matrices,
    const size_t          *widths,
    size_t                 num_matrices,
    size_t                 num_rows,
    dnac_p2_digest_t      *out_root,
    dnac_p2_mmcs_tree_t  **out_tree)
{
    if (!matrices || !widths || !out_root || num_matrices == 0 ||
        !p2m_is_pow2(num_rows))
        return DNAC_P2M_ERR_PARAM;

    size_t total_width = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        if (widths[m] == 0 || !matrices[m]) return DNAC_P2M_ERR_PARAM;
        if (!p2m_all_canonical(matrices[m], num_rows * widths[m]))
            return DNAC_P2M_ERR_NONCANONICAL;
        total_width += widths[m];
    }

    size_t depth = p2m_log2(num_rows);
    dnac_p2_mmcs_tree_t *t =
        (dnac_p2_mmcs_tree_t *)calloc(1, sizeof(*t));
    if (!t) return DNAC_P2M_ERR_ALLOC;
    t->num_rows = num_rows;
    t->depth = depth;
    t->layers =
        (dnac_p2_digest_t **)calloc(depth + 1, sizeof(dnac_p2_digest_t *));
    if (!t->layers) {
        free(t);
        return DNAC_P2M_ERR_ALLOC;
    }

    uint64_t *scratch = (uint64_t *)malloc(total_width * sizeof(uint64_t));
    if (!scratch) {
        dnac_p2_mmcs_tree_free(t);
        return DNAC_P2M_ERR_ALLOC;
    }

    /* layer 0: leaf digests (first_digest_layer, merkle_tree.rs:266-331) */
    t->layers[0] =
        (dnac_p2_digest_t *)malloc(num_rows * sizeof(dnac_p2_digest_t));
    if (!t->layers[0]) {
        free(scratch);
        dnac_p2_mmcs_tree_free(t);
        return DNAC_P2M_ERR_ALLOC;
    }
    for (size_t r = 0; r < num_rows; r++)
        p2m_leaf_digest(matrices, widths, num_matrices, r, scratch,
                        total_width, t->layers[0][r].lanes);
    free(scratch);

    /* internal layers: binary compress (compress_and_inject N=2, no inject) */
    for (size_t l = 1; l <= depth; l++) {
        size_t n = num_rows >> l;
        t->layers[l] = (dnac_p2_digest_t *)malloc(n * sizeof(dnac_p2_digest_t));
        if (!t->layers[l]) {
            dnac_p2_mmcs_tree_free(t);
            return DNAC_P2M_ERR_ALLOC;
        }
        for (size_t i = 0; i < n; i++)
            dnac_p2_mmcs_compress(t->layers[l - 1][2 * i].lanes,
                                  t->layers[l - 1][2 * i + 1].lanes,
                                  t->layers[l][i].lanes);
    }

    *out_root = t->layers[depth][0];
    if (out_tree) {
        /* Keep internal row copies for open_batch (borrowed-row contract). */
        t->num_matrices = num_matrices;
        t->widths = (size_t *)malloc(num_matrices * sizeof(size_t));
        t->mats = (uint64_t **)calloc(num_matrices, sizeof(uint64_t *));
        if (!t->widths || !t->mats) {
            dnac_p2_mmcs_tree_free(t);
            return DNAC_P2M_ERR_ALLOC;
        }
        for (size_t m = 0; m < num_matrices; m++) {
            size_t n = num_rows * widths[m];
            t->widths[m] = widths[m];
            t->mats[m] = (uint64_t *)malloc(n * sizeof(uint64_t));
            if (!t->mats[m]) {
                dnac_p2_mmcs_tree_free(t);
                return DNAC_P2M_ERR_ALLOC;
            }
            memcpy(t->mats[m], matrices[m], n * sizeof(uint64_t));
        }
        *out_tree = t;
    } else {
        dnac_p2_mmcs_tree_free(t);
    }
    return DNAC_P2M_OK;
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_open_batch(
    const dnac_p2_mmcs_tree_t *tree,
    uint64_t                   leaf_index,
    const uint64_t           **out_rows,
    dnac_p2_proof_t           *out_proof)
{
    if (!tree || !out_rows || !out_proof || !tree->mats)
        return DNAC_P2M_ERR_PARAM;
    if (leaf_index >= tree->num_rows) return DNAC_P2M_ERR_BAD_INDEX;
    if (tree->depth > 0 && !out_proof->siblings) return DNAC_P2M_ERR_PARAM;
    for (size_t m = 0; m < tree->num_matrices; m++)
        out_rows[m] = tree->mats[m] + (size_t)leaf_index * tree->widths[m];
    uint64_t idx = leaf_index;
    for (size_t l = 0; l < tree->depth; l++) {
        out_proof->siblings[l] = tree->layers[l][idx ^ 1];
        idx >>= 1;
    }
    out_proof->leaf_index = leaf_index;
    out_proof->depth = (uint32_t)tree->depth;
    out_proof->num_matrices = (uint32_t)tree->num_matrices;
    return DNAC_P2M_OK;
}

size_t dnac_p2_mmcs_tree_num_matrices(const dnac_p2_mmcs_tree_t *tree) {
    return tree ? tree->num_matrices : 0;
}

size_t dnac_p2_mmcs_tree_width(const dnac_p2_mmcs_tree_t *tree, size_t m) {
    if (!tree || !tree->widths || m >= tree->num_matrices) return 0;
    return tree->widths[m];
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_open(
    const dnac_p2_mmcs_tree_t *tree,
    uint64_t                   leaf_index,
    dnac_p2_digest_t          *out_siblings,
    size_t                    *out_depth)
{
    if (!tree || !out_siblings || !out_depth) return DNAC_P2M_ERR_PARAM;
    if (leaf_index >= tree->num_rows) return DNAC_P2M_ERR_BAD_INDEX;

    /* open_batch sibling walk (mmcs.rs:1009-1021): level l sibling =
     * layers[l][idx ^ 1], idx >>= 1 — leaf-level-first. */
    uint64_t idx = leaf_index;
    for (size_t l = 0; l < tree->depth; l++) {
        out_siblings[l] = tree->layers[l][idx ^ 1];
        idx >>= 1;
    }
    *out_depth = tree->depth;
    return DNAC_P2M_OK;
}

size_t dnac_p2_mmcs_tree_depth(const dnac_p2_mmcs_tree_t *tree) {
    return tree ? tree->depth : 0;
}

void dnac_p2_mmcs_tree_free(dnac_p2_mmcs_tree_t *tree) {
    if (!tree) return;
    if (tree->layers) {
        for (size_t l = 0; l <= tree->depth; l++) free(tree->layers[l]);
        free(tree->layers);
    }
    if (tree->mats) {
        for (size_t m = 0; m < tree->num_matrices; m++) free(tree->mats[m]);
        free(tree->mats);
    }
    free(tree->widths);
    free(tree->heights);
    free(tree);
}

/* ============================================================================
 * MIXED-height batch (P2L-d d1a) — merkle_tree.rs:127-176 build with N=2
 * (arity schedule all 2s, select_arity_step:227-242) + the mmcs.rs:1052-1180
 * verify walk. Power-of-two heights only (the DNAC batch shapes; the Rust
 * "heights rounding to the same pow2 must be equal" rule is then trivial).
 * ========================================================================== */

/* Hash the concatenation of rows at `row` from every matrix whose height is
 * `group_h`, in ORIGINAL insertion order (stable grouping,
 * merkle_tree.rs:113-116 / mmcs.rs:1098-1104). Returns the number of lanes
 * consumed (0 => no matrix of that height). */
static size_t p2m_group_row_concat(const uint64_t *const *matrices,
                                   const size_t *widths, const size_t *heights,
                                   size_t num_matrices, size_t group_h,
                                   size_t row, uint64_t *scratch)
{
    size_t off = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        if (heights[m] == group_h) {
            memcpy(scratch + off, matrices[m] + row * widths[m],
                   widths[m] * sizeof(uint64_t));
            off += widths[m];
        }
    }
    return off;
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_commit_mixed(
    const uint64_t *const *matrices,
    const size_t          *widths,
    const size_t          *heights,
    size_t                 num_matrices,
    dnac_p2_digest_t      *out_root,
    dnac_p2_mmcs_tree_t  **out_tree)
{
    if (!matrices || !widths || !heights || !out_root || num_matrices == 0)
        return DNAC_P2M_ERR_PARAM;

    size_t max_h = 0, total_width = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        if (widths[m] == 0 || !matrices[m] || !p2m_is_pow2(heights[m]))
            return DNAC_P2M_ERR_PARAM;
        if (!p2m_all_canonical(matrices[m], heights[m] * widths[m]))
            return DNAC_P2M_ERR_NONCANONICAL;
        if (heights[m] > max_h) max_h = heights[m];
        total_width += widths[m];
    }
    const size_t depth = p2m_log2(max_h);

    dnac_p2_mmcs_tree_t *t = (dnac_p2_mmcs_tree_t *)calloc(1, sizeof(*t));
    if (!t) return DNAC_P2M_ERR_ALLOC;
    t->num_rows = max_h;
    t->depth = depth;
    t->layers =
        (dnac_p2_digest_t **)calloc(depth + 1, sizeof(dnac_p2_digest_t *));
    uint64_t *scratch = (uint64_t *)malloc(total_width * sizeof(uint64_t));
    if (!t->layers || !scratch) {
        free(scratch);
        dnac_p2_mmcs_tree_free(t);
        return DNAC_P2M_ERR_ALLOC;
    }

    /* Leaf layer: the tallest group only (first_digest_layer,
     * merkle_tree.rs:129-136). */
    t->layers[0] =
        (dnac_p2_digest_t *)malloc(max_h * sizeof(dnac_p2_digest_t));
    if (!t->layers[0]) {
        free(scratch);
        dnac_p2_mmcs_tree_free(t);
        return DNAC_P2M_ERR_ALLOC;
    }
    for (size_t r = 0; r < max_h; r++) {
        size_t n = p2m_group_row_concat(matrices, widths, heights,
                                        num_matrices, max_h, r, scratch);
        dnac_p2_mmcs_hash_iter(scratch, n, t->layers[0][r].lanes);
    }

    /* Internal layers: binary compress + injection when a group's height
     * equals the new layer length (compress_and_inject with N=2,
     * merkle_tree.rs:139-168, 337-440: next[i] = C(C(prev[2i], prev[2i+1]),
     * H(injected rows at i)) when an injection group exists). */
    for (size_t l = 1; l <= depth; l++) {
        const size_t n = max_h >> l;
        int inject = 0;
        for (size_t m = 0; m < num_matrices; m++) {
            if (heights[m] == n && n != max_h) inject = 1;
        }
        t->layers[l] = (dnac_p2_digest_t *)malloc(n * sizeof(dnac_p2_digest_t));
        if (!t->layers[l]) {
            free(scratch);
            dnac_p2_mmcs_tree_free(t);
            return DNAC_P2M_ERR_ALLOC;
        }
        for (size_t i = 0; i < n; i++) {
            uint64_t d[P2M_OUT];
            dnac_p2_mmcs_compress(t->layers[l - 1][2 * i].lanes,
                                  t->layers[l - 1][2 * i + 1].lanes, d);
            if (inject) {
                size_t cnt = p2m_group_row_concat(matrices, widths, heights,
                                                  num_matrices, n, i, scratch);
                uint64_t rows_digest[P2M_OUT];
                dnac_p2_mmcs_hash_iter(scratch, cnt, rows_digest);
                dnac_p2_mmcs_compress(d, rows_digest, t->layers[l][i].lanes);
            } else {
                memcpy(t->layers[l][i].lanes, d, sizeof(d));
            }
        }
    }
    free(scratch);

    *out_root = t->layers[depth][0];
    if (out_tree) {
        t->num_matrices = num_matrices;
        t->widths = (size_t *)malloc(num_matrices * sizeof(size_t));
        t->heights = (size_t *)malloc(num_matrices * sizeof(size_t));
        t->mats = (uint64_t **)calloc(num_matrices, sizeof(uint64_t *));
        if (!t->widths || !t->heights || !t->mats) {
            dnac_p2_mmcs_tree_free(t);
            return DNAC_P2M_ERR_ALLOC;
        }
        for (size_t m = 0; m < num_matrices; m++) {
            size_t n = heights[m] * widths[m];
            t->widths[m] = widths[m];
            t->heights[m] = heights[m];
            t->mats[m] = (uint64_t *)malloc(n * sizeof(uint64_t));
            if (!t->mats[m]) {
                dnac_p2_mmcs_tree_free(t);
                return DNAC_P2M_ERR_ALLOC;
            }
            memcpy(t->mats[m], matrices[m], n * sizeof(uint64_t));
        }
        *out_tree = t;
    } else {
        dnac_p2_mmcs_tree_free(t);
    }
    return DNAC_P2M_OK;
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_open_mixed(
    const dnac_p2_mmcs_tree_t *tree,
    uint64_t                   index,
    const uint64_t           **out_rows,
    dnac_p2_proof_t           *out_proof)
{
    if (!tree || !out_rows || !out_proof || !tree->mats || !tree->heights)
        return DNAC_P2M_ERR_PARAM;
    if (index >= tree->num_rows) return DNAC_P2M_ERR_BAD_INDEX;
    if (tree->depth > 0 && !out_proof->siblings) return DNAC_P2M_ERR_PARAM;

    /* Per-matrix reduced index (mmcs.rs:989-998):
     * index >> (log_max - log2(height_m)). */
    for (size_t m = 0; m < tree->num_matrices; m++) {
        size_t shift = tree->depth - p2m_log2(tree->heights[m]);
        size_t reduced = (size_t)(index >> shift);
        out_rows[m] = tree->mats[m] + reduced * tree->widths[m];
    }
    /* Sibling walk is height-agnostic (one sibling per binary level,
     * mmcs.rs:1007-1019; injection combines carry no siblings). */
    uint64_t idx = index;
    for (size_t l = 0; l < tree->depth; l++) {
        out_proof->siblings[l] = tree->layers[l][idx ^ 1];
        idx >>= 1;
    }
    out_proof->leaf_index = index;
    out_proof->depth = (uint32_t)tree->depth;
    out_proof->num_matrices = (uint32_t)tree->num_matrices;
    return DNAC_P2M_OK;
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_verify_mixed(
    const dnac_p2_digest_t *root,
    const uint64_t *const  *opened_rows,
    const size_t           *widths,
    const size_t           *heights,
    size_t                  num_matrices,
    uint64_t                index,
    const dnac_p2_proof_t  *proof)
{
    if (!root || !opened_rows || !widths || !heights || num_matrices == 0 ||
        !proof)
        return DNAC_P2M_ERR_PARAM;
    /* `depth` is the LENGTH of `siblings`, not a caller-derived height — see
     * the poseidon2_mmcs.h contract. The walk below is bounded by it. */
    const size_t            depth    = (size_t)proof->depth;
    const dnac_p2_digest_t *siblings = proof->siblings;
    if (depth > 0 && !siblings) return DNAC_P2M_ERR_PARAM;

    size_t max_h = 0, total_width = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        if (widths[m] == 0 || !opened_rows[m] || !p2m_is_pow2(heights[m]))
            return DNAC_P2M_ERR_PARAM;
        if (!p2m_all_canonical(opened_rows[m], widths[m]))
            return DNAC_P2M_ERR_NONCANONICAL;
        if (heights[m] > max_h) max_h = heights[m];
        total_width += widths[m];
    }
    if (index >= max_h) return DNAC_P2M_ERR_BAD_INDEX; /* mmcs.rs:1094-1096 */
    /* opening_proof.len() != expected_proof_len => WrongHeight
     * (mmcs.rs:1110-1116; N=2 + cap 0 => expected = log2(max height)). */
    if (depth != p2m_log2(max_h))
        return DNAC_P2M_ERR_BAD_DEPTH;

    uint64_t *scratch = (uint64_t *)malloc(total_width * sizeof(uint64_t));
    if (!scratch) return DNAC_P2M_ERR_ALLOC;

    /* digest = H(concat tallest-group opened rows) (mmcs.rs:1098-1104). */
    uint64_t digest[P2M_OUT];
    {
        size_t n = p2m_group_row_concat(opened_rows, widths, heights,
                                        num_matrices, max_h, 0, scratch);
        /* opened rows are single rows: row index 0 within each opened slice */
        dnac_p2_mmcs_hash_iter(scratch, n, digest);
    }

    /* Walk (mmcs.rs:1120-1170): compress with the sibling (bit order), then
     * inject any group whose height equals the halved layer length. */
    uint64_t idx = index;
    size_t cur = max_h;
    for (size_t l = 0; l < depth; l++) {
        uint64_t next[P2M_OUT];
        if ((idx & 1) == 0)
            dnac_p2_mmcs_compress(digest, siblings[l].lanes, next);
        else
            dnac_p2_mmcs_compress(siblings[l].lanes, digest, next);
        memcpy(digest, next, sizeof(next));
        idx >>= 1;
        cur >>= 1;

        int has_group = 0;
        for (size_t m = 0; m < num_matrices; m++) {
            if (heights[m] == cur) has_group = 1;
        }
        if (has_group) {
            size_t n = p2m_group_row_concat(opened_rows, widths, heights,
                                            num_matrices, cur, 0, scratch);
            uint64_t rows_digest[P2M_OUT];
            dnac_p2_mmcs_hash_iter(scratch, n, rows_digest);
            dnac_p2_mmcs_compress(digest, rows_digest, next);
            memcpy(digest, next, sizeof(next));
        }
    }
    free(scratch);

    if (memcmp(digest, root->lanes, sizeof(digest)) != 0)
        return DNAC_P2M_ERR_ROOT_MISMATCH;
    return DNAC_P2M_OK;
}

dnac_p2_mmcs_status_t dnac_p2_mmcs_verify(
    const dnac_p2_digest_t *root,
    const uint64_t *const  *opened_rows,
    const size_t           *widths,
    size_t                  num_matrices,
    size_t                  num_rows,
    uint64_t                leaf_index,
    const dnac_p2_proof_t  *proof)
{
    if (!root || !opened_rows || !widths || num_matrices == 0 ||
        !p2m_is_pow2(num_rows) || !proof)
        return DNAC_P2M_ERR_PARAM;
    /* `depth` is the LENGTH of `siblings`, not a caller-derived height — see
     * the poseidon2_mmcs.h contract. The walk below is bounded by it. */
    const size_t            depth    = (size_t)proof->depth;
    const dnac_p2_digest_t *siblings = proof->siblings;
    if (depth > 0 && !siblings) return DNAC_P2M_ERR_PARAM;
    if (leaf_index >= num_rows) return DNAC_P2M_ERR_BAD_INDEX; /* mmcs.rs:1093 */
    /* opening_proof.len() != expected_proof_len => WrongHeight
     * (mmcs.rs:1110-1116; N=2 + cap 0 => expected = log2(num_rows)). */
    if (depth != p2m_log2(num_rows))
        return DNAC_P2M_ERR_BAD_DEPTH;

    size_t total_width = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        if (widths[m] == 0 || !opened_rows[m]) return DNAC_P2M_ERR_PARAM;
        if (!p2m_all_canonical(opened_rows[m], widths[m]))
            return DNAC_P2M_ERR_NONCANONICAL;
        total_width += widths[m];
    }

    /* leaf digest from the opened rows (mmcs.rs:1097-1103) */
    uint64_t *scratch = (uint64_t *)malloc(total_width * sizeof(uint64_t));
    if (!scratch) return DNAC_P2M_ERR_ALLOC;
    {
        size_t off = 0;
        for (size_t m = 0; m < num_matrices; m++) {
            memcpy(scratch + off, opened_rows[m],
                   widths[m] * sizeof(uint64_t));
            off += widths[m];
        }
    }
    uint64_t digest[P2M_OUT];
    dnac_p2_mmcs_hash_iter(scratch, total_width, digest);
    free(scratch);

    /* walk (mmcs.rs:1118-1141): pos_in_group = index % 2 — bit 0 => digest
     * is the LEFT input, else RIGHT; index /= 2 per level. */
    uint64_t idx = leaf_index;
    for (size_t l = 0; l < depth; l++) {
        uint64_t next[P2M_OUT];
        if ((idx & 1) == 0)
            dnac_p2_mmcs_compress(digest, siblings[l].lanes, next);
        else
            dnac_p2_mmcs_compress(siblings[l].lanes, digest, next);
        memcpy(digest, next, sizeof(next));
        idx >>= 1;
    }

    /* cap 0 root compare (mmcs.rs:1172-1179) */
    if (memcmp(digest, root->lanes, sizeof(digest)) != 0)
        return DNAC_P2M_ERR_ROOT_MISMATCH;
    return DNAC_P2M_OK;
}
