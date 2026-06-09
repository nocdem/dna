/**
 * @file merkle_smt.c
 * @brief Binary Merkle / MMCS core implementation (Stage M2, 2026-05-27).
 *
 * See merkle_smt.h for the contract. This file implements:
 *   - dnac_merkle_commit
 *   - dnac_merkle_open
 *   - dnac_merkle_tree_free
 *   - dnac_merkle_verify
 *
 * Source mapping (Plonky3 commit 82cfad73):
 *   - Leaf hash semantics: merkle-tree/src/merkle_tree.rs:266-327 (first_digest_layer).
 *   - Parent compression: symmetric/src/compression.rs:51-78
 *     (CompressionFunctionFromHasher::compress = hash_iter(flatten)).
 *   - Verify loop side selection: merkle-tree/src/mmcs.rs:1125, 1127-1142.
 *   - Sibling order during open: merkle-tree/src/mmcs.rs:1009-1019.
 *   - Cap_height = 0 single-root semantics: symmetric/src/hash.rs:22-23, 53-55.
 *   - Goldilocks canonical encoding: field/src/integers.rs:556-588
 *     (impl_raw_serializable_primefield64! → to_unique_u64().to_le_bytes()).
 *   - Modulus p = 2^64 - 2^32 + 1: goldilocks/src/goldilocks.rs:27.
 *
 * Determinism rules (design § 3.1):
 *   D1 canonical Goldilocks encoding — rejected at commit with NONCANONICAL.
 *   D3 leaf hash input = byte_stream(row_i), no separator.
 *   D4 parent hash input = L ‖ R, 128 bytes, no separator.
 *   D5 sibling order = level-0 first.
 *   D6 index bit order = LSB-first, level 0 first.
 *   D8 default_digest padding — N/A in this scope (single matrix, pow2 height).
 *   D10 FIPS-202 SHA3-512 backend — uses crypto/hash/qgp_sha3.h one-shot.
 */

#include "merkle_smt.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* -------------------------------------------------------------------------- */
/* Internal constants                                                         */
/* -------------------------------------------------------------------------- */

/* Goldilocks modulus p = 2^64 - 2^32 + 1.
 * Cited from Plonky3 goldilocks.rs:27 (`pub(crate) const P: u64 = ...`).
 * Used by the canonical check in merkle_validate_rows_canonical(). */
#define DNAC_MERKLE_GOLDILOCKS_P 0xFFFFFFFF00000001ULL

/* -------------------------------------------------------------------------- */
/* Opaque tree                                                                */
/* -------------------------------------------------------------------------- */

/* The tree owns three heap allocations:
 *   1. `rows`         — copy of the input matrix, row-major.
 *   2. `digest_layers`— flat array of all internal digests.
 *      Layer 0 holds `num_rows` leaf digests (= num_rows entries).
 *      Layer 1 holds `num_rows/2` parent digests, …
 *      Layer `depth` holds 1 digest (root). Total = 2*num_rows - 1.
 *   3. The struct itself.
 *
 * `layer_offsets[i]` gives the index of layer i's first digest within
 * `digest_layers`. For depth d:
 *   layer_offsets[0] = 0
 *   layer_offsets[1] = num_rows
 *   layer_offsets[2] = num_rows + num_rows/2
 *   ...
 *   layer_offsets[d] = 2*num_rows - 2  (root sits at this offset, one entry)
 *
 * For num_rows = 1 (depth = 0): digest_layers has exactly 1 entry (the root,
 * which is also the leaf hash); layer_offsets = {0}. */
struct dnac_merkle_tree_s {
    uint8_t              *rows;          /* owned: num_rows * row_byte_len bytes */
    size_t                row_byte_len;
    size_t                num_rows;
    uint32_t              depth;         /* log2(num_rows) */
    dnac_merkle_digest_t *digest_layers; /* owned: 2*num_rows - 1 digests */
    size_t               *layer_offsets; /* owned: depth + 1 entries */
};

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/* Test whether `n` is a power of two and ≥ 1. */
static int dnac_is_pow2(size_t n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

/* Compute log2(n) for n a positive power of two. */
static uint32_t dnac_log2_pow2(size_t n)
{
    uint32_t k = 0;
    while ((n >> k) > 1) {
        k++;
    }
    return k;
}

/* Validate that every 8-byte chunk in `rows` decodes (little-endian) to a
 * canonical Goldilocks u64 in [0, p). Per design § 3.1 D1 — enforces byte
 * identity with the Rust oracle's Goldilocks::to_unique_u64 path
 * (Plonky3 field/src/integers.rs:563 + goldilocks.rs:516-523). */
static dnac_merkle_status_t dnac_merkle_validate_rows_canonical(
    const uint8_t *rows, size_t row_byte_len, size_t num_rows)
{
    const size_t total_chunks = (row_byte_len / 8) * num_rows;
    for (size_t i = 0; i < total_chunks; i++) {
        const uint8_t *p = rows + i * 8;
        /* Explicit little-endian decode — no memcpy aliasing, no endian
         * dependence on the host. Matches Plonky3
         * u64::from_le_bytes semantics. */
        uint64_t v = (uint64_t)p[0]
                   | ((uint64_t)p[1] << 8)
                   | ((uint64_t)p[2] << 16)
                   | ((uint64_t)p[3] << 24)
                   | ((uint64_t)p[4] << 32)
                   | ((uint64_t)p[5] << 40)
                   | ((uint64_t)p[6] << 48)
                   | ((uint64_t)p[7] << 56);
        if (v >= DNAC_MERKLE_GOLDILOCKS_P) {
            return DNAC_MERKLE_ERR_NONCANONICAL;
        }
    }
    return DNAC_MERKLE_OK;
}

/* Compute parent = SHA3-512(left ‖ right). Buffer is a fixed 128-byte stack
 * scratch — no heap, no incremental sponge state (design § 9 rule 9). */
static dnac_merkle_status_t dnac_merkle_compress_pair(
    const dnac_merkle_digest_t *left,
    const dnac_merkle_digest_t *right,
    dnac_merkle_digest_t       *out)
{
    uint8_t buf[2 * DNAC_MERKLE_DIGEST_BYTES];
    memcpy(buf, left->bytes, DNAC_MERKLE_DIGEST_BYTES);
    memcpy(buf + DNAC_MERKLE_DIGEST_BYTES, right->bytes, DNAC_MERKLE_DIGEST_BYTES);

    /* qgp_sha3_512 returns 0 on success; treat any non-zero as backend failure.
     * The function operates on a contiguous 128-byte buffer — identical to
     * Plonky3 CompressionFunctionFromHasher::compress flattening [L, R] into
     * a 128-byte stream (compression.rs:67-69). */
    if (qgp_sha3_512(buf, sizeof(buf), out->bytes) != 0) {
        return DNAC_MERKLE_ERR_OOM;
    }
    return DNAC_MERKLE_OK;
}

/* -------------------------------------------------------------------------- */
/* Public API: commit                                                          */
/* -------------------------------------------------------------------------- */

dnac_merkle_status_t dnac_merkle_commit(
    const uint8_t            *rows,
    size_t                    row_byte_len,
    size_t                    num_rows,
    dnac_merkle_digest_t     *out_root,
    dnac_merkle_tree_t      **out_tree)
{
    if (!rows || !out_root || !out_tree) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }
    /* Row byte length must be a positive multiple of 8 (Goldilocks element
     * width per design § 5.1). */
    if (row_byte_len == 0 || (row_byte_len % 8) != 0) {
        return DNAC_MERKLE_ERR_BAD_HEIGHT;
    }
    /* Number of rows must be a positive power of two (design § 1.1 first scope —
     * no padded_len logic, no default_digest padding). */
    if (!dnac_is_pow2(num_rows)) {
        return DNAC_MERKLE_ERR_BAD_HEIGHT;
    }

    /* Canonical-encoding gate (design § 3.1 D1) — runs BEFORE any allocation
     * so a malformed input returns cheaply. */
    dnac_merkle_status_t rc =
        dnac_merkle_validate_rows_canonical(rows, row_byte_len, num_rows);
    if (rc != DNAC_MERKLE_OK) {
        return rc;
    }

    const uint32_t depth = dnac_log2_pow2(num_rows);
    /* Total digest count = num_rows + num_rows/2 + ... + 1 = 2*num_rows - 1.
     * For num_rows = 1: total = 1 (root, which is also the leaf hash). */
    const size_t total_digests = 2 * num_rows - 1;
    const size_t total_row_bytes = num_rows * row_byte_len;

    /* Allocate everything up front. On any failure free what was allocated. */
    dnac_merkle_tree_t *t = (dnac_merkle_tree_t *)calloc(1, sizeof(*t));
    if (!t) {
        return DNAC_MERKLE_ERR_OOM;
    }
    t->rows = (uint8_t *)malloc(total_row_bytes);
    t->digest_layers =
        (dnac_merkle_digest_t *)calloc(total_digests, sizeof(*t->digest_layers));
    t->layer_offsets = (size_t *)calloc((size_t)depth + 1, sizeof(*t->layer_offsets));
    if (!t->rows || !t->digest_layers || !t->layer_offsets) {
        dnac_merkle_tree_free(t);
        return DNAC_MERKLE_ERR_OOM;
    }

    memcpy(t->rows, rows, total_row_bytes);
    t->row_byte_len = row_byte_len;
    t->num_rows     = num_rows;
    t->depth        = depth;

    /* layer_offsets[i] = sum_{j<i} (num_rows >> j) */
    {
        size_t acc = 0;
        for (uint32_t i = 0; i <= depth; i++) {
            t->layer_offsets[i] = acc;
            acc += (num_rows >> i);
        }
    }

    /* Layer 0: leaf hashes. leaf[i] = SHA3-512(row_i_bytes).
     * Plonky3 reference: merkle_tree.rs:266-327, the `h.hash_iter(row)` call. */
    for (size_t i = 0; i < num_rows; i++) {
        const uint8_t *row_ptr = t->rows + i * row_byte_len;
        if (qgp_sha3_512(row_ptr, row_byte_len,
                         t->digest_layers[i].bytes) != 0) {
            dnac_merkle_tree_free(t);
            return DNAC_MERKLE_ERR_OOM;
        }
    }

    /* Layers 1..depth: each parent = SHA3-512(left ‖ right).
     * Plonky3 reference: compression.rs:67-69 + the per-level loop semantics
     * of MerkleTree::new (merkle_tree.rs:139-168). With single matrix +
     * pow2 height + N=2, arity_schedule is uniformly 2 and the inject branch
     * never fires (verified in audit Q1, GROUNDED).
     *
     * For num_rows = 1 (depth = 0) this loop body does not execute — the root
     * is already in digest_layers[0] (the single leaf hash). */
    for (uint32_t lvl = 1; lvl <= depth; lvl++) {
        const size_t parent_count = num_rows >> lvl;
        const size_t child_off    = t->layer_offsets[lvl - 1];
        const size_t parent_off   = t->layer_offsets[lvl];
        for (size_t p = 0; p < parent_count; p++) {
            dnac_merkle_status_t srh = dnac_merkle_compress_pair(
                &t->digest_layers[child_off + 2 * p],
                &t->digest_layers[child_off + 2 * p + 1],
                &t->digest_layers[parent_off + p]);
            if (srh != DNAC_MERKLE_OK) {
                dnac_merkle_tree_free(t);
                return srh;
            }
        }
    }

    /* Root is the last entry. For depth = 0 it's the single leaf hash;
     * for depth ≥ 1 it's the last digest in the layer of length 1. */
    memcpy(out_root->bytes,
           t->digest_layers[total_digests - 1].bytes,
           DNAC_MERKLE_DIGEST_BYTES);
    *out_tree = t;
    return DNAC_MERKLE_OK;
}

/* -------------------------------------------------------------------------- */
/* Public API: open                                                            */
/* -------------------------------------------------------------------------- */

dnac_merkle_status_t dnac_merkle_open(
    const dnac_merkle_tree_t *tree,
    uint64_t                  leaf_index,
    const uint8_t           **out_leaf_bytes,
    size_t                   *out_leaf_byte_len,
    dnac_merkle_proof_t      *out_proof)
{
    if (!tree || !out_leaf_bytes || !out_leaf_byte_len || !out_proof) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }
    if (leaf_index >= tree->num_rows) {
        return DNAC_MERKLE_ERR_BAD_INDEX;
    }
    if (out_proof->depth != tree->depth) {
        return DNAC_MERKLE_ERR_BAD_DEPTH;
    }
    /* For depth > 0 the caller MUST have allocated siblings; for depth == 0
     * we never write to siblings, so NULL is acceptable. */
    if (tree->depth > 0 && out_proof->siblings == NULL) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }

    out_proof->leaf_index   = leaf_index;
    /* Single-matrix open populates num_matrices = 1 for forward compatibility
     * with the batch API's shape check. Legacy single-matrix verify ignores
     * the field. */
    out_proof->num_matrices = 1;

    /* Sibling-walk per design § 5.5 / Plonky3 mmcs.rs:1009-1019:
     *   for layer_idx in 0..depth:
     *     sibling = digest_layers[layer_idx][(idx ^ 1)]
     *     idx >>= 1
     * The XOR-1 is the binary-tree formulation of `group_start + k` for
     * `k != pos_in_group` when step = 2. */
    {
        uint64_t idx = leaf_index;
        for (uint32_t lvl = 0; lvl < tree->depth; lvl++) {
            const size_t sib_pos  = (size_t)(idx ^ 1ULL);
            const size_t layer_off = tree->layer_offsets[lvl];
            memcpy(out_proof->siblings[lvl].bytes,
                   tree->digest_layers[layer_off + sib_pos].bytes,
                   DNAC_MERKLE_DIGEST_BYTES);
            idx >>= 1;
        }
    }

    /* Leaf bytes are borrowed from the tree's owned row copy. */
    *out_leaf_bytes    = tree->rows + (size_t)leaf_index * tree->row_byte_len;
    *out_leaf_byte_len = tree->row_byte_len;
    return DNAC_MERKLE_OK;
}

/* -------------------------------------------------------------------------- */
/* Public API: free                                                            */
/* -------------------------------------------------------------------------- */

void dnac_merkle_tree_free(dnac_merkle_tree_t *tree)
{
    if (!tree) {
        return;
    }
    if (tree->rows) {
        free(tree->rows);
    }
    if (tree->digest_layers) {
        free(tree->digest_layers);
    }
    if (tree->layer_offsets) {
        free(tree->layer_offsets);
    }
    free(tree);
}

/* -------------------------------------------------------------------------- */
/* Public API: verify                                                          */
/* -------------------------------------------------------------------------- */

dnac_merkle_status_t dnac_merkle_verify(
    const dnac_merkle_digest_t *root,
    const uint8_t              *leaf_bytes,
    size_t                      leaf_byte_len,
    const dnac_merkle_proof_t  *proof)
{
    if (!root || !leaf_bytes || !proof) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }
    if (leaf_byte_len == 0) {
        return DNAC_MERKLE_ERR_BAD_HEIGHT;
    }
    /* `siblings` may be NULL only when depth == 0 (no siblings consumed). */
    if (proof->depth > 0 && proof->siblings == NULL) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }

    /* Start digest = SHA3-512(leaf_bytes). Design § 5.3.
     * No domain separator, no length prefix — matches Plonky3
     * SerializingHasher<Sha3_512Hash> → into_byte_stream → SHA3-512 path. */
    dnac_merkle_digest_t digest;
    if (qgp_sha3_512(leaf_bytes, leaf_byte_len, digest.bytes) != 0) {
        return DNAC_MERKLE_ERR_OOM;
    }

    /* Verify loop. Design § 5.6 / Plonky3 mmcs.rs:1125, 1127-1142:
     *   bit i of leaf_index selects pos at level i (LSB-first)
     *   bit == 0  →  parent = SHA3-512(digest ‖ sibling)
     *   bit == 1  →  parent = SHA3-512(sibling ‖ digest)
     * For depth == 0 the loop body never executes — digest IS the root claim. */
    for (uint32_t i = 0; i < proof->depth; i++) {
        const uint64_t bit = (proof->leaf_index >> i) & 1ULL;
        dnac_merkle_digest_t next;
        dnac_merkle_status_t rc;
        if (bit == 0ULL) {
            rc = dnac_merkle_compress_pair(&digest, &proof->siblings[i], &next);
        } else {
            rc = dnac_merkle_compress_pair(&proof->siblings[i], &digest, &next);
        }
        if (rc != DNAC_MERKLE_OK) {
            return rc;
        }
        digest = next;
    }

    /* Constant-time byte comparison would be a nice-to-have here, but per
     * design § 4.3 NG3 the Merkle verifier operates on public data so timing
     * leaks are not security-relevant. memcmp is sufficient. */
    if (memcmp(digest.bytes, root->bytes, DNAC_MERKLE_DIGEST_BYTES) != 0) {
        return DNAC_MERKLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_MERKLE_OK;
}

/* ========================================================================== */
/* Phase 2A — Same-height multi-matrix batch API                              */
/*                                                                            */
/* Per dnac/docs/plans/2026-05-26-merkle-mmcs-design.md § 1.4.                */
/*                                                                            */
/* Source mapping (Plonky3 commit 82cfad73):                                  */
/*   - Multi-matrix leaf hash (concat by hash_iter_slices):                   */
/*       merkle-tree/src/mmcs.rs:1100-1104                                    */
/*   - verify_batch shape + per-level loop:                                   */
/*       merkle-tree/src/mmcs.rs:1052-1180 (binary same-height case has no    */
/*       arity bridge and no injection — schedule is uniformly 2)             */
/*   - Sibling order during open: unchanged from single-matrix                */
/*       (merkle-tree/src/mmcs.rs:1009-1019)                                  */
/* ========================================================================== */

struct dnac_merkle_batch_tree_s {
    size_t                  num_matrices;
    size_t                  num_rows;        /* shared across matrices */
    uint32_t                depth;           /* log2(num_rows) */
    size_t                 *row_byte_lens;   /* owned: array[num_matrices] */
    uint8_t               **rows_per_matrix; /* owned: array[num_matrices] of owned row buffers */
    dnac_merkle_digest_t   *digest_layers;   /* owned: 2*num_rows - 1 digests */
    size_t                 *layer_offsets;   /* owned: depth + 1 entries */
};

/* Sum the bytes-per-row across all matrices (the leaf-concat buffer size). */
static size_t dnac_merkle_batch_sum_row_bytes(const size_t *row_byte_lens, size_t num_matrices)
{
    size_t total = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        total += row_byte_lens[m];
    }
    return total;
}

/* Concat row `idx` from each matrix into `out_buf` in original commit order.
 * `out_buf` must be sized to dnac_merkle_batch_sum_row_bytes(row_byte_lens, num_matrices). */
static void dnac_merkle_batch_concat_row(
    uint8_t                  *out_buf,
    const uint8_t * const    *matrices_rows,
    const size_t             *row_byte_lens,
    size_t                    num_matrices,
    size_t                    row_index)
{
    size_t off = 0;
    for (size_t m = 0; m < num_matrices; m++) {
        const size_t rlen = row_byte_lens[m];
        memcpy(out_buf + off, matrices_rows[m] + row_index * rlen, rlen);
        off += rlen;
    }
}

dnac_merkle_status_t dnac_merkle_batch_commit(
    const uint8_t * const     *matrices_rows,
    const size_t              *row_byte_lens,
    size_t                     num_matrices,
    size_t                     num_rows,
    dnac_merkle_digest_t      *out_root,
    dnac_merkle_batch_tree_t **out_tree)
{
    if (!matrices_rows || !row_byte_lens || !out_root || !out_tree) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }
    if (num_matrices == 0) {
        return DNAC_MERKLE_ERR_WRONG_BATCH_SIZE;
    }
    /* Validate each row_byte_lens entry is positive and a multiple of 8. */
    for (size_t m = 0; m < num_matrices; m++) {
        if (row_byte_lens[m] == 0 || (row_byte_lens[m] % 8) != 0) {
            return DNAC_MERKLE_ERR_BAD_HEIGHT;
        }
        if (!matrices_rows[m]) {
            return DNAC_MERKLE_ERR_NULL_ARG;
        }
    }
    if (!dnac_is_pow2(num_rows)) {
        return DNAC_MERKLE_ERR_BAD_HEIGHT;
    }

    /* Canonical-encoding gate (design § 3.1 D1) — per matrix, BEFORE allocation. */
    for (size_t m = 0; m < num_matrices; m++) {
        dnac_merkle_status_t rc = dnac_merkle_validate_rows_canonical(
            matrices_rows[m], row_byte_lens[m], num_rows);
        if (rc != DNAC_MERKLE_OK) {
            return rc;
        }
    }

    const uint32_t depth         = dnac_log2_pow2(num_rows);
    const size_t   total_digests = 2 * num_rows - 1;
    const size_t   concat_bytes  = dnac_merkle_batch_sum_row_bytes(row_byte_lens, num_matrices);

    dnac_merkle_batch_tree_t *t =
        (dnac_merkle_batch_tree_t *)calloc(1, sizeof(*t));
    if (!t) {
        return DNAC_MERKLE_ERR_OOM;
    }
    t->num_matrices = num_matrices;
    t->num_rows     = num_rows;
    t->depth        = depth;

    t->row_byte_lens =
        (size_t *)calloc(num_matrices, sizeof(*t->row_byte_lens));
    t->rows_per_matrix =
        (uint8_t **)calloc(num_matrices, sizeof(*t->rows_per_matrix));
    t->digest_layers =
        (dnac_merkle_digest_t *)calloc(total_digests, sizeof(*t->digest_layers));
    t->layer_offsets =
        (size_t *)calloc((size_t)depth + 1, sizeof(*t->layer_offsets));

    if (!t->row_byte_lens || !t->rows_per_matrix
        || !t->digest_layers || !t->layer_offsets) {
        dnac_merkle_batch_tree_free(t);
        return DNAC_MERKLE_ERR_OOM;
    }

    for (size_t m = 0; m < num_matrices; m++) {
        const size_t rlen        = row_byte_lens[m];
        const size_t total_bytes = rlen * num_rows;
        t->row_byte_lens[m]   = rlen;
        t->rows_per_matrix[m] = (uint8_t *)malloc(total_bytes);
        if (!t->rows_per_matrix[m]) {
            dnac_merkle_batch_tree_free(t);
            return DNAC_MERKLE_ERR_OOM;
        }
        memcpy(t->rows_per_matrix[m], matrices_rows[m], total_bytes);
    }

    /* layer_offsets[i] = sum_{j<i} (num_rows >> j) */
    {
        size_t acc = 0;
        for (uint32_t i = 0; i <= depth; i++) {
            t->layer_offsets[i] = acc;
            acc += (num_rows >> i);
        }
    }

    /* Leaf layer: per-row SHA3-512 over the concatenation of all matrices'
     * rows at that index (Plonky3 mmcs.rs:1100-1104 semantics). For N=1 this
     * degenerates to SHA3-512(single row bytes) — byte-identical to the
     * single-matrix commit path. */
    {
        uint8_t *concat = (uint8_t *)malloc(concat_bytes);
        if (!concat) {
            dnac_merkle_batch_tree_free(t);
            return DNAC_MERKLE_ERR_OOM;
        }
        for (size_t i = 0; i < num_rows; i++) {
            dnac_merkle_batch_concat_row(
                concat,
                /* feed from the tree's owned copy so the caller's pointers
                 * are not aliased while we hash */
                (const uint8_t * const *)t->rows_per_matrix,
                row_byte_lens, num_matrices, i);
            if (qgp_sha3_512(concat, concat_bytes,
                             t->digest_layers[i].bytes) != 0) {
                free(concat);
                dnac_merkle_batch_tree_free(t);
                return DNAC_MERKLE_ERR_OOM;
            }
        }
        free(concat);
    }

    /* Internal layers: identical to single-matrix path (binary same-height
     * has no arity bridges and no injection — schedule is uniformly 2). */
    for (uint32_t lvl = 1; lvl <= depth; lvl++) {
        const size_t parent_count = num_rows >> lvl;
        const size_t child_off    = t->layer_offsets[lvl - 1];
        const size_t parent_off   = t->layer_offsets[lvl];
        for (size_t p = 0; p < parent_count; p++) {
            dnac_merkle_status_t srh = dnac_merkle_compress_pair(
                &t->digest_layers[child_off + 2 * p],
                &t->digest_layers[child_off + 2 * p + 1],
                &t->digest_layers[parent_off + p]);
            if (srh != DNAC_MERKLE_OK) {
                dnac_merkle_batch_tree_free(t);
                return srh;
            }
        }
    }

    memcpy(out_root->bytes,
           t->digest_layers[total_digests - 1].bytes,
           DNAC_MERKLE_DIGEST_BYTES);
    *out_tree = t;
    return DNAC_MERKLE_OK;
}

dnac_merkle_status_t dnac_merkle_batch_open(
    const dnac_merkle_batch_tree_t *tree,
    uint64_t                        leaf_index,
    const uint8_t                 **out_opened_rows,
    dnac_merkle_proof_t            *out_proof)
{
    if (!tree || !out_opened_rows || !out_proof) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }
    if (leaf_index >= tree->num_rows) {
        return DNAC_MERKLE_ERR_BAD_INDEX;
    }
    if (out_proof->depth != tree->depth) {
        return DNAC_MERKLE_ERR_BAD_DEPTH;
    }
    if (tree->depth > 0 && out_proof->siblings == NULL) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }

    out_proof->leaf_index   = leaf_index;
    out_proof->num_matrices = (uint32_t)tree->num_matrices;

    /* Sibling walk — identical to single-matrix path. */
    {
        uint64_t idx = leaf_index;
        for (uint32_t lvl = 0; lvl < tree->depth; lvl++) {
            const size_t sib_pos   = (size_t)(idx ^ 1ULL);
            const size_t layer_off = tree->layer_offsets[lvl];
            memcpy(out_proof->siblings[lvl].bytes,
                   tree->digest_layers[layer_off + sib_pos].bytes,
                   DNAC_MERKLE_DIGEST_BYTES);
            idx >>= 1;
        }
    }

    /* Per-matrix borrowed row pointers, original commit order. */
    for (size_t m = 0; m < tree->num_matrices; m++) {
        out_opened_rows[m] = tree->rows_per_matrix[m]
                           + (size_t)leaf_index * tree->row_byte_lens[m];
    }
    return DNAC_MERKLE_OK;
}

size_t dnac_merkle_batch_tree_num_matrices(const dnac_merkle_batch_tree_t *tree)
{
    return tree ? tree->num_matrices : 0;
}

size_t dnac_merkle_batch_tree_row_byte_len(const dnac_merkle_batch_tree_t *tree, size_t m)
{
    if (!tree || m >= tree->num_matrices) {
        return 0;
    }
    return tree->row_byte_lens[m];
}

size_t dnac_merkle_batch_tree_num_rows(const dnac_merkle_batch_tree_t *tree)
{
    return tree ? tree->num_rows : 0;
}

void dnac_merkle_batch_tree_free(dnac_merkle_batch_tree_t *tree)
{
    if (!tree) {
        return;
    }
    if (tree->rows_per_matrix) {
        for (size_t m = 0; m < tree->num_matrices; m++) {
            if (tree->rows_per_matrix[m]) {
                free(tree->rows_per_matrix[m]);
            }
        }
        free(tree->rows_per_matrix);
    }
    if (tree->row_byte_lens) {
        free(tree->row_byte_lens);
    }
    if (tree->digest_layers) {
        free(tree->digest_layers);
    }
    if (tree->layer_offsets) {
        free(tree->layer_offsets);
    }
    free(tree);
}

dnac_merkle_status_t dnac_merkle_batch_verify(
    const dnac_merkle_digest_t  *root,
    const uint8_t * const       *opened_rows,
    const size_t                *row_byte_lens,
    size_t                       num_matrices,
    size_t                       num_rows,
    const dnac_merkle_proof_t   *proof)
{
    if (!root || !opened_rows || !row_byte_lens || !proof) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }
    if (num_matrices == 0) {
        return DNAC_MERKLE_ERR_WRONG_BATCH_SIZE;
    }
    /* Shape check against the proof's commit-time num_matrices, mirroring
     * Plonky3's `dimensions.len() != opened_values.len()` rejection at
     * merkle-tree/src/mmcs.rs:1061. Catches a caller who passes a smaller
     * batch than the proof was built for (or vice versa). */
    if ((uint64_t)proof->num_matrices != (uint64_t)num_matrices) {
        return DNAC_MERKLE_ERR_WRONG_BATCH_SIZE;
    }
    /* Shape pre-checks against caller-supplied tree dimensions (no hashing
     * yet) — mirror Plonky3 verify_batch's IndexOutOfBounds / WrongHeight
     * gates at mmcs.rs:1094 and :1111. */
    if (!dnac_is_pow2(num_rows)) {
        return DNAC_MERKLE_ERR_BAD_HEIGHT;
    }
    if (proof->leaf_index >= (uint64_t)num_rows) {
        return DNAC_MERKLE_ERR_BAD_INDEX;
    }
    {
        const uint32_t expected_depth = dnac_log2_pow2(num_rows);
        if (proof->depth != expected_depth) {
            return DNAC_MERKLE_ERR_BAD_DEPTH;
        }
    }
    for (size_t m = 0; m < num_matrices; m++) {
        if (row_byte_lens[m] == 0) {
            return DNAC_MERKLE_ERR_BAD_HEIGHT;
        }
        if (!opened_rows[m]) {
            return DNAC_MERKLE_ERR_NULL_ARG;
        }
    }
    if (proof->depth > 0 && proof->siblings == NULL) {
        return DNAC_MERKLE_ERR_NULL_ARG;
    }

    /* Recompute leaf digest = SHA3-512(opened_rows[0] || ... || opened_rows[N-1]).
     * For N=1 this is SHA3-512(opened_rows[0]) — byte-identical to the
     * single-matrix verifier's leaf digest. */
    const size_t concat_bytes =
        dnac_merkle_batch_sum_row_bytes(row_byte_lens, num_matrices);
    uint8_t *concat = (uint8_t *)malloc(concat_bytes);
    if (!concat) {
        return DNAC_MERKLE_ERR_OOM;
    }
    {
        size_t off = 0;
        for (size_t m = 0; m < num_matrices; m++) {
            memcpy(concat + off, opened_rows[m], row_byte_lens[m]);
            off += row_byte_lens[m];
        }
    }
    dnac_merkle_digest_t digest;
    if (qgp_sha3_512(concat, concat_bytes, digest.bytes) != 0) {
        free(concat);
        return DNAC_MERKLE_ERR_OOM;
    }
    free(concat);

    /* Verifier walk — identical to single-matrix. */
    for (uint32_t i = 0; i < proof->depth; i++) {
        const uint64_t bit = (proof->leaf_index >> i) & 1ULL;
        dnac_merkle_digest_t next;
        dnac_merkle_status_t rc;
        if (bit == 0ULL) {
            rc = dnac_merkle_compress_pair(&digest, &proof->siblings[i], &next);
        } else {
            rc = dnac_merkle_compress_pair(&proof->siblings[i], &digest, &next);
        }
        if (rc != DNAC_MERKLE_OK) {
            return rc;
        }
        digest = next;
    }

    if (memcmp(digest.bytes, root->bytes, DNAC_MERKLE_DIGEST_BYTES) != 0) {
        return DNAC_MERKLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_MERKLE_OK;
}
