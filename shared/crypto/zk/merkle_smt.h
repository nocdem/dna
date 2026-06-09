/**
 * @file merkle_smt.h
 * @brief Binary Merkle / MMCS core for DNAC v3 ZK stack (Stage M2, 2026-05-27).
 *
 * Implements a pure binary (N=2) Merkle commitment over a single matrix of
 * Goldilocks field elements, with cap_height = 0 (single root) and FIPS-202
 * SHA3-512 as the leaf and parent hash. The Rust oracle for this module is
 * Plonky3's MerkleTreeMmcs at pinned commit 82cfad73 (see
 * shared/crypto/zk/tools/plonky3_oracle/src/main.rs Merkle module).
 *
 * Source of truth:
 *   - dnac/docs/plans/2026-05-26-merkle-mmcs-design.md (whole document)
 *   - Plonky3 commit 82cfad73 — merkle-tree/src/{mmcs.rs, merkle_tree.rs}
 *
 * Scope (first-pass — see design § 1.1 / § 1.2):
 *   - Binary arity N=2 only
 *   - Single matrix only (no mixed-height injection)
 *   - cap_height = 0 only (single 64-byte root)
 *   - No pruning, no multi-matrix commit
 *   - Matrix height must be an exact power of two (≥ 1)
 *
 * Determinism invariants (design § 3.1):
 *   - Goldilocks elements serialized as canonical u64 in [0, p) little-endian
 *     (matches Plonky3 `field/src/integers.rs:563` and the Strategy-C oracle
 *      glue at plonky3_oracle/src/main.rs Merkle module § 7.1).
 *   - Leaf hash:   leaf_digest = SHA3-512(row_bytes), no separator, no prefix.
 *   - Parent hash: parent      = SHA3-512(L_digest ‖ R_digest), 128 input bytes.
 *   - Sibling order in proof:   level-0 first (leaf-level sibling at index 0),
 *                                root-side last.
 *   - Index bit order during verify: LSB-first, bit i selects at level i.
 *
 * Security goals (design § 4.2 G1-G6):
 *   G1 binding, G2 position-binding, G3 sibling-tampering soundness,
 *   G4 completeness, G5 no internal domain confusion, G6 post-quantum 128-bit.
 *
 * C ABI authority: design § 6.1 / § 6.2 (this header is the implementation).
 */

#ifndef DNAC_MERKLE_SMT_H
#define DNAC_MERKLE_SMT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

/** Digest size in bytes — FIPS-202 SHA3-512 output. Design § 1.1, § 5.3. */
#define DNAC_MERKLE_DIGEST_BYTES 64

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * 64-byte SHA3-512 digest. Wire representation matches the Rust oracle:
 * `lane_digest_to_bytes` in plonky3_oracle/src/main.rs converts the internal
 * `[u64; 8]` lane view back to these same 64 bytes via per-lane to_le_bytes
 * (design § 5.7 byte-identity rule).
 */
typedef struct {
    uint8_t bytes[DNAC_MERKLE_DIGEST_BYTES];
} dnac_merkle_digest_t;

/**
 * Merkle authentication proof for a single leaf.
 *
 * Layout invariant (design § 5.5): `siblings[0]` is the leaf-level sibling
 * (the other child at the lowest internal node); `siblings[depth-1]` is the
 * root-child sibling. This matches Plonky3's `open_batch` walk order at
 * mmcs.rs:1009-1019 (loop `for layer_idx in 0..proof_levels` from leaf upward).
 *
 * `depth = log2(num_rows)`. For `num_rows = 1` (single-leaf tree),
 * `depth = 0` and the siblings array is unused (length 0).
 *
 * `num_matrices` is the commit-time matrix count for the batch that produced
 * this proof:
 *   - dnac_merkle_open() (single-matrix) writes 1.
 *   - dnac_merkle_batch_open() (Phase 2A) writes the tree's num_matrices.
 *   - Single-matrix dnac_merkle_verify() ignores this field.
 *   - dnac_merkle_batch_verify() compares it against the caller's
 *     num_matrices argument (mirrors Plonky3's
 *     `dimensions.len() != opened_values.len()` shape check at
 *     merkle-tree/src/mmcs.rs:1061) and returns
 *     DNAC_MERKLE_ERR_WRONG_BATCH_SIZE on mismatch.
 * Legacy single-matrix callers that zero-initialize this struct continue to
 * work because single-matrix verify never reads the field.
 */
typedef struct {
    uint64_t              leaf_index;
    uint32_t              depth;
    uint32_t              num_matrices;
    dnac_merkle_digest_t *siblings;
} dnac_merkle_proof_t;

/**
 * Opaque prover-side tree handle. Holds an owned copy of the input rows and
 * all intermediate digest layers (sufficient for any future open call).
 * Created by `dnac_merkle_commit`; freed by `dnac_merkle_tree_free`.
 */
typedef struct dnac_merkle_tree_s dnac_merkle_tree_t;

/**
 * Status codes — design § 6.1.
 *
 * Phase 2A multi-matrix batch API additionally returns:
 *   DNAC_MERKLE_ERR_WRONG_BATCH_SIZE — num_matrices == 0 or caller-supplied
 *     num_matrices disagrees with the proof / tree handle.
 */
typedef enum {
    DNAC_MERKLE_OK                     = 0,
    DNAC_MERKLE_ERR_NULL_ARG           = 1,
    DNAC_MERKLE_ERR_BAD_HEIGHT         = 2,  /* num_rows == 0 or not power of two */
    DNAC_MERKLE_ERR_BAD_INDEX          = 3,  /* leaf_index >= num_rows */
    DNAC_MERKLE_ERR_BAD_DEPTH          = 4,  /* proof->depth != log2(num_rows) */
    DNAC_MERKLE_ERR_ROOT_MISMATCH      = 5,  /* verification failed */
    DNAC_MERKLE_ERR_NONCANONICAL       = 6,  /* row chunk u64 >= Goldilocks p */
    DNAC_MERKLE_ERR_OOM                = 7,
    DNAC_MERKLE_ERR_WRONG_BATCH_SIZE   = 8   /* batch API: num_matrices == 0 or mismatch */
} dnac_merkle_status_t;

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Commit to a single matrix of `num_rows` × `row_byte_len`-byte rows.
 *
 * Per design § 5.1: each row consists of `row_byte_len / 8` Goldilocks field
 * elements, each encoded as a canonical u64 in [0, p) little-endian over 8
 * bytes. `row_byte_len` MUST be a positive multiple of 8.
 *
 * Per design § 5.3: leaf digest = SHA3-512(row_bytes). No separator, no length
 * prefix, no padding beyond FIPS-202 SHA3-512's internal pad10*1.
 *
 * Per design § 5.4: parent digest = SHA3-512(left ‖ right), 128 input bytes.
 *
 * Per design § 1.1: `num_rows` MUST be a power of two ≥ 1. Height = 1 is the
 * degenerate edge case where the root equals the single leaf hash and any
 * subsequent open call returns an empty proof.
 *
 * Per design § 3.1 D1: any 8-byte chunk in `rows` whose little-endian u64
 * decoding is ≥ Goldilocks p (0xFFFFFFFF00000001) is rejected with
 * DNAC_MERKLE_ERR_NONCANONICAL before any hashing — this enforces byte
 * identity with the Rust oracle's canonical encoding (Plonky3
 * `goldilocks.rs:512-524`, `integers.rs:563`).
 *
 * Memory: on success, `*out_tree` is a heap-allocated handle owning a copy of
 * the input rows and all intermediate digest layers. Caller MUST release via
 * `dnac_merkle_tree_free` after all opens complete.
 *
 * @param rows           Row-major matrix bytes (length = num_rows * row_byte_len).
 * @param row_byte_len   Bytes per row. Must be > 0 and a multiple of 8.
 * @param num_rows       Number of rows. Must be > 0 and a power of two.
 * @param out_root       Receives the 64-byte root digest. Must be non-NULL.
 * @param out_tree       Receives the opaque tree handle. Must be non-NULL.
 *
 * @return DNAC_MERKLE_OK or one of DNAC_MERKLE_ERR_*.
 */
dnac_merkle_status_t dnac_merkle_commit(
    const uint8_t            *rows,
    size_t                    row_byte_len,
    size_t                    num_rows,
    dnac_merkle_digest_t     *out_root,
    dnac_merkle_tree_t      **out_tree
);

/**
 * Open the row at `leaf_index`.
 *
 * Caller pre-allocates `out_proof->siblings` (a contiguous array of
 * `dnac_merkle_digest_t` of length equal to the tree's depth) and sets
 * `out_proof->depth = depth` on entry; this function fills `siblings[0..depth]`
 * level-0-first and writes `leaf_index` to `out_proof->leaf_index`.
 *
 * `*out_leaf_bytes` is a borrowed pointer into the tree's internal row copy
 * (no allocation, no copy). Valid for the lifetime of `tree`.
 * `*out_leaf_byte_len` always equals the tree's `row_byte_len`.
 *
 * For a single-row tree (depth = 0), no siblings are written; the caller may
 * pass `out_proof->siblings = NULL` since the dereference never happens.
 *
 * @return DNAC_MERKLE_OK, DNAC_MERKLE_ERR_NULL_ARG, DNAC_MERKLE_ERR_BAD_INDEX,
 *         or DNAC_MERKLE_ERR_BAD_DEPTH (when out_proof->depth doesn't match).
 */
dnac_merkle_status_t dnac_merkle_open(
    const dnac_merkle_tree_t *tree,
    uint64_t                  leaf_index,
    const uint8_t           **out_leaf_bytes,
    size_t                   *out_leaf_byte_len,
    dnac_merkle_proof_t      *out_proof
);

/**
 * Release a tree handle. Safe to call on NULL.
 */
void dnac_merkle_tree_free(dnac_merkle_tree_t *tree);

/**
 * Verify a Merkle authentication proof against the given root.
 *
 * Per design § 5.5 / § 5.6:
 *   digest = SHA3-512(leaf_bytes)
 *   for i in 0..proof->depth:
 *     bit = (proof->leaf_index >> i) & 1
 *     if bit == 0:  digest = SHA3-512(digest ‖ proof->siblings[i].bytes)
 *     else:         digest = SHA3-512(proof->siblings[i].bytes ‖ digest)
 *   accept iff digest == root
 *
 * Stateless — does not require a `tree` handle. Returns DNAC_MERKLE_OK on
 * acceptance, DNAC_MERKLE_ERR_ROOT_MISMATCH on rejection.
 */
dnac_merkle_status_t dnac_merkle_verify(
    const dnac_merkle_digest_t *root,
    const uint8_t              *leaf_bytes,
    size_t                      leaf_byte_len,
    const dnac_merkle_proof_t  *proof
);

/* ========================================================================== */
/* Phase 2A — Same-height multi-matrix batch API                              */
/*                                                                            */
/* Per dnac/docs/plans/2026-05-26-merkle-mmcs-design.md § 1.4.                */
/*                                                                            */
/* Mirrors Plonky3 MerkleTreeMmcs::commit / open_batch / verify_batch         */
/* (merkle-tree/src/mmcs.rs:929, :976, :1052) restricted to:                  */
/*   - All matrices in a batch have IDENTICAL num_rows (same-height).         */
/*   - Per-matrix row_byte_lens may differ.                                   */
/*   - Binary arity N=2, cap_height=0, single 64-byte root.                   */
/*   - Original matrix commit order is preserved at the leaf hash             */
/*     and in opened_rows; no internal sort, no separator, no length prefix.  */
/*                                                                            */
/* Leaf hash invariant (mmcs.rs:1100-1104):                                   */
/*   leaf_digest = SHA3-512(row_m0_bytes || row_m1_bytes || ... || row_m{N-1})*/
/*                                                                            */
/* Byte-identity invariant (Phase 2A oracle gate):                            */
/*   For num_matrices == 1, dnac_merkle_batch_commit produces a root + proof  */
/*   byte-identical to dnac_merkle_commit for the same single matrix.         */
/* ========================================================================== */

/**
 * Opaque batch tree handle. Distinct opaque type from dnac_merkle_tree_t so
 * callers cannot accidentally pass a batch handle to dnac_merkle_open() or
 * vice versa. Freed via dnac_merkle_batch_tree_free.
 */
typedef struct dnac_merkle_batch_tree_s dnac_merkle_batch_tree_t;

/**
 * Commit to a batch of same-height matrices. See header notes above for
 * algorithm and invariants. Per design § 3.1 D1 any 8-byte chunk in any
 * matrix that decodes (LE) to a u64 >= Goldilocks p is rejected with
 * DNAC_MERKLE_ERR_NONCANONICAL before any hashing.
 */
dnac_merkle_status_t dnac_merkle_batch_commit(
    const uint8_t * const     *matrices_rows,
    const size_t              *row_byte_lens,
    size_t                     num_matrices,
    size_t                     num_rows,
    dnac_merkle_digest_t      *out_root,
    dnac_merkle_batch_tree_t **out_tree
);

/**
 * Open the row at leaf_index across all matrices. out_opened_rows[m] is
 * a borrowed pointer into the tree's internal copy for matrix m. Caller
 * pre-allocates out_opened_rows (num_matrices pointers) and
 * out_proof->siblings (depth digests) and sets out_proof->depth = depth.
 */
dnac_merkle_status_t dnac_merkle_batch_open(
    const dnac_merkle_batch_tree_t *tree,
    uint64_t                        leaf_index,
    const uint8_t                 **out_opened_rows,
    dnac_merkle_proof_t            *out_proof
);

/** Number of matrices in a batch tree. Returns 0 if tree==NULL. */
size_t dnac_merkle_batch_tree_num_matrices(const dnac_merkle_batch_tree_t *tree);

/** Per-matrix bytes-per-row for matrix index m. Returns 0 if tree==NULL or m out of range. */
size_t dnac_merkle_batch_tree_row_byte_len(const dnac_merkle_batch_tree_t *tree, size_t m);

/** Number of rows in a batch tree (shared across matrices). Returns 0 if tree==NULL. */
size_t dnac_merkle_batch_tree_num_rows(const dnac_merkle_batch_tree_t *tree);

/** Release a batch tree handle. Safe to call on NULL. */
void dnac_merkle_batch_tree_free(dnac_merkle_batch_tree_t *tree);

/**
 * Verify a batch opening against the given root.
 *
 * Pre-checks (cheap, no hashing — match Plonky3 verify_batch shape checks):
 *   - num_matrices == 0                     -> DNAC_MERKLE_ERR_WRONG_BATCH_SIZE
 *   - num_rows == 0 or not pow2             -> DNAC_MERKLE_ERR_BAD_HEIGHT
 *   - proof->leaf_index >= num_rows         -> DNAC_MERKLE_ERR_BAD_INDEX
 *     (mirrors mmcs.rs:1094 IndexOutOfBounds)
 *   - proof->depth != log2(num_rows)        -> DNAC_MERKLE_ERR_BAD_DEPTH
 *     (mirrors mmcs.rs:1111 WrongHeight; for binary same-height the
 *      expected siblings count equals log2(num_rows))
 *   - row_byte_lens[m] == 0                 -> DNAC_MERKLE_ERR_BAD_HEIGHT
 *
 * Hash chain:
 *   digest = SHA3-512(opened_rows[0] || opened_rows[1] || ... || opened_rows[N-1])
 *   for i in 0..proof->depth:
 *     bit = (proof->leaf_index >> i) & 1
 *     if bit == 0:  digest = SHA3-512(digest || proof->siblings[i].bytes)
 *     else:         digest = SHA3-512(proof->siblings[i].bytes || digest)
 *   accept iff digest == root, else DNAC_MERKLE_ERR_ROOT_MISMATCH
 *
 * Note: Plonky3's `WrongBatchSize` (`dimensions.len() != opened_values.len()`)
 * has no direct DNAC analogue. The DNAC API takes `num_matrices` from one
 * source (the caller); there is no independent "opened values count" inside
 * the proof structure. A caller-passed mismatch versus the original commit
 * count results in a leaf-hash divergence and is reported as
 * DNAC_MERKLE_ERR_ROOT_MISMATCH.
 */
dnac_merkle_status_t dnac_merkle_batch_verify(
    const dnac_merkle_digest_t  *root,
    const uint8_t * const       *opened_rows,
    const size_t                *row_byte_lens,
    size_t                       num_matrices,
    size_t                       num_rows,
    const dnac_merkle_proof_t   *proof
);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_MERKLE_SMT_H */
