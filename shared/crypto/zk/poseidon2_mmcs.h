/**
 * @file poseidon2_mmcs.h
 * @brief Poseidon2 Merkle MMCS over Goldilocks — 4-lane digests (P1b).
 *
 * Grounded C port of Plonky3 @ 82cfad73:
 *   MerkleTreeMmcs<ValPacking, ValPacking,
 *                  PaddingFreeSponge<Perm, 8, 4, 4>,      // leaf hash H
 *                  TruncatedPermutation<Perm, 2, 4, 8>,   // node compressor C
 *                  2, 4>  with cap_height = 0
 * (types per keccak-air/examples/prove_goldilocks_poseidon2.rs:41-48;
 * permutation INSTANCE = default_goldilocks_poseidon2_8() = the byte-matched
 * `poseidon2_goldilocks8_permute` — P1 design doc §0 F4 pin).
 *
 * Pinned semantics (P1 design doc §0 v2):
 *   - Leaf hash H = PaddingFreeSponge<8,4,4> over the CONCATENATED element
 *     stream of all matrices' rows at the index (verify_batch
 *     hash_iter_slices == hash_iter over the flattened stream,
 *     merkle-tree/src/mmcs.rs:1097-1103 + symmetric/src/hasher.rs:24-30).
 *     Sponge loop: zero state; per block overwrite state[0..RATE] one element
 *     at a time; full block => permute; input exhausted mid-block (i>0) =>
 *     permute and stop; exhausted AT a block boundary => NO extra permute;
 *     squeeze = state[0..4] (symmetric/src/sponge.rs:172-203 — the same
 *     schedule note_sponge_hash8 hardcodes for length 8).
 *   - Node compressor C = TruncatedPermutation<2,4,8>: pre[0..4]=left,
 *     pre[4..8]=right, ONE permutation, out = post[0..4]
 *     (symmetric/src/compression.rs:40-48). STRUCTURALLY DISTINCT from the
 *     leaf hash (G-SEC-P1-3) and from note_merkle_compress (which is the
 *     two-permutation sponge form — a DIFFERENT construction, not reusable
 *     here).
 *   - Walk: index bit LSB-first; bit==0 => C(digest, sib), bit==1 =>
 *     C(sib, digest); siblings leaf-level-first (mmcs.rs:1009-1021,
 *     1118-1141); root compare at the end (cap 0 => commit[0],
 *     mmcs.rs:1172-1179).
 *
 * Scope: binary arity N=2 only; cap_height 0; heights exact powers of two
 *   >= 1. Same-height batches via dnac_p2_mmcs_commit/open/verify (P1b,
 *   KAT-frozen), MIXED-height batches via the *_mixed entries (P2L-d d1a):
 *   the tallest group forms the leaf layer and every shorter group is
 *   injected at the layer whose length equals its height —
 *   next[i] = C(C(prev[2i], prev[2i+1]), H(concat injected rows at i))
 *   (merkle_tree.rs:127-176, 337-440 with N=2 so the arity schedule is all
 *   2s — select_arity_step returns 2 when N==2, merkle_tree.rs:227-242).
 *   Grouping is STABLE: matrices sort tallest-first but keep insertion
 *   order within a height group (sorted_by_key stability,
 *   merkle_tree.rs:113-116) — the concat order inside H depends on it.
 *   Opened rows stay indexed by ORIGINAL matrix position; matrix m opens
 *   row `index >> (log_max_height - log2(heights[m]))`
 *   (mmcs.rs:989-998, 1044-1046). The sibling path has exactly
 *   log2(max_height) digests (one per binary step; injection combines use
 *   opened rows, not siblings — mmcs.rs:1109-1116, 1120-1170).
 *
 * SALT-AGNOSTIC CORE: the hiding form (MerkleTreeHidingMmcs, G-SEC-P1-6)
 * hashes leaf = row ‖ salt — the CALLER assembles that concatenation (exactly
 * how fri_verifier.c consumes this MMCS (P1c: Poseidon2, SHA3 retired), and exactly what
 * HidingMmcs::commit does internally via HorizontalPair, hiding_mmcs.rs:
 * 121-134/159-175). The salted byte-match KAT (test_poseidon2_mmcs) proves
 * this assembly against REAL MerkleTreeHidingMmcs vectors. `salt_elems`
 * itself MUST be consensus-pinned by the caller (G-SEC-P1-6) — this module
 * never reads a salt count from data.
 *
 * Determinism: pure functions of the input matrices; canonicality fail-close
 * (any input lane >= p rejected before hashing, G-DET-P1-5); digest lanes are
 * permutation outputs (canonical by construction).
 *
 * Byte-match gate: tools/vectors/poseidon2_mmcs.json
 * (`plonky3_oracle dump-poseidon2-mmcs` — 9 trees plain+salted, openings at
 * EVERY index, each verify_batch-checked in-oracle) +
 * tests/test_poseidon2_mmcs.c.
 *
 * WIRED (P1c, 2026-07-22): this is the LIVE FRI/STARK MMCS — fri_verifier.c,
 * stark_priming.c, and every prover commit through it. The SHA3 merkle_smt was
 * deleted at P1c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_POSEIDON2_MMCS_H
#define DNAC_ZK_POSEIDON2_MMCS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Digest width in Goldilocks lanes (DIGEST_ELEMS const generic) = 32 bytes
 *  on the wire (vs SHA3's 64 — the P1 digest-width change). */
#define DNAC_P2M_DIGEST_LANES 4

/** 4-lane Poseidon2 digest. Lanes are canonical (< p) by construction
 *  (permutation outputs). */
typedef struct {
    uint64_t lanes[DNAC_P2M_DIGEST_LANES];
} dnac_p2_digest_t;

/**
 * Merkle authentication proof for one leaf (field layout mirrors the retired
 * SHA3 dnac_merkle_proof_t so proof-struct consumers port 1:1). siblings[0]
 * is the leaf-level sibling; siblings[depth-1] the root-side one
 * (open_batch order, mmcs.rs:1009-1021).
 *
 * PRODUCER CONTRACT (all three producers honour it: fri_proof_codec.c:352-360
 * and :410-419 from the wire, batch_prover.c:1489/:1553 from the tree,
 * dnac_p2_mmcs_open_batch below): `depth` is the number of digests actually
 * present in `siblings` — never a separately-derived height. The verify entries
 * rely on exactly this to bound the walk, so a producer that sets one without
 * the other reintroduces the out-of-bounds read S2'-d closed.
 */
typedef struct {
    uint64_t          leaf_index;
    uint32_t          depth;
    uint32_t          num_matrices;
    dnac_p2_digest_t *siblings;
} dnac_p2_proof_t;

typedef enum {
    DNAC_P2M_OK = 0,
    DNAC_P2M_ERR_PARAM,        /**< NULL / zero matrices / height not pow2 */
    DNAC_P2M_ERR_ALLOC,        /**< allocation failure */
    DNAC_P2M_ERR_NONCANONICAL, /**< an input lane >= p (fail-close, no hash) */
    DNAC_P2M_ERR_BAD_INDEX,    /**< leaf_index >= num_rows */
    DNAC_P2M_ERR_BAD_DEPTH,    /**< proof depth != log2(num_rows) */
    DNAC_P2M_ERR_ROOT_MISMATCH /**< recomputed digest != root */
} dnac_p2_mmcs_status_t;

/* --------------------------------------------------------------------------
 * Primitives (exposed for P1c consumers and the KAT)
 * ------------------------------------------------------------------------ */

/** PaddingFreeSponge<Perm,8,4,4> over an arbitrary-length canonical element
 *  stream (sponge.rs:172-203 schedule; see header). For n == 8 this equals
 *  note_sponge_hash8 (KAT-bridged). Caller guarantees canonical lanes. */
void dnac_p2_mmcs_hash_iter(const uint64_t *elems, size_t n,
                            uint64_t out[DNAC_P2M_DIGEST_LANES]);

/** TruncatedPermutation<Perm,2,4,8> 2-to-1 compressor (compression.rs:40-48):
 *  ONE permutation over left‖right, truncate to 4 lanes. */
void dnac_p2_mmcs_compress(const uint64_t left[DNAC_P2M_DIGEST_LANES],
                           const uint64_t right[DNAC_P2M_DIGEST_LANES],
                           uint64_t out[DNAC_P2M_DIGEST_LANES]);

/* --------------------------------------------------------------------------
 * Batch commit / open / verify (same-height, N=2, cap 0)
 * ------------------------------------------------------------------------ */

/** Opaque tree handle (digest layers, leaf-first). Freed via
 *  dnac_p2_mmcs_tree_free. */
typedef struct dnac_p2_mmcs_tree_s dnac_p2_mmcs_tree_t;

/**
 * Commit to a batch of same-height matrices of canonical Goldilocks lanes.
 *
 * @param matrices     matrices[m] = row-major lanes, num_rows * widths[m].
 * @param widths       per-matrix row width in lanes (> 0).
 * @param num_matrices > 0.
 * @param num_rows     power of two >= 1 (shared height).
 * @param out_root     required.
 * @param out_tree     optional (NULL => root only, no tree kept).
 *
 * Leaf i digest = H(concat over m of matrices[m][row i]). Any lane >= p =>
 * DNAC_P2M_ERR_NONCANONICAL before hashing.
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_commit(
    const uint64_t *const *matrices,
    const size_t          *widths,
    size_t                 num_matrices,
    size_t                 num_rows,
    dnac_p2_digest_t      *out_root,
    dnac_p2_mmcs_tree_t  **out_tree);

/**
 * Open leaf_index: write the depth sibling digests (leaf-level-first, the
 * open_batch order mmcs.rs:1009-1021) into out_siblings (caller-allocated,
 * capacity >= tree depth) and the depth into *out_depth.
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_open(
    const dnac_p2_mmcs_tree_t *tree,
    uint64_t                   leaf_index,
    dnac_p2_digest_t          *out_siblings,
    size_t                    *out_depth);

/**
 * Batch-open leaf_index (prover side): out_rows[m] receives a BORROWED
 * pointer into the tree's internal row copy for matrix m (valid until
 * tree_free — the merkle_smt batch_open contract, ported); out_proof gets
 * leaf_index/depth/num_matrices set and its caller-allocated siblings array
 * (capacity >= depth) filled leaf-level-first.
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_open_batch(
    const dnac_p2_mmcs_tree_t *tree,
    uint64_t                   leaf_index,
    const uint64_t           **out_rows,
    dnac_p2_proof_t           *out_proof);

/** Tree depth = log2(num_rows). Returns 0 for NULL. */
size_t dnac_p2_mmcs_tree_depth(const dnac_p2_mmcs_tree_t *tree);

/** Number of matrices committed in the tree. 0 for NULL. */
size_t dnac_p2_mmcs_tree_num_matrices(const dnac_p2_mmcs_tree_t *tree);

/** Lane width of matrix m. 0 for NULL / out of range. */
size_t dnac_p2_mmcs_tree_width(const dnac_p2_mmcs_tree_t *tree, size_t m);

/** Release a tree handle. Safe on NULL. */
void dnac_p2_mmcs_tree_free(dnac_p2_mmcs_tree_t *tree);

/**
 * Verify an opening: recompute leaf digest from the opened rows (caller
 * passes rows WITH salts already appended for the hiding form), walk the
 * sibling path (LSB-first bit order), compare against root. Fail-close on any
 * non-canonical opened lane.
 *
 * The path arrives as a whole `dnac_p2_proof_t` — pointer AND length together,
 * the C form of upstream's `opening_proof: &[Digest]`. That is deliberate and
 * load-bearing (S2'-d, 2026-07-27): the earlier signature took `siblings` as a
 * bare pointer plus a SEPARATE `depth`, so callers passed the depth they had
 * DERIVED while the array had been allocated to the length the WIRE declared.
 * `dnac_p2_mmcs_verify` then walked past the allocation whenever the two
 * disagreed. Binding them into one object makes that class unrepresentable:
 * `proof->depth` is the length of `proof->siblings`, and the expected length is
 * derived here, from `num_rows`.
 *
 * Enforced: `proof->depth == log2(num_rows)`, else DNAC_P2M_ERR_BAD_DEPTH —
 * upstream's `opening_proof.len() != expected_proof_len => WrongHeight`
 * (82cfad73 merkle-tree/src/mmcs.rs:1110-1116, unchanged at v0.6.2
 * merkle-tree/src/mmcs/batch.rs:174-179; N=2 + cap 0 makes the arity schedule
 * all-2s, so expected_proof_len = sum(step-1) = log2(num_rows)).
 *
 * NOT READ from the proof: `leaf_index` and `num_matrices`. Both are VERIFIER
 * knowledge — the index is computed from the query (verifier.rs:576-580) and
 * the matrix count comes from the committed dimensions — so both are taken as
 * explicit parameters and the proof-side copies are ignored on purpose. A
 * decoder is free to leave them zero.
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_verify(
    const dnac_p2_digest_t *root,
    const uint64_t *const  *opened_rows,
    const size_t           *widths,
    size_t                  num_matrices,
    size_t                  num_rows,
    uint64_t                leaf_index,
    const dnac_p2_proof_t  *proof);

/* --------------------------------------------------------------------------
 * MIXED-height batch commit / open / verify (P2L-d d1a; N=2, cap 0,
 * power-of-two heights — see the header Scope note for the injection
 * layout pins)
 * ------------------------------------------------------------------------ */

/**
 * Commit to matrices of (possibly) different power-of-two heights.
 * heights[m] rows of widths[m] lanes each; the tallest group hashes into
 * the leaf layer, shorter groups inject at their matching layer
 * (merkle_tree.rs:127-176). Same salt-agnostic contract as the same-height
 * form: for the hiding tree the caller appends the salt lanes as extra
 * columns of each matrix.
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_commit_mixed(
    const uint64_t *const *matrices,
    const size_t          *widths,
    const size_t          *heights,
    size_t                 num_matrices,
    dnac_p2_digest_t      *out_root,
    dnac_p2_mmcs_tree_t  **out_tree);

/**
 * Open `index` (< max height) of a mixed tree: out_rows[m] receives a
 * BORROWED pointer to matrix m's row at its reduced index
 * `index >> (log_max - log2(heights[m]))` (mmcs.rs:989-998); out_proof
 * gets log2(max_height) siblings, leaf-level-first (mmcs.rs:1007-1019).
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_open_mixed(
    const dnac_p2_mmcs_tree_t *tree,
    uint64_t                   index,
    const uint64_t           **out_rows,
    dnac_p2_proof_t           *out_proof);

/**
 * Verify a mixed-height opening (mmcs.rs:1052-1180 walk, N=2/cap 0/pow2):
 * digest = H(concat tallest-group opened rows); per level compress with the
 * sibling (LSB-first bit order), then, when a group's height equals the new
 * layer length, digest = C(digest, H(concat that group's opened rows)).
 * `proof->depth` MUST equal log2(max height) (proof length rule
 * mmcs.rs:1109-1116). Opened rows are indexed by ORIGINAL matrix position and
 * carry any hiding salts already appended (widths[m] = row lanes incl. salts).
 * Same path-object contract as dnac_p2_mmcs_verify above, for the same reason:
 * `proof->depth` is the length of `proof->siblings`, and `proof->leaf_index` /
 * `proof->num_matrices` are NOT read.
 */
dnac_p2_mmcs_status_t dnac_p2_mmcs_verify_mixed(
    const dnac_p2_digest_t *root,
    const uint64_t *const  *opened_rows,
    const size_t           *widths,
    const size_t           *heights,
    size_t                  num_matrices,
    uint64_t                index,
    const dnac_p2_proof_t  *proof);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_POSEIDON2_MMCS_H */
