/**
 * @file shared/dnac/cmt_merkle.h
 * @brief cometbft @709fd12b `crypto/merkle` (RFC 6962) ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-A of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only. The live witness BFT,
 * QC V2 and the T3 wave-1 modules are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * This is the tree that produces DataHash, LastCommitHash, ValidatorsHash,
 * NextValidatorsHash, LastResultsHash, EvidenceHash, the PartSet hash and
 * Header.Hash itself (D-19 rev 6, atlas-dec-d106407a31d7d16d49d51990b75c36c6).
 * Its shape is RFC 6962 as the reference implements it:
 *
 *     root(∅)      = H("")                       (hash.go:16-18)
 *     root([x])    = H(0x00 ‖ x)                 (hash.go:21-23)
 *     root(xs)     = H(0x01 ‖ root(left) ‖ root(right))   (hash.go:34-36)
 *     |left| = getSplitPoint(|xs|) = largest power of two < |xs|
 *
 * ── Substitution ───────────────────────────────────────────────────────
 * The ONLY difference from the reference is the digest: SHA3-512 / 64
 * bytes instead of SHA-256 / 32 (cmt_tmhash.h). Prefixes, split rule,
 * recursion order and every edge case are the reference's.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments. Nothing reads a
 * clock, seeds any randomness, consults any map, or re-orders its input:
 * leaves are hashed in exactly the order the caller supplied. Two nodes
 * given the same items produce the same root, byte for byte.
 *
 * ── Recursion depth ────────────────────────────────────────────────────
 * cmt_merkle_hash_from_byte_slices, cmt_merkle_proofs_from_byte_slices and
 * cmt_compute_hash_from_aunts recurse to depth ceil(log2(n)) — at most 63
 * frames for any n an int64 can hold, and at most 11 for the largest set
 * this chain builds (MaxBlockPartsCount = 1601 parts). Each frame is a few
 * dozen bytes; there is no stack-exhaustion path from a wire value here,
 * because n is a count of objects the caller already holds in memory.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `Proof.String` / `Proof.StringIndented` (proof.go:97-108) — display
 *     only; the port has no string rendering of consensus objects.
 *   · `Proof.ToProto` / `ProofFromProto` (proof.go:134-161) — these are the
 *     codec's, and live in cmt_pb.{h,c} as `cmt_proof_to_proto` /
 *     `cmt_proof_from_proto`. ToProto is a field-for-field copy in the
 *     reference, so in C it is the identity on cmt_proof_t and the codec
 *     marshals the struct directly. FromProto ends in ValidateBasic
 *     (proof.go:160), which is `cmt_proof_validate_basic` below.
 *   · `leafHashOpt` (hash.go:26-31) and `innerHashOpt` (hash.go:38-44) —
 *     the incremental-hasher forms of leafHash / innerHash. With a
 *     one-shot digest they ARE leafHash / innerHash; both line ranges are
 *     cited on the single C function so no Go row is left unaccounted for.
 *
 * Reference @709fd12b (SHA-256 of each file verified before use):
 *   crypto/merkle/hash.go   44 lines a2ac0743130b4e50088703705389aa0d7c5155c3da5d9d235a5217b182eac246
 *   crypto/merkle/tree.go  112 lines 1dff4c0a658b53091cbca57ee25dc252b85ac1d195d3846cb10c568bbeb5a453
 *   crypto/merkle/proof.go 252 lines ddffde7a097d6a8d0ad3af25f559494065e535c8b7fa10aed66ed534ba07c907
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_MERKLE_H
#define SHARED_DNAC_CMT_MERKLE_H

#include <stdint.h>
#include <stddef.h>

#include "cmt_tmhash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b crypto/merkle/proof.go:16 — `MaxAunts = 100`.
 *  "A tree of size 2^100"; the cap exists to bound a proof's size against
 *  a denial-of-service, and is enforced by cmt_proof_validate_basic. */
#define CMT_MERKLE_MAX_AUNTS 100

/** One leaf, as the caller holds it. The reference's `[][]byte`. */
typedef struct {
    const uint8_t *data;
    size_t         len;
} cmt_merkle_item_t;

/**
 * cometbft@709fd12b crypto/merkle/proof.go:26-31 — `type Proof struct`.
 *
 * `leaf_hash_len` and `aunt_len[]` exist because Go's `[]byte` carries its
 * own length and the reference's ValidateBasic (proof.go:120-130) checks
 * every one of them against tmhash.Size. A decoder that dropped the
 * lengths could not run that check, so the lengths are kept and the check
 * is kept (INVARIANT 7495d337). In a proof this module BUILDS they are
 * always CMT_TMHASH_SIZE; in a proof that arrived on the wire they are
 * whatever the sender wrote, and validate_basic is what refuses them.
 */
typedef struct {
    int64_t total;                                            /* proof.go:27 */
    int64_t index;                                            /* proof.go:28 */
    uint8_t leaf_hash[CMT_TMHASH_SIZE];                       /* proof.go:29 */
    size_t  leaf_hash_len;
    size_t  aunts_len;                                        /* proof.go:30 */
    uint8_t aunts[CMT_MERKLE_MAX_AUNTS][CMT_TMHASH_SIZE];
    size_t  aunt_len[CMT_MERKLE_MAX_AUNTS];
} cmt_proof_t;

/**
 * cometbft@709fd12b crypto/merkle/proof.go:204-209 — `type ProofNode struct`.
 * Exactly one of left/right is set, except at the root where both are NULL.
 * The nodes live in an arena owned by cmt_merkle_trails_from_byte_slices
 * and are released with cmt_merkle_trails_free.
 */
typedef struct cmt_proof_node {
    uint8_t                hash[CMT_TMHASH_SIZE];
    struct cmt_proof_node *parent;
    struct cmt_proof_node *left;   /* left sibling  */
    struct cmt_proof_node *right;  /* right sibling */
} cmt_proof_node_t;

/** The tree built by cmt_merkle_trails_from_byte_slices. `trails[i]` is
 *  the leaf node for item i; `root` is the tree root. Both point into
 *  `arena`, which is one allocation. */
typedef struct {
    cmt_proof_node_t  *arena;
    size_t             arena_cap;
    size_t             arena_used;
    cmt_proof_node_t **trails;   /* n entries, leaf order */
    size_t             n;
    cmt_proof_node_t  *root;
} cmt_merkle_trails_t;

/* ── hash.go ────────────────────────────────────────────────────────── */

/** cometbft@709fd12b crypto/merkle/hash.go:16-18 — `emptyHash()`.
 *  H(""), the root of an empty tree. Also the reference's LastCommitHash
 *  at height 1 and its first LastResultsHash (D-19 rev 6 items 4 and 7). */
int cmt_merkle_empty_hash(uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@709fd12b crypto/merkle/hash.go:21-23 `leafHash()` and :26-31
 *  `leafHashOpt()` — H(0x00 ‖ leaf). A NULL leaf with len 0 is the
 *  reference's nil leaf and hashes H(0x00), which is what cdcEncode's
 *  nil-for-empty rule relies on (K-1 rev 2 rule d). */
int cmt_merkle_leaf_hash(const uint8_t *leaf, size_t len,
                         uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@709fd12b crypto/merkle/hash.go:34-36 `innerHash()` and :38-44
 *  `innerHashOpt()` — H(0x01 ‖ left ‖ right). */
int cmt_merkle_inner_hash(const uint8_t left[CMT_TMHASH_SIZE],
                          const uint8_t right[CMT_TMHASH_SIZE],
                          uint8_t out[CMT_TMHASH_SIZE]);

/* ── tree.go ────────────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b crypto/merkle/tree.go:101-112 — `getSplitPoint()`.
 * The largest power of two strictly less than `length`.
 * @return the split point, or -1 where the reference panics (length < 1).
 *         A real split point is always >= 1, so -1 is unambiguous.
 */
int64_t cmt_merkle_get_split_point(int64_t length);

/** cometbft@709fd12b crypto/merkle/tree.go:11-13 `HashFromByteSlices()` and
 *  :15-27 `hashFromByteSlices()` — the recursive RFC 6962 root.
 *  @return CMT_OK, CMT_FAULT on a hash backend or allocation failure. */
int cmt_merkle_hash_from_byte_slices(const cmt_merkle_item_t *items,
                                     size_t n,
                                     uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b crypto/merkle/tree.go:68-98 —
 * `HashFromByteSlicesIterative()`.
 *
 * ZERO CONSUMERS, in the reference and here: nothing in cometbft's
 * consensus path calls it (the map records it as a zero-consumer PORT
 * row). It is ported because "the reference in everything" is the rule,
 * and because it is a second, structurally different implementation of the
 * same root — the test uses it as a cross-check on the recursive one.
 *
 * It is a DIFFERENT ALGORITHM with the same result: it hashes every leaf
 * first, then repeatedly folds adjacent pairs and carries an odd trailing
 * node up unchanged, where cmt_merkle_hash_from_byte_slices splits at the
 * largest power of two below n. The two were checked to agree for every
 * n in 0..129 with the independent python oracle before this comment was
 * written; that is a MEASURED range, not a proof for all n, and the test
 * pins the same range. Any n where they were to disagree would be a
 * finding about the reference, not about this port.
 *
 * @return CMT_OK, CMT_FAULT on a hash backend or allocation failure.
 */
int cmt_merkle_hash_from_byte_slices_iterative(const cmt_merkle_item_t *items,
                                               size_t n,
                                               uint8_t out[CMT_TMHASH_SIZE]);

/* ── proof.go ───────────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b crypto/merkle/proof.go:232-252 —
 * `trailsFromByteSlices()`. Builds the whole tree and returns the leaf
 * trail for every item. On success the caller MUST release it with
 * cmt_merkle_trails_free.
 * @return CMT_OK, CMT_FAULT on allocation or hash backend failure.
 */
int cmt_merkle_trails_from_byte_slices(const cmt_merkle_item_t *items,
                                       size_t n,
                                       cmt_merkle_trails_t *out);

/** NULL-safe release of a cmt_merkle_trails_t. Zeroes *t. */
void cmt_merkle_trails_free(cmt_merkle_trails_t *t);

/**
 * cometbft@709fd12b crypto/merkle/proof.go:213-228 — `FlattenAunts()`.
 * Walks from a leaf up to the root collecting each step's sibling hash,
 * innermost (the leaf's own sibling) first.
 * @param out_len in: capacity of out[]; out: number of aunts written.
 * @return CMT_OK, CMT_REJECT if the walk is deeper than the capacity.
 */
int cmt_proof_node_flatten_aunts(const cmt_proof_node_t *spn,
                                 uint8_t (*out)[CMT_TMHASH_SIZE],
                                 size_t *out_len);

/**
 * cometbft@709fd12b crypto/merkle/proof.go:35-48 —
 * `ProofsFromByteSlices()`. Computes the root and the inclusion proof for
 * every item. `proofs` must have room for n entries (it may be NULL when
 * n is 0). `root` may be NULL if only the proofs are wanted.
 * @return CMT_OK, CMT_FAULT on allocation or hash backend failure.
 */
int cmt_merkle_proofs_from_byte_slices(const cmt_merkle_item_t *items,
                                       size_t n,
                                       uint8_t root[CMT_TMHASH_SIZE],
                                       cmt_proof_t *proofs);

/**
 * cometbft@709fd12b crypto/merkle/proof.go:52-74 — `(sp *Proof) Verify()`.
 * Checks that `leaf` hashes to sp->leaf_hash and that the aunts rebuild
 * `root_hash`.
 * @return CMT_OK when the proof holds, CMT_REJECT when it does not,
 *         CMT_FAULT on a hash backend failure.
 */
int cmt_proof_verify(const cmt_proof_t *sp,
                     const uint8_t root_hash[CMT_TMHASH_SIZE],
                     const uint8_t *leaf, size_t leaf_len);

/**
 * cometbft@709fd12b crypto/merkle/proof.go:77-83 `ComputeRootHash()` and
 * :86-93 `computeRootHash()`. The reference has two entry points that
 * differ only in whether the error panics; with panic → error return they
 * are one function.
 * @return CMT_OK, CMT_REJECT if index/total/aunt count disagree,
 *         CMT_FAULT on a hash backend failure.
 */
int cmt_proof_compute_root_hash(const cmt_proof_t *sp,
                                uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b crypto/merkle/proof.go:113-132 —
 * `(sp *Proof) ValidateBasic()`. Negative total or index, a leaf hash that
 * is not CMT_TMHASH_SIZE, more than CMT_MERKLE_MAX_AUNTS aunts, or any
 * aunt that is not CMT_TMHASH_SIZE, all REJECT. This is the check
 * cmt_proof_from_proto runs at the end of every decode (proof.go:160).
 * @return CMT_OK or CMT_REJECT.
 */
int cmt_proof_validate_basic(const cmt_proof_t *sp);

/**
 * cometbft@709fd12b crypto/merkle/proof.go:166-197 —
 * `computeHashFromAunts()`. Rebuilds a root from a leaf hash and the aunt
 * list. Where the reference panics on `total == 0` (:171-172) this returns
 * CMT_REJECT — and note that the guard on :167 has already refused that
 * case, so the panic is unreachable in the reference too.
 * @return CMT_OK, CMT_REJECT on an invalid index/total or a wrong number
 *         of inner hashes, CMT_FAULT on a hash backend failure.
 */
int cmt_compute_hash_from_aunts(int64_t index, int64_t total,
                                const uint8_t leaf_hash[CMT_TMHASH_SIZE],
                                const uint8_t (*inner_hashes)[CMT_TMHASH_SIZE],
                                size_t n_inner,
                                uint8_t out[CMT_TMHASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_MERKLE_H */
