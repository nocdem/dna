/**
 * @file shared/dnac/cmt_merkle.c
 * @brief cometbft @709fd12b `crypto/merkle` ported to C — see cmt_merkle.h.
 *
 * Every function below carries the reference line range it is a port of.
 * The only substitution is the digest (SHA3-512, 64 bytes) and Go's panics
 * becoming error returns (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_merkle.h"

#include <stdlib.h>
#include <string.h>

/* The reference's package-level prefixes, crypto/merkle/hash.go:10-13. */
static const uint8_t CMT_LEAF_PREFIX  = 0x00;   /* hash.go:11 */
static const uint8_t CMT_INNER_PREFIX = 0x01;   /* hash.go:12 */

/* ── hash.go ────────────────────────────────────────────────────────── */

/* cometbft@709fd12b crypto/merkle/hash.go:16-18 — emptyHash() */
int cmt_merkle_empty_hash(uint8_t out[CMT_TMHASH_SIZE])
{
    return cmt_tmhash_sum(NULL, 0, out);
}

/* cometbft@709fd12b crypto/merkle/hash.go:21-23 leafHash(), :26-31 leafHashOpt() */
int cmt_merkle_leaf_hash(const uint8_t *leaf, size_t len,
                         uint8_t out[CMT_TMHASH_SIZE])
{
    cmt_tmhash_part_t parts[2];

    parts[0].data = &CMT_LEAF_PREFIX;
    parts[0].len  = 1;
    parts[1].data = leaf;
    parts[1].len  = len;
    return cmt_tmhash_sum_many(parts, 2, out);
}

/* cometbft@709fd12b crypto/merkle/hash.go:34-36 innerHash(), :38-44 innerHashOpt() */
int cmt_merkle_inner_hash(const uint8_t left[CMT_TMHASH_SIZE],
                          const uint8_t right[CMT_TMHASH_SIZE],
                          uint8_t out[CMT_TMHASH_SIZE])
{
    cmt_tmhash_part_t parts[3];

    if (left == NULL || right == NULL) {
        return CMT_FAULT;
    }
    parts[0].data = &CMT_INNER_PREFIX;
    parts[0].len  = 1;
    parts[1].data = left;
    parts[1].len  = CMT_TMHASH_SIZE;
    parts[2].data = right;
    parts[2].len  = CMT_TMHASH_SIZE;
    return cmt_tmhash_sum_many(parts, 3, out);
}

/* ── tree.go ────────────────────────────────────────────────────────── */

/* cometbft@709fd12b crypto/merkle/tree.go:101-112 — getSplitPoint().
 *
 * Go reads the bit length with math/bits.Len; written out here because C
 * has no portable equivalent. `k = 1 << (bitlen - 1)` is the highest power
 * of two <= length, halved again when it equals length — i.e. the largest
 * power of two STRICTLY less than length.
 *
 * Where the reference panics (:102-104, length < 1) this returns -1. */
int64_t cmt_merkle_get_split_point(int64_t length)
{
    uint64_t u;
    int      bitlen = 0;
    int64_t  k;

    if (length < 1) {
        return -1;                       /* tree.go:102-104 panic */
    }
    u = (uint64_t)length;
    while (u != 0) {                     /* bits.Len(uLength) */
        bitlen++;
        u >>= 1;
    }
    k = (int64_t)((uint64_t)1 << (unsigned)(bitlen - 1));
    if (k == length) {
        k >>= 1;
    }
    return k;
}

/* cometbft@709fd12b crypto/merkle/tree.go:15-27 — hashFromByteSlices().
 * tree.go:11-13 HashFromByteSlices() is the same call with the hasher
 * supplied, which a one-shot digest does not need. */
int cmt_merkle_hash_from_byte_slices(const cmt_merkle_item_t *items,
                                     size_t n,
                                     uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t left[CMT_TMHASH_SIZE];
    uint8_t right[CMT_TMHASH_SIZE];
    int64_t k;
    int     rc;

    if (out == NULL || (items == NULL && n != 0)) {
        return CMT_FAULT;
    }
    if (n == 0) {                                    /* tree.go:17-18 */
        return cmt_merkle_empty_hash(out);
    }
    if (n == 1) {                                    /* tree.go:19-20 */
        return cmt_merkle_leaf_hash(items[0].data, items[0].len, out);
    }
    k = cmt_merkle_get_split_point((int64_t)n);      /* tree.go:22 */
    if (k < 1 || (uint64_t)k >= (uint64_t)n) {
        /* Unreachable for n >= 2; an explicit guard because everything
         * below indexes with k (INVARIANT 7495d337). */
        return CMT_FAULT;
    }
    rc = cmt_merkle_hash_from_byte_slices(items, (size_t)k, left);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_merkle_hash_from_byte_slices(items + k, n - (size_t)k, right);
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_merkle_inner_hash(left, right, out);  /* tree.go:25 */
}

/* cometbft@709fd12b crypto/merkle/tree.go:68-98 —
 * HashFromByteSlicesIterative(). Zero consumers; see the header. */
int cmt_merkle_hash_from_byte_slices_iterative(const cmt_merkle_item_t *items,
                                               size_t n,
                                               uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t (*hashes)[CMT_TMHASH_SIZE];
    size_t   size, rp, wp, i;
    int      rc = CMT_OK;

    if (out == NULL || (items == NULL && n != 0)) {
        return CMT_FAULT;
    }
    if (n == 0) {                                    /* tree.go:78-79 */
        return cmt_merkle_empty_hash(out);
    }
    if (n > (size_t)-1 / CMT_TMHASH_SIZE) {
        return CMT_FAULT;
    }
    hashes = (uint8_t (*)[CMT_TMHASH_SIZE])malloc(n * CMT_TMHASH_SIZE);
    if (hashes == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {                        /* tree.go:71-73 */
        rc = cmt_merkle_leaf_hash(items[i].data, items[i].len, hashes[i]);
        if (rc != CMT_OK) {
            free(hashes);
            return rc;
        }
    }
    size = n;                                        /* tree.go:75 */
    for (;;) {
        if (size == 1) {                             /* tree.go:80-81 */
            memcpy(out, hashes[0], CMT_TMHASH_SIZE);
            free(hashes);
            return CMT_OK;
        }
        rp = 0;
        wp = 0;
        while (rp < size) {                          /* tree.go:85-94 */
            if (rp + 1 < size) {
                uint8_t tmp[CMT_TMHASH_SIZE];
                rc = cmt_merkle_inner_hash(hashes[rp], hashes[rp + 1], tmp);
                if (rc != CMT_OK) {
                    free(hashes);
                    return rc;
                }
                /* Go writes items[wp] directly; wp <= rp always, so the
                 * write can overlap the reads. The temporary makes the
                 * aliasing explicit instead of relying on it. */
                memcpy(hashes[wp], tmp, CMT_TMHASH_SIZE);
                rp += 2;
            } else {
                if (wp != rp) {
                    memcpy(hashes[wp], hashes[rp], CMT_TMHASH_SIZE);
                }
                rp++;
            }
            wp++;
        }
        size = wp;                                   /* tree.go:95 */
    }
}

/* ── proof.go ───────────────────────────────────────────────────────── */

/* Carve one node out of the arena. Returns NULL when the arena is spent,
 * which cannot happen for a correctly sized arena (see below). */
static cmt_proof_node_t *cmt_arena_take(cmt_merkle_trails_t *t)
{
    if (t->arena_used >= t->arena_cap) {
        return NULL;
    }
    return &t->arena[t->arena_used++];
}

/* cometbft@709fd12b crypto/merkle/proof.go:232-252 — the recursion of
 * trailsFromByteSlices(). `slots` is the segment of the trails array that
 * belongs to this subtree, so the reference's `append(lefts, rights...)`
 * (:250) becomes writing left into slots[0..k-1] and right into
 * slots[k..n-1] — the same leaf order. */
static int cmt_trails_rec(cmt_merkle_trails_t *t,
                          const cmt_merkle_item_t *items, size_t n,
                          cmt_proof_node_t **slots,
                          cmt_proof_node_t **subroot)
{
    cmt_proof_node_t *left_root  = NULL;
    cmt_proof_node_t *right_root = NULL;
    cmt_proof_node_t *node;
    int64_t           k;
    int               rc;

    if (n == 0) {                                    /* proof.go:235-236 */
        node = cmt_arena_take(t);
        if (node == NULL) {
            return CMT_FAULT;
        }
        rc = cmt_merkle_empty_hash(node->hash);
        if (rc != CMT_OK) {
            return rc;
        }
        *subroot = node;
        return CMT_OK;
    }
    if (n == 1) {                                    /* proof.go:237-239 */
        node = cmt_arena_take(t);
        if (node == NULL) {
            return CMT_FAULT;
        }
        rc = cmt_merkle_leaf_hash(items[0].data, items[0].len, node->hash);
        if (rc != CMT_OK) {
            return rc;
        }
        slots[0] = node;
        *subroot = node;
        return CMT_OK;
    }
    k = cmt_merkle_get_split_point((int64_t)n);      /* proof.go:241 */
    if (k < 1 || (uint64_t)k >= (uint64_t)n) {
        return CMT_FAULT;
    }
    rc = cmt_trails_rec(t, items, (size_t)k, slots, &left_root);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_trails_rec(t, items + k, n - (size_t)k, slots + k, &right_root);
    if (rc != CMT_OK) {
        return rc;
    }
    node = cmt_arena_take(t);
    if (node == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_merkle_inner_hash(left_root->hash, right_root->hash,
                               node->hash);          /* proof.go:244 */
    if (rc != CMT_OK) {
        return rc;
    }
    left_root->parent  = node;                       /* proof.go:246-249 */
    left_root->right   = right_root;
    right_root->parent = node;
    right_root->left   = left_root;
    *subroot = node;
    return CMT_OK;
}

int cmt_merkle_trails_from_byte_slices(const cmt_merkle_item_t *items,
                                       size_t n,
                                       cmt_merkle_trails_t *out)
{
    size_t cap;
    int    rc;

    if (out == NULL || (items == NULL && n != 0)) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));

    /* A binary tree with n leaves has n - 1 internal nodes, so 2n - 1
     * nodes in all; n == 0 produces the single emptyHash node. Each
     * overflow is checked BEFORE the arithmetic that could overflow
     * (INVARIANT 7495d337). */
    if (n != 0 && (n > (size_t)-1 / 2 ||
                   n > (size_t)-1 / sizeof(cmt_proof_node_t *) ||
                   (2 * n - 1) > (size_t)-1 / sizeof(cmt_proof_node_t))) {
        return CMT_FAULT;
    }
    cap = (n == 0) ? 1 : (2 * n - 1);
    out->arena = (cmt_proof_node_t *)calloc(cap, sizeof(cmt_proof_node_t));
    if (out->arena == NULL) {
        return CMT_FAULT;
    }
    out->arena_cap = cap;
    if (n != 0) {
        out->trails = (cmt_proof_node_t **)calloc(n,
                                                  sizeof(cmt_proof_node_t *));
        if (out->trails == NULL) {
            free(out->arena);
            memset(out, 0, sizeof(*out));
            return CMT_FAULT;
        }
    }
    out->n = n;
    rc = cmt_trails_rec(out, items, n, out->trails, &out->root);
    if (rc != CMT_OK) {
        cmt_merkle_trails_free(out);
        return rc;
    }
    return CMT_OK;
}

void cmt_merkle_trails_free(cmt_merkle_trails_t *t)
{
    if (t == NULL) {
        return;
    }
    free(t->arena);
    free(t->trails);
    memset(t, 0, sizeof(*t));
}

/* cometbft@709fd12b crypto/merkle/proof.go:213-228 — FlattenAunts().
 *
 * NOTE reference quirk: the `default: break` at :222-223 breaks out of the
 * Go `switch`, not out of the `for` — so a node with neither sibling (only
 * the root) simply contributes nothing and the walk continues to its nil
 * parent, ending the loop. The C `if / else if` below has exactly that
 * effect without needing the quirk. */
int cmt_proof_node_flatten_aunts(const cmt_proof_node_t *spn,
                                 uint8_t (*out)[CMT_TMHASH_SIZE],
                                 size_t *out_len)
{
    size_t cap;
    size_t n = 0;

    if (out_len == NULL || (out == NULL && *out_len != 0)) {
        return CMT_FAULT;
    }
    cap = *out_len;
    while (spn != NULL) {                            /* proof.go:216 */
        const uint8_t *aunt = NULL;

        if (spn->left != NULL) {                     /* proof.go:218-219 */
            aunt = spn->left->hash;
        } else if (spn->right != NULL) {             /* proof.go:220-221 */
            aunt = spn->right->hash;
        }
        if (aunt != NULL) {
            if (n >= cap) {
                *out_len = n;
                return CMT_REJECT;
            }
            memcpy(out[n], aunt, CMT_TMHASH_SIZE);
            n++;
        }
        spn = spn->parent;                           /* proof.go:225 */
    }
    *out_len = n;
    return CMT_OK;
}

/* cometbft@709fd12b crypto/merkle/proof.go:35-48 — ProofsFromByteSlices() */
int cmt_merkle_proofs_from_byte_slices(const cmt_merkle_item_t *items,
                                       size_t n,
                                       uint8_t root[CMT_TMHASH_SIZE],
                                       cmt_proof_t *proofs)
{
    cmt_merkle_trails_t trails;
    size_t              i;
    int                 rc;

    if (n != 0 && proofs == NULL) {
        return CMT_FAULT;
    }
    /* p->total and p->index are int64_t; guard the cast. The #if keeps
     * the comparison from being a tautology (and a -Wtype-limits error)
     * on a 32-bit target where size_t cannot reach INT64_MAX. */
#if SIZE_MAX > INT64_MAX
    if (n > (size_t)INT64_MAX) {
        return CMT_FAULT;
    }
#endif
    rc = cmt_merkle_trails_from_byte_slices(items, n, &trails);
    if (rc != CMT_OK) {
        return rc;
    }
    if (root != NULL) {
        memcpy(root, trails.root->hash, CMT_TMHASH_SIZE);  /* proof.go:37 */
    }
    for (i = 0; i < n; i++) {                        /* proof.go:39-46 */
        cmt_proof_t *p = &proofs[i];
        size_t       na;

        memset(p, 0, sizeof(*p));
        p->total = (int64_t)n;
        p->index = (int64_t)i;
        memcpy(p->leaf_hash, trails.trails[i]->hash, CMT_TMHASH_SIZE);
        p->leaf_hash_len = CMT_TMHASH_SIZE;
        na = CMT_MERKLE_MAX_AUNTS;
        rc = cmt_proof_node_flatten_aunts(trails.trails[i], p->aunts, &na);
        if (rc != CMT_OK) {
            /* Only reachable if the tree were deeper than 100 levels,
             * i.e. n >= 2^100, which no size_t can express. */
            cmt_merkle_trails_free(&trails);
            return CMT_FAULT;
        }
        p->aunts_len = na;
        for (size_t j = 0; j < na; j++) {
            p->aunt_len[j] = CMT_TMHASH_SIZE;
        }
    }
    cmt_merkle_trails_free(&trails);
    return CMT_OK;
}

/* cometbft@709fd12b crypto/merkle/proof.go:52-74 — (sp *Proof) Verify() */
int cmt_proof_verify(const cmt_proof_t *sp,
                     const uint8_t root_hash[CMT_TMHASH_SIZE],
                     const uint8_t *leaf, size_t leaf_len)
{
    uint8_t want_leaf[CMT_TMHASH_SIZE];
    uint8_t computed[CMT_TMHASH_SIZE];
    int     rc;

    if (sp == NULL) {
        return CMT_FAULT;
    }
    if (root_hash == NULL) {                         /* proof.go:53-55 */
        return CMT_REJECT;
    }
    if (sp->total < 0) {                             /* proof.go:56-58 */
        return CMT_REJECT;
    }
    if (sp->index < 0) {                             /* proof.go:59-61 */
        return CMT_REJECT;
    }
    rc = cmt_merkle_leaf_hash(leaf, leaf_len, want_leaf);  /* proof.go:62 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (sp->leaf_hash_len != CMT_TMHASH_SIZE ||      /* proof.go:63-65 */
        memcmp(sp->leaf_hash, want_leaf, CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    rc = cmt_proof_compute_root_hash(sp, computed);  /* proof.go:66-69 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (memcmp(computed, root_hash, CMT_TMHASH_SIZE) != 0) {  /* :70-72 */
        return CMT_REJECT;
    }
    return CMT_OK;
}

/* cometbft@709fd12b crypto/merkle/proof.go:77-83 ComputeRootHash(),
 * :86-93 computeRootHash() — one function once the panic is a return. */
int cmt_proof_compute_root_hash(const cmt_proof_t *sp,
                                uint8_t out[CMT_TMHASH_SIZE])
{
    if (sp == NULL) {
        return CMT_FAULT;
    }
    return cmt_compute_hash_from_aunts(sp->index, sp->total, sp->leaf_hash,
                                       sp->aunts, sp->aunts_len, out);
}

/* cometbft@709fd12b crypto/merkle/proof.go:113-132 — ValidateBasic() */
int cmt_proof_validate_basic(const cmt_proof_t *sp)
{
    size_t i;

    if (sp == NULL) {
        return CMT_FAULT;
    }
    if (sp->total < 0) {                             /* proof.go:114-116 */
        return CMT_REJECT;
    }
    if (sp->index < 0) {                             /* proof.go:117-119 */
        return CMT_REJECT;
    }
    if (sp->leaf_hash_len != CMT_TMHASH_SIZE) {      /* proof.go:120-122 */
        return CMT_REJECT;
    }
    if (sp->aunts_len > CMT_MERKLE_MAX_AUNTS) {      /* proof.go:123-125 */
        return CMT_REJECT;
    }
    for (i = 0; i < sp->aunts_len; i++) {            /* proof.go:126-130 */
        if (sp->aunt_len[i] != CMT_TMHASH_SIZE) {
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* cometbft@709fd12b crypto/merkle/proof.go:166-197 — computeHashFromAunts() */
int cmt_compute_hash_from_aunts(int64_t index, int64_t total,
                                const uint8_t leaf_hash[CMT_TMHASH_SIZE],
                                const uint8_t (*inner_hashes)[CMT_TMHASH_SIZE],
                                size_t n_inner,
                                uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t sub[CMT_TMHASH_SIZE];
    int64_t num_left;
    int     rc;

    if (out == NULL || leaf_hash == NULL) {
        return CMT_FAULT;
    }
    if (index >= total || index < 0 || total <= 0) { /* proof.go:167-169 */
        return CMT_REJECT;
    }
    if (total == 1) {                                /* proof.go:173-177 */
        if (n_inner != 0) {
            return CMT_REJECT;
        }
        memcpy(out, leaf_hash, CMT_TMHASH_SIZE);
        return CMT_OK;
    }
    /* proof.go:179-181 — default branch */
    if (n_inner == 0) {
        return CMT_REJECT;
    }
    if (inner_hashes == NULL) {
        return CMT_FAULT;
    }
    num_left = cmt_merkle_get_split_point(total);    /* proof.go:182 */
    if (num_left < 1 || num_left >= total) {
        return CMT_FAULT;                            /* unreachable, total >= 2 */
    }
    if (index < num_left) {                          /* proof.go:183-190 */
        rc = cmt_compute_hash_from_aunts(index, num_left, leaf_hash,
                                         inner_hashes, n_inner - 1, sub);
        if (rc != CMT_OK) {
            return rc;
        }
        return cmt_merkle_inner_hash(sub, inner_hashes[n_inner - 1], out);
    }
    /* proof.go:191-195 */
    rc = cmt_compute_hash_from_aunts(index - num_left, total - num_left,
                                     leaf_hash, inner_hashes, n_inner - 1,
                                     sub);
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_merkle_inner_hash(inner_hashes[n_inner - 1], sub, out);
}
