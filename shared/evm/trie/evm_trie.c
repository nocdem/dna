/**
 * @file evm_trie.c
 * @brief Nodus EVM state commitment: persistent, incremental MPT with SHA3-512
 *        node digests. See evm_trie.h for the root definition, the store
 *        contract and the verification rules.
 *
 * In memory a trie is a tree of `tnode`s hanging off t->root. A node is
 * one of:
 *   N_REF     a committed node not loaded yet: only its 64-byte digest;
 *   N_LEAF    remaining key nibbles + value;
 *   N_EXT     shared key segment + one child (always a branch);
 *   N_BRANCH  16 children (NULL = absent), no value (fixed-length paths).
 * A REF is replaced IN PLACE by the decoded node the first time a walk
 * reaches it (resolve()), so a parent's child pointer never changes when a
 * node is loaded. Every node on a modified path is marked dirty; commit
 * re-encodes dirty nodes only and refers to clean hashed nodes by their
 * cached digest.
 *
 * The update rules keep the tree in the exact shape patricialize
 * (merkle_patricia_trie.py:507-581) builds for the same key set:
 *   - one key below a point          -> a leaf          (:537-539)
 *   - all keys share a prefix p > 0  -> extension(p) over a branch (:554-562)
 *   - otherwise                      -> a branch on the next nibble (:564-581)
 * so insert splits leaves/extensions at the first differing nibble, and
 * delete merges a branch left with one child into that child (prepending
 * the child's nibble) and an extension into a leaf/extension child.
 */
#include "evm_trie.h"
#include "evm_trie_rlp.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdlib.h>
#include <string.h>

/* Substitution (2): the inline threshold equals the digest length. */
#define TRIE_INLINE_LIMIT EVM_TRIE_DIGEST_LEN

enum { N_REF = 1, N_LEAF, N_EXT, N_BRANCH };

typedef struct tnode {
    uint8_t        kind;
    uint8_t        dirty;       /* modified since loaded / committed        */
    uint8_t        has_digest;  /* clean, encoding >= 64 B, digest valid    */
    uint8_t        is_root;     /* N_REF: the committed root (may be < 64 B) */
    uint8_t        must_branch; /* N_REF: referenced by an extension        */
    uint8_t        nlen;        /* leaf rest / extension segment, nibbles   */
    uint8_t        nib[EVM_TRIE_PATH_NIBBLES];
    uint8_t        digest[EVM_TRIE_DIGEST_LEN];
    uint8_t       *val;         /* N_LEAF                                   */
    size_t         val_len;
    struct tnode  *child[16];   /* N_BRANCH: by nibble; N_EXT: child[0]     */
} tnode;

struct evm_trie {
    evm_trie_store_t store;
    tnode           *root;      /* NULL = empty trie                        */
    int              fault;     /* sticky -2                                */
};

/* ── hashing ───────────────────────────────────────────────────────── */

/* SHA3-512 (substitutions 1, 3, 4). qgp_sha3_512 rejects a NULL pointer
 * even for len 0, so an empty input is passed as a non-NULL dummy. */
static int h512(const uint8_t *p, size_t len, uint8_t out[64])
{
    static const uint8_t none = 0;
    return qgp_sha3_512(len ? p : &none, len, out) == 0 ? 0 : -2;
}

int evm_trie_empty_root(uint8_t root[EVM_TRIE_DIGEST_LEN])
{
    if (!root) return -1;
    const uint8_t rlp_empty = 0x80;              /* RLP(b"") — subst. (4) */
    return h512(&rlp_empty, 1, root);
}

static void path_to_nibbles(const uint8_t path[EVM_TRIE_PATH_LEN],
                            uint8_t nibs[EVM_TRIE_PATH_NIBBLES])
{
    /* bytes_to_nibble_list, merkle_patricia_trie.py:395-404 */
    for (size_t i = 0; i < EVM_TRIE_PATH_LEN; i++) {
        nibs[2 * i]     = (uint8_t)((path[i] & 0xF0) >> 4);
        nibs[2 * i + 1] = (uint8_t)(path[i] & 0x0F);
    }
}

/* ── nodes ─────────────────────────────────────────────────────────── */

static tnode *node_new(uint8_t kind)
{
    tnode *n = calloc(1, sizeof(*n));
    if (n) {
        n->kind = kind;
        n->dirty = 1;
    }
    return n;
}

static void node_free(tnode *n)
{
    if (!n) return;
    for (int i = 0; i < 16; i++) node_free(n->child[i]);
    free(n->val);
    free(n);
}

/* A node's content is about to change: it no longer matches any digest. */
static void touch(tnode *n)
{
    n->dirty = 1;
    n->has_digest = 0;
}

static int set_fault(evm_trie_t *t)
{
    t->fault = 1;
    return -2;
}

/* ── encoding (encode_internal_node, merkle_patricia_trie.py:213-249) ── */

/* nibble_list_to_compact (merkle_patricia_trie.py:360-392), as an RLP
 * string. */
static int put_compact(evm_trie_rlp_buf *out, const uint8_t *x, size_t n,
                       int is_leaf)
{
    uint8_t c[1 + EVM_TRIE_PATH_NIBBLES / 2];
    size_t k = 0, i = 0;
    if (n > EVM_TRIE_PATH_NIBBLES) return -2;
    if (n % 2 == 0) {                                     /* :383-386 */
        c[k++] = (uint8_t)(16 * (2 * is_leaf));
    } else {                                              /* :387-390 */
        c[k++] = (uint8_t)(16 * ((2 * is_leaf) + 1) + x[0]);
        i = 1;
    }
    for (; i < n; i += 2) c[k++] = (uint8_t)(16 * x[i] + x[i + 1]);
    return evm_trie_rlp_put_bytes(out, c, k);
}

static int node_encode(evm_trie_t *t, tnode *n, evm_trie_rlp_buf *out,
                       int write);

/* Append the item a parent holds for child `c`: b"" when absent; the
 * child's own RLP when that is < 64 bytes (embedded, :246-247); otherwise
 * the 64-byte SHA3-512 digest as an RLP string (:248-249, subst. 1+2).
 * With `write`, a child that ends up hashed is put to the store first and
 * becomes clean. */
static int put_child_ref(evm_trie_t *t, tnode *c, evm_trie_rlp_buf *out,
                         int write)
{
    if (!c) return evm_trie_rlp_put_bytes(out, NULL, 0);
    if (c->kind == N_REF || (c->has_digest && !c->dirty))
        return evm_trie_rlp_put_bytes(out, c->digest, EVM_TRIE_DIGEST_LEN);

    evm_trie_rlp_buf enc = {0};
    int rc = node_encode(t, c, &enc, write);
    if (rc == 0) {
        if (enc.len < TRIE_INLINE_LIMIT) {
            rc = evm_trie_rlp_put_raw(out, enc.p, enc.len);
            if (rc == 0 && write) c->dirty = 0;
        } else {
            rc = h512(enc.p, enc.len, c->digest);
            if (rc == 0 && write) {
                if (t->store.put(t->store.ctx, c->digest, enc.p, enc.len) != 0)
                    rc = -2;
                else {
                    c->has_digest = 1;
                    c->dirty = 0;
                }
            }
            if (rc == 0)
                rc = evm_trie_rlp_put_bytes(out, c->digest,
                                            EVM_TRIE_DIGEST_LEN);
        }
    }
    evm_trie_rlp_buf_free(&enc);
    return rc;
}

/* The RLP of node n (never N_REF), children in nibble order 0..15. */
static int node_encode(evm_trie_t *t, tnode *n, evm_trie_rlp_buf *out,
                       int write)
{
    size_t start = out->len;
    int rc;
    switch (n->kind) {
    case N_LEAF:                                          /* :230-234 */
        if ((rc = put_compact(out, n->nib, n->nlen, 1)) != 0) return rc;
        if ((rc = evm_trie_rlp_put_bytes(out, n->val, n->val_len)) != 0)
            return rc;
        break;
    case N_EXT:                                           /* :235-239 */
        if ((rc = put_compact(out, n->nib, n->nlen, 0)) != 0) return rc;
        if ((rc = put_child_ref(t, n->child[0], out, write)) != 0) return rc;
        break;
    case N_BRANCH:                                        /* :240-241 */
        for (int k = 0; k < 16; k++)
            if ((rc = put_child_ref(t, n->child[k], out, write)) != 0)
                return rc;
        /* branch value: always b"" with 128-nibble paths */
        if ((rc = evm_trie_rlp_put_bytes(out, NULL, 0)) != 0) return rc;
        break;
    default:
        return -2;
    }
    rc = evm_trie_rlp_wrap_list(out, start);
    return rc == 0 ? 0 : -2;
}

/* ── decoding + verification of stored nodes ───────────────────────── */

/* Split the payload of a list into at most `max` items; the items must
 * consume the payload exactly. @return item count, or -1. */
static int split_list(const evm_trie_rlp_item *list, evm_trie_rlp_item *items,
                      int max)
{
    const uint8_t *p = list->payload;
    size_t rem = list->len;
    int n = 0;
    while (rem > 0) {
        if (n == max) return -1;
        if (evm_trie_rlp_decode_item(p, rem, &items[n]) != 0) return -1;
        p += items[n].total;
        rem -= items[n].total;
        n++;
    }
    return n;
}

/* Hex-prefix decode: canonical flag nibble (0..3, pad nibble 0 when the
 * length is even). @return 0 or -1. */
static int read_compact(const evm_trie_rlp_item *it, uint8_t *nib,
                        size_t *nlen, int *is_leaf)
{
    if (it->is_list || it->len == 0) return -1;
    const uint8_t *c = it->payload;
    unsigned flag = c[0] >> 4;
    if (flag > 3) return -1;
    int odd = (int)(flag & 1);
    *is_leaf = (flag & 2) ? 1 : 0;
    if (!odd && (c[0] & 0x0F) != 0) return -1;
    size_t n = 2 * (it->len - 1) + (size_t)odd;
    if (n > EVM_TRIE_PATH_NIBBLES) return -1;
    size_t k = 0;
    if (odd) nib[k++] = (uint8_t)(c[0] & 0x0F);
    for (size_t i = 1; i < it->len; i++) {
        nib[k++] = (uint8_t)(c[i] >> 4);
        nib[k++] = (uint8_t)(c[i] & 0x0F);
    }
    *nlen = n;
    return 0;
}

static int decode_node(const uint8_t *p, size_t len, size_t depth,
                       int expect_branch, tnode **out);

/* A child reference inside a stored node: b"" -> NULL; a 64-byte string ->
 * an unresolved N_REF; an embedded list whose encoding is < 64 bytes ->
 * the decoded node. Anything else is malformed. @return 0 or -1/-2. */
static int decode_child(const evm_trie_rlp_item *it, size_t depth,
                        int expect_branch, tnode **out)
{
    *out = NULL;
    if (!it->is_list) {
        if (it->len == 0) return expect_branch ? -1 : 0;
        if (it->len != EVM_TRIE_DIGEST_LEN) return -1;
        tnode *r = node_new(N_REF);
        if (!r) return -2;
        r->dirty = 0;
        r->must_branch = (uint8_t)expect_branch;
        memcpy(r->digest, it->payload, EVM_TRIE_DIGEST_LEN);
        *out = r;
        return 0;
    }
    if (it->total >= TRIE_INLINE_LIMIT) return -1;   /* would be hashed */
    const uint8_t *start = it->payload - (it->total - it->len);
    return decode_node(start, it->total, depth, expect_branch, out);
}

/* Decode one node from exactly `len` bytes at `depth` nibbles. All nodes
 * produced are clean. @return 0, -1 (malformed / non-canonical shape), -2
 * (allocation). */
static int decode_node(const uint8_t *p, size_t len, size_t depth,
                       int expect_branch, tnode **out)
{
    evm_trie_rlp_item top, it[17];
    *out = NULL;
    if (depth > EVM_TRIE_PATH_NIBBLES) return -1;
    if (evm_trie_rlp_decode_item(p, len, &top) != 0) return -1;
    if (!top.is_list || top.total != len) return -1;
    int cnt = split_list(&top, it, 17);
    if (cnt == 2) {
        uint8_t nib[EVM_TRIE_PATH_NIBBLES];
        size_t nlen;
        int is_leaf;
        if (expect_branch) return -1;
        if (read_compact(&it[0], nib, &nlen, &is_leaf) != 0) return -1;
        tnode *n = node_new(is_leaf ? N_LEAF : N_EXT);
        if (!n) return -2;
        n->dirty = 0;
        n->nlen = (uint8_t)nlen;
        memcpy(n->nib, nib, nlen);
        if (is_leaf) {
            /* the rest of a 128-nibble path; a non-empty opaque value */
            if (nlen != EVM_TRIE_PATH_NIBBLES - depth ||
                it[1].is_list || it[1].len == 0) {
                node_free(n);
                return -1;
            }
            n->val = malloc(it[1].len);
            if (!n->val) { node_free(n); return -2; }
            memcpy(n->val, it[1].payload, it[1].len);
            n->val_len = it[1].len;
        } else {
            /* >= 1 nibble, and room below for the branch it leads to */
            if (nlen == 0 || depth + nlen >= EVM_TRIE_PATH_NIBBLES) {
                node_free(n);
                return -1;
            }
            int rc = decode_child(&it[1], depth + nlen, 1, &n->child[0]);
            if (rc == 0 && !n->child[0]) rc = -1;
            if (rc != 0) { node_free(n); return rc; }
        }
        *out = n;
        return 0;
    }
    if (cnt == 17) {
        if (depth >= EVM_TRIE_PATH_NIBBLES) return -1;
        /* branch value b"" (no key ends inside a 128-nibble trie) */
        if (it[16].is_list || it[16].len != 0) return -1;
        tnode *n = node_new(N_BRANCH);
        if (!n) return -2;
        n->dirty = 0;
        int kids = 0;
        for (int k = 0; k < 16; k++) {
            int rc = decode_child(&it[k], depth + 1, 0, &n->child[k]);
            if (rc != 0) { node_free(n); return rc; }
            if (n->child[k]) kids++;
        }
        if (kids < 2) { node_free(n); return -1; }
        *out = n;
        return 0;
    }
    return -1;
}

/* Load an N_REF in place at `depth`: fetch, check the digest, decode,
 * re-encode and compare (canonical form), check the size class. */
static int resolve(evm_trie_t *t, tnode *n, size_t depth)
{
    if (n->kind != N_REF) return 0;
    uint8_t *rlp = NULL;
    size_t len = 0;
    int grc = t->store.get(t->store.ctx, n->digest, &rlp, &len);
    if (grc != 0 || !rlp || len == 0) {
        if (grc == 0) free(rlp);
        return set_fault(t);
    }

    int rc = 0;
    uint8_t d[EVM_TRIE_DIGEST_LEN];
    tnode *dec = NULL;
    evm_trie_rlp_buf re = {0};
    if (h512(rlp, len, d) != 0 || memcmp(d, n->digest, sizeof(d)) != 0)
        rc = -2;
    /* a hashed child encodes to >= 64 bytes; only the root may be smaller */
    else if (!n->is_root && len < TRIE_INLINE_LIMIT)
        rc = -2;
    else if (decode_node(rlp, len, depth, n->must_branch, &dec) != 0)
        rc = -2;
    else if (node_encode(t, dec, &re, 0) != 0 || re.len != len ||
             memcmp(re.p, rlp, len) != 0)
        rc = -2;
    evm_trie_rlp_buf_free(&re);
    free(rlp);
    if (rc != 0) {
        node_free(dec);
        return set_fault(t);
    }

    /* move the decoded content into n, keep n's identity and digest */
    n->kind = dec->kind;
    n->dirty = 0;
    n->has_digest = (len >= TRIE_INLINE_LIMIT) ? 1 : 0;
    n->nlen = dec->nlen;
    memcpy(n->nib, dec->nib, sizeof(n->nib));
    n->val = dec->val;
    n->val_len = dec->val_len;
    memcpy(n->child, dec->child, sizeof(n->child));
    free(dec);                     /* shell only: its parts now belong to n */
    return 0;
}

/* ── insert / delete / lookup ──────────────────────────────────────── */

static size_t common_prefix(const uint8_t *a, const uint8_t *b, size_t n)
{
    /* common_prefix_length, merkle_patricia_trie.py:350-357 */
    size_t i = 0;
    while (i < n && a[i] == b[i]) i++;
    return i;
}

static tnode *leaf_new(const uint8_t *nibs, size_t nlen, const uint8_t *val,
                       size_t val_len)
{
    tnode *l = node_new(N_LEAF);
    if (!l) return NULL;
    l->val = malloc(val_len);
    if (!l->val) { free(l); return NULL; }
    memcpy(l->val, val, val_len);
    l->val_len = val_len;
    l->nlen = (uint8_t)nlen;
    memcpy(l->nib, nibs, nlen);
    return l;
}

/* Drop the first `k` nibbles of n's key / segment. */
static void nib_drop(tnode *n, size_t k)
{
    memmove(n->nib, n->nib + k, n->nlen - k);
    n->nlen = (uint8_t)(n->nlen - k);
    touch(n);
}

/* Prepend `pre` (np nibbles) to n's key / segment. */
static void nib_prepend(tnode *n, const uint8_t *pre, size_t np)
{
    memmove(n->nib + np, n->nib, n->nlen);
    memcpy(n->nib, pre, np);
    n->nlen = (uint8_t)(n->nlen + np);
    touch(n);
}

static int ins(evm_trie_t *t, tnode **slot, size_t depth,
               const uint8_t *path, const uint8_t *val, size_t val_len)
{
    tnode *n = *slot;
    const uint8_t *rest = path + depth;
    size_t rlen = EVM_TRIE_PATH_NIBBLES - depth;

    if (!n) {                                         /* new leaf */
        tnode *l = leaf_new(rest, rlen, val, val_len);
        if (!l) return set_fault(t);
        *slot = l;
        return 0;
    }
    if (resolve(t, n, depth) != 0) return -2;

    if (n->kind == N_BRANCH) {
        int rc = ins(t, &n->child[rest[0]], depth + 1, path, val, val_len);
        if (rc == 0) touch(n);
        return rc;
    }

    if (n->kind == N_LEAF) {
        size_t cp = common_prefix(n->nib, rest, rlen);
        if (cp == rlen) {                             /* same key: replace */
            uint8_t *nv = malloc(val_len);
            if (!nv) return set_fault(t);
            memcpy(nv, val, val_len);
            free(n->val);
            n->val = nv;
            n->val_len = val_len;
            touch(n);
            return 0;
        }
        /* split at nibble cp: [extension(cp)] -> branch -> two leaves */
        tnode *br = node_new(N_BRANCH);
        tnode *nl = leaf_new(rest + cp + 1, rlen - cp - 1, val, val_len);
        tnode *ex = cp ? node_new(N_EXT) : NULL;
        if (!br || !nl || (cp && !ex)) {
            free(br);
            node_free(nl);
            free(ex);
            return set_fault(t);
        }
        uint8_t old_nib = n->nib[cp];
        nib_drop(n, cp + 1);
        br->child[old_nib] = n;
        br->child[rest[cp]] = nl;
        if (ex) {
            ex->nlen = (uint8_t)cp;
            memcpy(ex->nib, rest, cp);
            ex->child[0] = br;
            *slot = ex;
        } else {
            *slot = br;
        }
        return 0;
    }

    if (n->kind == N_EXT) {
        size_t seg = n->nlen;
        size_t cp = common_prefix(n->nib, rest, seg);
        if (cp == seg) {
            int rc = ins(t, &n->child[0], depth + seg, path, val, val_len);
            if (rc == 0) touch(n);
            return rc;
        }
        /* split the segment at nibble cp (cp < seg; rest is longer than
         * seg because the extension leads to a branch above depth 128) */
        tnode *br = node_new(N_BRANCH);
        tnode *nl = leaf_new(rest + cp + 1, rlen - cp - 1, val, val_len);
        tnode *ex = cp ? node_new(N_EXT) : NULL;
        if (!br || !nl || (cp && !ex)) {
            free(br);
            node_free(nl);
            free(ex);
            return set_fault(t);
        }
        uint8_t old_nib = n->nib[cp];
        if (ex) {
            ex->nlen = (uint8_t)cp;
            memcpy(ex->nib, n->nib, cp);
            ex->child[0] = br;
        }
        if (seg - cp - 1 > 0) {           /* n keeps the tail of the segment */
            nib_drop(n, cp + 1);
            br->child[old_nib] = n;
        } else {                          /* nothing left: n's branch moves up */
            br->child[old_nib] = n->child[0];
            n->child[0] = NULL;
            node_free(n);
        }
        br->child[rest[cp]] = nl;
        *slot = ex ? ex : br;
        return 0;
    }
    return set_fault(t);
}

/* *found = 1 when the key existed (and is now removed). */
static int del(evm_trie_t *t, tnode **slot, size_t depth,
               const uint8_t *path, int *found)
{
    tnode *n = *slot;
    const uint8_t *rest = path + depth;
    size_t rlen = EVM_TRIE_PATH_NIBBLES - depth;

    *found = 0;
    if (!n) return 0;
    if (resolve(t, n, depth) != 0) return -2;

    if (n->kind == N_LEAF) {
        if (n->nlen == rlen && memcmp(n->nib, rest, rlen) == 0) {
            node_free(n);
            *slot = NULL;
            *found = 1;
        }
        return 0;
    }

    if (n->kind == N_EXT) {
        size_t seg = n->nlen;
        if (seg >= rlen || memcmp(n->nib, rest, seg) != 0) return 0;
        int rc = del(t, &n->child[0], depth + seg, path, found);
        if (rc != 0 || !*found) return rc;
        tnode *c = n->child[0];
        if (!c) return set_fault(t);           /* a branch never empties */
        if (c->kind == N_BRANCH) {
            touch(n);
        } else {                               /* leaf / extension below: merge */
            nib_prepend(c, n->nib, seg);
            n->child[0] = NULL;
            node_free(n);
            *slot = c;
        }
        return 0;
    }

    if (n->kind == N_BRANCH) {
        int rc = del(t, &n->child[rest[0]], depth + 1, path, found);
        if (rc != 0 || !*found) return rc;
        int kids = 0, last = -1;
        for (int k = 0; k < 16; k++)
            if (n->child[k]) { kids++; last = k; }
        if (kids >= 2) {
            touch(n);
            return 0;
        }
        if (kids != 1) return set_fault(t);    /* had >= 2 before the delete */
        /* one child left: the branch disappears (patricialize never builds
         * a one-child branch) */
        tnode *c = n->child[last];
        if (resolve(t, c, depth + 1) != 0) return -2;
        uint8_t pre = (uint8_t)last;
        if (c->kind == N_BRANCH) {
            tnode *ex = node_new(N_EXT);
            if (!ex) return set_fault(t);
            ex->nlen = 1;
            ex->nib[0] = pre;
            ex->child[0] = c;
            n->child[last] = NULL;
            node_free(n);
            *slot = ex;
        } else {
            nib_prepend(c, &pre, 1);
            n->child[last] = NULL;
            node_free(n);
            *slot = c;
        }
        return 0;
    }
    return set_fault(t);
}

/* ── public API ────────────────────────────────────────────────────── */

int evm_trie_open(const evm_trie_store_t *store,
                  const uint8_t root[EVM_TRIE_DIGEST_LEN], evm_trie_t **out)
{
    if (!out) return -1;
    *out = NULL;
    if (!store || !store->get || !store->put || !root) return -1;
    uint8_t empty[EVM_TRIE_DIGEST_LEN];
    if (evm_trie_empty_root(empty) != 0) return -2;

    evm_trie_t *t = calloc(1, sizeof(*t));
    if (!t) return -2;
    t->store = *store;
    if (memcmp(root, empty, sizeof(empty)) != 0) {
        t->root = node_new(N_REF);
        if (!t->root) { free(t); return -2; }
        t->root->dirty = 0;
        t->root->is_root = 1;
        memcpy(t->root->digest, root, EVM_TRIE_DIGEST_LEN);
    }
    *out = t;
    return 0;
}

void evm_trie_close(evm_trie_t *t)
{
    if (!t) return;
    node_free(t->root);
    free(t);
}

int evm_trie_set_path(evm_trie_t *t, const uint8_t path[EVM_TRIE_PATH_LEN],
                      const uint8_t *value, size_t value_len)
{
    if (!t || !path || (value_len && !value)) return -1;
    if (t->fault) return -2;
    uint8_t nibs[EVM_TRIE_PATH_NIBBLES];
    path_to_nibbles(path, nibs);
    if (value_len == 0) {                      /* empty value = delete */
        int found;
        return del(t, &t->root, 0, nibs, &found);
    }
    return ins(t, &t->root, 0, nibs, value, value_len);
}

int evm_trie_set(evm_trie_t *t, const uint8_t *key, size_t key_len,
                 const uint8_t *value, size_t value_len)
{
    if (!t || (key_len && !key) || (value_len && !value)) return -1;
    if (t->fault) return -2;
    uint8_t path[EVM_TRIE_PATH_LEN];
    if (h512(key, key_len, path) != 0) return set_fault(t);  /* subst. (3) */
    return evm_trie_set_path(t, path, value, value_len);
}

int evm_trie_delete(evm_trie_t *t, const uint8_t *key, size_t key_len)
{
    return evm_trie_set(t, key, key_len, NULL, 0);
}

int evm_trie_get_path(evm_trie_t *t, const uint8_t path[EVM_TRIE_PATH_LEN],
                      uint8_t **value, size_t *value_len)
{
    if (!t || !path || !value || !value_len) return -1;
    *value = NULL;
    *value_len = 0;
    if (t->fault) return -2;
    uint8_t nibs[EVM_TRIE_PATH_NIBBLES];
    path_to_nibbles(path, nibs);

    tnode *n = t->root;
    size_t depth = 0;
    while (n) {
        if (resolve(t, n, depth) != 0) return -2;
        const uint8_t *rest = nibs + depth;
        size_t rlen = EVM_TRIE_PATH_NIBBLES - depth;
        if (n->kind == N_LEAF) {
            if (n->nlen != rlen || memcmp(n->nib, rest, rlen) != 0) return 1;
            uint8_t *v = malloc(n->val_len);
            if (!v) return set_fault(t);
            memcpy(v, n->val, n->val_len);
            *value = v;
            *value_len = n->val_len;
            return 0;
        }
        if (n->kind == N_EXT) {
            if (n->nlen >= rlen || memcmp(n->nib, rest, n->nlen) != 0)
                return 1;
            depth += n->nlen;
            n = n->child[0];
        } else if (n->kind == N_BRANCH) {
            n = n->child[rest[0]];
            depth += 1;
        } else {
            return set_fault(t);
        }
    }
    return 1;
}

int evm_trie_get(evm_trie_t *t, const uint8_t *key, size_t key_len,
                 uint8_t **value, size_t *value_len)
{
    if (!t || (key_len && !key) || !value || !value_len) return -1;
    *value = NULL;
    *value_len = 0;
    if (t->fault) return -2;
    uint8_t path[EVM_TRIE_PATH_LEN];
    if (h512(key, key_len, path) != 0) return set_fault(t);  /* subst. (3) */
    return evm_trie_get_path(t, path, value, value_len);
}

int evm_trie_commit(evm_trie_t *t, uint8_t root[EVM_TRIE_DIGEST_LEN])
{
    if (!t || !root) return -1;
    if (t->fault) return -2;
    tnode *r = t->root;

    if (!r) return evm_trie_empty_root(root) == 0 ? 0 : set_fault(t);
    if (r->kind == N_REF || (r->has_digest && !r->dirty)) {
        memcpy(root, r->digest, EVM_TRIE_DIGEST_LEN);  /* unchanged */
    } else {
        /* root() :499-504 with subst. (1)+(2): under both arms the result
         * is SHA3-512(RLP(root node)); the root node is always stored. */
        evm_trie_rlp_buf enc = {0};
        int rc = node_encode(t, r, &enc, 1);
        if (rc == 0) rc = h512(enc.p, enc.len, root);
        if (rc == 0 && t->store.put(t->store.ctx, root, enc.p, enc.len) != 0)
            rc = -2;
        evm_trie_rlp_buf_free(&enc);
        if (rc != 0) return set_fault(t);
    }

    /* keep only the committed root; nodes are reloaded on demand */
    tnode *ref = node_new(N_REF);
    if (!ref) return set_fault(t);
    ref->dirty = 0;
    ref->is_root = 1;
    memcpy(ref->digest, root, EVM_TRIE_DIGEST_LEN);
    node_free(t->root);
    t->root = ref;
    return 0;
}
