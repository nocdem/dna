/**
 * @file evm_trie_proof.c
 * @brief HF-9 WP6 trie proofs. Contract and references: evm_trie_proof.h.
 *
 * One walker serves both directions: prove fetches nodes from the store (and
 * records them), verify looks them up in the verifier-indexed bundle. The
 * node decoding and structural checks are evm_trie_node_check (evm_trie.c),
 * the same decoder the store's load verification uses.
 */
#include "evm_trie_proof.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdlib.h>
#include <string.h>

static int h512(const uint8_t *p, size_t len, uint8_t out[64])
{
    return qgp_sha3_512(p, len, out) == 0 ? 0 : -2;
}

void evm_trie_proof_set_free(evm_trie_proof_set_t *s)
{
    if (!s) return;
    for (size_t i = 0; i < s->n; i++) free(s->v[i].rlp);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

int evm_trie_proof_path_of_key(const uint8_t *key, size_t key_len,
                               uint8_t path[EVM_TRIE_PATH_LEN])
{
    static const uint8_t none = 0;
    if (!path || (key_len && !key)) return -1;
    return h512(key_len ? key : &none, key_len, path);
}

int evm_trie_proof_check_node(const uint8_t digest[EVM_TRIE_DIGEST_LEN],
                              const uint8_t *rlp, size_t len, size_t depth,
                              int expect_branch, int size_class,
                              evm_trie_node_view_t *out)
{
    uint8_t d[EVM_TRIE_DIGEST_LEN];
    if (!digest || !rlp || len == 0 || !out) return -1;
    if (h512(rlp, len, d) != 0 || memcmp(d, digest, sizeof(d)) != 0)
        return -2;
    return evm_trie_node_check(rlp, len, depth, expect_branch, size_class,
                               out) == 0 ? 0 : -2;
}

/* ── the walker ─────────────────────────────────────────────────────── */

/* Fetch the node reached through `digest`: *rlp stays valid until the walk
 * ends. 0 ok, -2 missing / fault. */
typedef int (*fetch_fn)(void *ctx, const uint8_t digest[64],
                        const uint8_t **rlp, size_t *len);

static void path_nibbles(const uint8_t path[EVM_TRIE_PATH_LEN],
                         uint8_t nibs[EVM_TRIE_PATH_NIBBLES])
{
    for (size_t i = 0; i < EVM_TRIE_PATH_LEN; i++) {
        nibs[2 * i]     = (uint8_t)(path[i] >> 4);
        nibs[2 * i + 1] = (uint8_t)(path[i] & 0x0F);
    }
}

static int walk(fetch_fn fetch, void *ctx, const uint8_t root[64],
                const uint8_t path[64], evm_trie_proof_result_t *res)
{
    uint8_t nibs[EVM_TRIE_PATH_NIBBLES], empty[64], dig[64];
    const uint8_t *cur = NULL;
    size_t clen = 0, depth = 0;
    int size_class = EVM_TRIE_NODE_ROOT, eb = 0, embedded = 0;

    memset(res, 0, sizeof(*res));
    if (evm_trie_empty_root(empty) != 0) return -2;
    if (memcmp(root, empty, 64) == 0) return 0;      /* empty leg: absent */
    path_nibbles(path, nibs);
    memcpy(dig, root, 64);

    for (;;) {
        evm_trie_node_view_t v;
        int ci;
        if (!embedded && fetch(ctx, dig, &cur, &clen) != 0)
            return -2;             /* a node the path needs is missing */
        if (evm_trie_node_check(cur, clen, depth, eb, size_class, &v) != 0)
            return -2;
        if (v.kind == EVM_TRIE_NODE_LEAF) {
            if (memcmp(v.nib, nibs + depth, v.nlen) == 0) {
                res->found = 1;
                res->val = v.val;
                res->val_len = v.val_len;
            }
            return 0;
        }
        if (v.kind == EVM_TRIE_NODE_EXT) {
            if (memcmp(v.nib, nibs + depth, v.nlen) != 0)
                return 0;     /* mismatching extension: absent, child unread */
            depth += v.nlen;
            ci = 0;
            eb = 1;
        } else {
            ci = nibs[depth];
            depth += 1;
            eb = 0;
        }
        if (v.child[ci].kind == EVM_TRIE_CHILD_NONE)
            return 0;                                    /* nil child: absent */
        if (v.child[ci].kind == EVM_TRIE_CHILD_HASH) {
            memcpy(dig, v.child[ci].p, 64);
            embedded = 0;
            size_class = EVM_TRIE_NODE_HASHED;
        } else {
            cur = v.child[ci].p;
            clen = v.child[ci].len;
            embedded = 1;
            size_class = EVM_TRIE_NODE_EMBEDDED;
        }
    }
}

/* ── prove ──────────────────────────────────────────────────────────── */

typedef struct {
    const evm_trie_store_t *store;
    evm_trie_proof_set_t   *set;
} prove_ctx_t;

static int set_add(evm_trie_proof_set_t *s, const uint8_t digest[64],
                   uint8_t *rlp, size_t len)
{
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 64;
        evm_trie_proof_node_t *nv = realloc(s->v, nc * sizeof(*nv));
        if (!nv) return -2;
        s->v = nv;
        s->cap = nc;
    }
    memcpy(s->v[s->n].digest, digest, 64);
    s->v[s->n].rlp = rlp;
    s->v[s->n].len = len;
    s->n++;
    return 0;
}

static int prove_fetch(void *ctx, const uint8_t digest[64],
                       const uint8_t **rlp, size_t *len)
{
    prove_ctx_t *pc = ctx;
    uint8_t *buf = NULL;
    size_t n = 0;
    uint8_t d[64];
    int grc = pc->store->get(pc->store->ctx, digest, &buf, &n);
    if (grc != 0 || !buf || n == 0) {
        if (grc == 0) free(buf);
        return -2;
    }
    if (n > EVM_TRIE_PROOF_NODE_MAX_BYTES || h512(buf, n, d) != 0 ||
        memcmp(d, digest, 64) != 0) {
        free(buf);
        return -2;
    }
    /* the root always; any other node reached through a reference is
     * >= 64 bytes (checked by the walker's size class) */
    if (set_add(pc->set, digest, buf, n) != 0) {
        free(buf);
        return -2;
    }
    *rlp = buf;
    *len = n;
    return 0;
}

int evm_trie_prove_path(const evm_trie_store_t *store,
                        const uint8_t root[EVM_TRIE_DIGEST_LEN],
                        const uint8_t path[EVM_TRIE_PATH_LEN],
                        evm_trie_proof_set_t *set)
{
    evm_trie_proof_result_t r;
    prove_ctx_t pc;
    if (!store || !store->get || !root || !path || !set) return -1;
    pc.store = store;
    pc.set = set;
    return walk(prove_fetch, &pc, root, path, &r);
}

static int digest_cmp(const void *a, const void *b)
{
    return memcmp(((const evm_trie_proof_node_t *)a)->digest,
                  ((const evm_trie_proof_node_t *)b)->digest, 64);
}

int evm_trie_proof_set_finish(evm_trie_proof_set_t *s)
{
    if (!s) return -2;
    if (s->n > 1) qsort(s->v, s->n, sizeof(*s->v), digest_cmp);
    size_t w = 0;
    for (size_t i = 0; i < s->n; i++) {
        if (w > 0 && memcmp(s->v[w - 1].digest, s->v[i].digest, 64) == 0) {
            free(s->v[i].rlp);                  /* the same digest, the same
                                                 * bytes (verified on load) */
            continue;
        }
        s->v[w++] = s->v[i];
    }
    s->n = w;
    return 0;
}

/* ── verify ─────────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *const *nodes;
    const size_t         *lens;
    uint8_t             (*dig)[64];      /* the verifier's own digests */
    size_t                n;
} bundle_t;

static int bundle_fetch(void *ctx, const uint8_t digest[64],
                        const uint8_t **rlp, size_t *len)
{
    const bundle_t *b = ctx;
    size_t lo = 0, hi = b->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(b->dig[mid], digest, 64);
        if (c == 0) {
            *rlp = b->nodes[mid];
            *len = b->lens[mid];
            return 0;
        }
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -2;
}

int evm_trie_proof_verify_batch(const uint8_t root[EVM_TRIE_DIGEST_LEN],
                                const uint8_t *const *nodes,
                                const size_t *node_lens, size_t n_nodes,
                                const uint8_t (*paths)[EVM_TRIE_PATH_LEN],
                                size_t n_keys, evm_trie_proof_result_t *res)
{
    if (!root || !paths || !res || (n_nodes && (!nodes || !node_lens)))
        return -1;
    if (n_keys == 0 || n_keys > EVM_TRIE_PROOF_MAX_KEYS ||
        n_nodes > EVM_TRIE_PROOF_MAX_NODES)
        return -1;
    for (size_t i = 0; i < n_nodes; i++)
        if (!nodes[i] || node_lens[i] == 0 ||
            node_lens[i] > EVM_TRIE_PROOF_NODE_MAX_BYTES)
            return -1;
    for (size_t i = 0; i < n_keys; i++)
        for (size_t j = i + 1; j < n_keys; j++)
            if (memcmp(paths[i], paths[j], EVM_TRIE_PATH_LEN) == 0)
                return -1;                       /* a duplicate key */

    uint8_t empty[64];
    if (evm_trie_empty_root(empty) != 0) return -2;
    if (memcmp(root, empty, 64) == 0) {
        if (n_nodes != 0) return -2;             /* empty leg: empty bundle */
        for (size_t i = 0; i < n_keys; i++) memset(&res[i], 0, sizeof(res[i]));
        return 0;
    }

    bundle_t b;
    b.nodes = nodes;
    b.lens = node_lens;
    b.n = n_nodes;
    b.dig = n_nodes ? malloc(n_nodes * sizeof(*b.dig)) : NULL;
    if (n_nodes && !b.dig) return -2;
    int rc = 0;
    for (size_t i = 0; i < n_nodes && rc == 0; i++) {
        if (h512(nodes[i], node_lens[i], b.dig[i]) != 0) rc = -2;
        /* strictly ascending by the verifier's digest: unique and ordered */
        else if (i > 0 && memcmp(b.dig[i - 1], b.dig[i], 64) >= 0) rc = -2;
    }
    for (size_t i = 0; i < n_keys && rc == 0; i++)
        rc = walk(bundle_fetch, &b, root, paths[i], &res[i]);
    free(b.dig);
    return rc;
}
