/**
 * @file evm_trie_full.c
 * @brief Full-rebuild MPT root — TEST-ONLY straight port of the reference.
 *        See evm_trie_full.h.
 *
 * Each function below mirrors one reference function (line numbers in
 * execution-specs @a87891f7 src/ethereum/merkle_patricia_trie.py). Where
 * the reference returns an "Extended" (an unencoded node or a digest), this
 * port appends that item's RLP to the parent's buffer instead — the same
 * bytes `rlp.encode` would write for it inside the parent.
 */
#include "evm_trie_full.h"
#include "evm_trie_rlp.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/keccak256.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t       *nib;      /* nibble key (bytes_to_nibble_list) */
    size_t         nlen;
    const uint8_t *val;
    size_t         val_len;
} ent;

typedef struct {
    evm_trie_full_hash h;
    size_t             dl;   /* digest length = inline threshold */
} fctx;

size_t evm_trie_full_digest_len(evm_trie_full_hash h)
{
    return h == EVM_TRIE_FULL_KECCAK256 ? 32 : 64;
}

static int hashf(const fctx *c, const uint8_t *p, size_t len, uint8_t *out)
{
    static const uint8_t none = 0;
    if (!len) p = &none;
    if (c->h == EVM_TRIE_FULL_KECCAK256)
        return keccak256(p, len, out) == 0 ? 0 : -2;
    return qgp_sha3_512(p, len, out) == 0 ? 0 : -2;
}

/* common_prefix_length :350-357 */
static size_t common_prefix_length(const uint8_t *a, size_t alen,
                                   const uint8_t *b, size_t blen)
{
    for (size_t i = 0; i < alen; i++)
        if (i >= blen || a[i] != b[i]) return i;
    return alen;
}

/* nibble_list_to_compact :360-392, appended as an RLP string */
static int nibble_list_to_compact(evm_trie_rlp_buf *out, const uint8_t *x,
                                  size_t n, int is_leaf)
{
    uint8_t *c = malloc(1 + n / 2);
    if (!c) return -2;
    size_t k = 0;
    if (n % 2 == 0) {
        c[k++] = (uint8_t)(16 * (2 * is_leaf));
        for (size_t i = 0; i < n; i += 2)
            c[k++] = (uint8_t)(16 * x[i] + x[i + 1]);
    } else {
        c[k++] = (uint8_t)(16 * ((2 * is_leaf) + 1) + x[0]);
        for (size_t i = 1; i < n; i += 2)
            c[k++] = (uint8_t)(16 * x[i] + x[i + 1]);
    }
    int rc = evm_trie_rlp_put_bytes(out, c, k);
    free(c);
    return rc;
}

static int patricialize(const fctx *c, ent **obj, size_t n, size_t level,
                        evm_trie_rlp_buf *node, int *is_none);

/* encode_internal_node :213-249 applied to patricialize(obj, level), with
 * the result appended to `out` as the parent stores it: None -> b"";
 * an encoding < threshold -> embedded as-is; otherwise its digest. */
static int put_subnode(const fctx *c, ent **obj, size_t n, size_t level,
                       evm_trie_rlp_buf *out)
{
    evm_trie_rlp_buf node = {0};
    int is_none = 0;
    int rc = patricialize(c, obj, n, level, &node, &is_none);
    if (rc == 0) {
        if (is_none) {
            rc = evm_trie_rlp_put_bytes(out, NULL, 0);           /* :228-229 */
        } else if (node.len < c->dl) {
            rc = evm_trie_rlp_put_raw(out, node.p, node.len);    /* :246-247 */
        } else {
            uint8_t d[64];
            rc = hashf(c, node.p, node.len, d);                  /* :248-249 */
            if (rc == 0) rc = evm_trie_rlp_put_bytes(out, d, c->dl);
        }
    }
    evm_trie_rlp_buf_free(&node);
    return rc;
}

/* patricialize :507-581 — writes the RLP of the node it builds (the
 * `rlp.encode(unencoded)` of encode_internal_node :245) into `node`. */
static int patricialize(const fctx *c, ent **obj, size_t n, size_t level,
                        evm_trie_rlp_buf *node, int *is_none)
{
    int rc;
    *is_none = 0;
    if (n == 0) {                                                /* :531-532 */
        *is_none = 1;
        return 0;
    }
    const ent *arbitrary_key = obj[0];                           /* :534 */

    if (n == 1) {                                                /* :537-539 */
        if ((rc = nibble_list_to_compact(node, arbitrary_key->nib + level,
                                         arbitrary_key->nlen - level, 1)) != 0)
            return rc;
        if ((rc = evm_trie_rlp_put_bytes(node, arbitrary_key->val,
                                         arbitrary_key->val_len)) != 0)
            return rc;
        return evm_trie_rlp_wrap_list(node, 0) == 0 ? 0 : -2;
    }

    /* :543-552 */
    const uint8_t *substring = arbitrary_key->nib + level;
    size_t sublen = arbitrary_key->nlen - level;
    size_t prefix_length = sublen;
    for (size_t i = 0; i < n; i++) {
        size_t l = common_prefix_length(substring, sublen,
                                        obj[i]->nib + level,
                                        obj[i]->nlen - level);
        if (l < prefix_length) prefix_length = l;
        if (prefix_length == 0) break;
    }

    if (prefix_length > 0) {                                     /* :555-562 */
        if ((rc = nibble_list_to_compact(node, substring, prefix_length, 0))
            != 0)
            return rc;
        if ((rc = put_subnode(c, obj, n, level + prefix_length, node)) != 0)
            return rc;
        return evm_trie_rlp_wrap_list(node, 0) == 0 ? 0 : -2;
    }

    /* :564-572 — partition by the next nibble, keeping input order */
    ent **sorted = malloc(n * sizeof(*sorted));
    if (!sorted) return -2;
    size_t count[16] = {0}, off[16];
    const ent *value = NULL;
    for (size_t i = 0; i < n; i++) {
        if (obj[i]->nlen == level) value = obj[i];
        else count[obj[i]->nib[level]]++;
    }
    size_t acc = 0;
    for (int k = 0; k < 16; k++) { off[k] = acc; acc += count[k]; }
    size_t pos[16];
    memcpy(pos, off, sizeof(pos));
    for (size_t i = 0; i < n; i++)
        if (obj[i]->nlen != level) sorted[pos[obj[i]->nib[level]]++] = obj[i];

    rc = 0;
    for (int k = 0; k < 16 && rc == 0; k++)                      /* :574-577 */
        rc = put_subnode(c, sorted + off[k], count[k], level + 1, node);
    if (rc == 0) {                                               /* :578-581 */
        if (value) rc = evm_trie_rlp_put_bytes(node, value->val, value->val_len);
        else       rc = evm_trie_rlp_put_bytes(node, NULL, 0);
    }
    if (rc == 0 && evm_trie_rlp_wrap_list(node, 0) != 0) rc = -2;
    free(sorted);
    return rc;
}

static int ent_cmp(const void *a, const void *b)
{
    const ent *x = *(const ent *const *)a, *y = *(const ent *const *)b;
    size_t m = x->nlen < y->nlen ? x->nlen : y->nlen;
    int r = m ? memcmp(x->nib, y->nib, m) : 0;
    if (r != 0) return r;
    return (x->nlen > y->nlen) - (x->nlen < y->nlen);
}

int evm_trie_full_root(const evm_trie_full_kv *kvs, size_t n, int secured,
                       evm_trie_full_hash h, uint8_t *root)
{
    if (!root || (n && !kvs)) return -1;
    if (h != EVM_TRIE_FULL_SHA3_512 && h != EVM_TRIE_FULL_KECCAK256) return -1;
    fctx c = { h, evm_trie_full_digest_len(h) };

    if (n > SIZE_MAX / sizeof(ent)) return -2;
    ent *ents = calloc(n ? n : 1, sizeof(ent));
    ent **obj = calloc(n ? n : 1, sizeof(ent *));
    ent **chk = calloc(n ? n : 1, sizeof(ent *));
    int rc = 0;
    if (!ents || !obj || !chk) { rc = -2; goto out; }

    /* _prepare_data :427-448 */
    for (size_t i = 0; i < n; i++) {
        if (kvs[i].val_len == 0 || !kvs[i].val) { rc = -1; goto out; }
        uint8_t d[64];
        const uint8_t *key = kvs[i].key;
        size_t klen = kvs[i].key_len;
        if (klen && !key) { rc = -1; goto out; }
        if (secured) {                                           /* :441-443 */
            if ((rc = hashf(&c, key, klen, d)) != 0) goto out;
            key = d;
            klen = c.dl;
        }
        if (klen > (SIZE_MAX - 1) / 2) { rc = -2; goto out; }
        ents[i].nib = malloc(2 * klen + 1);
        if (!ents[i].nib) { rc = -2; goto out; }
        for (size_t b = 0; b < klen; b++) {                      /* :400-404 */
            ents[i].nib[2 * b]     = (uint8_t)((key[b] & 0xF0) >> 4);
            ents[i].nib[2 * b + 1] = (uint8_t)(key[b] & 0x0F);
        }
        ents[i].nlen = 2 * klen;
        ents[i].val = kvs[i].val;
        ents[i].val_len = kvs[i].val_len;
        obj[i] = &ents[i];
        chk[i] = &ents[i];
    }

    /* the reference's dict cannot hold a key twice; refuse duplicates
     * (a sorted copy, used for this check only) */
    if (n > 1) {
        qsort(chk, n, sizeof(*chk), ent_cmp);
        for (size_t i = 1; i < n; i++)
            if (ent_cmp(&chk[i - 1], &chk[i]) == 0) { rc = -1; goto out; }
    }

    /* root :497-504: root_node = encode_internal_node(patricialize(obj, 0));
     * under both arms the result is H(RLP(root node)); for no keys the
     * root node is b"" and RLP(b"") = 0x80 (EMPTY_TRIE_ROOT :71-75). */
    {
        evm_trie_rlp_buf node = {0};
        int is_none = 0;
        rc = patricialize(&c, obj, n, 0, &node, &is_none);
        if (rc == 0) {
            if (is_none) {
                const uint8_t empty = 0x80;
                rc = hashf(&c, &empty, 1, root);
            } else {
                rc = hashf(&c, node.p, node.len, root);
            }
        }
        evm_trie_rlp_buf_free(&node);
    }
out:
    if (ents)
        for (size_t i = 0; i < n; i++) free(ents[i].nib);
    free(chk);
    free(obj);
    free(ents);
    return rc;
}
