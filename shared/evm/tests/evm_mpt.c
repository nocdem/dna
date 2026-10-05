/**
 * @file evm_mpt.c
 * @brief Ethereum Merkle Patricia Trie root — TEST-ONLY. See evm_mpt.h.
 */
#include "evm_mpt.h"
#include "evm_rlp.h"
#include "crypto/hash/keccak256.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *key;      /* raw key, or points into the hashed-key pool */
    size_t         key_len;  /* bytes; nibble length is 2 * key_len         */
    const uint8_t *val;
    size_t         val_len;
} leaf_t;

static unsigned nib(const leaf_t *l, size_t i)
{
    uint8_t b = l->key[i / 2];
    return (i % 2 == 0) ? (unsigned)(b >> 4) : (unsigned)(b & 0x0f);
}

static int leaf_cmp(const void *a, const void *b)
{
    const leaf_t *x = a, *y = b;
    size_t m = x->key_len < y->key_len ? x->key_len : y->key_len;
    int c = m ? memcmp(x->key, y->key, m) : 0;
    if (c != 0) return c;
    if (x->key_len < y->key_len) return -1;
    if (x->key_len > y->key_len) return 1;
    return 0;
}

/* nibble_list_to_compact (merkle_patricia_trie.py:360-392) over the
 * nibbles [from, to) of leaf l, written as an RLP string into out. */
static int put_compact(evm_rlp_buf *out, const leaf_t *l, size_t from,
                       size_t to, int is_leaf)
{
    size_t n = to - from;
    uint8_t tmp[1 + 64];
    uint8_t *c = tmp;
    uint8_t *heap = NULL;
    size_t clen = 1 + n / 2;
    if (clen > sizeof(tmp)) {
        heap = malloc(clen);
        if (!heap) return -2;
        c = heap;
    }
    size_t k = 0;
    size_t i = from;
    if (n % 2 == 0) {
        c[k++] = (uint8_t)(16 * (2 * is_leaf));
    } else {
        c[k++] = (uint8_t)(16 * (2 * is_leaf + 1) + nib(l, i));
        i++;
    }
    for (; i < to; i += 2)
        c[k++] = (uint8_t)(16 * nib(l, i) + nib(l, i + 1));
    int rc = evm_rlp_put_bytes(out, c, k);
    free(heap);
    return rc;
}

static int node_rlp(const leaf_t *lv, size_t lo, size_t hi, size_t level,
                    evm_rlp_buf *out);

/* Append the reference a parent holds for the subtree [lo, hi) at `level`
 * (encode_internal_node, merkle_patricia_trie.py:213-249). */
static int put_child_ref(const leaf_t *lv, size_t lo, size_t hi,
                         size_t level, evm_rlp_buf *out)
{
    if (lo == hi) return evm_rlp_put_bytes(out, NULL, 0); /* b"" */
    evm_rlp_buf node = {0};
    int rc = node_rlp(lv, lo, hi, level, &node);
    if (rc == 0) {
        if (node.len < 32) {
            rc = evm_rlp_put_raw(out, node.p, node.len);
        } else {
            uint8_t h[32];
            if (keccak256(node.p, node.len, h) != 0) rc = -2;
            else rc = evm_rlp_put_bytes(out, h, 32);
        }
    }
    evm_rlp_buf_free(&node);
    return rc;
}

/* RLP of the node patricialize() builds for [lo, hi) at `level`
 * (merkle_patricia_trie.py:507-581). Requires hi > lo. */
static int node_rlp(const leaf_t *lv, size_t lo, size_t hi, size_t level,
                    evm_rlp_buf *out)
{
    size_t start = out->len;
    int rc;

    if (hi - lo == 1) {                               /* leaf */
        const leaf_t *l = &lv[lo];
        if ((rc = put_compact(out, l, level, 2 * l->key_len, 1)) != 0)
            return rc;
        if ((rc = evm_rlp_put_bytes(out, l->val, l->val_len)) != 0)
            return rc;
        return evm_rlp_wrap_list(out, start);
    }

    /* Sorted: the common prefix of the whole range is that of its first
     * and last key. */
    const leaf_t *a = &lv[lo], *b = &lv[hi - 1];
    size_t an = 2 * a->key_len, bn = 2 * b->key_len;
    size_t p = 0;
    while (level + p < an && level + p < bn &&
           nib(a, level + p) == nib(b, level + p))
        p++;

    if (p > 0) {                                      /* extension */
        if ((rc = put_compact(out, a, level, level + p, 0)) != 0) return rc;
        if ((rc = put_child_ref(lv, lo, hi, level + p, out)) != 0) return rc;
        return evm_rlp_wrap_list(out, start);
    }

    /* branch: a key ending exactly here sorts first (it is a prefix of
     * every other key in the range); the rest group by nibble `level`
     * into contiguous sub-ranges. */
    size_t i = lo;
    const leaf_t *value = NULL;
    if (2 * lv[i].key_len == level) {
        value = &lv[i];
        i++;
    }
    for (unsigned k = 0; k < 16; k++) {
        size_t j = i;
        while (j < hi && nib(&lv[j], level) == k) j++;
        if ((rc = put_child_ref(lv, i, j, level + 1, out)) != 0) return rc;
        i = j;
    }
    if (i != hi) return -1;                           /* unreachable if sorted */
    if (value) rc = evm_rlp_put_bytes(out, value->val, value->val_len);
    else       rc = evm_rlp_put_bytes(out, NULL, 0);
    if (rc != 0) return rc;
    return evm_rlp_wrap_list(out, start);
}

int evm_mpt_root(const evm_mpt_kv *kvs, size_t n, int secured,
                 uint8_t root[32])
{
    if (n == 0) {
        const uint8_t empty = 0x80;                   /* rlp(b"") */
        return keccak256(&empty, 1, root) == 0 ? 0 : -2;
    }
    if (n > SIZE_MAX / sizeof(leaf_t) || n > SIZE_MAX / 32) return -2;

    leaf_t  *lv   = malloc(n * sizeof(leaf_t));
    uint8_t *pool = secured ? malloc(n * 32) : NULL;
    int rc = 0;
    if (!lv || (secured && !pool)) { rc = -2; goto out; }

    for (size_t i = 0; i < n; i++) {
        if (kvs[i].val_len == 0) { rc = -1; goto out; }
        lv[i].val = kvs[i].val;
        lv[i].val_len = kvs[i].val_len;
        if (secured) {
            if (keccak256(kvs[i].key, kvs[i].key_len, pool + 32 * i) != 0) {
                rc = -2;
                goto out;
            }
            lv[i].key = pool + 32 * i;
            lv[i].key_len = 32;
        } else {
            lv[i].key = kvs[i].key;
            lv[i].key_len = kvs[i].key_len;
        }
    }
    qsort(lv, n, sizeof(leaf_t), leaf_cmp);
    for (size_t i = 1; i < n; i++)
        if (leaf_cmp(&lv[i - 1], &lv[i]) == 0) { rc = -1; goto out; }

    {
        evm_rlp_buf node = {0};
        rc = node_rlp(lv, 0, n, 0, &node);
        if (rc == 0 && keccak256(node.p, node.len, root) != 0) rc = -2;
        evm_rlp_buf_free(&node);
    }
out:
    free(pool);
    free(lv);
    return rc;
}
