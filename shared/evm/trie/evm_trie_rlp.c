/**
 * @file evm_trie_rlp.c
 * @brief Minimal RLP encoder/decoder for the Nodus EVM state trie. See
 *        evm_trie_rlp.h.
 */
#include "evm_trie_rlp.h"

#include <stdlib.h>
#include <string.h>

void evm_trie_rlp_buf_free(evm_trie_rlp_buf *b)
{
    if (!b) return;
    free(b->p);
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

static int buf_reserve(evm_trie_rlp_buf *b, size_t extra)
{
    if (extra > SIZE_MAX - b->len) return -2;
    size_t need = b->len + extra;
    if (need <= b->cap) return 0;
    size_t ncap = b->cap ? b->cap : 128;
    while (ncap < need) {
        if (ncap > SIZE_MAX / 2) { ncap = need; break; }
        ncap *= 2;
    }
    uint8_t *np = realloc(b->p, ncap);
    if (!np) return -2;
    b->p = np;
    b->cap = ncap;
    return 0;
}

int evm_trie_rlp_put_raw(evm_trie_rlp_buf *b, const uint8_t *data, size_t len)
{
    if (len == 0) return 0;
    if (buf_reserve(b, len) != 0) return -2;
    memcpy(b->p + b->len, data, len);
    b->len += len;
    return 0;
}

/* Header for a payload of `len` bytes with short-form base `base`
 * (0x80 strings, 0xc0 lists). Writes into hdr (max 9 bytes). */
static size_t make_header(uint8_t hdr[9], uint8_t base, size_t len)
{
    if (len <= 55) {
        hdr[0] = (uint8_t)(base + len);
        return 1;
    }
    uint8_t lb[8];
    size_t n = 0;
    uint64_t v = (uint64_t)len;
    while (v) {
        lb[n++] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    hdr[0] = (uint8_t)(base + 55 + n);
    for (size_t i = 0; i < n; i++) hdr[1 + i] = lb[n - 1 - i];
    return 1 + n;
}

int evm_trie_rlp_put_bytes(evm_trie_rlp_buf *b, const uint8_t *data,
                           size_t len)
{
    if (len == 1 && data[0] < 0x80) return evm_trie_rlp_put_raw(b, data, 1);
    uint8_t hdr[9];
    size_t hl = make_header(hdr, 0x80, len);
    if (evm_trie_rlp_put_raw(b, hdr, hl) != 0) return -2;
    return evm_trie_rlp_put_raw(b, data, len);
}

int evm_trie_rlp_wrap_list(evm_trie_rlp_buf *b, size_t start)
{
    if (start > b->len) return -1;
    size_t plen = b->len - start;
    uint8_t hdr[9];
    size_t hl = make_header(hdr, 0xc0, plen);
    if (buf_reserve(b, hl) != 0) return -2;
    memmove(b->p + start + hl, b->p + start, plen);
    memcpy(b->p + start, hdr, hl);
    b->len += hl;
    return 0;
}

/* Read a big-endian long-form length of n bytes (1..8), canonical. */
static int read_long_len(const uint8_t *p, size_t n, size_t *out)
{
    if (n == 0 || n > 8 || p[0] == 0) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | p[i];
    if (v <= 55) return -1;
    if (v > (uint64_t)SIZE_MAX) return -1;
    *out = (size_t)v;
    return 0;
}

int evm_trie_rlp_decode_item(const uint8_t *in, size_t in_len,
                             evm_trie_rlp_item *out)
{
    if (!in || in_len == 0) return -1;
    uint8_t h = in[0];
    size_t hl, len;
    int is_list;
    if (h < 0x80) {
        out->is_list = 0;
        out->payload = in;
        out->len = 1;
        out->total = 1;
        return 0;
    } else if (h <= 0xb7) {
        is_list = 0; hl = 1; len = (size_t)(h - 0x80);
    } else if (h < 0xc0) {
        is_list = 0;
        size_t n = (size_t)(h - 0xb7);
        if (in_len < 1 + n || read_long_len(in + 1, n, &len) != 0) return -1;
        hl = 1 + n;
    } else if (h <= 0xf7) {
        is_list = 1; hl = 1; len = (size_t)(h - 0xc0);
    } else {
        is_list = 1;
        size_t n = (size_t)(h - 0xf7);
        if (in_len < 1 + n || read_long_len(in + 1, n, &len) != 0) return -1;
        hl = 1 + n;
    }
    if (len > in_len - hl) return -1;
    /* canonical: a single byte < 0x80 must be encoded as itself */
    if (!is_list && hl == 1 && len == 1 && in[1] < 0x80) return -1;
    out->is_list = is_list;
    out->payload = in + hl;
    out->len = len;
    out->total = hl + len;
    return 0;
}
