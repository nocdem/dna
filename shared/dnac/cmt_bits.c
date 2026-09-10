/**
 * @file shared/dnac/cmt_bits.c
 * @brief cometbft @709fd12b `libs/bits.BitArray` ported to C — see cmt_bits.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_bits.h"

#include <string.h>

#include "crypto/utils/qgp_random.h"

/* ── local helpers (no Go counterpart; they exist because C lacks what
 *    Go provides implicitly) ─────────────────────────────────────────── */

/* Go evaluates `uint64(1) << 64` as 0 (the spec defines an over-wide shift
 * as zero); in C that shift is undefined behaviour. Every place the
 * reference relies on it goes through here. */
static uint64_t cmt_bits_low_mask(unsigned n)
{
    if (n >= 64) {
        return ~(uint64_t)0;
    }
    return ((uint64_t)1 << n) - 1;
}

/* Go's math/bits.OnesCount64, written out. */
static int cmt_bits_ones_count64(uint64_t v)
{
    int c = 0;

    while (v != 0) {
        v &= v - 1;
        c++;
    }
    return c;
}

/* cometbft@709fd12b libs/bits/bit_array.go:31, :44, :124 — (bits+63)/64 */
size_t cmt_bits_num_elems(int bits)
{
    if (bits <= 0) {
        return 0;
    }
    return ((size_t)bits + 63u) / 64u;
}

/* ── constructors ───────────────────────────────────────────────────── */

/* cometbft@709fd12b libs/bits/bit_array.go:25-33 — NewBitArray() */
int cmt_bits_new(cmt_bit_array_t *ba, int bits)
{
    if (ba == NULL) {
        return CMT_FAULT;
    }
    memset(ba, 0, sizeof(*ba));
    if (bits <= 0) {
        return CMT_BITS_NIL;                         /* :26-28 returns nil */
    }
    if (bits > CMT_BITS_MAX_BITS) {
        return CMT_REJECT;                           /* derived bound */
    }
    ba->bits    = bits;
    ba->n_elems = cmt_bits_num_elems(bits);          /* :31 */
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:38-53 — NewBitArrayFromFn() */
int cmt_bits_new_from_fn(cmt_bit_array_t *ba, int bits,
                         bool (*fn)(int i, void *ctx), void *ctx)
{
    int i;
    int rc;

    if (fn == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_bits_new(ba, bits);
    if (rc != CMT_OK) {
        return rc;                                   /* :39-41 nil */
    }
    for (i = 0; i < bits; i++) {                     /* :46-51 */
        if (fn(i, ctx)) {
            ba->elems[(size_t)i / 64u] |=
                ((uint64_t)1 << (unsigned)((size_t)i % 64u));
        }
    }
    return CMT_OK;
}

/* ── accessors ──────────────────────────────────────────────────────── */

/* cometbft@709fd12b libs/bits/bit_array.go:56-61 — Size() */
int cmt_bits_size(const cmt_bit_array_t *ba)
{
    if (ba == NULL) {
        return 0;                                    /* :57-59 */
    }
    return ba->bits;
}

/* cometbft@709fd12b libs/bits/bit_array.go:65-72 GetIndex(), :74-79 getIndex() */
int cmt_bits_get_index(const cmt_bit_array_t *ba, int i)
{
    size_t w;

    if (ba == NULL) {
        return 0;                                    /* :66-68 */
    }
    if (i < 0) {
        return CMT_FAULT;    /* Go: negative subscript panic */
    }
    if (i >= ba->bits) {
        return 0;                                    /* :75-77 */
    }
    w = (size_t)i / 64u;
    if (w >= ba->n_elems) {
        return CMT_FAULT;    /* i < bits but the words are missing */
    }
    return (ba->elems[w] & ((uint64_t)1 << (unsigned)((size_t)i % 64u))) != 0
           ? 1 : 0;                                  /* :78 */
}

/* cometbft@709fd12b libs/bits/bit_array.go:83-90 SetIndex(), :92-102 setIndex() */
int cmt_bits_set_index(cmt_bit_array_t *ba, int i, bool v)
{
    size_t   w;
    uint64_t bit;

    if (ba == NULL) {
        return 0;                                    /* :84-86 */
    }
    if (i < 0) {
        return CMT_FAULT;
    }
    if (i >= ba->bits) {
        return 0;                                    /* :93-95 */
    }
    w = (size_t)i / 64u;
    if (w >= ba->n_elems) {
        return CMT_FAULT;
    }
    bit = (uint64_t)1 << (unsigned)((size_t)i % 64u);
    if (v) {
        ba->elems[w] |= bit;                         /* :96-97 */
    } else {
        ba->elems[w] &= ~bit;                        /* :98-99 */
    }
    return 1;                                        /* :101 */
}

/* ── combinators ────────────────────────────────────────────────────── */

/* cometbft@709fd12b libs/bits/bit_array.go:105-112 Copy(), :114-121 copy() */
int cmt_bits_copy(const cmt_bit_array_t *ba, cmt_bit_array_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    if (ba == NULL) {
        return CMT_BITS_NIL;                         /* :106-108 */
    }
    if (ba->n_elems > CMT_BITS_MAX_ELEMS) {
        return CMT_FAULT;
    }
    out->bits    = ba->bits;                         /* :117-120 */
    out->n_elems = ba->n_elems;
    memcpy(out->elems, ba->elems, ba->n_elems * sizeof(uint64_t));
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:123-130 — copyBits() */
int cmt_bits_copy_bits(const cmt_bit_array_t *ba, int bits,
                       cmt_bit_array_t *out)
{
    size_t want;
    size_t n;

    if (out == NULL || ba == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    if (bits < 0 || bits > CMT_BITS_MAX_BITS) {
        return CMT_REJECT;
    }
    want = cmt_bits_num_elems(bits);                 /* :124 */
    /* Go's copy(dst, src) moves min(len(dst), len(src)) words (:125). */
    n = (want < ba->n_elems) ? want : ba->n_elems;
    if (n > CMT_BITS_MAX_ELEMS) {
        return CMT_FAULT;
    }
    out->bits    = bits;                             /* :126-129 */
    out->n_elems = want;
    if (n != 0) {
        memcpy(out->elems, ba->elems, n * sizeof(uint64_t));
    }
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:135-155 — Or() */
int cmt_bits_or(const cmt_bit_array_t *ba, const cmt_bit_array_t *o,
                cmt_bit_array_t *out)
{
    size_t smaller;
    size_t i;
    int    max_bits;
    int    rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (ba == NULL && o == NULL) {
        memset(out, 0, sizeof(*out));
        return CMT_BITS_NIL;                         /* :136-138 */
    }
    if (ba == NULL) {
        return cmt_bits_copy(o, out);                /* :139-141 */
    }
    if (o == NULL) {
        return cmt_bits_copy(ba, out);               /* :142-144 */
    }
    max_bits = (ba->bits > o->bits) ? ba->bits : o->bits;
    rc = cmt_bits_copy_bits(ba, max_bits, out);      /* :147 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* NOTE reference quirk (:148-151): only min(len(ba), len(o)) words are
     * ORed, so when `o` is the wider array its high words never reach the
     * result even though the result is wide enough to hold them. */
    smaller = (ba->n_elems < o->n_elems) ? ba->n_elems : o->n_elems;
    for (i = 0; i < smaller && i < out->n_elems; i++) {
        out->elems[i] |= o->elems[i];
    }
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:160-171 And(), :173-179 and() */
int cmt_bits_and(const cmt_bit_array_t *ba, const cmt_bit_array_t *o,
                 cmt_bit_array_t *out)
{
    size_t i;
    int    min_bits;
    int    rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (ba == NULL || o == NULL) {
        memset(out, 0, sizeof(*out));
        return CMT_BITS_NIL;                         /* :161-163 */
    }
    min_bits = (ba->bits < o->bits) ? ba->bits : o->bits;
    rc = cmt_bits_copy_bits(ba, min_bits, out);      /* :174 */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < out->n_elems; i++) {             /* :175-177 */
        /* len(c.Elems) <= len(o.Elems) holds because c is min-width, but
         * a wire-built `o` could be inconsistent; check it (INVARIANT). */
        if (i >= o->n_elems) {
            return CMT_FAULT;
        }
        out->elems[i] &= o->elems[i];
    }
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:182-189 Not(), :191-197 not() */
int cmt_bits_not(const cmt_bit_array_t *ba, cmt_bit_array_t *out)
{
    size_t i;
    int    rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (ba == NULL) {
        memset(out, 0, sizeof(*out));
        return CMT_BITS_NIL;                         /* :183-185 */
    }
    rc = cmt_bits_copy(ba, out);                     /* :192 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :193-195 complements whole words, padding included. */
    for (i = 0; i < out->n_elems; i++) {
        out->elems[i] = ~out->elems[i];
    }
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:203-224 — Sub() */
int cmt_bits_sub(const cmt_bit_array_t *ba, const cmt_bit_array_t *o,
                 cmt_bit_array_t *out)
{
    size_t smaller;
    size_t i;
    int    rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (ba == NULL || o == NULL) {
        memset(out, 0, sizeof(*out));
        return CMT_BITS_NIL;                         /* :204-207 */
    }
    rc = cmt_bits_copy_bits(ba, ba->bits, out);      /* :211 */
    if (rc != CMT_OK) {
        return rc;
    }
    smaller = (ba->n_elems < o->n_elems) ? ba->n_elems : o->n_elems;
    for (i = 0; i < smaller && i < out->n_elems; i++) {   /* :217-220 */
        out->elems[i] &= ~o->elems[i];               /* Go's &^= */
    }
    return CMT_OK;
}

/* ── predicates ─────────────────────────────────────────────────────── */

/* cometbft@709fd12b libs/bits/bit_array.go:227-239 — IsEmpty() */
int cmt_bits_is_empty(const cmt_bit_array_t *ba)
{
    size_t i;

    if (ba == NULL) {
        return 1;                                    /* :228-230 */
    }
    for (i = 0; i < ba->n_elems; i++) {              /* :233-237 */
        if (ba->elems[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* cometbft@709fd12b libs/bits/bit_array.go:242-260 — IsFull() */
int cmt_bits_is_full(const cmt_bit_array_t *ba)
{
    size_t   i;
    unsigned last_elem_bits;
    uint64_t last;

    if (ba == NULL) {
        return 1;                                    /* :243-245 */
    }
    if (ba->n_elems == 0 || ba->n_elems > CMT_BITS_MAX_ELEMS) {
        /* Go slices from the end at :250 / :258 and panics here. */
        return CMT_FAULT;
    }
    for (i = 0; i + 1 < ba->n_elems; i++) {          /* :250-254 */
        if (~ba->elems[i] != 0) {
            return 0;
        }
    }
    /* :257 lastElemBits := (Bits+63)%64 + 1 — for Bits a multiple of 64
     * this is 64, and :259's `1 << 64` is 0 in Go, which makes the mask
     * all-ones. cmt_bits_low_mask reproduces that without UB. */
    last_elem_bits = (unsigned)((((unsigned)ba->bits + 63u) % 64u) + 1u);
    last = ba->elems[ba->n_elems - 1];               /* :258 */
    return ((last + 1u) & cmt_bits_low_mask(last_elem_bits)) == 0 ? 1 : 0;
}

/* ── population ─────────────────────────────────────────────────────── */

/* cometbft@709fd12b libs/bits/bit_array.go:284-299 — getNumTrueIndices() */
int cmt_bits_get_num_true_indices(const cmt_bit_array_t *ba)
{
    size_t i;
    int    count = 0;
    long   num_final_bits;

    if (ba == NULL || ba->n_elems == 0 || ba->n_elems > CMT_BITS_MAX_ELEMS) {
        return CMT_FAULT;
    }
    for (i = 0; i + 1 < ba->n_elems; i++) {          /* :287-290 */
        count += cmt_bits_ones_count64(ba->elems[i]);
    }
    /* :292 numFinalBits := Bits - (numElems-1)*64 */
    num_final_bits = (long)ba->bits - (long)((ba->n_elems - 1) * 64u);
    for (long j = 0; j < num_final_bits && j < 64; j++) {   /* :293-297 */
        if ((ba->elems[ba->n_elems - 1] & ((uint64_t)1 << (unsigned)j)) != 0) {
            count++;
        }
    }
    return count;
}

/* cometbft@709fd12b libs/bits/bit_array.go:304-334 — getNthTrueIndex() */
int cmt_bits_get_nth_true_index(const cmt_bit_array_t *ba, int n)
{
    size_t i;
    int    count = 0;

    if (ba == NULL || ba->n_elems == 0 || ba->n_elems > CMT_BITS_MAX_ELEMS) {
        return -1;
    }
    for (i = 0; i < ba->n_elems; i++) {              /* :309 */
        int set_bits = cmt_bits_ones_count64(ba->elems[i]);   /* :311 */

        /* NOTE reference quirk (:315): `>=` where `>` is the exact test.
         * Harmless — see the header. */
        if (count + set_bits >= n) {
            for (int j = 0; j < 64; j++) {           /* :317-325 */
                if ((ba->elems[i] & ((uint64_t)1 << (unsigned)j)) != 0) {
                    if (count == n) {
                        return (int)(i * 64u) + j;   /* :321 */
                    }
                    count++;
                }
            }
        } else {
            count += set_bits;                       /* :328 */
        }
    }
    return -1;                                       /* :333 */
}

/* cometbft@709fd12b libs/bits/bit_array.go:265-282 — PickRandom().
 * cmtrand.Intn (libs/rand/random.go:280-285) is replaced by
 * qgp_randombytes with rejection sampling; see the header. */
int cmt_bits_pick_random(const cmt_bit_array_t *ba, int *out_index)
{
    int      num_true;
    int      index;
    uint32_t n;
    uint32_t limit;
    uint32_t draw;

    if (out_index == NULL) {
        return CMT_FAULT;
    }
    if (ba == NULL) {
        return CMT_REJECT;                           /* :266-268 `0, false` */
    }
    num_true = cmt_bits_get_num_true_indices(ba);    /* :271 */
    if (num_true < 0) {
        return CMT_FAULT;
    }
    if (num_true == 0) {
        return CMT_REJECT;                           /* :272-275 */
    }

    /* Uniform over [0, num_true) by rejection sampling: reject any draw at
     * or above the largest multiple of n that fits in 32 bits, so every
     * residue is equally likely. Loops with probability < 1/2 per round. */
    n     = (uint32_t)num_true;
    limit = (uint32_t)((UINT32_MAX / n) * n);        /* n >= 1 */
    for (;;) {
        uint8_t buf[4];

        if (qgp_randombytes(buf, sizeof(buf)) != 0) {
            return CMT_FAULT;
        }
        draw = ((uint32_t)buf[0])       | ((uint32_t)buf[1] << 8) |
               ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
        if (draw < limit) {
            break;
        }
    }
    index = cmt_bits_get_nth_true_index(ba, (int)(draw % n));   /* :276 */
    if (index == -1) {
        return CMT_REJECT;                           /* :278-280 */
    }
    *out_index = index;
    return CMT_OK;                                   /* :281 */
}

/* ── bytes / update ─────────────────────────────────────────────────── */

/* cometbft@709fd12b libs/bits/bit_array.go:384-396 — Bytes() */
int cmt_bits_bytes(const cmt_bit_array_t *ba, uint8_t *out, size_t cap,
                   size_t *out_len)
{
    size_t num_bytes;
    size_t i;

    if (ba == NULL || out_len == NULL) {
        return CMT_FAULT;    /* the reference panics on a nil receiver */
    }
    if (ba->bits < 0 || ba->n_elems > CMT_BITS_MAX_ELEMS) {
        return CMT_FAULT;
    }
    num_bytes = ((size_t)ba->bits + 7u) / 8u;        /* :388 */
    *out_len = num_bytes;
    if (num_bytes == 0) {
        return CMT_OK;
    }
    if (out == NULL || cap < num_bytes) {
        return CMT_REJECT;
    }
    memset(out, 0, num_bytes);
    for (i = 0; i < ba->n_elems; i++) {              /* :390-394 */
        uint64_t v = ba->elems[i];
        size_t   base = i * 8u;
        size_t   k;

        if (base >= num_bytes) {
            break;   /* Go's copy() truncates at the destination length */
        }
        for (k = 0; k < 8u && base + k < num_bytes; k++) {
            out[base + k] = (uint8_t)((v >> (unsigned)(8u * k)) & 0xFFu);
        }
    }
    return CMT_OK;
}

/* cometbft@709fd12b libs/bits/bit_array.go:400-410 — Update() */
int cmt_bits_update(cmt_bit_array_t *ba, const cmt_bit_array_t *o)
{
    size_t n;

    if (ba == NULL || o == NULL) {
        return CMT_OK;                               /* :401-403 no-op */
    }
    if (ba->n_elems > CMT_BITS_MAX_ELEMS || o->n_elems > CMT_BITS_MAX_ELEMS) {
        return CMT_FAULT;
    }
    /* :407 copy(bA.Elems, o.Elems) moves min(len, len) words and, NOTE
     * reference quirk, leaves bA.Bits untouched. */
    n = (ba->n_elems < o->n_elems) ? ba->n_elems : o->n_elems;
    if (n != 0) {
        memcpy(ba->elems, o->elems, n * sizeof(uint64_t));
    }
    return CMT_OK;
}
