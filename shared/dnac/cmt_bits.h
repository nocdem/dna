/**
 * @file shared/dnac/cmt_bits.h
 * @brief cometbft @709fd12b `libs/bits.BitArray` ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-A of the cometbft → C consensus port. Nothing calls this yet;
 * additive only. The live witness BFT and QC V2 are untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A BitArray is what a VoteSet reports as "who has voted" and what a
 * PartSet reports as "which parts I hold". It travels on the wire inside
 * HasVote / VoteSetBits / NewValidBlock messages.
 *
 * ── Two substitutions, no others ───────────────────────────────────────
 * 1. NO LOCK. The reference embeds a `sync.Mutex` (bit_array.go:18) and
 *    every exported method takes it. This port is single-threaded
 *    (umbrella rev 3 item 4), so the lock is dropped and each exported /
 *    unexported pair (GetIndex/getIndex, SetIndex/setIndex, Copy/copy,
 *    And/and, Not/not) collapses into ONE C function that carries both
 *    line ranges.
 * 2. FIXED CAPACITY instead of a heap slice. Go grows `Elems` on demand;
 *    here the array is inline and bounded. The bound is DERIVED, not
 *    chosen: the largest BitArray any consensus path builds is a part-set
 *    bit array, one bit per block part, and
 *        MaxBlockPartsCount = MaxBlockSizeBytes / BlockPartSizeBytes + 1
 *                           = 104857600 / 65536 + 1
 *                           = 1601                       (types/params.go:16, :19, :22)
 *    so CMT_BITS_MAX_BITS = 1601 and CMT_BITS_MAX_ELEMS = 26. A vote bit
 *    array is far smaller — one bit per validator, bounded by
 *    DNA_MAX_ACTIVE_VALIDATORS = 128 (shared/dnac/ledger_ids.h:103) = 2
 *    elems. Anything larger than the derived bound is REFUSED rather than
 *    truncated; a wire value cannot make this module allocate.
 *
 * ── Go's nil *BitArray ─────────────────────────────────────────────────
 * Half of these methods have a documented nil behaviour (Size 0, GetIndex
 * false, IsEmpty true, IsFull true, Or/And/Sub/Not/Copy their own rules).
 * A nil *BitArray is a NULL cmt_bit_array_t * here, and each function
 * reproduces the reference's nil answer at the cited line. A constructor
 * that would have returned nil returns CMT_BITS_NIL and leaves the output
 * struct zeroed; the caller then passes NULL onward wherever the reference
 * would have passed the nil pointer.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments EXCEPT
 * cmt_bits_pick_random, which draws randomness. That function is
 * GOSSIP-ONLY: its single reference consumer is PeerState.PickVoteToSend
 * (consensus/reactor.go:1188), which chooses WHICH vote to send to a peer
 * next. It decides no state transition, enters no hash and is never part
 * of a vote, a block or a state root. Nothing else in this file consults a
 * clock, a map, or any global.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `String` (:342-344), `StringIndented` (:348-355), `stringIndented`
 *     (:357-381) — display only.
 *   · `MarshalJSON` (:414-432), `UnmarshalJSON` (:438-472) — the reference
 *     persists a BitArray as JSON for its RPC; this port has no JSON and
 *     no RPC surface for consensus objects.
 *   · `ToProto` (:475-484) and `FromProto` (:487-497) — the codec's, in
 *     cmt_pb.{h,c} as cmt_bits_to_proto / cmt_bits_from_proto.
 *
 * Reference @709fd12b: libs/bits/bit_array.go, 497 lines,
 * de70791bae05efc5c2e059f56c6582b7cbe700531dfb73c0e53077cfaa297d49.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * chunking rev 2 (atlas-dec-6d35670369b69df4439cb720036fa2d7 — the part
 * set is un-parked, which is why the 1601-bit bound is the live one).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_BITS_H
#define SHARED_DNAC_CMT_BITS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Derived capacity (see the header comment for the derivation) ──── */

/** cometbft@709fd12b types/params.go:16 — `MaxBlockSizeBytes`. */
#define CMT_BITS_MAX_BLOCK_SIZE_BYTES  104857600
/** cometbft@709fd12b types/params.go:19 — `BlockPartSizeBytes`. */
#define CMT_BITS_BLOCK_PART_SIZE_BYTES 65536
/** cometbft@709fd12b types/params.go:22 — `MaxBlockPartsCount`. */
#define CMT_BITS_MAX_BLOCK_PARTS_COUNT \
    ((CMT_BITS_MAX_BLOCK_SIZE_BYTES / CMT_BITS_BLOCK_PART_SIZE_BYTES) + 1)

/** The widest bit array this port will build or accept: 1601 bits. */
#define CMT_BITS_MAX_BITS  CMT_BITS_MAX_BLOCK_PARTS_COUNT
/** (1601 + 63) / 64 = 26 uint64 words. */
#define CMT_BITS_MAX_ELEMS ((CMT_BITS_MAX_BITS + 63) / 64)
/** (1601 + 7) / 8 = 201 bytes, the widest cmt_bits_bytes output. */
#define CMT_BITS_MAX_BYTES ((CMT_BITS_MAX_BITS + 7) / 8)

/** A constructor or combinator returned the reference's nil *BitArray.
 *  POSITIVE, so it is never confused with CMT_REJECT / CMT_FAULT: a nil
 *  result is a normal outcome in the reference, not a failure. */
#define CMT_BITS_NIL 1

/**
 * cometbft@709fd12b libs/bits/bit_array.go:17-21 — `type BitArray struct`.
 * The `sync.Mutex` of :18 is dropped (single-threaded port).
 * `n_elems` is the reference's `len(Elems)`; it is ALWAYS
 * (bits + 63) / 64 for any array this module builds, and is validated
 * against `bits` by cmt_bits_from_proto before a wire array is used.
 */
typedef struct {
    int      bits;                          /* bit_array.go:19 `Bits`  */
    size_t   n_elems;                       /* bit_array.go:20 len()   */
    uint64_t elems[CMT_BITS_MAX_ELEMS];     /* bit_array.go:20 `Elems` */
} cmt_bit_array_t;

/** The number of uint64 words a `bits`-wide array needs: (bits+63)/64.
 *  This is the reference's expression at bit_array.go:31, :44, :124. */
size_t cmt_bits_num_elems(int bits);

/* ── constructors ───────────────────────────────────────────────────── */

/** cometbft@709fd12b libs/bits/bit_array.go:25-33 — `NewBitArray()`.
 *  @return CMT_OK; CMT_BITS_NIL when bits <= 0 (the reference's nil,
 *          :26-28); CMT_REJECT when bits > CMT_BITS_MAX_BITS. */
int cmt_bits_new(cmt_bit_array_t *ba, int bits);

/** cometbft@709fd12b libs/bits/bit_array.go:38-53 — `NewBitArrayFromFn()`.
 *  `fn` is called for i in [0, bits) in ascending order. */
int cmt_bits_new_from_fn(cmt_bit_array_t *ba, int bits,
                         bool (*fn)(int i, void *ctx), void *ctx);

/* ── accessors ──────────────────────────────────────────────────────── */

/** cometbft@709fd12b libs/bits/bit_array.go:56-61 — `Size()`.
 *  A NULL array is the reference's nil and answers 0 (:57-59). */
int cmt_bits_size(const cmt_bit_array_t *ba);

/** cometbft@709fd12b libs/bits/bit_array.go:65-72 `GetIndex()` and
 *  :74-79 `getIndex()`.
 *  @return 1 set, 0 clear (NULL array :66-68, or i >= bits :75-77),
 *          CMT_FAULT for i < 0 — where Go would index with a negative
 *          subscript and panic (INVARIANT 7495d337). */
int cmt_bits_get_index(const cmt_bit_array_t *ba, int i);

/** cometbft@709fd12b libs/bits/bit_array.go:83-90 `SetIndex()` and
 *  :92-102 `setIndex()`.
 *  @return 1 when the bit was written, 0 when it was not (NULL array
 *          :84-86, or i >= bits :93-95), CMT_FAULT for i < 0. */
int cmt_bits_set_index(cmt_bit_array_t *ba, int i, bool v);

/* ── combinators ────────────────────────────────────────────────────── */

/** cometbft@709fd12b libs/bits/bit_array.go:105-112 `Copy()` and
 *  :114-121 `copy()`. @return CMT_OK, or CMT_BITS_NIL for a NULL input. */
int cmt_bits_copy(const cmt_bit_array_t *ba, cmt_bit_array_t *out);

/** cometbft@709fd12b libs/bits/bit_array.go:123-130 — `copyBits()`.
 *  Copies min(len(src.elems), (bits+63)/64) words into an array of the
 *  requested width; the reference does NOT clear bits above `bits` that
 *  survive inside the last copied word. */
int cmt_bits_copy_bits(const cmt_bit_array_t *ba, int bits,
                       cmt_bit_array_t *out);

/**
 * cometbft@709fd12b libs/bits/bit_array.go:135-155 — `Or()`.
 * Result width is max(bits); the smaller operand is right-padded with 0.
 *
 * NOTE reference quirk (:147-151): the result is a copy of `ba` widened to
 * max(bits), and only min(len(ba.Elems), len(o.Elems)) words are ORed in.
 * When `o` is the WIDER array, its high words are therefore NOT carried
 * into the result — those bits are silently lost. Ported as-is per the
 * "the reference in everything" rule; the test pins the behaviour.
 */
int cmt_bits_or(const cmt_bit_array_t *ba, const cmt_bit_array_t *o,
                cmt_bit_array_t *out);

/** cometbft@709fd12b libs/bits/bit_array.go:160-171 `And()` and :173-179
 *  `and()`. Result width is min(bits); nil in, nil out (:161-163). */
int cmt_bits_and(const cmt_bit_array_t *ba, const cmt_bit_array_t *o,
                 cmt_bit_array_t *out);

/** cometbft@709fd12b libs/bits/bit_array.go:182-189 `Not()` and :191-197
 *  `not()`. Complements ALL 64 bits of every word, including the padding
 *  above `bits` in the last word — that is the reference's behaviour and
 *  is what makes cmt_bits_get_num_true_indices and
 *  cmt_bits_get_nth_true_index disagree about the padding (see those). */
int cmt_bits_not(const cmt_bit_array_t *ba, cmt_bit_array_t *out);

/** cometbft@709fd12b libs/bits/bit_array.go:203-224 — `Sub()`.
 *  Carry-less subtraction, a AND NOT b. Result width is always ba's. */
int cmt_bits_sub(const cmt_bit_array_t *ba, const cmt_bit_array_t *o,
                 cmt_bit_array_t *out);

/* ── predicates ─────────────────────────────────────────────────────── */

/** cometbft@709fd12b libs/bits/bit_array.go:227-239 — `IsEmpty()`.
 *  NULL is the reference's nil and answers true (:228-230).
 *  @return 1 true, 0 false. */
int cmt_bits_is_empty(const cmt_bit_array_t *ba);

/**
 * cometbft@709fd12b libs/bits/bit_array.go:242-260 — `IsFull()`.
 * NULL is the reference's nil and answers true (:243-245).
 *
 * Two things the reference leaves implicit are explicit here:
 *   · `Elems[:len(Elems)-1]` (:250) and `Elems[len(Elems)-1]` (:258) both
 *     index from the end, so an array with ZERO words panics in Go. That
 *     shape is unreachable through NewBitArray, but a wire array could
 *     carry it; here it returns CMT_FAULT instead of reading out of
 *     bounds (INVARIANT 7495d337). cmt_bits_from_proto refuses it first.
 *   · `1 << lastElemBits` (:259) with lastElemBits == 64 is 0 in Go and
 *     UNDEFINED in C. The mask is computed with an explicit 64-bit case.
 *
 * @return 1 true, 0 false, CMT_FAULT for the zero-word shape.
 */
int cmt_bits_is_full(const cmt_bit_array_t *ba);

/* ── population ─────────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b libs/bits/bit_array.go:284-299 —
 * `getNumTrueIndices()`. Counts every set bit in all words but the last,
 * then only the first `Bits - (n-1)*64` bits of the last word — so bits
 * that Not() left set in the last word's PADDING are NOT counted.
 * @return the count, or CMT_FAULT for a NULL or zero-word array.
 */
int cmt_bits_get_num_true_indices(const cmt_bit_array_t *ba);

/**
 * cometbft@709fd12b libs/bits/bit_array.go:304-334 —
 * `getNthTrueIndex()`. n is 0-based.
 *
 * NOTE reference quirk (:317): the inner scan runs j over all 64 bits of a
 * word, INCLUDING the last word's padding, while getNumTrueIndices above
 * excludes that padding. The two therefore count differently on an array
 * whose padding bits are set (only Not() can do that). It is safe in the
 * reference only because the sole caller, PickRandom, passes an n drawn
 * below the SMALLER count, and the padding bits are the highest indices;
 * so the n-th set bit is always a real one. Ported as-is.
 *
 * NOTE reference quirk (:315): the branch test is `count+setBits >= n`
 * where `> n` would be the exact condition. It is harmless: on the
 * boundary the inner loop finds no match and leaves `count` at exactly
 * the value the `else` branch would have set. Ported as-is.
 *
 * @return the index, or -1 when there is no n-th set bit (:333) or the
 *         array is NULL / zero-word.
 */
int cmt_bits_get_nth_true_index(const cmt_bit_array_t *ba, int n);

/**
 * cometbft@709fd12b libs/bits/bit_array.go:265-282 — `PickRandom()`.
 *
 * SUBSTITUTION: the reference draws with `cmtrand.Intn` (:276), a global
 * math/rand PRNG seeded from the OS at process start
 * (libs/rand/random.go:29-32, :40-48, :280-285). This port draws from
 * `qgp_randombytes` (shared/crypto/utils/qgp_random.h:24) with rejection
 * sampling, which gives the same UNIFORM distribution over the set bits
 * but a different SEQUENCE. That is sound here and only here: the value
 * chooses which vote to gossip next (consensus/reactor.go:1188) and never
 * reaches a hash, a vote, a block or a state root. It must not be reused
 * for anything a second node has to agree with.
 *
 * @param out_index receives the chosen index when the result is CMT_OK.
 * @return CMT_OK when a set bit was chosen; CMT_REJECT when there is none
 *         (the reference's `0, false` at :272-275 and :278-280);
 *         CMT_FAULT if the random source fails.
 */
int cmt_bits_pick_random(const cmt_bit_array_t *ba, int *out_index);

/* ── bytes / update ─────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b libs/bits/bit_array.go:384-396 — `Bytes()`.
 * (bits + 7) / 8 bytes, each word written little-endian, the last word
 * truncated to whatever room is left. The reference does NOT mask the
 * padding bits inside the final byte, so a Not() result reports them.
 *
 * NOTE reference quirk: `Bytes()` has no nil check (:385 locks the mutex
 * of a nil receiver) and panics on a nil BitArray. Here a NULL array
 * returns CMT_FAULT.
 *
 * @param cap capacity of out; @param out_len receives the byte count.
 * @return CMT_OK, CMT_REJECT if cap is too small, CMT_FAULT on NULL.
 */
int cmt_bits_bytes(const cmt_bit_array_t *ba, uint8_t *out, size_t cap,
                   size_t *out_len);

/**
 * cometbft@709fd12b libs/bits/bit_array.go:400-410 — `Update()`.
 * Copies min(len) words from `o` into `ba`.
 *
 * NOTE reference quirk: it copies WORDS only — `ba.Bits` is left alone, so
 * after Update the array keeps its own width while carrying another
 * array's contents. Ported as-is.
 *
 * @return CMT_OK, including when either side is NULL (the reference
 *         returns without doing anything, :401-403).
 */
int cmt_bits_update(cmt_bit_array_t *ba, const cmt_bit_array_t *o);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_BITS_H */
