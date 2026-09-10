/**
 * Nodus — cometbft @709fd12b C port, wave R1-A: `libs/bits.BitArray` tests
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the bit array a VoteSet uses to say "who voted" and a PartSet uses
 * to say "which parts I hold" behaves exactly as the reference's, and that
 * the two places where C differs from Go — an over-wide shift and a
 * missing bounds check — are handled instead of being undefined. If this
 * file failed, one of these would be false:
 *   · a NULL array answers the reference's nil answers: Size 0, GetIndex
 *     false, IsEmpty true, IsFull true, and the combinators their own nil
 *     rules — the behaviour half of cometbft's call sites rely on;
 *   · the derived capacity is the reference's MaxBlockPartsCount, 1601
 *     bits in 26 words, and asking for more is REFUSED rather than
 *     truncated, so no wire value can make the module allocate;
 *   · GetIndex/SetIndex are little-endian WITHIN a word (bit i is word
 *     i/64, bit i%64) — the layout Bytes() and the packed `elems` codec
 *     both depend on;
 *   · IsFull is right when Bits is a multiple of 64, the case where the
 *     reference relies on Go evaluating `1 << 64` as 0 and where C would
 *     be undefined;
 *   · Or, And, Not and Sub produce the reference's widths and contents,
 *     INCLUDING Or's quirk of dropping the wider operand's high words;
 *   · getNumTrueIndices excludes the last word's padding while
 *     getNthTrueIndex scans all 64 bits of it — the reference's asymmetry,
 *     which is only safe because PickRandom draws below the smaller count;
 *   · PickRandom never returns an index whose bit is clear, and reports
 *     "nothing to pick" rather than picking, on an empty or nil array.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock. It DOES draw from the system random source
 * (qgp_randombytes, via cmt_bits_pick_random) — see "how it can lie".
 * Safe under `ctest -j`. No heap allocation. Nothing to clean up.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. UNIFORMITY OF PickRandom IS NOT TESTED, and cannot be from here: the
 *     ported API takes no injectable RNG, because the reference's is a
 *     process-global math/rand. What IS tested is deterministic no matter
 *     what the source returns — that the chosen index always has its bit
 *     set, and that a one-bit array always yields that one bit. A biased
 *     or broken random source would pass this file. That is acceptable
 *     ONLY because the value is gossip-only (reactor.go:1188) and reaches
 *     no hash, vote, block or state root; if a later wave ever routes it
 *     into consensus, this file stops being sufficient.
 *  2. It never builds a 1601-bit array with real part data. It pins the
 *     BOUND and the refusal past it, not the behaviour of a full part set.
 *  3. The quirk assertions (Or's dropped words, Update leaving Bits alone)
 *     pin what the REFERENCE does. If a future cometbft pin fixes them,
 *     this file will fail — and that failure is the correct signal, not a
 *     defect in the port.
 *  4. Nothing here touches the wire codec; cmt_bits_to_proto /
 *     cmt_bits_from_proto and the "elems must match bits" refusal are
 *     tested in test_cmt_pb.c.
 *
 * @file test_cmt_bits.c
 */

#include "dnac/cmt_bits.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Build an array from a "x_x_" style pattern: 'x' sets the bit. */
static int from_pattern(cmt_bit_array_t *ba, const char *pat)
{
    int n = (int)strlen(pat);
    int i;

    if (cmt_bits_new(ba, n) != CMT_OK) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (pat[i] == 'x' && cmt_bits_set_index(ba, i, true) != 1) {
            return 0;
        }
    }
    return 1;
}

static int matches(const cmt_bit_array_t *ba, const char *pat)
{
    int n = (int)strlen(pat);
    int i;

    if (cmt_bits_size(ba) != n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        int want = (pat[i] == 'x') ? 1 : 0;

        if (cmt_bits_get_index(ba, i) != want) {
            return 0;
        }
    }
    return 1;
}

/* ── capacity, derived from the reference's constants ───────────────── */

static int test_capacity(void)
{
    cmt_bit_array_t ba;

    /* MaxBlockPartsCount = MaxBlockSizeBytes / BlockPartSizeBytes + 1
     * (types/params.go:16, :19, :22) = 104857600 / 65536 + 1 = 1601. */
    CHECK(CMT_BITS_MAX_BLOCK_SIZE_BYTES == 104857600, "MaxBlockSizeBytes");
    CHECK(CMT_BITS_BLOCK_PART_SIZE_BYTES == 65536, "BlockPartSizeBytes");
    CHECK(CMT_BITS_MAX_BLOCK_PARTS_COUNT == 1601, "MaxBlockPartsCount");
    CHECK(CMT_BITS_MAX_BITS == 1601, "max bits");
    CHECK(CMT_BITS_MAX_ELEMS == 26, "(1601+63)/64 = 26");
    CHECK(CMT_BITS_MAX_BYTES == 201, "(1601+7)/8 = 201");
    OK();

    CHECK(cmt_bits_new(&ba, CMT_BITS_MAX_BITS) == CMT_OK, "1601 must fit");
    CHECK(ba.n_elems == CMT_BITS_MAX_ELEMS, "1601 -> 26 words");
    CHECK(cmt_bits_new(&ba, CMT_BITS_MAX_BITS + 1) == CMT_REJECT,
          "1602 must REJECT, never truncate");
    CHECK(ba.bits == 0 && ba.n_elems == 0, "a refused array must be zeroed");
    OK();

    /* The reference returns nil for bits <= 0 (bit_array.go:26-28). */
    CHECK(cmt_bits_new(&ba, 0) == CMT_BITS_NIL, "0 bits is nil");
    CHECK(cmt_bits_new(&ba, -1) == CMT_BITS_NIL, "negative bits is nil");
    OK();

    /* (bits+63)/64 at the word boundaries. */
    CHECK(cmt_bits_num_elems(1) == 1, "1 -> 1");
    CHECK(cmt_bits_num_elems(63) == 1, "63 -> 1");
    CHECK(cmt_bits_num_elems(64) == 1, "64 -> 1");
    CHECK(cmt_bits_num_elems(65) == 2, "65 -> 2");
    CHECK(cmt_bits_num_elems(128) == 2, "128 -> 2");
    CHECK(cmt_bits_num_elems(0) == 0, "0 -> 0");
    OK();
    return 0;
}

/* ── the nil (NULL) contract ────────────────────────────────────────── */

static int test_nil_contract(void)
{
    cmt_bit_array_t a;
    cmt_bit_array_t out;

    CHECK(from_pattern(&a, "x_x_"), "fixture");

    CHECK(cmt_bits_size(NULL) == 0, "nil Size");
    CHECK(cmt_bits_get_index(NULL, 0) == 0, "nil GetIndex");
    CHECK(cmt_bits_set_index(NULL, 0, true) == 0, "nil SetIndex");
    CHECK(cmt_bits_is_empty(NULL) == 1, "nil IsEmpty is TRUE");
    CHECK(cmt_bits_is_full(NULL) == 1, "nil IsFull is TRUE");
    OK();

    CHECK(cmt_bits_copy(NULL, &out) == CMT_BITS_NIL, "nil Copy");
    CHECK(cmt_bits_not(NULL, &out) == CMT_BITS_NIL, "nil Not");
    CHECK(cmt_bits_or(NULL, NULL, &out) == CMT_BITS_NIL, "nil|nil");
    CHECK(cmt_bits_and(&a, NULL, &out) == CMT_BITS_NIL, "a&nil");
    CHECK(cmt_bits_and(NULL, &a, &out) == CMT_BITS_NIL, "nil&a");
    CHECK(cmt_bits_sub(&a, NULL, &out) == CMT_BITS_NIL, "a-nil");
    CHECK(cmt_bits_sub(NULL, &a, &out) == CMT_BITS_NIL, "nil-a");
    OK();

    /* Or with one nil side is a COPY of the other (bit_array.go:139-144). */
    CHECK(cmt_bits_or(NULL, &a, &out) == CMT_OK, "nil|a");
    CHECK(matches(&out, "x_x_"), "nil|a must copy a");
    CHECK(cmt_bits_or(&a, NULL, &out) == CMT_OK, "a|nil");
    CHECK(matches(&out, "x_x_"), "a|nil must copy a");
    OK();

    /* Update with either side nil is a no-op that still succeeds. */
    CHECK(cmt_bits_update(&a, NULL) == CMT_OK, "update nil src");
    CHECK(matches(&a, "x_x_"), "update with nil changed the array");
    CHECK(cmt_bits_update(NULL, &a) == CMT_OK, "update nil dst");
    OK();
    return 0;
}

/* ── get / set ──────────────────────────────────────────────────────── */

static int test_get_set(void)
{
    cmt_bit_array_t ba;

    CHECK(cmt_bits_new(&ba, 130) == CMT_OK, "new 130");
    CHECK(ba.n_elems == 3, "130 -> 3 words");

    /* Bit i lives in word i/64 at position i%64 — little-endian within a
     * word. Set the first bit of each word and read the words back. */
    CHECK(cmt_bits_set_index(&ba, 0, true) == 1, "set 0");
    CHECK(cmt_bits_set_index(&ba, 64, true) == 1, "set 64");
    CHECK(cmt_bits_set_index(&ba, 128, true) == 1, "set 128");
    CHECK(ba.elems[0] == 1u, "word 0");
    CHECK(ba.elems[1] == 1u, "word 1");
    CHECK(ba.elems[2] == 1u, "word 2");
    CHECK(cmt_bits_set_index(&ba, 63, true) == 1, "set 63");
    CHECK(ba.elems[0] == (1u | ((uint64_t)1 << 63)), "bit 63 is the MSB");
    OK();

    CHECK(cmt_bits_get_index(&ba, 0) == 1, "get 0");
    CHECK(cmt_bits_get_index(&ba, 1) == 0, "get 1");
    CHECK(cmt_bits_get_index(&ba, 63) == 1, "get 63");
    CHECK(cmt_bits_get_index(&ba, 128) == 1, "get 128");
    OK();

    /* Out of range: the reference returns false and writes nothing
     * (bit_array.go:75-77, :93-95). */
    CHECK(cmt_bits_get_index(&ba, 130) == 0, "get past the end is false");
    CHECK(cmt_bits_get_index(&ba, 1000000) == 0, "get far past the end");
    CHECK(cmt_bits_set_index(&ba, 130, true) == 0, "set past the end fails");
    CHECK(cmt_bits_set_index(&ba, 131, true) == 0, "set past the end fails");
    CHECK(ba.elems[2] == 1u, "a refused set must not touch the words");
    OK();

    /* Negative: Go would index with a negative subscript and panic; here
     * it is an explicit error, never a read below the array. */
    CHECK(cmt_bits_get_index(&ba, -1) == CMT_FAULT, "get(-1)");
    CHECK(cmt_bits_set_index(&ba, -1, true) == CMT_FAULT, "set(-1)");
    CHECK(cmt_bits_get_index(&ba, -1000000) == CMT_FAULT, "get(very -ve)");
    OK();

    /* Clearing works and is idempotent. */
    CHECK(cmt_bits_set_index(&ba, 0, false) == 1, "clear 0");
    CHECK(cmt_bits_get_index(&ba, 0) == 0, "cleared");
    CHECK(cmt_bits_set_index(&ba, 0, false) == 1, "clear again");
    CHECK(cmt_bits_get_index(&ba, 0) == 0, "still cleared");
    OK();
    return 0;
}

/* ── combinators ────────────────────────────────────────────────────── */

static int test_combinators(void)
{
    cmt_bit_array_t a, b, out;

    CHECK(from_pattern(&a, "xx__xx__"), "a");
    CHECK(from_pattern(&b, "x_x_x_x_"), "b");

    CHECK(cmt_bits_or(&a, &b, &out) == CMT_OK, "or");
    CHECK(matches(&out, "xxx_xxx_"), "or contents");
    CHECK(cmt_bits_and(&a, &b, &out) == CMT_OK, "and");
    CHECK(matches(&out, "x___x___"), "and contents");
    CHECK(cmt_bits_sub(&a, &b, &out) == CMT_OK, "sub");
    CHECK(matches(&out, "_x___x__"), "sub is a AND NOT b");
    CHECK(cmt_bits_not(&a, &out) == CMT_OK, "not");
    CHECK(matches(&out, "__xx__xx"), "not contents");
    OK();

    /* Copy is deep: mutating the copy must not touch the original. */
    CHECK(cmt_bits_copy(&a, &out) == CMT_OK, "copy");
    CHECK(matches(&out, "xx__xx__"), "copy contents");
    CHECK(cmt_bits_set_index(&out, 0, false) == 1, "mutate the copy");
    CHECK(matches(&a, "xx__xx__"), "the original changed with its copy");
    OK();

    /* Widths: Or takes the max, And takes the min, Sub keeps bA's. */
    {
        cmt_bit_array_t wide, narrow;

        CHECK(from_pattern(&wide, "xxxxxxxxxxxx"), "wide 12");
        CHECK(from_pattern(&narrow, "xxxx"), "narrow 4");

        CHECK(cmt_bits_or(&wide, &narrow, &out) == CMT_OK, "or w|n");
        CHECK(cmt_bits_size(&out) == 12, "Or width is the max");
        CHECK(cmt_bits_or(&narrow, &wide, &out) == CMT_OK, "or n|w");
        CHECK(cmt_bits_size(&out) == 12, "Or width is the max either way");

        CHECK(cmt_bits_and(&wide, &narrow, &out) == CMT_OK, "and");
        CHECK(cmt_bits_size(&out) == 4, "And width is the min");
        CHECK(cmt_bits_and(&narrow, &wide, &out) == CMT_OK, "and swapped");
        CHECK(cmt_bits_size(&out) == 4, "And width is the min either way");

        CHECK(cmt_bits_sub(&wide, &narrow, &out) == CMT_OK, "sub");
        CHECK(cmt_bits_size(&out) == 12, "Sub keeps the left width");
        CHECK(matches(&out, "____xxxxxxxx"),
              "Sub right-pads the shorter operand with zeroes");
        OK();
    }

    /* NOTE reference quirk (bit_array.go:147-151): when the RIGHT operand
     * is the wider one, Or only folds min(words) words, so the right
     * operand's high WORDS are dropped even though the result is wide
     * enough to hold them. Bits 0..63 come through, bit 64 does not. */
    {
        cmt_bit_array_t small, big;

        CHECK(cmt_bits_new(&small, 8) == CMT_OK, "small 8 (1 word)");
        CHECK(cmt_bits_new(&big, 130) == CMT_OK, "big 130 (3 words)");
        CHECK(cmt_bits_set_index(&big, 0, true) == 1, "big bit 0");
        CHECK(cmt_bits_set_index(&big, 64, true) == 1, "big bit 64");
        CHECK(cmt_bits_set_index(&big, 128, true) == 1, "big bit 128");

        CHECK(cmt_bits_or(&small, &big, &out) == CMT_OK, "small|big");
        CHECK(cmt_bits_size(&out) == 130, "width is still the max");
        CHECK(cmt_bits_get_index(&out, 0) == 1,
              "the shared word IS folded in");
        CHECK(cmt_bits_get_index(&out, 64) == 0,
              "quirk: the wider operand's word 1 is dropped");
        CHECK(cmt_bits_get_index(&out, 128) == 0,
              "quirk: the wider operand's word 2 is dropped");
        OK();

        /* The other way round loses nothing, since the left operand's own
         * words are all copied by copyBits. */
        CHECK(cmt_bits_or(&big, &small, &out) == CMT_OK, "big|small");
        CHECK(cmt_bits_get_index(&out, 64) == 1, "big|small keeps word 1");
        CHECK(cmt_bits_get_index(&out, 128) == 1, "big|small keeps word 2");
        OK();
    }

    /* NOTE reference quirk (bit_array.go:400-410): Update copies WORDS and
     * leaves Bits alone. */
    {
        cmt_bit_array_t dst, src;

        CHECK(from_pattern(&dst, "________"), "dst 8");
        CHECK(from_pattern(&src, "xxxxxxxxxxxx"), "src 12");
        CHECK(cmt_bits_update(&dst, &src) == CMT_OK, "update");
        CHECK(cmt_bits_size(&dst) == 8,
              "quirk: Update must NOT change the destination's width");
        CHECK(matches(&dst, "xxxxxxxx"), "the words did come across");
        OK();
    }
    return 0;
}

/* ── IsEmpty / IsFull, including the 1 << 64 case ───────────────────── */

static int test_predicates(void)
{
    cmt_bit_array_t ba;
    int             widths[] = { 1, 7, 8, 63, 64, 65, 127, 128, 129, 1601 };
    size_t          w;

    CHECK(from_pattern(&ba, "____"), "empty 4");
    CHECK(cmt_bits_is_empty(&ba) == 1, "all-clear is empty");
    CHECK(cmt_bits_is_full(&ba) == 0, "all-clear is not full");
    CHECK(cmt_bits_set_index(&ba, 2, true) == 1, "set one");
    CHECK(cmt_bits_is_empty(&ba) == 0, "one set bit is not empty");
    OK();

    /* IsFull across the word boundary. Bits == 64 and 128 are the cases
     * where the reference's mask is `1 << 64`, zero in Go and undefined
     * in C; getting the mask wrong would make a full array report empty
     * or a nearly-full array report full. */
    for (w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
        int n = widths[w];
        int i;

        CHECK(cmt_bits_new(&ba, n) == CMT_OK, "new");
        CHECK(cmt_bits_is_full(&ba) == 0, "a fresh array is not full");
        for (i = 0; i < n; i++) {
            CHECK(cmt_bits_set_index(&ba, i, true) == 1, "set");
            if (i + 1 < n) {
                if (cmt_bits_is_full(&ba) != 0) {
                    fprintf(stderr,
                            "IsFull true too early: width %d, %d bits set\n",
                            n, i + 1);
                    return 1;
                }
            }
        }
        if (cmt_bits_is_full(&ba) != 1) {
            fprintf(stderr, "IsFull false for a full array of width %d\n", n);
            return 1;
        }
        CHECK(cmt_bits_is_empty(&ba) == 0, "a full array is not empty");
        /* Clearing any one bit makes it not full again. */
        CHECK(cmt_bits_set_index(&ba, n / 2, false) == 1, "clear middle");
        if (cmt_bits_is_full(&ba) != 0) {
            fprintf(stderr, "IsFull true with a hole at width %d\n", n);
            return 1;
        }
    }
    OK();

    /* A zero-word array is the shape the reference indexes from the end
     * of and panics on; here it is a reported fault, never a read. */
    {
        cmt_bit_array_t bad;

        memset(&bad, 0, sizeof(bad));
        bad.bits = 8;
        bad.n_elems = 0;
        CHECK(cmt_bits_is_full(&bad) == CMT_FAULT, "zero-word IsFull");
        CHECK(cmt_bits_get_num_true_indices(&bad) == CMT_FAULT,
              "zero-word count");
        CHECK(cmt_bits_get_nth_true_index(&bad, 0) == -1, "zero-word nth");
        OK();
    }
    return 0;
}

/* ── population counts ──────────────────────────────────────────────── */

static int test_population(void)
{
    cmt_bit_array_t ba;

    CHECK(from_pattern(&ba, "x__x_x"), "pattern");
    CHECK(cmt_bits_get_num_true_indices(&ba) == 3, "three set bits");
    CHECK(cmt_bits_get_nth_true_index(&ba, 0) == 0, "0th");
    CHECK(cmt_bits_get_nth_true_index(&ba, 1) == 3, "1st");
    CHECK(cmt_bits_get_nth_true_index(&ba, 2) == 5, "2nd");
    CHECK(cmt_bits_get_nth_true_index(&ba, 3) == -1, "past the end is -1");
    CHECK(cmt_bits_get_nth_true_index(&ba, 100) == -1, "far past is -1");
    OK();

    CHECK(from_pattern(&ba, "______"), "empty");
    CHECK(cmt_bits_get_num_true_indices(&ba) == 0, "none set");
    OK();

    /* Across words: bits 0, 64 and 129 of a 130-bit array. */
    {
        CHECK(cmt_bits_new(&ba, 130) == CMT_OK, "new 130");
        CHECK(cmt_bits_set_index(&ba, 0, true) == 1, "0");
        CHECK(cmt_bits_set_index(&ba, 64, true) == 1, "64");
        CHECK(cmt_bits_set_index(&ba, 129, true) == 1, "129");
        CHECK(cmt_bits_get_num_true_indices(&ba) == 3, "3 across 3 words");
        CHECK(cmt_bits_get_nth_true_index(&ba, 0) == 0, "0th across words");
        CHECK(cmt_bits_get_nth_true_index(&ba, 1) == 64, "1st across words");
        CHECK(cmt_bits_get_nth_true_index(&ba, 2) == 129, "2nd across words");
        OK();
    }

    /* NOTE reference quirk: Not() sets the last word's PADDING bits, and
     * the two counters then disagree — getNumTrueIndices stops at Bits,
     * getNthTrueIndex scans all 64 bits of the word. Pinned so that a
     * "tidy-up" of either one is caught. */
    {
        cmt_bit_array_t all_clear, notted;

        CHECK(cmt_bits_new(&all_clear, 4) == CMT_OK, "new 4");
        CHECK(cmt_bits_not(&all_clear, &notted) == CMT_OK, "not");
        CHECK(notted.elems[0] == ~(uint64_t)0,
              "quirk: Not complements the padding too");
        CHECK(cmt_bits_get_num_true_indices(&notted) == 4,
              "the count stops at Bits");
        CHECK(cmt_bits_get_nth_true_index(&notted, 3) == 3, "3rd is bit 3");
        CHECK(cmt_bits_get_nth_true_index(&notted, 7) == 7,
              "quirk: the nth scan reaches into the padding");
        OK();
    }
    return 0;
}

/* ── Bytes ──────────────────────────────────────────────────────────── */

static int test_bytes(void)
{
    cmt_bit_array_t ba;
    uint8_t         buf[CMT_BITS_MAX_BYTES];
    size_t          n;

    /* Little-endian per word, (bits+7)/8 bytes out. */
    CHECK(cmt_bits_new(&ba, 16) == CMT_OK, "new 16");
    CHECK(cmt_bits_set_index(&ba, 0, true) == 1, "bit 0");
    CHECK(cmt_bits_set_index(&ba, 9, true) == 1, "bit 9");
    CHECK(cmt_bits_bytes(&ba, buf, sizeof(buf), &n) == CMT_OK, "bytes");
    CHECK(n == 2, "16 bits -> 2 bytes");
    CHECK(buf[0] == 0x01, "byte 0 carries bit 0");
    CHECK(buf[1] == 0x02, "byte 1 carries bit 9");
    OK();

    /* A width that is not a whole number of bytes still rounds up. */
    CHECK(cmt_bits_new(&ba, 9) == CMT_OK, "new 9");
    CHECK(cmt_bits_set_index(&ba, 8, true) == 1, "bit 8");
    CHECK(cmt_bits_bytes(&ba, buf, sizeof(buf), &n) == CMT_OK, "bytes 9");
    CHECK(n == 2, "9 bits -> 2 bytes");
    CHECK(buf[0] == 0x00 && buf[1] == 0x01, "bit 8 is byte 1 bit 0");
    OK();

    /* Across three words, at the widest supported size. */
    CHECK(cmt_bits_new(&ba, CMT_BITS_MAX_BITS) == CMT_OK, "new 1601");
    CHECK(cmt_bits_set_index(&ba, 1600, true) == 1, "top bit");
    CHECK(cmt_bits_bytes(&ba, buf, sizeof(buf), &n) == CMT_OK, "bytes 1601");
    CHECK(n == CMT_BITS_MAX_BYTES, "1601 bits -> 201 bytes");
    CHECK(buf[200] == 0x01, "bit 1600 is byte 200 bit 0");
    OK();

    /* Too small an output buffer REJECTS and still reports the size. */
    CHECK(cmt_bits_bytes(&ba, buf, 4, &n) == CMT_REJECT, "short buffer");
    CHECK(n == CMT_BITS_MAX_BYTES, "the needed size is still reported");
    /* The reference panics on a nil receiver; here it is a fault. */
    CHECK(cmt_bits_bytes(NULL, buf, sizeof(buf), &n) == CMT_FAULT, "nil");
    OK();
    return 0;
}

/* ── PickRandom ─────────────────────────────────────────────────────── */

static int test_pick_random(void)
{
    cmt_bit_array_t ba;
    int             idx;
    int             i;

    /* Nothing to pick: reported, never invented. */
    CHECK(cmt_bits_pick_random(NULL, &idx) == CMT_REJECT, "nil");
    CHECK(from_pattern(&ba, "____"), "all clear");
    CHECK(cmt_bits_pick_random(&ba, &idx) == CMT_REJECT, "no set bits");
    OK();

    /* One set bit: the answer is forced, so this is deterministic no
     * matter what the random source returns. */
    CHECK(from_pattern(&ba, "___x____"), "one set bit");
    for (i = 0; i < 200; i++) {
        idx = -1;
        CHECK(cmt_bits_pick_random(&ba, &idx) == CMT_OK, "pick");
        CHECK(idx == 3, "a one-bit array must always yield that bit");
    }
    OK();

    /* Many set bits: whatever comes back, its bit must be SET and inside
     * the array. This holds for every possible draw, so it is not a
     * probabilistic assertion. */
    CHECK(from_pattern(&ba, "x__x_x__x"), "four set bits");
    for (i = 0; i < 500; i++) {
        idx = -1;
        CHECK(cmt_bits_pick_random(&ba, &idx) == CMT_OK, "pick");
        CHECK(idx >= 0 && idx < cmt_bits_size(&ba), "index in range");
        CHECK(cmt_bits_get_index(&ba, idx) == 1,
              "PickRandom returned an index whose bit is CLEAR");
    }
    OK();

    /* Across words, same property. */
    CHECK(cmt_bits_new(&ba, 200) == CMT_OK, "new 200");
    CHECK(cmt_bits_set_index(&ba, 7, true) == 1, "7");
    CHECK(cmt_bits_set_index(&ba, 70, true) == 1, "70");
    CHECK(cmt_bits_set_index(&ba, 199, true) == 1, "199");
    for (i = 0; i < 500; i++) {
        idx = -1;
        CHECK(cmt_bits_pick_random(&ba, &idx) == CMT_OK, "pick");
        CHECK(idx == 7 || idx == 70 || idx == 199,
              "PickRandom left the set of set bits");
    }
    OK();
    return 0;
}

int main(void)
{
    if (test_capacity() != 0)     { return 1; }
    if (test_nil_contract() != 0) { return 1; }
    if (test_get_set() != 0)      { return 1; }
    if (test_combinators() != 0)  { return 1; }
    if (test_predicates() != 0)   { return 1; }
    if (test_population() != 0)   { return 1; }
    if (test_bytes() != 0)        { return 1; }
    if (test_pick_random() != 0)  { return 1; }

    printf("test_cmt_bits: OK (%d groups)\n", g_checks);
    return 0;
}
