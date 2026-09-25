/**
 * Nodus — cometbft @709fd12b C port, wave R1-A: `types/time` tests
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That BFT-time's weighted median — the function that decides a block's
 * timestamp from the previous commit's votes, and which every validator
 * must compute identically — is the reference's walk, and that the C time
 * value carries Go's semantics rather than C's defaults. If this file
 * failed, one of these would be false:
 *   · Go's ZERO time is seconds = -62135596800, not 0. A struct that is
 *     merely memset to zero is 1970 and encodes to ZERO BYTES, where the
 *     reference's zero time encodes to eleven. Every Absent CommitSig and
 *     every unset vote timestamp in the chain depends on this;
 *   · the valid Timestamp range is [-62135596800, 253402300800) with the
 *     LOWER bound included and the upper excluded, and nanos in [0, 1e9)
 *     — the range a decoded Timestamp is checked against;
 *   · Canonical is the identity on this representation, and still refuses
 *     an out-of-range value rather than passing it into consensus;
 *   · WeightedMedian reproduces the three cases of the reference's own
 *     types/time/time_test.go, INCLUDING its third case, whose input has
 *     two nil holes — the shape state/state.go:269 MedianTime always
 *     produces, one hole per Absent signature;
 *   · WeightedMedian reproduces the worked example of the reference's
 *     spec/consensus/bft-time.md: with the faulty validators p3 (1000) and
 *     p4 (500) outvoted by p2's 27 power, the answer is 98 — the property
 *     that stops a faulty validator dragging block time into the future;
 *   · when nothing is selected — no entries, all nil, or weights that
 *     never reach the median — the answer is Go's ZERO time, not 1970;
 *   · UnixNano, the sort key, wraps exactly as Go's int64 arithmetic does.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, NO CLOCK (the module reads none) and no RNG. Safe under
 * `ctest -j`. No heap allocation. Nothing to clean up.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The three WeightedMedian cases and the bft-time.md example ARE the
 *     reference's own vectors, read from the pinned tree
 *     (types/time/time_test.go d78232b0…, 56 lines;
 *     spec/consensus/bft-time.md 5f75056f…, 126 lines). They are the only
 *     externally-grounded assertions in wave R1-A. Everything else in this
 *     file is derived from reading types/time/time.go.
 *  2. The reference's time_test.go builds its instants from `Now()`. This
 *     file uses FIXED instants instead, because the port reads no clock;
 *     the WEIGHTS and the relative ORDER — the only things the median
 *     depends on — are the reference's unchanged.
 *  3. THE SORT IS NOT THE REFERENCE'S. Go uses the unstable `sort.Slice`;
 *     this port uses a stable insertion sort. The two agree on every input
 *     where equal sort keys imply equal times, which is every time inside
 *     the UnixNano range. Outside it they can differ, and this file does
 *     NOT test that region — it tests that the wrap itself is reproduced.
 *     Keeping vote timestamps inside the non-wrapping range is a later
 *     wave's obligation and is not covered here.
 *  4. Nothing here proves that the HOST feeds MedianTime the right commit,
 *     or compares the result to a header. That is wave R1-C / R2 work.
 *
 * @file test_cmt_time.c
 */

#include "dnac/cmt_time.h"

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

/* Go's zero time.Time as a plain object. CMT_TIME_ZERO is a compound
 * literal, so it may be assigned or passed but never cast. */
static const cmt_time_t g_go_zero = { CMT_TIME_MIN_SECONDS, 0 };

static int time_eq(cmt_time_t a, cmt_time_t b)
{
    return a.seconds == b.seconds && a.nanos == b.nanos;
}

static cmt_time_t mk(int64_t s, int32_t n)
{
    cmt_time_t t;

    t.seconds = s;
    t.nanos   = n;
    return t;
}

/* ── the zero value and the range ───────────────────────────────────── */

static int test_zero_and_range(void)
{
    cmt_time_t zero = CMT_TIME_ZERO;
    cmt_time_t memzero;

    /* The trap this constant exists for. */
    CHECK(zero.seconds == -62135596800LL, "Go's zero time seconds");
    CHECK(zero.nanos == 0, "Go's zero time nanos");
    memset(&memzero, 0, sizeof(memzero));
    CHECK(!time_eq(zero, memzero),
          "a memset time must NOT equal Go's zero time");
    CHECK(memzero.seconds == 0, "memset is the Unix epoch");
    OK();

    /* validateTimestamp's bounds: the lower one is INCLUSIVE, the upper
     * one EXCLUSIVE (gogoproto types/timestamp.go:65-70). */
    CHECK(cmt_time_validate(mk(CMT_TIME_MIN_SECONDS, 0)) == CMT_OK,
          "the minimum second is VALID");
    CHECK(cmt_time_validate(mk(CMT_TIME_MIN_SECONDS - 1, 0)) == CMT_REJECT,
          "one second below the minimum must REJECT");
    CHECK(cmt_time_validate(mk(CMT_TIME_MAX_SECONDS - 1, 999999999))
          == CMT_OK, "the last valid instant");
    CHECK(cmt_time_validate(mk(CMT_TIME_MAX_SECONDS, 0)) == CMT_REJECT,
          "the maximum second is EXCLUSIVE and must REJECT");
    CHECK(cmt_time_validate(mk(CMT_TIME_MAX_SECONDS + 1, 0)) == CMT_REJECT,
          "above the maximum must REJECT");
    OK();

    CHECK(cmt_time_validate(mk(0, 0)) == CMT_OK, "the Unix epoch is valid");
    CHECK(cmt_time_validate(mk(0, 999999999)) == CMT_OK, "999999999 nanos");
    CHECK(cmt_time_validate(mk(0, 1000000000)) == CMT_REJECT,
          "1e9 nanos must REJECT");
    CHECK(cmt_time_validate(mk(0, -1)) == CMT_REJECT,
          "negative nanos must REJECT");
    CHECK(cmt_time_validate(mk(0, INT32_MIN)) == CMT_REJECT, "min nanos");
    CHECK(cmt_time_validate(mk(0, INT32_MAX)) == CMT_REJECT, "max nanos");
    OK();
    return 0;
}

/* ── Canonical ──────────────────────────────────────────────────────── */

static int test_canonical(void)
{
    cmt_time_t out;
    cmt_time_t in = mk(1700000000LL, 123456789);

    /* Round(0).UTC() changes only representation details a {seconds,
     * nanos} pair does not carry, so it is the identity here. */
    CHECK(cmt_time_canonical(in, &out) == CMT_OK, "canonical");
    CHECK(time_eq(in, out), "Canonical must not move the instant");
    CHECK(cmt_time_canonical(CMT_TIME_ZERO, &out) == CMT_OK, "zero");
    CHECK(time_eq(out, g_go_zero), "zero stays zero");
    OK();

    /* It still refuses what a decoder would refuse. */
    CHECK(cmt_time_canonical(mk(CMT_TIME_MAX_SECONDS, 0), &out)
          == CMT_REJECT, "out of range must REJECT");
    CHECK(cmt_time_canonical(mk(0, 1000000000), &out) == CMT_REJECT,
          "bad nanos must REJECT");
    CHECK(cmt_time_canonical(in, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

/* ── UnixNano, the sort key ─────────────────────────────────────────── */

static int test_unix_nano(void)
{
    CHECK(cmt_time_unix_nano(mk(0, 0)) == 0, "epoch");
    CHECK(cmt_time_unix_nano(mk(1, 0)) == 1000000000LL, "one second");
    CHECK(cmt_time_unix_nano(mk(0, 1)) == 1LL, "one nanosecond");
    CHECK(cmt_time_unix_nano(mk(-1, 0)) == -1000000000LL, "before epoch");
    CHECK(cmt_time_unix_nano(mk(1700000000LL, 123456789)) ==
          1700000000123456789LL, "a real instant");
    OK();

    /* Ordering agrees with (seconds, nanos) inside the representable
     * range — the region every honest timestamp lives in. */
    CHECK(cmt_time_unix_nano(mk(5, 0)) < cmt_time_unix_nano(mk(5, 1)),
          "nanos break ties");
    CHECK(cmt_time_unix_nano(mk(4, 999999999)) <
          cmt_time_unix_nano(mk(5, 0)), "seconds dominate");
    OK();

    /* Outside it, Go's int64 arithmetic WRAPS, and this port wraps the
     * same way instead of invoking undefined behaviour. Year 9999 is a
     * VALID Timestamp whose nanosecond count does not fit in an int64. */
    {
        int64_t far = cmt_time_unix_nano(mk(CMT_TIME_MAX_SECONDS - 1, 0));

        /* 253402300799 * 1e9 overflows int64 (max ~9.22e18); the wrapped
         * value is what the reference sorts on. Assert only the fact that
         * it wrapped, since the exact value is the wrap's business. */
        CHECK(far < 0,
              "a year-9999 timestamp must wrap negative, as Go's does");
        OK();
    }
    return 0;
}

/* ── WeightedMedian: the reference's own vectors ────────────────────── */

static int test_weighted_median_reference(void)
{
    cmt_time_t t1 = mk(1700000000LL, 0);
    cmt_time_t t2 = mk(1700000005LL, 0);   /* t1 + 5s  */
    cmt_time_t t3 = mk(1700000010LL, 0);   /* t1 + 10s */
    cmt_time_t t4 = mk(1700000015LL, 0);   /* t1 + 15s */
    cmt_time_t t5 = mk(1700000060LL, 0);   /* t1 + 60s */
    cmt_time_t out;

    /* types/time/time_test.go:11-26 — three validators, 33/40/27 of 100.
     * The faulty one (t1, 33) does not decide the answer. */
    {
        cmt_weighted_time_t w[3];
        const cmt_weighted_time_t *m[3];

        CHECK(cmt_new_weighted_time(t1, 33, &w[0]) == CMT_OK, "w0");
        CHECK(cmt_new_weighted_time(t2, 40, &w[1]) == CMT_OK, "w1");
        CHECK(cmt_new_weighted_time(t3, 27, &w[2]) == CMT_OK, "w2");
        m[2] = &w[0];   /* the reference's own index assignment */
        m[0] = &w[1];
        m[1] = &w[2];
        CHECK(cmt_weighted_median(m, 3, 100, &out) == CMT_OK, "median 1");
        CHECK(time_eq(out, t2), "time_test.go case 1 must give t2");
        OK();
    }

    /* types/time/time_test.go:28-37 — the same powers, different owners. */
    {
        cmt_weighted_time_t w[3];
        const cmt_weighted_time_t *m[3];

        CHECK(cmt_new_weighted_time(t1, 40, &w[0]) == CMT_OK, "w0");
        CHECK(cmt_new_weighted_time(t2, 27, &w[1]) == CMT_OK, "w1");
        CHECK(cmt_new_weighted_time(t3, 33, &w[2]) == CMT_OK, "w2");
        m[1] = &w[0];
        m[2] = &w[1];
        m[0] = &w[2];
        CHECK(cmt_weighted_median(m, 3, 100, &out) == CMT_OK, "median 2");
        CHECK(time_eq(out, t2), "time_test.go case 2 must give t2");
        OK();
    }

    /* types/time/time_test.go:39-55 — eight slots, SIX filled and TWO NIL
     * (indices 2 and 6 are never assigned). That is exactly the shape
     * state/state.go:269 MedianTime builds: one nil per Absent signature.
     * A port that skipped nils wrongly, or sorted them first, would land
     * on a different answer here. */
    {
        cmt_weighted_time_t w[6];
        const cmt_weighted_time_t *m[8];
        size_t i;

        for (i = 0; i < 8; i++) {
            m[i] = NULL;
        }
        CHECK(cmt_new_weighted_time(t1, 10, &w[0]) == CMT_OK, "t1");
        CHECK(cmt_new_weighted_time(t2, 10, &w[1]) == CMT_OK, "t2 a");
        CHECK(cmt_new_weighted_time(t2, 10, &w[2]) == CMT_OK, "t2 b");
        CHECK(cmt_new_weighted_time(t3, 23, &w[3]) == CMT_OK, "t3");
        CHECK(cmt_new_weighted_time(t4, 20, &w[4]) == CMT_OK, "t4");
        CHECK(cmt_new_weighted_time(t5, 10, &w[5]) == CMT_OK, "t5");
        m[3] = &w[0];
        m[1] = &w[1];
        m[5] = &w[2];
        m[4] = &w[3];
        m[0] = &w[4];
        m[7] = &w[5];
        CHECK(cmt_weighted_median(m, 8, 83, &out) == CMT_OK, "median 3");
        CHECK(time_eq(out, t3),
              "time_test.go case 3 (with two nil holes) must give t3");
        OK();
    }

    /* spec/consensus/bft-time.md:56-58 — p2 (98, power 27), p3 (1000,
     * power 10) and p4 (500, power 10). The total handed to the median is
     * the sum of the PARTICIPATING powers, 47, because state/state.go:269
     * accumulates only the non-Absent signatures. Median 23 falls inside
     * p2's 27, so the two faulty far-future stamps cannot move it. */
    {
        cmt_weighted_time_t w[3];
        const cmt_weighted_time_t *m[3];
        cmt_time_t p2 = mk(98, 0);
        cmt_time_t p3 = mk(1000, 0);
        cmt_time_t p4 = mk(500, 0);

        CHECK(cmt_new_weighted_time(p2, 27, &w[0]) == CMT_OK, "p2");
        CHECK(cmt_new_weighted_time(p3, 10, &w[1]) == CMT_OK, "p3");
        CHECK(cmt_new_weighted_time(p4, 10, &w[2]) == CMT_OK, "p4");
        m[0] = &w[0];
        m[1] = &w[1];
        m[2] = &w[2];
        CHECK(cmt_weighted_median(m, 3, 27 + 10 + 10, &out) == CMT_OK,
              "spec median");
        CHECK(time_eq(out, p2), "bft-time.md example must give 98");
        OK();

        /* The same set in the reverse order must give the same answer —
         * the median is a property of the multiset, not of arrival order.
         * This is the determinism claim: two validators that received the
         * precommits in different orders must still agree. */
        m[0] = &w[2];
        m[1] = &w[1];
        m[2] = &w[0];
        CHECK(cmt_weighted_median(m, 3, 47, &out) == CMT_OK, "reversed");
        CHECK(time_eq(out, p2), "arrival order changed the median");
        OK();
    }
    return 0;
}

/* ── WeightedMedian: the edges ──────────────────────────────────────── */

static int test_weighted_median_edges(void)
{
    cmt_time_t out;
    cmt_time_t t = mk(1700000000LL, 0);

    /* Nothing selected -> Go's ZERO time. Not 1970, not the first entry. */
    CHECK(cmt_weighted_median(NULL, 0, 100, &out) == CMT_OK, "empty");
    CHECK(time_eq(out, g_go_zero),
          "an empty median must be Go's zero time, not the epoch");
    OK();

    {
        const cmt_weighted_time_t *m[3] = { NULL, NULL, NULL };

        CHECK(cmt_weighted_median(m, 3, 100, &out) == CMT_OK, "all nil");
        CHECK(time_eq(out, g_go_zero),
              "an all-nil median must be Go's zero time");
        OK();
    }

    {
        /* Weights that never reach the median: the loop runs off the end
         * and the result stays at the zero value (time.go:35, :48-56). */
        cmt_weighted_time_t w[2];
        const cmt_weighted_time_t *m[2];

        CHECK(cmt_new_weighted_time(t, 1, &w[0]) == CMT_OK, "w0");
        CHECK(cmt_new_weighted_time(t, 1, &w[1]) == CMT_OK, "w1");
        m[0] = &w[0];
        m[1] = &w[1];
        CHECK(cmt_weighted_median(m, 2, 1000000, &out) == CMT_OK, "under");
        CHECK(time_eq(out, g_go_zero),
              "weights below the median must leave the zero time");
        OK();
    }

    {
        /* One entry whose weight covers the median: itself. */
        cmt_weighted_time_t w;
        const cmt_weighted_time_t *m[1];

        CHECK(cmt_new_weighted_time(t, 10, &w) == CMT_OK, "w");
        m[0] = &w;
        CHECK(cmt_weighted_median(m, 1, 10, &out) == CMT_OK, "single");
        CHECK(time_eq(out, t), "a single covering entry is the answer");

        /* median <= weight is inclusive: total 20 -> median 10 <= 10. */
        CHECK(cmt_weighted_median(m, 1, 20, &out) == CMT_OK, "boundary");
        CHECK(time_eq(out, t), "the median comparison is <=, not <");

        /* total 21 -> median 10 (truncating division) <= 10, still t. */
        CHECK(cmt_weighted_median(m, 1, 21, &out) == CMT_OK, "odd total");
        CHECK(time_eq(out, t), "totalVotingPower / 2 truncates");

        /* total 22 -> median 11 > 10, nothing selected. */
        CHECK(cmt_weighted_median(m, 1, 22, &out) == CMT_OK, "past");
        CHECK(time_eq(out, g_go_zero), "one past the edge");
        OK();
    }

    /* The array IS reordered in place, as the reference's sort.Slice
     * reorders the caller's slice. Pinned so a caller is never surprised. */
    {
        cmt_weighted_time_t w[3];
        const cmt_weighted_time_t *m[3];

        CHECK(cmt_new_weighted_time(mk(300, 0), 1, &w[0]) == CMT_OK, "a");
        CHECK(cmt_new_weighted_time(mk(100, 0), 1, &w[1]) == CMT_OK, "b");
        CHECK(cmt_new_weighted_time(mk(200, 0), 1, &w[2]) == CMT_OK, "c");
        m[0] = &w[0];
        m[1] = &w[1];
        m[2] = &w[2];
        CHECK(cmt_weighted_median(m, 3, 3, &out) == CMT_OK, "median");
        CHECK(m[0] == &w[1] && m[1] == &w[2] && m[2] == &w[0],
              "the caller's array must come back sorted ascending");
        OK();
    }

    /* Nils sort LAST, so they never displace a real entry (time.go:39-44). */
    {
        cmt_weighted_time_t w[2];
        const cmt_weighted_time_t *m[4];

        CHECK(cmt_new_weighted_time(mk(200, 0), 5, &w[0]) == CMT_OK, "a");
        CHECK(cmt_new_weighted_time(mk(100, 0), 5, &w[1]) == CMT_OK, "b");
        m[0] = NULL;
        m[1] = &w[0];
        m[2] = NULL;
        m[3] = &w[1];
        CHECK(cmt_weighted_median(m, 4, 10, &out) == CMT_OK, "median");
        CHECK(m[0] == &w[1] && m[1] == &w[0] &&
              m[2] == NULL && m[3] == NULL,
              "nils must sort to the end");
        CHECK(time_eq(out, mk(100, 0)), "median with nil holes");
        OK();
    }

    CHECK(cmt_weighted_median(NULL, 3, 10, &out) == CMT_FAULT,
          "NULL array with a non-zero count is a fault");
    OK();
    return 0;
}

int main(void)
{
    if (test_zero_and_range() != 0)           { return 1; }
    if (test_canonical() != 0)                { return 1; }
    if (test_unix_nano() != 0)                { return 1; }
    if (test_weighted_median_reference() != 0){ return 1; }
    if (test_weighted_median_edges() != 0)    { return 1; }

    printf("test_cmt_time: OK (%d groups)\n", g_checks);
    return 0;
}
