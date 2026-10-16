/**
 * @file shared/dnac/cmt_time.c
 * @brief cometbft @v0.38.26 `types/time/time.go` in C — see cmt_time.h.
 *
 * NOTHING HERE READS A CLOCK. `Now()` is HOST; this file declares only its
 * type (in the header) and never calls it.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_time.h"

#include <stdbool.h>
#include <string.h>

/* Go `time.Time.IsZero()` — year one, NOT the Unix epoch. Call sites in
 * the pinned tree: types/block.go:674, types/genesis.go:101. Moved here
 * from cmt_genesis.c by wave R1-D; the body is unchanged. */
bool cmt_time_is_zero(cmt_time_t t)
{
    return t.seconds == CMT_TIME_MIN_SECONDS && t.nanos == 0;
}

/* gogoproto v1.7.0 types/timestamp.go:61-75 — validateTimestamp() */
int cmt_time_validate(cmt_time_t t)
{
    if (t.seconds < CMT_TIME_MIN_SECONDS) {          /* timestamp.go:65-67 */
        return CMT_REJECT;
    }
    if (t.seconds >= CMT_TIME_MAX_SECONDS) {         /* timestamp.go:68-70 */
        return CMT_REJECT;
    }
    if (t.nanos < 0 || t.nanos >= CMT_TIME_NANOS_PER_SECOND) {  /* :71-73 */
        return CMT_REJECT;
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/time/time.go:16-18 — Canonical().
 * The identity on this representation; see the header for why. */
int cmt_time_canonical(cmt_time_t t, cmt_time_t *out)
{
    int rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_time_validate(t);
    if (rc != CMT_OK) {
        return rc;
    }
    *out = t;
    return CMT_OK;
}

/* Go `time.Time.UnixNano()`. It was the sort key of types/time/time.go:45
 * up to 709fd12b; since cometbft v0.38.26 that sort uses Time.Before
 * (cmt_wt_less below), and this function serves the scheduling callers
 * (cmt_cs.c, cmt_conr.c, cmt_memr.c, cmt_bsync_reactor.c). Computed in
 * uint64 so the overflow WRAPS as Go's int64 arithmetic does, instead of
 * being undefined as C signed overflow is. */
int64_t cmt_time_unix_nano(cmt_time_t t)
{
    uint64_t ns;

    ns = (uint64_t)t.seconds * (uint64_t)1000000000u;
    ns += (uint64_t)(int64_t)t.nanos;
    /* Implementation-defined for values above INT64_MAX before C23, but
     * two's complement on every target this project builds for; the cast
     * reproduces Go's wrap. */
    return (int64_t)ns;
}

/** Go `time.Time.After` — strictly later. (Moved from cmt_cs.c's static
 *  cs_time_after, body unchanged; see cmt_time.h.) */
bool cmt_time_after(cmt_time_t a, cmt_time_t b)
{
    if (a.seconds != b.seconds) {
        return a.seconds > b.seconds;
    }
    return a.nanos > b.nanos;
}

/** Go `time.Time.Before` — strictly earlier: b is after a. */
bool cmt_time_before(cmt_time_t a, cmt_time_t b)
{
    return cmt_time_after(b, a);
}

/**
 * Go `t.Add(d)` for a nanosecond duration, with the carry `cmt_time_t`
 * needs (nanos always in [0, 1e9) — cmt_time.h:89-91). The arithmetic is
 * formed in unsigned words because Go's int64 arithmetic wraps and C's
 * signed overflow is undefined; the value is identical wherever the
 * reference is itself well defined. Same shape as cmt_config.h:205-231.
 * (Moved from cmt_cs.c's static cs_time_add_ns, body unchanged.)
 */
cmt_time_t cmt_time_add_ns(cmt_time_t t, int64_t ns)
{
    cmt_time_t out;
    int64_t    add_secs;
    int64_t    add_nanos;
    uint64_t   secs;
    int64_t    nanos;

    add_secs  = ns / (int64_t)1000000000;
    add_nanos = ns % (int64_t)1000000000;

    secs  = (uint64_t)t.seconds + (uint64_t)add_secs;
    nanos = (int64_t)t.nanos + add_nanos;
    if (nanos >= (int64_t)CMT_TIME_NANOS_PER_SECOND) {
        nanos -= (int64_t)CMT_TIME_NANOS_PER_SECOND;
        secs  += 1u;
    } else if (nanos < 0) {
        nanos += (int64_t)CMT_TIME_NANOS_PER_SECOND;
        secs  -= 1u;
    }
    out.seconds = (int64_t)secs;
    out.nanos   = (int32_t)nanos;
    return out;
}

/* cometbft@v0.38.26 types/time/time.go:27-32 — NewWeightedTime() */
int cmt_new_weighted_time(cmt_time_t t, int64_t weight,
                          cmt_weighted_time_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    out->time   = t;                                 /* time.go:29 */
    out->weight = weight;                            /* time.go:30 */
    return CMT_OK;
}

/* The comparator of cometbft@v0.38.26 types/time/time.go:38-46, written
 * out. Returns true when a must sort before b.
 *   a == NULL             -> false  (:39-41: a nil is never "less")
 *   b == NULL, a != NULL  -> true   (:42-44: everything precedes a nil)
 *   otherwise             -> a.Time.Before(b.Time)       (:45)
 * Go's Time.Before compares the instant — seconds first, then
 * nanoseconds — over the WHOLE range. At 709fd12b :45 compared UnixNano,
 * which wraps outside ~1678..2262, so a valid year-9999 stamp sorted
 * BELOW every present-day one. `nanos` is in [0, 1e9) for every valid
 * time (cmt_time_validate), so (seconds, nanos) order IS instant order. */
static bool cmt_wt_less(const cmt_weighted_time_t *a,
                        const cmt_weighted_time_t *b)
{
    if (a == NULL) {
        return false;
    }
    if (b == NULL) {
        return true;
    }
    if (a->time.seconds != b->time.seconds) {
        return a->time.seconds < b->time.seconds;
    }
    return a->time.nanos < b->time.nanos;
}

/* cometbft@v0.38.26 types/time/time.go:35-58 — WeightedMedian()
 * (line numbers identical to 709fd12b; only :45 changed). */
int cmt_weighted_median(const cmt_weighted_time_t **weighted_times, size_t n,
                        int64_t total_voting_power, cmt_time_t *out)
{
    int64_t median;
    size_t  i;

    if (out == NULL || (weighted_times == NULL && n != 0)) {
        return CMT_FAULT;
    }
    /* time.go:35 names the result and never assigns it when nothing is
     * selected, so the fallback is Go's ZERO time, not the Unix epoch. */
    *out = CMT_TIME_ZERO;

    median = total_voting_power / 2;                 /* time.go:36 */

    /* time.go:38-46 sorts the caller's slice in place. Insertion sort is
     * used here because it is STABLE, which removes the reference's
     * order-dependence on equal sort keys (see the header) while producing
     * the same sequence wherever the reference is well-defined. n is the
     * validator count (<= 128), so the quadratic worst case is bounded and
     * tiny; nothing here depends on timing. */
    for (i = 1; i < n; i++) {
        const cmt_weighted_time_t *key = weighted_times[i];
        size_t j = i;

        while (j > 0 && cmt_wt_less(key, weighted_times[j - 1])) {
            weighted_times[j] = weighted_times[j - 1];
            j--;
        }
        weighted_times[j] = key;
    }

    for (i = 0; i < n; i++) {                        /* time.go:48-56 */
        const cmt_weighted_time_t *wt = weighted_times[i];

        if (wt != NULL) {                            /* time.go:49 */
            if (median <= wt->weight) {              /* time.go:50-53 */
                *out = wt->time;
                break;
            }
            median -= wt->weight;                    /* time.go:54 */
        }
    }
    return CMT_OK;
}
