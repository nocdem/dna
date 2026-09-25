/**
 * @file shared/dnac/cmt_time.h
 * @brief cometbft @709fd12b `types/time/time.go` ported to C — BFT-time.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-A of the cometbft → C consensus port. Additive only. NOTHING IN
 * THIS FILE READS A CLOCK — see "The clock" below.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── The time value ─────────────────────────────────────────────────────
 * A time is {int64 seconds; int32 nanos}, the shape of
 * google.protobuf.Timestamp (K-1 rev 2 rule c,
 * atlas-dec-3ba8153088b0d60c63083028023b61be), because that is what goes
 * on the wire and into every hash. Valid range, from gogoproto
 * v1.7.0 types/timestamp.go:45-48 and :61-75:
 *     seconds in [-62135596800, 253402300800)   lower bound INCLUSIVE
 *     nanos   in [0, 1e9)
 *
 * ⚠ A ZERO-INITIALISED cmt_time_t IS NOT GO'S ZERO TIME. `{0, 0}` is
 * 1970-01-01 (the Unix epoch), which marshals to ZERO BYTES. Go's zero
 * `time.Time` is 0001-01-01, i.e. seconds = -62135596800, which marshals
 * to the eleven bytes 08 80 92 b8 c3 98 fe ff ff ff 01. Anywhere the
 * reference leaves a time.Time at its zero value — an Absent CommitSig
 * (types/block.go:616-620), a vote that carries no time, the fallback of
 * WeightedMedian below — the correct C value is CMT_TIME_ZERO, never a
 * memset. Getting this wrong changes bytes that are inside BlockID and
 * therefore inside every signature.
 *
 * ── The clock ──────────────────────────────────────────────────────────
 * `Now()` (time.go:9-11) is HOST, not ported: it is the single place the
 * reference reads a wall clock, and under the APPROVED clock POLICY
 * (atlas-dec-4ac0423068085c100fdfa3e264ca16bc) the port routes every clock
 * read in a ported body through one host callback. This header declares
 * only the callback's TYPE. No function in wave R1-A calls it and no
 * translation unit here links a clock. The host supplies the callback in a
 * later wave; the sites that will use it are listed in
 * tasks/comet-port-map.md ("Saat okuma yerleri — TAM liste").
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * cmt_time_canonical, cmt_time_unix_nano, cmt_new_weighted_time and
 * cmt_weighted_median are pure functions of their arguments. The median is
 * the value every validator must reach identically from the previous
 * commit's timestamps (BFT-time, D-20), so its ordering is fully specified
 * below — see cmt_weighted_median's note on the reference's unstable sort.
 *
 * Reference @709fd12b: types/time/time.go, 58 lines,
 * a7c231ae400d7e2520c2d721bc6162dcd57a1f815df86752db996c6f74a88a2e.
 * (`libs/time/time.go`, named in the port map's rev-1 pin table, does not
 * exist in this tree; types/time/time.go is the file.)
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_TIME_H
#define SHARED_DNAC_CMT_TIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT */

#ifdef __cplusplus
extern "C" {
#endif

/** gogoproto v1.7.0 types/timestamp.go:45 — `minValidSeconds`. Also the
 *  seconds field of Go's zero time.Time (0001-01-01T00:00:00Z). */
#define CMT_TIME_MIN_SECONDS ((int64_t)-62135596800)
/** gogoproto v1.7.0 types/timestamp.go:48 — `maxValidSeconds`, EXCLUSIVE. */
#define CMT_TIME_MAX_SECONDS ((int64_t)253402300800)
/** Nanoseconds per second; the exclusive upper bound on `nanos`. */
#define CMT_TIME_NANOS_PER_SECOND ((int32_t)1000000000)

/** A point in time, in the shape google.protobuf.Timestamp puts on the
 *  wire. `nanos` is always in [0, 1e9) for a valid value: Go normalises,
 *  it never carries a negative nanosecond remainder. */
typedef struct {
    int64_t seconds;
    int32_t nanos;
} cmt_time_t;

/** Go's zero `time.Time`. Use this, never `{0, 0}` — see the header. */
#define CMT_TIME_ZERO ((cmt_time_t){ CMT_TIME_MIN_SECONDS, 0 })

/**
 * Go `time.Time.IsZero()` — "reports whether t represents the zero time
 * instant, January 1, year 1, 00:00:00 UTC".
 *
 * ⚠ THE SAME WARNING AS CMT_TIME_ZERO: this is TRUE for
 * {CMT_TIME_MIN_SECONDS, 0} and FALSE for a memset-zeroed `cmt_time_t`,
 * which is 1970. Every reference site that tests a time for zero means
 * year one — see the file header.
 *
 * The pinned tree tests a `time.Time` for zero in exactly TWO places
 * (`grep -n '\.IsZero()' types/ state/`, every other hit is a BlockID or a
 * PartSetHeader, a different type):
 *   · types/block.go:668     `CommitSig.ValidateBasic` — an ABSENT entry
 *                            must carry the zero time.
 *   · types/genesis.go:101   `GenesisDoc.ValidateAndComplete` — a zero
 *                            genesis time is completed from the clock.
 *
 * It lived in cmt_genesis.{h,c} through wave R1-C — the wrong home, since
 * it is a property of a time and cmt_block.c had to keep a private copy of
 * it. Wave R1-D moved it here; both call sites now use this one function
 * and the behaviour is unchanged.
 */
bool cmt_time_is_zero(cmt_time_t t);

/**
 * cometbft@709fd12b types/time/time.go:9-11 — `Now()`, HOST.
 *
 * The type only. A host that supplies this MUST return a canonical UTC
 * time, i.e. what `Canonical(time.Now())` produces. It is not called
 * anywhere in wave R1-A.
 *
 * @param ctx opaque host context.
 * @param out receives the current time.
 * @return CMT_OK, or CMT_FAULT if the host has no usable clock.
 */
typedef int (*cmt_now_fn)(void *ctx, cmt_time_t *out);

/**
 * cometbft@709fd12b types/time/time.go:16-18 — `Canonical()`.
 *
 * The reference computes `t.Round(0).UTC()`: `Round(0)` strips the
 * monotonic clock reading and `.UTC()` sets the location to UTC. NEITHER
 * CHANGES THE INSTANT — they change only representation details that a
 * Go time.Time carries and a {seconds, nanos} pair does not have. On this
 * representation Canonical is therefore the IDENTITY, and this function
 * exists so that the ported call sites read like the reference and so that
 * the reasoning above is recorded at the place it applies. It still
 * validates, so a caller cannot canonicalise an out-of-range value into
 * the consensus path.
 *
 * @return CMT_OK, CMT_REJECT if `t` is out of range, CMT_FAULT on NULL.
 */
int cmt_time_canonical(cmt_time_t t, cmt_time_t *out);

/**
 * gogoproto v1.7.0 types/timestamp.go:61-75 — `validateTimestamp()`.
 * The check every decoded Timestamp passes (K-1 rev 2 rule c); shared with
 * cmt_pb so there is one definition of "a valid time" in the port.
 * @return CMT_OK or CMT_REJECT.
 */
int cmt_time_validate(cmt_time_t t);

/**
 * Go `time.Time.UnixNano()` — seconds*1e9 + nanos, as an int64 that WRAPS.
 *
 * This is not a convenience: it is the exact sort key the reference uses
 * at types/time/time.go:45, and Go's int64 arithmetic wraps on overflow by
 * specification. The wrap is reproduced here with unsigned arithmetic
 * (C signed overflow is undefined), so the ordering matches the reference
 * bit for bit, including for the times where the reference's ordering is
 * itself surprising: UnixNano overflows outside roughly
 * [1677-09-21, 2262-04-11], while the Timestamp range reaches year 9999.
 */
int64_t cmt_time_unix_nano(cmt_time_t t);

/** cometbft@709fd12b types/time/time.go:21-24 — `type WeightedTime`. */
typedef struct {
    cmt_time_t time;      /* time.go:22 */
    int64_t    weight;    /* time.go:23 */
} cmt_weighted_time_t;

/**
 * cometbft@709fd12b types/time/time.go:27-32 — `NewWeightedTime()`.
 * A plain field-for-field constructor; it validates nothing, exactly as
 * the reference does not.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_new_weighted_time(cmt_time_t t, int64_t weight,
                          cmt_weighted_time_t *out);

/**
 * cometbft@709fd12b types/time/time.go:35-58 — `WeightedMedian()`.
 * The block time of BFT-time: the weighted median of the previous
 * commit's vote timestamps.
 *
 * The walk, line by line: `median = totalVotingPower / 2` (:36, truncating
 * division — C99 and Go truncate toward zero identically); the entries are
 * sorted ascending by UnixNano with NULLs last (:38-46); then the first
 * entry whose weight is at least the remaining median is the answer, and
 * every entry passed over subtracts its weight from the remaining median
 * (:48-56). NULL entries are skipped (:49).
 *
 * If the loop never selects — an empty array, all-NULL entries, or weights
 * that never reach the median — the result is Go's zero time (:35 names
 * the result `res` and never assigns it), i.e. CMT_TIME_ZERO, NOT the
 * Unix epoch.
 *
 * ⚠ THE ARRAY IS REORDERED IN PLACE, exactly as the reference's
 * `sort.Slice` reorders the caller's slice (:38). A caller that needs its
 * original order must copy first.
 *
 * NOTE reference quirk: Go's `sort.Slice` is NOT STABLE. Two entries whose
 * UnixNano values are equal can be ordered either way, and if their
 * WEIGHTS differ the running subtraction visits them in an unspecified
 * order. This is harmless wherever equal UnixNano implies an equal time
 * value — which holds for every time inside the UnixNano range, since
 * seconds*1e9 + nanos is injective there. It does NOT hold once UnixNano
 * wraps, where two different instants can share a sort key. This port
 * sorts with a STABLE insertion sort, so two DNA nodes always agree with
 * each other; agreement with Go is exact wherever Go is itself
 * well-defined. A later wave must keep vote timestamps inside the
 * non-wrapping range for the two to coincide everywhere.
 *
 * @param weighted_times array of n pointers; an entry may be NULL.
 * @return CMT_OK, CMT_FAULT on NULL arguments.
 */
int cmt_weighted_median(const cmt_weighted_time_t **weighted_times, size_t n,
                        int64_t total_voting_power, cmt_time_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_TIME_H */
