/**
 * Nodus — cometbft @709fd12b C port, wave R2-B: the timeout ticker's
 * decision (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the rule deciding whether an incoming timeout REPLACES the pending
 * one is consensus/ticker.go:108-118, branch for branch. If this file
 * failed, one of these would be false:
 *   · a fresh ticker is NOT armed and its pending timeout is the zero one
 *     — the reference builds a timer, marks it active and immediately
 *     stops it (ticker.go:43-51), and every later comparison is made
 *     against that zero;
 *   · a LOWER height is dropped; at the SAME height a lower round is
 *     dropped; at the same height AND round a step is dropped only when
 *     `ti.Step > 0 && newti.Step <= ti.Step` — so while the pending step
 *     is still 0 nothing is dropped, which is what lets the FIRST timeout
 *     of a height through;
 *   · a schedule that is accepted always tells the host to cancel the
 *     previous timer first (the `stopTimer()` of :121) and then to arm
 *     for the new duration (:126), and a dropped one tells it to do
 *     NOTHING;
 *   · a NON-POSITIVE duration is passed through unchanged, because the
 *     reference says twice that it may be one (:16, :124);
 *   · the expiry hands back the timeout that was pending and clears the
 *     armed flag (:131-137), and a second expiry with nothing armed is a
 *     FAULT rather than a phantom timeout.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, NO CLOCK — the test drives the expiry itself, which
 * is the whole point of the port's shape. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no processes, no allocation at all: every fixture is
 * a stack value.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THERE IS NO REAL TIMER HERE. The host owns it, and every obligation
 *     this port places on the host — cancel, DRAIN a fired-but-unread
 *     expiry, arm for a possibly non-positive duration — is asserted only
 *     as a returned FLAG. A host that ignores the flags would still let
 *     this file pass and would still misbehave. Those are wave R3's tests.
 *  2. It exercises the rule as a sequence of direct calls. The reference
 *     runs it in a goroutine reading a 10-deep channel, and the ORDER in
 *     which two ticks arrive is the host's business here; a green says
 *     nothing about the host's queueing.
 *  3. `cmt_ticker_fire` is called by the test whenever it likes. Nothing
 *     here proves that the host calls it only when its timer really
 *     expired.
 *
 * ── REFERENCE TEST CASES PORTED ────────────────────────────────────────
 * consensus/ticker_test.go (40 lines, pinned by rev 6, SHA-256
 * 71bf7a5581ee057b5a8d83724d118e59dfec523d98ad3e346090c86810983747):
 * `TestTimeoutTicker` (:12-39) — schedule, then receive the tock. Its
 * wall-clock wait becomes a direct `cmt_ticker_fire`, because the port
 * has no timer to wait on.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_ticker.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static cmt_timeout_info_t ti_of(int64_t h, int32_t r, uint8_t s, int64_t d)
{
    cmt_timeout_info_t ti;

    memset(&ti, 0, sizeof(ti));
    ti.height   = h;
    ti.round    = r;
    ti.step     = s;
    ti.duration = d;
    return ti;
}

/* ══ construction ═════════════════════════════════════════════════════ */

static int test_new(void)
{
    cmt_ticker_t t;
    bool         cancel = true;

    CHECK(cmt_ticker_init(&t) == CMT_OK, "NewTimeoutTicker");
    /* ticker.go:46 marks the timer active and :51 stops it again, so the
     * net state is NOT armed — "don't want to fire until the first
     * scheduled timeout". */
    CHECK(!t.timer_active, "a fresh ticker is not armed");
    CHECK(t.ti.height == 0 && t.ti.round == 0 && t.ti.step == 0 &&
          t.ti.duration == 0,
          "and its pending timeout is the zero one (ticker.go:101)");
    CHECK(cmt_ticker_stop_timer(&t, &cancel) == CMT_OK && !cancel,
          "stopping a ticker that is not armed asks the host for nothing"
          " (ticker.go:84-86)");
    OK();

    CHECK(cmt_ticker_init(NULL) == CMT_FAULT, "NULL");
    CHECK(cmt_ticker_stop_timer(&t, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

/* ══ the ignore rule, one row per branch of ticker.go:108-118 ═════════ */

static int test_ignore_rule(void)
{
    /* Each row: the PENDING timeout, then the incoming one, then whether
     * the reference accepts it, and the line the branch comes from. */
    static const struct {
        int64_t     p_h;
        int32_t     p_r;
        uint8_t     p_s;
        int64_t     n_h;
        int32_t     n_r;
        uint8_t     n_s;
        int         accept;
        const char *why;
    } rows[] = {
        /* :108-109 — a LOWER height is dropped. */
        { 5, 0, 0,  4, 9, 9, 0, "lower height dropped (:108)" },
        /* a HIGHER height is always accepted, whatever the round/step. */
        { 5, 9, 9,  6, 0, 0, 1, "higher height accepted (:108 false)" },
        /* :110-112 — the same height with a lower round is dropped. */
        { 5, 3, 0,  5, 2, 9, 0, "same height, lower round dropped (:111)" },
        /* the same height with a higher round is accepted. */
        { 5, 3, 9,  5, 4, 0, 1, "same height, higher round accepted" },
        /* :113-116 — the same height AND round. The guard has TWO halves.
         * While the pending step is 0, NOTHING is dropped: */
        { 5, 3, 0,  5, 3, 0, 1, "pending step 0 lets step 0 through"
                                " (:114 `ti.Step > 0` is false)" },
        { 5, 3, 0,  5, 3, 1, 1, "pending step 0 lets any step through" },
        /* once it is non-zero, an equal or lower step is dropped: */
        { 5, 3, 2,  5, 3, 1, 0, "lower step dropped (:114)" },
        { 5, 3, 2,  5, 3, 2, 0, "EQUAL step dropped (:114 `<=`)" },
        { 5, 3, 2,  5, 3, 3, 1, "higher step accepted" },
        /* and a step of 0 arriving at a non-zero pending step is dropped,
         * because 0 <= 2. */
        { 5, 3, 2,  5, 3, 0, 0, "step 0 dropped once the pending step is"
                                " non-zero" },
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_ticker_t        t;
        cmt_ticker_action_t a;
        cmt_timeout_info_t  first;
        cmt_timeout_info_t  next;

        CHECK(cmt_ticker_init(&t) == CMT_OK, "init");

        /* Put the ticker in the pending state the row describes. The
         * FIRST schedule always passes the rule from the zero state. */
        first = ti_of(rows[i].p_h, rows[i].p_r, rows[i].p_s, 1000);
        CHECK(cmt_ticker_schedule_timeout(&t, &first, &a) == CMT_OK,
              "arming the pending timeout");
        CHECK(a.arm, "the first schedule is always accepted from zero");

        next = ti_of(rows[i].n_h, rows[i].n_r, rows[i].n_s, 2000);
        CHECK(cmt_ticker_schedule_timeout(&t, &next, &a) == CMT_OK,
              rows[i].why);
        if (rows[i].accept) {
            CHECK(a.arm, rows[i].why);
            CHECK(a.cancel_previous,
                  "an accepted tick stops the last timer first (:121)");
            CHECK(a.duration == 2000,
                  "and arms for the NEW duration (:126)");
            CHECK(t.ti.height == rows[i].n_h && t.ti.round == rows[i].n_r &&
                  t.ti.step == rows[i].n_s,
                  "and the pending timeout becomes the new one (:125)");
            CHECK(t.timer_active, "and the timer is marked active (:127)");
        } else {
            CHECK(!a.arm && !a.cancel_previous && a.duration == 0,
                  rows[i].why);
            CHECK(t.ti.height == rows[i].p_h && t.ti.round == rows[i].p_r &&
                  t.ti.step == rows[i].p_s,
                  "and the pending timeout is untouched (`continue`)");
        }
        OK();
    }
    return 0;
}

/* ══ the durations the reference allows ═══════════════════════════════ */

static int test_non_positive_duration(void)
{
    cmt_ticker_t        t;
    cmt_ticker_action_t a;
    cmt_timeout_info_t  ti;

    CHECK(cmt_ticker_init(&t) == CMT_OK, "init");

    /* ticker.go:16 and :124 both say the duration may be non-positive,
     * and Go's timer fires immediately for those. Nothing here clamps. */
    ti = ti_of(1, 0, 1, 0);
    CHECK(cmt_ticker_schedule_timeout(&t, &ti, &a) == CMT_OK && a.arm &&
          a.duration == 0, "a ZERO duration is armed as zero");
    ti = ti_of(1, 0, 2, -5);
    CHECK(cmt_ticker_schedule_timeout(&t, &ti, &a) == CMT_OK && a.arm &&
          a.duration == -5, "and a NEGATIVE one is passed through");
    OK();
    return 0;
}

/* ══ the expiry ═══════════════════════════════════════════════════════ */

static int test_fire_and_stop(void)
{
    cmt_ticker_t        t;
    cmt_ticker_action_t a;
    cmt_timeout_info_t  ti;
    cmt_timeout_info_t  got;
    bool                cancel = false;

    /* ticker_test.go:12-39's scenario: schedule one timeout, then receive
     * it. The reference waits on a channel for the real timer; here the
     * host's expiry is a direct call. */
    CHECK(cmt_ticker_init(&t) == CMT_OK, "init");
    ti = ti_of(4, 2, 3, 250);
    CHECK(cmt_ticker_schedule_timeout(&t, &ti, &a) == CMT_OK && a.arm,
          "schedule");
    CHECK(cmt_ticker_fire(&t, &got) == CMT_OK, "the timer expires");
    CHECK(got.height == 4 && got.round == 2 && got.step == 3 &&
          got.duration == 250,
          "and the tock carries the timeout that was pending (:137)");
    CHECK(!t.timer_active, "the timer is no longer armed (:131)");
    OK();

    /* A second expiry with nothing armed is a HOST defect: stopTimer
     * drains a fired-but-unread expiry precisely so it cannot happen. */
    CHECK(cmt_ticker_fire(&t, &got) == CMT_FAULT,
          "an expiry with no armed timer is a FAULT, not a timeout");
    OK();

    /* After an expiry the pending timeout is UNCHANGED, so the ignore
     * rule still refuses an older tick — the reference keeps `ti` across
     * the fire (it is the routine's own variable, :101). */
    ti = ti_of(4, 2, 3, 999);
    CHECK(cmt_ticker_schedule_timeout(&t, &ti, &a) == CMT_OK && !a.arm,
          "the same H/R/S is still dropped after the expiry");
    ti = ti_of(4, 2, 4, 999);
    CHECK(cmt_ticker_schedule_timeout(&t, &ti, &a) == CMT_OK && a.arm,
          "and a later step is still accepted");
    CHECK(!a.cancel_previous,
          "with NOTHING to cancel, because the timer already fired"
          " (:84-86)");
    OK();

    /* ticker.go:138-140 — the quit branch stops the timer. */
    CHECK(cmt_ticker_stop(&t, &cancel) == CMT_OK && cancel,
          "stopping an armed ticker asks the host to cancel and drain");
    CHECK(!t.timer_active, "and it is no longer armed");
    CHECK(cmt_ticker_stop(&t, &cancel) == CMT_OK && !cancel,
          "stopping it again asks for nothing");
    OK();

    CHECK(cmt_ticker_fire(NULL, &got) == CMT_FAULT, "NULL");
    CHECK(cmt_ticker_stop(&t, NULL) == CMT_FAULT, "NULL out");
    CHECK(cmt_ticker_schedule_timeout(&t, NULL, &a) == CMT_FAULT, "NULL ti");
    OK();
    return 0;
}

int main(void)
{
    if (test_new() != 0)                   { return 1; }
    if (test_ignore_rule() != 0)           { return 1; }
    if (test_non_positive_duration() != 0) { return 1; }
    if (test_fire_and_stop() != 0)         { return 1; }

    printf("test_cmt_ticker: OK (%d groups)\n", g_checks);
    return 0;
}
