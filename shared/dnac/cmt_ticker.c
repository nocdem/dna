/**
 * @file shared/dnac/cmt_ticker.c
 * @brief cometbft @709fd12b `consensus/ticker.go` in C — see cmt_ticker.h
 *        for the contract, the host's obligations and the taşınmadı list.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_ticker.h"

#include <string.h>

/* cometbft@709fd12b consensus/ticker.go:41-53 — NewTimeoutTicker().
 * :43 creates the timer, :46 marks it active, :51 stops it again — so the
 * ticker begins NOT ARMED with a zero `ti`. */
int cmt_ticker_init(cmt_ticker_t *t)
{
    if (t == NULL) {
        return CMT_FAULT;
    }
    memset(t, 0, sizeof(*t));
    t->timer_active = false;                                 /* :51 */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/ticker.go:83-92 —
 * (t *timeoutTicker) stopTimer() */
int cmt_ticker_stop_timer(cmt_ticker_t *t, bool *out_cancel)
{
    if (t == NULL || out_cancel == NULL) {
        return CMT_FAULT;
    }
    if (!t->timer_active) {
        *out_cancel = false;                                 /* :84-86 */
        return CMT_OK;
    }
    /* :88-90 — Stop(), and drain the channel when it had already fired.
     * Both are the host's; this reports that they are due. */
    *out_cancel     = true;
    t->timer_active = false;                                 /* :91 */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/ticker.go:76-81 ScheduleTimeout() together
 * with the tick branch of timeoutRoutine(), :104-129. */
int cmt_ticker_schedule_timeout(cmt_ticker_t *t,
                                const cmt_timeout_info_t *ti,
                                cmt_ticker_action_t *out_action)
{
    bool cancel = false;

    if (t == NULL || ti == NULL || out_action == NULL) {
        return CMT_FAULT;
    }
    out_action->cancel_previous = false;
    out_action->arm             = false;
    out_action->duration        = 0;

    /* :107-118 — ignore tickers for old height/round/step. */
    if (ti->height < t->ti.height) {
        return CMT_OK;                                       /* :108-109 */
    }
    if (ti->height == t->ti.height) {                        /* :110 */
        if (ti->round < t->ti.round) {
            return CMT_OK;                                   /* :111-112 */
        }
        if (ti->round == t->ti.round) {                      /* :113 */
            if (t->ti.step > 0u && ti->step <= t->ti.step) {
                return CMT_OK;                               /* :114-116 */
            }
        }
    }

    /* :120-121 — stop the last timer if it exists. */
    if (cmt_ticker_stop_timer(t, &cancel) != CMT_OK) {
        return CMT_FAULT;
    }
    out_action->cancel_previous = cancel;

    /* :123-127 — update timeoutInfo, reset the timer, mark it active.
     * The duration is passed through unchanged, non-positive included
     * (:124). */
    t->ti           = *ti;                                   /* :125 */
    out_action->arm      = true;                             /* :126 */
    out_action->duration = t->ti.duration;
    t->timer_active = true;                                  /* :127 */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/ticker.go:130-137 — the timer branch. */
int cmt_ticker_fire(cmt_ticker_t *t, cmt_timeout_info_t *out_ti)
{
    if (t == NULL || out_ti == NULL) {
        return CMT_FAULT;
    }
    if (!t->timer_active) {
        /* Unreachable in the reference: stopTimer drains a fired-but-
         * unread expiry (:88-90) so this branch is only taken for a timer
         * that is genuinely armed. Reaching it means the host delivered a
         * stale expiry — a local defect. See cmt_ticker.h. */
        return CMT_FAULT;
    }
    t->timer_active = false;                                 /* :131 */
    *out_ti         = t->ti;                                 /* :137 */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/ticker.go:138-140 — the quit branch. */
int cmt_ticker_stop(cmt_ticker_t *t, bool *out_cancel)
{
    if (t == NULL || out_cancel == NULL) {
        return CMT_FAULT;
    }
    return cmt_ticker_stop_timer(t, out_cancel);             /* :139 */
}
