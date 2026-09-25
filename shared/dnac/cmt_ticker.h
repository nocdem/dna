/**
 * @file shared/dnac/cmt_ticker.h
 * @brief cometbft @709fd12b `consensus/ticker.go` in C — the timeout
 *        ticker's DECISION, without its goroutine.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything here yet; additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THE REFERENCE IS, AND WHAT IS PORTED ──────────────────────────
 * The reference is one goroutine (`timeoutRoutine`, ticker.go:99-143)
 * selecting over three channels: a tick to schedule, the `time.Timer`
 * firing, and a quit. Two things live inside it — a `time.Timer` and the
 * RULE that decides whether an incoming tick replaces the pending timeout.
 *
 * The RULE is ported here, as a synchronous state machine. The TIMER is
 * the host's: this port replaces goroutines and channels with one event
 * loop (umbrella rev 3, the behavioural determinization), so the host owns
 * exactly one real timer and drives it from what these functions return.
 *
 * ── THE HOST'S OBLIGATIONS, EACH WITH THE GO LINE IT COMES FROM ────────
 *  1. `cmt_ticker_schedule_timeout` returns an action. When
 *     `cancel_previous` is set, the host MUST cancel its timer and, if the
 *     timer had already fired and the expiry has not been consumed yet,
 *     DISCARD that expiry — that is `stopTimer`'s `if !t.timer.Stop() {
 *     <-t.timer.C }` (ticker.go:88-90), whose whole purpose is that a
 *     fired-but-unread timeout never reaches the state machine.
 *  2. When `arm` is set, the host arms its timer for `duration`
 *     NANOSECONDS — `t.timer.Reset(ti.Duration)` (:126).
 *  3. `duration` MAY BE ZERO OR NEGATIVE. The reference says so twice
 *     (:16 "The timeoutInfo.Duration may be non-positive", :124 "NOTE
 *     time.Timer allows duration to be non-positive") and Go's timer fires
 *     immediately for those. A host that clamps or refuses a non-positive
 *     duration changes the state machine's behaviour.
 *  4. When the host's timer expires it calls `cmt_ticker_fire`, which
 *     hands back the pending `timeoutInfo` — the `tockChan` send of :137.
 *  5. On shutdown the host calls `cmt_ticker_stop`, the `<-t.Quit()` case
 *     of :138-140.
 *
 * taşınmadı, with the reason:
 *   · `tickTockBufferSize` (:11) and the `tickChan` / `tockChan` of
 *     :47-48 — channel depths. The single-threaded port has no channels;
 *     scheduling is a direct call and the expiry is a direct call back.
 *   · the `TimeoutTicker` interface (:17-24), `OnStart` (:56-61),
 *     `OnStop` (:64-66) and `Chan` (:69-71) — service plumbing and the
 *     goroutine's start/stop, HOST.
 *   · `service.BaseService` (:32) and its logging.
 *   · the `go func(toi timeoutInfo) { ... }` of :137 — a goroutine that
 *     exists so the routine cannot block on a full channel. With a direct
 *     call there is nothing to block on. The reference's own comment at
 *     :134 says determinism comes from the receiveRoutine's playback, not
 *     from this goroutine.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * NO CLOCK IS READ HERE. The rule is a pure function of the pending
 * timeoutInfo and the incoming one; the only thing that varies between
 * nodes is WHEN the host's timer expires, which is what a timeout is.
 * The state machine's decisions are identical on every node given the same
 * sequence of calls.
 *
 * Reference @709fd12b: consensus/ticker.go, 143 lines, SHA-256
 * f08d7195f0a6ba820243d0e6aed9499f1cc334984a665d5d0bd6da394de1b26c.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_TICKER_H
#define SHARED_DNAC_CMT_TICKER_H

#include <stdint.h>
#include <stdbool.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "cmt_msgs.h"     /* cmt_timeout_info_t               */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cometbft@709fd12b consensus/ticker.go:31-38 —
 * `type timeoutTicker struct`, minus everything that is a channel, a
 * goroutine or a logger.
 *
 * `ti` is the routine's own `var ti timeoutInfo` (:101). Its ZERO VALUE is
 * the initial state and the rule at :108-118 is written against it — in
 * particular the `ti.Step > 0` guard at :114 is what lets the very first
 * tick through while `ti` is still zero. Do not initialise it to anything
 * else.
 */
typedef struct {
    bool               timer_active;   /* ticker.go:34 */
    cmt_timeout_info_t ti;             /* ticker.go:101 */
} cmt_ticker_t;

/** What the host must do to its timer after a call. */
typedef struct {
    /** `stopTimer()` ran: cancel the timer and discard an expiry that has
     *  already happened but has not been delivered (ticker.go:83-92). */
    bool    cancel_previous;
    /** Arm the timer for `duration` (ticker.go:126). */
    bool    arm;
    /** Nanoseconds; MAY BE ZERO OR NEGATIVE (ticker.go:16, :124). */
    int64_t duration;
} cmt_ticker_action_t;

/**
 * cometbft@709fd12b consensus/ticker.go:41-53 — `NewTimeoutTicker()`.
 *
 * The reference creates a timer, marks it active (:46) and then calls
 * `stopTimer()` (:51) precisely so nothing fires before the first
 * scheduled timeout. The net state is: NOT ARMED, `ti` zero — which is
 * what this leaves.
 *
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_ticker_init(cmt_ticker_t *t);

/**
 * cometbft@709fd12b consensus/ticker.go:83-92 —
 * `(t *timeoutTicker) stopTimer()`.
 *
 * `if !t.timerActive { return }` (:84-86), then stop and drain (:88-90),
 * then `t.timerActive = false` (:91).
 *
 * @param out_cancel true when the host must cancel and drain — i.e. when
 *        the timer was active. False means there was nothing to stop and
 *        the host must do nothing.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_ticker_stop_timer(cmt_ticker_t *t, bool *out_cancel);

/**
 * cometbft@709fd12b consensus/ticker.go:76-81 `ScheduleTimeout()` and the
 * tick branch of `timeoutRoutine()`, :104-129.
 *
 * The reference's `ScheduleTimeout` only pushes onto `tickChan`; the
 * decision is made when the routine reads it, so the two are one function
 * here. THE RULE, exactly as :108-118 writes it:
 *   · a LOWER height is dropped (:108-109);
 *   · at the SAME height, a lower round is dropped (:110-112);
 *   · at the same height AND round, a step is dropped when
 *     `ti.Step > 0 && newti.Step <= ti.Step` (:114-116) — note both
 *     halves: while the pending step is 0 nothing is dropped, so an
 *     incoming step 0 gets through, and so does a repeat of step 0.
 * Anything not dropped stops the old timer (:121), becomes the pending
 * timeout (:125) and arms the timer for its duration (:126-127).
 *
 * @param out_action what the host must do; never NULL. A dropped tick
 *        leaves it all false, which is the reference's `continue`.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_ticker_schedule_timeout(cmt_ticker_t *t,
                                const cmt_timeout_info_t *ti,
                                cmt_ticker_action_t *out_action);

/**
 * cometbft@709fd12b consensus/ticker.go:130-137 — the timer branch of
 * `timeoutRoutine()`. The host calls this when its timer expires.
 *
 * `t.timerActive = false` (:131) and the pending `ti` is handed to the
 * caller, which is the `tockChan <- ti` of :137.
 *
 * @param out_ti receives the timeout that fired.
 * @return CMT_OK; CMT_FAULT on NULL, or when no timer was armed — in the
 *         reference that branch can only be taken because the channel
 *         fired, and `stopTimer` drains a stale expiry precisely so this
 *         cannot happen, so reaching it means the HOST failed obligation
 *         1 above. It is a local defect, never a peer's doing.
 */
int cmt_ticker_fire(cmt_ticker_t *t, cmt_timeout_info_t *out_ti);

/**
 * cometbft@709fd12b consensus/ticker.go:138-140 — the quit branch of
 * `timeoutRoutine()`: `stopTimer()` and return.
 *
 * @param out_cancel as `cmt_ticker_stop_timer`.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_ticker_stop(cmt_ticker_t *t, bool *out_cancel);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_TICKER_H */
