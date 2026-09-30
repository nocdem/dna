/**
 * @file shared/dnac/cmt_flowrate.h
 * @brief cometbft @v0.38.26 `libs/flowrate/flowrate.go` + `util.go` ported
 *        to C — the transfer-rate Monitor the MConnection throttles its
 *        send and receive routines with.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F2 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row 3, §9). Its only consumer is cmt_p2p_mconn (the same phase), which
 * nothing in the running node constructs yet. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IS PORTED ─────────────────────────────────────────────────────
 * The whole `Monitor` (flowrate.go:16-276) and the helpers of util.go it
 * uses (:13-54). NOT ported: `io.go` (`Reader` / `Writer` / `Limiter`,
 * io.go:12-133) — wrappers around io.Reader / io.Writer that nothing in
 * connection.go uses (connection.go:188-189 builds bare Monitors with
 * `flow.New(0, 0)`); `Percent.Float` / `Percent.String` (util.go:56-67)
 * — formatting only.
 *
 * ── THE CLOCK (DEVIATION R-P2P-15) ─────────────────────────────────────
 * The reference reads `time.Now()` inside the Monitor (util.go:21-23).
 * Here NO clock is read: every function that the reference lets read the
 * clock takes `now_ns`, the caller's MONOTONIC nanoseconds, and applies
 * util.go's 20 ms rounding to it (`clock()`, util.go:21-23). The
 * reference's `time.Now().Round(clockRate)` STRIPS the monotonic reading
 * (Go 1.21.5 src/time/time.go:1545-1546, local toolchain, not in the
 * pinned tarball), so the reference's Monitor measures WALL time; this
 * port measures monotonic time (p2p-port design §6 D3 "monotonic
 * clock"). The rounding grid is anchored at monotonic zero instead of
 * the process-start instant `czero` (util.go:18) — every value the
 * Monitor compares is a DIFFERENCE of two clock() values, so the anchor
 * cancels; `Status.start_ns` is reported on the caller's monotonic scale
 * instead of `clockToTime` (util.go:26-28).
 *
 * ── BLOCKING (DEVIATION R-P2P-16) ──────────────────────────────────────
 * `Limit(want, rate, block = true)` SLEEPS in `waitNextSample`
 * (flowrate.go:190-194, :260-276) until the next sample starts. One
 * event loop cannot sleep: here `cmt_flowrate_limit` with `block` set
 * returns at once with `*would_block = true` and `*retry_at_ns` — the
 * instant `waitNextSample` would have slept until (`current + sRate`,
 * at least `now + minWait`, :261-270). The caller calls again at or after
 * that instant; the second call's `update(0)` starts the new sample
 * (:230-245) exactly as the reference's wake-up does (:273), so the
 * outcome of the call that finally passes is the reference's outcome.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (p2p-port design §6 D1): the rates
 * throttle this node's own transport. The reference computes in float64
 * (flowrate.go:24-27, :231-242); so does this port (`double`, `exp`) —
 * floating point is allowed here because no value reaches a block, a
 * vote or any root.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_FLOWRATE_H
#define CMT_FLOWRATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** util.go:14 `clockRate` — the resolution of clock(): 20 ms. */
#define CMT_FLOWRATE_CLOCK_RATE_NS    (20LL * 1000 * 1000)
/** flowrate.go:51 — the default sampling rate, 5 × clockRate = 100 ms. */
#define CMT_FLOWRATE_DEFAULT_SAMPLE_NS (5LL * CMT_FLOWRATE_CLOCK_RATE_NS)
/** flowrate.go:54 — the default EMA window, 1 s. */
#define CMT_FLOWRATE_DEFAULT_WINDOW_NS (1000LL * 1000 * 1000)
/** flowrate.go:261 `minWait` — waitNextSample's shortest sleep, 5 ms. */
#define CMT_FLOWRATE_MIN_WAIT_NS      (5LL * 1000 * 1000)
/** flowrate.go:106 `timeRemLimit` = 999 h 59 m 59 s. */
#define CMT_FLOWRATE_TIME_REM_LIMIT_NS \
    ((999LL * 3600 + 59 * 60 + 59) * 1000LL * 1000 * 1000)

/** flowrate.go:16-35 `Monitor`. The mutex (:18) is dropped — one event
 *  loop owns the Monitor. Every `time.Duration` is int64 nanoseconds on
 *  the clock() scale (file header). */
typedef struct {
    bool    active;     /* :19 */
    int64_t start;      /* :20 transfer start time (clock value)          */
    int64_t bytes;      /* :21 total bytes transferred                    */
    int64_t samples;    /* :22 total samples taken                        */

    double  r_sample;   /* :24 most recent rate sample, bytes/s           */
    double  r_ema;      /* :25 EMA of r_sample                            */
    double  r_peak;     /* :26 max r_sample                               */
    double  r_window;   /* :27 EMA window, SECONDS                        */

    int64_t s_bytes;    /* :29 bytes since s_last                         */
    int64_t s_last;     /* :30 most recent sample time                    */
    int64_t s_rate;     /* :31 sampling rate                              */

    int64_t t_bytes;    /* :33 bytes expected in the transfer             */
    int64_t t_last;     /* :34 time of the last transfer of >= 1 byte     */
} cmt_flowrate_t;

/** flowrate.go:108-124 `Status`. `start_ns` is on the caller's monotonic
 *  scale (file header); `progress` is util.go:44 `Percent` (1/1000 %). */
typedef struct {
    int64_t  start_ns;   /* :111 */
    int64_t  bytes;      /* :112 */
    int64_t  samples;    /* :113 */
    int64_t  inst_rate;  /* :114 */
    int64_t  cur_rate;   /* :115 */
    int64_t  avg_rate;   /* :116 */
    int64_t  peak_rate;  /* :117 */
    int64_t  bytes_rem;  /* :118 */
    int64_t  duration;   /* :119 ns */
    int64_t  idle;       /* :120 ns */
    int64_t  time_rem;   /* :121 ns */
    uint32_t progress;   /* :122 */
    bool     active;     /* :123 */
} cmt_flowrate_status_t;

/** util.go:21-23 `clock()` — `now_ns` rounded to the nearest clockRate
 *  (half rounds up, Go's Time.Round). Exposed for the tests. */
int64_t cmt_flowrate_clock(int64_t now_ns);

/** util.go:31-33 `clockRound(d)`. */
int64_t cmt_flowrate_clock_round(int64_t d);

/** util.go:36-41 `round(x)` — nearest int64, non-negative values only. */
int64_t cmt_flowrate_round(double x);

/**
 * flowrate.go:49-65 `New(sampleRate, windowSize)`. A value <= 0 takes the
 * default (100 ms after clockRound, 1 s).
 */
void cmt_flowrate_init(cmt_flowrate_t *m, int64_t sample_rate_ns,
                       int64_t window_size_ns, int64_t now_ns);

/** flowrate.go:69-74 `Update(n)` — records n bytes, returns n. */
int cmt_flowrate_update(cmt_flowrate_t *m, int n, int64_t now_ns);

/** flowrate.go:77-82 `SetREMA` — the reference's own "hack"; its one
 *  consumer is blocksync/pool.go:624. */
void cmt_flowrate_set_rema(cmt_flowrate_t *m, double r_ema);

/** flowrate.go:93-103 `Done()` — returns the total bytes transferred. */
int64_t cmt_flowrate_done(cmt_flowrate_t *m, int64_t now_ns);

/** flowrate.go:128-164 `Status()`. */
void cmt_flowrate_status(cmt_flowrate_t *m, int64_t now_ns,
                         cmt_flowrate_status_t *out);

/**
 * flowrate.go:177-206 `Limit(want, rate, block)`.
 *
 * `block == false` is the reference exactly. `block == true` never
 * sleeps (DEVIATION R-P2P-16, file header): when the reference would
 * enter `waitNextSample`, this returns 0 with `*would_block = true` and
 * `*retry_at_ns` set; otherwise `*would_block = false` and the return is
 * the reference's.
 *
 * @param would_block  may be NULL only when `block` is false
 * @param retry_at_ns  may be NULL
 */
int cmt_flowrate_limit(cmt_flowrate_t *m, int want, int64_t rate, bool block,
                       int64_t now_ns, bool *would_block,
                       int64_t *retry_at_ns);

/** flowrate.go:210-217 `SetTransferSize`. */
void cmt_flowrate_set_transfer_size(cmt_flowrate_t *m, int64_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* CMT_FLOWRATE_H */
