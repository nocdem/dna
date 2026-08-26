/**
 * O15H — TEMPORARY DIAGNOSTIC INSTRUMENTATION. NOT PRODUCTION CODE.
 *
 * Exists to prove or disprove ONE causal question: why the 20-node
 * rehearsal stalls at the e* boundary with view-change escalation churn.
 * Everything here is compile-gated behind the CMake option `O15H_DIAG`
 * (default OFF). With the option off this header expands to nothing, so
 * a default build is byte-identical in behaviour to one without the
 * file — that is the property that makes the instrumentation revertible
 * and keeps it out of any shipped binary.
 *
 * WHY A SEPARATE CLOCK. The consensus path measures time with
 * `time_ms()` = `nodus_time_now() * 1000` (nodus_witness_bft.c:101-103),
 * which has ONE-SECOND granularity — that is why every observed timeout
 * elapsed is a round thousand (11000 / 16000). A one-second clock cannot
 * order events inside a round, so diagnosis needs its own monotonic
 * millisecond source. `o15h_diag_ms()` reads CLOCK_MONOTONIC and is used
 * ONLY for logging; no consensus value is derived from it.
 *
 * COST. One `fprintf` to a per-node file per state transition. These are
 * round-scale events (a handful per 5-second block), so the write rate is
 * a few per second per node — far below anything that could perturb the
 * timing being measured. The stream is line-buffered on purpose: a
 * larger buffer would be cheaper but would lose the tail on SIGKILL,
 * and the tail is exactly where the failure lives.
 *
 * CHAIN TAG (`sc=`). A single nodus-server process hosts TWO witness
 * instances — the legacy chain and the V2 successor — and both call this
 * emitter, so the first round of logs conflated them: on node1 of the
 * 20260825T211825Z run, 87 of 88 `commit` records were legacy-chain
 * noise. Every record now carries `sc=` (w->v2_successor), derived
 * inside the emitter so no call site had to change.
 *
 * REVERT LIST (delete these to remove the instrumentation entirely):
 *   - this header and nodus_witness_o15h_diag.c
 *   - the `O15H_DIAG` option + source entry in nodus/CMakeLists.txt
 *   - every `O15H_DIAG_*(...)` call site (all are one-line, all guarded).
 *     Grep `O15H_DIAG(` rather than trusting a count here — a later
 *     season added one and this list had to be corrected:
 *       nodus_witness_bft.c      — 10 round/view-change sites
 *                                + 1 `idle_stall` site in check_timeout
 *                                + 1 `p2_propose_deadman` site (O15I P2)
 *       nodus_witness_handlers.c — 1 `fwd_leader` site in the T2 spend
 *                                  forward branch (+ its #include)
 */
#ifndef NODUS_WITNESS_O15H_DIAG_H
#define NODUS_WITNESS_O15H_DIAG_H

#ifdef O15H_DIAG_ENABLED

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Monotonic milliseconds. Diagnostic use only. */
uint64_t o15h_diag_ms(void);

/**
 * Rate limiter for heartbeat-style records.
 *
 * Returns true at most once per `min_interval_ms` for a given
 * (witness, key) pair. The state lives HERE, in the temporary
 * translation unit, deliberately: a process hosts two witnesses, so a
 * function-local `static` would throttle them against each other, and
 * adding a field to nodus_witness_t would put diagnostic state in a
 * production struct. A small pointer-keyed table costs nothing and
 * leaves the production headers untouched.
 */
bool o15h_diag_rate_ok(const void *w_opaque, unsigned key,
                       uint64_t min_interval_ms);

/**
 * Emit one diagnostic record.
 *
 * `ev`  — the state transition being reported (round_start, vc_enter_*,
 *         escalate, vote_drop_phase, commit, …)
 * `why` — free text: the reason the transition fired, in the emitter's
 *         own words. This is the field that distinguishes "entered
 *         VIEW_CHANGE because my round timed out" from "entered because
 *         f+1 peers asked", which is the whole point of the exercise.
 * `who` — sender / voter id (may be NULL)
 */
void o15h_diag_emit(const void *w_opaque,
                    const char *ev,
                    const unsigned char *who,
                    unsigned long long height,
                    unsigned cur_view,
                    unsigned tgt_view,
                    int phase,
                    unsigned long long phase_start_ms,
                    unsigned long long elapsed_ms,
                    const char *msg_type,
                    int is_leader,
                    unsigned tally,
                    unsigned quorum,
                    const char *why);

#ifdef __cplusplus
}
#endif

/* The call macro every site uses. Off → the arguments are not even
 * evaluated, so an instrumented expression can never have a side effect
 * in a production build. */
#define O15H_DIAG(w, ev, who, h, cv, tv, ph, pst, el, mt, ld, ta, qu, why) \
    o15h_diag_emit((w), (ev), (who), (unsigned long long)(h),             \
                   (unsigned)(cv), (unsigned)(tv), (int)(ph),             \
                   (unsigned long long)(pst), (unsigned long long)(el),   \
                   (mt), (ld), (unsigned)(ta), (unsigned)(qu), (why))

/* Guard for heartbeat records: false in a production build, so the
 * emitter it guards is never even reached. */
#define O15H_DIAG_RATE(w, key, ms) o15h_diag_rate_ok((w), (key), (ms))

#else  /* !O15H_DIAG_ENABLED */

#define O15H_DIAG(w, ev, who, h, cv, tv, ph, pst, el, mt, ld, ta, qu, why) \
    do { } while (0)

#define O15H_DIAG_RATE(w, key, ms) (0)

#endif /* O15H_DIAG_ENABLED */

#endif /* NODUS_WITNESS_O15H_DIAG_H */
