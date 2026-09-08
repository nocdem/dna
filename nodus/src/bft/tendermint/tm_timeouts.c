/* DNA — Tendermint timeout arithmetic and the pending-timer slots (T1),
 * design §7.
 *
 * timeoutX(r) = init_X + r * delta_X  (Algorithm 1 lines 21 / 35 / 48, and the
 * paper's §II requirement that the timeout GROWS with the round, which is what
 * makes the protocol live after GST).
 *
 * The core NEVER READS A CLOCK (DG-4). `now_ms` arrives as a parameter on
 * every entry point and the deadline is a plain u64 comparison; time.h is not
 * included here or anywhere else in the module.
 *
 * Exactly three pending slots exist, one per step: for a given (h, r) at most
 * one timeout of each kind can be outstanding, so `schedule` OVERWRITES its
 * slot rather than queueing. A slot that belonged to a stale (h, r) is not
 * cancelled on the round change — it fires and the Algorithm 1 equality check
 * at lines 58 / 62 / 66 discards it.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../dna_consensus.h"
#include "tm_core.h"

void tm_params_default(tm_params_t *p)
{
    if (!p) return;
    p->propose_init_ms      = TM_TIMEOUT_PROPOSE_INIT_MS;
    p->propose_delta_ms     = TM_TIMEOUT_PROPOSE_DELTA_MS;
    p->prevote_init_ms      = TM_TIMEOUT_PREVOTE_INIT_MS;
    p->prevote_delta_ms     = TM_TIMEOUT_PREVOTE_DELTA_MS;
    p->precommit_init_ms    = TM_TIMEOUT_PRECOMMIT_INIT_MS;
    p->precommit_delta_ms   = TM_TIMEOUT_PRECOMMIT_DELTA_MS;
    p->round_lookahead      = TM_ROUND_LOOKAHEAD;
    p->max_height_log_bytes = TM_MAX_HEIGHT_LOG_BYTES;
    p->max_value_bytes      = TM_MAX_VALUE_BYTES;
}

/* Overflow is impossible by construction: round <= 2^32-1 and delta <= 2^32-1,
 * so the product is below 2^64 and the sum with a u32 init cannot wrap. */
uint64_t tm_timeout_ms(const tm_params_t *p, tm_step_t step, uint32_t round)
{
    uint64_t init, delta;

    if (!p) return 0;
    switch (step) {
        case TM_STEP_PROPOSE:   init = p->propose_init_ms;   delta = p->propose_delta_ms;   break;
        case TM_STEP_PREVOTE:   init = p->prevote_init_ms;   delta = p->prevote_delta_ms;   break;
        case TM_STEP_PRECOMMIT: init = p->precommit_init_ms; delta = p->precommit_delta_ms; break;
        default:                return 0;
    }
    return init + (uint64_t)round * delta;
}

uint64_t tm_deadline_ms(uint64_t now_ms, uint64_t timeout_ms)
{
    if (timeout_ms > UINT64_MAX - now_ms) return UINT64_MAX;
    return now_ms + timeout_ms;
}

void tm_timers_reset(tm_timers_t *t)
{
    if (!t) return;
    memset(t, 0, sizeof(*t));
}

void tm_timers_schedule(tm_timers_t *t, tm_step_t step, uint64_t h, uint32_t r, uint64_t deadline_ms)
{
    if (!t) return;
    /* One unsigned bound covers both ends: the enum's smallest value is 0. */
    if ((unsigned)step > (unsigned)TM_STEP_PRECOMMIT) return;
    t->slot[step].armed       = 1;
    t->slot[step].height      = h;
    t->slot[step].round       = r;
    t->slot[step].deadline_ms = deadline_ms;
}

/* Fixed scan order PROPOSE, PREVOTE, PRECOMMIT (design §7) — two nodes that
 * tick at the same `now` with the same armed slots must fire them in the same
 * sequence (DG-1). The slot is disarmed BEFORE it is reported so that the
 * handler may re-arm the same kind without being taken twice. */
int tm_timers_take_expired(tm_timers_t *t, uint64_t now_ms,
                           tm_step_t *step, uint64_t *h, uint32_t *r)
{
    int i;

    if (!t || !step || !h || !r) return 0;
    for (i = 0; i < 3; i++) {
        if (t->slot[i].armed && t->slot[i].deadline_ms <= now_ms) {
            t->slot[i].armed = 0;
            *step = (tm_step_t)i;
            *h    = t->slot[i].height;
            *r    = t->slot[i].round;
            return 1;
        }
    }
    return 0;
}
