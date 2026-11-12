/**
 * amm_test_gate.h -- a counting gate for the stub providers of the swap bot's
 * tests (header-only; every user includes it once).
 *
 * WHAT IT IS. A gate is armed with k (the number of providers that will call
 * the gated method in each group) and a mode. On entry a call registers its
 * provider index and waits; when the k-th call of the current group has
 * arrived, the gate opens. In "reverse" mode the calls then return strictly in
 * descending provider index (each waits until the ones above it have
 * returned); in "plain" mode they all return as soon as the gate is open. A
 * group's calls arrive in a new generation once the previous group's k calls
 * have all passed.
 *
 * WHAT IT PROVES. The k calls of a group were in flight at the same time (the
 * parallel fan-out): a serial implementation makes the first call of a group
 * wait for arrivals that never come, the wait reaches its bound, `timed_out`
 * is set and the test's CHECK fails. A parallel implementation never reaches
 * the bound. Reverse mode additionally makes the calls finish in the order
 * opposite to the provider order, so a result that depended on arrival order
 * would change.
 *
 * THE BOUND. AMM_GATE_WAIT_MS = 20000, a test constant (not a setting). It is
 * large because the selected tests run under `ctest -j$(nproc)` and under
 * ThreadSanitizer, where a correct implementation's thread start and scheduling
 * are slowed ("a test that passes only at -j1 is a defect", nodus/CLAUDE.md).
 * It exists only so that a serial implementation fails instead of hanging; a
 * serial implementation fails at any bound, so its size does not decide the
 * verdict. To keep a broken run short, the gate LATCHES: once any wait in the
 * process reaches the bound, every later wait returns at once and every later
 * gated run also records timed_out = 1 (a serial implementation costs one bound
 * per test binary, and every gated CHECK still fails). This is an assertion on
 * an expected asynchronous condition, not a retry and not a raised timeout.
 *
 * SCOPING RULE (so that correct code never meets the bound). A method is gated
 * only in a step whose every caller of that method calls it once per usable
 * provider in each group. The user of the gate checks this and reports a
 * mis-scoped run as a wrong generation count (amm_gate_gens), not as a
 * sporadic timeout.
 *
 * The counter helper (amm_ctr_t) is the same bounded wait for "provider X's
 * unit is done" conditions (W34b, E19b).
 *
 * HOW IT CAN FALSELY PASS: a gate that is armed for a method no code path calls
 * never opens and never times out (the user's generation-count assertion shows
 * it); a stub that does not call amm_gate_enter ignores the gate.
 */
#ifndef AMM_TEST_GATE_H
#define AMM_TEST_GATE_H

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define AMM_GATE_WAIT_MS 20000

/* set once any bounded wait of this process reached its bound */
static int g_amm_gate_latched = 0;
static pthread_mutex_t g_amm_gate_latch_mu = PTHREAD_MUTEX_INITIALIZER;

static inline int amm_gate_is_latched(void) {
    pthread_mutex_lock(&g_amm_gate_latch_mu);
    int v = g_amm_gate_latched;
    pthread_mutex_unlock(&g_amm_gate_latch_mu);
    return v;
}

static inline void amm_gate_latch(void) {
    pthread_mutex_lock(&g_amm_gate_latch_mu);
    g_amm_gate_latched = 1;
    pthread_mutex_unlock(&g_amm_gate_latch_mu);
}

/* an absolute CLOCK_MONOTONIC deadline AMM_GATE_WAIT_MS from now */
static inline void amm_gate_deadline(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
    ts->tv_sec += AMM_GATE_WAIT_MS / 1000;
    ts->tv_nsec += (long)(AMM_GATE_WAIT_MS % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

/* ── the counting gate ─────────────────────────────────────────────────── */

#define AMM_GATE_MAX_IDX 32

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int      armed;
    int      k;            /* arrivals that open a generation                  */
    int      reverse;      /* 1: calls return in descending provider index      */
    uint32_t arrived;      /* bit i: provider i is waiting in this generation   */
    int      n_arrived;
    int      open;         /* the current generation is open                    */
    int      cur;          /* reverse mode: the index allowed to return next   */
    int      passed;       /* calls of the open generation that have returned   */
    int      gens;         /* generations completed since arm                   */
    int      timed_out;    /* a wait reached the bound (or the process latched) */
} amm_gate_t;

static inline void amm_gate_init(amm_gate_t *g) {
    memset(g, 0, sizeof(*g));
    pthread_mutex_init(&g->mu, NULL);
    pthread_condattr_t at;
    pthread_condattr_init(&at);
    pthread_condattr_setclock(&at, CLOCK_MONOTONIC);
    pthread_cond_init(&g->cv, &at);
    pthread_condattr_destroy(&at);
}

static inline void amm_gate_destroy(amm_gate_t *g) {
    pthread_cond_destroy(&g->cv);
    pthread_mutex_destroy(&g->mu);
}

/* Arm between steps, on the test thread. Resets the generation count. */
static inline void amm_gate_arm(amm_gate_t *g, int k, int reverse) {
    pthread_mutex_lock(&g->mu);
    g->armed = 1; g->k = k; g->reverse = reverse;
    g->arrived = 0; g->n_arrived = 0; g->open = 0; g->cur = -1; g->passed = 0;
    g->gens = 0;
    g->timed_out = amm_gate_is_latched();
    pthread_mutex_unlock(&g->mu);
}

static inline void amm_gate_disarm(amm_gate_t *g) {
    pthread_mutex_lock(&g->mu);
    g->armed = 0;
    pthread_mutex_unlock(&g->mu);
}

static inline int amm_gate_gens(amm_gate_t *g) {
    pthread_mutex_lock(&g->mu);
    int v = g->gens;
    pthread_mutex_unlock(&g->mu);
    return v;
}

static inline int amm_gate_timed_out(amm_gate_t *g) {
    pthread_mutex_lock(&g->mu);
    int v = g->timed_out;
    pthread_mutex_unlock(&g->mu);
    return v;
}

static inline int amm_gate_highest(uint32_t m) {
    for (int i = AMM_GATE_MAX_IDX - 1; i >= 0; i--)
        if (m & (1u << i)) return i;
    return -1;
}

/* One bounded wait on g->cv for `pred` to hold; g->mu is held by the caller.
 * Returns 1 when the predicate held, 0 when the bound (or the latch) cut it. */
#define AMM_GATE_WAIT_FOR(g, pred)                                           \
    ({                                                                       \
        int ok_ = 1;                                                         \
        struct timespec dl_;                                                 \
        amm_gate_deadline(&dl_);                                             \
        while (!(pred)) {                                                    \
            if (amm_gate_is_latched()) { (g)->timed_out = 1; ok_ = 0; break; } \
            if (pthread_cond_timedwait(&(g)->cv, &(g)->mu, &dl_) != 0 && !(pred)) { \
                amm_gate_latch();                                            \
                (g)->timed_out = 1; ok_ = 0; break;                          \
            }                                                                \
        }                                                                    \
        ok_;                                                                 \
    })

/* Called by a stub provider at the start of the gated method; `idx` is the
 * provider's index (< AMM_GATE_MAX_IDX). A NULL or disarmed gate returns 0 at
 * once. Otherwise the call waits as the gate's rule says and returns 1 (it is
 * "tracked": it must call amm_gate_leave with the same idx when its work is
 * done, on every return path), or returns 0 when the bound was reached (the
 * call then proceeds alone and is not tracked). */
static inline int amm_gate_enter(amm_gate_t *g, int idx) {
    if (!g) return 0;
    pthread_mutex_lock(&g->mu);
    if (!g->armed) { pthread_mutex_unlock(&g->mu); return 0; }
    /* a new generation starts only after the previous one fully left */
    (void)AMM_GATE_WAIT_FOR(g, !g->open);
    if (g->open) {                       /* the wait was cut: let the call go */
        pthread_mutex_unlock(&g->mu);
        return 0;
    }
    g->arrived |= 1u << idx;
    g->n_arrived++;
    if (g->n_arrived >= g->k) {
        g->open = 1;
        g->passed = 0;
        g->cur = amm_gate_highest(g->arrived);
        pthread_cond_broadcast(&g->cv);
    }
    int got = AMM_GATE_WAIT_FOR(g, g->open && (!g->reverse || g->cur == idx));
    if (!got) {
        /* the bound was reached: this call proceeds alone and is untracked */
        g->arrived &= ~(1u << idx);
        if (g->n_arrived > 0) g->n_arrived--;
        pthread_cond_broadcast(&g->cv);
        pthread_mutex_unlock(&g->mu);
        return 0;
    }
    pthread_mutex_unlock(&g->mu);
    return 1;
}

/* The last statement of a tracked call (amm_gate_enter returned 1), after its
 * own work, on every return path. In reverse mode it hands the turn to the next
 * lower index only now, so "provider i returns after every provider above it"
 * is true of the stub's return, not only of the gate's exit. The last call of
 * a generation closes it (the next group may then arrive). */
static inline void amm_gate_leave(amm_gate_t *g, int idx, int tracked) {
    if (!g || !tracked) return;
    pthread_mutex_lock(&g->mu);
    g->arrived &= ~(1u << idx);
    g->passed++;
    if (g->reverse) g->cur = amm_gate_highest(g->arrived);
    if (g->passed >= g->k) {
        g->open = 0; g->n_arrived = 0; g->arrived = 0; g->cur = -1; g->passed = 0;
        g->gens++;
    }
    pthread_cond_broadcast(&g->cv);
    pthread_mutex_unlock(&g->mu);
}

/* A gated stub body: `GATE_CALL(g, idx, expr)` enters the gate, evaluates the
 * call expression, leaves, and yields the expression's int value. */
#define GATE_CALL(g, idx, expr)                                              \
    ({ int t_ = amm_gate_enter((g), (idx)); int r_ = (expr);                 \
       amm_gate_leave((g), (idx), t_); r_; })

/* ── a counter with a bounded wait ─────────────────────────────────────── */

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int v;
    int timed_out;
} amm_ctr_t;

static inline void amm_ctr_init(amm_ctr_t *c) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->mu, NULL);
    pthread_condattr_t at;
    pthread_condattr_init(&at);
    pthread_condattr_setclock(&at, CLOCK_MONOTONIC);
    pthread_cond_init(&c->cv, &at);
    pthread_condattr_destroy(&at);
}

static inline void amm_ctr_destroy(amm_ctr_t *c) {
    pthread_cond_destroy(&c->cv);
    pthread_mutex_destroy(&c->mu);
}

static inline void amm_ctr_reset(amm_ctr_t *c) {
    pthread_mutex_lock(&c->mu);
    c->v = 0;
    c->timed_out = amm_gate_is_latched();
    pthread_mutex_unlock(&c->mu);
}

static inline void amm_ctr_inc(amm_ctr_t *c) {
    pthread_mutex_lock(&c->mu);
    c->v++;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static inline int amm_ctr_get(amm_ctr_t *c) {
    pthread_mutex_lock(&c->mu);
    int v = c->v;
    pthread_mutex_unlock(&c->mu);
    return v;
}

static inline int amm_ctr_timed_out(amm_ctr_t *c) {
    pthread_mutex_lock(&c->mu);
    int v = c->timed_out;
    pthread_mutex_unlock(&c->mu);
    return v;
}

/* Wait until the counter reaches `want`; bounded (the same bound and latch as
 * the gate). Returns 1 on success, 0 when the bound was reached. */
static inline int amm_ctr_wait_ge(amm_ctr_t *c, int want) {
    pthread_mutex_lock(&c->mu);
    int ok = 1;
    struct timespec dl;
    amm_gate_deadline(&dl);
    while (c->v < want) {
        if (amm_gate_is_latched()) { c->timed_out = 1; ok = 0; break; }
        if (pthread_cond_timedwait(&c->cv, &c->mu, &dl) != 0 && c->v < want) {
            amm_gate_latch();
            c->timed_out = 1; ok = 0; break;
        }
    }
    pthread_mutex_unlock(&c->mu);
    return ok;
}

#endif /* AMM_TEST_GATE_H */
