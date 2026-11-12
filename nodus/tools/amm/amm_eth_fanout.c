/**
 * @file amm_eth_fanout.c
 * @brief see amm_eth_fanout.h
 */
#include "amm_eth_fanout.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_FANOUT"

static atomic_uint g_fail_mask;

void amm_fanout_test_fail_create(unsigned mask) { atomic_store(&g_fail_mask, mask); }

typedef struct {
    amm_fanout_fn fn;
    void         *arg;
    int           i;
    pthread_t     th;
    int           started;
} slot_t;

static void *slot_main(void *p) {
    slot_t *s = p;
    s->fn(s->arg, s->i);
    return NULL;
}

void amm_fanout_run(int n, const int *use, amm_fanout_fn fn, void *arg) {
    if (!fn || n <= 0) return;
    if (n > AMM_ETH_MAX_PROVIDERS) n = AMM_ETH_MAX_PROVIDERS;
    slot_t s[AMM_ETH_MAX_PROVIDERS];
    int sel = 0;
    for (int i = 0; i < n; i++) {
        s[i].fn = fn; s[i].arg = arg; s[i].i = i; s[i].started = 0;
        sel += (!use || use[i]) ? 1 : 0;
    }
    if (sel == 0) return;

    /* block every asynchronous signal while the threads are created: they
     * inherit the mask. Faults stay deliverable (their generation while
     * blocked is undefined). */
    sigset_t all, old;
    sigfillset(&all);
    sigdelset(&all, SIGSEGV);
    sigdelset(&all, SIGBUS);
    sigdelset(&all, SIGFPE);
    sigdelset(&all, SIGILL);
    pthread_sigmask(SIG_SETMASK, &all, &old);
    const unsigned fail = atomic_load(&g_fail_mask);
    int failed = 0, last_err = 0;
    for (int i = 0; i < n; i++) {
        if (use && !use[i]) continue;
        int err = (i < 32 && ((fail >> i) & 1u)) ? EAGAIN
                  : pthread_create(&s[i].th, NULL, slot_main, &s[i]);
        if (err == 0) s[i].started = 1;
        else { failed++; last_err = err; }
    }
    pthread_sigmask(SIG_SETMASK, &old, NULL);

    /* a call whose thread could not be started runs here, in index order, with
     * the caller's own mask, beside the started threads and before the join */
    if (failed > 0) {
        QGP_LOG_WARN(LOG_TAG, "%d of %d provider calls ran on the calling thread (no thread: error %d)",
                     failed, sel, last_err);
        for (int i = 0; i < n; i++)
            if ((!use || use[i]) && !s[i].started) fn(arg, i);
    }
    for (int i = 0; i < n; i++)
        if (s[i].started) pthread_join(s[i].th, NULL);
}
