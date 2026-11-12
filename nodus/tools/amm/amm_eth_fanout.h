/**
 * @file amm_eth_fanout.h
 * @brief The calls of one group of Ethereum provider reads ("ask every usable
 *        provider for X") run at the same time, one short-lived thread per
 *        provider, and the caller examines the answers after every call has
 *        returned (swap bot plan docs/plans/approved/2026-11-12-bot-round-latency.md,
 *        section 6.2.1).
 *
 * The helper holds no state between groups. It gathers; it never combines: the
 * watcher's and the payer's existing quorum code runs unchanged, on the
 * answers, in provider index order, after amm_fanout_run has returned.
 *
 * SIGNALS. Every asynchronous signal is blocked on the calling thread while the
 * threads are created (they inherit that mask), except SIGSEGV, SIGBUS, SIGFPE
 * and SIGILL, whose generation while blocked is undefined (sigprocmask(2)), so a
 * fault in a provider thread still reaches its default action or the
 * sanitizers' handlers. The caller's mask is restored before the call returns.
 * Signal delivery therefore stays on the threads that have it today.
 *
 * WHEN A THREAD CANNOT BE STARTED (pthread_create fails, EAGAIN): the call of
 * that index runs on the calling thread, in index order, after the other
 * threads were started and before the join, with the caller's own mask, and one
 * WARN line names it. Those calls then run one after another beside the started
 * ones.
 */
#ifndef AMM_ETH_FANOUT_H
#define AMM_ETH_FANOUT_H

#include "amm_eth.h"

/** Run fn(arg, i) once for every i in [0, n) with use == NULL or use[i] != 0,
 *  each on its own thread, and return when EVERY call has returned. fn may
 *  touch only provider i and slot i of the caller's arrays; it must not log
 *  through the caller's text buffers, take the caller's locks or use the
 *  journal (test stubs excepted). n <= AMM_ETH_MAX_PROVIDERS (a larger n is
 *  cut to it). */
typedef void (*amm_fanout_fn)(void *arg, int i);
void amm_fanout_run(int n, const int *use, amm_fanout_fn fn, void *arg);

/** Test-only hook, in the pattern of the journal's pre-commit hook: makes
 *  pthread_create count as failed for the indexes whose bit is set in `mask`
 *  (default 0). Production never calls it. */
void amm_fanout_test_fail_create(unsigned mask);

#endif /* AMM_ETH_FANOUT_H */
