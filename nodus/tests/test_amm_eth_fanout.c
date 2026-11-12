/**
 * test_amm_eth_fanout.c -- amm_fanout_run (amm_eth_fanout.c): the helper that
 * runs one call per usable provider at the same time and returns when every
 * call has returned (plan docs/plans/approved/2026-11-12-bot-round-latency.md,
 * section 6.2.1 and 7.1.1).
 *
 * WHAT IT PROVES
 *   F1  every selected index is called exactly once and an unselected one never:
 *       use all, none, sparse, n = 1, n = 16, and use == NULL (every index).
 *       No fallback WARN line ("AMM_FANOUT: ...") is written when no thread
 *       creation is forced to fail.
 *   F2  all selected calls are in flight at once: a counting gate (tests/
 *       amm_test_gate.h) with k = the selected count opens only when every call
 *       has arrived; timed_out == 0 and the gate saw exactly one generation. A
 *       serial implementation makes the first call wait for arrivals that never
 *       come: the gate's bound is reached and the CHECK fails.
 *   F3  amm_fanout_run returns only after every call has returned: the gate in
 *       reverse mode lets index 0 return last; after the helper returns every
 *       done[i] is 1 and the calls returned in descending index order.
 *   F4  signals: inside a provider call SIGTERM and SIGINT (and the other
 *       asynchronous signals the caller had unblocked) are blocked while
 *       SIGSEGV, SIGBUS, SIGFPE and SIGILL are not; the caller's own mask is
 *       identical before and after the call.
 *   F5  thread creation fails (amm_fanout_test_fail_create for some indexes):
 *       every selected index is still called exactly once, the failed ones on
 *       the calling thread (pthread_equal), the others still concurrent (gate
 *       with k = the started count), and exactly one WARN line names the
 *       fallback ("2 of 6 provider calls ran on the calling thread").
 * BUILD FLAGS: none. ENVIRONMENT: none. LEAVES BEHIND: nothing (one mkdtemp
 *   directory under /tmp for the log file, removed at the end).
 * HOW IT CAN FALSELY PASS: F1's n = 16 and F2's n = 16 need 16 threads; on a
 *   host that cannot start them the helper's fallback runs the rest on the
 *   calling thread and F2 then fails (visible, by the gate's bound), F1 fails on
 *   its WARN count (visible, not silent). F4 reads the mask of a thread the
 *   helper made: a helper that blocked nothing would fail it; one that blocked
 *   every signal would fail the SIGSEGV check. F3's order check proves the
 *   gate's order, which is the property the join must outlast.
 */
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_eth_fanout.h"
#include "amm_test_gate.h"
#include "nodus_log_shim.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

#define MAXN 16

static char g_dir[64];

/* the number of "AMM_FANOUT:" lines in the log file so far, -1 if unreadable */
static int fanout_lines(void) {
    char p[128];
    snprintf(p, sizeof(p), "%s/nodus-amm.log", g_dir);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    char line[1100];
    int n = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, "AMM_FANOUT:")) n++;
    fclose(f);
    return n;
}

/* the last "AMM_FANOUT:" line, "" if none */
static void last_fanout_line(char *out, size_t cap) {
    out[0] = '\0';
    char p[128];
    snprintf(p, sizeof(p), "%s/nodus-amm.log", g_dir);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char line[1100];
    while (fgets(line, sizeof(line), f))
        if (strstr(line, "AMM_FANOUT:")) snprintf(out, cap, "%s", line);
    fclose(f);
}

/* ── F1 ──────────────────────────────────────────────────────────────── */

static atomic_int g_calls[MAXN];

static void count_fn(void *arg, int i) {
    (void)arg;
    atomic_fetch_add(&g_calls[i], 1);
}

static void f1_each_once(void) {
    printf("F1 every selected index exactly once, never an unselected one\n");
    int before = fanout_lines();
    struct { int n; int use[MAXN]; int use_null; const char *what; } t[] = {
        { 3, {1, 1, 1}, 0, "use all (n = 3)" },
        { 3, {0, 0, 0}, 0, "use none (n = 3)" },
        { 5, {1, 0, 1, 0, 1}, 0, "sparse (n = 5)" },
        { 1, {1}, 0, "n = 1" },
        { 16, {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 0, "n = 16, all" },
        { 16, {0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1}, 0, "n = 16, sparse" },
        { 4, {0}, 1, "use == NULL: every index" },
    };
    for (size_t k = 0; k < sizeof(t) / sizeof(t[0]); k++) {
        for (int i = 0; i < MAXN; i++) atomic_store(&g_calls[i], 0);
        amm_fanout_run(t[k].n, t[k].use_null ? NULL : t[k].use, count_fn, NULL);
        int ok = 1;
        for (int i = 0; i < MAXN; i++) {
            int want = (i < t[k].n && (t[k].use_null || t[k].use[i])) ? 1 : 0;
            if (atomic_load(&g_calls[i]) != want) ok = 0;
        }
        char m[96];
        snprintf(m, sizeof(m), "%s: each selected called once, no other", t[k].what);
        CHECK(ok, m);
    }
    int after = fanout_lines();
    CHECK(before == 0 && after == 0, "no fallback WARN line when no thread creation fails");
}

/* ── F2 / F3 ─────────────────────────────────────────────────────────── */

static amm_gate_t g_gate;
static atomic_int g_done[MAXN];
static atomic_int g_order[MAXN];       /* the index that returned at position p */
static atomic_int g_pos;

static void gate_fn(void *arg, int i) {
    (void)arg;
    int t = amm_gate_enter(&g_gate, i);
    atomic_fetch_add(&g_calls[i], 1);
    int p = atomic_fetch_add(&g_pos, 1);
    if (p < MAXN) atomic_store(&g_order[p], i);
    atomic_store(&g_done[i], 1);
    amm_gate_leave(&g_gate, i, t);
}

static void f2_all_in_flight(void) {
    printf("F2 all selected calls are in flight at once\n");
    static const int sizes[] = { 2, 3, 16 };
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        int n = sizes[s];
        for (int i = 0; i < MAXN; i++) { atomic_store(&g_calls[i], 0); atomic_store(&g_done[i], 0); }
        atomic_store(&g_pos, 0);
        amm_gate_arm(&g_gate, n, 0);
        amm_fanout_run(n, NULL, gate_fn, NULL);
        int all = 1;
        for (int i = 0; i < n; i++) all &= atomic_load(&g_calls[i]) == 1;
        amm_gate_disarm(&g_gate);
        char m[96];
        snprintf(m, sizeof(m), "n = %d: the gate opened (every call in flight at once)", n);
        CHECK(amm_gate_timed_out(&g_gate) == 0 && all, m);
        snprintf(m, sizeof(m), "n = %d: exactly one generation", n);
        CHECK(amm_gate_gens(&g_gate) == 1, m);
    }
}

static void f3_returns_after_all(void) {
    printf("F3 the helper returns only after every call has returned\n");
    const int n = 4;
    for (int i = 0; i < MAXN; i++) { atomic_store(&g_calls[i], 0); atomic_store(&g_done[i], 0); atomic_store(&g_order[i], -1); }
    atomic_store(&g_pos, 0);
    amm_gate_arm(&g_gate, n, 1);                    /* reverse: index 0 returns last */
    amm_fanout_run(n, NULL, gate_fn, NULL);
    amm_gate_disarm(&g_gate);
    int all = 1;
    for (int i = 0; i < n; i++) all &= atomic_load(&g_done[i]) == 1;
    CHECK(amm_gate_timed_out(&g_gate) == 0, "the reverse gate opened");
    CHECK(all, "after the helper returned every done[i] is 1 (index 0, the last to return, included)");
    CHECK(atomic_load(&g_order[0]) == 3 && atomic_load(&g_order[1]) == 2 &&
          atomic_load(&g_order[2]) == 1 && atomic_load(&g_order[3]) == 0,
          "the calls returned in descending index order");
}

/* ── F4 ──────────────────────────────────────────────────────────────── */

static sigset_t g_seen[MAXN];

static void sig_fn(void *arg, int i) {
    (void)arg;
    pthread_sigmask(SIG_BLOCK, NULL, &g_seen[i]);
}

static void f4_signals(void) {
    printf("F4 asynchronous signals are blocked in provider calls, the caller's mask is kept\n");
    /* a caller mask that blocks SIGUSR1 only, so "identical" is a real comparison */
    sigset_t want, before, after, old;
    sigemptyset(&want);
    sigaddset(&want, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &want, &old);
    pthread_sigmask(SIG_BLOCK, NULL, &before);
    memset(g_seen, 0, sizeof(g_seen));
    amm_fanout_run(3, NULL, sig_fn, NULL);
    pthread_sigmask(SIG_BLOCK, NULL, &after);
    int same = 1;
    for (int s = 1; s < 32; s++) same &= sigismember(&before, s) == sigismember(&after, s);
    CHECK(same, "the caller's signal mask is identical before and after the call");
    int term = 1, intr = 1, usr2 = 1, fault_free = 1;
    for (int i = 0; i < 3; i++) {
        term &= sigismember(&g_seen[i], SIGTERM) == 1;
        intr &= sigismember(&g_seen[i], SIGINT) == 1;
        usr2 &= sigismember(&g_seen[i], SIGUSR2) == 1;
        fault_free &= sigismember(&g_seen[i], SIGSEGV) == 0 && sigismember(&g_seen[i], SIGBUS) == 0 &&
                      sigismember(&g_seen[i], SIGFPE) == 0 && sigismember(&g_seen[i], SIGILL) == 0;
    }
    CHECK(term && intr, "SIGTERM and SIGINT are blocked in every provider call");
    CHECK(usr2, "another asynchronous signal (SIGUSR2) is blocked too");
    CHECK(fault_free, "SIGSEGV, SIGBUS, SIGFPE and SIGILL are NOT blocked (a fault still reaches its handler)");
    pthread_sigmask(SIG_SETMASK, &old, NULL);
}

/* ── F5 ──────────────────────────────────────────────────────────────── */

static pthread_t g_caller;
static atomic_int g_on_caller[MAXN];

static void fb_fn(void *arg, int i) {
    (void)arg;
    atomic_fetch_add(&g_calls[i], 1);
    if (pthread_equal(pthread_self(), g_caller)) {
        atomic_store(&g_on_caller[i], 1);
        return;                                   /* the fallback runs serially: no gate */
    }
    int t = amm_gate_enter(&g_gate, i);
    amm_gate_leave(&g_gate, i, t);
}

static void f5_create_fails(void) {
    printf("F5 a thread that cannot be created runs on the calling thread\n");
    const int n = 6;
    const unsigned mask = (1u << 1) | (1u << 4);
    for (int i = 0; i < MAXN; i++) { atomic_store(&g_calls[i], 0); atomic_store(&g_on_caller[i], 0); }
    g_caller = pthread_self();
    int before = fanout_lines();
    amm_gate_arm(&g_gate, n - 2, 0);                /* the 4 started calls are concurrent */
    amm_fanout_test_fail_create(mask);
    amm_fanout_run(n, NULL, fb_fn, NULL);
    amm_fanout_test_fail_create(0);
    amm_gate_disarm(&g_gate);
    int once = 1, on_ok = 1;
    for (int i = 0; i < n; i++) {
        once &= atomic_load(&g_calls[i]) == 1;
        on_ok &= atomic_load(&g_on_caller[i]) == ((mask >> i) & 1u ? 1 : 0);
    }
    CHECK(once, "every selected index was called exactly once");
    CHECK(on_ok, "exactly the indexes whose creation failed ran on the calling thread");
    CHECK(amm_gate_timed_out(&g_gate) == 0 && amm_gate_gens(&g_gate) == 1,
          "the started calls were still concurrent (the gate with k = 4 opened)");
    char ln[1100];
    last_fanout_line(ln, sizeof(ln));
    CHECK(fanout_lines() == before + 1 && strstr(ln, "2 of 6 provider calls ran on the calling thread") != NULL,
          "one WARN line names the fallback: \"2 of 6 provider calls ran on the calling thread\"");
}

static void cleanup(void) {
    char p[128];
    snprintf(p, sizeof(p), "%s/nodus-amm.log", g_dir);
    unlink(p);
    rmdir(g_dir);
}

int main(void) {
    printf("test_amm_eth_fanout\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/amm_fanout_testXXXXXX");
    if (!mkdtemp(g_dir)) { printf("FATAL mkdtemp\n"); return 2; }
    if (nodus_log_file_open(g_dir, 1 << 20, 1) != 0) { printf("FATAL log file\n"); return 2; }
    amm_gate_init(&g_gate);
    f1_each_once();
    f2_all_in_flight();
    f3_returns_after_all();
    f4_signals();
    f5_create_fails();
    nodus_log_file_close();
    amm_gate_destroy(&g_gate);
    cleanup();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
