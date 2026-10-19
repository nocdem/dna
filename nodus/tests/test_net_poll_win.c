/**
 * @file nodus/tests/test_net_poll_win.c
 * @brief Unit test of the nodus_net_poll readiness backend, Windows (select)
 *        arm — net-layer design 2026-10-19 §2 + §9 (R5, R7) + §10 (R7
 *        amended: fair rotation), package N1. The Linux arm is
 *        test_net_poll.c.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   1. nodus_net_startup / _cleanup are reference-counted: after two
 *      startups and one cleanup Winsock still answers (a socket can be
 *      made); after the second cleanup it does not (WSANOTINITIALISED).
 *   2. add / mod / del: a socket is reported under the tag and mask it was
 *      last given; a second add of the same socket, the reserved wake tag
 *      (add and mod), the invalid socket, a mod or del of an unregistered
 *      socket are refused, each with nodus_net_errno() == WSAEINVAL.
 *   3. level-triggered IN: unread bytes are reported on two consecutive
 *      waits, and no longer once read.
 *   4. FAIR ROTATION (R7 amended): 10 sockets all readable, cap 3 — every
 *      wait returns exactly 3 distinct tags and any 4 (= ceil(10/3))
 *      consecutive waits report all 10; after a del in the middle of the
 *      rotation any 3 (= ceil(9/3)) consecutive waits report all 9
 *      remaining and never the deleted one (the cursor survives removal).
 *   5. a wake from another thread ends a wait WITHOUT a time limit
 *      (returning at all is the proof) and is not reported (0 entries);
 *      a following wait(0) returns 0.
 *   6. a wake and a ready socket in one wait: the socket is reported, the
 *      wake is not.
 *   7. nodus_net_probe_connect answers "finished" (> 0) for a loopback
 *      connect that succeeded (SO_ERROR 0) and for one that was refused —
 *      the refusal reported as NODUS_NET_ERR through the except set,
 *      SO_ERROR != 0.
 *   8. WSAENOTSOCK eviction: a registered socket closed without _del is
 *      reported once as ERR|HUP under its tag and not again.
 *   9. empty set: wait(0) returns 0; wait without limit is refused with
 *      -1 / WSAEINVAL.
 *
 * REQUIRES: compile — a Windows build of nodus (the "Windows cross build"
 *   in nodus/README.md, llvm-mingw; target test_net_poll_win, linked
 *   -static); environment — nothing. Run natively on Windows or under Wine.
 *   Loopback TCP on 127.0.0.1 with system-chosen ports only (no fixed
 *   port). One helper thread (case 5, CreateThread). Not registered with
 *   ctest (a Windows configure stops before enable_testing()).
 *
 * LEAVES BEHIND: nothing — every socket is closed (case 8's victim by the
 *   case itself), every set freed, no file written.
 *
 * SYNCHRONISATION: no sleep is used as synchronisation and no assertion is
 *   decided by a clock. Every "becomes ready" is a loop of
 *   nodus_net_poll_wait(ATTEMPT_MS) bounded by ATTEMPTS calls (ATTEMPTS ×
 *   ATTEMPT_MS = 5 s) — case 7's refused connect by REFUSE_ATTEMPTS (30 s),
 *   because Windows retries a SYN answered by RST before it reports the
 *   connect refused (the retry count and spacing are NOT verified here; the
 *   bound is generous on purpose). Expiry of an attempt bound is a FAIL,
 *   never a pass. Every measured wait after readiness was established is
 *   wait(0) on a state where nothing is in flight.
 *
 * WHAT WINE CANNOT PROVE: under Wine the readiness, errors and handle
 *   values come from Wine's ws2_32 emulation over the Linux kernel, not
 *   from Winsock. A PASS under Wine proves the backend's logic against
 *   Wine; native Windows is still required for Winsock itself, in
 *   particular: a refused connect reported in the except set (case 7),
 *   the SYN-retry timing after RST (Wine follows the Linux kernel and
 *   reports at once), select failing with WSAENOTSOCK on a closed handle
 *   (case 8), WSANOTINITIALISED after the last WSACleanup (case 1), and
 *   the reuse of a closed handle value (not tested at all — BUGS.md C-06).
 *
 * HOW IT CAN LIE:
 *   · Case 5 wants the wake to land while the main thread is BLOCKED in
 *     select. Nothing here observes that: when the helper thread wakes
 *     before the main thread enters the wait, the case exercises only the
 *     pending-wake path and still PASSES. A wake that does not work makes
 *     the wait without limit HANG — not FAIL; there is no ctest timeout
 *     around this binary, so whoever runs it must treat a hang as a FAIL.
 *   · "The wake is drained" (cases 5 and 6) is NOT observable through the
 *     public API: a wake alone is never reported, so wait(0) returns 0
 *     whether the wake pair was drained or a byte is still pending. Those
 *     checks prove only that the wake is never reported.
 *   · Case 6 cannot see whether the wake byte had arrived on the wake pair
 *     when select ran (the wake is sent on the loop thread just before the
 *     wait); if it had not, the case exercises a ready socket alone.
 *   · Case 7 assumes a non-blocking loopback connect returns WSAEWOULDBLOCK
 *     (both to the listener and to the bound, not-listening port). A stack
 *     that completed or refused inside connect() FAILS the case (with a
 *     note) — a false FAIL, never a false PASS.
 *   · Case 8 relies on no new socket being created between closesocket and
 *     the wait (the test creates none; the backend's stale check —
 *     getsockopt SO_TYPE — runs before its eviction log line); the
 *     eviction of a REUSED handle value is not tested.
 *   · Case 4 deletes index 5 with the cursor where the earlier waits left
 *     it: at index 9 when the first readiness wait already reported all 10
 *     (then only the "removed entry before the cursor" branch of the
 *     backend's cursor update runs); elsewhere if earlier readiness waits
 *     returned fewer. The test does not choose the branch, and "cursor
 *     wraps to 0" is not deliberately exercised.
 *   · It tests the backend only; no caller (nodus_tcp, p2p) uses the
 *     Windows arm in N1.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "net/nodus_net_poll.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int passed = 0, failed = 0;

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while (0)
#define CHECK(c)   do { if (!(c)) { ok = 0; printf("\n    check failed: %s (line %d)", #c, __LINE__); } } while (0)
#define DONE()     do { if (ok) { printf("PASS\n"); passed++; } \
                        else { printf("\n    FAIL\n"); failed++; } } while (0)

#define ATTEMPT_MS       100         /* one bounded wait                    */
#define ATTEMPTS         50          /* waits before "never became ready"   */
#define REFUSE_ATTEMPTS  300         /* case 7 refused connect (SYN retry)  */

#define ROT_N    10                  /* case 4: sockets in the rotation     */
#define ROT_CAP  3                   /* case 4: cap per wait                */
#define ROT_RUNS 12                  /* case 4: waits recorded per phase    */

/* ── loopback helpers ──────────────────────────────────────────────── */

/* Wait, bounded by `attempts` calls of wait(ATTEMPT_MS), until `tag` is
 * reported in `p`; its ready bits, or 0 when the bound expired or a wait
 * failed. */
static uint32_t wait_tag(nodus_net_poll_t *p, uint64_t tag, int attempts)
{
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    int a, i, n;

    for (a = 0; a < attempts; a++) {
        n = nodus_net_poll_wait(p, ATTEMPT_MS, ev, NODUS_NET_POLL_MAX_BATCH);
        if (n < 0) {
            printf("\n    wait failed: %d", nodus_net_errno());
            return 0;
        }
        for (i = 0; i < n; i++) {
            if (ev[i].tag == tag) {
                return ev[i].ready;
            }
        }
    }
    printf("\n    tag %llu not reported within %d attempts",
           (unsigned long long)tag, attempts);
    return 0;
}

/* The ready bits `s` reports for `mask` through a set of its own, bounded
 * by `attempts` (0 = not ready in time, or the set failed). */
static uint32_t wait_ready(nodus_sock_t s, uint32_t mask, int attempts)
{
    nodus_net_poll_t q;
    uint32_t r = 0;

    if (nodus_net_poll_init(&q, false) != 0) {
        return 0;
    }
    if (nodus_net_poll_add(&q, s, 1, mask) == 0) {
        r = wait_tag(&q, 1, attempts);
    }
    nodus_net_poll_free(&q);
    return r;
}

static void lo_addr(struct sockaddr_in *a, uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a->sin_port = htons(port);
}

/* A non-blocking socket bound to 127.0.0.1:<system port>, listening when
 * `do_listen`; *port gets the port. NODUS_SOCK_INVALID on failure. */
static nodus_sock_t lo_bound(uint16_t *port, bool do_listen)
{
    struct sockaddr_in a;
    int al = (int)sizeof(a);
    nodus_sock_t l = nodus_net_socket(AF_INET, SOCK_STREAM);

    if (l == NODUS_SOCK_INVALID) {
        return NODUS_SOCK_INVALID;
    }
    lo_addr(&a, 0);
    if (bind((SOCKET)l, (struct sockaddr *)&a, (int)sizeof(a)) != 0 ||
        (do_listen && listen((SOCKET)l, 16) != 0) ||
        getsockname((SOCKET)l, (struct sockaddr *)&a, &al) != 0) {
        nodus_net_close(l);
        return NODUS_SOCK_INVALID;
    }
    *port = ntohs(a.sin_port);
    return l;
}

/* Start a non-blocking connect from nodus_net_socket to 127.0.0.1:port.
 * Returns the socket only if connect() answered WSAEWOULDBLOCK (in
 * progress); anything else is printed and the socket closed. */
static nodus_sock_t lo_connect_start(uint16_t port)
{
    struct sockaddr_in a;
    nodus_sock_t c = nodus_net_socket(AF_INET, SOCK_STREAM);
    int e;

    if (c == NODUS_SOCK_INVALID) {
        return NODUS_SOCK_INVALID;
    }
    lo_addr(&a, port);
    if (connect((SOCKET)c, (struct sockaddr *)&a, (int)sizeof(a)) == 0) {
        printf("\n    NOTE: non-blocking connect completed inside connect()");
        nodus_net_close(c);
        return NODUS_SOCK_INVALID;
    }
    e = nodus_net_errno();
    if (!NODUS_NET_IS_EINPROGRESS(e)) {
        printf("\n    NOTE: connect() answered %d, not WSAEWOULDBLOCK", e);
        nodus_net_close(c);
        return NODUS_SOCK_INVALID;
    }
    return c;
}

/* SO_ERROR of `s`, or -1 when getsockopt fails. */
static int so_error(nodus_sock_t s)
{
    int v = 0, vl = (int)sizeof(v);

    if (getsockopt((SOCKET)s, SOL_SOCKET, SO_ERROR, (char *)&v, &vl) != 0) {
        return -1;
    }
    return v;
}

/* A connected loopback TCP pair, both ends non-blocking: connect through
 * the backend (OUT without ERR), accept only after the listener was
 * reported IN. 0 or -1. */
static int lo_pair(nodus_sock_t *x, nodus_sock_t *y)
{
    uint16_t port = 0;
    nodus_sock_t l = lo_bound(&port, true), c, s;
    uint32_t r;

    if (l == NODUS_SOCK_INVALID) {
        return -1;
    }
    c = lo_connect_start(port);
    if (c == NODUS_SOCK_INVALID) {
        nodus_net_close(l);
        return -1;
    }
    r = wait_ready(c, NODUS_NET_OUT | NODUS_NET_CONNECT, ATTEMPTS);
    if ((r & NODUS_NET_OUT) == 0 || (r & NODUS_NET_ERR) != 0 ||
        (wait_ready(l, NODUS_NET_IN, ATTEMPTS) & NODUS_NET_IN) == 0) {
        nodus_net_close(c);
        nodus_net_close(l);
        return -1;
    }
    s = nodus_net_accept(l, NULL, NULL);
    nodus_net_close(l);
    if (s == NODUS_SOCK_INVALID || nodus_net_set_nonblocking(s) != 0) {
        if (s != NODUS_SOCK_INVALID) {
            nodus_net_close(s);
        }
        nodus_net_close(c);
        return -1;
    }
    *x = c;
    *y = s;
    return 0;
}

static void lo_pair_close(nodus_sock_t x, nodus_sock_t y)
{
    nodus_net_close(x);
    nodus_net_close(y);
}

/* Read and discard up to `want` bytes from the non-blocking `s`, waiting
 * through the backend (bounded) while fewer arrived. Bytes read. */
static long drain_bytes(nodus_sock_t s, long want)
{
    char b[64];
    long got = 0, r;
    int a;

    for (a = 0; got < want && a < ATTEMPTS; a++) {
        r = nodus_net_recv(s, b, sizeof(b) < (size_t)(want - got)
                                   ? sizeof(b) : (size_t)(want - got));
        if (r > 0) {
            got += r;
            continue;
        }
        if (r == 0 || !NODUS_NET_IS_EAGAIN(nodus_net_errno()) ||
            (wait_ready(s, NODUS_NET_IN, ATTEMPTS) & NODUS_NET_IN) == 0) {
            break;
        }
    }
    return got;
}

/* ── 1. startup / cleanup reference counting ───────────────────────── */

static void test_startup_refcount(void)
{
    int ok = 1;
    nodus_sock_t s;

    TEST("1 startup / cleanup reference counting");
    /* Baseline: before any startup, Winsock refuses. */
    s = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(s == NODUS_SOCK_INVALID);
    CHECK(nodus_net_errno() == WSANOTINITIALISED);
    if (s != NODUS_SOCK_INVALID) {
        nodus_net_close(s);
    }

    CHECK(nodus_net_startup() == 0);
    CHECK(nodus_net_startup() == 0);
    nodus_net_cleanup();                 /* one reference still held */
    s = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(s != NODUS_SOCK_INVALID);
    if (s != NODUS_SOCK_INVALID) {
        CHECK(nodus_net_close(s) == 0);
    }
    nodus_net_cleanup();                 /* the last one: WSACleanup     */
    s = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(s == NODUS_SOCK_INVALID);
    CHECK(nodus_net_errno() == WSANOTINITIALISED);
    if (s != NODUS_SOCK_INVALID) {
        nodus_net_close(s);
    }
    DONE();
}

/* ── 2. init with wake; add / mod / del and their refusals ─────────── */

static void test_add_mod_del(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    nodus_sock_t x = NODUS_SOCK_INVALID, y = NODUS_SOCK_INVALID, u;
    uint32_t r;

    TEST("2 init(wake); add / mod / del; refusals -> WSAEINVAL");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    CHECK(nodus_net_poll_is_open(&p));
    CHECK(lo_pair(&x, &y) == 0);
    u = nodus_net_socket(AF_INET, SOCK_STREAM);      /* never registered */
    CHECK(u != NODUS_SOCK_INVALID);

    /* add x IN under tag 1: nothing to read, nothing reported. */
    CHECK(nodus_net_poll_add(&p, x, 1, NODUS_NET_IN) == 0);
    CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH) == 0);

    WSASetLastError(0);
    CHECK(nodus_net_poll_add(&p, x, 9, NODUS_NET_IN) == -1);         /* twice */
    CHECK(nodus_net_errno() == WSAEINVAL);
    WSASetLastError(0);
    CHECK(nodus_net_poll_add(&p, u, NODUS_NET_TAG_WAKE, NODUS_NET_IN) == -1);
    CHECK(nodus_net_errno() == WSAEINVAL);
    WSASetLastError(0);
    CHECK(nodus_net_poll_add(&p, NODUS_SOCK_INVALID, 9, NODUS_NET_IN) == -1);
    CHECK(nodus_net_errno() == WSAEINVAL);
    WSASetLastError(0);
    CHECK(nodus_net_poll_mod(&p, x, NODUS_NET_TAG_WAKE, NODUS_NET_IN) == -1);
    CHECK(nodus_net_errno() == WSAEINVAL);
    WSASetLastError(0);
    CHECK(nodus_net_poll_mod(&p, u, 9, NODUS_NET_IN) == -1);         /* unknown */
    CHECK(nodus_net_errno() == WSAEINVAL);
    WSASetLastError(0);
    CHECK(nodus_net_poll_del(&p, u) == -1);                           /* unknown */
    CHECK(nodus_net_errno() == WSAEINVAL);

    /* mod x to OUT under tag 2: a connected socket is writable, reported
     * under the NEW tag with the NEW mask. */
    CHECK(nodus_net_poll_mod(&p, x, 2, NODUS_NET_OUT) == 0);
    r = wait_tag(&p, 2, ATTEMPTS);
    CHECK((r & NODUS_NET_OUT) != 0);
    CHECK((r & NODUS_NET_IN) == 0);
    {
        int n = nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH);

        CHECK(n == 1);
        CHECK(n == 1 && ev[0].tag == 2 && ev[0].ready == NODUS_NET_OUT);
    }

    /* del x: no longer reported; a second del and a mod are refused. */
    CHECK(nodus_net_poll_del(&p, x) == 0);
    CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH) == 0);
    WSASetLastError(0);
    CHECK(nodus_net_poll_del(&p, x) == -1);
    CHECK(nodus_net_errno() == WSAEINVAL);
    WSASetLastError(0);
    CHECK(nodus_net_poll_mod(&p, x, 3, NODUS_NET_IN) == -1);
    CHECK(nodus_net_errno() == WSAEINVAL);

    /* A deleted socket can be added again. */
    CHECK(nodus_net_poll_add(&p, x, 4, NODUS_NET_OUT) == 0);
    CHECK((wait_tag(&p, 4, ATTEMPTS) & NODUS_NET_OUT) != 0);
    CHECK(nodus_net_poll_del(&p, x) == 0);

    nodus_net_poll_free(&p);
    CHECK(!nodus_net_poll_is_open(&p));
    nodus_net_poll_free(&p);                          /* twice: no-op */
    if (u != NODUS_SOCK_INVALID) {
        nodus_net_close(u);
    }
    if (x != NODUS_SOCK_INVALID) {
        lo_pair_close(x, y);
    }
    DONE();
}

/* ── 3. level-triggered IN ─────────────────────────────────────────── */

static void test_level_in(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    nodus_sock_t x = NODUS_SOCK_INVALID, y = NODUS_SOCK_INVALID;
    int n;

    TEST("3 level-triggered IN until read");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    CHECK(lo_pair(&x, &y) == 0);
    CHECK(nodus_net_send(x, "abcd", 4) == 4);
    CHECK(nodus_net_poll_add(&p, y, 3, NODUS_NET_IN) == 0);
    /* Wait (bounded) until the bytes arrived ... */
    CHECK((wait_tag(&p, 3, ATTEMPTS) & NODUS_NET_IN) != 0);
    /* ... then two consecutive waits report it again: level, not edge. */
    n = nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH);
    CHECK(n == 1 && ev[0].tag == 3 && ev[0].ready == NODUS_NET_IN);
    n = nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH);
    CHECK(n == 1 && ev[0].tag == 3 && ev[0].ready == NODUS_NET_IN);
    /* Read every byte: nothing left to report. */
    CHECK(drain_bytes(y, 4) == 4);
    CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH) == 0);
    CHECK(nodus_net_poll_del(&p, y) == 0);
    nodus_net_poll_free(&p);
    if (x != NODUS_SOCK_INVALID) {
        lo_pair_close(x, y);
    }
    DONE();
}

/* ── 4. fair rotation ──────────────────────────────────────────────── */

/* Record `runs` waits of cap ROT_CAP into seen[run][slot] (tag index, -1 =
 * empty). Checks per wait: exactly min(cap, live) entries, every entry a
 * live tag, no tag twice. Returns 0 if every check held. */
static int rot_record(nodus_net_poll_t *p, const bool live[ROT_N], int nlive,
                      int runs, int seen[ROT_RUNS][ROT_N])
{
    nodus_net_event_t ev[ROT_CAP];
    int run, i, j, n, bad = 0;
    int want = nlive < ROT_CAP ? nlive : ROT_CAP;

    for (run = 0; run < runs; run++) {
        for (i = 0; i < ROT_N; i++) {
            seen[run][i] = 0;
        }
        n = nodus_net_poll_wait(p, 0, ev, ROT_CAP);
        if (n != want) {
            printf("\n    wait %d returned %d, expected %d", run, n, want);
            bad = 1;
            continue;
        }
        for (j = 0; j < n; j++) {
            uint64_t t = ev[j].tag;

            if (t < 100 || t >= 100 + ROT_N || !live[t - 100] ||
                ev[j].ready != NODUS_NET_IN) {
                printf("\n    wait %d: unexpected tag %llu ready 0x%x", run,
                       (unsigned long long)t, (unsigned)ev[j].ready);
                bad = 1;
                continue;
            }
            if (seen[run][t - 100]) {
                printf("\n    wait %d: tag %llu returned twice", run,
                       (unsigned long long)t);
                bad = 1;
            }
            seen[run][t - 100] = 1;
        }
    }
    return bad;
}

/* Every window of `win` consecutive recorded waits covers every live tag. */
static int rot_windows(const bool live[ROT_N], int runs, int win,
                       int seen[ROT_RUNS][ROT_N])
{
    int start, k, i, bad = 0;

    for (start = 0; start + win <= runs; start++) {
        for (i = 0; i < ROT_N; i++) {
            int hit = 0;

            if (!live[i]) {
                continue;
            }
            for (k = start; k < start + win; k++) {
                hit |= seen[k][i];
            }
            if (!hit) {
                printf("\n    tag %d not reported in waits %d..%d", 100 + i,
                       start, start + win - 1);
                bad = 1;
            }
        }
    }
    return bad;
}

static void test_fair_rotation(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    nodus_sock_t x[ROT_N], y[ROT_N];
    bool live[ROT_N];
    int seen[ROT_RUNS][ROT_N];
    int i, a, n = -1, npairs = 0, j;
    const int victim = 5;

    TEST("4 fair rotation: 10 ready, cap 3, del mid-rotation");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    for (i = 0; i < ROT_N; i++) {
        live[i] = false;
        if (lo_pair(&x[i], &y[i]) != 0) {
            CHECK(0);
            break;
        }
        npairs++;
        CHECK(nodus_net_send(x[i], "r", 1) == 1);
        CHECK(nodus_net_poll_add(&p, y[i], (uint64_t)(100 + i), NODUS_NET_IN) == 0);
        live[i] = true;
    }

    if (ok) {
        /* Readiness first (bounded): one wait with room for all reports
         * all 10 — every byte has arrived and stays unread. */
        for (a = 0; a < ATTEMPTS; a++) {
            n = nodus_net_poll_wait(&p, ATTEMPT_MS, ev, NODUS_NET_POLL_MAX_BATCH);
            if (n < 0 || n == ROT_N) {
                break;
            }
        }
        CHECK(n == ROT_N);
    }

    if (ok) {
        /* 10 live, cap 3: any ceil(10/3) = 4 consecutive waits cover all. */
        CHECK(rot_record(&p, live, ROT_N, ROT_RUNS, seen) == 0);
        CHECK(rot_windows(live, ROT_RUNS, (ROT_N + ROT_CAP - 1) / ROT_CAP,
                          seen) == 0);

        /* One more wait so the cursor sits mid-registry, then del an entry
         * in the middle of the registry. */
        CHECK(nodus_net_poll_wait(&p, 0, ev, ROT_CAP) == ROT_CAP);
        CHECK(nodus_net_poll_del(&p, y[victim]) == 0);
        live[victim] = false;

        /* 9 live, cap 3: any ceil(9/3) = 3 consecutive waits cover all
         * 9, and the deleted tag never appears (rot_record refuses it). */
        CHECK(rot_record(&p, live, ROT_N - 1, ROT_RUNS, seen) == 0);
        CHECK(rot_windows(live, ROT_RUNS, (ROT_N - 1 + ROT_CAP - 1) / ROT_CAP,
                          seen) == 0);
    }

    for (j = 0; j < npairs; j++) {
        if (live[j]) {
            nodus_net_poll_del(&p, y[j]);
        }
        lo_pair_close(x[j], y[j]);
    }
    nodus_net_poll_free(&p);
    DONE();
}

/* ── 5. wake from another thread ───────────────────────────────────── */

static DWORD WINAPI waker(LPVOID arg)
{
    nodus_net_poll_wake((nodus_net_poll_t *)arg);
    return 0;
}

static void test_wake_thread(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    HANDLE th;

    TEST("5 wake from another thread ends wait(-1)");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    if (ok) {
        th = CreateThread(NULL, 0, waker, &p, 0, NULL);
        CHECK(th != NULL);
        if (th != NULL) {
            /* Without a limit: only the wake can end this wait. */
            CHECK(nodus_net_poll_wait(&p, -1, ev, NODUS_NET_POLL_MAX_BATCH) == 0);
            /* R5 free order: join every waker before _free. */
            CHECK(WaitForSingleObject(th, INFINITE) == WAIT_OBJECT_0);
            CloseHandle(th);
            CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH) == 0);
        }
    }
    nodus_net_poll_free(&p);
    DONE();
}

/* ── 6. wake + a ready socket in one wait ──────────────────────────── */

static void test_wake_and_ready(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    nodus_sock_t x = NODUS_SOCK_INVALID, y = NODUS_SOCK_INVALID;
    int n, i;

    TEST("6 wake + ready socket: socket reported, wake not");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    CHECK(lo_pair(&x, &y) == 0);
    CHECK(nodus_net_send(x, "w", 1) == 1);
    /* The byte has arrived before the socket joins the set. */
    CHECK((wait_ready(y, NODUS_NET_IN, ATTEMPTS) & NODUS_NET_IN) != 0);
    CHECK(nodus_net_poll_add(&p, y, 6, NODUS_NET_IN) == 0);
    nodus_net_poll_wake(&p);
    n = nodus_net_poll_wait(&p, -1, ev, NODUS_NET_POLL_MAX_BATCH);
    CHECK(n == 1);
    for (i = 0; i < n; i++) {
        CHECK(ev[i].tag != NODUS_NET_TAG_WAKE);
    }
    CHECK(n == 1 && ev[0].tag == 6 && ev[0].ready == NODUS_NET_IN);
    CHECK(drain_bytes(y, 1) == 1);
    CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH) == 0);
    CHECK(nodus_net_poll_del(&p, y) == 0);
    nodus_net_poll_free(&p);
    if (x != NODUS_SOCK_INVALID) {
        lo_pair_close(x, y);
    }
    DONE();
}

/* ── 7. connect probe: succeeded and refused ───────────────────────── */

static void test_connect_probe(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_sock_t l, c, h;
    uint16_t port = 0;
    uint32_t r;
    int e;

    TEST("7 connect probe: succeeded and refused");
    CHECK(nodus_net_poll_init(&p, false) == 0);

    /* Succeeded: a listening loopback port. */
    l = lo_bound(&port, true);
    CHECK(l != NODUS_SOCK_INVALID);
    c = l != NODUS_SOCK_INVALID ? lo_connect_start(port) : NODUS_SOCK_INVALID;
    CHECK(c != NODUS_SOCK_INVALID);
    if (c != NODUS_SOCK_INVALID) {
        CHECK(nodus_net_poll_add(&p, c, 71, NODUS_NET_OUT | NODUS_NET_CONNECT) == 0);
        r = wait_tag(&p, 71, ATTEMPTS);
        CHECK((r & NODUS_NET_OUT) != 0);
        CHECK((r & NODUS_NET_ERR) == 0);
        CHECK(nodus_net_probe_connect(c) > 0);
        e = so_error(c);
        CHECK(e == 0);
        CHECK(nodus_net_poll_del(&p, c) == 0);
        nodus_net_close(c);
    }
    if (l != NODUS_SOCK_INVALID) {
        nodus_net_close(l);
    }

    /* Refused: the port is held by a bound socket that does not listen. */
    h = lo_bound(&port, false);
    CHECK(h != NODUS_SOCK_INVALID);
    c = h != NODUS_SOCK_INVALID ? lo_connect_start(port) : NODUS_SOCK_INVALID;
    CHECK(c != NODUS_SOCK_INVALID);
    if (c != NODUS_SOCK_INVALID) {
        CHECK(nodus_net_poll_add(&p, c, 72, NODUS_NET_OUT | NODUS_NET_IN |
                                 NODUS_NET_CONNECT) == 0);
        /* Windows retries a SYN answered by RST before it reports the
         * refusal: REFUSE_ATTEMPTS, not ATTEMPTS. */
        r = wait_tag(&p, 72, REFUSE_ATTEMPTS);
        CHECK(r != 0);
        CHECK((r & NODUS_NET_ERR) != 0);
        CHECK(nodus_net_probe_connect(c) > 0);
        e = so_error(c);
        CHECK(e != 0);
        if (e != 0) {
            printf("\n    note: refused connect SO_ERROR = %d (WSAECONNREFUSED = %d)",
                   e, WSAECONNREFUSED);
        }
        CHECK(nodus_net_poll_del(&p, c) == 0);
        nodus_net_close(c);
    }
    if (h != NODUS_SOCK_INVALID) {
        nodus_net_close(h);
    }
    nodus_net_poll_free(&p);
    DONE();
}

/* ── 8. WSAENOTSOCK eviction ───────────────────────────────────────── */

static void test_enotsock_evict(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    nodus_sock_t v;
    int n;

    TEST("8 closed without del -> ERR|HUP once, then gone");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    v = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(v != NODUS_SOCK_INVALID);
    if (ok) {
        CHECK(nodus_net_poll_add(&p, v, 8, NODUS_NET_IN) == 0);
        /* Closed WITHOUT _del; no socket is created before the wait. */
        CHECK(closesocket((SOCKET)v) == 0);
        n = nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH);
        CHECK(n == 1);
        CHECK(n == 1 && ev[0].tag == 8 &&
              ev[0].ready == (NODUS_NET_ERR | NODUS_NET_HUP));
        n = nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH);
        CHECK(n == 0);
        /* The entry was evicted: a del of the old value is refused. */
        WSASetLastError(0);
        CHECK(nodus_net_poll_del(&p, v) == -1);
        CHECK(nodus_net_errno() == WSAEINVAL);
    }
    nodus_net_poll_free(&p);
    DONE();
}

/* ── 9. empty set ──────────────────────────────────────────────────── */

static void test_empty_set(void)
{
    int ok = 1;
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];

    TEST("9 empty set: wait(0) = 0, wait(-1) refused");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH) == 0);
    WSASetLastError(0);
    CHECK(nodus_net_poll_wait(&p, -1, ev, NODUS_NET_POLL_MAX_BATCH) == -1);
    CHECK(nodus_net_errno() == WSAEINVAL);
    nodus_net_poll_free(&p);
    DONE();
}

int main(void)
{
    printf("test_net_poll_win (select arm)\n");
    /* Case 1 must run before anything holds a Winsock reference. */
    test_startup_refcount();
    if (nodus_net_startup() != 0) {
        printf("  nodus_net_startup failed: %d\n", nodus_net_errno());
        return 1;
    }
    test_add_mod_del();
    test_level_in();
    test_fair_rotation();
    test_wake_thread();
    test_wake_and_ready();
    test_connect_probe();
    test_enotsock_evict();
    test_empty_set();
    nodus_net_cleanup();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
