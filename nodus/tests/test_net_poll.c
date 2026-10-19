/**
 * @file nodus/tests/test_net_poll.c
 * @brief Unit test of the nodus_net_poll readiness backend, Linux (epoll)
 *        arm — net-layer design 2026-10-19 §2 + §9 rev 1 + §10, package N1.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · add / mod / del: a registered socket is reported under the tag it
 *     was last given; mask 0 keeps it registered but silent; del removes
 *     it; a second add of the same socket and the reserved wake tag are
 *     refused.
 *   · level vs edge: without NODUS_NET_EDGE unread bytes are reported on
 *     every wait; with it only once per arrival (EPOLLET passed through).
 *   · the result bits stay apart (R2): a peer's write-half shutdown is
 *     RDHUP (+ IN) without HUP or ERR; both halves shut is HUP; a refused
 *     connect is ERR, and SO_ERROR then reads ECONNREFUSED.
 *   · the wake: a wake from another thread ends a wait WITHOUT a time
 *     limit (returning at all is the proof), is not reported as an event,
 *     and the eventfd is drained (a direct read then answers EAGAIN); two
 *     pending wakes are drained by one wait; a set without wake ignores it.
 *   · a wake and a ready socket in the same wait (cap 64): the socket is
 *     reported, the wake is not, and the wake is drained by that call.
 *   · nodus_net_probe_connect answers "finished" for a refused connect
 *     and for a loopback connect that succeeded.
 *   · the wait cap: 3 ready sockets, cap 2 → 2 written; cap 64
 *     (NODUS_NET_POLL_MAX_BATCH) accepted; cap 0 and cap 65 refused.
 *   · the shims: nodus_net_socket is non-blocking + close-on-exec; an
 *     accepted socket is neither until set_nonblocking / set_cloexec set
 *     the flags; nodus_net_close keeps errno; send / recv move bytes.
 *
 * REQUIRES: compile — a default Linux build (no flags); environment —
 *   nothing. Loopback TCP on 127.0.0.1 with kernel-chosen ports; /proc
 *   mounted (the wake case reads /proc/self/task/<tid>/stat). One helper
 *   thread (the wake case). ctest -j safe: no fixed port, no file written.
 *   ctest TIMEOUT 120 s (nodus/CMakeLists.txt) is a hang guard only — the
 *   one wait without a limit is the wake case's.
 *
 * LEAVES BEHIND: nothing — every socket is closed, no file is written.
 *
 * SYNCHRONISATION: no sleep is used as synchronisation and no assertion
 *   is decided by a clock. Every "becomes ready" waits through the backend
 *   with a READY_MS (5 s) limit; expiry is a FAIL, never a pass. Every
 *   "nothing ready" check is wait(0) on a state where no byte is in
 *   flight. Listeners are non-blocking and accept only after the backend
 *   reported them IN; connects are non-blocking and wait for OUT.
 *
 * HOW IT CAN LIE:
 *   · It tests the backend, NOT that the 4004 host (net/nodus_p2p_host.c,
 *     moved out of nodus_witness_p2p.c in N3) issues the same
 *     syscalls as before N1 — that claim rests on reading the diff (and
 *     an strace comparison, if one is made); test_p2p_switch's loopback
 *     cases drive the host itself.
 *   · The HUP case relies on Linux tcp_poll reporting EPOLLHUP once both
 *     shutdown directions are set; a kernel that reported it differently
 *     would fail the case, not pass it wrongly.
 *   · The level/edge and cap cases let the bytes arrive BEFORE the
 *     sockets join the set and rely on epoll reporting a socket that is
 *     already ready at EPOLL_CTL_ADD, EPOLLET included (once). A kernel
 *     that did not would FAIL those cases, not pass them wrongly.
 *   · The refused-connect case assumes a non-blocking loopback connect to
 *     a bound, not-listening port returns EINPROGRESS (the RST is handled
 *     after connect returns). A kernel that processed the RST inside the
 *     connect call would return ECONNREFUSED at once and FAIL the case —
 *     a false FAIL, never a false PASS.
 *   · The wake case wants the wake to land while the main thread is
 *     BLOCKED in epoll_wait (the interrupted-wait path). The waker polls
 *     the main thread's /proc state for 'S' (interruptible sleep), bounded
 *     by WAKER_ATTEMPTS, and assumes an 'S' seen after pthread_create is
 *     that epoll_wait — nothing between pthread_create returning and the
 *     wait sleeps, but that is read, not proven. If 'S' is never seen the
 *     waker wakes anyway: the case then exercises only the pending-wake
 *     path (wake before wait), still PASSES, and prints a NOTE saying the
 *     interrupted-wait path was NOT exercised. Read the output.
 *   · Windows' select arm is NOT exercised here (no Windows machine) —
 *     neither its fair rotation, its WSAENOTSOCK eviction, nor its wake
 *     pair; its only claim is that it compiles.
 */

#include "net/nodus_net_poll.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int passed = 0, failed = 0;

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while (0)
#define CHECK(c)   do { if (!(c)) { ok = 0; printf("\n    check failed: %s (line %d)", #c, __LINE__); } } while (0)
#define DONE()     do { if (ok) { printf("PASS\n"); passed++; } \
                        else { printf("\n    FAIL\n"); failed++; } } while (0)

#define READY_MS 5000                /* the bound on every "becomes ready" */
#define WAKER_ATTEMPTS 200000        /* /proc reads before waking anyway   */

/* ── loopback helpers ──────────────────────────────────────────────── */

/* The ready bits `fd` reports for `mask` within READY_MS, through a set of
 * its own (0 = not ready in time, or the set failed). */
static uint32_t wait_ready(int fd, uint32_t mask)
{
    nodus_net_poll_t q;
    nodus_net_event_t ev[1];
    uint32_t r = 0;

    if (nodus_net_poll_init(&q, false) != 0) {
        return 0;
    }
    if (nodus_net_poll_add(&q, fd, 1, mask) == 0 &&
        nodus_net_poll_wait(&q, READY_MS, ev, 1) == 1 && ev[0].tag == 1) {
        r = ev[0].ready;
    }
    nodus_net_poll_free(&q);
    return r;
}

/* A non-blocking listening socket on 127.0.0.1:<kernel port>; *port gets
 * the port. */
static int lo_listener(uint16_t *port)
{
    struct sockaddr_in a;
    socklen_t al = (socklen_t)sizeof(a);
    int l = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

    if (l < 0) {
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(l, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(l, 8) != 0 ||
        getsockname(l, (struct sockaddr *)&a, &al) != 0) {
        close(l);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return l;
}

static void lo_addr(struct sockaddr_in *a, uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a->sin_port = htons(port);
}

/* Accept on the non-blocking listener `l` once the backend reported it IN
 * (never a blocking accept). The result carries no flags. -1 on failure. */
static int lo_accept(int l)
{
    if ((wait_ready(l, NODUS_NET_IN) & NODUS_NET_IN) == 0) {
        return -1;
    }
    return nodus_net_accept(l, NULL, NULL);
}

/* A non-blocking connect from nodus_net_socket to 127.0.0.1:port, waited
 * through the backend until OUT without ERR / HUP. -1 on failure. */
static int lo_connect(uint16_t port)
{
    struct sockaddr_in a;
    int c = nodus_net_socket(AF_INET, SOCK_STREAM), rc;
    uint32_t r;

    if (c < 0) {
        return -1;
    }
    lo_addr(&a, port);
    rc = connect(c, (struct sockaddr *)&a, sizeof(a));
    if (rc != 0 && !NODUS_NET_IS_EINPROGRESS(errno)) {
        close(c);
        return -1;
    }
    r = wait_ready(c, NODUS_NET_OUT | NODUS_NET_CONNECT);
    if ((r & NODUS_NET_OUT) == 0 || (r & (NODUS_NET_ERR | NODUS_NET_HUP)) != 0) {
        close(c);
        return -1;
    }
    return c;
}

/* A connected loopback TCP pair, both ends non-blocking. 0 or -1. */
static int lo_pair(int *x, int *y)
{
    uint16_t port = 0;
    int l = lo_listener(&port), c, s;

    if (l < 0) {
        return -1;
    }
    c = lo_connect(port);
    if (c < 0) {
        close(l);
        return -1;
    }
    s = lo_accept(l);
    close(l);
    if (s < 0) {
        close(c);
        return -1;
    }
    if (nodus_net_set_nonblocking(s) != 0) {
        close(c);
        close(s);
        return -1;
    }
    *x = s;
    *y = c;
    return 0;
}

/* ── cases ─────────────────────────────────────────────────────────── */

static void test_add_mod_del(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8];
    int a = -1, b = -1, ok = 1, n;

    TEST("add / mod / del, mask 0, duplicate add, reserved tag");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    CHECK(nodus_net_poll_is_open(&p));
    CHECK(lo_pair(&a, &b) == 0);
    CHECK(nodus_net_poll_add(&p, a, 7, NODUS_NET_IN) == 0);
    CHECK(nodus_net_poll_add(&p, a, 8, NODUS_NET_IN) != 0);     /* duplicate */
    CHECK(nodus_net_poll_add(&p, b, NODUS_NET_TAG_WAKE, NODUS_NET_IN) != 0);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 8) == 0);              /* nothing yet */
    CHECK(send(b, "x", 1, MSG_NOSIGNAL) == 1);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1);
    CHECK(n == 1 && ev[0].tag == 7 && (ev[0].ready & NODUS_NET_IN) != 0);
    CHECK(nodus_net_poll_mod(&p, a, 7, 0) == 0);                /* silent */
    CHECK(nodus_net_poll_wait(&p, 0, ev, 8) == 0);
    CHECK(nodus_net_poll_mod(&p, a, 9, NODUS_NET_IN) == 0);     /* new tag */
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1 && ev[0].tag == 9);
    CHECK(nodus_net_poll_del(&p, a) == 0);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 8) == 0);
    CHECK(nodus_net_poll_del(&p, a) != 0);                      /* not there */
    CHECK(nodus_net_poll_mod(&p, a, 9, NODUS_NET_IN) != 0);
    nodus_net_poll_free(&p);
    CHECK(!nodus_net_poll_is_open(&p));
    nodus_net_poll_free(&p);                                    /* twice: safe */
    close(a);
    close(b);
    DONE();
}

static void test_level_vs_edge(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8];
    int a = -1, b = -1, c = -1, d = -1, ok = 1, n, i, saw_lvl = 0, saw_edge = 0;

    TEST("level reports unread bytes every wait, EDGE once per arrival");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    CHECK(lo_pair(&a, &b) == 0);
    CHECK(lo_pair(&c, &d) == 0);
    CHECK(send(b, "x", 1, MSG_NOSIGNAL) == 1);
    CHECK(send(d, "y", 1, MSG_NOSIGNAL) == 1);
    /* Both bytes have arrived (each reported by a set of its own) BEFORE
     * the two sockets join `p`: epoll reports a socket that is ready when
     * added, EDGE included — so one wait(0) must see both, with no loop. */
    CHECK((wait_ready(a, NODUS_NET_IN) & NODUS_NET_IN) != 0);
    CHECK((wait_ready(c, NODUS_NET_IN) & NODUS_NET_IN) != 0);
    CHECK(nodus_net_poll_add(&p, a, 1, NODUS_NET_IN) == 0);
    CHECK(nodus_net_poll_add(&p, c, 2, NODUS_NET_IN | NODUS_NET_EDGE) == 0);
    n = nodus_net_poll_wait(&p, 0, ev, 8);
    for (i = 0; i < n; i++) {
        saw_lvl |= ev[i].tag == 1;
        saw_edge |= ev[i].tag == 2;
    }
    CHECK(n == 2 && saw_lvl && saw_edge);
    /* Nothing new arrived and nothing was read: level again, edge not. */
    n = nodus_net_poll_wait(&p, 0, ev, 8);
    CHECK(n == 1 && ev[0].tag == 1);
    n = nodus_net_poll_wait(&p, 0, ev, 8);
    CHECK(n == 1 && ev[0].tag == 1);
    /* A new arrival fires the edge socket once more. */
    CHECK(nodus_net_poll_del(&p, a) == 0);
    CHECK(send(d, "z", 1, MSG_NOSIGNAL) == 1);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1 && ev[0].tag == 2 && (ev[0].ready & NODUS_NET_IN) != 0);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 8) == 0);
    nodus_net_poll_free(&p);
    close(a);
    close(b);
    close(c);
    close(d);
    DONE();
}

static void test_rdhup_hup_bits(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8];
    int a = -1, b = -1, ok = 1, n;

    TEST("RDHUP (peer write half shut) apart from HUP and ERR");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    CHECK(lo_pair(&a, &b) == 0);
    CHECK(nodus_net_poll_add(&p, a, 3, NODUS_NET_IN | NODUS_NET_RDHUP) == 0);
    CHECK(shutdown(b, SHUT_WR) == 0);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_RDHUP) != 0);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_IN) != 0);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_HUP) == 0);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_ERR) == 0);
    /* Our own write half shut as well: both directions → HUP. */
    CHECK(shutdown(a, SHUT_WR) == 0);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_HUP) != 0);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_RDHUP) != 0);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_ERR) == 0);
    nodus_net_poll_free(&p);
    close(a);
    close(b);
    DONE();
}

static void test_refused_connect(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8];
    struct sockaddr_in a;
    socklen_t al = (socklen_t)sizeof(a);
    int hold, s, ok = 1, n, rc, e, err = 0;
    socklen_t el = (socklen_t)sizeof(err);

    TEST("refused connect: ERR, probe finished, SO_ERROR ECONNREFUSED");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    /* A bound, NOT listening socket holds the port for the whole case, so
     * no other process can take it: the connect is refused (RST). */
    hold = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(hold >= 0 && bind(hold, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(getsockname(hold, (struct sockaddr *)&a, &al) == 0);
    s = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(s != NODUS_SOCK_INVALID);
    rc = connect(s, (struct sockaddr *)&a, sizeof(a));
    e = nodus_net_errno();
    CHECK(rc != 0 && NODUS_NET_IS_EINPROGRESS(e));
    CHECK(nodus_net_poll_add(&p, s, 4, NODUS_NET_OUT | NODUS_NET_IN |
                                         NODUS_NET_CONNECT) == 0);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1 && ev[0].tag == 4 && (ev[0].ready & NODUS_NET_ERR) != 0);
    CHECK(n == 1 && (ev[0].ready & NODUS_NET_CONNECT) == 0);
    CHECK(nodus_net_probe_connect(s) > 0);
    CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) == 0 &&
          err == ECONNREFUSED);
    CHECK(nodus_net_poll_del(&p, s) == 0);
    nodus_net_poll_free(&p);
    close(s);
    close(hold);
    DONE();
}

static void test_connect_ok(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8];
    struct sockaddr_in a;
    uint16_t port = 0;
    int l, s, ok = 1, n, rc, e, err = -1, acc;
    socklen_t el = (socklen_t)sizeof(err);

    TEST("loopback connect: OUT without ERR, probe finished, SO_ERROR 0");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    l = lo_listener(&port);
    CHECK(l >= 0);
    s = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(s != NODUS_SOCK_INVALID);
    lo_addr(&a, port);
    rc = connect(s, (struct sockaddr *)&a, sizeof(a));
    e = nodus_net_errno();
    CHECK(rc == 0 || NODUS_NET_IS_EINPROGRESS(e));
    CHECK(nodus_net_poll_add(&p, s, 5, NODUS_NET_OUT | NODUS_NET_CONNECT) == 0);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    CHECK(n == 1 && ev[0].tag == 5 && (ev[0].ready & NODUS_NET_OUT) != 0);
    CHECK(n == 1 && (ev[0].ready & (NODUS_NET_ERR | NODUS_NET_HUP)) == 0);
    CHECK(nodus_net_probe_connect(s) > 0);
    CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0);
    /* The accepted end (non-blocking listener, accepted once reported IN):
     * accept(2) gives it neither flag — the shims set them. */
    acc = l >= 0 ? lo_accept(l) : -1;
    CHECK(acc != NODUS_SOCK_INVALID);
    if (acc != NODUS_SOCK_INVALID) {
        CHECK((fcntl(acc, F_GETFL, 0) & O_NONBLOCK) == 0);
        CHECK((fcntl(acc, F_GETFD, 0) & FD_CLOEXEC) == 0);
        CHECK(nodus_net_set_nonblocking(acc) == 0);
        CHECK(nodus_net_set_cloexec(acc) == 0);
        CHECK((fcntl(acc, F_GETFL, 0) & O_NONBLOCK) != 0);
        CHECK((fcntl(acc, F_GETFD, 0) & FD_CLOEXEC) != 0);
        CHECK(nodus_net_send(s, "ab", 2) == 2);
        {
            char buf[4];
            nodus_net_event_t e2[2];
            nodus_net_poll_t q;

            CHECK(nodus_net_poll_init(&q, false) == 0);
            CHECK(nodus_net_poll_add(&q, acc, 1, NODUS_NET_IN) == 0);
            CHECK(nodus_net_poll_wait(&q, READY_MS, e2, 2) == 1);
            CHECK(nodus_net_recv(acc, buf, sizeof(buf)) == 2 &&
                  memcmp(buf, "ab", 2) == 0);
            CHECK(nodus_net_recv(acc, buf, sizeof(buf)) == -1 &&
                  NODUS_NET_IS_EAGAIN(nodus_net_errno()));
            nodus_net_poll_free(&q);
        }
        (void)nodus_net_close(acc);
    }
    nodus_net_poll_free(&p);
    close(s);
    if (l >= 0) {
        close(l);
    }
    DONE();
}

/* The waker: wait (bounded by WAKER_ATTEMPTS reads of /proc) until the
 * main thread is in an interruptible sleep — the epoll_wait — then wake.
 * Wakes whether or not it saw that, so the wait without limit returns. */
typedef struct {
    nodus_net_poll_t *p;
    pid_t             tid;               /* the thread blocked in _wait  */
    int               saw_sleep;         /* 1 = woke an observed sleep   */
} waker_arg_t;

static int thread_state(pid_t tid)
{
    char path[64], buf[512];
    const char *rp;
    ssize_t n;
    int fd;

    snprintf(path, sizeof(path), "/proc/self/task/%d/stat", (int)tid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    /* "pid (comm) S ..." — comm may hold spaces and ')': take the last. */
    rp = strrchr(buf, ')');
    if (rp == NULL || rp[1] != ' ' || rp[2] == '\0') {
        return -1;
    }
    return (unsigned char)rp[2];
}

static void *waker(void *arg)
{
    waker_arg_t *w = (waker_arg_t *)arg;
    int i;

    for (i = 0; i < WAKER_ATTEMPTS; i++) {
        if (thread_state(w->tid) == 'S') {
            w->saw_sleep = 1;
            break;
        }
        sched_yield();
    }
    nodus_net_poll_wake(w->p);
    return NULL;
}

static void test_wake(void)
{
    nodus_net_poll_t p, q;
    nodus_net_event_t ev[8];
    pthread_t th;
    waker_arg_t wa;
    uint64_t v;
    int ok = 1, n, created;

    TEST("wake from another thread ends a wait without limit; drained");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    CHECK(p.wake_fd >= 0);
    wa.p = &p;
    wa.tid = (pid_t)syscall(SYS_gettid);
    wa.saw_sleep = 0;
    created = pthread_create(&th, NULL, waker, &wa) == 0;
    CHECK(created);
    if (created) {
        /* No limit: only the wake can end this wait (the ctest TIMEOUT is
         * the hang guard). Nothing else is registered. */
        n = nodus_net_poll_wait(&p, -1, ev, 8);
        CHECK(pthread_join(th, NULL) == 0);
        CHECK(n == 0);
        /* Drained: the eventfd holds nothing. */
        errno = 0;
        CHECK(read(p.wake_fd, &v, sizeof(v)) == -1 && errno == EAGAIN);
    }
    /* Two wakes before one wait: one wait drains both. */
    nodus_net_poll_wake(&p);
    nodus_net_poll_wake(&p);
    CHECK(nodus_net_poll_wait(&p, READY_MS, ev, 8) == 0);
    errno = 0;
    CHECK(read(p.wake_fd, &v, sizeof(v)) == -1 && errno == EAGAIN);
    nodus_net_poll_free(&p);
    /* No wake asked: the call is a no-op. */
    CHECK(nodus_net_poll_init(&q, false) == 0);
    CHECK(q.wake_fd == -1);
    nodus_net_poll_wake(&q);
    CHECK(nodus_net_poll_wait(&q, 0, ev, 8) == 0);
    nodus_net_poll_free(&q);
    DONE();
    if (created && !wa.saw_sleep) {
        printf("    NOTE: the waker never saw the main thread asleep in the "
               "wait (%d /proc reads):\n          the interrupted-wait path "
               "was NOT exercised, only the pending-wake path.\n",
               WAKER_ATTEMPTS);
    } else if (created) {
        printf("    (the wake interrupted a wait the waker saw asleep)\n");
    }
}

static void test_wake_and_socket(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[NODUS_NET_POLL_MAX_BATCH];
    uint64_t v;
    int a = -1, b = -1, ok = 1, n;

    TEST("wake + ready socket in one wait (cap 64): socket only");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    CHECK(lo_pair(&a, &b) == 0);
    CHECK(nodus_net_poll_add(&p, a, 21, NODUS_NET_IN) == 0);
    CHECK(send(b, "w", 1, MSG_NOSIGNAL) == 1);
    /* The byte has arrived (level: it stays ready, nothing reads it). */
    n = nodus_net_poll_wait(&p, READY_MS, ev, NODUS_NET_POLL_MAX_BATCH);
    CHECK(n == 1 && ev[0].tag == 21);
    /* Now both are pending at once: the same wait sees the eventfd and
     * the socket; it reports the socket, and the eventfd is drained by
     * that very call (the read below finds it empty). */
    nodus_net_poll_wake(&p);
    n = nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH);
    CHECK(n == 1);
    CHECK(n == 1 && ev[0].tag == 21 && (ev[0].ready & NODUS_NET_IN) != 0);
    CHECK(n < 1 || ev[0].tag != NODUS_NET_TAG_WAKE);
    errno = 0;
    CHECK(read(p.wake_fd, &v, sizeof(v)) == -1 && errno == EAGAIN);
    nodus_net_poll_free(&p);
    close(a);
    close(b);
    DONE();
}

static void test_wait_cap(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8], ev64[NODUS_NET_POLL_MAX_BATCH];
    int x[3], y[3], ok = 1, i;

    TEST("wait cap honoured; cap 64 accepted, cap 0 and 65 refused");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    for (i = 0; i < 3; i++) {
        x[i] = y[i] = -1;
        CHECK(lo_pair(&x[i], &y[i]) == 0);
        CHECK(send(y[i], "q", 1, MSG_NOSIGNAL) == 1);
        /* Arrived before the socket joins `p` (level: stays ready). */
        CHECK((wait_ready(x[i], NODUS_NET_IN) & NODUS_NET_IN) != 0);
        CHECK(nodus_net_poll_add(&p, x[i], (uint64_t)(10 + i), NODUS_NET_IN) == 0);
    }
    CHECK(nodus_net_poll_wait(&p, 0, ev, 8) == 3);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 2) == 2);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 1) == 1);
    CHECK(nodus_net_poll_wait(&p, 0, ev64, NODUS_NET_POLL_MAX_BATCH) == 3);
    errno = 0;
    CHECK(nodus_net_poll_wait(&p, 0, ev, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(nodus_net_poll_wait(&p, 0, ev64, NODUS_NET_POLL_MAX_BATCH + 1) == -1 &&
          errno == EINVAL);
    nodus_net_poll_free(&p);
    for (i = 0; i < 3; i++) {
        if (x[i] >= 0) {
            close(x[i]);
        }
        if (y[i] >= 0) {
            close(y[i]);
        }
    }
    DONE();
}

static void test_shims(void)
{
    int ok = 1, s, fl;

    TEST("socket shim non-blocking + cloexec; close keeps errno");
    s = nodus_net_socket(AF_INET, SOCK_STREAM);
    CHECK(s != NODUS_SOCK_INVALID);
    fl = fcntl(s, F_GETFL, 0);
    CHECK(fl >= 0 && (fl & O_NONBLOCK) != 0);
    fl = fcntl(s, F_GETFD, 0);
    CHECK(fl >= 0 && (fl & FD_CLOEXEC) != 0);
    errno = ETIMEDOUT;
    CHECK(nodus_net_close(s) == 0);
    CHECK(errno == ETIMEDOUT);
    errno = ETIMEDOUT;
    CHECK(nodus_net_close(s) == -1);         /* already closed: EBADF … */
    CHECK(errno == ETIMEDOUT);               /* … but errno kept */
    CHECK(NODUS_NET_IS_EAGAIN(EAGAIN) && NODUS_NET_IS_EAGAIN(EWOULDBLOCK));
    CHECK(NODUS_NET_IS_EINPROGRESS(EINPROGRESS) && !NODUS_NET_IS_EINPROGRESS(EAGAIN));
    CHECK(NODUS_NET_IS_EINTR_IO(EINTR) && !NODUS_NET_IS_EINTR_IO(EAGAIN));
    CHECK(NODUS_NET_IS_PEER_GONE(EPIPE) && NODUS_NET_IS_PEER_GONE(ECONNRESET));
    CHECK(NODUS_NET_IS_CONNABORTED(ECONNABORTED));
    CHECK(nodus_net_startup() == 0);
    nodus_net_cleanup();
    DONE();
}

int main(void)
{
    printf("test_net_poll (nodus_net_poll, Linux epoll arm)\n");
    test_add_mod_del();
    test_level_vs_edge();
    test_rdhup_hup_bits();
    test_refused_connect();
    test_connect_ok();
    test_wake();
    test_wake_and_socket();
    test_wait_cap();
    test_shims();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
