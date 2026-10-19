/**
 * @file nodus/tests/test_net_poll.c
 * @brief Unit test of the nodus_net_poll readiness backend, Linux (epoll)
 *        arm — net-layer design 2026-10-19 §2 + §9 rev 1, package N1.
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
 *   · the wake: a wake from another thread ends a wait that has a 5 s
 *     limit, is not reported as an event, and the eventfd is drained
 *     (a direct read then answers EAGAIN); a set without wake ignores it.
 *   · nodus_net_probe_connect answers "finished" for a refused connect
 *     and for a loopback connect that succeeded.
 *   · the wait cap: 3 ready sockets, cap 2 → 2 written; cap 0 and
 *     cap > NODUS_NET_POLL_MAX_BATCH are refused.
 *   · the shims: nodus_net_socket is non-blocking + close-on-exec;
 *     set_nonblocking / set_cloexec set the flags on an accepted socket;
 *     nodus_net_close keeps errno; send / recv move bytes.
 *
 * REQUIRES: compile — a default Linux build (no flags); environment —
 *   nothing. Loopback TCP on 127.0.0.1 with kernel-chosen ports.
 *   One helper thread (the wake case). ctest -j safe: no fixed port, no
 *   file.
 *
 * LEAVES BEHIND: nothing — every socket is closed, no file is written.
 *
 * HOW IT CAN LIE:
 *   · It tests the backend, NOT that nodus_witness_p2p.c issues the same
 *     syscalls as before N1 — that claim rests on reading the diff (and
 *     an strace comparison, if one is made); test_p2p_switch's loopback
 *     cases drive the host itself.
 *   · The HUP case relies on Linux tcp_poll reporting EPOLLHUP once both
 *     shutdown directions are set; a kernel that reported it differently
 *     would fail the case, not pass it wrongly.
 *   · The wake case's "ended before the limit" is the one timing-shaped
 *     check: it asserts elapsed < 4 s against a 5 s wait. A wake that
 *     never arrives fails it; a scheduler stall over 4 s would too (a
 *     false FAIL, never a false PASS).
 *   · Windows' select arm is NOT exercised here (no Windows machine); its
 *     only claim is that it compiles.
 *   · Every "nothing ready" check uses wait(0) on a state where no byte
 *     is in flight; every "ready" check waits up to 5 s for it (the two
 *     collect-loops over level sockets are bounded by a 5 s deadline).
 *     Expiry is a FAIL, never a pass.
 */

#include "net/nodus_net_poll.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int passed = 0, failed = 0;

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while (0)
#define CHECK(c)   do { if (!(c)) { ok = 0; printf("\n    check failed: %s (line %d)", #c, __LINE__); } } while (0)
#define DONE()     do { if (ok) { printf("PASS\n"); passed++; } \
                        else { printf("\n    FAIL\n"); failed++; } } while (0)

#define READY_MS 5000                /* the bound on every "becomes ready" */

/* ── loopback helpers ──────────────────────────────────────────────── */

/* A listening socket on 127.0.0.1:<kernel port>; *port gets the port. */
static int lo_listener(uint16_t *port)
{
    struct sockaddr_in a;
    socklen_t al = (socklen_t)sizeof(a);
    int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

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

/* A connected loopback TCP pair, both ends non-blocking. 0 or -1. */
static int lo_pair(int *x, int *y)
{
    struct sockaddr_in a;
    uint16_t port = 0;
    int l = lo_listener(&port), c, s;

    if (l < 0) {
        return -1;
    }
    c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    lo_addr(&a, port);
    if (c < 0 || connect(c, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (c >= 0) {
            close(c);
        }
        close(l);
        return -1;
    }
    s = accept(l, NULL, NULL);
    close(l);
    if (s < 0) {
        close(c);
        return -1;
    }
    if (nodus_net_set_nonblocking(c) != 0 || nodus_net_set_nonblocking(s) != 0) {
        close(c);
        close(s);
        return -1;
    }
    *x = s;
    *y = c;
    return 0;
}

static int64_t mono_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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
    int a = -1, b = -1, c = -1, d = -1, ok = 1, n, i, saw_lvl, saw_edge;
    int64_t t0;

    TEST("level reports unread bytes every wait, EDGE once per arrival");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    CHECK(lo_pair(&a, &b) == 0);
    CHECK(lo_pair(&c, &d) == 0);
    CHECK(nodus_net_poll_add(&p, a, 1, NODUS_NET_IN) == 0);
    CHECK(nodus_net_poll_add(&p, c, 2, NODUS_NET_IN | NODUS_NET_EDGE) == 0);
    CHECK(send(b, "x", 1, MSG_NOSIGNAL) == 1);
    CHECK(send(d, "y", 1, MSG_NOSIGNAL) == 1);
    /* Both arrivals, within the bound (a level socket returns at once, so
     * the loop is bounded by the deadline, not by the wait). */
    saw_lvl = saw_edge = 0;
    t0 = mono_ms();
    while ((saw_lvl == 0 || saw_edge == 0) && mono_ms() - t0 < READY_MS) {
        n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
        if (n <= 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            saw_lvl |= ev[i].tag == 1;
            saw_edge |= ev[i].tag == 2;
        }
    }
    CHECK(saw_lvl && saw_edge);
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
    /* The accepted end: the shims set its flags. */
    acc = nodus_net_accept(l, NULL, NULL);
    CHECK(acc != NODUS_SOCK_INVALID);
    if (acc != NODUS_SOCK_INVALID) {
        CHECK((fcntl(acc, F_GETFL, 0) & O_NONBLOCK) == 0);
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
    close(l);
    DONE();
}

static void *waker(void *arg)
{
    nodus_net_poll_wake((nodus_net_poll_t *)arg);
    return NULL;
}

static void test_wake(void)
{
    nodus_net_poll_t p, q;
    nodus_net_event_t ev[8];
    pthread_t th;
    uint64_t v;
    int64_t t0, dt;
    int ok = 1, n;

    TEST("wake from another thread ends the wait; drained, not reported");
    CHECK(nodus_net_poll_init(&p, true) == 0);
    CHECK(p.wake_fd >= 0);
    t0 = mono_ms();
    CHECK(pthread_create(&th, NULL, waker, &p) == 0);
    n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
    dt = mono_ms() - t0;
    CHECK(pthread_join(th, NULL) == 0);
    CHECK(n == 0);
    CHECK(dt < READY_MS - 1000);
    /* Drained: the eventfd holds nothing. */
    errno = 0;
    CHECK(read(p.wake_fd, &v, sizeof(v)) == -1 && errno == EAGAIN);
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
}

static void test_wait_cap(void)
{
    nodus_net_poll_t p;
    nodus_net_event_t ev[8];
    int x[3], y[3], ok = 1, i, n, seen = 0;
    int64_t t0;

    TEST("wait cap honoured; cap 0 and cap > MAX_BATCH refused");
    CHECK(nodus_net_poll_init(&p, false) == 0);
    for (i = 0; i < 3; i++) {
        x[i] = y[i] = -1;
        CHECK(lo_pair(&x[i], &y[i]) == 0);
        CHECK(nodus_net_poll_add(&p, x[i], (uint64_t)(10 + i), NODUS_NET_IN) == 0);
        CHECK(send(y[i], "q", 1, MSG_NOSIGNAL) == 1);
    }
    /* All three ready (level: each stays ready until read). Bounded by
     * the deadline: a ready socket makes every wait return at once. */
    t0 = mono_ms();
    while (seen != 7 && mono_ms() - t0 < READY_MS) {
        n = nodus_net_poll_wait(&p, READY_MS, ev, 8);
        if (n <= 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            if (ev[i].tag >= 10 && ev[i].tag < 13) {
                seen |= 1 << (int)(ev[i].tag - 10);
            }
        }
    }
    CHECK(seen == 7);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 8) == 3);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 2) == 2);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 1) == 1);
    CHECK(nodus_net_poll_wait(&p, 0, ev, 0) == -1);
    CHECK(nodus_net_poll_wait(&p, 0, ev, NODUS_NET_POLL_MAX_BATCH + 1) == -1);
    nodus_net_poll_free(&p);
    for (i = 0; i < 3; i++) {
        close(x[i]);
        close(y[i]);
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
    test_wait_cap();
    test_shims();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
