/**
 * @file nodus/tests/test_tcp_sigpipe.c
 * @brief O15B §8 — the TCP transport must never kill its host process, and
 *        must never report a failed write as a success.
 *
 * ── THE DEFECT THIS PINS ──────────────────────────────────────────────
 * `nodus_tcp.c` wrote with raw `write(2)`. Writing to a socket whose peer
 * has closed raises SIGPIPE, whose default disposition is TERMINATE. Two of
 * the three processes linking this transport install
 * `signal(SIGPIPE, SIG_IGN)` in main() (nodus-server.c, nodus-cli.c) — but
 * the transport is a LIBRARY, and every other consumer inherits the default
 * and dies on an ordinary peer disconnect. That is the intermittent
 * `test_cc_client` SIGPIPE recorded in BUGS.md, and it is a whole-process
 * kill, not a test flake.
 *
 * A second, quieter defect sat beside it: `nodus_tcp_send`'s immediate-send
 * loop treated EVERY non-positive result as "would block" and returned 0.
 * A peer that had already gone therefore produced "send succeeded", and the
 * caller waited for a response that could never arrive — on the submit path
 * that is a 60-second timeout reported for a write that demonstrably failed.
 *
 * ── WHY THIS TEST DOES NOT INSTALL A SIGNAL HANDLER ───────────────────
 * Installing `SIG_IGN` here would make the test pass with the fix reverted,
 * which is precisely the wrong test. The process is left at the DEFAULT
 * disposition on purpose: if the transport ever raises SIGPIPE again, this
 * test dies by signal instead of printing a failure — an unmissable result,
 * and the honest one.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include "transport/nodus_tcp.h"

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

/* Count open descriptors, so a leak is measured rather than assumed. */
static int open_fd_count(void) {
    int n = 0;
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return -1;
    long max = (long)rl.rlim_cur;
    if (max > 4096) max = 4096;
    for (long fd = 0; fd < max; fd++)
        if (fcntl((int)fd, F_GETFD) != -1) n++;
    return n;
}

/* A connected socket pair with the transport's own non-blocking setup, so
 * the code under test sees exactly the socket shape production gives it. */
static int mkpair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(sv[i], F_GETFL, 0);
        if (fl < 0 || fcntl(sv[i], F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    }
    return 0;
}

/* ── Driving the REAL transport ───────────────────────────────────────
 *
 * An earlier draft of this test called send(2) directly. That would have
 * proved only that MSG_NOSIGNAL works in this kernel — it would have said
 * NOTHING about whether nodus_tcp.c uses it, and would have passed with the
 * fix fully reverted. A test of a fix must execute the fixed code.
 *
 * `nodus_tcp_t` and `nodus_tcp_conn_t` are fully declared in the public
 * header, so a connection can be built around a socketpair descriptor and
 * handed to the production `nodus_tcp_send()`. No test-only hook is added to
 * the library: the code under test is exactly the shipped code.
 *
 * The transport is multi-MB (a 1024-slot connection pool), so it is
 * heap-allocated — never on the stack.
 */
typedef struct {
    nodus_tcp_t      *tcp;
    nodus_tcp_conn_t *conn;
    int               sv[2];
} rig_t;

static int rig_up(rig_t *r) {
    memset(r, 0, sizeof(*r));
    if (mkpair(r->sv) != 0) return -1;

    r->tcp = calloc(1, sizeof(*r->tcp));
    if (!r->tcp) return -1;
    r->tcp->epoll_fd = -1;          /* no epoll: we call send() directly */
    r->tcp->listen_fd = -1;
    r->tcp->level_triggered = true;

    r->conn = calloc(1, sizeof(*r->conn));
    if (!r->conn) return -1;
    r->conn->fd    = r->sv[0];
    r->conn->slot  = 0;
    r->conn->state = NODUS_CONN_CONNECTED;
    r->conn->tcp_parent = r->tcp;
    r->conn->auth_required = false;      /* skip the auth queue gate */
    r->conn->rcap = 4096;
    r->conn->rbuf = malloc(r->conn->rcap);
    r->conn->wcap = 65536;
    r->conn->wbuf = malloc(r->conn->wcap);
    if (!r->conn->rbuf || !r->conn->wbuf) return -1;
    snprintf(r->conn->ip, sizeof(r->conn->ip), "%s", "127.0.0.1");
    r->conn->port = 1;

    r->tcp->pool[0] = r->conn;
    r->tcp->count = 1;
    return 0;
}

static void rig_down(rig_t *r) {
    if (r->conn) {
        free(r->conn->rbuf);
        free(r->conn->wbuf);
        free(r->conn);
        r->conn = NULL;
    }
    free(r->tcp);
    r->tcp = NULL;
    if (r->sv[0] >= 0) { close(r->sv[0]); r->sv[0] = -1; }
    if (r->sv[1] >= 0) { close(r->sv[1]); r->sv[1] = -1; }
}

int main(void) {
    printf("=== O15B §8 — transport SIGPIPE / partial write / EINTR ===\n");

    /* THE DEFAULT DISPOSITION IS LEFT IN PLACE. See the file comment: a
     * handler here would make this test pass with the fix reverted. */
    CHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR, "SIGPIPE left at default");

    int fd_before = open_fd_count();
    CHECK(fd_before > 0, "descriptor accounting works");

    /* ── 1. WRITE TO A CLOSED PEER MUST NOT KILL THE PROCESS ──────────
     *
     * The whole point. With the old raw write(2) this raised SIGPIPE and
     * the process died right here — the test would not print a failure, it
     * would simply stop existing.
     *
     * Two writes: the first may be absorbed by the socket buffer (the FIN
     * has not been processed yet), the second is the one that reliably
     * meets EPIPE. */
    {
        rig_t r;
        CHECK(rig_up(&r) == 0, "transport rig");
        close(r.sv[1]);
        r.sv[1] = -1;                       /* peer gone */

        uint8_t payload[64];
        memset(payload, 0xA5, sizeof(payload));

        /* THE PRODUCTION ENTRY POINT. With the old raw write(2) the first
         * or second of these raised SIGPIPE and the process died here — the
         * test would not print a failure, it would stop existing. */
        int rc1 = nodus_tcp_send(r.conn, payload, sizeof(payload));
        int rc2 = nodus_tcp_send(r.conn, payload, sizeof(payload));

        CHECK(1, "SURVIVED nodus_tcp_send to a closed peer (no SIGPIPE)");

        /* And the failure is REPORTED. Before this season the immediate-send
         * loop broke on every non-positive result and returned 0, so a dead
         * peer produced "send succeeded" and the caller waited for a reply
         * that could never come — the 60 s submit-path timeout. */
        CHECK(rc1 == -1 || rc2 == -1,
              "nodus_tcp_send REPORTS the failed write instead of returning "
              "success for a peer that is gone");
        CHECK(r.conn->send_error_count >= 1,
              "the failure is counted as a write error, not as a buffer-full "
              "refusal (send_full_count)");
        CHECK(r.conn->send_full_count == 0,
              "and send_full_count — which means something else entirely — "
              "was not incremented");
        rig_down(&r);
    }

    /* ── 2. REPEATED BROKEN PIPES DO NOT ACCUMULATE OR TERMINATE ──────
     *
     * One survived write could be luck. `test_cc_client`'s failure was
     * LOAD-dependent (10/10 standalone, 1-2/12 under `ctest -j`), so the
     * interesting property is that the hundredth is as safe as the first,
     * and that nothing leaks along the way. */
    {
        uint8_t payload[128];
        memset(payload, 0x5A, sizeof(payload));
        int survived = 0, reported = 0;
        for (int i = 0; i < 200; i++) {
            rig_t r;
            if (rig_up(&r) != 0) { rig_down(&r); break; }
            close(r.sv[1]);
            r.sv[1] = -1;
            int a = nodus_tcp_send(r.conn, payload, sizeof(payload));
            int b = nodus_tcp_send(r.conn, payload, sizeof(payload));
            if (a == -1 || b == -1) reported++;
            rig_down(&r);
            survived++;
        }
        CHECK(survived == 200,
              "200 broken pipes through the PRODUCTION send path, all survived");
        CHECK(reported == 200, "and every one of them reported the failure");
    }

    /* ── 3. PARTIAL WRITES ARE ACCOUNTED BY BYTES ACCEPTED ────────────
     *
     * A non-blocking socket accepts what fits and reports it. Treating the
     * OFFERED length as written is mutant #17 of the season campaign: it
     * silently truncates a frame, and the receiver then reads a valid
     * length prefix followed by the next frame's bytes.
     *
     * Filling the buffer without draining forces the partial. */
    {
        rig_t r;
        CHECK(rig_up(&r) == 0, "transport rig");

        /* Force the partial-write regime DETERMINISTICALLY by shrinking the
         * kernel's send buffer, rather than by sending enough to hope the
         * socket fills. A load-dependent trigger would make this test flaky,
         * which is the class of test this project forbids outright. */
        int small = 4096;
        int snd_rc = setsockopt(r.sv[0], SOL_SOCKET, SO_SNDBUF,
                                &small, sizeof(small));
        int rcv_rc = setsockopt(r.sv[1], SOL_SOCKET, SO_RCVBUF,
                                &small, sizeof(small));
        CHECK(snd_rc == 0 && rcv_rc == 0,
              "the socket buffers were actually shrunk — without this the "
              "partial-write regime is never entered and the section below "
              "passes vacuously");

        static uint8_t chunk[8 * 1024];
        memset(chunk, 0x33, sizeof(chunk));

        size_t offered_framed = 0;
        int sends_ok = 0;
        for (int i = 0; i < 4; i++) {
            if (nodus_tcp_send(r.conn, chunk, sizeof(chunk)) == 0) {
                sends_ok++;
                offered_framed += NODUS_FRAME_HEADER_SIZE + sizeof(chunk);
            }
        }
        CHECK(sends_ok == 4, "four frames accepted by the transport");

        /* EAGAIN must be reported as SUCCESS-so-far, never as an error: the
         * bytes are buffered and the poll loop will flush them. That
         * distinction is exactly why a dead peer and a full buffer must not
         * share a code path — before this season they did. */
        CHECK(r.conn->send_error_count == 0,
              "a full socket buffer is NOT a write error");
        CHECK(r.conn->wpos <= r.conn->wlen, "wpos never passes wlen");

        /* THE INVARIANT.
         *
         * `residue` is what the transport says is still unsent. Note wpos
         * and wlen are BOTH reset to 0 once the buffer fully drains, so
         * `wpos` alone is not a running total — the invariant must be
         * expressed over the residue, which is valid in both cases:
         *
         *     bytes the peer receives + bytes still queued == bytes offered
         *
         * If a partial write were counted as complete, wpos would advance
         * past what the kernel took, residue would shrink accordingly, and
         * this sum would come out SHORT — the missing bytes being precisely
         * the ones silently dropped from the middle of a frame. */
        size_t residue = r.conn->wlen - r.conn->wpos;

        /* THE SECTION IS ONLY MEANINGFUL IF A PARTIAL WRITE ACTUALLY
         * HAPPENED. With `residue == 0` everything drained, the invariant
         * below holds trivially, and a transport that counted OFFERED bytes
         * as written would pass unnoticed. Review R3 caught this: the
         * shrink's return was discarded and nothing asserted the regime was
         * reached. */
        CHECK(residue > 0,
              "the partial-write regime was actually reached (bytes remain "
              "queued) — otherwise this section proves nothing");

        size_t drained = 0;
        for (int spin = 0; spin < 1000; spin++) {
            uint8_t rb[65536];
            ssize_t n = recv(r.sv[1], rb, sizeof(rb), 0);
            if (n > 0) { drained += (size_t)n; continue; }
            break;
        }

        CHECK(drained + residue == offered_framed,
              "RECEIVED + STILL-QUEUED == OFFERED — a partial write is "
              "never counted as complete, and no byte is silently dropped");
        printf("  partial-write: offered=%zu drained=%zu residue=%zu\n",
               offered_framed, drained, residue);
        checks++;
        rig_down(&r);
    }

    /* ── 4. EAGAIN IS NOT AN ERROR, AND EPIPE IS NOT EAGAIN ───────────
     *
     * The two must stay distinguishable: conflating them is what let the
     * old immediate-send loop return success for a dead peer. */
    {
        /* Two rigs, ONE difference: one peer is alive, one is gone. If
         * EAGAIN and EPIPE shared a code path — as they did before this
         * season — these two would be indistinguishable at the API. */
        static uint8_t chunk[16 * 1024];
        memset(chunk, 0x77, sizeof(chunk));

        rig_t alive;
        CHECK(rig_up(&alive) == 0, "rig (peer alive)");
        int rc_alive = nodus_tcp_send(alive.conn, chunk, sizeof(chunk));
        CHECK(rc_alive == 0, "a live peer: send reports success");
        CHECK(alive.conn->send_error_count == 0, "and no write error");
        rig_down(&alive);

        rig_t dead;
        CHECK(rig_up(&dead) == 0, "rig (peer gone)");
        close(dead.sv[1]);
        dead.sv[1] = -1;
        int a = nodus_tcp_send(dead.conn, chunk, sizeof(chunk));
        int b = nodus_tcp_send(dead.conn, chunk, sizeof(chunk));
        CHECK(a == -1 || b == -1, "a dead peer: send reports failure");
        CHECK(dead.conn->send_error_count >= 1, "and counts a write error");
        rig_down(&dead);
    }

    /* ── 5. MSG_NOSIGNAL IS SCOPED TO THE CALL ────────────────────────
     *
     * The narrowness of the fix is itself the property: the transport must
     * not have changed SIGPIPE's disposition for the whole host program.
     * A library that installs a process-wide handler silently changes
     * behaviour for file and pipe descriptors it never touches. */
    {
        void (*disp)(int) = signal(SIGPIPE, SIG_DFL);
        CHECK(disp == SIG_DFL,
              "the transport did NOT install a process-wide SIGPIPE handler");
    }

    /* ── 6. NO DESCRIPTOR LEAK ────────────────────────────────────────── */
    {
        int fd_after = open_fd_count();
        CHECK(fd_after >= 0, "descriptor accounting works");
        CHECK(fd_after <= fd_before,
              "no descriptors leaked across 200+ connect/close cycles");
    }

    printf("test_tcp_sigpipe: ALL %d checks passed\n", checks);
    return 0;
}
