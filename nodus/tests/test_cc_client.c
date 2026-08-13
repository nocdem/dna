/**
 * @file tests/test_cc_client.c
 * @brief Stage E.2 — unit tests for nodus_client_cc_vote_send guard paths.
 *
 * Scope: argument validation + timeout behavior against a dead peer. The
 * full connect → send → recv → verify round trip is covered by the Stage F
 * integration harness (3 loopback nodus-server processes, separate commit);
 * duplicating that here would require reimplementing the witness-side
 * w_cc_vote_req handler in-test, which is already tested via
 * test_chain_config_votes.c and the witness cascade.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_wire.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond) do {                                                \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
    }                                                                    \
} while (0)

static void test_null_args_rejected(void) {
    nodus_seckey_t sk;
    nodus_pubkey_t pk;
    uint8_t wid[32] = {0};
    uint8_t cid[32] = {0};
    nodus_t3_cc_vote_req_t req;
    nodus_t3_cc_vote_rsp_t rsp;

    memset(&sk, 0, sizeof(sk));
    memset(&pk, 0, sizeof(pk));
    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    CHECK(nodus_client_cc_vote_send(NULL, &pk, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", NULL, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", &pk, NULL, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", &pk, &sk, NULL, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", &pk, &sk, wid, NULL, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", &pk, &sk, wid, &pk, NULL,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", &pk, &sk, wid, &pk, cid,
                                     NULL, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:4004", &pk, &sk, wid, &pk, cid,
                                     &req, 100, NULL) == -1);
}

static void test_malformed_address_rejected(void) {
    nodus_seckey_t sk;
    nodus_pubkey_t pk;
    uint8_t wid[32] = {0};
    uint8_t cid[32] = {0};
    nodus_t3_cc_vote_req_t req;
    nodus_t3_cc_vote_rsp_t rsp;

    memset(&sk, 0, sizeof(sk));
    memset(&pk, 0, sizeof(pk));
    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    /* Empty string, no port number, port out of range. */
    CHECK(nodus_client_cc_vote_send("", &pk, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:99999", &pk, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:0", &pk, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send("127.0.0.1:-5", &pk, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
    CHECK(nodus_client_cc_vote_send(":4004", &pk, &sk, wid, &pk, cid,
                                     &req, 100, &rsp) == -1);
}

/* ── Conn-lifetime regression suite ─────────────────────────────────
 *
 * nodus_client_cc_vote_send BORROWS its nodus_tcp_conn_t from the
 * transport, and any nodus_tcp_poll may free it (connect refusal, peer
 * close, read/write error, bad frame). Pre-fix, the connect-wait loop
 * read conn->state after handle_connect_complete freed the conn — the
 * O11 ASan finding (heap-use-after-free, nodus_cc_client.c:233). These
 * tests drive every teardown path a unit test can construct without a
 * full witness peer; each must complete without a sanitizer finding and
 * return a failure code with *rsp_out still zeroed. The full success
 * round trip stays Stage F integration scope (see file header).
 */

typedef enum {
    PEER_CLOSE_ON_ACCEPT = 0,   /* FIN right after accept              */
    PEER_CHALLENGE_THEN_CLOSE,  /* drain hello, real t2 challenge, FIN */
    PEER_GARBAGE_FRAME,         /* bytes with a bad frame magic        */
    PEER_TRUNCATED_FRAME,       /* valid header, missing payload, FIN  */
    PEER_RST_ON_ACCEPT,         /* SO_LINGER 0 close → RST read error  */
    PEER_SILENT,                /* stays connected, never answers      */
} peer_mode_t;

typedef struct {
    int         lfd;
    peer_mode_t mode;
} peer_args_t;

static void *fake_peer_main(void *arg) {
    peer_args_t *pa = (peer_args_t *)arg;

    struct pollfd pfd = { .fd = pa->lfd, .events = POLLIN };
    if (poll(&pfd, 1, 5000) <= 0) return NULL;   /* client never came */

    int cfd = accept(pa->lfd, NULL, NULL);
    if (cfd < 0) return NULL;

    switch (pa->mode) {
    case PEER_CLOSE_ON_ACCEPT:
        break;

    case PEER_CHALLENGE_THEN_CLOSE: {
        /* Wait for (some of) the client hello, then answer with a real
         * T2 challenge and close. The client may see challenge+FIN in
         * one poll (conn freed in the same pass that satisfied the
         * predicate — the former send-site UAF) or split across polls
         * (conn dies while awaiting auth_ok); both must be safe. */
        uint8_t drain[8192];
        struct pollfd cp = { .fd = cfd, .events = POLLIN };
        if (poll(&cp, 1, 5000) > 0)
            (void)read(cfd, drain, sizeof(drain));

        uint8_t nonce[NODUS_NONCE_LEN];
        memset(nonce, 0x5A, sizeof(nonce));
        uint8_t payload[512];
        size_t  plen = 0;
        if (nodus_t2_challenge(7, nonce, payload, sizeof(payload), &plen) == 0) {
            uint8_t frame[600];
            size_t flen = nodus_frame_encode(frame, sizeof(frame),
                                             payload, (uint32_t)plen);
            if (flen > 0)
                (void)write(cfd, frame, flen);
        }
        break;
    }

    case PEER_GARBAGE_FRAME: {
        uint8_t junk[16];
        memset(junk, 0xFF, sizeof(junk));   /* wrong magic → bad frame */
        (void)write(cfd, junk, sizeof(junk));
        break;
    }

    case PEER_TRUNCATED_FRAME: {
        /* A valid header promising 64 payload bytes, but only 10 sent,
         * then FIN: the client parses "incomplete", then hits EOF and
         * the transport frees the conn with the partial frame pending. */
        uint8_t payload[64];
        memset(payload, 0x33, sizeof(payload));
        uint8_t frame[128];
        size_t flen = nodus_frame_encode(frame, sizeof(frame),
                                         payload, (uint32_t)sizeof(payload));
        if (flen > 0)
            (void)write(cfd, frame, NODUS_FRAME_HEADER_SIZE + 10);
        break;
    }

    case PEER_RST_ON_ACCEPT: {
        struct linger lg = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        break;
    }

    case PEER_SILENT: {
        /* Hold the conn open, draining whatever arrives, until the
         * client gives up and closes its side (10 s hard cap). Drives
         * the deadline-expiry path where the conn is still ALIVE at
         * cleanup — the one path where nodus_tcp_close is the final
         * release of the borrowed conn. */
        uint8_t drain[8192];
        struct pollfd cp = { .fd = cfd, .events = POLLIN };
        while (poll(&cp, 1, 10000) > 0) {
            ssize_t n = read(cfd, drain, sizeof(drain));
            if (n <= 0) break;
        }
        break;
    }
    }

    close(cfd);
    return NULL;
}

/* Run one cc_vote_send call against a loopback fake peer. Returns the
 * call's rc; *rsp is pre-filled with 0xAA so the caller can assert the
 * zeroed-on-failure output contract. */
static int run_against_fake_peer(peer_mode_t mode, uint32_t timeout_ms,
                                  nodus_t3_cc_vote_rsp_t *rsp) {
    nodus_seckey_t sk;
    nodus_pubkey_t pk;
    uint8_t wid[32] = {0};
    uint8_t cid[32] = {0};
    nodus_t3_cc_vote_req_t req;

    memset(&sk, 0, sizeof(sk));
    memset(&pk, 0, sizeof(pk));
    memset(&req, 0, sizeof(req));
    memset(rsp, 0xAA, sizeof(*rsp));
    req.param_id  = 1;
    req.new_value = 5;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { CHECK(lfd >= 0); return -100; }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;   /* ephemeral */
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(lfd, 1) != 0) {
        CHECK(!"bind/listen failed");
        close(lfd);
        return -100;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);

    char peer_addr[64];
    snprintf(peer_addr, sizeof(peer_addr), "127.0.0.1:%u",
             (unsigned)ntohs(addr.sin_port));

    peer_args_t pa = { .lfd = lfd, .mode = mode };
    pthread_t tid;
    if (pthread_create(&tid, NULL, fake_peer_main, &pa) != 0) {
        CHECK(!"pthread_create failed");
        close(lfd);
        return -100;
    }

    nodus_seckey_t sk2;      /* separate copy: keep call args symmetric */
    memset(&sk2, 0, sizeof(sk2));
    int rc = nodus_client_cc_vote_send(peer_addr, &pk, &sk2, wid, &pk, cid,
                                        &req, timeout_ms, rsp);

    pthread_join(tid, NULL);
    close(lfd);
    return rc;
}

static bool all_zero(const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; i++)
        if (b[i] != 0) return false;
    return true;
}

/* Repeated refused-connect calls: the original O11 UAF path, driven
 * repeatedly so a stale pointer or double free in the teardown path
 * cannot hide from ASan behind a single lucky allocation. */
static void test_dead_peer_repeated(void) {
    nodus_seckey_t sk;
    nodus_pubkey_t pk;
    uint8_t wid[32] = {0};
    uint8_t cid[32] = {0};
    nodus_t3_cc_vote_req_t req;
    nodus_t3_cc_vote_rsp_t rsp;

    memset(&sk, 0, sizeof(sk));
    memset(&pk, 0, sizeof(pk));
    memset(&req, 0, sizeof(req));
    req.param_id  = 1;
    req.new_value = 5;

    for (int i = 0; i < 25; i++) {
        memset(&rsp, 0xAA, sizeof(rsp));
        int rc = nodus_client_cc_vote_send("127.0.0.1:1", &pk, &sk, wid,
                                            &pk, cid, &req, 200, &rsp);
        CHECK(rc == -1 || rc == -2);
        CHECK(all_zero(&rsp, sizeof(rsp)));   /* zeroed-on-failure contract */
    }
}

/* Peer accepts, then tears the conn down mid-session in five different
 * ways. Every path must return a failure code — never 0, never -3 (no
 * verified response exists) — with rsp zeroed, and must be sanitizer-
 * clean: pre-fix, the challenge-then-close shape could reach the
 * phase-2/3 sends with a freed conn. */
static void test_peer_teardown_paths(void) {
    static const peer_mode_t modes[] = {
        PEER_CLOSE_ON_ACCEPT,
        PEER_CHALLENGE_THEN_CLOSE,
        PEER_GARBAGE_FRAME,
        PEER_TRUNCATED_FRAME,
        PEER_RST_ON_ACCEPT,
    };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        nodus_t3_cc_vote_rsp_t rsp;
        int rc = run_against_fake_peer(modes[i], 800, &rsp);
        CHECK(rc == -1 || rc == -2);
        CHECK(all_zero(&rsp, sizeof(rsp)));
    }
}

/* Peer accepts and never answers: the deadline expires with the conn
 * still alive, so cleanup's nodus_tcp_close performs the one legitimate
 * final release. Exact rc pin (-2): this is the documented timeout
 * classification and must not drift. */
static void test_peer_silent_timeout(void) {
    nodus_t3_cc_vote_rsp_t rsp;
    int rc = run_against_fake_peer(PEER_SILENT, 500, &rsp);
    CHECK(rc == -2);
    CHECK(all_zero(&rsp, sizeof(rsp)));
}

/* The challenge-then-close shape repeated: exercises the poll that both
 * satisfies the wait predicate and frees the conn (the send-site half
 * of the lifetime class) across many runs so either interleaving gets
 * coverage under ASan. */
static void test_challenge_close_repeated(void) {
    for (int i = 0; i < 10; i++) {
        nodus_t3_cc_vote_rsp_t rsp;
        int rc = run_against_fake_peer(PEER_CHALLENGE_THEN_CLOSE, 800, &rsp);
        CHECK(rc == -1 || rc == -2);
        CHECK(all_zero(&rsp, sizeof(rsp)));
    }
}

static void test_timeout_on_dead_peer(void) {
    /* Pick a local port nothing's listening on — connection refused. The
     * helper should return promptly with -1 (connect fail) or -2 (timeout);
     * either is an acceptable guard signal. Not -3 (wsig), not 0. */
    nodus_seckey_t sk;
    nodus_pubkey_t pk;
    uint8_t wid[32] = {0};
    uint8_t cid[32] = {0};
    nodus_t3_cc_vote_req_t req;
    nodus_t3_cc_vote_rsp_t rsp;

    memset(&sk, 0, sizeof(sk));
    memset(&pk, 0, sizeof(pk));
    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.param_id      = 1;
    req.new_value     = 5;

    /* Port 1 is reserved and never has a listener on Linux. */
    time_t t0 = time(NULL);
    int rc = nodus_client_cc_vote_send("127.0.0.1:1", &pk, &sk, wid, &pk, cid,
                                        &req, 200, &rsp);
    time_t t1 = time(NULL);
    CHECK(rc == -1 || rc == -2);
    CHECK((t1 - t0) < 2);  /* well under the 200ms deadline in real time */
}

int main(void) {
    test_null_args_rejected();
    test_malformed_address_rejected();
    test_timeout_on_dead_peer();
    test_dead_peer_repeated();
    test_peer_teardown_paths();
    test_challenge_close_repeated();
    /* Deliberately LAST: the silent peer leaves the conn alive into
     * cleanup, so a cleanup-bypass defect surfaces as a clean LSan
     * leak at process exit instead of poisoning later tests. */
    test_peer_silent_timeout();

    if (failures) {
        fprintf(stderr, "test_cc_client: %d check(s) failed\n", failures);
        return 1;
    }
    printf("test_cc_client: all checks passed\n");
    return 0;
}
