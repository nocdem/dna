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
#include "protocol/nodus_tier3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

    if (failures) {
        fprintf(stderr, "test_cc_client: %d check(s) failed\n", failures);
        return 1;
    }
    printf("test_cc_client: all checks passed\n");
    return 0;
}
