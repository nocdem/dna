/**
 * @file tests/test_chain_config_rate_limit.c
 * @brief Hard-Fork v1 Stage C.3 — per-proposer rate-limit unit tests.
 *
 * Covers the pure-function API (check + record) without spinning up a
 * witness. The handler-integration path is exercised by the Stage F
 * integration harness (separate commit, 3-node loopback).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus_chain_config.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                                \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
    }                                                                    \
} while (0)

static void fill_wid(uint8_t wid[NODUS_CC_WITNESS_ID_SIZE], uint8_t seed) {
    for (int i = 0; i < NODUS_CC_WITNESS_ID_SIZE; i++)
        wid[i] = (uint8_t)(seed + i);
}

static void test_first_request_allowed(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
    fill_wid(wid, 0x10);

    uint64_t elapsed = 999;  /* poisoned — must not be touched on accept */
    CHECK(nodus_cc_rate_limit_check(&t, wid, 1000, &elapsed) == 0);
    CHECK(elapsed == 999);  /* untouched */
    CHECK(t.rate_limited_count == 0);
}

static void test_cooldown_within_window(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
    fill_wid(wid, 0x20);

    /* First accept. */
    CHECK(nodus_cc_rate_limit_check(&t, wid, 1000, NULL) == 0);
    nodus_cc_rate_limit_record(&t, wid, 1000);

    /* 1ms later → rate-limited. */
    uint64_t elapsed = 0;
    CHECK(nodus_cc_rate_limit_check(&t, wid, 1001, &elapsed) == -1);
    CHECK(elapsed == 1);

    /* Just before window expires (4999ms). */
    elapsed = 0;
    CHECK(nodus_cc_rate_limit_check(&t, wid, 1000 + 4999, &elapsed) == -1);
    CHECK(elapsed == 4999);
}

static void test_allowed_after_window(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
    fill_wid(wid, 0x30);

    nodus_cc_rate_limit_record(&t, wid, 1000);

    /* Exactly at window boundary — allow. */
    CHECK(nodus_cc_rate_limit_check(&t, wid,
            1000 + NODUS_CC_RATE_LIMIT_WINDOW_MS, NULL) == 0);

    /* Well after — allow. */
    CHECK(nodus_cc_rate_limit_check(&t, wid, 1000 + 60000, NULL) == 0);
}

static void test_distinct_senders_independent(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t a[NODUS_CC_WITNESS_ID_SIZE];
    uint8_t b[NODUS_CC_WITNESS_ID_SIZE];
    fill_wid(a, 0x40);
    fill_wid(b, 0x50);

    /* A records, B's fresh request is unaffected. */
    nodus_cc_rate_limit_record(&t, a, 1000);
    CHECK(nodus_cc_rate_limit_check(&t, b, 1001, NULL) == 0);
    nodus_cc_rate_limit_record(&t, b, 1001);

    /* Both are in cooldown in their own slots. */
    uint64_t e = 0;
    CHECK(nodus_cc_rate_limit_check(&t, a, 1500, &e) == -1);
    CHECK(e == 500);
    e = 0;
    CHECK(nodus_cc_rate_limit_check(&t, b, 1500, &e) == -1);
    CHECK(e == 499);
}

static void test_record_upsert_same_sender(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
    fill_wid(wid, 0x60);

    /* Two records for same sender must share a single slot. */
    nodus_cc_rate_limit_record(&t, wid, 1000);
    nodus_cc_rate_limit_record(&t, wid, 2000);

    int used = 0;
    for (uint32_t i = 0; i < NODUS_CC_RATE_LIMIT_MAX_PROPOSERS; i++)
        if (t.slots[i].in_use) used++;
    CHECK(used == 1);

    /* Latest timestamp wins. */
    uint64_t e = 0;
    CHECK(nodus_cc_rate_limit_check(&t, wid, 2500, &e) == -1);
    CHECK(e == 500);
}

static void test_lru_eviction_when_table_full(void) {
    /* Sized to committee max (7). Filling all slots and adding an 8th
     * sender should evict the oldest slot, not refuse the new sender.
     * In practice the dispatch guard prevents non-committee senders from
     * reaching here, so this path tolerates a hypothetical roster drift
     * without a panic. */
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t wid[NODUS_CC_RATE_LIMIT_MAX_PROPOSERS + 1]
              [NODUS_CC_WITNESS_ID_SIZE];

    for (uint32_t i = 0; i < NODUS_CC_RATE_LIMIT_MAX_PROPOSERS; i++) {
        fill_wid(wid[i], (uint8_t)(0x70 + i));
        /* Strictly monotonic ts so LRU has a deterministic oldest. */
        nodus_cc_rate_limit_record(&t, wid[i], 1000 + 10 * i);
    }

    /* 8th sender forces eviction of wid[0] (ts=1000 = oldest). */
    fill_wid(wid[NODUS_CC_RATE_LIMIT_MAX_PROPOSERS],
              (uint8_t)(0x70 + NODUS_CC_RATE_LIMIT_MAX_PROPOSERS));
    nodus_cc_rate_limit_record(&t, wid[NODUS_CC_RATE_LIMIT_MAX_PROPOSERS],
                                 2000);

    /* wid[0] should no longer be tracked — its fresh request is allowed. */
    CHECK(nodus_cc_rate_limit_check(&t, wid[0], 2001, NULL) == 0);

    /* 8th sender is now in cooldown. */
    uint64_t e = 0;
    CHECK(nodus_cc_rate_limit_check(&t, wid[NODUS_CC_RATE_LIMIT_MAX_PROPOSERS],
                                      2100, &e) == -1);
    CHECK(e == 100);
}

static void test_clock_skew_does_not_permit_bypass(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));

    uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
    fill_wid(wid, 0x80);

    nodus_cc_rate_limit_record(&t, wid, 10000);

    /* Negative elapsed (now_ms < last_accepted_ms): treat as 0, still in
     * cooldown. Prevents a crafted-time bypass if the monotonic clock
     * ever regresses. */
    uint64_t e = 999;
    CHECK(nodus_cc_rate_limit_check(&t, wid, 5000, &e) == -1);
    CHECK(e == 0);
}

static void test_null_args(void) {
    nodus_cc_rate_limit_table_t t;
    memset(&t, 0, sizeof(t));
    uint8_t wid[NODUS_CC_WITNESS_ID_SIZE] = {0};

    CHECK(nodus_cc_rate_limit_check(NULL, wid, 0, NULL) == -1);
    CHECK(nodus_cc_rate_limit_check(&t, NULL, 0, NULL) == -1);

    /* record with NULL is a no-op (must not crash). */
    nodus_cc_rate_limit_record(NULL, wid, 0);
    nodus_cc_rate_limit_record(&t, NULL, 0);

    /* Table should be empty — no slot claimed. */
    for (uint32_t i = 0; i < NODUS_CC_RATE_LIMIT_MAX_PROPOSERS; i++)
        CHECK(t.slots[i].in_use == false);
}

int main(void) {
    test_first_request_allowed();
    test_cooldown_within_window();
    test_allowed_after_window();
    test_distinct_senders_independent();
    test_record_upsert_same_sender();
    test_lru_eviction_when_table_full();
    test_clock_skew_does_not_permit_bypass();
    test_null_args();

    if (failures) {
        fprintf(stderr, "test_chain_config_rate_limit: %d check(s) failed\n",
                failures);
        return 1;
    }
    printf("test_chain_config_rate_limit: all checks passed\n");
    return 0;
}
