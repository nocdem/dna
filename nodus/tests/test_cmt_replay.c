/**
 * Nodus — cometbft @709fd12b C port, wave R2-B: the handshake classifier
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a node starting up chooses the same recovery action cometbft would
 * choose, given the same four heights and the same initial height. If this
 * file failed, one of these would be false:
 *   · every one of the twelve branches of
 *     `ReplayBlocksWithContext` (replay.go:376-459) is reachable and is
 *     chosen for the inputs the reference chooses it for;
 *   · the ORDER of the edge cases is the reference's — a Go
 *     `switch { case ... }` is top-to-bottom and several of these
 *     conditions overlap, so an empty store wins over "the app is ahead"
 *     and "the app is behind a truncated store" wins over "the state is
 *     ahead of the store";
 *   · the three states the reference PANICS in are reported as their own
 *     outcomes and are distinguishable from the two it returns an ERROR
 *     for — collapsing them would turn a node-local defect into something
 *     a caller might retry;
 *   · both app-hash assertions compare LENGTH as well as content, because
 *     the reference's `bytes.Equal` does;
 *   · the ONE bound the port adds on top of the reference holds — a
 *     negative height is refused before any comparison forms a
 *     difference, so the rewritten `storeBlockHeight > stateBlockHeight+1`
 *     can never overflow (undefined in C, merely wrapping in Go).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, no clock, no RNG. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. The state and block fixtures are HEAP-allocated because a
 * `cmt_state_t` carries three validator sets and must never be a stack
 * object (cmt_state.h); both are freed on the success path.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. IT REPLAYS NOTHING. The classifier chooses an action; performing it
 *     — InitChain, loading blocks, running them against the real or a mock
 *     application, saving the state — is the HOST's and is wave R3's. A
 *     green here proves the node knows WHAT to do and nothing about
 *     whether it does it.
 *  2. `readReplayMessage` and `catchupReplay` (replay.go:39-167) are
 *     methods on the consensus state and are NOT in this module at all,
 *     so the WAL-driven half of recovery is untested here by
 *     construction.
 *  3. The reference's own handshake tests (`replay_test.go:563-611` and
 *     the surrounding table) are NOT ported: they need the mock
 *     application and the block store, which arrive with R3. What is
 *     ported is the branch table, derived from the source.
 *  4. A FAULT outcome is returned as a VALUE here, not as a halt. Nothing
 *     in this file proves the caller halts on one.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_replay.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ══ the branch table ═════════════════════════════════════════════════
 * One row per distinct outcome of replay.go:376-459, with the inputs
 * derived from the `case` it must select and the line it comes from.
 * ══════════════════════════════════════════════════════════════════════ */

static int test_classifier(void)
{
    static const struct {
        int64_t             store_h;
        int64_t             store_base;
        int64_t             state_h;
        int64_t             app_h;
        int64_t             initial_h;
        cmt_replay_action_t want;
        const char         *why;
    } rows[] = {
        /* :377-379 — an EMPTY block store wins over everything below it,
         * including inputs that would otherwise be "app ahead of store". */
        { 0, 0, 0, 0, 1, CMT_REPLAY_STORE_EMPTY_RETURN_APP_HASH,
          "store height 0 (:377)" },
        { 0, 0, 0, 5, 1, CMT_REPLAY_STORE_EMPTY_RETURN_APP_HASH,
          "store height 0 wins over an app that is ahead — ORDER (:377"
          " before :389)" },

        /* :381-383 — the app has no state and the store is truncated
         * above the initial height. */
        { 100, 50, 0, 0, 1, CMT_REPLAY_ERR_APP_HEIGHT_TOO_LOW_AT_GENESIS,
          "app at genesis, store base above the initial height (:381)" },
        /* The same shape with initial_height == store_base is NOT this
         * case: the test is `<`, not `<=`. */
        { 100, 50, 100, 100, 50, CMT_REPLAY_IN_SYNC_RETURN_APP_HASH,
          "initial height EQUAL to the store base is not too low (:381"
          " uses `<`)" },

        /* :385-387 — the app is more than one behind a truncated store. */
        { 100, 50, 100, 40, 1, CMT_REPLAY_ERR_APP_HEIGHT_TOO_LOW,
          "app 40 against store base 50 (:385)" },
        /* app == storeBlockBase-1 is ALLOWED: "can be 1 behind since we
         * replay the next" (:386). */
        { 100, 50, 100, 49, 1, CMT_REPLAY_BLOCKS_NO_MUTATE,
          "app exactly one below the store base is allowed (:386)" },

        /* :389-391 — the app is ahead of the store. */
        { 10, 1, 10, 11, 1, CMT_REPLAY_ERR_APP_HEIGHT_TOO_HIGH,
          "app ahead of the store (:389)" },

        /* :393-396 — the state is ahead of the store. PANIC. */
        { 10, 1, 11, 5, 1, CMT_REPLAY_FAULT_STATE_AHEAD_OF_STORE,
          "state ahead of the store (:393) — node-local, FAULT" },

        /* :397-400 — the store is more than one ahead of the state. */
        { 12, 1, 10, 5, 1, CMT_REPLAY_FAULT_STORE_TOO_FAR_AHEAD,
          "store two ahead of the state (:397) — node-local, FAULT" },
        /* Exactly one ahead is the normal case, not this one. */
        { 11, 1, 10, 10, 1, CMT_REPLAY_LAST_BLOCK_REAL_APP,
          "store exactly one ahead is NOT too far (:397 uses `>`)" },

        /* :406-411 — store == state, app behind: replay without the WAL
         * and without mutating the state. */
        { 10, 1, 10, 4, 1, CMT_REPLAY_BLOCKS_NO_MUTATE,
          "store == state, app behind (:409)" },

        /* :413-416 — everything level. */
        { 10, 1, 10, 10, 1, CMT_REPLAY_IN_SYNC_RETURN_APP_HASH,
          "store == state == app (:413)" },

        /* :419-426 — store == state+1, app behind the state. */
        { 11, 1, 10, 4, 1, CMT_REPLAY_BLOCKS_MUTATE,
          "store == state+1, app behind the state (:423)" },

        /* :428-435 — store == state+1, app == state: Commit did not run. */
        { 11, 1, 10, 10, 1, CMT_REPLAY_LAST_BLOCK_REAL_APP,
          "Commit did not run: replay the last block against the real"
          " application (:428)" },

        /* :437-453 — store == state+1, app == store: Commit ran but the
         * state was not saved. */
        { 11, 1, 10, 11, 1, CMT_REPLAY_LAST_BLOCK_MOCK_APP,
          "Commit ran, state not saved: replay against a mock app (:437)" },
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_replay_action_t got = CMT_REPLAY_FAULT_UNCOVERED;

        CHECK(cmt_replay_handshake_classify(rows[i].store_h,
                                            rows[i].store_base,
                                            rows[i].state_h, rows[i].app_h,
                                            rows[i].initial_h, &got)
              == CMT_OK, rows[i].why);
        if (got != rows[i].want) {
            fprintf(stderr, "row %zu (%s): got %d, want %d\n", i,
                    rows[i].why, (int)got, (int)rows[i].want);
            return 1;
        }
        OK();
    }

    CHECK(cmt_replay_handshake_classify(1, 1, 1, 1, 1, NULL) == CMT_FAULT,
          "NULL out");
    OK();
    return 0;
}

/* ══ the uncovered case, and total coverage ═══════════════════════════
 * replay.go:458-459 ends the function with a `panic("uncovered case!")`,
 * which is the reference asserting that the two switches above it leave
 * nothing unhandled. Reading them shows why: once the edge cases have
 * refused `store < app`, `store < state` and `store > state+1`, the only
 * remaining shapes are store == state (with app below or equal) and
 * store == state+1 (with app below the state, at the state, or at the
 * store), and all five have a branch.
 *
 * The sweep below is that argument, executed: over every combination of
 * five small heights the classifier lands on a NAMED branch and never on
 * the uncovered one. It is a coverage assertion, not a reachability one —
 * if a future edit dropped a condition, some row here would fall through
 * and this test would say so.
 * ══════════════════════════════════════════════════════════════════════ */

static int test_uncovered(void)
{
    cmt_replay_action_t got = CMT_REPLAY_IN_SYNC_RETURN_APP_HASH;
    size_t              i;
    int                 seen_uncovered = 0;
    size_t              first_bad = 0;

    /* 4^5 = 1024 distinct combinations of five heights drawn from 0..3.
     * The bound is 1024 and not 4096: with five digits the fifth divisor
     * is 256, so anything at or above 1024 only repeats a combination. */
    for (i = 0; i < 1024u; i++) {
        int64_t store_h = (int64_t)(i % 4u);
        int64_t base    = (int64_t)((i / 4u) % 4u);
        int64_t state_h = (int64_t)((i / 16u) % 4u);
        int64_t app_h   = (int64_t)((i / 64u) % 4u);
        int64_t init_h  = (int64_t)((i / 256u) % 4u);

        if (cmt_replay_handshake_classify(store_h, base, state_h, app_h,
                                          init_h, &got) != CMT_OK) {
            fprintf(stderr, "classify failed at i=%zu\n", i);
            return 1;
        }
        if (got == CMT_REPLAY_FAULT_UNCOVERED && !seen_uncovered) {
            seen_uncovered = 1;
            first_bad = i;
        }
        if ((unsigned)got > (unsigned)CMT_REPLAY_FAULT_UNCOVERED) {
            fprintf(stderr, "classify returned an unnamed action at i=%zu\n",
                    i);
            return 1;
        }
    }
    if (seen_uncovered) {
        fprintf(stderr, "first uncovered combination at i=%zu\n", first_bad);
    }
    CHECK(!seen_uncovered,
          "over a 4x4x4x4x4 grid of small heights the classifier NEVER"
          " falls through to the uncovered case — every combination is"
          " covered by a named branch, which is what the reference's own"
          " panic message asserts");
    OK();

    /* The explicit bound the port adds on top of the reference: no height
     * the reference reads can be negative, and one of the overflow-free
     * rewrites depends on saying so, so a negative one is fail-stop.
     * INT64_MAX paired with -1 is the input that would otherwise overflow
     * at the rewritten :397. */
    CHECK(cmt_replay_handshake_classify(-1, 0, 0, 0, 1, &got) == CMT_FAULT,
          "a negative store height is FAULT");
    CHECK(cmt_replay_handshake_classify(1, -1, 0, 0, 1, &got) == CMT_FAULT,
          "so is a negative store base");
    CHECK(cmt_replay_handshake_classify(INT64_MAX, 0, -1, 0, 1, &got)
          == CMT_FAULT,
          "and the pair that would overflow the rewritten :397 never"
          " reaches it");
    CHECK(cmt_replay_handshake_classify(1, 0, 0, -1, 1, &got) == CMT_FAULT,
          "a negative app height is FAULT");
    CHECK(cmt_replay_handshake_classify(1, 0, 0, 0, -1, &got) == CMT_FAULT,
          "and so is a negative initial height");
    OK();
    return 0;
}

/* ══ the two assertions ═══════════════════════════════════════════════ */

static int test_app_hash_assertions(void)
{
    cmt_state_t *st;
    cmt_block_t *b;
    uint8_t      h1[64];
    uint8_t      h2[64];
    size_t       i;

    for (i = 0; i < 64u; i++) {
        h1[i] = (uint8_t)i;
        h2[i] = (uint8_t)i;
    }
    h2[63] = 0xFF;

    st = (cmt_state_t *)malloc(sizeof(*st));
    b  = (cmt_block_t *)malloc(sizeof(*b));
    CHECK(st != NULL && b != NULL, "allocation");
    memset(st, 0, sizeof(*st));
    memset(b, 0, sizeof(*b));

    memcpy(st->app_hash, h1, 64);
    st->app_hash_len = 64;
    memcpy(b->header.app_hash, h1, 64);
    b->header.app_hash_len = 64;

    /* replay.go:555-565 */
    CHECK(cmt_replay_assert_app_hash_equals_one_from_state(h1, 64, st)
          == CMT_OK, "an equal app hash passes the state assertion");
    CHECK(cmt_replay_assert_app_hash_equals_one_from_state(h2, 64, st)
          == CMT_FAULT,
          "a differing one FAULTS, where the reference panics (:557)");
    CHECK(cmt_replay_assert_app_hash_equals_one_from_state(h1, 63, st)
          == CMT_FAULT,
          "and so does a SHORTER one — bytes.Equal compares lengths");
    OK();

    /* replay.go:545-553 */
    CHECK(cmt_replay_assert_app_hash_equals_one_from_block(h1, 64, b)
          == CMT_OK, "an equal app hash passes the block assertion");
    CHECK(cmt_replay_assert_app_hash_equals_one_from_block(h2, 64, b)
          == CMT_FAULT, "a differing one FAULTS (:547)");
    OK();

    /* Two EMPTY hashes are equal, as bytes.Equal(nil, nil) is true. */
    st->app_hash_len = 0;
    CHECK(cmt_replay_assert_app_hash_equals_one_from_state(NULL, 0, st)
          == CMT_OK, "two empty app hashes are equal");
    CHECK(cmt_replay_assert_app_hash_equals_one_from_state(h1, 64, st)
          == CMT_FAULT, "and an empty one differs from a 64-byte one");
    OK();

    CHECK(cmt_replay_assert_app_hash_equals_one_from_state(h1, 64, NULL)
          == CMT_FAULT, "NULL state");
    CHECK(cmt_replay_assert_app_hash_equals_one_from_block(h1, 64, NULL)
          == CMT_FAULT, "NULL block");
    OK();

    free(st);
    free(b);
    return 0;
}

int main(void)
{
    if (test_classifier() != 0)           { return 1; }
    if (test_uncovered() != 0)            { return 1; }
    if (test_app_hash_assertions() != 0)  { return 1; }

    printf("test_cmt_replay: OK (%d groups)\n", g_checks);
    return 0;
}
