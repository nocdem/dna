/**
 * Nodus — O15J Faz 3 — the `syncing` latch must not be one-way
 *
 * WHAT THIS PROVES
 *
 * `sync_state.syncing` is set when a block request goes out, and every
 * clear of it lives on a RESPONSE path. So before this season a response
 * that never arrived — peer died mid-sync, frame dropped, peer serving
 * nothing — latched the flag forever. `nodus_witness_sync_check` returned
 * at its "already syncing" guard on every later tick, and the node was
 * permanently, SILENTLY out of sync: no error, no retry, no recovery
 * short of an operator restart.
 *
 * HOW IT WAS FOUND (a real wedge, not a hypothetical)
 *
 * A brand-new node joining a chain already past genesis ran sync_check
 * while still in bootstrap DISCOVER, before a chain DB existed. It
 * latched `syncing` and requested block 1 into nothing. Bootstrap then
 * created the DB and reset `last_sync_attempt` to defeat the rate limit
 * — but the `syncing` guard sits ABOVE the rate limit and stayed set.
 * The node finished bootstrap, joined the peer mesh, and never fetched a
 * single block: `blocks` and `validators` both empty forever, every
 * round logging `C5 prepared cert REJECTED ... committee=-1`.
 * Reproduced by the Stage F scenario `test_vset_grow_shrink.sh`; see
 * nodus/BUGS.md.
 *
 * THE THREE INVARIANTS LOCKED HERE
 *
 *   1. NO DATABASE, NO LATCH — sync_check on a witness with no chain DB
 *      must return WITHOUT setting `syncing`. This is the upstream fix:
 *      the impossible sync is never begun, so there is nothing to
 *      recover from. (Genesis does not come through sync; bootstrap
 *      fetches it with w_genesis_req/rsp.)
 *
 *   2. A STALLED SYNC IS RELEASED — `syncing` true with no progress for
 *      >= SYNC_STALL_TIMEOUT_SEC must be cleared, so the node can start
 *      over instead of wedging.
 *
 *   3. A HEALTHY SYNC IS NOT DISTURBED — `syncing` true with recent
 *      progress must be left alone. A watchdog that fires during a
 *      normal multi-block catch-up would be worse than the bug: it would
 *      abandon and restart real progress.
 *
 * Invariant 3 is what makes this test able to fail in both directions.
 * A watchdog with too short a timeout, or one keyed on a field the
 * response path never refreshes (`last_sync_attempt` — stamped by
 * sync_check's guard pass, NOT by block arrival), passes 2 and fails 3.
 *
 * HOW THIS TEST COULD LIE: it drives sync_check directly with a
 * hand-built witness rather than a live peer, so it proves the LATCH
 * discipline, not that a real stalled peer is detected end to end. That
 * half is the Stage F scenario's job.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_sync.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Must match nodus_witness_sync.c. Kept as a local literal on purpose:
 * if someone retunes the constant there, this test's expectations should
 * be re-read by a human rather than silently following along. */
#define EXPECTED_STALL_TIMEOUT_SEC 60

static int failures = 0;

#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "  [FAIL] %s (%s:%d)\n", (msg),               \
                    __FILE__, __LINE__);                                  \
            failures++;                                                   \
        } else {                                                          \
            printf("  [ok] %s\n", (msg));                                 \
        }                                                                 \
    } while (0)

/* A witness shaped so that sync_check reaches the guards under test:
 * running, legacy role, IDLE phase, rate limit already expired. */
static void fixture_init(nodus_witness_t *w)
{
    memset(w, 0, sizeof(*w));
    w->running           = true;
    w->v2_successor      = false;
    w->round_state.phase = NODUS_W_PHASE_IDLE;
    w->peer_count        = 0;      /* no peer ahead -> no NEW sync starts */
    w->db                = NULL;

    uint64_t now = (uint64_t)time(NULL);
    /* Well past SYNC_MIN_INTERVAL_SEC so the rate limit is never what
     * this test is measuring. */
    w->sync_state.last_sync_attempt = now - 3600;
}

/* ── 1. No chain database → no latch ─────────────────────────────── */
static void test_no_db_never_latches(void)
{
    printf("\n1. a witness with NO chain DB must not start a sync\n");

    static nodus_witness_t w;      /* multi-MB — static, never on stack */
    fixture_init(&w);
    w.db = NULL;

    CHECK(w.sync_state.syncing == false, "starts unlatched");

    nodus_witness_sync_check(&w);

    CHECK(w.sync_state.syncing == false,
          "sync_check with db == NULL leaves `syncing` CLEAR "
          "(the pre-chain-DB wedge cannot arise)");
}

/* ── 2. A stalled sync is released ───────────────────────────────── */
static void test_stalled_latch_is_released(void)
{
    printf("\n2. a sync with no progress past the timeout is RELEASED\n");

    static nodus_witness_t w;
    fixture_init(&w);
    w.db = NULL;   /* the no-db guard must not mask the watchdog */

    uint64_t now = (uint64_t)time(NULL);
    w.sync_state.syncing            = true;
    w.sync_state.sync_peer_idx      = 0;
    w.sync_state.sync_current_height = 1;
    /* Comfortably past the timeout, so this is not a boundary test. */
    w.sync_state.sync_last_progress = now - (EXPECTED_STALL_TIMEOUT_SEC + 30);

    nodus_witness_sync_check(&w);

    CHECK(w.sync_state.syncing == false,
          "a latch with no progress for > SYNC_STALL_TIMEOUT_SEC is "
          "CLEARED, so the node can sync again");
}

/* A zero progress stamp means "latched, never recorded progress" — the
 * exact shape the bootstrap wedge left behind. It must not be read as
 * "progress at epoch 0 is recent". */
static void test_zero_progress_stamp_is_released(void)
{
    printf("\n2b. a latch with a ZERO progress stamp is RELEASED\n");

    static nodus_witness_t w;
    fixture_init(&w);
    w.db = NULL;

    w.sync_state.syncing            = true;
    w.sync_state.sync_last_progress = 0;

    nodus_witness_sync_check(&w);

    CHECK(w.sync_state.syncing == false,
          "syncing=true with sync_last_progress==0 is treated as STALE, "
          "not as fresh progress");
}

/* ── 3. A healthy sync is left alone ─────────────────────────────── */
static void test_healthy_sync_is_not_disturbed(void)
{
    printf("\n3. a sync that IS progressing must NOT be interrupted\n");

    static nodus_witness_t w;
    fixture_init(&w);
    w.db = NULL;

    uint64_t now = (uint64_t)time(NULL);
    w.sync_state.syncing            = true;
    w.sync_state.sync_peer_idx      = 0;
    w.sync_state.sync_current_height = 42;
    w.sync_state.sync_last_progress = now;   /* a block just arrived */

    nodus_witness_sync_check(&w);

    CHECK(w.sync_state.syncing == true,
          "a freshly-progressing sync KEEPS its latch (the watchdog must "
          "not abandon a real multi-block catch-up)");
    CHECK(w.sync_state.sync_current_height == 42,
          "and its position is untouched");
}

/* The field the watchdog keys on must be independent of the rate-limit
 * timestamp. If a future edit collapses the two, a healthy catch-up —
 * which never refreshes last_sync_attempt — starts looking stalled. */
static void test_progress_field_is_independent(void)
{
    printf("\n4. progress is tracked separately from the rate limit\n");

    static nodus_witness_t w;
    fixture_init(&w);
    w.db = NULL;

    uint64_t now = (uint64_t)time(NULL);
    w.sync_state.syncing            = true;
    w.sync_state.sync_current_height = 7;
    /* Rate-limit stamp ANCIENT (as it is during a long catch-up, since
     * sync_check returns at the syncing guard before refreshing it), but
     * progress RECENT. The watchdog must read progress, not this. */
    w.sync_state.last_sync_attempt  = now - 3600;
    w.sync_state.sync_last_progress = now;

    nodus_witness_sync_check(&w);

    CHECK(w.sync_state.syncing == true,
          "an ancient last_sync_attempt does NOT trip the watchdog while "
          "sync_last_progress is fresh");
}

int main(void)
{
    printf("\n=== O15J Faz 3 — sync stall watchdog / latch discipline "
           "===\n");

    test_no_db_never_latches();
    test_stalled_latch_is_released();
    test_zero_progress_stamp_is_released();
    test_healthy_sync_is_not_disturbed();
    test_progress_field_is_independent();

    if (failures) {
        fprintf(stderr,
                "\n%d CHECK(s) FAILED — the `syncing` latch can wedge a "
                "node out of sync permanently.\n", failures);
        return 1;
    }
    printf("\ntest_sync_stall_watchdog: ALL checks passed\n");
    return 0;
}
