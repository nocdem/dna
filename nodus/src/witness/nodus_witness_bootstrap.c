/**
 * Nodus — Witness Auto-Bootstrap (PR 3 Yol B)
 *
 * State machine implementation. Phases:
 *
 *   - C1  Skeleton (this file's prior shape)
 *   - C2  HAVE_CHAIN branch (chain DB present → refresh bft_config)
 *   - C3  DISCOVER branch (peer mesh query, C-1 / C-2 / C-4 mitigations)
 *   - C4  --cold-bootstrap operator override (C-2 cold-DR escape)
 *   - C5  FETCH_GENESIS branch (atomic chain_def + genesis write, H-7)
 *   - C6  Wire bootstrap_start into nodus_witness_init
 *
 * @file nodus_witness_bootstrap.c
 */

#include "witness/nodus_witness_bootstrap.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sqlite3.h>

/* Settle-window default if w->round_timeout_ms is unset (zero).
 *
 * H-4 mitigation: a freshly-bootstrapped witness MUST stay
 * leader-ineligible for a window after DONE so a peer who is mid-round
 * does not see this node sign a competing PROPOSE. Two round timeouts
 * is the design-spec margin.
 *
 * 5000 ms is the production round_timeout_ms baseline; the fallback
 * here ensures the H-4 invariant holds even if a test or fresh init
 * has not yet populated round_timeout_ms. */
#define NODUS_W_BOOTSTRAP_DEFAULT_ROUND_TIMEOUT_MS  5000U

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Returns the highest block_height in the witness DB, or 0 if no
 * blocks are present. Used to decide HAVE_CHAIN vs DISCOVER on
 * startup. -1 propagates a SQLite error. */
static int64_t chain_tip_height(sqlite3 *db) {
    if (!db) return -1;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(height), 0) FROM blocks",
            -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    int64_t out = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return out;
}

int nodus_witness_bootstrap_start(nodus_witness_t *w) {
    if (!w) return -1;

    /* INIT entry — every call starts here. */
    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_INIT;

    int64_t tip = chain_tip_height(w->db);
    if (tip < 0) {
        /* DB error — refuse to advance. Caller treats this as a hard
         * init failure; nodus_witness_init aborts. */
        return -1;
    }

    if (tip >= 1) {
        /* HAVE_CHAIN branch (C2): genesis block exists locally, so we
         * can refresh bft_config from the on-chain committee and let
         * the existing sync_check + replay path catch up to the tip. */
        w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_HAVE_CHAIN;

        /* Best-effort committee refresh. PR 1 made
         * refresh_bft_config_from_committee public for exactly this
         * call. We pass the local tip so the refresh consults the
         * committee row that was active for the block we last
         * committed; the very next sync round will refresh again
         * against the actual chain head. A non-zero return means the
         * row could not be loaded (e.g., empty committee table) but
         * does NOT block bootstrap — sync_check + replay still run
         * and the steady-state code paths repopulate bft_config. */
        (void)refresh_bft_config_from_committee(w, (uint64_t)tip);

        /* H-4: settle window before this witness becomes
         * leader-eligible. Skipping leader rotation until peers have
         * had two round timeouts to notice us prevents a mid-round
         * disrupt where two leaders sign competing PROPOSEs. */
        uint32_t rto = w->bft_config.round_timeout_ms;
        if (rto == 0) rto = NODUS_W_BOOTSTRAP_DEFAULT_ROUND_TIMEOUT_MS;
        w->bootstrap_settle_until_ms = monotonic_ms() + (uint64_t)(2U * rto);

        w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_BOOTSTRAP_CONFIG;
        w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DONE;

        fprintf(stderr,
                "WITNESS-BOOTSTRAP: state=DONE branch=HAVE_CHAIN tip=%lld "
                "settle_until_ms=%llu\n",
                (long long)tip,
                (unsigned long long)w->bootstrap_settle_until_ms);
        return 0;
    }

    /* DISCOVER branch lands in C3 — for now leave state at INIT and
     * return 0 so the witness can still start (sync via legacy path).
     * Once C3 ships, this path will instead transition to DISCOVER
     * and start the peer-mesh query loop. */
    fprintf(stderr,
            "WITNESS-BOOTSTRAP: state=INIT branch=DISCOVER (deferred to C3)\n");
    return 0;
}
