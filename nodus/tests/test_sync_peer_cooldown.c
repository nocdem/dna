/**
 * Nodus — O15G HIGH-1: per-peer invalid-cert cooldown (byzantine sync-wedge).
 *
 * A byzantine peer that inflates its IDENT height is always the highest and is
 * re-selected every sync tick; serving invalid certs it can wedge an honest
 * node whose valid-block peer sits at a lower index (design §8.2). The fix is a
 * per-peer `sync_bad_until` cooldown stamped on CONSENSUS_INVALID and skipped by
 * both peer-selection functions.
 *
 * This suite drives nodus_witness_sync_find_peer / _rotate_peer directly (both
 * un-static'd under NODUS_WITNESS_INTERNAL_API) with hand-built peer records:
 *   · a byzantine height-inflating peer in cooldown is SKIPPED while an honest
 *     lower-index peer is selected;
 *   · cooldown EXPIRY re-admits the (transiently-behind) honest peer;
 *   · rotate_peer (forward-only) also skips cooldown peers;
 *   · the cooldown never blacklists permanently — an expired stamp is inert.
 *
 * Peer scoring is node-local liveness steering; it can never change an
 * accept/reject verdict, so it is NOT a consensus-determinism input. That is
 * exactly why this can be a pure selection unit test with no signatures.
 *
 * @file test_sync_peer_cooldown.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "witness/nodus_witness.h"
#include "transport/nodus_tcp.h"
#include "nodus/nodus_chain_config.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Small fixture: a heap witness (multi-MB — never stack) with a legacy chain DB
 * open so nodus_witness_block_height returns 0 (empty chain), plus fake CONNECTED
 * peer connections. */
typedef struct {
    nodus_witness_t  *w;
    char              dir[128];
    nodus_tcp_conn_t  conns[NODUS_T3_MAX_WITNESSES];
} cd_fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static int cd_open(cd_fixture_t *fx) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_synccd_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t chain16[16]; memset(chain16, 0x4E, sizeof(chain16));
    if (nodus_witness_create_chain_db(fx->w, chain16) != 0) return -1;
    for (int i = 0; i < NODUS_T3_MAX_WITNESSES; i++)
        fx->conns[i].state = NODUS_CONN_CONNECTED;
    return 0;
}

static void cd_close(cd_fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    if (fx->dir[0]) rmrf(fx->dir);
}

/* Configure peer i as an identified, CONNECTED peer at `height` with cooldown
 * `bad_until` (0 = clear). */
static void set_peer(cd_fixture_t *fx, int i, uint64_t height,
                     uint64_t bad_until) {
    nodus_witness_peer_t *p = &fx->w->peers[i];
    p->identified    = true;
    p->conn          = &fx->conns[i];
    p->remote_height = height;
    p->sync_bad_until = bad_until;
    memset(p->witness_id, (uint8_t)(0x10 + i), NODUS_T3_WITNESS_ID_LEN);
}

int main(void) {
    printf("Sync peer invalid-cert cooldown tests\n");
    printf("=====================================\n");

    cd_fixture_t fx;
    CHECK(cd_open(&fx) == 0, "fixture open");
    fx.w->peer_count = 3;

    const uint64_t now      = (uint64_t)time(NULL);
    const uint64_t FUTURE   = now + 1000;   /* unexpired cooldown */
    const uint64_t PAST     = (now > 10) ? now - 10 : 0;  /* expired */
    const uint64_t BYZ_H    = 1000000ULL;   /* byzantine inflated height */

    /* Layout: peer0 honest@5, peer1 honest@6, peer2 byzantine@1e6.
     * local height == 0 (empty chain), so all three are candidates. */

    /* §1 — with NO cooldown, find_peer selects the byzantine (highest). */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 6, 0);
        set_peer(&fx, 2, BYZ_H, 0);
        int pick = nodus_witness_sync_find_peer(fx.w);
        CHECK(pick == 2, "find_peer must pick the highest when no cooldown"); OK();
    }

    /* §2 — the byzantine peer served an invalid cert → stamped into cooldown.
     * find_peer now SKIPS it and picks the honest next-highest (peer1@6),
     * EVEN THOUGH that peer sits at a lower index than the byzantine one. This
     * is the wedge-break: a lower-index honest peer becomes reachable. */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 6, 0);
        set_peer(&fx, 2, BYZ_H, FUTURE);   /* byzantine in cooldown */
        int pick = nodus_witness_sync_find_peer(fx.w);
        CHECK(pick == 1, "cooldown byzantine peer was re-selected"); OK();
    }

    /* §3 — two peers in cooldown: selection falls through to the only clear
     * one, regardless of its (lower) height. No busy-loop: an unreachable
     * highest simply is not chosen. */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 6, FUTURE);
        set_peer(&fx, 2, BYZ_H, FUTURE);
        int pick = nodus_witness_sync_find_peer(fx.w);
        CHECK(pick == 0, "cooldown must fall through to the clear peer"); OK();
    }

    /* §4 — every candidate in cooldown ⇒ no peer this tick (-1). The caller's
     * SYNC_MIN_INTERVAL_SEC rate limit is the bounded backoff; there is no
     * tight retry loop because a skipped peer is simply not returned. */
    {
        set_peer(&fx, 0, 5, FUTURE);
        set_peer(&fx, 1, 6, FUTURE);
        set_peer(&fx, 2, BYZ_H, FUTURE);
        int pick = nodus_witness_sync_find_peer(fx.w);
        CHECK(pick == -1, "all-cooldown must select no peer"); OK();
    }

    /* §5 — cooldown EXPIRY re-admits the peer: a transiently-behind honest peer
     * (or a once-byzantine slot now serving valid data) is never permanently
     * blacklisted. With the byzantine stamp in the PAST, it is chosen again. */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 6, 0);
        set_peer(&fx, 2, BYZ_H, PAST);   /* expired */
        int pick = nodus_witness_sync_find_peer(fx.w);
        CHECK(pick == 2, "expired cooldown must re-admit the peer"); OK();
    }

    /* §6 — rotate_peer (forward-only) also skips cooldown peers. From current
     * peer 0 needing the height it is stuck on, a cooldown peer1 is skipped and
     * the next clear peer2 that HOLDS the height is returned. */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 6, FUTURE);        /* skipped by cooldown */
        set_peer(&fx, 2, BYZ_H, 0);         /* clear, holds the height */
        fx.w->sync_state.sync_peer_idx     = 0;
        fx.w->sync_state.sync_current_height = 3;   /* <= peer2 height */
        int nxt = nodus_witness_sync_rotate_peer(fx.w);
        CHECK(nxt == 2, "rotate must skip cooldown and pick a clear peer"); OK();
    }

    /* §7 — rotate_peer returns -1 when the only forward peer is in cooldown,
     * which (with find_peer's next-tick reselection) is what terminates the
     * rotation chain in syncing=false rather than looping. */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 6, FUTURE);
        set_peer(&fx, 2, BYZ_H, FUTURE);
        fx.w->sync_state.sync_peer_idx       = 0;
        fx.w->sync_state.sync_current_height = 3;
        int nxt = nodus_witness_sync_rotate_peer(fx.w);
        CHECK(nxt == -1, "rotate must not return a cooldown peer"); OK();
    }

    /* §8 — a peer whose height is BELOW what we need is not a rotation target
     * even when clear (the pre-existing forward-only bound is preserved). */
    {
        set_peer(&fx, 0, 5, 0);
        set_peer(&fx, 1, 2, 0);   /* clear but below need */
        set_peer(&fx, 2, 2, 0);   /* clear but below need */
        fx.w->sync_state.sync_peer_idx       = 0;
        fx.w->sync_state.sync_current_height = 4;
        int nxt = nodus_witness_sync_rotate_peer(fx.w);
        CHECK(nxt == -1, "rotate must not pick a peer below the needed height"); OK();
    }

    cd_close(&fx);

    printf("\nAll %d checks passed.\n", g_checks);
    return 0;
}
